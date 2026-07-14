/*
 * Author: Ruben Fiszel
 * Copyright: Windmill Labs, Inc 2022
 * This file and its contents are licensed under the AGPLv3 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-AGPL for a copy of the license.
 */

//! Infomaniak SSO for the community build: the authorization-code login flow plus
//! synchronization of Infomaniak teams into Windmill workspace groups.
//!
//! Infomaniak is a standard OIDC provider (`https://login.infomaniak.com`). Its
//! endpoints live in `backend/oauth_login.json` like every other login provider;
//! the admin only supplies a client id/secret under the `infomaniak` key of the
//! `oauths` instance setting.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;

use axum::{
    extract::{Extension, Path, Query},
    response::Redirect,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_cookies::{Cookie, Cookies};
use windmill_common::error::{self, Error};
use windmill_common::global_settings::{load_value_from_global_settings, OAUTH_SETTING};
use windmill_common::oauth2::{normalize_external_email, REQUIRE_PREEXISTING_USER_FOR_OAUTH};
use windmill_common::usernames::generate_instance_wide_unique_username;
use windmill_common::utils::IS_SECURE;
use windmill_common::BASE_URL;
use windmill_oauth::{
    build_basic_client, exchange_code, http_get_user_info, set_csrf_cookie, OAuthCallback,
    OAuthClient, OAuthConfig, State, TokenResponse, OAUTH_HTTP_CLIENT,
};

use crate::db::DB;
use crate::oauth2_oss::check_nb_of_user;
use crate::users::create_session_token;

pub const INFOMANIAK: &str = "infomaniak";

const LOGIN_CONFIGS: &str = include_str!("../../oauth_login.json");

/// Base of the Infomaniak REST API, used only by the teams fallback when the
/// `groups` claim is absent from the userinfo response.
const API_BASE: &str = "https://api.infomaniak.com";

pub fn global_service() -> Router {
    Router::new()
        .route("/login/{client_name}", get(login))
        .route("/login_callback/{client_name}", post(login_callback))
}

/// One `Infomaniak team -> Windmill workspace group` rule, as configured by the
/// instance admin in the SSO settings.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct TeamMapping {
    pub team: String,
    pub workspace_id: String,
    pub group: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct TeamSync {
    #[serde(default)]
    pub enabled: bool,
    /// Create the target group when it does not exist yet, instead of skipping
    /// the mapping.
    #[serde(default)]
    pub create_missing_groups: bool,
    /// Infomaniak account whose teams are listed. Only used by the API fallback;
    /// when absent the accounts reachable by the access token are discovered.
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub mappings: Vec<TeamMapping>,
}

/// The `oauths.infomaniak` entry of the instance settings. Extra keys written by
/// other providers' settings components are ignored.
#[derive(Deserialize, Debug)]
struct InfomaniakSettings {
    #[serde(default)]
    id: String,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    allowed_domains: Option<Vec<String>>,
    #[serde(default)]
    team_sync: Option<TeamSync>,
}

/// Standard OIDC claims returned by `https://login.infomaniak.com/oauth2/userinfo`.
#[derive(Deserialize, Debug)]
struct UserInfo {
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    /// Infomaniak advertises a `groups` claim. Its members are strings on some
    /// setups and objects on others, so they are normalized by [`team_names`].
    #[serde(default)]
    groups: Option<Vec<serde_json::Value>>,
}

/// The `(type, display name)` the login page needs to render the Infomaniak
/// button, or `None` when the provider is not usable. An unconfigured provider is
/// the normal case, so it is not surfaced as an error: the login page must still
/// render its other options.
pub async fn infomaniak_login_settings(db: &DB) -> Option<(String, String)> {
    let settings = match load_settings(db).await {
        Ok(settings) => settings,
        Err(e) => {
            tracing::debug!("Infomaniak SSO not listed as a login option: {e:#}");
            return None;
        }
    };
    Some((
        INFOMANIAK.to_string(),
        settings
            .display_name
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| "Infomaniak".to_string()),
    ))
}

async fn load_settings(db: &DB) -> error::Result<InfomaniakSettings> {
    let entry = load_value_from_global_settings(db, OAUTH_SETTING)
        .await?
        .and_then(|o| o.get(INFOMANIAK).cloned())
        .ok_or_else(|| {
            Error::BadRequest("Infomaniak SSO is not configured on this instance".to_string())
        })?;

    let settings: InfomaniakSettings = serde_json::from_value(entry)
        .map_err(|e| Error::BadConfig(format!("Invalid Infomaniak SSO instance settings: {e}")))?;

    if settings.id.is_empty() || settings.secret.is_empty() {
        return Err(Error::BadRequest(
            "Infomaniak SSO is missing a client id or client secret".to_string(),
        ));
    }
    Ok(settings)
}

fn registry_config() -> error::Result<OAuthConfig> {
    serde_json::from_str::<HashMap<String, OAuthConfig>>(LOGIN_CONFIGS)
        .map_err(|e| Error::internal_err(format!("Failed to parse oauth_login.json: {e}")))?
        .remove(INFOMANIAK)
        .ok_or_else(|| Error::internal_err("No infomaniak entry in oauth_login.json".to_string()))
}

fn build_client(
    settings: &InfomaniakSettings,
    config: &OAuthConfig,
) -> error::Result<windmill_oauth::OClient> {
    let base_url = (**BASE_URL.load()).clone();
    let (_, client) = build_basic_client(
        INFOMANIAK.to_string(),
        config.clone(),
        OAuthClient {
            id: settings.id.clone(),
            secret: settings.secret.clone(),
            display_name: None,
            allowed_domains: None,
            connect_config: None,
            login_config: None,
            tenant: None,
            grant_types: vec!["authorization_code".to_string()],
        },
        true,
        &base_url,
        None,
    )?;
    Ok(client)
}

fn ensure_infomaniak(client_name: &str) -> error::Result<()> {
    if client_name != INFOMANIAK {
        return Err(Error::BadRequest(format!(
            "'{client_name}' SSO login is not available in this build, only '{INFOMANIAK}' is"
        )));
    }
    Ok(())
}

#[derive(Deserialize)]
struct LoginQuery {
    #[serde(default)]
    close: bool,
}

async fn login(
    Path(client_name): Path<String>,
    Query(query): Query<LoginQuery>,
    Extension(db): Extension<DB>,
    cookies: Cookies,
) -> error::Result<Redirect> {
    ensure_infomaniak(&client_name)?;
    let settings = load_settings(&db).await?;
    let config = registry_config()?;
    let mut client = build_client(&settings, &config)?;

    for scope in config.scopes.iter().flatten() {
        client.add_scope(scope);
    }

    let is_secure = IS_SECURE.load(Ordering::Relaxed);
    let state = State::new_random();
    let auth_url = client.authorize_url(&state);
    set_csrf_cookie(&state, cookies.clone(), is_secure);
    // The login page opens this endpoint in a popup when it wants the tab to close
    // itself on success; the callback page reads the flag back from this cookie.
    let mut close_cookie = Cookie::new("close", query.close.to_string());
    close_cookie.set_secure(is_secure);
    close_cookie.set_same_site(Some(tower_cookies::cookie::SameSite::Lax));
    close_cookie.set_path("/");
    cookies.add(close_cookie);

    Ok(Redirect::to(auth_url.as_str()))
}

async fn login_callback(
    Path(client_name): Path<String>,
    cookies: Cookies,
    Extension(db): Extension<DB>,
    Json(callback): Json<OAuthCallback>,
) -> error::Result<String> {
    ensure_infomaniak(&client_name)?;
    let settings = load_settings(&db).await?;
    let config = registry_config()?;
    let client = build_client(&settings, &config)?;

    let token = exchange_code::<TokenResponse>(
        callback,
        &cookies,
        client,
        config.extra_params_callback.clone(),
        &OAUTH_HTTP_CLIENT,
    )
    .await?;
    let access_token = token.access_token.to_string();

    let userinfo_url = config.userinfo_url.as_ref().ok_or_else(|| {
        Error::internal_err("No userinfo url configured for infomaniak".to_string())
    })?;
    let user: UserInfo =
        http_get_user_info(&OAUTH_HTTP_CLIENT, userinfo_url, &access_token).await?;

    let email = user.email.as_deref().ok_or_else(|| {
        Error::BadRequest(
            "Infomaniak did not return an email, the 'email' scope is required".to_string(),
        )
    })?;
    let email = normalize_external_email(email);
    if user.email_verified == Some(false) {
        return Err(Error::BadRequest(format!(
            "The Infomaniak email {email} is not verified"
        )));
    }
    check_allowed_domains(&settings, &email)?;

    let session = login_or_create_user(&db, &email, user.name.as_deref(), cookies).await?;

    if let Some(sync) = settings
        .team_sync
        .filter(|s| s.enabled && !s.mappings.is_empty())
    {
        // A failing team sync must not lock the user out: they are already
        // authenticated at this point, so only their group memberships are stale.
        if let Err(e) = sync_teams(&db, &email, &user, &access_token, &sync).await {
            tracing::error!("Infomaniak team sync failed for {email}: {e:#}");
        }
    }

    Ok(session)
}

fn check_allowed_domains(settings: &InfomaniakSettings, email: &str) -> error::Result<()> {
    let Some(domains) = settings.allowed_domains.as_ref().filter(|d| !d.is_empty()) else {
        return Ok(());
    };
    if domains
        .iter()
        .any(|domain| email.ends_with(&format!("@{}", domain.trim().to_lowercase())))
    {
        return Ok(());
    }
    Err(Error::BadRequest(format!(
        "The email domain of {email} is not allowed to sign in through Infomaniak"
    )))
}

async fn login_or_create_user(
    db: &DB,
    email: &str,
    name: Option<&str>,
    cookies: Cookies,
) -> error::Result<String> {
    let mut tx = db.begin().await?;

    let existing = sqlx::query!(
        "SELECT super_admin, disabled FROM password WHERE email = $1",
        email
    )
    .fetch_optional(&mut *tx)
    .await?;

    let super_admin = match existing {
        Some(user) => {
            if user.disabled {
                return Err(Error::BadRequest(format!("The user {email} is disabled")));
            }
            user.super_admin
        }
        None => {
            if REQUIRE_PREEXISTING_USER_FOR_OAUTH.load(Ordering::Relaxed) {
                return Err(Error::BadRequest(format!(
                    "An administrator must add {email} to this Windmill instance before they can \
                     sign in through Infomaniak"
                )));
            }
            check_nb_of_user(db).await?;
            let username = generate_instance_wide_unique_username(&mut tx, email).await?;
            sqlx::query!(
                "INSERT INTO password (email, login_type, verified, name, first_time_user, username)
                 VALUES ($1, 'infomaniak', true, $2, true, $3)",
                email,
                name,
                username
            )
            .execute(&mut *tx)
            .await?;
            false
        }
    };

    let session = create_session_token(email, super_admin, None, false, &mut tx, cookies).await?;
    tx.commit().await?;
    Ok(session)
}

/// The teams the user belongs to, from the `groups` claim when Infomaniak returns
/// one, else from the teams API.
async fn user_teams(
    user: &UserInfo,
    access_token: &str,
    sync: &TeamSync,
) -> error::Result<Vec<String>> {
    if let Some(groups) = user.groups.as_ref().filter(|g| !g.is_empty()) {
        return Ok(team_names(groups));
    }
    fetch_teams_from_api(access_token, sync).await
}

/// Normalize a `groups` claim entry to a team name. Entries are plain strings on
/// some setups and objects on others.
fn team_names(groups: &[serde_json::Value]) -> Vec<String> {
    groups
        .iter()
        .filter_map(|g| match g {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Object(o) => o
                .get("name")
                .or_else(|| o.get("display_name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            _ => None,
        })
        .collect()
}

#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
}

#[derive(Deserialize)]
struct ApiProfile {
    id: i64,
}

#[derive(Deserialize)]
struct ApiAccount {
    id: i64,
}

#[derive(Deserialize)]
struct ApiTeam {
    name: String,
    #[serde(default)]
    users: Option<Vec<ApiTeamUser>>,
}

#[derive(Deserialize)]
struct ApiTeamUser {
    id: i64,
}

async fn get_api<T: serde::de::DeserializeOwned>(url: &str, token: &str) -> error::Result<T> {
    let res = OAUTH_HTTP_CLIENT
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| Error::internal_err(format!("Infomaniak API call to {url} failed: {e}")))?;
    if !res.status().is_success() {
        return Err(Error::internal_err(format!(
            "Infomaniak API call to {url} responded with {}: {}",
            res.status(),
            res.text().await.unwrap_or_default()
        )));
    }
    res.json::<Envelope<T>>()
        .await
        .map(|e| e.data)
        .map_err(|e| Error::internal_err(format!("Could not decode {url}: {e}")))
}

/// Teams of the logged-in user, read from the Infomaniak API. A team is only
/// returned when the API positively lists the user among its members: a team whose
/// membership cannot be established is left out rather than granting the group.
async fn fetch_teams_from_api(token: &str, sync: &TeamSync) -> error::Result<Vec<String>> {
    let profile: ApiProfile = get_api(&format!("{API_BASE}/2/profile"), token).await?;

    let accounts: Vec<String> = match sync.account_id.as_ref().filter(|a| !a.is_empty()) {
        // The account id lands in the request path, so keep it to the digits an
        // Infomaniak account id is made of rather than letting it reshape the URL.
        Some(account) if account.chars().all(|c| c.is_ascii_digit()) => vec![account.clone()],
        Some(account) => {
            return Err(Error::BadConfig(format!(
                "'{account}' is not a valid Infomaniak account id"
            )))
        }
        None => get_api::<Vec<ApiAccount>>(&format!("{API_BASE}/1/account"), token)
            .await?
            .into_iter()
            .map(|a| a.id.to_string())
            .collect(),
    };

    let mut teams = Vec::new();
    for account in accounts {
        let account_teams: Vec<ApiTeam> = get_api(
            &format!("{API_BASE}/1/accounts/{account}/teams?with=users"),
            token,
        )
        .await?;
        for team in account_teams {
            let Some(users) = team.users else {
                tracing::warn!(
                    "Infomaniak team '{}' of account {account} returned no user list, skipping it",
                    team.name
                );
                continue;
            };
            if users.iter().any(|u| u.id == profile.id) {
                teams.push(team.name);
            }
        }
    }
    Ok(teams)
}

/// Reconcile the user's memberships in every group named by a mapping: joined when
/// the corresponding Infomaniak team is one of theirs, removed otherwise. Groups
/// outside the mappings are never touched, so memberships managed by hand survive.
async fn sync_teams(
    db: &DB,
    email: &str,
    user: &UserInfo,
    access_token: &str,
    sync: &TeamSync,
) -> error::Result<()> {
    let teams = user_teams(user, access_token, sync).await?;
    let teams: HashSet<String> = teams.iter().map(|t| t.trim().to_lowercase()).collect();

    for mapping in &sync.mappings {
        let is_member = teams.contains(&mapping.team.trim().to_lowercase());
        if let Err(e) =
            apply_mapping(db, email, mapping, is_member, sync.create_missing_groups).await
        {
            tracing::error!(
                "Could not sync Infomaniak team '{}' to group '{}' of workspace '{}' for {email}: \
                 {e:#}",
                mapping.team,
                mapping.group,
                mapping.workspace_id
            );
        }
    }
    Ok(())
}

async fn apply_mapping(
    db: &DB,
    email: &str,
    mapping: &TeamMapping,
    is_member: bool,
    create_missing_groups: bool,
) -> error::Result<()> {
    let mut tx = db.begin().await?;

    let username = sqlx::query_scalar!(
        "SELECT username FROM usr WHERE workspace_id = $1 AND email = $2",
        mapping.workspace_id,
        email
    )
    .fetch_optional(&mut *tx)
    .await?;

    // The user is not a member of the target workspace. Adding them is only
    // warranted when the team grants them a group there; otherwise there is
    // nothing to revoke either.
    let username = match (username, is_member) {
        (Some(username), _) => username,
        (None, false) => return Ok(()),
        (None, true) => join_workspace(&mut tx, &mapping.workspace_id, email).await?,
    };

    if !is_member {
        sqlx::query!(
            "DELETE FROM usr_to_group WHERE workspace_id = $1 AND usr = $2 AND group_ = $3",
            mapping.workspace_id,
            username,
            mapping.group
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(());
    }

    let group_exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM group_ WHERE workspace_id = $1 AND name = $2)",
        mapping.workspace_id,
        mapping.group
    )
    .fetch_one(&mut *tx)
    .await?
    .unwrap_or(false);

    if !group_exists {
        if !create_missing_groups {
            return Err(Error::BadRequest(format!(
                "The group '{}' does not exist in workspace '{}' and the creation of missing \
                 groups is disabled",
                mapping.group, mapping.workspace_id
            )));
        }
        sqlx::query!(
            "INSERT INTO group_ (workspace_id, name, summary) VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING",
            mapping.workspace_id,
            mapping.group,
            format!("Members of the Infomaniak team {}", mapping.team)
        )
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query!(
        "INSERT INTO usr_to_group (workspace_id, usr, group_) VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING",
        mapping.workspace_id,
        username,
        mapping.group
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Add the user to the workspace as a regular member and return the username they
/// hold there. Uses their instance-wide username so they keep one identity across
/// workspaces.
async fn join_workspace<'c>(
    tx: &mut sqlx::Transaction<'c, sqlx::Postgres>,
    w_id: &str,
    email: &str,
) -> error::Result<String> {
    let workspace_exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM workspace WHERE id = $1 AND deleted = false)",
        w_id
    )
    .fetch_one(&mut **tx)
    .await?
    .unwrap_or(false);
    if !workspace_exists {
        return Err(Error::BadRequest(format!(
            "The workspace '{w_id}' does not exist"
        )));
    }

    let username =
        match sqlx::query_scalar!("SELECT username FROM password WHERE email = $1", email)
            .fetch_optional(&mut **tx)
            .await?
            .flatten()
        {
            Some(username) => username,
            None => generate_instance_wide_unique_username(tx, email).await?,
        };

    sqlx::query!(
        "INSERT INTO usr (workspace_id, username, email, is_admin, operator) VALUES ($1, $2, $3, false, false)
         ON CONFLICT DO NOTHING",
        w_id,
        username,
        email
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query!(
        "INSERT INTO usr_to_group (workspace_id, usr, group_) VALUES ($1, $2, 'all')
         ON CONFLICT DO NOTHING",
        w_id,
        username
    )
    .execute(&mut **tx)
    .await?;

    Ok(username)
}
