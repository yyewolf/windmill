#[cfg(feature = "private")]
#[allow(unused)]
pub use crate::git_sync_ee::*;

#[cfg(not(feature = "private"))]
use std::collections::HashMap;

#[cfg(not(feature = "private"))]
use globset::Glob;
#[cfg(not(feature = "private"))]
use serde::Serialize;
#[cfg(not(feature = "private"))]
use serde_json::value::RawValue;
#[cfg(not(feature = "private"))]
use uuid::Uuid;
#[cfg(not(feature = "private"))]
use windmill_common::{
    error::Result,
    jobs::JobPayload,
    runnable_settings::DebouncingSettings,
    users::username_to_permissioned_as,
    worker::to_raw_value,
    workspaces::{GitRepositorySettings, ObjectType, WorkspaceGitSyncSettings},
};
#[cfg(not(feature = "private"))]
use windmill_queue::{push, PushArgs, PushIsolationLevel};

#[cfg(not(feature = "private"))]
use crate::{DeployedObject, DB};

/// One entry of the `items` argument of the git-sync hub script (its `SyncObject`). The
/// script and the `wmill sync git-deploy` CLI command derive the include globs, the target
/// branch and the commit message from this list.
#[cfg(not(feature = "private"))]
#[derive(Serialize, Debug, Clone)]
struct SyncItem {
    path_type: String,
    path: Option<String>,
    parent_path: Option<String>,
    commit_msg: String,
}

/// The `PathType` union of the hub script. It is *not* `DeployedObject::get_kind()`: the
/// script spells the compound kinds without a separator (`resourcetype`, `httptrigger`), and
/// `gitSyncIncludePattern` in the CLI switches on these exact strings to build the
/// `--extra-includes` globs. An unrecognized string falls through to the CLI's script default
/// (`<path>.*`), which pulls the wrong files.
#[cfg(not(feature = "private"))]
fn path_type(obj: &DeployedObject) -> &'static str {
    match obj {
        DeployedObject::Script { .. } => "script",
        DeployedObject::Flow { .. } => "flow",
        DeployedObject::App { .. } => "app",
        DeployedObject::RawApp { .. } => "raw_app",
        DeployedObject::Folder { .. } => "folder",
        DeployedObject::Resource { .. } => "resource",
        DeployedObject::Variable { .. } => "variable",
        DeployedObject::Schedule { .. } => "schedule",
        DeployedObject::ResourceType { .. } => "resourcetype",
        DeployedObject::User { .. } => "user",
        DeployedObject::Group { .. } => "group",
        DeployedObject::HttpTrigger { .. } => "httptrigger",
        DeployedObject::WebsocketTrigger { .. } => "websockettrigger",
        DeployedObject::KafkaTrigger { .. } => "kafkatrigger",
        DeployedObject::NatsTrigger { .. } => "natstrigger",
        DeployedObject::PostgresTrigger { .. } => "postgrestrigger",
        DeployedObject::MqttTrigger { .. } => "mqtttrigger",
        DeployedObject::AmqpTrigger { .. } => "amqptrigger",
        DeployedObject::SqsTrigger { .. } => "sqstrigger",
        DeployedObject::GcpTrigger { .. } => "gcptrigger",
        DeployedObject::AzureTrigger { .. } => "azuretrigger",
        DeployedObject::EmailTrigger { .. } => "emailtrigger",
        DeployedObject::Settings { .. } => "settings",
        DeployedObject::Key { .. } => "key",
        DeployedObject::WorkspaceDependencies { .. } => "workspace_dependencies",
        DeployedObject::DatatableMigration { .. } => "datatable_migration",
    }
}

/// The `include_type` entry that governs an object. All trigger kinds share the single
/// `Trigger` type, and both app flavours share `App`.
#[cfg(not(feature = "private"))]
fn object_type(obj: &DeployedObject) -> ObjectType {
    match obj {
        DeployedObject::Script { .. } => ObjectType::Script,
        DeployedObject::Flow { .. } => ObjectType::Flow,
        DeployedObject::App { .. } | DeployedObject::RawApp { .. } => ObjectType::App,
        DeployedObject::Folder { .. } => ObjectType::Folder,
        DeployedObject::Resource { .. } => ObjectType::Resource,
        DeployedObject::Variable { .. } => ObjectType::Variable,
        DeployedObject::Schedule { .. } => ObjectType::Schedule,
        DeployedObject::ResourceType { .. } => ObjectType::ResourceType,
        DeployedObject::User { .. } => ObjectType::User,
        DeployedObject::Group { .. } => ObjectType::Group,
        DeployedObject::HttpTrigger { .. }
        | DeployedObject::WebsocketTrigger { .. }
        | DeployedObject::KafkaTrigger { .. }
        | DeployedObject::NatsTrigger { .. }
        | DeployedObject::PostgresTrigger { .. }
        | DeployedObject::MqttTrigger { .. }
        | DeployedObject::AmqpTrigger { .. }
        | DeployedObject::SqsTrigger { .. }
        | DeployedObject::GcpTrigger { .. }
        | DeployedObject::AzureTrigger { .. }
        | DeployedObject::EmailTrigger { .. } => ObjectType::Trigger,
        DeployedObject::Settings { .. } => ObjectType::Settings,
        DeployedObject::Key { .. } => ObjectType::Key,
        DeployedObject::WorkspaceDependencies { .. } => ObjectType::WorkspaceDependencies,
        DeployedObject::DatatableMigration { .. } => ObjectType::DatatableMigration,
    }
}

/// The filters deciding whether an object is synced to one repository. A repository either
/// carries its own `settings`, or predates them and inherits the workspace-level filters
/// minus its `exclude_types_override`.
#[cfg(not(feature = "private"))]
struct RepoFilters {
    include_path: Vec<String>,
    extra_include_path: Vec<String>,
    exclude_path: Vec<String>,
    include_type: Vec<ObjectType>,
}

#[cfg(not(feature = "private"))]
fn repo_filters(repo: &GitRepositorySettings, ws: &WorkspaceGitSyncSettings) -> RepoFilters {
    if let Some(settings) = repo.settings.as_ref() {
        return RepoFilters {
            include_path: settings.include_path.clone(),
            extra_include_path: settings.extra_include_path.clone().unwrap_or_default(),
            exclude_path: settings.exclude_path.clone().unwrap_or_default(),
            include_type: settings.include_type.clone(),
        };
    }

    let excluded = repo.exclude_types_override.clone().unwrap_or_default();
    RepoFilters {
        include_path: ws.include_path.clone().unwrap_or_default(),
        extra_include_path: ws.extra_include_path.clone().unwrap_or_default(),
        exclude_path: ws.exclude_path.clone().unwrap_or_default(),
        include_type: ws
            .include_type
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|t| !excluded.contains(t))
            .collect(),
    }
}

#[cfg(not(feature = "private"))]
fn matches_any_glob(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|pattern| match Glob::new(pattern) {
        Ok(glob) => glob.compile_matcher().is_match(path),
        Err(err) => {
            tracing::warn!("git sync: ignoring invalid path filter {pattern}: {err}");
            false
        }
    })
}

#[cfg(not(feature = "private"))]
fn is_selected(obj: &DeployedObject, filters: &RepoFilters) -> bool {
    let ty = object_type(obj);

    // Whether a variable is secret is only known by reading it back from the database, which
    // this path deliberately does not do. Enabling either type lets the deploy through, and the
    // `skip_secret` argument then decides whether the value reaches the repository.
    let type_included = filters.include_type.contains(&ty)
        || (ty == ObjectType::Variable && filters.include_type.contains(&ObjectType::Secret));
    if !type_included {
        return false;
    }

    // Workspace-global objects (users, groups, settings, ...) have no path to match a filter
    // against; `get_ignore_regex_filter` marks exactly those.
    if obj.get_ignore_regex_filter() {
        return true;
    }

    let path = obj.get_path();
    if matches_any_glob(&filters.exclude_path, &path) {
        return false;
    }
    matches_any_glob(&filters.include_path, &path)
        || matches_any_glob(&filters.extra_include_path, &path)
}

#[cfg(not(feature = "private"))]
fn sync_item(obj: &DeployedObject, renamed_from: Option<&str>, commit_msg: &str) -> SyncItem {
    SyncItem {
        path_type: path_type(obj).to_string(),
        path: Some(obj.get_path()),
        // The former path of a renamed object: the CLI stages it too, so the file is removed
        // from the repository under its old name instead of being left behind as a duplicate.
        parent_path: renamed_from
            .map(str::to_string)
            .or_else(|| obj.get_parent_path()),
        commit_msg: commit_msg.to_string(),
    }
}

#[cfg(not(feature = "private"))]
fn default_commit_msg(obj: &DeployedObject) -> String {
    format!("{} '{}' deployed", path_type(obj), obj.get_path())
}

#[cfg(not(feature = "private"))]
async fn get_git_sync_settings(db: &DB, w_id: &str) -> Result<Option<WorkspaceGitSyncSettings>> {
    let raw = sqlx::query_scalar!(
        "SELECT git_sync FROM workspace_settings WHERE workspace_id = $1",
        w_id
    )
    .fetch_optional(db)
    .await?
    .flatten();

    let Some(raw) = raw else {
        return Ok(None);
    };

    match serde_json::from_value::<WorkspaceGitSyncSettings>(raw) {
        Ok(settings) if !settings.repositories.is_empty() => Ok(Some(settings)),
        Ok(_) => Ok(None),
        Err(err) => {
            tracing::error!("git sync: could not parse settings of workspace {w_id}: {err}");
            Ok(None)
        }
    }
}

/// Enqueue one deployment-callback job per repository. The job runs the git-sync hub script,
/// which clones the repository, has `wmill sync git-deploy` write the deployed objects into
/// the working tree, then commits and pushes.
#[cfg(not(feature = "private"))]
async fn push_sync_jobs(
    email: &str,
    created_by: &str,
    db: &DB,
    w_id: &str,
    repos: &[(&GitRepositorySettings, Vec<SyncItem>, bool)],
    only_create_branch: bool,
    parent_workspace_id: Option<&str>,
) -> Result<Vec<Uuid>> {
    let mut job_ids = Vec::with_capacity(repos.len());

    for (repo, items, skip_secret) in repos {
        let mut args: HashMap<String, Box<RawValue>> = HashMap::new();
        args.insert("items".to_string(), to_raw_value(items));
        args.insert("workspace_id".to_string(), to_raw_value(&w_id));
        // The resource path is stored `$res:`-prefixed, but the hub script resolves it itself
        // with `getResource`. Left prefixed, the worker would substitute the resource *contents*
        // into the argument and the script would be handed an object instead of a path.
        args.insert(
            "repo_url_resource_path".to_string(),
            to_raw_value(&repo.git_repo_resource_path.trim_start_matches("$res:")),
        );
        args.insert("skip_secret".to_string(), to_raw_value(skip_secret));
        args.insert(
            "use_individual_branch".to_string(),
            to_raw_value(&repo.use_individual_branch.unwrap_or(false)),
        );
        args.insert(
            "group_by_folder".to_string(),
            to_raw_value(&repo.group_by_folder.unwrap_or(false)),
        );
        args.insert(
            "only_create_branch".to_string(),
            to_raw_value(&only_create_branch),
        );
        if let Some(parent) = parent_workspace_id {
            args.insert("parent_workspace_id".to_string(), to_raw_value(&parent));
        }

        let (job_id, tx) = push(
            db,
            PushIsolationLevel::IsolatedRoot(db.clone()),
            w_id,
            JobPayload::DeploymentCallback {
                path: repo.effective_script_path().to_string(),
                debouncing_settings: DebouncingSettings::default(),
                // Jobs sharing a concurrency key run one at a time. Keying on the repository —
                // rather than on the workspace, as the payload does by default — keeps concurrent
                // pushes to the same clone serialized while letting distinct repositories, which
                // share no working tree, sync in parallel.
                concurrency_key_append: Some(repo.git_repo_resource_path.clone()),
            },
            PushArgs::from(&args),
            created_by,
            email,
            username_to_permissioned_as(created_by),
            Some("git_sync"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            true,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
        )
        .await?;
        tx.commit().await?;

        job_ids.push(job_id);
    }

    Ok(job_ids)
}

/// Record the deployment and the callback jobs it spawned. Only scripts, flows and apps are
/// versioned objects with a row here; the other kinds sync without being tracked.
#[cfg(not(feature = "private"))]
async fn insert_deployment_metadata(
    db: &DB,
    w_id: &str,
    obj: &DeployedObject,
    deployment_message: Option<&String>,
    job_ids: &[Uuid],
) -> Result<()> {
    let msg = deployment_message.map(|x| x.as_str());
    match obj {
        DeployedObject::Script { hash, path, .. } => {
            sqlx::query!(
                "INSERT INTO deployment_metadata (workspace_id, path, script_hash, deployment_msg, callback_job_ids)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (workspace_id, script_hash) WHERE script_hash IS NOT NULL
                 DO UPDATE SET deployment_msg = EXCLUDED.deployment_msg, callback_job_ids = EXCLUDED.callback_job_ids",
                w_id,
                path,
                hash.0,
                msg,
                job_ids,
            )
            .execute(db)
            .await?;
        }
        DeployedObject::Flow { path, version, .. } => {
            sqlx::query!(
                "INSERT INTO deployment_metadata (workspace_id, path, flow_version, deployment_msg, callback_job_ids)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (workspace_id, path, flow_version) WHERE flow_version IS NOT NULL
                 DO UPDATE SET deployment_msg = EXCLUDED.deployment_msg, callback_job_ids = EXCLUDED.callback_job_ids",
                w_id,
                path,
                version,
                msg,
                job_ids,
            )
            .execute(db)
            .await?;
        }
        DeployedObject::App { path, version, .. } => {
            sqlx::query!(
                "INSERT INTO deployment_metadata (workspace_id, path, app_version, deployment_msg, callback_job_ids)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (workspace_id, path, app_version) WHERE app_version IS NOT NULL
                 DO UPDATE SET deployment_msg = EXCLUDED.deployment_msg, callback_job_ids = EXCLUDED.callback_job_ids",
                w_id,
                path,
                version,
                msg,
                job_ids,
            )
            .execute(db)
            .await?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(not(feature = "private"))]
pub async fn handle_deployment_metadata<'c>(
    email: &str,
    created_by: &str,
    db: &DB,
    w_id: &str,
    obj: DeployedObject,
    deployment_message: Option<String>,
    skip_db_insert: bool,
    renamed_from: Option<&str>,
) -> Result<()> {
    let commit_msg = deployment_message
        .clone()
        .unwrap_or_else(|| default_commit_msg(&obj));

    let job_ids = match get_git_sync_settings(db, w_id).await? {
        None => vec![],
        Some(ws) => {
            let repos = ws
                .repositories
                .iter()
                .filter_map(|repo| {
                    let filters = repo_filters(repo, &ws);
                    if !is_selected(&obj, &filters) {
                        return None;
                    }
                    let skip_secret = !filters.include_type.contains(&ObjectType::Secret);
                    Some((
                        repo,
                        vec![sync_item(&obj, renamed_from, &commit_msg)],
                        skip_secret,
                    ))
                })
                .collect::<Vec<_>>();

            push_sync_jobs(email, created_by, db, w_id, &repos, false, None).await?
        }
    };

    if !skip_db_insert {
        insert_deployment_metadata(db, w_id, &obj, deployment_message.as_ref(), &job_ids).await?;
    }

    Ok(())
}

#[cfg(not(feature = "private"))]
pub async fn tally_deployed_object_changes(
    _w_id: &str,
    _obj: &DeployedObject,
    _db: &DB,
    _renamed_from: Option<&str>,
    _origin: Option<windmill_common::deploy_origin::DeployOrigin>,
) -> Result<()> {
    // Workspace forks are an enterprise feature and not part of the open-source version
    return Ok(());
}

/// Sync several objects in a single commit per repository. Used where one action deploys many
/// objects at once — rotating the workspace encryption key re-encrypts every secret variable.
#[cfg(not(feature = "private"))]
pub async fn handle_deployment_metadata_batch<'c>(
    email: &str,
    created_by: &str,
    db: &DB,
    w_id: &str,
    objs: Vec<DeployedObject>,
    deployment_message: Option<String>,
) -> Result<()> {
    if objs.is_empty() {
        return Ok(());
    }

    let Some(ws) = get_git_sync_settings(db, w_id).await? else {
        return Ok(());
    };

    let repos = ws
        .repositories
        .iter()
        .filter_map(|repo| {
            let filters = repo_filters(repo, &ws);
            let items = objs
                .iter()
                .filter(|obj| is_selected(obj, &filters))
                .map(|obj| {
                    let commit_msg = deployment_message
                        .clone()
                        .unwrap_or_else(|| default_commit_msg(obj));
                    sync_item(obj, None, &commit_msg)
                })
                .collect::<Vec<_>>();
            if items.is_empty() {
                return None;
            }
            let skip_secret = !filters.include_type.contains(&ObjectType::Secret);
            Some((repo, items, skip_secret))
        })
        .collect::<Vec<_>>();

    push_sync_jobs(email, created_by, db, w_id, &repos, false, None).await?;

    Ok(())
}

/// Publish the branch a fork workspace syncs to, before it holds any content. The hub script
/// pushes the (empty) branch ref and stops without committing.
#[cfg(not(feature = "private"))]
pub async fn handle_fork_branch_creation<'c>(
    email: &str,
    created_by: &str,
    db: &DB,
    w_id: &str,
    fork_workspace_id: &str,
) -> Result<Vec<Uuid>> {
    let Some(ws) = get_git_sync_settings(db, fork_workspace_id).await? else {
        return Ok(vec![]);
    };

    let repos = ws
        .repositories
        .iter()
        .map(|repo| (repo, vec![], true))
        .collect::<Vec<_>>();

    push_sync_jobs(
        email,
        created_by,
        db,
        fork_workspace_id,
        &repos,
        true,
        Some(w_id),
    )
    .await
}

#[cfg(all(test, not(feature = "private")))]
mod git_sync_oss_tests {
    use super::*;
    use windmill_common::scripts::ScriptHash;

    fn script(path: &str) -> DeployedObject {
        DeployedObject::Script { hash: ScriptHash(1), path: path.to_string(), parent_path: None }
    }

    fn filters(include_path: &[&str], include_type: Vec<ObjectType>) -> RepoFilters {
        RepoFilters {
            include_path: include_path.iter().map(|x| x.to_string()).collect(),
            extra_include_path: vec![],
            exclude_path: vec![],
            include_type,
        }
    }

    #[test]
    fn folder_glob_selects_nested_paths() {
        let f = filters(&["f/**"], vec![ObjectType::Script]);
        assert!(is_selected(&script("f/team/deploy"), &f));
        assert!(is_selected(&script("f/deploy"), &f));
        assert!(!is_selected(&script("u/alice/deploy"), &f));
    }

    #[test]
    fn excluded_path_wins_over_include() {
        let mut f = filters(&["f/**"], vec![ObjectType::Script]);
        f.exclude_path = vec!["f/secret/**".to_string()];
        assert!(is_selected(&script("f/team/deploy"), &f));
        assert!(!is_selected(&script("f/secret/deploy"), &f));
    }

    #[test]
    fn extra_include_path_selects_outside_include_path() {
        let mut f = filters(&["f/**"], vec![ObjectType::Script]);
        f.extra_include_path = vec!["u/alice/**".to_string()];
        assert!(is_selected(&script("u/alice/deploy"), &f));
        assert!(!is_selected(&script("u/bob/deploy"), &f));
    }

    #[test]
    fn type_must_be_included() {
        let f = filters(&["f/**"], vec![ObjectType::Flow]);
        assert!(!is_selected(&script("f/team/deploy"), &f));
    }

    #[test]
    fn secret_type_alone_selects_variables() {
        let f = filters(&["f/**"], vec![ObjectType::Secret]);
        let variable =
            DeployedObject::Variable { path: "f/team/token".to_string(), parent_path: None };
        assert!(is_selected(&variable, &f));
    }

    #[test]
    fn path_filters_are_ignored_for_workspace_global_objects() {
        // A group has no path to match `f/**` against, and must sync regardless.
        let f = filters(&["f/**"], vec![ObjectType::Group]);
        let group = DeployedObject::Group { name: "devs".to_string() };
        assert!(is_selected(&group, &f));
    }

    #[test]
    fn all_trigger_kinds_map_to_the_trigger_type() {
        let f = filters(&["f/**"], vec![ObjectType::Trigger]);
        let trigger =
            DeployedObject::HttpTrigger { path: "f/team/hook".to_string(), parent_path: None };
        assert!(is_selected(&trigger, &f));
        assert_eq!(path_type(&trigger), "httptrigger");
    }
}
