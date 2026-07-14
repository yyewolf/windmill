<script lang="ts">
	import { Plus, X } from 'lucide-svelte'
	import Button from './common/button/Button.svelte'
	import CollapseLink from './CollapseLink.svelte'
	import OAuthSetting from './OAuthSetting.svelte'
	import SettingCard from './instanceSettings/SettingCard.svelte'
	import TextInput from './text_input/TextInput.svelte'
	import Toggle from './Toggle.svelte'

	interface TeamMapping {
		team: string
		workspace_id: string
		group: string
	}

	interface Props {
		value: any
	}

	let { value = $bindable() }: Props = $props()

	let teamSync = $derived(value?.['team_sync'])
	let mappings: TeamMapping[] = $derived(teamSync?.['mappings'] ?? [])

	function setTeamSyncEnabled(enabled: boolean) {
		if (!value) return
		if (enabled) {
			value = {
				...value,
				team_sync: { enabled: true, create_missing_groups: true, mappings: [] }
			}
		} else {
			const { team_sync, ...rest } = value
			value = rest
		}
	}

	function updateMappings(next: TeamMapping[]) {
		value = { ...value, team_sync: { ...teamSync, mappings: next } }
	}
</script>

<div class="flex flex-col gap-2">
	<OAuthSetting name="infomaniak" bind:value />
	{#if value}
		<SettingCard class="mb-4 flex flex-col gap-6">
			<!-- svelte-ignore a11y_label_has_associated_control -->
			<label class="flex gap-4 items-center text-xs font-semibold text-emphasis">
				<div class="w-[120px]">Team sync</div>
				<Toggle
					checked={teamSync?.['enabled'] ?? false}
					on:change={(e) => setTeamSyncEnabled(e.detail)}
				/>
			</label>
			{#if teamSync?.['enabled']}
				<span class="text-secondary font-normal text-xs">
					On each Infomaniak login, the user is added to the workspace group mapped to each of their
					Infomaniak teams, and removed from the mapped groups of the teams they left. Groups that
					are not the target of a mapping are never touched. A user mapped into a workspace they are
					not a member of yet is added to it as a regular member.
				</span>
				<label class="flex flex-col gap-1">
					<span class="text-emphasis font-semibold text-xs">Infomaniak account id</span>
					<span class="text-secondary font-normal text-xs">
						Optional. Only used when Infomaniak returns no groups claim and the teams have to be
						read from the API: it pins which account's teams are listed instead of discovering every
						account the user can reach.
					</span>
					<TextInput
						inputProps={{ type: 'text', placeholder: 'Account id' }}
						bind:value={value['team_sync']['account_id']}
					/>
				</label>
				<Toggle
					options={{ right: 'Create the mapped group when it does not exist in the workspace' }}
					checked={teamSync?.['create_missing_groups'] ?? false}
					on:change={(e) => {
						value = { ...value, team_sync: { ...teamSync, create_missing_groups: e.detail } }
					}}
				/>
				<div class="flex flex-col gap-2">
					<span class="text-emphasis font-semibold text-xs">Team mappings</span>
					{#if mappings.length > 0}
						<div class="grid grid-cols-[1fr_1fr_1fr_auto] gap-2 items-center">
							<span class="text-secondary font-normal text-xs">Infomaniak team</span>
							<span class="text-secondary font-normal text-xs">Workspace id</span>
							<span class="text-secondary font-normal text-xs">Group</span>
							<span></span>
							{#each mappings as _, idx (idx)}
								<TextInput
									inputProps={{ type: 'text', placeholder: 'Engineering' }}
									bind:value={value['team_sync']['mappings'][idx]['team']}
								/>
								<TextInput
									inputProps={{ type: 'text', placeholder: 'my_workspace' }}
									bind:value={value['team_sync']['mappings'][idx]['workspace_id']}
								/>
								<TextInput
									inputProps={{ type: 'text', placeholder: 'engineers' }}
									bind:value={value['team_sync']['mappings'][idx]['group']}
								/>
								<Button
									variant="subtle"
									destructive
									iconOnly
									unifiedSize="sm"
									startIcon={{ icon: X }}
									onclick={() => updateMappings(mappings.filter((_, i) => i !== idx))}
								/>
							{/each}
						</div>
					{/if}
					<div class="flex">
						<Button
							variant="default"
							unifiedSize="md"
							startIcon={{ icon: Plus }}
							onclick={() =>
								updateMappings([...mappings, { team: '', workspace_id: '', group: '' }])}
						>
							Add mapping
						</Button>
					</div>
				</div>
			{/if}
			<CollapseLink text="Instructions">
				<div class="text-xs text-primary rounded-md">
					Create an application in the <a
						href="https://manager.infomaniak.com/v3/ng/accounts/token/list/api"
						target="_blank">Infomaniak manager</a
					>
					and set its redirect URI to <code>BASE_URL/user/login_callback/infomaniak</code> where
					BASE_URL is what you configured as core BASE_URL. Team sync reads the teams from the
					<code>groups</code>
					claim of the Infomaniak userinfo endpoint, and falls back to the
					<code>/1/accounts/&lbrace;account&rbrace;/teams</code> API when that claim is absent.
				</div>
			</CollapseLink>
		</SettingCard>
	{/if}
</div>
