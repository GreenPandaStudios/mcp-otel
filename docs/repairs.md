# Pluggable investigation and repair hooks

The core calls an administrator-configured authenticated hook. It does not execute model-generated commands. A hook can integrate another investigation or repair system; the included Codex implementation performs on-demand investigation and patch preparation. Nothing invokes an always-running LLM loop.

| Route | Contract |
| --- | --- |
| `POST /prepare` | Idempotent job ID and untrusted incident evidence; return quickly, prepare asynchronously |
| `POST /inspect` | Return preparing, failure, or a fresh complete tested snapshot |
| `POST /deploy` | Recheck exact approved version, then merge/roll out once |
| `POST /outcome` | Persistent deploying/healthy/recovered/failed outcome with verification evidence |

Use `REPAIR_HOOK_URL` and `REPAIR_HOOK_KEY` in the core. The endpoint must be private, authenticated and reachable through a narrowly scoped egress policy. Do not expose it through the public ingress. The example generator leaves it disabled until configured.

The tested snapshot includes PR URL, `codex/` branch, head/base SHAs, built artifact digest, current previous digest, passed checks tied to the head, diff, and deployment target. Canonical SHA-256 binds approval to the whole object. The worker independently re-fetches the snapshot immediately before deployment. A changed code/check/base/target state stops it. Expired or revoked browser approval stops it.

## Codex worker

Build `hooks/codex/Dockerfile`, then run `hooks/codex/worker.js` on a trusted deployment host with its configuration in `REPAIR_CONFIG` and keys in protected environment variables. It requires Docker, git, a narrowly scoped kubeconfig, a dedicated Codex credential directory, and source-host authorization. `GITHUB_TOKEN` is used only for the chosen repository's PR/check APIs. Git pushes use the host's configured SSH access. Neither credential reaches the model container.

For a public repository without a server-side GitHub token, the worker pushes the tested branch using its existing SSH access and returns `awaiting_pull_request` with the branch, head, artifact and compare URL. The authorized ChatGPT/GitHub connection can create that PR. The worker discovers the exact matching open PR through the public API before reporting ready. This separates source-host connection permissions from telemetry/event delivery. Private repositories require an appropriate read credential as well.

Configure explicit namespace/service → repository, test command, Dockerfile/context, image repository, health URL and deployment/container mappings. The default example is synthetic only. Do not enable another target without reviewing its tests, privacy, required checks and rollout/recovery behavior.

The model receives only a worktree, its dedicated Codex auth and untrusted incident evidence in an unprivileged container. Tests run in another container without network or deployment/source-host credentials. The trusted worker commits the tested changes, builds/pushes an image, and opens a PR. Its local evidence and jobs are stored under a protected state directory.

After approval, a regular fast-forward push puts the exact tested commit on the base branch; it cannot discard an intervening divergent change. The worker confirms GitHub reports the PR merged, rolls out the approved image digest, waits for deployment readiness, checks health, and checks the live digest. Failure rolls back only if the failed digest still occupies the target; it does not overwrite an unrelated concurrent deployment. Recovery is called successful only after health verifies.

Branch protection can require a different merge workflow; provide a source-host adapter with equivalent immutable-state checks rather than bypassing protection. Source-host auth/configuration is independent of direct MCP event delivery. No repository access is necessary for logs, metrics, traces, health, subscriptions or notifications.

The included worker needs live validation with the operator's Codex/source-host credentials. HTTP protocol fixtures validate core gates but are not evidence of an actual Codex-generated PR or production rollout. An interrupted worker job requires operator inspection; do not silently re-run an uncertain deployment.
