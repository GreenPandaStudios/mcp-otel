# Launch verification

Record what was implemented, deployed, verified and pending separately. Never equate a protocol fixture with actual ChatGPT delivery or a real rollout.

- Verify trusted HTTPS externally and `GET /livez`, `/readyz`, discovery, and OAuth metadata.
- Verify missing, wrong-client, wrong-resource, expired, reused and revoked credentials fail. Check namespace/scope isolation and restricted Kubernetes RBAC.
- Query real node/pod/service health, Prometheus metrics, collected stdout and stderr, and instrumented OTLP traces. Verify synthetic credential/private-body canaries are absent from storage and results.
- Exercise authenticated callback challenge, signature tampering/replay rejection, filtering, refresh and key rotation, restart persistence, retries, duplicate IDs, expiry, unsubscribe and revocation. Observe failed delivery state.
- In the actual supported ChatGPT Work cloud/dot connection, confirm discovered tools/events, subscription creation, callback verification, receipt/processing of a synthetic incident containing logs, and unsubscribe. Confirm account eligibility in the UI.
- Configure Codex and source-host credentials separately. On a synthetic target, prepare a real tested PR; verify its diff, checks, immutable artifact and repair status in ChatGPT. Try stale-version and tool-only approvals and verify rejection. Approve the exact current version with the authenticated human UI. Verify merge, digest rollout, health, and a controlled recovery case.
- Back up and restore PostgreSQL/encryption key and telemetry persistence; verify the restored subscription resumes pending delivery without inventing historical replay.

The normal integration tests use a dedicated `_test` database and controlled callback/hook fixtures. They deliberately do not claim the account-level or live repair checks above passed.
