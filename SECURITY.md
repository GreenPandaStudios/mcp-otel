# Security model

Report a suspected vulnerability privately to the repository owner through GitHub's private vulnerability reporting when available. Do not put credentials or private telemetry in public issues.

## Installation identity

An administrator provisions a confidential OAuth client mapped to a stored principal. The public package contains no client secret and there is no anonymous sign-up or dynamic registration. The client secret must be entered only in the owner's private custom connection; distributing it as a shared public-plugin credential would authorize everyone receiving it.

The connection authenticates an installation, not an independently attested ChatGPT user subject. Whoever holds its secret can authorize that installation. Revoke the client or its grant to stop access. Deployments requiring many independently authenticated users should replace this adapter with an identity provider and explicit principal mappings.

Authorization codes expire after 60 seconds, require an exact redirect URI, resource audience and S256 PKCE, and are consumed once. Access tokens are opaque, hashed in PostgreSQL, and expire after one hour. Refresh tokens rotate; reuse revokes the grant. Current principal/client/grant state is checked on each call and delivery. Browser repair approval sessions activate only after a valid confidential token exchange.

No bearer-accessible tool approves a repair. The browser panel requires an HttpOnly Secure SameSite cookie, same-origin POST, CSRF value, current grant and exact version hash. Human approval expires after 15 minutes before deployment starts. Revalidation checks code, base, artifact, checks and current target digest. Do not put a reverse proxy in front of the approval page that strips these controls.

## Telemetry and events

Logs are untrusted evidence. Credential-pattern redaction is defense in depth, not a universal personal-data detector. Review and configure the private namespace pipeline for your applications. The collector must drop private message bodies before export; downstream redaction alone cannot undo storage of private content.

Callbacks must use HTTPS on port 443 with no credentials or fragments. Every connection resolves and validates all addresses, pins a validated public address during TLS, follows no redirects, and revalidates on retries. Standard Webhooks signatures cover ID, timestamp and exact body bytes. Verification uses a fresh random challenge, constant-time comparison and no application data. Signing secrets use AES-256-GCM at rest. Protect the encryption key separately from database backups.

The core reads pod/service/node metadata and workload health; it cannot read Kubernetes Secrets, exec into pods, mutate deployments, or retrieve arbitrary URLs. The collector alone mounts pod logs; node-exporter mounts host proc/sys/root read-only. Backends are cluster-internal. Repair credentials are separate from the core and the model's container.

The reference single-node backend stack has local persistence and finite retention. Test backups and restore, monitor failed deliveries, and apply normal image updates. Network policies require a CNI that enforces them.
