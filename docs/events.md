# Event contract

The authenticated `/mcp` endpoint advertises protocol `2026-07-28`, tools, resources and events through `server/discover`.

| Event | Trigger | Payload context |
| --- | --- | --- |
| `incident.changed` | Alert opens, evidence changes, or service recovers | Summary, severity, evidence, bounded redacted stdout/stderr log excerpts |
| `repair.ready` | A hook produces a complete tested snapshot | Exact version, checks, PR and review link |
| `deployment.changed` | Approved rollout verifies health, fails, or recovers | Version, verification/recovery outcome, available operational evidence |

Every subscription requires `namespace`; `service` optionally narrows it. Authorization is checked before callback verification, creation, every publish, and each delivery. Identity is a canonical hash of principal, callback URL, event name and filter arguments. Key order does not create duplicates. Unsubscribe is idempotent and principal-scoped.

The default granted lifetime is one day; requested shorter lifetimes are honored down to a one-minute minimum. Non-expiring requests receive a finite lifetime. Refresh replaces the signing secret with a five-minute overlap. A callback challenge is verified on every refresh. `refreshBefore` records the actual granted expiration.

This version does **not** advertise historical replay: `cursor` is always `null`. Events queued for an active subscription persist across server restarts. Expired/revoked/unsubscribed subscriptions stop delivery; events missed while no active subscription existed cannot be replayed. A non-null replay cursor is rejected explicitly.

Application events and their fan-out queue commit in one PostgreSQL transaction. Each event retains one ID through retries. Delivery is at least once: a timeout or crash after receiver acknowledgement can cause a duplicate. Receivers must deduplicate `eventId`. One event is sent per request; ChatGPT controls task batching.

The worker uses bounded exponential backoff, fresh signing timestamps, and up to 12 attempts. HTTP 410 disables the subscription; 400/401/403/404/413 are terminal for that event. Failed queue rows remain inspectable. In-flight sends can finish while unsubscribe/revocation is taking effect, but no new send starts after the worker observes it. There is no local desktop heartbeat or GitHub notification bridge.

Inspect queues as an operator:

```sql
SELECT status, count(*) FROM deliveries GROUP BY status;
SELECT subscription_id,event_seq,attempts,last_status FROM deliveries WHERE status='failed';
```

Follow the [official callback protocol and ChatGPT lifecycle test](https://developers.openai.com/plugins/build/mcp-events). Actual receipt and ChatGPT behavior must be tested in the supported user connection.
