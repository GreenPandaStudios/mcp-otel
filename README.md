# MCP-OTel

An authenticated MCP server for Kubernetes observability, durable incident events with log evidence, and human-approved repairs. Apache-2.0 licensed.

The reusable core queries Loki, Prometheus, Tempo, and the Kubernetes API. Grafana provides an operator UI over the same backends. A separate Codex hook can investigate an incident and prepare a tested pull request; the core requires explicit approval of the exact tested snapshot before rollout.

## What it provides

- MCP `2026-07-28` discovery and bounded tools for services, logs, metric templates, traces, health, incident context, and repairs.
- Direct `events/list`, `events/subscribe`, and `events/unsubscribe` on the authenticated MCP endpoint. Incident payloads include up to 20 redacted stdout/stderr excerpts, timestamps, and source metadata.
- PostgreSQL subscription storage and transactional event/delivery outbox. Signed, verified HTTPS callbacks, secret rotation, deduplication, retries, expiry, and revocation checks survive restarts.
- A private OAuth authorization-code + S256 PKCE connection, with audience, scope and namespace enforcement. Installing a plugin or signing into an arbitrary ChatGPT account grants no cluster access.
- A repair review widget and authenticated browser panel. Approval binds the PR head and base, image digest, check evidence, diff and target; bearer tools cannot approve themselves.
- Kubernetes manifests generated from a small configuration file. No dependency on GitHub for telemetry or event delivery.

The reference deployment is a single-node installation. Persistent volumes on one node are not high availability. Back up the database, encryption key, and backend storage before treating it as a durable production service.

## Quick start

Requires Node 24+, PostgreSQL, and reachable telemetry backends:

```sh
npm ci
cp .env.example .env
# Fill database URL, random encryption key, alert ingestion key and backend URLs.
node --env-file=.env src/main.js
```

Provision an installation from a trusted administrator shell:

```sh
BOOTSTRAP_FILE=/secure/owner-client.json node --env-file=.env scripts/bootstrap.js
```

The resulting confidential OAuth client belongs to one private connection. Supply its ID and secret in ChatGPT's custom MCP setup. Keep the secret out of the public plugin package. This uses MCP-OTel's own OAuth server, not Sign in with ChatGPT.

See [deployment](docs/deployment.md), [ChatGPT setup](plugin/README.md), [security](SECURITY.md), [events](docs/events.md), and [repair hooks](docs/repairs.md).

## Collection and privacy

The collector tails Kubernetes CRI stdout/stderr files. It parses stream and workload metadata, filters configured private application content, redacts credentials, and exports to Loki. Operational log excerpts are included in incident events. The reference configuration uses an explicit private-namespace policy; review it for your applications before collecting content.

Traces require application instrumentation that sends OTLP spans. Arbitrary stdout does not create distributed traces. The example synthetic service independently emits stdout, stderr, metrics and OTLP spans. Trace attributes use an allowlist and span events are removed before storage. Do not record private application message bodies in general telemetry.

Queries allow at most one hour within the last seven days, 500 log results, 50 trace search results, bounded metric templates/resolution, 10-second backend timeouts, and bounded response bytes. Returned log text is untrusted data.

## ChatGPT support and verification

The official [MCP Events documentation](https://developers.openai.com/plugins/build/mcp-events) specifies Work chats on web, Work with Cloud selected on desktop, and dots. Workspace controls and account eligibility still apply. A plugin package alone does not prove event delivery into a user's connection.

Verify discovery, OAuth linking, callback challenge, delivery acknowledgement, actual event receipt in ChatGPT, filtering, refresh, and unsubscribe using [the launch checklist](docs/verification.md). A successful callback `2xx` is an acknowledgement, not proof that ChatGPT ran the requested investigation. The user chooses their ongoing investigation instructions in ChatGPT.

## Test

```sh
npm test
npm run check
# Dedicated disposable database name must end in _test:
TEST_DATABASE_URL=postgresql://.../mcp_otel_test npm run test:integration
```

The integration suite exercises real PostgreSQL persistence and HTTP OAuth/approval routes with a controlled callback and repair-hook fixture. Live ChatGPT delivery and source-host/cluster repair tests are separate checks. The deliberately failing repair demo test is an isolated exercise and is excluded from the normal test suite.

## Project layout

| Path | Purpose |
| --- | --- |
| `src/` | Transport, auth, telemetry adapters, incidents, durable events, repair lifecycle |
| `deploy/` | Reusable Kubernetes manifest generator and example configuration |
| `plugin/` | Portable custom plugin package and setup instructions |
| `hooks/codex/` | On-demand, isolated Codex preparation and trusted rollout hook |
| `examples/repair-demo/` | Synthetic log/metric/trace and repair exercise |
| `test/` | Security and PostgreSQL lifecycle tests |

## Upstream components

This project uses Grafana, Loki, Prometheus, Tempo, kube-state-metrics, node-exporter and the OpenTelemetry Collector. Their licenses apply to their own images. [Grafana's MCP server](https://github.com/grafana/mcp-grafana) is a useful broader Grafana integration; MCP-OTel keeps its launch query surface narrower and calls the backends directly to enforce its bounds and authorization. No Grafana MCP source is vendored.

The [OpenTelemetry Kubernetes component guide](https://opentelemetry.io/docs/platforms/kubernetes/collector/components/) informed the filelog and Kubernetes metadata pipeline. [Official plugin authentication](https://developers.openai.com/plugins/build/auth) and [packaging](https://developers.openai.com/plugins/build/plugins) documents define the connection contract.
