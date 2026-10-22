# Isolated repair exercise

This example deliberately reports unhealthy at `/health`. It belongs in a dedicated synthetic namespace, never in production. Its separate `demo.test.js` initially fails so the Codex hook has a small, verifiable repair to prepare. It is excluded from the project's normal passing test suite.

The service emits stdout and stderr log evidence, a synthetic credential canary for redaction checks, Prometheus metrics, and real OTLP spans. Stdout collection and trace instrumentation are separate paths. Only synthetic data is used.

The hook must prepare a PR, run the example test in an isolated container, build an immutable image, and wait for explicit approval. The initial fault is intentional; deploying this example is not a production outage.
