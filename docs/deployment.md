# Kubernetes deployment

Inspect existing observability, ingress, storage and database services before adding anything. `deploy/render.js` creates a complete reference stack; adapt it to reuse existing backends or deploy only the core when those already exist.

1. Create a dedicated PostgreSQL database and non-superuser login. Grant access only to the MCP-OTel database. Keep private application databases and credentials separate.
2. Create namespace `mcp-otel` and Secret `mcp-otel` with `DATABASE_URL`, `ENCRYPTION_KEY` (32 random bytes, base64), `ALERT_INGEST_KEY`, and `GRAFANA_ADMIN_PASSWORD`.
3. Build the core image and push it to a registry your nodes can pull. Use an immutable digest for production.
4. Copy `deploy/config.example.json` to an administrator-controlled path. Set the image, HTTPS origin, storage class, ingress class and certificate resolver. Configure private namespaces before collecting logs.
5. Render, validate and apply:

```sh
node deploy/render.js /secure/deploy.json > /secure/manifests.json
kubectl apply --dry-run=server -f /secure/manifests.json
kubectl apply -f /secure/manifests.json
kubectl -n mcp-otel get pods
```

The generated ingress uses Traefik's `letsencrypt` resolver; another controller requires adapting its annotations and TLS configuration. DNS must point at the existing public ingress, and HTTP-01 validation must reach it. Do not bypass certificate errors during verification.

The stack includes Grafana, Loki, Tempo, Prometheus, Alertmanager, kube-state-metrics, node-exporter and an OpenTelemetry Collector DaemonSet. Backend ports are cluster-internal. Access Grafana through an authenticated operator port-forward; the initial admin password remains in the Kubernetes Secret.

The core's ServiceAccount has read-only pod/service/node and workload metadata permissions. It cannot read Secrets or mutate workloads. Prometheus needs node proxy access for kubelet/cAdvisor metrics. The collector uses Kubernetes metadata and a read-only pod-log mount, with durable local file checkpoints/export queues. Review privileged host visibility and CNI policy enforcement in your environment.

Loki and Prometheus retain seven days. Bound local volume sizes and monitor disk growth; backend filesystem persistence does not provide independent backups. Retention/compaction behavior and trace storage should be validated for the selected Tempo release. Subscriptions and approval state live in PostgreSQL; back it up with the encryption key stored separately.

`mcp-otel-synthetic` is reserved for optional verification fixtures. Never change private applications or induce a production failure to test events or repair hooks.
