import { readFileSync } from 'node:fs';
const c=JSON.parse(readFileSync(process.argv[2]??new URL('./config.example.json',import.meta.url),'utf8'));
const ns=c.namespace??'mcp-otel',origin=new URL(c.origin),items=[];
if(!/^[a-z0-9-]{1,63}$/.test(ns)||origin.protocol!=='https:')throw new Error('Invalid namespace or HTTPS origin');
const labels=name=>({app:name,'app.kubernetes.io/part-of':'mcp-otel'});
function add(kind,name,spec,apiVersion='v1',extra={}){const r={apiVersion,kind,metadata:{name,namespace:ns,labels:labels(name)},...extra,...(spec?{spec}:{})};items.push(r);return r;}
const namespace=add('Namespace',ns);delete namespace.metadata.namespace;
add('ServiceAccount','mcp-otel');add('ServiceAccount','prometheus');add('ServiceAccount','collector');add('ServiceAccount','kube-state-metrics');
function rbac(name,rules){const role=add('ClusterRole',`${ns}-${name}`,null,'rbac.authorization.k8s.io/v1',{rules});delete role.metadata.namespace;const binding=add('ClusterRoleBinding',`${ns}-${name}`,null,'rbac.authorization.k8s.io/v1',{roleRef:{apiGroup:'rbac.authorization.k8s.io',kind:'ClusterRole',name:`${ns}-${name}`},subjects:[{kind:'ServiceAccount',name,namespace:ns}]});delete binding.metadata.namespace;}
rbac('mcp-otel',[{apiGroups:[''],resources:['pods','services','nodes'],verbs:['get','list']},{apiGroups:['apps'],resources:['deployments','daemonsets','statefulsets'],verbs:['get','list']}]);
rbac('collector',[{apiGroups:[''],resources:['pods','namespaces','nodes'],verbs:['get','list','watch']}]);
rbac('prometheus',[{apiGroups:[''],resources:['nodes','nodes/proxy','services','endpoints','pods'],verbs:['get','list','watch']},{apiGroups:['discovery.k8s.io'],resources:['endpointslices'],verbs:['get','list','watch']},{nonResourceURLs:['/metrics','/metrics/cadvisor'],verbs:['get']}]);
rbac('kube-state-metrics',[{apiGroups:[''],resources:['nodes','pods','services','namespaces','persistentvolumeclaims','persistentvolumes','resourcequotas','limitranges','replicationcontrollers','endpoints'],verbs:['list','watch']},{apiGroups:['apps'],resources:['deployments','daemonsets','statefulsets','replicasets'],verbs:['list','watch']},{apiGroups:['batch'],resources:['jobs','cronjobs'],verbs:['list','watch']},{apiGroups:['autoscaling'],resources:['horizontalpodautoscalers'],verbs:['list','watch']},{apiGroups:['policy'],resources:['poddisruptionbudgets'],verbs:['list','watch']},{apiGroups:['storage.k8s.io'],resources:['storageclasses','volumeattachments'],verbs:['list','watch']},{apiGroups:['networking.k8s.io'],resources:['ingresses','networkpolicies'],verbs:['list','watch']},{apiGroups:['certificates.k8s.io'],resources:['certificatesigningrequests'],verbs:['list','watch']}]);
function config(name,data){return add('ConfigMap',name,null,'v1',{data});}
function pvc(name,size){add('PersistentVolumeClaim',name,{accessModes:['ReadWriteOnce'],storageClassName:c.storageClass??'local-path',resources:{requests:{storage:size}}});}
function workload(name,image,ports,{args=[],env=[],mounts=[],volumes=[],sa,uid=1000,fsGroup=1000,storage,memory='256Mi',cpu='100m',kind='Deployment',readiness,security={}}={}){
  if(storage){pvc(name,storage);volumes.push({name:'data',persistentVolumeClaim:{claimName:name}});mounts.push({name:'data',mountPath:'/data'});}
  const container={name,image,imagePullPolicy:'IfNotPresent',ports:ports.map(([n,p])=>({name:n,containerPort:p})),args,env,volumeMounts:mounts,resources:{requests:{cpu,memory},limits:{memory:memory==='1Gi'?'2Gi':memory==='512Mi'?'1Gi':'512Mi'}},securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:['ALL']},readOnlyRootFilesystem:true,...security}};
  if(readiness){container.readinessProbe={httpGet:{path:readiness,port:ports[0][1]},initialDelaySeconds:10,periodSeconds:10};container.livenessProbe={httpGet:{path:readiness,port:ports[0][1]},initialDelaySeconds:90,periodSeconds:20,failureThreshold:6};}
  volumes.push({name:'tmp',emptyDir:{sizeLimit:'128Mi'}});mounts.push({name:'tmp',mountPath:'/tmp'});
  const pod={serviceAccountName:sa??'default',automountServiceAccountToken:!!sa,securityContext:{runAsNonRoot:uid!==0,runAsUser:uid,runAsGroup:uid,fsGroup,seccompProfile:{type:'RuntimeDefault'}},containers:[container],volumes};
  const spec={selector:{matchLabels:{app:name}},template:{metadata:{labels:labels(name)},spec:pod}};
  if(kind==='Deployment'){spec.replicas=1;spec.strategy={type:'Recreate'};}
  add(kind,name,spec,'apps/v1');
  if(ports.length)add('Service',name,{selector:{app:name},ports:ports.map(([n,p])=>({name:n,port:p,targetPort:p}))});
}
const cm=(name,path)=>({mounts:[{name:'config',mountPath:path,readOnly:true}],volumes:[{name:'config',configMap:{name}}]});
config('loki',{'config.yaml':`auth_enabled: false
server:
  http_listen_port: 3100
common:
  instance_addr: 127.0.0.1
  path_prefix: /data
  storage:
    filesystem:
      chunks_directory: /data/chunks
      rules_directory: /data/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
compactor:
  working_directory: /data/compactor
  retention_enabled: true
  delete_request_store: filesystem
limits_config:
  retention_period: 168h
  max_query_length: 1h
  max_query_series: 100
  max_entries_limit_per_query: 500
  allow_structured_metadata: true
  otlp_config:
    resource_attributes:
      ignore_defaults: true
      attributes_config:
        - action: index_label
          attributes: [service.name, namespace, pod, stream]
analytics:
  reporting_enabled: false
`});
workload('loki','grafana/loki:3.7.9',[['http',3100]],{...cm('loki','/etc/loki'),args:['-config.file=/etc/loki/config.yaml'],storage:'20Gi',memory:'512Mi',uid:10001,readiness:'/ready'});
config('tempo',{'config.yaml':`stream_over_http_enabled: true
server:
  http_listen_port: 3200
distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: 0.0.0.0:4317
        http:
          endpoint: 0.0.0.0:4318
storage:
  trace:
    backend: local
    wal:
      path: /data/wal
    local:
      path: /data/blocks
usage_report:
  reporting_enabled: false
`});
workload('tempo','grafana/tempo:3.1.1',[['http',3200],['otlp-grpc',4317],['otlp-http',4318]],{...cm('tempo','/etc/tempo'),mounts:[...cm('tempo','/etc/tempo').mounts,{name:'data',mountPath:'/var/tempo'}],args:['-config.file=/etc/tempo/config.yaml'],storage:'10Gi',memory:'512Mi',uid:10001,readiness:'/ready'});
config('prometheus',{'prometheus.yaml':`global:
  scrape_interval: 30s
  evaluation_interval: 30s
rule_files: [/etc/prometheus/rules.yaml]
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']
scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ['localhost:9090']
  - job_name: kube-state-metrics
    static_configs:
      - targets: ['kube-state-metrics:8080']
  - job_name: node-exporter
    static_configs:
      - targets: ['node-exporter:9100']
  - job_name: kubelet-cadvisor
    scheme: https
    authorization:
      credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    tls_config:
      ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    kubernetes_sd_configs:
      - role: node
    relabel_configs:
      - target_label: __address__
        replacement: kubernetes.default.svc:443
      - source_labels: [__meta_kubernetes_node_name]
        target_label: __metrics_path__
        replacement: /api/v1/nodes/${1}/proxy/metrics/cadvisor
  - job_name: application-opt-in
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: 'true'
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        target_label: __address__
        regex: '([^:]+)(?::[0-9]+)?;([0-9]+)'
        replacement: '${1}:${2}'
      - source_labels: [__meta_kubernetes_namespace]
        target_label: namespace
      - source_labels: [__meta_kubernetes_pod_name]
        target_label: pod
`, 'rules.yaml':`groups:
  - name: cluster-health
    rules:
      - alert: DeploymentUnavailable
        expr: kube_deployment_spec_replicas > 0 unless on(namespace,deployment) (kube_deployment_status_replicas_available > 0)
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: 'Deployment {{ $labels.deployment }} has no available replicas'
      - alert: ContainerRestarting
        expr: increase(kube_pod_container_status_restarts_total[10m]) > 3
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: 'Container {{ $labels.container }} is repeatedly restarting'
      - alert: KubernetesNodeNotReady
        expr: kube_node_status_condition{condition="Ready",status="true"} == 0
        for: 3m
        labels:
          severity: critical
          namespace: ${ns}
          service: cluster
        annotations:
          summary: 'Node {{ $labels.node }} is not ready'
`});
workload('prometheus','prom/prometheus:v3.15.1',[['http',9090]],{...cm('prometheus','/etc/prometheus'),args:['--config.file=/etc/prometheus/prometheus.yaml','--storage.tsdb.path=/data','--storage.tsdb.retention.time=7d','--storage.tsdb.retention.size=8GB','--web.enable-remote-write-receiver'],storage:'10Gi',sa:'prometheus',uid:65534,memory:'512Mi',readiness:'/-/ready'});
config('alertmanager',{'alertmanager.yaml':`global:
  resolve_timeout: 5m
route:
  receiver: mcp-otel
  group_by: [namespace, alertname, deployment, pod]
  group_wait: 30s
  group_interval: 2m
  repeat_interval: 4h
receivers:
  - name: mcp-otel
    webhook_configs:
      - url: http://mcp-otel:8080/ingest/alerts
        send_resolved: true
        max_alerts: 20
        http_config:
          authorization:
            type: Bearer
            credentials_file: /secrets/ALERT_INGEST_KEY
`});
workload('alertmanager','prom/alertmanager:v0.31.1',[['http',9093]],{...cm('alertmanager','/etc/alertmanager'),args:['--config.file=/etc/alertmanager/alertmanager.yaml','--storage.path=/data','--cluster.listen-address='],storage:'1Gi',uid:65534,mounts:[...cm('alertmanager','/etc/alertmanager').mounts,{name:'secrets',mountPath:'/secrets',readOnly:true}],volumes:[...cm('alertmanager','/etc/alertmanager').volumes,{name:'secrets',secret:{secretName:'mcp-otel',items:[{key:'ALERT_INGEST_KEY',path:'ALERT_INGEST_KEY'}]}}],readiness:'/-/ready'});
config('grafana',{'datasources.yaml':`apiVersion: 1
datasources:
  - name: Prometheus
    uid: prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
  - name: Loki
    uid: loki
    type: loki
    access: proxy
    url: http://loki:3100
    editable: false
  - name: Tempo
    uid: tempo
    type: tempo
    access: proxy
    url: http://tempo:3200
    editable: false
`});
workload('grafana','grafana/grafana:13.2.4',[['http',3000]],{...cm('grafana','/etc/grafana/provisioning/datasources'),storage:'2Gi',uid:472,memory:'256Mi',env:[{name:'GF_PATHS_DATA',value:'/data'},{name:'GF_PATHS_PLUGINS',value:'/data/plugins'},{name:'GF_PATHS_LOGS',value:'/tmp'},{name:'GF_ANALYTICS_REPORTING_ENABLED',value:'false'},{name:'GF_ANALYTICS_CHECK_FOR_UPDATES',value:'false'},{name:'GF_AUTH_ANONYMOUS_ENABLED',value:'false'},{name:'GF_SECURITY_ADMIN_PASSWORD',valueFrom:{secretKeyRef:{name:'mcp-otel',key:'GRAFANA_ADMIN_PASSWORD'}}}],readiness:'/api/health'});
workload('kube-state-metrics','registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.20.0',[['http',8080]],{sa:'kube-state-metrics',uid:65534,args:['--resources=nodes,pods,services,namespaces,deployments,daemonsets,statefulsets,replicasets,jobs,cronjobs,persistentvolumeclaims,persistentvolumes'],readiness:'/healthz'});
workload('node-exporter','prom/node-exporter:v1.12.1',[['http',9100]],{uid:65534,kind:'DaemonSet',args:['--path.procfs=/host/proc','--path.sysfs=/host/sys','--path.rootfs=/host/root','--collector.filesystem.mount-points-exclude=^/(dev|proc|sys|var/lib/docker|var/lib/kubelet)(/|$)'],mounts:[{name:'proc',mountPath:'/host/proc',readOnly:true},{name:'sys',mountPath:'/host/sys',readOnly:true},{name:'root',mountPath:'/host/root',readOnly:true}],volumes:[{name:'proc',hostPath:{path:'/proc'}},{name:'sys',hostPath:{path:'/sys'}},{name:'root',hostPath:{path:'/'}}]});
const privateCondition=(c.privateNamespaces??[]).map(n=>`resource.attributes["k8s.namespace.name"] == ${JSON.stringify(n)}`).join(' or ')||'false';
config('collector',{'config.yaml':`extensions:
  health_check:
    endpoint: 0.0.0.0:13133
  file_storage:
    directory: /data/checkpoints
    create_directory: true
receivers:
  filelog:
    include: [/var/log/pods/*/*/*.log]
    exclude: [/var/log/pods/${ns}_collector-*/*/*.log]
    start_at: end
    include_file_path: true
    max_log_size: 64KiB
    storage: file_storage
    operators:
      - type: container
        id: container-parser
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 256
    spike_limit_mib: 64
  k8sattributes:
    auth_type: serviceAccount
    extract:
      metadata: [k8s.namespace.name, k8s.pod.name, k8s.pod.uid, k8s.node.name]
      labels:
        - tag_name: service.name
          key: app.kubernetes.io/name
          from: pod
        - tag_name: app.name
          key: app
          from: pod
    pod_association:
      - sources:
          - from: resource_attribute
            name: k8s.pod.uid
      - sources:
          - from: connection
  transform/logs:
    error_mode: propagate
    log_statements:
      - context: log
        statements:
          - set(resource.attributes["namespace"], resource.attributes["k8s.namespace.name"])
          - set(resource.attributes["pod"], resource.attributes["k8s.pod.name"])
          - set(resource.attributes["stream"], attributes["log.iostream"])
          - set(resource.attributes["service.name"], resource.attributes["app.name"]) where resource.attributes["service.name"] == nil
          - set(resource.attributes["service.name"], resource.attributes["k8s.container.name"]) where resource.attributes["service.name"] == nil
          - set(body, "[private application content withheld]") where (${privateCondition}) and not IsMatch(body, "^(info|warn|fail|crit|dbug): (Microsoft[.]|System[.])")
          - replace_pattern(body, "(?i)(Bearer|Basic) [A-Za-z0-9+/_.=-]+", "[REDACTED]")
          - replace_pattern(body, "(?i)(password|secret|token|api_key)[^:=]{0,4}[=:] *[^ ,;]+", "[REDACTED]")
          - replace_pattern(body, "sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]+", "[REDACTED]")
          - replace_pattern(body, "(?i)(prompt|completion|transcript|message_body|messages)[^:]*:.*", "[private message body withheld]")
          - keep_keys(attributes, ["log.iostream"])
          - keep_keys(resource.attributes, ["namespace", "pod", "stream", "service.name", "k8s.namespace.name", "k8s.pod.name", "k8s.container.name", "k8s.node.name"])
  transform/traces:
    error_mode: propagate
    trace_statements:
      - context: resource
        statements:
          - keep_keys(attributes, ["service.name", "service.version", "k8s.namespace.name", "k8s.pod.name", "k8s.node.name"])
      - context: span
        statements:
          - keep_keys(attributes, ["http.request.method", "http.response.status_code", "http.route", "rpc.system", "rpc.method", "error.type"])
          - set(events, [])
          - replace_pattern(name, "(?i)(password|secret|token|prompt|messages)[=:].*", "[REDACTED]")
  batch:
    timeout: 2s
    send_batch_size: 256
exporters:
  otlphttp/loki:
    endpoint: http://loki:3100/otlp
    sending_queue:
      storage: file_storage
      queue_size: 1000
  otlphttp/tempo:
    endpoint: http://tempo:4318
    sending_queue:
      storage: file_storage
      queue_size: 1000
service:
  extensions: [health_check, file_storage]
  pipelines:
    logs:
      receivers: [filelog]
      processors: [memory_limiter, k8sattributes, transform/logs, batch]
      exporters: [otlphttp/loki]
    traces:
      receivers: [otlp]
      processors: [memory_limiter, k8sattributes, transform/traces, batch]
      exporters: [otlphttp/tempo]
`});
workload('collector','otel/opentelemetry-collector-contrib:0.163.2',[['health',13133],['otlp-grpc',4317],['otlp-http',4318]],{...cm('collector','/etc/otel'),args:['--config=/etc/otel/config.yaml'],kind:'DaemonSet',sa:'collector',uid:0,memory:'256Mi',mounts:[...cm('collector','/etc/otel').mounts,{name:'podlogs',mountPath:'/var/log/pods',readOnly:true},{name:'checkpoints',mountPath:'/data'}],volumes:[...cm('collector','/etc/otel').volumes,{name:'podlogs',hostPath:{path:'/var/log/pods'}},{name:'checkpoints',hostPath:{path:'/var/lib/mcp-otel/collector',type:'DirectoryOrCreate'}}],readiness:'/'});
workload('mcp-otel',c.image,[['http',8080]],{sa:'mcp-otel',memory:'256Mi',env:[{name:'PUBLIC_ORIGIN',value:c.origin},{name:'LOKI_URL',value:'http://loki:3100'},{name:'PROMETHEUS_URL',value:'http://prometheus:9090'},{name:'TEMPO_URL',value:'http://tempo:3200'},{name:'GRAFANA_URL',value:'http://grafana:3000'},...['DATABASE_URL','ENCRYPTION_KEY','ALERT_INGEST_KEY'].map(key=>({name:key,valueFrom:{secretKeyRef:{name:'mcp-otel',key}}}))],readiness:'/readyz'});
const ingress=add('Ingress','mcp-otel',{ingressClassName:c.ingressClass??'traefik',rules:[{host:origin.hostname,http:{paths:[{path:'/',pathType:'Prefix',backend:{service:{name:'mcp-otel',port:{number:8080}}}}]}}],tls:[{hosts:[origin.hostname]}]},'networking.k8s.io/v1');
ingress.metadata.annotations={'traefik.ingress.kubernetes.io/router.entrypoints':'websecure','traefik.ingress.kubernetes.io/router.tls':'true','traefik.ingress.kubernetes.io/router.tls.certresolver':c.certificateResolver??'letsencrypt'};
add('NetworkPolicy','isolate-ingress',{podSelector:{},policyTypes:['Ingress'],ingress:[{from:[{podSelector:{}}]},{from:[{namespaceSelector:{matchLabels:{'kubernetes.io/metadata.name':'kube-system'}}}],ports:[{port:8080,protocol:'TCP'}]}]},'networking.k8s.io/v1');
add('NetworkPolicy','instrumented-apps',{podSelector:{matchLabels:{app:'collector'}},policyTypes:['Ingress'],ingress:[{from:[{namespaceSelector:{}}],ports:[{port:4317,protocol:'TCP'},{port:4318,protocol:'TCP'}]}]},'networking.k8s.io/v1');
// Core has no host mounts or mutation RBAC. Only DNS, telemetry, database,
// Kubernetes and outbound HTTPS are reachable. Callback address pinning adds
// application-level SSRF protection, including against public DNS rebinding.
add('NetworkPolicy','core-egress',{podSelector:{matchLabels:{app:'mcp-otel'}},policyTypes:['Egress'],egress:[{to:[{namespaceSelector:{matchLabels:{'kubernetes.io/metadata.name':'kube-system'}}}],ports:[{port:53,protocol:'UDP'},{port:53,protocol:'TCP'}]},{to:[{podSelector:{}}],ports:[{port:3100,protocol:'TCP'},{port:3200,protocol:'TCP'},{port:9090,protocol:'TCP'},{port:3000,protocol:'TCP'}]},{ports:[{port:443,protocol:'TCP'},{port:5432,protocol:'TCP'}]}]},'networking.k8s.io/v1');
// JSON string literals are valid YAML scalars and protect OTTL expressions
// containing colon-space, quotes and regular-expression backslashes.
const collector=items.find(i=>i.kind==='ConfigMap'&&i.metadata.name==='collector');
collector.data['config.yaml']=collector.data['config.yaml'].split('\n').map(line=>line.replace(/^(\s+- )((?:set|replace_pattern|keep_keys)\(.*)$/,(all,prefix,statement)=>prefix+JSON.stringify(statement))).join('\n');
console.log(JSON.stringify({apiVersion:'v1',kind:'List',items},null,2));
