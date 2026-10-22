import { readFile } from 'node:fs/promises';
import https from 'node:https';
import { requireNamespace } from './auth.js';
import { redact } from './security.js';

export function bounds(input={},now=Date.now()){
  const end=input.end?Date.parse(input.end):now,start=input.start?Date.parse(input.start):end-15*60000;
  const limit=input.limit??100;
  if(!Number.isFinite(start)||!Number.isFinite(end)||end<start||end-start>3600000||end>now+60000||start<now-7*86400000
    ||!Number.isInteger(limit)||limit<1||limit>500)throw new Error('Queries allow a one-hour range within seven days and 1–500 results');
  return {start,end,limit};
}
export async function boundedJSON(url,options={}){
  const response=await fetch(url,{...options,redirect:'error',signal:AbortSignal.timeout(10000)});
  if(!response.ok)throw new Error(`Backend returned HTTP ${response.status}`);
  const reader=response.body.getReader();let size=0;const parts=[];
  for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>2*1024*1024){await reader.cancel();throw new Error('Backend response exceeds bound');}parts.push(Buffer.from(value));}
  return JSON.parse(Buffer.concat(parts).toString());
}
export class Kubernetes {
  constructor(config){this.base=config.kubernetesURL??'https://kubernetes.default.svc';this.directory=config.serviceAccountPath??'/var/run/secrets/kubernetes.io/serviceaccount';}
  async get(path){
    const [token,ca]=await Promise.all([readFile(`${this.directory}/token`,'utf8'),readFile(`${this.directory}/ca.crt`)]);
    return new Promise((resolve,reject)=>{
      const req=https.get(this.base+path,{ca,headers:{authorization:`Bearer ${token.trim()}`},timeout:10000},res=>{
        const parts=[];let size=0;
        res.on('data',b=>{size+=b.length;if(size>4*1024*1024)res.destroy(new Error('Kubernetes response exceeds bound'));else parts.push(b);});
        res.on('error',reject);res.on('end',()=>{try{if(res.statusCode!==200)throw new Error(`Kubernetes HTTP ${res.statusCode}`);resolve(JSON.parse(Buffer.concat(parts).toString()));}catch(e){reject(e);}});
      });req.on('error',reject);req.on('timeout',()=>req.destroy(new Error('Kubernetes timeout')));
    });
  }
  async health(namespace){
    const prefix=namespace?`/api/v1/namespaces/${encodeURIComponent(namespace)}`:'/api/v1';
    const pods=await this.get(prefix+'/pods?limit=500');
    const result={pods:pods.items.map(p=>({namespace:p.metadata.namespace,name:p.metadata.name,service:p.metadata.labels?.['app.kubernetes.io/name']??p.metadata.labels?.app??p.metadata.name.replace(/-[a-f0-9]{6,10}-[a-z0-9]{5}$/,''),phase:p.status.phase,ready:(p.status.conditions??[]).some(c=>c.type==='Ready'&&c.status==='True'),containers:(p.status.containerStatuses??[]).map(c=>({name:c.name,ready:c.ready,restarts:c.restartCount,state:c.state.waiting?.reason??c.state.terminated?.reason??'Running'}))})),truncated:!!pods.metadata?.continue};
    if(!namespace){const n=await this.get('/api/v1/nodes?limit=100');result.nodes=n.items.map(x=>({name:x.metadata.name,conditions:x.status.conditions.map(c=>({type:c.type,status:c.status,reason:c.reason}))}));}
    return result;
  }
  async services(namespace){
    const response=await this.get(`/api/v1/namespaces/${encodeURIComponent(namespace)}/services?limit=500`);
    return {services:response.items.map(s=>({name:s.metadata.name,namespace:s.metadata.namespace,ports:s.spec.ports.map(p=>({name:p.name,port:p.port,protocol:p.protocol}))})),truncated:!!response.metadata?.continue};
  }
}
const metricTemplates={
  pod_cpu:'sum by (namespace,pod) (rate(container_cpu_usage_seconds_total{namespace=NS,container!="",container!="POD"}[5m]))',
  pod_memory:'sum by (namespace,pod) (container_memory_working_set_bytes{namespace=NS,container!="",container!="POD"})',
  restarts:'sum by (namespace,pod,container) (kube_pod_container_status_restarts_total{namespace=NS})',
  availability:'kube_deployment_status_replicas_available{namespace=NS}',
  request_rate:'sum by (service) (rate(traces_spanmetrics_calls_total{namespace=NS}[5m]))',
  node_cpu:'1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m]))',
  node_memory:'1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes',
  cluster_targets:'up'
};
export class Telemetry {
  constructor(config,kube=new Kubernetes(config)){this.config=config;this.kube=kube;}
  async health(principal,{namespace}={}){
    if(namespace)requireNamespace(principal,namespace);else if(!principal.namespaces.includes('*'))throw new Error('Cluster scope required');
    return this.kube.health(namespace);
  }
  async services(principal,{namespace}){requireNamespace(principal,namespace);return this.kube.services(namespace);}
  async logs(principal,input){
    requireNamespace(principal,input.namespace);const {start,end,limit}=bounds(input);
    const labels=[`namespace=${JSON.stringify(input.namespace)}`];
    if(input.service)labels.push(`service_name=${JSON.stringify(input.service)}`);
    if(input.pod)labels.push(`pod=${JSON.stringify(input.pod)}`);
    let query=`{${labels.join(',')}}`;
    if(input.contains)query+=` |= ${JSON.stringify(input.contains)}`;
    const u=new URL('/loki/api/v1/query_range',this.config.lokiURL);
    u.search=new URLSearchParams({query,start:String(BigInt(start)*1000000n),end:String(BigInt(end)*1000000n),limit:String(limit),direction:'backward'});
    const data=await boundedJSON(u);
    return {untrusted:true,range:{start:new Date(start).toISOString(),end:new Date(end).toISOString()},logs:(data.data?.result??[]).flatMap(s=>s.values.map(v=>({timestamp:new Date(Number(BigInt(v[0])/1000000n)).toISOString(),...s.stream,line:redact(v[1])}))).sort((a,b)=>b.timestamp.localeCompare(a.timestamp)).slice(0,limit),limit};
  }
  async metrics(principal,input){
    requireNamespace(principal,input.namespace);const {start,end}=bounds(input);
    if(!metricTemplates[input.metric])throw new Error('Unknown metric template');
    if(input.metric.startsWith('node_')||input.metric==='cluster_targets')if(!principal.namespaces.includes('*'))throw new Error('Cluster scope required');
    const query=metricTemplates[input.metric].replaceAll('NS',JSON.stringify(input.namespace));
    const u=new URL('/api/v1/query_range',this.config.prometheusURL);
    u.search=new URLSearchParams({query,start:String(start/1000),end:String(end/1000),step:String(Math.max(30,Math.ceil((end-start)/1000/120))),timeout:'8s',limit:'100'});
    return {metric:input.metric,...redact(await boundedJSON(u))};
  }
  async traces(principal,input){
    requireNamespace(principal,input.namespace);const {start,end,limit}=bounds(input);
    if(input.trace_id){
      if(!/^[a-f0-9]{32}$/.test(input.trace_id))throw new Error('Invalid trace ID');
      const result=await boundedJSON(new URL(`/api/traces/${input.trace_id}`,this.config.tempoURL));
      // Never trust a trace ID alone for tenant authorization: verify every resource.
      const batches=result.batches??result.resourceSpans??[];
      if(!batches.length||batches.some(b=>!(b.resource?.attributes??[]).some(a=>a.key==='k8s.namespace.name'&&a.value?.stringValue===input.namespace)))throw new Error('Trace namespace not authorized');
      // Span events, exception messages, and arbitrary attributes may contain bodies.
      return {trace_id:input.trace_id,resources:batches.map(b=>({namespace:input.namespace,spans:(b.scopeSpans??b.instrumentationLibrarySpans??[]).flatMap(s=>s.spans??[]).map(s=>({traceId:s.traceId,spanId:s.spanId,parentSpanId:s.parentSpanId,name:s.name,kind:s.kind,startTimeUnixNano:s.startTimeUnixNano,endTimeUnixNano:s.endTimeUnixNano,status:{code:s.status?.code}}))}))};
    }
    const q=`{ resource.k8s.namespace.name = ${JSON.stringify(input.namespace)}${input.service?` && resource.service.name = ${JSON.stringify(input.service)}`:''} }`;
    const u=new URL('/api/search',this.config.tempoURL);u.search=new URLSearchParams({q,start:String(Math.floor(start/1000)),end:String(Math.floor(end/1000)),limit:String(Math.min(limit,50))});
    const result=await boundedJSON(u);return {traces:redact(result.traces??[]),metrics:result.metrics};
  }
  async backends(){
    const urls={grafana:[this.config.grafanaURL,'/api/health'],loki:[this.config.lokiURL,'/ready'],prometheus:[this.config.prometheusURL,'/-/ready'],tempo:[this.config.tempoURL,'/ready']};
    return Object.fromEntries(await Promise.all(Object.entries(urls).map(async([name,[base,path]])=>{
      try{const r=await fetch(new URL(path,base),{redirect:'error',signal:AbortSignal.timeout(3000)});await r.body?.cancel();return [name,{ready:r.ok,status:r.status}];}catch{return [name,{ready:false}];}
    })));
  }
}
