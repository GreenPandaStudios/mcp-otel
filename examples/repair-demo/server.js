import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { healthStatus } from './health.js';
const namespace=process.env.NAMESPACE??'mcp-otel-synthetic',service='repair-demo';
const collector=process.env.OTEL_EXPORTER_OTLP_ENDPOINT??'http://collector.mcp-otel.svc.cluster.local:4318';
http.createServer((req,res)=>{
  if(req.url==='/metrics'){res.writeHead(200,{'content-type':'text/plain'});return res.end('mcp_otel_synthetic_up 1\n');}
  const status=req.url==='/ready'?'healthy':healthStatus();res.writeHead(status==='healthy'?200:503,{'content-type':'application/json'});res.end(JSON.stringify({status,synthetic:true}));
}).listen(8080,'0.0.0.0');
async function emit(){
  console.log(JSON.stringify({level:'info',event:'synthetic.heartbeat',status:healthStatus()}));
  console.error('synthetic stderr evidence token=MCP_OTEL_SECRET_CANARY');
  const start=BigInt(Date.now())*1000000n;
  const payload={resourceSpans:[{resource:{attributes:[{key:'service.name',value:{stringValue:service}},{key:'k8s.namespace.name',value:{stringValue:namespace}}]},scopeSpans:[{scope:{name:'mcp-otel-synthetic'},spans:[{traceId:randomBytes(16).toString('hex'),spanId:randomBytes(8).toString('hex'),name:'GET /health',kind:2,startTimeUnixNano:String(start),endTimeUnixNano:String(start+1000000n),attributes:[{key:'http.request.method',value:{stringValue:'GET'}},{key:'http.route',value:{stringValue:'/health'}},{key:'prompt',value:{stringValue:'MCP_OTEL_PRIVATE_BODY_CANARY'}}],status:{code:healthStatus()==='healthy'?1:2}}]}]}]};
  try{const r=await fetch(collector+'/v1/traces',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload),signal:AbortSignal.timeout(5000)});await r.body?.cancel();}catch{}
}
setInterval(emit,10000);emit();
