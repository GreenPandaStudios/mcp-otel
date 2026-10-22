import { Store } from './store.js';
import { cipher } from './security.js';
import { Telemetry } from './telemetry.js';
import { Events } from './events.js';
import { Repairs } from './repairs.js';
import { Incidents } from './incidents.js';
import { createApp } from './server.js';

const config={origin:process.env.PUBLIC_ORIGIN??'https://otel.example.com',lokiURL:process.env.LOKI_URL??'http://loki:3100',prometheusURL:process.env.PROMETHEUS_URL??'http://prometheus:9090',tempoURL:process.env.TEMPO_URL??'http://tempo:3200',grafanaURL:process.env.GRAFANA_URL??'http://grafana:3000',callbackHosts:(process.env.CALLBACK_HOSTS??'').split(',').filter(Boolean),repairHookURL:process.env.REPAIR_HOOK_URL,repairHookKey:process.env.REPAIR_HOOK_KEY,alertKey:process.env.ALERT_INGEST_KEY};
if(new URL(config.origin).protocol!=='https:')throw new Error('PUBLIC_ORIGIN must use HTTPS');
const store=new Store(process.env.DATABASE_URL);await store.migrate();
const telemetry=new Telemetry(config),events=new Events(store,config,cipher(process.env.ENCRYPTION_KEY));
const repairs=new Repairs(store,config,events),incidents=new Incidents(store,telemetry,events,config);
const app=createApp({store,config,telemetry,events,repairs,incidents});
const server=app.listen(Number(process.env.PORT??8080),'0.0.0.0',()=>console.log(JSON.stringify({event:'server.started',version:'0.1.0'})));
const timers=[setInterval(()=>events.drain().catch(()=>console.error('{"event":"delivery.worker_failed"}')),1000),setInterval(()=>incidents.tick().catch(()=>console.error('{"event":"incident.poll_failed"}')),30000),setInterval(()=>repairs.tick().catch(()=>console.error('{"event":"repair.worker_failed"}')),5000)];
let stopping=false;
async function stop(){if(stopping)return;stopping=true;timers.forEach(clearInterval);server.close(async()=>{await store.close();process.exit(0);});setTimeout(()=>process.exit(1),15000).unref();}
process.on('SIGTERM',stop);process.on('SIGINT',stop);
