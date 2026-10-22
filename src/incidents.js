import { hash, canonical, redact } from './security.js';
export class Incidents {
  constructor(store,telemetry,events,config){this.store=store;this.telemetry=telemetry;this.events=events;this.config=config;this.running=false;}
  async record({source,namespace,service,status,severity,summary,evidence={},fingerprint}){
    const id='inc_'+hash(`${source}:${fingerprint}`).slice(0,32);
    const cleaned=redact({summary,evidence});
    const principal={namespaces:['*']};let logs=[],log_status='available';
    try{logs=(await this.telemetry.logs(principal,{namespace,service,limit:20})).logs.map(l=>({...l,line:l.line.slice(0,2000)}));}catch{log_status='backend_unavailable';}
    await this.store.tx(async tx=>{
      await tx.query('SELECT pg_advisory_xact_lock(6194302)');
      const old=(await tx.query('SELECT * FROM incidents WHERE id=$1',[id])).rows[0];
      const evidence={...cleaned.evidence,log_status};
      if(old?.status===status&&old.severity===severity&&old.summary===cleaned.summary&&canonical(old.evidence)===canonical(evidence))return;
      await tx.query(`INSERT INTO incidents(id,source,namespace,service,status,severity,summary,evidence,fingerprint) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
        ON CONFLICT(id) DO UPDATE SET status=excluded.status,severity=excluded.severity,summary=excluded.summary,evidence=excluded.evidence,updated_at=now()`,[id,source,namespace,service,status,severity,cleaned.summary,evidence,`${source}:${fingerprint}`]);
      // Incident state and delivery outbox commit atomically. Reopening an old
      // incident creates a new event even if its evidence is unchanged.
      await this.events.publish('incident.changed',{id,namespace,service,status,summary:cleaned.summary,evidence:{...evidence,severity},logs,url:`${this.config.origin}/incidents/${id}`},`${id}:${status}:${old?.updated_at?.toISOString()??'first'}:${hash(canonical(evidence))}`,tx);
    });
    return id;
  }
  async tick(){
    if(this.running)return;this.running=true;
    try{
      const health=await this.telemetry.kube.health();
      for(const p of health.pods){
        if(p.phase==='Succeeded')continue;
        const unhealthy=p.phase==='Failed'||p.containers.some(c=>['CrashLoopBackOff','ImagePullBackOff','ErrImagePull','OOMKilled','Error'].includes(c.state));
        const fingerprint=`${p.namespace}/${p.name}`;
        if(unhealthy)await this.record({source:'kubernetes',namespace:p.namespace,service:p.service,status:'open',severity:'warning',summary:`Pod ${p.name} requires attention`,evidence:{pod:p.name,phase:p.phase,containers:p.containers},fingerprint});
        else if(p.ready){
          const existing=await this.store.query(`SELECT id FROM incidents WHERE fingerprint=$1 AND status='open'`,[`kubernetes:${fingerprint}`]);
          if(existing.rows.length)await this.record({source:'kubernetes',namespace:p.namespace,service:p.service,status:'resolved',severity:'info',summary:`Pod ${p.name} recovered`,evidence:{pod:p.name,ready:true},fingerprint});
        }
      }
    }finally{this.running=false;}
  }
}
