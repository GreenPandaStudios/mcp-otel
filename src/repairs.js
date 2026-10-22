import { hash, canonical, random, escapeHtml, equal } from './security.js';
import { requireScope, requireNamespace, browserIdentity, page } from './auth.js';
import { boundedJSON } from './telemetry.js';

export function versionOf(snapshot){return hash(canonical(snapshot));}
export function validateSnapshot(s){
  if(!s||!/^https:\/\/github\.com\/[^/]+\/[^/]+\/pull\/\d+$/.test(s.pr_url)
    ||!/^codex\//.test(s.branch)||! /^[a-f0-9]{40}$/.test(s.head_sha)||! /^[a-f0-9]{40}$/.test(s.base_sha)
    ||!/^sha256:[a-f0-9]{64}$/.test(s.artifact_digest)||!/^sha256:[a-f0-9]{64}$/.test(s.previous_digest)
    ||!s.checks?.length||s.checks.some(c=>c.status!=='passed'||c.head_sha!==s.head_sha||!c.evidence_hash)
    ||typeof s.diff!=='string'||s.diff.length>100000||!s.target?.namespace||!s.target?.deployment||!s.target?.container)throw new Error('Repair is not a complete tested artifact');
  return s;
}
export class HTTPRepairHook {
  constructor(config){this.url=config.repairHookURL;this.key=config.repairHookKey;}
  get enabled(){return !!this.url&&!!this.key;}
  async call(action,data){
    if(!this.enabled)throw new Error('Codex repair hook is not configured');
    return boundedJSON(new URL('/'+action,this.url),{method:'POST',headers:{'content-type':'application/json',authorization:`Bearer ${this.key}`},body:JSON.stringify(data)});
  }
}
export class Repairs {
  constructor(store,config,events,hook=new HTTPRepairHook(config)){this.store=store;this.config=config;this.events=events;this.hook=hook;this.running=false;}
  async get(principal,id){
    requireScope(principal,'repairs:read');
    const {rows}=await this.store.query(`SELECT r.*,i.namespace,i.service,i.summary FROM repairs r JOIN incidents i ON i.id=r.incident_id WHERE r.id=$1 AND r.principal_id=$2`,[id,principal.id]);
    if(!rows[0])throw new Error('Repair not found');requireNamespace(principal,rows[0].namespace);
    const r=rows[0];delete r.approval_hash;delete r.approved_session;
    r.review_url=`${this.config.origin}/repairs/${encodeURIComponent(r.id)}`;
    return r;
  }
  async prepare(principal,{incident_id}){
    requireScope(principal,'repairs:prepare');requireScope(principal,'repairs:read');
    if(!this.hook.enabled)throw new Error('Codex repair hook is not configured');
    const {rows}=await this.store.query('SELECT * FROM incidents WHERE id=$1',[incident_id]);
    const i=rows[0];if(!i)throw new Error('Incident not found');requireNamespace(principal,i.namespace);
    const id='repair_'+random();
    const inserted=await this.store.query(`INSERT INTO repairs(id,principal_id,incident_id,status) VALUES($1,$2,$3,'preparing') ON CONFLICT DO NOTHING RETURNING id`,[id,principal.id,i.id]);
    if(!inserted.rows.length){const existing=await this.store.query(`SELECT id FROM repairs WHERE principal_id=$1 AND incident_id=$2 AND status IN('preparing','ready','approved','deploying')`,[principal.id,i.id]);return this.get(principal,existing.rows[0].id);}
    const evidence=await this.store.query(`SELECT payload->'logs' AS logs FROM events WHERE payload->>'id'=$1 ORDER BY seq DESC LIMIT 1`,[i.id]);
    try{await this.hook.call('prepare',{id,incident:{...i,logs:evidence.rows[0]?.logs??[]}});}catch(e){await this.store.query(`UPDATE repairs SET status='failed',result=$2 WHERE id=$1`,[id,{reason:'prepare_hook_failed'}]);throw e;}
    return this.get(principal,id);
  }
  async tick(){
    if(this.running||!this.hook.enabled)return;this.running=true;
    try{
      const {rows}=await this.store.query(`SELECT r.*,i.namespace,i.service FROM repairs r JOIN incidents i ON i.id=r.incident_id WHERE r.status IN('preparing','approved','deploying') ORDER BY updated_at LIMIT 5`);
      for(const r of rows){
        try{
          if(r.status==='preparing'){
            const progress=await this.hook.call('inspect',{id:r.id});
            if(progress.status==='preparing')continue;
            if(progress.status==='awaiting_pull_request'){await this.store.query('UPDATE repairs SET result=$2,updated_at=now() WHERE id=$1',[r.id,progress]);continue;}
            if(progress.status!=='ready')throw new Error('Repair preparation failed');
            const snapshot=validateSnapshot(progress.snapshot);
            if(snapshot.target.namespace!==r.namespace)throw new Error('Repair target namespace mismatch');
            const version=versionOf(snapshot);
            await this.store.query(`UPDATE repairs SET status='ready',snapshot=$2,version_hash=$3,expires_at=now()+interval '1 day',updated_at=now() WHERE id=$1 AND status='preparing'`,[r.id,snapshot,version]);
            await this.events.publish('repair.ready',{id:r.id,namespace:r.namespace,service:r.service,status:'ready',summary:'Tested repair is ready for explicit approval',logs:[],repair:{version,pr_url:snapshot.pr_url,checks:snapshot.checks},url:`${this.config.origin}/repairs/${r.id}`},`repair-ready:${r.id}:${version}`);
          } else if(r.status==='approved'){
            const access=await this.store.query(`SELECT p.namespaces FROM browser_sessions s JOIN principals p ON p.id=s.principal_id JOIN grants g ON g.id=s.grant_id JOIN oauth_clients c ON c.id=g.client_id
              WHERE s.id_hash=$1 AND s.expires_at>now() AND p.active AND g.active AND c.active AND 'repairs:prepare'=ANY(g.scopes) AND 'repairs:prepare'=ANY(p.scopes)`,[r.approved_session]);
            if(!access.rows[0])throw new Error('Approver connection revoked');
            requireNamespace(access.rows[0],r.namespace);
            // Re-fetch and compare all code, artifact, base, checks and target state.
            const current=await this.hook.call('inspect',{id:r.id});
            if(current.status!=='ready'||versionOf(validateSnapshot(current.snapshot))!==r.version_hash)throw new Error('Approved version is stale');
            const claimed=await this.store.query(`UPDATE repairs SET status='deploying',updated_at=now() WHERE id=$1 AND status='approved' AND approved_at>now()-interval '15 minutes' RETURNING id`,[r.id]);
            if(!claimed.rows.length)throw new Error('Approval expired');
            await this.hook.call('deploy',{id:r.id,version:r.version_hash,snapshot:r.snapshot});
          } else {
            const progress=await this.hook.call('outcome',{id:r.id});
            if(progress.status==='deploying')continue;
            if(!['healthy','recovered','failed'].includes(progress.status))throw new Error('Invalid deployment outcome');
            await this.store.query(`UPDATE repairs SET status=$2,result=$3,updated_at=now() WHERE id=$1`,[r.id,progress.status,progress]);
            await this.events.publish('deployment.changed',{id:r.id,namespace:r.namespace,service:r.service,status:progress.status,summary:`Approved deployment ${progress.status}`,logs:progress.logs??[],repair:{version:r.version_hash,result:progress},url:`${this.config.origin}/repairs/${r.id}`},`deployment:${r.id}:${progress.status}`);
          }
        }catch{
          await this.store.query(`UPDATE repairs SET status='failed',result=$2,updated_at=now() WHERE id=$1`,[r.id,{reason:'Hook failed or approved state changed; inspect worker audit before retry'}]);
          await this.events.publish('deployment.changed',{id:r.id,namespace:r.namespace,service:r.service,status:'failed',summary:'Repair stopped: hook failed or tested version changed',logs:[],repair:{version:r.version_hash??null},url:`${this.config.origin}/repairs/${r.id}`},`repair-failed:${r.id}`);
        }
      }
    }finally{this.running=false;}
  }
  routes(app){
    app.get('/repairs/:id',async(req,res)=>{
      res.set('Cache-Control','no-store');
      const user=await browserIdentity(this.store,req);
      if(!user)return res.status(401).type('html').send(page('Connect your plugin first','<p>Open this review in the browser used to connect MCP-OTel. Only the authenticated installation session can approve a repair.</p>'));
      const r=await this.get({...user,id:user.principal_id},req.params.id);
      const csrf=random();await this.store.query('UPDATE browser_sessions SET csrf_hash=$2 WHERE id_hash=$1',[user.id_hash,hash(csrf)]);
      const content=`<p>Status: <strong>${escapeHtml(r.status)}</strong></p><p>${escapeHtml(r.summary)}</p>${r.snapshot?`<p><a href="${escapeHtml(r.snapshot.pr_url)}">Review pull request</a></p><p>Version <code>${escapeHtml(r.version_hash)}</code></p><pre>${escapeHtml(JSON.stringify({head:r.snapshot.head_sha,base:r.snapshot.base_sha,artifact:r.snapshot.artifact_digest,target:r.snapshot.target,checks:r.snapshot.checks},null,2))}</pre><h2>Tested change</h2><pre>${escapeHtml(r.snapshot.diff)}</pre>`:''}`;
      const form=r.status==='ready'?`<form method="post"><input type="hidden" name="csrf" value="${csrf}"><input type="hidden" name="version" value="${escapeHtml(r.version_hash)}"><button>Approve this tested version and roll out</button></form>`:'';
      res.type('html').send(page('Review repair',content+form));
    });
    app.post('/repairs/:id',async(req,res)=>{
      res.set('Cache-Control','no-store');
      const user=await browserIdentity(this.store,req);
      if(!user||req.headers.origin!==this.config.origin||!equal(user.csrf_hash,hash(req.body.csrf??'')))return res.status(403).send('Authenticated browser confirmation required');
      requireScope(user,'repairs:prepare');
      await this.get({...user,id:user.principal_id},req.params.id);
      const updated=await this.store.tx(async tx=>{
        const {rows}=await tx.query(`UPDATE repairs SET status='approved',approval_hash=version_hash,approved_session=$3,approved_at=now(),updated_at=now()
          WHERE id=$1 AND principal_id=$2 AND status='ready' AND version_hash=$4 AND expires_at>now() RETURNING id`,[req.params.id,user.principal_id,user.id_hash,req.body.version]);
        if(rows.length)await tx.query(`INSERT INTO audit(principal_id,action,subject,detail) VALUES($1,'repair.approved',$2,$3)`,[user.principal_id,req.params.id,{version:req.body.version,session_hash:user.id_hash}]);
        return rows.length;
      });
      if(!updated)return res.status(409).send('This version is stale or already approved. Reload the review.');
      res.redirect(303,`/repairs/${encodeURIComponent(req.params.id)}`);
    });
  }
}
