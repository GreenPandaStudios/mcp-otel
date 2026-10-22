import Ajv from 'ajv';
import { hash, random, canonical, secretKey, signature, equal, publicPost, callbackURL, redact } from './security.js';
import { requireScope, requireNamespace } from './auth.js';

const filters = {type:'object',properties:{namespace:{type:'string',minLength:1,maxLength:63},service:{type:'string',minLength:1,maxLength:253}},required:['namespace'],additionalProperties:false};
export const eventDefinitions = ['incident.changed','repair.ready','deployment.changed'].map(name=>({
  name, description:({ 'incident.changed':'Incident opened, evidence updated, or recovered. Includes bounded redacted stdout/stderr excerpts.', 'repair.ready':'A tested repair is ready for human review. Includes exact version, checks, and review link.', 'deployment.changed':'An approved deployment completed, failed, or recovered.' })[name],
  delivery:['webhook'],inputSchema:filters,
  payloadSchema:{type:'object',properties:{id:{type:'string'},namespace:{type:'string'},service:{type:'string'},status:{type:'string'},summary:{type:'string'},evidence:{type:'object'},logs:{type:'array',maxItems:20,items:{type:'object'}},repair:{type:'object'},url:{type:'string'}},required:['id','namespace','service','status','summary','logs'],additionalProperties:false}
}));
const ajv = new Ajv(), validateFilters = ajv.compile(filters), validatePayload = ajv.compile(eventDefinitions[0].payloadSchema);
const eventNames = new Set(eventDefinitions.map(e=>e.name));
export class CallbackError extends Error {
  constructor(reason){ super('Callback could not be verified');this.code=-32015;this.data={reason}; }
}
export class Events {
  constructor(store,config,crypto,sender=publicPost){this.store=store;this.config=config;this.crypto=crypto;this.sender=sender;this.running=false;}
  identity(principal,params){
    requireScope(principal,'events:subscribe');
    if (!eventNames.has(params.name) || !validateFilters(params.arguments)) throw new Error('Invalid event or filters');
    requireNamespace(principal,params.arguments.namespace);
    if(params.delivery?.mode!=='webhook') throw new Error('Only webhook delivery is supported');
    callbackURL(params.delivery.url,this.config.callbackHosts);
    return 'sub_'+hash(canonical([principal.id,params.delivery.url,params.name,params.arguments]));
  }
  async send(sub,event,verification=false){
    const body=JSON.stringify(event);
    if(Buffer.byteLength(body)>262144) throw new Error('Event exceeds payload bound');
    const timestamp=String(Math.floor(Date.now()/1000)),id=verification?'verification_'+random():event.eventId;
    let sig=signature(this.crypto.open(sub.encrypted_secret),id,timestamp,body);
    if(sub.old_secret && new Date(sub.rotate_until)>new Date()) sig+=' '+signature(this.crypto.open(sub.old_secret),id,timestamp,body);
    return this.sender(sub.url,body,{'webhook-id':id,'webhook-timestamp':timestamp,'webhook-signature':sig,'X-MCP-Subscription-Id':sub.id},this.config.callbackHosts);
  }
  async subscribe(principal,params){
    const id=this.identity(principal,params);
    secretKey(params.delivery.secret);
    if(params.ttlMs!==undefined && params.ttlMs!==null && (!Number.isSafeInteger(params.ttlMs)||params.ttlMs<=0)) throw new Error('Invalid subscription lifetime');
    // Non-expiring requests are deliberately granted a finite, refreshable day.
    const ttl=Math.max(60000,Math.min(params.ttlMs??86400000,86400000));
    if(params.cursor!==undefined&&params.cursor!==null) throw new Error('Replay is not advertised; cursor must be null');
    const sub={id,url:params.delivery.url,encrypted_secret:this.crypto.seal(params.delivery.secret)};
    const challenge=random();let response;
    try{response=await this.send(sub,{type:'verification',challenge},true);}catch(e){throw new CallbackError(/timeout/i.test(e.message)?'timeout':'destination_rejected');}
    let echoed;try{echoed=JSON.parse(response.body).challenge;}catch{}
    if(response.status<200||response.status>=300||typeof echoed!=='string'||!equal(challenge,echoed)) throw new CallbackError('challenge_failed');
    const expiration=new Date(Date.now()+ttl).toISOString();
    await this.store.tx(async tx=>{
      await tx.query('SELECT pg_advisory_xact_lock(6194302)');
      const {rows}=await tx.query(`SELECT count(*)::int AS n FROM subscriptions WHERE principal_id=$1 AND active AND expires_at>now() AND id<>$2`,[principal.id,id]);
      if(rows[0].n>=50) throw new Error('Subscription limit reached');
      await tx.query(`INSERT INTO subscriptions(id,principal_id,grant_id,name,arguments,url,encrypted_secret,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET
        old_secret=CASE WHEN subscriptions.encrypted_secret<>excluded.encrypted_secret THEN subscriptions.encrypted_secret ELSE subscriptions.old_secret END,
        rotate_until=now()+interval '5 minutes',encrypted_secret=excluded.encrypted_secret,expires_at=excluded.expires_at,active=true,grant_id=excluded.grant_id`,
        [id,principal.id,principal.grant_id,params.name,params.arguments,sub.url,sub.encrypted_secret,expiration]);
      await tx.query(`INSERT INTO audit(principal_id,action,subject) VALUES($1,'events.subscribe',$2)`,[principal.id,id]);
    });
    return {id,refreshBefore:expiration,cursor:null,truncated:false};
  }
  async unsubscribe(principal,params){
    const id=this.identity(principal,params);
    await this.store.tx(async tx=>{
      await tx.query('SELECT pg_advisory_xact_lock(6194302)');
      await tx.query(`UPDATE subscriptions SET active=false WHERE id=$1 AND principal_id=$2`,[id,principal.id]);
      await tx.query(`UPDATE deliveries SET status='cancelled' WHERE subscription_id=$1 AND status='pending'`,[id]);
      await tx.query(`INSERT INTO audit(principal_id,action,subject) VALUES($1,'events.unsubscribe',$2)`,[principal.id,id]);
    }); return {};
  }
  async publish(name,payload,dedupe,transaction=null){
    payload=redact(payload);
    if(!eventNames.has(name)||!validatePayload(payload)||Buffer.byteLength(JSON.stringify(payload))>240000) throw new Error('Invalid event payload');
    const publish=async tx=>{
      await tx.query('SELECT pg_advisory_xact_lock(6194302)');
      const {rows}=await tx.query(`INSERT INTO events(id,name,namespace,service,payload,dedupe_key) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(dedupe_key) DO NOTHING RETURNING *`,['evt_'+random(),name,payload.namespace,payload.service,payload,dedupe]);
      if(!rows[0])return null;
      await tx.query(`INSERT INTO deliveries(subscription_id,event_seq)
        SELECT s.id,$1 FROM subscriptions s JOIN principals p ON p.id=s.principal_id JOIN grants g ON g.id=s.grant_id JOIN oauth_clients c ON c.id=g.client_id
        WHERE s.active AND s.expires_at>now() AND p.active AND g.active AND c.active AND 'events:subscribe'=ANY(g.scopes) AND 'events:subscribe'=ANY(p.scopes) AND s.name=$2
        AND s.arguments->>'namespace'=$3 AND (NOT s.arguments ? 'service' OR s.arguments->>'service'=$4)
        AND ('*'=ANY(p.namespaces) OR $3=ANY(p.namespaces))`,[rows[0].seq,name,payload.namespace,payload.service]);
      return rows[0].id;
    };
    return transaction?publish(transaction):this.store.tx(publish);
  }
  async drain(){
    if(this.running)return;this.running=true;
    try{
      // One worker lease is held across the send, so refresh/unsubscribe/revocation
      // committed before this claim suppresses delivery. An in-flight HTTPS send
      // may finish before unsubscribe returns; no later send is started.
      const jobs=await this.store.tx(async tx=>{
        await tx.query(`UPDATE deliveries d SET status='cancelled' FROM subscriptions s,grants g,principals p,oauth_clients c
          WHERE d.subscription_id=s.id AND g.id=s.grant_id AND p.id=s.principal_id AND c.id=g.client_id AND d.status='pending'
          AND (NOT s.active OR s.expires_at<=now() OR NOT g.active OR NOT p.active OR NOT c.active OR NOT 'events:subscribe'=ANY(g.scopes) OR NOT 'events:subscribe'=ANY(p.scopes) OR NOT ('*'=ANY(p.namespaces) OR s.arguments->>'namespace'=ANY(p.namespaces)))`);
        const {rows}=await tx.query(`SELECT d.subscription_id,d.event_seq FROM deliveries d WHERE d.status='pending' AND d.next_attempt<=now() AND (d.lease_until IS NULL OR d.lease_until<now()) ORDER BY d.event_seq LIMIT 10 FOR UPDATE SKIP LOCKED`);
        for(const j of rows)await tx.query(`UPDATE deliveries SET lease_until=now()+interval '30 seconds' WHERE subscription_id=$1 AND event_seq=$2`,[j.subscription_id,j.event_seq]);
        return rows;
      });
      for(const j of jobs){
        const {rows}=await this.store.query(`SELECT s.*,e.id AS event_id,e.name AS event_name,e.payload,e.occurred_at,d.attempts FROM deliveries d
          JOIN subscriptions s ON s.id=d.subscription_id JOIN events e ON e.seq=d.event_seq JOIN principals p ON p.id=s.principal_id
          JOIN grants g ON g.id=s.grant_id JOIN oauth_clients c ON c.id=g.client_id
          WHERE d.subscription_id=$1 AND d.event_seq=$2 AND d.status='pending' AND s.active AND s.expires_at>now() AND p.active AND g.active AND c.active AND 'events:subscribe'=ANY(g.scopes) AND 'events:subscribe'=ANY(p.scopes) AND ('*'=ANY(p.namespaces) OR s.arguments->>'namespace'=ANY(p.namespaces))`,[j.subscription_id,j.event_seq]);
        if(!rows[0])continue;
        const s=rows[0];let status=0;
        try{status=(await this.send(s,{eventId:s.event_id,name:s.event_name,timestamp:new Date(s.occurred_at).toISOString(),data:s.payload,cursor:null})).status;}catch{}
        const success=status>=200&&status<300, permanent=[400,401,403,404,410,413].includes(status), exhausted=s.attempts+1>=12;
        const delay=Math.min(3600000,1000*2**Math.min(s.attempts,12))+Math.floor(Math.random()*1000);
        await this.store.query(`UPDATE deliveries SET status=$3,attempts=attempts+1,last_status=$4,lease_until=NULL,next_attempt=now()+$5*interval '1 millisecond' WHERE subscription_id=$1 AND event_seq=$2`,[j.subscription_id,j.event_seq,success?'delivered':permanent||exhausted?'failed':'pending',status,delay]);
        if(status===410)await this.store.query('UPDATE subscriptions SET active=false WHERE id=$1',[s.id]);
      }
    }finally{this.running=false;}
  }
}
