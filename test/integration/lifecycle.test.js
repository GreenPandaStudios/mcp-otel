import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomBytes,createHash } from 'node:crypto';
import { Store } from '../../src/store.js';
import { hash,cipher,verifySignature } from '../../src/security.js';
import { Events } from '../../src/events.js';
import { Repairs } from '../../src/repairs.js';
import { Incidents } from '../../src/incidents.js';
import { createApp } from '../../src/server.js';
import { SCOPES } from '../../src/auth.js';

test('Postgres-backed OAuth, durable event and approval lifecycle',{skip:!process.env.TEST_DATABASE_URL},async t=>{
  const db=new URL(process.env.TEST_DATABASE_URL);
  assert.match(db.pathname,/_test$/,'Integration tests require a dedicated _test database');
  const store=new Store(db.href);await store.migrate();
  await store.query('TRUNCATE principals,oauth_clients,browser_sessions,oauth_codes,grants,oauth_tokens,subscriptions,events,deliveries,incidents,repairs,audit RESTART IDENTITY CASCADE');
  t.after(()=>store.close());
  const config={origin:'https://otel.example.test',callbackHosts:['callback.example'],alertKey:'test-alert-key'};
  const crypto=cipher(randomBytes(32).toString('base64')),secret='whsec_'+randomBytes(32).toString('base64');
  const received=[];let failNext=false;
  const sender=async(url,body,headers)=>{
    const data=JSON.parse(body);assert.equal(verifySignature(secret,headers,body),true);
    if(data.type==='verification')return {status:200,body:JSON.stringify({challenge:data.challenge})};
    received.push({data,headers,body});if(failNext){failNext=false;return {status:503,body:''};}return {status:200,body:''};
  };
  let events=new Events(store,config,crypto,sender);
  const telemetry={logs:async()=>({logs:[{timestamp:new Date().toISOString(),namespace:'synthetic',pod:'demo',stream:'stderr',line:'synthetic failure token=secret-value'}]}),backends:async()=>({}),health:async()=>({pods:[]}),kube:{health:async()=>({pods:[]})}};
  const initialSnapshot={pr_url:'https://github.com/example/repo/pull/1',branch:'codex/repair-1',head_sha:'a'.repeat(40),base_sha:'b'.repeat(40),artifact_digest:'sha256:'+'c'.repeat(64),previous_digest:'sha256:'+'d'.repeat(64),checks:[{name:'tests',head_sha:'a'.repeat(40),status:'passed',evidence_hash:'f'.repeat(64)}],diff:'- broken\n+ fixed',target:{namespace:'synthetic',deployment:'demo',container:'demo'}};
  let snapshot=structuredClone(initialSnapshot),deployments=0;
  const hook={enabled:true,call:async(action)=>{if(action==='inspect')return {status:'ready',snapshot};if(action==='deploy'){deployments++;return {status:'deploying'};}if(action==='outcome')return {status:'healthy',verified:true};return {status:'preparing'};}};
  const repairs=new Repairs(store,config,events,hook),incidents=new Incidents(store,telemetry,events,config);
  const app=createApp({store,config,telemetry,events,repairs,incidents}),server=app.listen(0,'127.0.0.1');await once(server,'listening');
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const base=`http://127.0.0.1:${server.address().port}`;
  const basic='Basic '+Buffer.from('owner-client:owner-secret').toString('base64');
  await store.query(`INSERT INTO principals(id,name,scopes,namespaces) VALUES('owner','Owner',$1,ARRAY['synthetic'])`,[SCOPES]);
  await store.query(`INSERT INTO oauth_clients(id,secret_hash,principal_id,redirects) VALUES('owner-client',$1,'owner',ARRAY['https://chatgpt.com/connector_platform_oauth_redirect'])`,[hash('owner-secret')]);
  const verifier='v'.repeat(64),params={client_id:'owner-client',redirect_uri:'https://chatgpt.com/connector_platform_oauth_redirect',response_type:'code',resource:config.origin,scope:SCOPES.join(' '),state:'outer-state',code_challenge_method:'S256',code_challenge:createHash('sha256').update(verifier).digest('base64url')};
  let access,cookie,grantId;
  const rpc=async(method,params={},token=access)=>{
    const r=await fetch(base+'/mcp',{method:'POST',headers:{'content-type':'application/json','mcp-protocol-version':'2026-07-28',...(token?{authorization:`Bearer ${token}`}:{})},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});
    return {status:r.status,body:await r.json()};
  };
  await t.test('unauthenticated calls fail; discovery and OAuth metadata remain usable',async()=>{
    assert.equal((await rpc('tools/list')).status,401);
    assert.equal((await rpc('server/discover')).body.result.supportedVersions[0],'2026-07-28');
    const r=await fetch(base+'/.well-known/oauth-authorization-server');assert.ok((await r.json()).code_challenge_methods_supported.includes('S256'));
  });
  await t.test('PKCE, exact resource, confidential connection and browser proof are required',async()=>{
    const r=await fetch(base+'/oauth/authorize?'+new URLSearchParams(params));cookie=r.headers.getSetCookie()[0].split(';')[0];
    assert.equal(r.headers.get('referrer-policy'),'same-origin','Browser form POSTs must preserve the same-origin Origin header');
    const csrf=(await r.text()).match(/name="csrf" value="([^"]+)"/)[1];
    const opaqueOrigin=await fetch(base+'/oauth/authorize',{method:'POST',redirect:'manual',headers:{'content-type':'application/x-www-form-urlencoded',cookie,origin:'null'},body:new URLSearchParams({...params,csrf})});
    assert.equal(opaqueOrigin.status,403,'Opaque origins remain unauthorized');
    const consent=await fetch(base+'/oauth/authorize',{method:'POST',redirect:'manual',headers:{'content-type':'application/x-www-form-urlencoded',cookie,origin:config.origin},body:new URLSearchParams({...params,csrf})});
    const callback=new URL(consent.headers.get('location'));assert.equal(callback.searchParams.get('iss'),config.origin);assert.equal(callback.searchParams.get('state'),'outer-state');
    const code=callback.searchParams.get('code'),body={grant_type:'authorization_code',code,redirect_uri:params.redirect_uri,code_verifier:verifier,resource:config.origin};
    const token=async(data,authorization=basic)=>fetch(base+'/oauth/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',authorization},body:new URLSearchParams(data)});
    assert.equal((await token(body,'Basic '+Buffer.from('owner-client:wrong').toString('base64'))).status,401);
    assert.equal((await token({...body,resource:'https://another.example'})).status,400);
    assert.equal((await token({...body,code_verifier:'x'.repeat(64)})).status,400);
    const result=await token(body);assert.equal(result.status,200);const tokens=await result.json();access=tokens.access_token;
    assert.equal((await token(body)).status,400,'Authorization codes are single-use');
    const profile=await rpc('tools/call',{name:'get_profile',arguments:{}});assert.equal(profile.body.result.structuredContent.id,'owner');
    grantId=(await store.query('SELECT id FROM grants WHERE principal_id=$1',['owner'])).rows[0].id;
  });
  const subscription={name:'incident.changed',arguments:{namespace:'synthetic',service:'demo'},delivery:{mode:'webhook',url:'https://callback.example/mcp-events/test',secret}};
  await t.test('event filters are authorized, subscriptions idempotent, and secrets encrypted',async()=>{
    assert.equal((await rpc('events/subscribe',{...subscription,arguments:{namespace:'other'}})).body.error.code,-32001);
    const a=(await rpc('events/subscribe',subscription)).body.result,b=(await rpc('events/subscribe',{...subscription,arguments:{service:'demo',namespace:'synthetic'}})).body.result;
    assert.equal(a.id,b.id);assert.equal(a.cursor,null);assert.ok(a.refreshBefore);
    const rows=(await store.query('SELECT * FROM subscriptions')).rows;assert.equal(rows.length,1);assert.ok(!rows[0].encrypted_secret.includes(secret));
  });
  await t.test('refresh rotates signing keys with overlap and callback failure never activates a subscription',async()=>{
    const identity={id:'owner',grant_id:grantId,scopes:SCOPES,namespaces:['synthetic']};
    const nextSecret='whsec_'+randomBytes(32).toString('base64');
    const rotating=new Events(store,config,crypto,async(_url,body,headers)=>{assert.ok(verifySignature(nextSecret,headers,body));return {status:200,body:JSON.stringify({challenge:JSON.parse(body).challenge})};});
    const refreshed=await rotating.subscribe(identity,{...subscription,delivery:{...subscription.delivery,secret:nextSecret},ttlMs:null});
    assert.ok(refreshed.refreshBefore,'Non-expiring request receives a finite grant');
    const saved=(await store.query('SELECT * FROM subscriptions WHERE id=$1',[refreshed.id])).rows[0];assert.equal(crypto.open(saved.encrypted_secret),nextSecret);assert.equal(crypto.open(saved.old_secret),secret);
    const invalid=new Events(store,config,crypto,async()=>({status:200,body:'{"challenge":"wrong"}'}));
    await assert.rejects(invalid.subscribe(identity,{...subscription,delivery:{...subscription.delivery,url:'https://callback.example/invalid'}}),e=>e.code===-32015&&e.data.reason==='challenge_failed');
    assert.equal((await store.query('SELECT count(*)::int AS n FROM subscriptions')).rows[0].n,1);
  });
  let incidentId;
  await t.test('incident includes stdout/stderr excerpts; failed delivery survives restart with stable ID',async()=>{
    incidentId=await incidents.record({source:'synthetic',namespace:'synthetic',service:'demo',status:'open',severity:'warning',summary:'Synthetic incident',fingerprint:'fixture'});
    failNext=true;await events.drain();assert.equal(received.length,1);
    assert.equal(received[0].data.data.logs[0].stream,'stderr');assert.ok(!received[0].body.includes('secret-value'));
    assert.equal(received[0].headers['webhook-signature'].split(' ').length,2,'Rotation signs with old and new keys');
    events=new Events(store,config,crypto,sender);
    await store.query(`UPDATE deliveries SET next_attempt=now()`);await events.drain();
    assert.equal(received.length,2);assert.equal(received[0].data.eventId,received[1].data.eventId);
    assert.equal((await store.query('SELECT status FROM deliveries')).rows[0].status,'delivered');
    await events.publish('incident.changed',{id:'other',namespace:'synthetic',service:'other',status:'open',summary:'Filtered out',logs:[]},'other');await events.drain();assert.equal(received.length,2);
  });
  async function approve(id,version){
    const r=await fetch(base+'/repairs/'+id,{headers:{cookie}}),html=await r.text(),csrf=html.match(/name="csrf" value="([^"]+)"/)?.[1];
    assert.ok(csrf,'Review must be available to authenticated connection browser');
    return fetch(base+'/repairs/'+id,{method:'POST',redirect:'manual',headers:{cookie,origin:config.origin,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf,version})});
  }
  const principal={id:'owner',grant_id:grantId,scopes:SCOPES,namespaces:['synthetic']};
  await t.test('bearer tools cannot approve; changed code invalidates an exact human approval',async()=>{
    const r=await repairs.prepare(principal,{incident_id:incidentId});await repairs.tick();const ready=await repairs.get(principal,r.id);assert.equal(ready.status,'ready');
    const forged=await fetch(base+'/repairs/'+r.id,{method:'POST',headers:{authorization:`Bearer ${access}`,'content-type':'application/x-www-form-urlencoded',origin:config.origin},body:new URLSearchParams({version:ready.version_hash,csrf:'invented'})});assert.equal(forged.status,403);
    assert.equal((await approve(r.id,'wrong-version')).status,409);
    assert.equal((await approve(r.id,ready.version_hash)).status,303);
    snapshot={...snapshot,base_sha:'e'.repeat(40)};await repairs.tick();assert.equal(deployments,0);assert.equal((await repairs.get(principal,r.id)).status,'failed');
  });
  await t.test('unchanged approved snapshot deploys once and stores verified outcome',async()=>{
    snapshot=structuredClone(initialSnapshot);const r=await repairs.prepare(principal,{incident_id:incidentId});await repairs.tick();const ready=await repairs.get(principal,r.id);
    assert.equal((await approve(r.id,ready.version_hash)).status,303);await repairs.tick();await repairs.tick();assert.equal(deployments,1);assert.equal((await repairs.get(principal,r.id)).status,'healthy');
    assert.equal((await store.query(`SELECT count(*)::int AS n FROM audit WHERE action='repair.approved'`)).rows[0].n,2);
  });
  await t.test('unsubscribe and connection revocation suppress queued events',async()=>{
    await rpc('events/unsubscribe',subscription);await rpc('events/unsubscribe',subscription);
    await events.publish('incident.changed',{id:'after-stop',namespace:'synthetic',service:'demo',status:'open',summary:'After stop',logs:[]},'after-stop');await events.drain();assert.equal(received.length,2);
    await rpc('events/subscribe',subscription);
    await events.publish('incident.changed',{id:'queued',namespace:'synthetic',service:'demo',status:'open',summary:'Queued',logs:[]},'queued');
    await store.query('UPDATE grants SET active=false WHERE id=$1',[grantId]);await events.drain();assert.equal(received.length,2);assert.equal((await rpc('tools/list')).status,401);
  });
});
