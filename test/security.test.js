import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { cipher,canonical,signature,verifySignature,secretKey,isPublicIP,callbackURL,publicPost,redact } from '../src/security.js';
import { bounds } from '../src/telemetry.js';
import { validateSnapshot,versionOf } from '../src/repairs.js';

test('Standard Webhooks signature covers exact bytes, ID, timestamp, and rejects replay',()=>{
  const secret='whsec_'+randomBytes(32).toString('base64'),body='{"eventId":"evt_1","data":{"status":"open"}}',ts=Math.floor(Date.now()/1000);
  const headers={'webhook-id':'evt_1','webhook-timestamp':String(ts),'webhook-signature':signature(secret,'evt_1',ts,body)};
  assert.equal(verifySignature(secret,headers,body),true);
  assert.equal(verifySignature(secret,headers,body+' '),false);
  assert.equal(verifySignature(secret,{...headers,'webhook-id':'evt_2'},body),false);
  assert.equal(verifySignature(secret,headers,body,Date.now()+600000),false);
  for(const invalid of ['plain','whsec_AAAA','whsec_%%%'])assert.throws(()=>secretKey(invalid));
});
test('subscription secrets are authenticated ciphertext and cannot be read with another key',()=>{
  const c=cipher(randomBytes(32).toString('base64')),value=c.seal('private-key');
  assert.equal(c.open(value),'private-key');assert.ok(!value.includes('private-key'));
  assert.throws(()=>cipher(randomBytes(32).toString('base64')).open(value));
  const bytes=Buffer.from(value,'base64');bytes[30]^=1;assert.throws(()=>c.open(bytes.toString('base64')));
});
test('callback boundary blocks IPv4/IPv6 internal, mapped, metadata and non-HTTPS destinations',async()=>{
  for(const a of ['127.0.0.1','10.0.0.1','192.168.1.1','169.254.169.254','100.64.0.1','0.0.0.0','224.0.0.1','::1','fe80::1','fc00::1','::ffff:127.0.0.1','2001:db8::1'])assert.equal(isPublicIP(a),false,a);
  assert.equal(isPublicIP('8.8.8.8'),true);
  for(const u of ['http://example.com','https://a:b@example.com','https://example.com:8443','https://example.com/#x'])assert.throws(()=>callbackURL(u));
  assert.throws(()=>callbackURL('https://attacker.example',['chatgpt.com']));
  await assert.rejects(publicPost('https://public.example/callback','{}',{},[],async()=>[{address:'8.8.8.8',family:4},{address:'127.0.0.1',family:4}]),/non-public/);
});
test('bounds constrain time, result sizes, and future or invalid ranges',()=>{
  const now=Date.now();assert.equal(bounds({},now).limit,100);
  for(const input of [{limit:501},{limit:0},{start:'bad'},{start:new Date(now-3600001).toISOString(),end:new Date(now).toISOString()},{end:new Date(now+120000).toISOString()}])assert.throws(()=>bounds(input,now));
});
test('redaction removes structured and textual credentials and private message bodies',()=>{
  const result=redact({authorization:'Bearer secret',api_key:'secret',messages:[{content:'private'}],line:'{"token": "sensitive", "prompt": "private body"}'});
  assert.equal(result.api_key,'[REDACTED]');assert.equal(result.messages,'[REDACTED]');
  assert.ok(!JSON.stringify(result).includes('sensitive'));assert.ok(!JSON.stringify(result).includes('private body'));
  assert.equal(canonical({b:2,a:1}),canonical({a:1,b:2}));
});
export function snapshot(){return {pr_url:'https://github.com/example/project/pull/1',branch:'codex/repair-example',head_sha:'a'.repeat(40),base_sha:'b'.repeat(40),artifact_digest:'sha256:'+'c'.repeat(64),previous_digest:'sha256:'+'d'.repeat(64),checks:[{name:'tests',head_sha:'a'.repeat(40),status:'passed',evidence_hash:'e'.repeat(64)}],diff:'- broken\n+ fixed',target:{namespace:'synthetic',deployment:'demo',container:'demo'}};}
test('approval identity includes code, base, artifacts, checks and rollout target',()=>{
  const s=snapshot();validateSnapshot(s);const version=versionOf(s);
  for(const changed of [{...s,head_sha:'e'.repeat(40)},{...s,base_sha:'e'.repeat(40)},{...s,artifact_digest:'sha256:'+'e'.repeat(64)},{...s,checks:[{...s.checks[0],evidence_hash:'other'}]},{...s,target:{...s.target,deployment:'other'}}])assert.notEqual(versionOf(changed),version);
  assert.throws(()=>validateSnapshot({...s,checks:[{...s.checks[0],status:'failed'}]}));
  assert.throws(()=>validateSnapshot({...s,branch:'main'}));
});
