import { hash, random, equal, escapeHtml } from './security.js';
import crypto from 'node:crypto';

export const SCOPES = ['telemetry:read', 'events:subscribe', 'repairs:read', 'repairs:prepare'];
const cookieName = '__Host-mcp_otel';
export function sessionCookie(req) {
  return req.headers.cookie?.split(';').map(s => s.trim()).find(s => s.startsWith(cookieName + '='))?.slice(cookieName.length + 1);
}
export async function browserIdentity(store, req) {
  const token = sessionCookie(req);
  if (!token) return null;
  const { rows } = await store.query(`SELECT s.*, ARRAY(SELECT unnest(g.scopes) INTERSECT SELECT unnest(p.scopes)) AS scopes, p.namespaces, p.name FROM browser_sessions s
    JOIN principals p ON p.id=s.principal_id JOIN grants g ON g.id=s.grant_id
    JOIN oauth_clients c ON c.id=g.client_id
    WHERE s.id_hash=$1 AND s.expires_at>now() AND p.active AND g.active AND c.active`, [hash(token)]);
  return rows[0] ?? null;
}
export async function bearerIdentity(store, req) {
  const match = /^Bearer ([A-Za-z0-9_-]{32,128})$/.exec(req.headers.authorization ?? '');
  if (!match) return null;
  const { rows } = await store.query(`SELECT p.id, p.name, p.namespaces, ARRAY(SELECT unnest(g.scopes) INTERSECT SELECT unnest(p.scopes)) AS scopes, g.id AS grant_id
    FROM oauth_tokens t JOIN grants g ON g.id=t.grant_id JOIN principals p ON p.id=g.principal_id
    JOIN oauth_clients c ON c.id=g.client_id
    WHERE t.token_hash=$1 AND t.kind='access' AND t.expires_at>now() AND NOT t.consumed
    AND p.active AND g.active AND c.active`, [hash(match[1])]);
  return rows[0] ?? null;
}
export function challenge(origin) {
  return `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource", error="invalid_token", error_description="Connect your authorized MCP-OTel account"`;
}
function noCache(res) { res.set('Cache-Control','no-store'); }
export function requireScope(identity, scope) {
  if (!identity?.scopes.includes(scope)) throw Object.assign(new Error('Insufficient scope'), { code: -32001, authScope:scope });
}
export function requireNamespace(identity, namespace) {
  if (!identity || (!identity.namespaces.includes('*') && !identity.namespaces.includes(namespace))) throw Object.assign(new Error('Namespace not authorized'), { code: -32001 });
}
export function authRoutes(app, store, config) {
  const { origin } = config;
  app.get(['/.well-known/oauth-protected-resource','/.well-known/oauth-protected-resource/mcp'], (_req,res) => res.json({resource:origin,authorization_servers:[origin],scopes_supported:SCOPES}));
  app.get('/.well-known/oauth-authorization-server', (_req,res) => res.json({
    issuer:origin, authorization_response_iss_parameter_supported:true,
    authorization_endpoint:`${origin}/oauth/authorize`, token_endpoint:`${origin}/oauth/token`,
    revocation_endpoint:`${origin}/oauth/revoke`, response_types_supported:['code'],
    grant_types_supported:['authorization_code','refresh_token'],
    token_endpoint_auth_methods_supported:['client_secret_basic'], code_challenge_methods_supported:['S256'], scopes_supported:SCOPES
  }));
  // A predefined confidential client belongs to one private ChatGPT connection.
  // Public source/package contains neither its ID nor secret. There is no DCR,
  // public sign-up, implicit owner enrollment, or user-supplied principal ID.
  async function clientRequest(req) {
    const q = req.method === 'GET' ? req.query : req.body;
    const { rows } = await store.query(`SELECT c.*,p.active AS owner_active,p.scopes FROM oauth_clients c JOIN principals p ON p.id=c.principal_id WHERE c.id=$1`, [q.client_id]);
    const c = rows[0], scopes = String(q.scope ?? '').split(' ').filter(Boolean);
    if (!c?.active || !c.owner_active || !c.redirects.includes(q.redirect_uri) || q.response_type !== 'code'
      || q.resource !== origin || q.code_challenge_method !== 'S256' || !/^[\w-]{43}$/.test(q.code_challenge ?? '')
      || !q.state || String(q.state).length > 2048 || !scopes.length || scopes.some(s => !c.scopes.includes(s))) throw new Error('Invalid authorization request');
    return { c, q, scopes };
  }
  app.get('/oauth/authorize', async (req,res) => {
    noCache(res);
    const { q } = await clientRequest(req);
    // Browsers also enforce form-action on the POST's redirect. Allow only
    // the callback origin from the already validated client registration.
    res.set('Content-Security-Policy',res.get('Content-Security-Policy').replace("form-action 'self';",`form-action 'self' ${new URL(q.redirect_uri).origin};`));
    const sid = random(), csrf = random();
    await store.query(`INSERT INTO browser_sessions(id_hash,csrf_hash,expires_at) VALUES($1,$2,now()+interval '10 minutes')`, [hash(sid),hash(csrf)]);
    res.cookie(cookieName,sid,{httpOnly:true,secure:true,sameSite:'lax',path:'/',maxAge:30*86400000});
    const fields = Object.entries({...q, csrf}).filter(([k]) => ['client_id','redirect_uri','response_type','resource','code_challenge','code_challenge_method','scope','state','csrf'].includes(k))
      .map(([k,v])=>`<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join('');
    res.type('html').send(page('Connect MCP-OTel', `<p>Connect your MCP client to this private installation.</p><p>Requested access: <code>${escapeHtml(q.scope)}</code>.</p><p>Rollouts require separate approval of the exact tested change.</p><form method="post">${fields}<button>Connect this installation</button></form>`));
  });
  app.post('/oauth/authorize', async (req,res) => {
    noCache(res);
    if (req.headers.origin !== origin) return res.status(403).send('Invalid origin');
    const { c,q,scopes } = await clientRequest(req);
    const sid = sessionCookie(req), code = random();
    const { rows } = await store.query(`SELECT * FROM browser_sessions WHERE id_hash=$1 AND expires_at>now() AND principal_id IS NULL`,[hash(sid ?? '')]);
    if (!rows[0] || !equal(rows[0].csrf_hash,hash(req.body.csrf ?? ''))) return res.status(403).send('Invalid browser session');
    await store.query(`INSERT INTO oauth_codes(code_hash,client_id,session_hash,redirect_uri,challenge,scopes,resource,expires_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,now()+interval '60 seconds')`, [hash(code),c.id,hash(sid),q.redirect_uri,q.code_challenge,scopes,origin]);
    const url = new URL(q.redirect_uri); url.searchParams.set('code',code); url.searchParams.set('state',q.state); url.searchParams.set('iss',origin);
    res.redirect(303,url.href);
  });
  async function privateClient(req, tx) {
    const match = /^Basic ([A-Za-z0-9+/=]+)$/.exec(req.headers.authorization ?? '');
    if (!match) throw new Error('invalid_client');
    const pair = Buffer.from(match[1],'base64').toString(), colon = pair.indexOf(':');
    if (colon < 0) throw new Error('invalid_client');
    const id = decodeURIComponent(pair.slice(0,colon)), secret = decodeURIComponent(pair.slice(colon+1));
    const { rows } = await tx.query(`SELECT c.* FROM oauth_clients c JOIN principals p ON p.id=c.principal_id WHERE c.id=$1 AND c.active AND p.active`,[id]);
    if (!rows[0] || !equal(rows[0].secret_hash,hash(secret))) throw new Error('invalid_client');
    return rows[0];
  }
  async function issue(tx, grant) {
    const access = random(), refresh = random();
    await tx.query(`INSERT INTO oauth_tokens(token_hash,grant_id,kind,expires_at) VALUES($1,$3,'access',now()+interval '1 hour'),($2,$3,'refresh',now()+interval '30 days')`, [hash(access),hash(refresh),grant.id]);
    return {access_token:access,refresh_token:refresh,token_type:'Bearer',expires_in:3600,scope:grant.scopes.join(' ')};
  }
  app.post('/oauth/token', async (req,res) => {
    noCache(res);
    try {
      const result = await store.tx(async tx => {
        const c = await privateClient(req,tx);
        if (req.body.resource !== origin) throw new Error('invalid_target');
        if (req.body.grant_type === 'authorization_code') {
          const { rows } = await tx.query(`DELETE FROM oauth_codes WHERE code_hash=$1 RETURNING *`,[hash(req.body.code ?? '')]);
          const code = rows[0], verifier = req.body.code_verifier ?? '';
          if (!code || code.client_id !== c.id || code.redirect_uri !== req.body.redirect_uri || new Date(code.expires_at)<=new Date()
            || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || code.resource !== origin
            || !equal(code.challenge,crypto.createHash('sha256').update(verifier).digest('base64url'))) throw new Error('invalid_grant');
          const grant = {id:random(),scopes:code.scopes};
          await tx.query(`INSERT INTO grants(id,principal_id,client_id,scopes) VALUES($1,$2,$3,$4)`,[grant.id,c.principal_id,c.id,grant.scopes]);
          // Only successful confidential token exchange authenticates this browser.
          await tx.query(`UPDATE browser_sessions SET principal_id=$2,grant_id=$3,expires_at=now()+interval '30 days' WHERE id_hash=$1`,[code.session_hash,c.principal_id,grant.id]);
          await tx.query(`INSERT INTO audit(principal_id,action,subject) VALUES($1,'connection.authorized',$2)`,[c.principal_id,grant.id]);
          return issue(tx,grant);
        }
        if (req.body.grant_type === 'refresh_token') {
          const { rows } = await tx.query(`SELECT t.*,g.client_id,g.scopes FROM oauth_tokens t JOIN grants g ON g.id=t.grant_id WHERE t.token_hash=$1 AND t.kind='refresh' AND g.active FOR UPDATE OF t`,[hash(req.body.refresh_token ?? '')]);
          const t=rows[0];
          if (!t || t.client_id!==c.id || new Date(t.expires_at)<=new Date()) throw new Error('invalid_grant');
          if (t.consumed) { await tx.query(`UPDATE grants SET active=false WHERE id=$1`,[t.grant_id]); return {error:'invalid_grant'}; }
          await tx.query(`UPDATE oauth_tokens SET consumed=true WHERE token_hash=$1`,[t.token_hash]);
          return issue(tx,{id:t.grant_id,scopes:t.scopes});
        }
        throw new Error('unsupported_grant_type');
      });
      res.status(result.error ? 400 : 200).json(result);
    } catch(e) { res.status(e.message==='invalid_client' ? 401 : 400).json({error:['invalid_client','invalid_target','unsupported_grant_type'].includes(e.message)?e.message:'invalid_grant'}); }
  });
  app.post('/oauth/revoke',async(req,res)=>{
    noCache(res);
    try {
      await store.tx(async tx=>{
        const c=await privateClient(req,tx);
        await tx.query(`UPDATE grants SET active=false WHERE client_id=$1 AND id IN(SELECT grant_id FROM oauth_tokens WHERE token_hash=$2)`,[c.id,hash(req.body.token??'')]);
      }); res.sendStatus(200);
    } catch {res.status(401).json({error:'invalid_client'});}
  });
}
export function page(title,body) {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font:16px system-ui;color:#dce8ef;background:#101b22;max-width:960px;margin:5vh auto;padding:24px}h1{font-size:30px}p{line-height:1.6}button,a.button{background:#b3f17f;color:#17251a;border:0;padding:12px 20px;border-radius:8px;font:inherit;cursor:pointer}pre{white-space:pre-wrap;word-break:break-word;background:#172630;padding:20px;border-radius:8px}a{color:#b3f17f}code{word-break:break-word}</style><h1>${escapeHtml(title)}</h1>${body}</html>`;
}
