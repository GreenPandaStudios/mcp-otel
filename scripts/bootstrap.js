import { readFile, writeFile } from 'node:fs/promises';
import { Store } from '../src/store.js';
import { random, hash } from '../src/security.js';
import { SCOPES } from '../src/auth.js';

// Run once from an administrator-controlled shell. Never put the resulting
// confidential connection credentials in a public plugin manifest or logs.
const path=process.env.BOOTSTRAP_FILE;
if(!path)throw new Error('Set BOOTSTRAP_FILE to an owner-only output path');
let credentials;
try{credentials=JSON.parse(await readFile(path,'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;}
credentials??={principal_id:'prf_'+random(),client_id:'mcp_otel_'+random(),client_secret:random(48),redirects:['https://chatgpt.com/connector_platform_oauth_redirect']};
const store=new Store(process.env.DATABASE_URL);await store.migrate();
await store.tx(async tx=>{
  await tx.query(`INSERT INTO principals(id,name,scopes,namespaces) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING`,[credentials.principal_id,'Cluster owner',SCOPES,['*']]);
  await tx.query(`INSERT INTO oauth_clients(id,secret_hash,principal_id,redirects) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING`,[credentials.client_id,hash(credentials.client_secret),credentials.principal_id,credentials.redirects]);
});
await writeFile(path,JSON.stringify(credentials,null,2)+'\n',{mode:0o600});
console.log('Private OAuth connection provisioned; credentials saved to BOOTSTRAP_FILE.');
await store.close();
