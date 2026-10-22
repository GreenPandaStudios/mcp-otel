import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
test('generated collection config preserves relabel captures and per-record stream identity',()=>{
  const {items}=JSON.parse(execFileSync(process.execPath,['deploy/render.js'],{encoding:'utf8'}));
  const prom=items.find(x=>x.kind==='ConfigMap'&&x.metadata.name==='prometheus').data['prometheus.yaml'];
  assert.ok(prom.includes('/nodes/$1/proxy/metrics/cadvisor'));assert.ok(prom.includes("replacement: '$1:$2'"));
  const collector=items.find(x=>x.kind==='ConfigMap'&&x.metadata.name==='collector').data['config.yaml'];
  assert.ok(collector.includes('filter/span-events'));assert.ok(!collector.includes('set(events, [])'));
  assert.ok(!collector.includes('set(resource.attributes[\\"stream\\"]'));
  const role=items.find(x=>x.kind==='ClusterRole'&&x.metadata.name.endsWith('-mcp-otel'));
  assert.ok(!role.rules.some(r=>(r.resources??[]).includes('secrets')));
});
