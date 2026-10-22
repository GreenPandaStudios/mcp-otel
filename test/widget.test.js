import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
test('repair view completes the host handshake and opens review only from user click',()=>{
  const source=readFileSync(new URL('../src/repair-widget.html',import.meta.url),'utf8').match(/<script>([\s\S]*)<\/script>/)[1];
  const messages=[],elements=new Map();let listener;
  const parent={postMessage:m=>messages.push(m)},document={getElementById:id=>{if(!elements.has(id))elements.set(id,{});return elements.get(id);}};
  vm.runInNewContext(source,{parent,document,URL,addEventListener:(_name,fn)=>{listener=fn;}});
  assert.equal(messages[0].method,'ui/initialize');
  listener({source:parent,data:{jsonrpc:'2.0',id:1,result:{}}});assert.equal(messages[1].method,'ui/notifications/initialized');
  listener({source:parent,data:{method:'ui/notifications/tool-result',params:{structuredContent:{status:'ready',review_url:'https://otel.example/repairs/repair_1',version_hash:'version',snapshot:{checks:[]}}}}});
  assert.equal(elements.get('status').textContent,'Status: ready');assert.equal(messages.length,2);
  elements.get('review').onclick({preventDefault(){}});assert.equal(messages[2].method,'ui/open-link');assert.equal(messages[2].params.url,'https://otel.example/repairs/repair_1');
});
