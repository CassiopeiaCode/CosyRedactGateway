import test from 'node:test';
import assert from 'node:assert/strict';
import { parseFlags, RedactionContext, handleRequest } from '../worker.js';

test('manual literals are case sensitive, reversible, flag controlled, and preserve tokens', async () => {
  const ctx = new RedactionContext({salt:'manual-test',manualWords:['内部代号','a.b']});
  const input='内部代号 a.b A.B aXb 内部代号';
  const output=await ctx.redactText(input,parseFlags('M'));
  assert(!output.includes('内部代号'));
  assert(!output.includes('a.b'));
  assert(output.includes('A.B aXb'));
  assert.equal(ctx.restoreText(output),input);
  assert.equal(await ctx.redactText(output,parseFlags('M')),output);
  assert.equal(await ctx.redactText(input,parseFlags('E')),input);
  assert.equal(parseFlags('').manual,true);
});

test('invalid manual configuration fails before forwarding only when M is enabled', async () => {
  for (const bad of ['invalid','{}','[""]','[1]']) {
    const response=await handleRequest(new Request('https://p/M$https://example.com'),{REDACT_MANUAL_WORDS:bad},{fetchImpl:async()=>{throw new Error('must not forward');}});
    assert.equal(response.status,500);
  }
  const response=await handleRequest(new Request('https://p/E$https://example.com'),{REDACT_MANUAL_WORDS:'invalid'},{fetchImpl:async()=>new Response('ok')});
  assert.equal(response.status,200);
});
