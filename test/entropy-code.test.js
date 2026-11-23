import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { isHighEntropyBlock, entropyThreshold, parseFlags, RedactionContext } from '../worker.js';
globalThis.crypto ??= webcrypto;

test('short blocks, numbers and repeated patterns stay intact', () => {
  for (const word of ['abc123', '12345678901234567890', 'zzzzzzzzzzzzzz', 'zxzxzxzxzxzxzxzx', 'configuration', 'authentication']) {
    assert.equal(isHighEntropyBlock(word), false, word);
  }
  assert.equal(entropyThreshold(8), Infinity);
});

test('H detection preserves offsets and supports exact restoration and existing tokens', async () => {
  const value = 'q7x9v2k8z4m6p3w5r1t0';
  assert.equal(isHighEntropyBlock(value), true);
  const ctx = new RedactionContext({ salt: 'entropy-test' });
  const input = `说明 configuration ${value} 结束`;
  const redacted = await ctx.redactText(input, parseFlags('H'));
  assert.notEqual(redacted, input);
  assert.equal(ctx.restoreText(redacted), input);
  assert.equal(await ctx.redactText(redacted, parseFlags('H')), redacted);
  assert.equal(await ctx.redactText(input, parseFlags('P')), input);
});

test('natural code identifiers with digits do not trigger H', () => {
  for (const name of ['judgeable100', 'example2026', 'configuration123', 'httpVersion11', 'sha256Digest']) {
    assert.equal(isHighEntropyBlock(name), false, name);
  }
});
