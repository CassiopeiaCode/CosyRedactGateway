#!/usr/bin/env node
/**
 * Local, synthetic-fixture demonstration of high-entropy credential detection.
 * No network, provider key, SDK, or external dependency is used.
 * Calls the checked-out worker.js rather than reimplementing its detector.
 * These synthetic fixtures do not measure production leak rates.
 * Run: node scripts/demo-high-entropy.mjs [--json] [--lang=zh|en]
 */
import assert from 'node:assert/strict';

const args = process.argv.slice(2);
const english = args.includes('--lang=en');
const unexpected = args.filter((arg) => !['--json', '--lang=en', '--lang=zh'].includes(arg));
if (unexpected.length) {
  console.error('Usage: node scripts/demo-high-entropy.mjs [--json] [--lang=zh|en]\nOnly built-in synthetic fixtures are accepted.');
  process.exit(2);
}

try {
  const core = await import('../worker.js');
  for (const name of ['parseFlags', 'isHighEntropyBlock', 'findSensitiveSpans', 'RedactionContext']) {
    assert.equal(typeof core[name], 'function', `worker.js must export ${name}. Check the repository revision.`);
  }
  const { parseFlags, isHighEntropyBlock, findSensitiveSpans, RedactionContext } = core;
  const candidate = 'q7X9v2L5m8N4r6T1w3Y0z5A8b2C9d7F4';
  const prefix = 'Inspect this value: ';
  const input = prefix + candidate;
  const start = prefix.length, end = input.length;
  const flags = parseFlags('');
  assert.ok(Object.values(flags).every(Boolean), 'Empty flags should enable every detector.');

  // Count union coverage within the candidate, not merely disappearance of its
  // full string. A partial match must never be mislabeled as full redaction.
  function coverage(spans) {
    const intervals = spans.map(({ start: a, end: b }) => [Math.max(start, a), Math.min(end, b)])
      .filter(([a, b]) => b > a).sort((a, b) => a[0] - b[0]);
    let covered = 0, right = start;
    for (const [a, b] of intervals) {
      covered += Math.max(0, b - Math.max(a, right));
      right = Math.max(right, b);
    }
    return covered;
  }

  const results = [];
  for (const [policy, value] of [[english ? 'High-entropy off' : '关闭高熵检测', 'PSIBEG'], [english ? 'High-entropy only' : '仅高熵检测', 'H'], [english ? 'All detectors on' : '全部启用', '']]) {
    const enabled = parseFlags(value);
    const spans = findSensitiveSpans(input, enabled);
    const context = new RedactionContext();
    const redacted = await context.redactText(input, enabled);
    const restored = context.restoreText(redacted);
    assert.equal(restored, input, `${policy}: round-trip restoration must preserve the original string.`);
    const covered = coverage(spans);
    results.push({
      policy, flags: value || '(empty = HPSIBEG)',
      candidateCharacters: candidate.length,
      redactedCandidateCharacters: covered,
      fullyRedacted: covered === candidate.length,
      matchingTypes: [...new Set(spans.filter((s) => s.end > start && s.start < end).map((s) => s.type))],
      restoredExactly: restored === input,
      redactedText: redacted,
    });
  }

  const exclusions = [
    ['8-character block', 'q7X9v2L5'],
    ['numeric-only block', '4928107365948271036594827103659482'],
    ['repetitive block', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
  ].map(([name, value]) => ({ name, matchedByH: isHighEntropyBlock(value) }));

  const checks = {
    emptyFlagsEnableAll: true,
    syntheticCandidateMatchedByH: isHighEntropyBlock(candidate),
    hOnlyCoversWholeCandidate: results[1].fullyRedacted,
    allOnCoversWholeCandidate: results[2].fullyRedacted,
    documentedExclusionsHold: exclusions.every((r) => !r.matchedByH),
    allRoundTripsExact: results.every((r) => r.restoredExactly),
  };
  const report = {
    kind: 'Synthetic local high-entropy detection demonstration; not a production leak-rate measurement',
    runtime: process.version,
    syntheticInput: input,
    results, exclusions, checks,
    // H-off is observed, not forced to miss: another detector may gain coverage
    // in a later revision. That should not invalidate a truthful demonstration.
    extraCoverageForThisCandidate: results[2].redactedCandidateCharacters - results[0].redactedCandidateCharacters,
  };

  if (process.argv.includes('--json')) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(english
      ? '\nCosy / High-entropy credential detection — local synthetic fixture, no network\n'
      : '\nCosy / 高熵凭据检测 — 本地合成样例，不联网\n');
    console.log(english ? 'Input:' : '输入：', input);
    console.table(results.map((r) => ({
      [english ? 'policy' : '策略']: r.policy, [english ? 'flags' : '开关']: r.flags,
      [english ? 'covered chars' : '覆盖字符数']: `${r.redactedCandidateCharacters}/${r.candidateCharacters}`,
      [english ? 'match types' : '命中类型']: r.matchingTypes.join(', ') || (english ? '(none)' : '（无）'),
      [english ? 'exact round trip' : '精确还原']: r.restoredExactly,
    })));
    console.table(exclusions);
    console.log(english ? 'All-on rewritten text:' : '全开后的文本：', results[2].redactedText);
    console.log(english ? '\nChecks:' : '\n检查：', checks);
    console.log(english
      ? '\nOnly these synthetic fixtures were tested. No network or model was used; results do not measure production leak rates.'
      : '\n只检查上述合成样例；未联网或调用模型，不代表生产环境泄漏率。');
  }

  assert.ok(Object.values(checks).every(Boolean),
    'A documented demonstration check failed. Review this checkout before publishing its output.');
} catch (error) {
  console.error(`High-entropy detection demonstration failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
