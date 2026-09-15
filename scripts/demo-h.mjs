#!/usr/bin/env node
/**
 * Local, synthetic-fixture demonstration of H's contribution.
 * No network, provider key, SDK, or external dependency is used.
 * Calls the checked-out worker.js rather than reimplementing its detector.
 * This is NOT a maskit benchmark or a production leak-rate measurement.
 * Run: node scripts/demo-h.mjs [--json]
 */
import assert from 'node:assert/strict';

const unexpected = process.argv.slice(2).filter((arg) => arg !== '--json');
if (unexpected.length) {
  console.error('Usage: node scripts/demo-h.mjs [--json]\nOnly built-in synthetic fixtures are accepted.');
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
  for (const [policy, value] of [['H off', 'PSIBEG'], ['H only', 'H'], ['All on', '']]) {
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
    kind: 'Synthetic local H contribution demonstration; not a comparative security benchmark',
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
    console.log('\nCosy / H contribution — local synthetic fixture, no network\n');
    console.log('Input:', input);
    console.table(results.map((r) => ({
      policy: r.policy, flags: r.flags,
      'covered chars': `${r.redactedCandidateCharacters}/${r.candidateCharacters}`,
      'match types': r.matchingTypes.join(', ') || '(none)',
      'exact round trip': r.restoredExactly,
    })));
    console.table(exclusions);
    console.log('All-on rewritten text:', results[2].redactedText);
    console.log('\nChecks:', checks);
    console.log('\nOnly these synthetic fixtures were tested. No maskit process or model was called.');
  }

  assert.ok(Object.values(checks).every(Boolean),
    'A documented demonstration check failed. Review this checkout before publishing its output.');
} catch (error) {
  console.error(`H demonstration failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
