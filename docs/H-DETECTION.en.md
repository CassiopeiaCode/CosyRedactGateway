# High-entropy credential detection

[简体中文](HIGH-ENTROPY.md) · [English README](../README.en.md) · [Technical reference](REFERENCE.en.md)

This note covers the implementation, existing synthetic-fixture results, verification steps, and security boundaries of high-entropy credential detection. Published results are not a fresh test of your current checkout; run the demonstration and regression tests against your own revision. The gateway tests were not rerun for this documentation update, which is not a security audit.

<a id="claim"></a>
The routing flag `H` selects high-entropy credential detection. Empty flags enable every detector, including high-entropy detection.

## The claim worth making

**High-entropy detection adds a detection path for eligible, random-looking strings without requiring a known provider prefix or a credential assignment label.** With all flags enabled, it complements Cosy's structured detectors and Gitleaks-compatible rules.

“Your code goes to AI. Your credentials shouldn't.” is an intended outcome, not a zero-leak certification. In a local deployment, matched text is replaced before the gateway forwards it. Cloudflare Workers and remote Deno deployments move that processing into another host's trust boundary.

The concrete implementation can be inspected in [`worker.js`](../worker.js): `parseFlags`, `tokenizeBlocks`, `entropyScore`, `isHighEntropyBlock`, `findSensitiveSpans`, `RedactionContext`, and `redactJson`. The public [entropy calibration document](ENTROPY.md) explains the score and thresholds.

## What high-entropy detection actually examines

High-entropy detection scores ASCII alphanumeric blocks longer than 8 characters. It excludes numeric-only blocks, uses English character-bigram cross entropy with a length-dependent threshold, and requires a minimum symbol-diversity floor. This is not a universal semantic credential detector, nor simply “Shannon entropy above a fixed number.”

Candidate spans from high-entropy detection and other enabled detectors are combined with overlap/priority handling. high-entropy detection is an additional candidate source, not a claim that all-on behavior is a mechanically independent, perfect union of every detector's matches.

Typical motivating cases are **unlabeled random-looking values** from internal services or copied tool output. These are use cases, not a guarantee for every token format. A string can be sensitive without looking random; a hash or identifier can look random without being sensitive.

## Local demonstration

```bash
node scripts/demo-high-entropy.mjs --lang=en
node scripts/demo-high-entropy.mjs --json
```

Run these from the repository root. The script imports the checked-out `worker.js`; it does not substitute a simplified detector. It compares `PSIBEG`, `H`, and the empty/all-on flags for one neutral-context synthetic candidate, counts matched character coverage within that candidate, and verifies exact restoration. Short, numeric-only, and repetitive blocks exercise documented high-entropy detection exclusions.

The high-entropy-off result is **observed rather than hardcoded to miss**. Another rule can gain coverage in a later revision. The script reports that change rather than manufacturing a difference. Its assertions fail visibly if the fixture no longer demonstrates the expected high-entropy-only / all-on coverage.

No network is used. This exercises exported detection and text-redaction functions—not SDK routing, a live upstream, or the whole HTTP gateway. README animations are separate explanatory illustrations, not recordings of this script.

## Existing calibration, not a new benchmark

The project's published documentation reports 296 of 30,000 held-out natural-word concatenations classified as high entropy (0.9867%), with random hex/base62 recall increasing with length. Those results describe the stated synthetic corpus and calibration, not a real-world leak rate. They were **not rerun as part of this documentation package**.

Reproduce the repository's own broader checks with:

```bash
npm test
npm run entropy-report
```

<a id="comparison"></a>
<a id="validation"></a>
## Verify the additional detection coverage

Keep the Cosy revision and inputs fixed, and observe these three policies:

| Policy | Flags | What to verify |
| :--- | :--- | :--- |
| High-entropy detection off | `PSIBEG` | Record actual coverage from the other detectors; do not assume they must miss. |
| High-entropy detection only | `H` | Isolate whether high-entropy detection matches, and which characters it covers. |
| All detectors enabled | Empty flags or `HPSIBEG` | Check combined coverage and exact restoration, not just disappearance of the original string. |

Use synthetic credentials and benign code in the same contexts, and check different encodings and field locations. Report misses, partial coverage, false positives, and uninspected content. Measure additional coverage on the actual fixtures; do not extrapolate it to a detection rate for every credential.

### Implementation and calibration references

Use the checked-out [`worker.js`](../worker.js), [entropy calibration](ENTROPY.md), and [local demonstration script](../scripts/demo-high-entropy.mjs) as verification entry points. Include the revision, policy, and fixture conditions when reporting results. This note adds no new performance or detection-rate claims.

## Boundaries that matter to developers

high-entropy detection can miss short, low-diversity, low-score, split or encoded secrets; delimiters split blocks, so a long overall value is not automatically an eligible high-entropy detection block. Benign identifiers, hashes, minified code and non-English transliterations can trigger false positives. Some skipped JSON control/URL/multimodal fields are not inspected, and JSON member names are not a general-purpose redaction target.

`Authorization` and `x-api-key` are intentionally forwarded to authenticate with the upstream. Requests that bypass the gateway, client fallbacks, surrounding logs, other host traffic, and remote processing environments require separate controls. Redaction can also remove context the model needs; restoration requires an unchanged, known token.

**Never replace “reduces exposure of matched payload values” with “no credential can ever leave the machine.”** Local deployment is necessary for local processing, but is not sufficient for exhaustive detection or host-wide egress protection. See [Security](../README.en.md#security) and [SECURITY.md](../SECURITY.md).

