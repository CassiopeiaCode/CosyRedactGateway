# Entropy calibration

The high-entropy detector is intentionally length-aware and runs only after lossless block tokenization.

## Why not ordinary Shannon entropy?

For short strings, empirical character-frequency Shannon entropy cannot distinguish many natural words from random tokens: a 9-character word with 9 unique characters and a 9-character random token with 9 unique characters both have `log2(9)` empirical bits/character. Hex strings are another failure mode because their alphabet caps ordinary entropy near 4 bits/character.

Cosy Redact Gateway therefore scores each ASCII alphanumeric block using a smoothed English character-bigram cross-entropy model and separately requires minimum observed-symbol diversity.

## Runtime rule

1. Split on whitespace and special characters; keep original offsets.
2. Ignore blocks of length `<= 8`.
3. Ignore numeric-only blocks for `H` (phone, ID, and bank detectors handle numeric structures).
4. Compute bigram cross entropy.
5. Interpolate a length-dependent threshold.
6. Require a small Shannon-diversity floor to reject repetitive strings.

Threshold anchors committed in `worker.js`:

| Length | bits/char |
|---:|---:|
| 9 | 5.4240 |
| 10 | 5.3667 |
| 11 | 5.3423 |
| 12 | 5.2820 |
| 13 | 5.2565 |
| 16 | 5.1799 |
| 20 | 5.0612 |
| 24 | 4.9833 |
| 32 | 4.8907 |
| 40 | 4.8327 |
| 48 | 4.7662 |
| 56 | 4.7277 |
| 64 | 4.7052 |
| 80 | 4.6549 |
| 96 | 4.6248 |
| 112 | 4.5948 |
| 128+ | 4.5660 |

The anchors are linearly interpolated. The 128 threshold is used as a floor beyond 128 characters rather than decreasing forever.

## Regression criterion

`test/entropy.test.js` deterministically generates 30,000 natural-language concatenation blocks from a held-out word fixture across lengths 9–128. Current result: 296 classifications, or `0.9867%` false positives.

The same test suite generates random hex and base62-like blocks and asserts increasing recall as length increases.

This is a practical calibration, not a claim that English bigram cross entropy is a universal semantic detector. Identifiers, minified code, hashes, non-English transliterations, and unusual product names can still look secret-like; that is why `H` remains independently selectable through the URL flags.
