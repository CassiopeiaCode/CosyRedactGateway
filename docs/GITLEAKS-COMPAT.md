# Gitleaks compatibility

`G` is a serverless-portable execution layer for the current public Gitleaks default-rule style. It is designed for Cloudflare Workers/Deno, so it cannot invoke the native Go Gitleaks binary or its RE2 engine.

The rule pack in `worker.js` is derived from the public Gitleaks default configuration (`config/gitleaks.toml`) as reviewed on 2026-09-11. The upstream file identifies itself as the generated default Gitleaks configuration and currently declares `minVersion = "v8.25.0"`.

## What is executed

The bundled evaluator currently contains **218 JavaScript evaluator entries**. That number is not intended to equal the number of upstream TOML rules: an upstream rule with several RE2 capture alternatives may be split into multiple JS entries, and a generic fallback is included for privacy-proxy use.

For supported rules, the evaluator implements these Gitleaks concepts rather than treating the config as regex-only:

- keyword prefilters;
- JavaScript-safe ports of provider/token regex signatures;
- `secretGroup`-style extraction so only the credential is replaced instead of the surrounding assignment;
- Shannon entropy thresholds used by Gitleaks rules;
- rule-level regex allowlists;
- stopwords for the generic credential fallback.

The pack covers direct/prefixed credentials and assignment-style credentials across major cloud, AI, source-control, package, messaging, payment, monitoring, CI/CD, database, identity and SaaS providers. It also includes private-key/JWT-like signatures, curl authorization forms, and a content-port of the Kubernetes Secret YAML rule.

`H` is separate. `G` uses ordinary Shannon entropy where an upstream Gitleaks rule specifies an entropy floor. `H` uses this project's length-aware character-language cross-entropy detector.

## Intentional serverless differences

Exact byte-for-byte parity with native Gitleaks is not claimed.

1. **RE2 vs JavaScript RegExp.** Gitleaks regexes can contain RE2/Go forms such as inline/scoped flags, POSIX classes and `\z`. Those patterns are manually represented by JavaScript-safe equivalents.
2. **Path conditions.** An LLM JSON request body has no source-repository filename. Pure path-only detections therefore cannot run. When an upstream rule has both a content regex and a path restriction, this proxy generally executes the content detector without the path restriction, preferring privacy over fewer false positives.
3. **Global allowlists.** Repository/path/commit-specific global allowlists are not meaningful for arbitrary LLM request text. The proxy implements high-value rule-level secret allowlists and a deliberately smaller generic stopword set. This is intentionally more sensitive than native Gitleaks in some contexts.
4. **Multi-capture rules.** When one upstream RE2 rule can return secrets from several alternative capture groups (for example curl authorization forms), the proxy splits it into multiple JavaScript evaluator entries.
5. **Line/file semantics.** Rules whose behavior depends on source line, commit, file extension or repository layout cannot be reproduced exactly from a JSON string value.

For this threat model, a false negative can disclose a secret to an untrusted upstream, so ambiguous compatibility choices are biased toward detection. Users who require conformance with the native Gitleaks CLI should run native Gitleaks/RE2 before this proxy rather than treating `G` as a drop-in scanner replacement.

## Updating

When updating the embedded rule pack, compare against:

- `https://github.com/gitleaks/gitleaks`
- `https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml`

Then run `npm test`. `test/gitleaks.test.js` checks the portable entry count, representative direct-provider signatures, assignment `secretGroup` behavior, Gitleaks entropy behavior, allowlists, private keys/JWTs, and generic credential fallback.

See `THIRD_PARTY_NOTICES.md` for license attribution.
