# Local test report

Build/test environment used for this archive:

- Node.js `v22.16.0`
- npm `10.9.2`
- Linux container
- no runtime dependencies

Commands executed:

```bash
node --check worker.js
npm run entropy-report
npm test
```

Final test result: **39/39 passing**.

Coverage includes real local HTTP upstream forwarding, the real Node adapter process, OpenAI Chat, OpenAI Responses, Anthropic Messages, non-stream JSON restoration, SSE restoration, reasoning/tool JSON delta channels, header privacy filtering, body/redaction limits, and every possible split boundary of a 75-byte redaction token while the underlying SSE transport is delivered one byte at a time.

Entropy regression result:

```text
natural false positives: 296/30000 = 0.9867%
hex    length=  9 recall=90.72%
base62 length=  9 recall=91.90%
hex    length= 12 recall=96.56%
base62 length= 12 recall=97.62%
hex    length= 16 recall=99.78%
base62 length= 16 recall=99.46%
hex    length= 24 recall=100.00%
base62 length= 24 recall=100.00%
hex    length= 32 recall=100.00%
base62 length= 32 recall=100.00%
```

Cloudflare `workerd`/Wrangler and the Deno binary were not installed in this build container, so those platform CLIs were not executed locally. `worker.js` has a regression test that forbids Node-only APIs/imports and uses only the Web Fetch/Streams/Crypto surface plus the guarded Deno direct-entry stanza.

The `G` detector now contains **218 JavaScript evaluator entries** and tests Gitleaks-style keywords/secretGroup extraction, Shannon entropy, rule-level allowlists, representative direct/assignment signatures, private keys/JWTs, and generic credential fallback. It remains intentionally serverless-portable rather than byte-for-byte execution of native Go/RE2; see `docs/GITLEAKS-COMPAT.md`.
