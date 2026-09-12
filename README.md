# Cosy Redact Gateway

> **Use the upstream you need. Keep the secrets it doesn't.**

**Cosy Redact Gateway** is a drop-in privacy relay for LLM APIs. Point your existing OpenAI- or Anthropic-compatible client at the proxy, and sensitive values are replaced with reversible `{{Redact:...}}` placeholders **before they reach the upstream model**. When the model returns those placeholders—whether in normal text, JSON, SSE, or tool-call arguments—the proxy restores the original values on the way back.

**Single file · zero runtime dependencies · Cloudflare Workers · Deno · Node 20+ · streaming-safe**

### Why use it?

- **Keep your existing client.** Change the base URL; Cosy Redact Gateway preserves the upstream wire format instead of translating it.
- **Protect prompts and tools.** Messages, tool inputs/results, and other JSON strings are scanned before forwarding.
- **Restore transparently.** Known placeholders are restored in regular responses and streaming tool/function-call deltas.
- **Choose your protection level.** Enable high-entropy detection, phone, `sk-` secrets, PRC ID, bank card, email, and a broad Gitleaks-compatible rule set with compact URL flags.
- **Run almost anywhere.** The deployable `worker.js` only uses Web Fetch, Web Streams, and Web Crypto APIs.

### 30-second example

Keep the original upstream URL after `$` and put the enabled detector flags before it:

```text
https://proxy.example.com/HPSE$https://api.openai.com/v1/chat/completions
```

Or enable **everything** by leaving the flag section empty:

```text
https://proxy.example.com/$https://api.openai.com/v1/responses
```

The data path is intentionally simple:

```text
client request
    │
    ├─ detect sensitive values
    ├─ replace them with {{Redact:<sha256>}}
    ├─ add a short Redact Notice to the last user message
    ▼
untrusted upstream model
    │
    ├─ model may echo placeholders in text or tool calls
    ▼
Cosy Redact Gateway restores known placeholders
    │
    ▼
client receives the original sensitive values
```

The replacement table is request-local and never persisted.

A tool round-trip looks like this:

```text
client/tool result:   {"email":"alice@example.com"}
upstream model sees:  {"email":"{{Redact:…}}"}
model tool call:      {"email":"{{Redact:…}}"}
client receives:      {"email":"alice@example.com"}
```

## Routing

The proxy follows the same URL-routing idea as TransformVetter: the proxy configuration and the real upstream URL live in the path.

```text
https://<proxy-host>/<flags>$<upstream-url>
```

Examples:

```text
https://proxy.example.com/HPSE$https://api.openai.com/v1/chat/completions
https://proxy.example.com/E$https://api.openai.com/v1/responses
https://proxy.example.com/P$https://api.anthropic.com/v1/messages
https://proxy.example.com/$https://api.example.com/v1/responses
```

An empty flag section means **all rules enabled**.

| Flag | Detector |
|---|---|
| `H` | length-aware high-entropy ASCII alphanumeric blocks (`length > 8`) |
| `P` | phone numbers (PRC mobile plus international `+...` form) |
| `S` | `sk-` followed by 60+ ASCII alphanumeric characters |
| `I` | PRC citizen identity number with checksum validation |
| `B` | 13-19 digit bank-card candidates with Luhn validation, including common grouped forms |
| `E` | email addresses |
| `G` | broad serverless Gitleaks-compatible rule evaluator (218 JS entries; keywords, secret groups, Shannon entropy, allowlists); see [Gitleaks compatibility](docs/GITLEAKS-COMPAT.md) |

The canonical all-on string is `HPSIBEG`, but `/$https://...` is preferred when everything should be enabled.

Unknown flag letters fail with HTTP 400 instead of silently changing policy.

## Supported LLM wire formats

The proxy **does not translate protocols**. It preserves the request shape and only edits string values that may contain sensitive text.

It has explicit notice injection and stream handling for:

- OpenAI Chat Completions (`/v1/chat/completions`)
- OpenAI Responses (`/v1/responses`)
- Anthropic Messages (`/v1/messages`)

Unknown JSON endpoints are still proxied and redacted generically, but no protocol-specific user-message notice is injected unless the body can be recognized as one of the supported families.

Headers such as `Authorization`, `x-api-key`, `anthropic-version`, OpenAI project/organization headers, and arbitrary provider headers are forwarded. Hop-by-hop headers plus proxy/browser identity headers (`Cookie`, `CF-*`, `Sec-*`, forwarding IP headers, etc.) are removed so the relay does not accidentally disclose its own session or network identity to an untrusted upstream. Upstream redirects are not followed.

## Redaction lifecycle

At runtime/isolate startup, `worker.js` generates a random 256-bit salt. For every request it creates a fresh in-memory replacement table.

A sensitive value becomes:

```text
{{Redact:<sha256-hex>}}
```

where the digest is:

```text
SHA-256(original_text + runtime_salt)
```

The same plaintext in the same runtime therefore gets the same token, and the same request reuses one mapping entry. The mapping is never persisted and is discarded after the request/response stream completes.

The implementation deliberately does not expose the salt or plaintext in response headers or logs.

### Redact Notice

The notice is **always enabled**; it is not a URL flag. Redaction happens first, then the following English metadata is inserted at byte/character position 0 of the last user message:

```text
Sensitive values are redacted before forwarding, including messages, tool inputs, and tool results. You may see {{Redact:sha256}} placeholders; treat them as opaque and preserve them exactly. Sensitive values you read appear as placeholders, and placeholders you emit in text or tool calls are restored to the original secrets.
```

This is deliberately short, but it tells the model both directions of the contract: **reads are redacted before reaching the model; outputs are restored before reaching the client**. That includes placeholders inside tool/function-call arguments as well as ordinary assistant text. Tool results or other sensitive tool content sent back to the model in a later request are scanned and redacted again before forwarding.

For OpenAI Responses with a string `input`, the notice is prefixed to that string. For array/message forms it is prefixed to the last `role: "user"` textual content block. If there is no user message, nothing artificial is added.

## Streaming

`text/event-stream` responses are restored incrementally with downstream backpressure.

The stream layer understands text/delta channels used by OpenAI Chat, OpenAI Responses, and Anthropic Messages, including tool/function argument deltas and common reasoning/text delta fields. A partial prefix of a possible `{{Redact:...}}` token is retained until enough subsequent SSE data proves that it is either a complete known token or cannot become one.

This means a token split across HTTP chunks **and** across logical SSE events is restored correctly. The tests exhaust every possible split position of a 75-byte placeholder and also exercise one-byte transport chunks.

## High-entropy detector

`H` runs only after tokenizing text into ASCII alphanumeric blocks separated by whitespace/special characters. It never scans blocks of length 8 or less, and numeric-only blocks are left to the structured phone/ID/bank detectors.

It uses an English character-bigram cross-entropy score rather than ordinary empirical Shannon entropy. The decision threshold decreases with block length and is linearly interpolated between calibrated anchors. A small symbol-diversity check rejects repetitive strings.

The deterministic local regression fixture currently produces:

- natural-word concatenations: `296 / 30000 = 0.9867%` classified high entropy
- random hex/base62 recall: about 91-92% at length 9, 96-98% at length 12, >99% around length 16, and 100% in the sampled length-24/32 sets

See [docs/ENTROPY.md](docs/ENTROPY.md) and run `npm run entropy-report` to reproduce the report.

## Cloudflare Workers

No build step is required.

```bash
npm install
npm test
npx wrangler deploy
```

`wrangler.toml` points directly at `worker.js`.

You can also paste/upload `worker.js` as a module Worker. The module exports:

```js
export default {
  fetch(request, env, ctx) { ... }
}
```

Recommended production variable:

```text
REDACT_ALLOWED_HOSTS=api.openai.com,api.anthropic.com,my-provider.example
```

Without `REDACT_ALLOWED_HOSTS`, the proxy accepts arbitrary `http://` and `https://` upstream hosts because arbitrary upstream routing is part of the design. Do not expose an unrestricted instance publicly unless you intentionally want an open relay.

## Deno

The same file can run directly:

```bash
deno run --allow-net --allow-env worker.js
```

or be used as the entry file in a Deno Deploy project. At direct execution, the bottom of `worker.js` calls `Deno.serve(...)`; when imported as a Cloudflare Worker module that branch is inert.

Environment variables are read with `Deno.env.toObject()` only in direct Deno mode.

## Local Node server

Node is only a development adapter; `worker.js` itself does not import Node APIs.

```bash
npm start
```

Default address:

```text
http://127.0.0.1:8787
```

Example:

```bash
curl -N \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $OPENAI_API_KEY" \
  --data '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"mail me at alice@example.com"}],"stream":true}' \
  'http://127.0.0.1:8787/E$https://api.openai.com/v1/chat/completions'
```

## Runtime settings

| Variable | Default | Meaning |
|---|---:|---|
| `REDACT_ALLOWED_HOSTS` | unset | comma-separated hostname allow-list; unset allows arbitrary upstreams |
| `REDACT_BLOCK_PRIVATE_UPSTREAMS` | `true` | block private, loopback, link-local, and metadata upstream addresses after host normalization; set to `false` only for a trusted private deployment |
| `REDACT_PARSE_NESTED_JSON` | `true` | recursively redact JSON-looking string values (including tool-call `arguments`); set to `false` for legacy text-only handling |
| `REDACT_MAX_BODY_BYTES` | 16 MiB | maximum request body buffered for safe JSON redaction |
| `REDACT_MAX_REDACTIONS` | 16384 | maximum unique plaintext replacements in one request |
| `REDACT_CORS_ORIGIN` | `*` | `Access-Control-Allow-Origin` value |
| `HOST` | `127.0.0.1` | Node local adapter only |
| `PORT` | `8787` | Node local adapter only |

Private, loopback, link-local, and metadata upstream addresses are blocked by default after the upstream host is parsed and normalized. Disable this only for a deliberately trusted private deployment. JSON-looking string fields are parsed and redacted recursively when possible, then serialized back to strings; this includes tool-call `arguments`.

Non-empty request bodies must be JSON. This is intentional fail-closed behavior: an unknown binary or plaintext body is rejected with 415 instead of being forwarded without redaction.

Large base64 image/audio payload fields and URL/control fields are excluded from text redaction to avoid corrupting multimodal requests. The defaults are intentionally generous for large LLM payloads; on memory-constrained deployments, lower `REDACT_MAX_BODY_BYTES` and/or `REDACT_MAX_REDACTIONS` explicitly.

## Tests

```bash
npm test
```

The suite covers:

- URL flag/default routing and upstream query preservation
- lossless text-block offsets
- email, phone, `sk-`, PRC ID, Luhn bank card, and representative Gitleaks-compatible provider rules
- repeated-value token reuse and exact restoration
- OpenAI Chat, OpenAI Responses, and Anthropic Messages request bodies
- Redact Notice placement
- authorization/API-key forwarding and stripping of proxy-only identity headers
- JSON fail-closed behavior and redaction limits
- real local HTTP upstream integration
- real local Node adapter integration
- non-stream restoration
- OpenAI Chat/Responses and Anthropic SSE
- tool/reasoning/partial-JSON delta fields
- one-byte HTTP chunks and every placeholder split boundary
- length-aware entropy Monte Carlo regression
- static Web-API-only portability check for `worker.js`

GitHub Actions runs the same test suite on every push and pull request.

The `G` rule signatures are partly derived from Gitleaks; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Security notes

This relay reduces what an untrusted upstream sees, but it is not a cryptographic sandbox and no pattern detector can guarantee discovery of every secret. In particular:

- a model can modify a placeholder instead of echoing it, in which case it cannot be restored;
- a detector false negative is still sent upstream;
- an unrestricted deployment is an open proxy unless you set `REDACT_ALLOWED_HOSTS` or protect the Worker externally;
- runtime salts are isolate-local, not globally stable across Cloudflare/Deno instances;
- replacement state is intentionally request-local, so a placeholder from an older request cannot be restored later;
- image/audio binary content is not inspected by this text-focused implementation.

See [SECURITY.md](SECURITY.md) for deployment guidance.

## TransformVetter relationship

The URL envelope intentionally follows TransformVetter's documented `/{config}${upstream-url}` proxy convention, while this project uses a much smaller letter-flag config and **pass-through protocol semantics**. It does not include TransformVetter's protocol conversion or moderation engine.

TransformVetter: https://github.com/CassiopeiaCode/TransformVetter

## Acknowledgements

Community support matters. ❤️

[Linux.do](https://linux.do/)  
Thanks to the support from Linux.do

## License

MIT.

## Rambling

~~However, Fengfeng10 added no value to this project.~~
