# Reduct Proxy

A dependency-free serverless privacy relay for LLM APIs. It redacts sensitive values **before** sending JSON to an upstream provider, keeps the plaintext mapping only for the lifetime of the request, and restores placeholders in normal JSON responses and SSE streams.

The proxy is intentionally protocol-preserving: it does **not** translate OpenAI ↔ Anthropic formats. The routing shape follows the same `/{config}${upstream}` idea used by TransformVetter, while the body remains in the client's original protocol.

## Supported API families

- OpenAI Chat Completions (`/v1/chat/completions` and compatible endpoints)
- OpenAI Responses (`/v1/responses` and compatible endpoints)
- Anthropic Messages (`/v1/messages` and compatible endpoints)
- Generic JSON pass-through also works, but Reduct Notice injection is only guaranteed when a recognizable `messages` or `input` shape exists.

Both normal responses and `text/event-stream` responses are supported. Streaming restoration handles placeholders split across **HTTP chunks and separate logical SSE delta events**.

## URL format

```text
https://YOUR_PROXY/<FLAGS>$<UPSTREAM_URL>
```

Example:

```text
https://proxy.example.com/HPSE$https://api.openai.com/v1/chat/completions
```

Flags are case-insensitive and order-independent:

| Flag | Detector |
|---|---|
| `H` | Dynamic high-entropy block detector |
| `P` | Phone numbers |
| `S` | `sk-` followed by 60+ alphanumeric characters |
| `I` | PRC 18-digit resident ID with checksum validation |
| `B` | 13–19 digit bank-card candidates with Luhn validation |
| `E` | Email addresses |
| `G` | Gitleaks-style portable secret rule pack |

No flags means **all flags are enabled**:

```text
https://proxy.example.com/$https://api.openai.com/v1/responses
```

Unknown flags return HTTP 400 instead of silently weakening protection.

## Reduct Notice

The notice is always enabled and has no flag. Redaction happens first, then the notice is inserted at byte/string position 0 of the last user text message:

```text
We have redacted sensitive content before forwarding this request. You may see sensitive values represented as placeholders in the form {{reduct:sha256}}. You may reproduce these placeholders exactly as shown; our system will automatically restore the original sensitive text in the response.
```

For OpenAI Responses with a string `input`, the notice is prepended directly. For message/content arrays, the first text block of the last `user` message is prefixed; if the user message is image/tool-only, a text block is inserted first.

## Placeholder design

At runtime startup/isolate creation a random 256-bit salt is generated. For each sensitive plaintext `x`:

```text
{{reduct:hex(sha256(x + startup_salt))}}
```

Example shape:

```text
{{reduct:5e1c...64-hex-characters...a901}}
```

The request owns two temporary maps (`plaintext → token` and `token → plaintext`). Equal plaintext in one request reuses the same token. The maps are never persisted and disappear after that request/stream completes.

A placeholder-looking value supplied by the client is not nested and is never restored unless it is an exact token generated in the current request.

## High-entropy detector

`H` first tokenizes text into ASCII alphanumeric blocks using spaces and special characters as separators. Only blocks with **more than 8 characters** are evaluated.

The score is character-bigram cross entropy, not naive character-frequency Shannon entropy. The threshold decreases with block length (about `5.424 bits/char` at length 9 to `4.566` at 128+). A Shannon-diversity guard prevents repetitive strings such as `aaaaaaaaaaaa` from being classified as secret-like solely because their English transition probability is unusual.

The committed Monte Carlo regression test uses a held-out word set and 30,000 randomly concatenated natural-language blocks; the current deterministic run classifies 296/30,000 (`0.9867%`) as high entropy, satisfying the requested `<1%` boundary. Random hex/base62 recall is separately tested.

See [`docs/ENTROPY.md`](docs/ENTROPY.md).

## Request safety behavior

This proxy is designed for the case where the upstream is not trusted with plaintext:

- API authentication headers such as `Authorization`, `x-api-key`, `anthropic-version`, OpenAI organization/project headers, etc. are forwarded.
- Network-origin headers such as `cf-connecting-ip`, `x-forwarded-for`, `x-real-ip`, `forwarded`, `cf-ray`, and hop-by-hop headers are stripped.
- Request bodies with data must be JSON. Non-JSON bodies fail with 415 rather than being forwarded unredacted.
- Invalid JSON fails with 400.
- Oversized bodies or too many distinct redactions fail closed with 413.
- Image/audio/base64 payload fields are skipped so the proxy does not replace random-looking media bytes.
- Response JSON is parsed and reserialized during restoration so plaintext containing quotes/backslashes cannot corrupt JSON.

Defaults:

```text
REDUCT_MAX_BODY_BYTES = 4194304
REDUCT_MAX_REDACTIONS = 4096
```

Optional environment variables:

| Variable | Meaning |
|---|---|
| `REDUCT_ALLOWED_HOSTS` | Comma-separated upstream host allow-list. Empty = arbitrary HTTP/HTTPS upstreams allowed. |
| `REDUCT_MAX_BODY_BYTES` | Maximum request body size. |
| `REDUCT_MAX_REDACTIONS` | Maximum number of distinct plaintext values per request. |
| `REDUCT_CORS_ORIGIN` | CORS allow-origin value. Default `*`. |

For an Internet-facing deployment, setting `REDUCT_ALLOWED_HOSTS` is strongly recommended.

## Cloudflare Workers

`worker.js` is already a single-file ES module and has no runtime dependencies.

With Wrangler installed:

```bash
npx wrangler deploy
```

Or paste `worker.js` into a module-style Cloudflare Worker. `wrangler.toml` is included.

## Deno / Deno Deploy

The same file is directly executable:

```bash
deno run --allow-net worker.js
```

If you want the optional environment settings locally, also grant `--allow-env`.

## Node local server

Node 20+ (Node 22 is used by CI):

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
  --data '{"model":"gpt-5","input":"email me at private@example.com","stream":true}' \
  'http://127.0.0.1:8787/E$https://api.openai.com/v1/responses'
```

## Tests

```bash
npm test
```

The suite covers:

- flag/default routing and upstream query preservation;
- all built-in structured detectors and overlap priority;
- deterministic hashing/reuse and current-request-only restoration;
- OpenAI Chat, OpenAI Responses, and Anthropic request notice injection;
- image/base64 skip behavior;
- normal JSON restoration;
- real local HTTP upstream forwarding and API-key preservation;
- fail-closed body/redaction limits;
- SSE placeholders split across separate logical delta events;
- arbitrary HTTP transport chunking;
- every possible split position inside a 75-character placeholder;
- JSON escaping after streamed restoration;
- high-entropy false-positive and random-secret recall regression tests.

## G flag / Gitleaks compatibility

The `G` flag is deliberately implemented without native binaries or WASM so this repository stays a single JavaScript file on Cloudflare and Deno. The official Gitleaks default configuration uses Go RE2 syntax plus per-rule keyword, path, allowlist, and entropy semantics, some of which do not map exactly to JavaScript `RegExp`.

The included portable rule pack covers common provider credential families and a generic credential assignment rule, but it is **not a byte-for-byte execution of every current upstream Gitleaks rule**. See [`docs/GITLEAKS-COMPAT.md`](docs/GITLEAKS-COMPAT.md). If exact Gitleaks parity is mandatory, the correct next step is a RE2/WASM rule engine rather than pretending incompatible regex semantics are identical.

## License

MIT.
