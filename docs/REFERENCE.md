# Technical reference

[← English README](../README.md) · [← 中文 README](../README.zh-CN.md)

This reference collects the routing, lifecycle, detector, streaming, and deployment details behind the README. The authoritative implementation is [`worker.js`](../worker.js); review it alongside the [test suite](../test/), [entropy calibration](ENTROPY.md), and [security policy](../SECURITY.md).

<a id="routing"></a>
## Routing and errors

```text
https://<proxy-host>/<flags>$<full-upstream-url>
```

The flags and upstream destination live in the path. Examples:

```text
https://proxy.example.com/HPSE$https://api.openai.com/v1/chat/completions
https://proxy.example.com/E$https://api.openai.com/v1/responses
https://proxy.example.com/P$https://api.anthropic.com/v1/messages
https://proxy.example.com/$https://api.example.com/v1/responses
```

`proxy.example.com` and `api.example.com` are illustrative hostnames, not provided services. Replace them with deployments you control or trust.

The empty flag section enables `HPSIBEG`. Flag parsing is case-insensitive; unknown letters cause an error. The upstream query string is preserved. Only HTTP and HTTPS destinations are accepted, and URL userinfo is rejected. Quote complete routes in shell commands so `$` remains literal. Intermediary proxies and clients must preserve the embedded URL rather than normalizing away its `//`.

| Status | Gateway condition |
| :---: | :--- |
| `200` | `/` or `/healthz` health response; does not test upstream availability |
| `400` | Invalid flags or target URL; malformed JSON request body |
| `403` | Destination rejected by `REDACT_ALLOWED_HOSTS` |
| `404` | Missing route envelope outside the health endpoints |
| `413` | Request body or unique-redaction limit exceeded |
| `415` | Non-empty request body is not JSON |
| `502` | Upstream fetch failed |

Upstream response statuses are otherwise preserved. Redirects are not followed by the relay. A client or reverse proxy may have its own redirect behavior; do not treat the gateway's setting as a complete client-side policy.

### Headers

Upstream authentication and provider headers are forwarded, including `Authorization`, `x-api-key`, `anthropic-version`, and OpenAI organization/project headers. Cosy is not designed to hide the credentials used to authenticate to the upstream.

Hop-by-hop headers and proxy/browser identity headers—including `Cookie`, `CF-*`, `Sec-*`, and forwarding-IP headers—are filtered. Request content length is adjusted after JSON rewriting. The relay's CORS configuration is separate from authentication and upstream authorization.

<a id="lifecycle"></a>
## Redaction lifecycle

At runtime/isolate startup, the core generates a random 256-bit salt. Each request gets a fresh in-memory mapping table.

```text
original sensitive text
        ↓
SHA-256(original_text + runtime_salt)
        ↓
{{Redact:<64-character hexadecimal digest>}}
```

A full placeholder is 75 ASCII bytes. Repeated plaintext reuses the same token within a request. The same plaintext also produces the same token across requests handled by the same runtime salt, although each request's lookup table is separate. Salts are not globally stable across Workers/Deno instances.

Restoration uses the request-local token-to-plaintext map. It is not decryption of the digest. The map is discarded after the request and response stream complete; no persistent replacement database is used. This does not promise cryptographic memory erasure or control over host-level logs and observability.

An old token without a corresponding mapping in the current request remains unresolved. If original plaintext is submitted again in a later request, it is scanned again and may establish a new current-request mapping.

### Redact Notice

The notice is always enabled and is **not** a URL flag. Redaction runs first; then a short English notice is prepended to the supported user input:

> Sensitive values are redacted before forwarding, including messages, tool inputs, and tool results. You may see {{Redact:sha256}} placeholders; treat them as opaque and preserve them exactly. Sensitive values you read appear as placeholders, and placeholders you emit in text or tool calls are restored to the original secrets.

For OpenAI Responses string `input`, the notice prefixes the string. For supported message arrays, it is placed at the beginning of the last user message's textual content. No artificial user message is added when none exists. Unknown endpoint URLs can still receive the notice if their request body is recognized as a supported family.

This notice asks the model to preserve placeholders; it cannot force compliance. Editing or inventing a token prevents reliable restoration.

### JSON strings and excluded fields

JSON-looking string values are recursively parsed, redacted, and serialized back to strings when `REDACT_PARSE_NESTED_JSON` is enabled. This includes tool-call `arguments`. It preserves the API structure, not necessarily the original JSON whitespace or byte sequence.

Selected control fields such as model/role/type identifiers, URL fields, and large base64 image/audio payload fields are skipped to avoid corrupting requests. Binary image/audio content is not inspected. The relay is not a whole-request data-loss-prevention guarantee.

<a id="streaming"></a>
## Streaming restoration

`text/event-stream` responses are restored incrementally with downstream backpressure. The implementation handles recognized text/delta channels for OpenAI Chat Completions, OpenAI Responses, and Anthropic Messages, including tool/function argument deltas and common reasoning/text fields.

If a chunk ends in a possible placeholder prefix, the stream layer retains that prefix until later data establishes either a complete known token or a sequence that cannot become one. This addresses both HTTP transport chunk boundaries and logical SSE event boundaries.

The repository documentation describes exhaustive tests of each split position of a 75-byte placeholder, plus one-byte transport chunks. It also lists tool/reasoning/partial-JSON deltas and local HTTP/Node integration. Run `npm test` in the repository to inspect the suite's results for your checkout. These are not a statement of universal compatibility with future or arbitrary streaming schemas.

<a id="detectors"></a>
## Detector behavior

| Flag | Matching behavior |
| :---: | :--- |
| `H` | Length-aware high-entropy ASCII alphanumeric blocks, strictly longer than 8 characters; numeric-only blocks excluded |
| `P` | PRC mobile and international `+…` phone-number forms |
| `S` | `sk-` plus at least 60 ASCII alphanumeric characters |
| `I` | PRC citizen identity-number candidates with checksum validation |
| `B` | 13–19 digit bank-card candidates with Luhn validation, including common grouped forms |
| `E` | Email-address pattern matching |
| `G` | Gitleaks-compatible JavaScript rule evaluation: keywords, secret groups, Shannon-entropy thresholds, allowlists |

The documented `G` rule set contains **218 JavaScript entries**. This is a rule-entry count, not the number of verified providers or a recall guarantee. Rule signatures are partly derived from Gitleaks; keep [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) with the project. The evaluator does not claim full parity with every Gitleaks CLI behavior.

### High-entropy scoring

The `H` detector tokenizes on whitespace and special characters while preserving text offsets. It scores qualifying blocks using an English character-bigram cross-entropy model, not ordinary empirical Shannon entropy alone. Thresholds are length-dependent and linearly interpolated between calibration anchors. A separate symbol-diversity check rejects repetitive strings. Numeric-only blocks are left to the structured detectors.

Recorded results for the deterministic local calibration fixture:

| Sample family | Reported result |
| :--- | :--- |
| Natural-word concatenations | `296 / 30000 = 0.9867%` classified high entropy |
| Random hex/base62, length 9 | About 91–92% recall |
| Random hex/base62, length 12 | About 96–98% recall |
| Random hex/base62, around length 16 | Above 99% recall |
| Sampled random hex/base62 sets, length 24/32 | 100% within those sampled sets |

These numbers describe synthetic fixtures under that calibration. They are not whole-system precision/recall, guarantees for non-English content, or production performance measurements. See [ENTROPY.md](ENTROPY.md) and reproduce the report with:

```bash
npm run entropy-report
```

<a id="settings"></a>
## Runtime settings

| Variable | Default | Meaning |
| :--- | :--- | :--- |
| `REDACT_ALLOWED_HOSTS` | Unset | Comma-separated hostname allowlist. Unset permits arbitrary upstream hosts subject to other checks. |
| `REDACT_BLOCK_PRIVATE_UPSTREAMS` | `true` | Reject recognized private, loopback, link-local, and metadata destinations after hostname parsing and normalization. |
| `REDACT_PARSE_NESTED_JSON` | `true` | Recursively redact JSON-looking strings, including tool arguments. |
| `REDACT_MAX_BODY_BYTES` | `16777216` (16 MiB) | Maximum buffered request body accepted for JSON redaction. |
| `REDACT_MAX_REDACTIONS` | `16384` | Maximum unique plaintext replacements per request. |
| `REDACT_CORS_ORIGIN` | `*` | `Access-Control-Allow-Origin` value. |
| `HOST` | `127.0.0.1` | Node development adapter only. |
| `PORT` | `8787` | Node development adapter only. |

Configure variables in the runtime that actually executes the gateway. Cloudflare Worker variables are not automatically populated by setting a variable in a local deployment shell. Direct Deno execution reads its environment with `Deno.env.toObject()`; `--allow-env` enables that access.

The request must be available for parsing and redaction before forwarding. Lower body and replacement limits for memory-constrained environments. Limits do not replace an external request-size cap, concurrency control, or rate limiting.

<a id="deployment-boundary"></a>
## Deployment boundary

**Trusted:** the client, the Cosy deployment, its runtime operator, and any surrounding infrastructure that can see original traffic.

**Reduced exposure:** matched string values sent onward to the configured upstream. Unmatched text, skipped fields, authentication headers, and surrounding context remain available to the upstream as applicable.

Before public exposure, configure the upstream allowlist, external caller authentication/access control, appropriate CORS policy, network-level egress restrictions, and logging/retention controls. Keep private-upstream blocking enabled unless a deliberately trusted private deployment requires otherwise.

The built-in host checks inspect parsed/normalized hostnames. They are not a complete DNS-resolution or network-level SSRF defense. An allowlist does not authenticate callers, and CORS is not access control. Never advertise an unrestricted instance as safe merely because text redaction is enabled.

The same runtime can generate repeated tokens for repeated values. The surrounding prompt can still reveal information. Applications must continue to authorize tool actions independently of whether their arguments were restored.

Refer to the existing [SECURITY.md](../SECURITY.md) for project security-reporting and deployment guidance.

---

[Back to the English README](../README.md) · [返回中文 README](../README.zh-CN.md)
