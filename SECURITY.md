# Security

## Threat model

Cosy Redact Gateway assumes the selected upstream may store or inspect everything it receives. The relay therefore edits supported JSON request text before the upstream fetch and only keeps the plaintext/token mapping in memory for the lifetime of that request.

It does **not** attempt to make a malicious upstream trustworthy. It only reduces accidental disclosure of values recognized by the configured detectors.

## Deployment checklist

1. Set `REDACT_ALLOWED_HOSTS` unless arbitrary upstream routing is an explicit requirement.
2. Protect public deployments with your platform's authentication/rate limiting if they should not be open relays.
3. Keep `REDACT_MAX_BODY_BYTES` and `REDACT_MAX_REDACTIONS` bounded. The shipped defaults are 16 MiB and 16384 respectively; lower them on memory-constrained deployments.
4. Do not log request bodies, upstream bodies, or the per-runtime salt in surrounding infrastructure.
5. Keep redirects disabled. The implementation uses `redirect: "manual"` so an upstream cannot redirect the forwarded API key to a second origin.
6. Treat URL-embedded upstream query parameters as visible routing metadata. Secrets should normally remain in forwarded authorization headers, not the proxy URL.
7. Review `docs/GITLEAKS-COMPAT.md` before relying on `G` as an exact Gitleaks replacement.

## Header policy

Authorization/provider headers are preserved, while hop-by-hop and relay identity/session headers are removed. In particular the proxy drops `Cookie`, `CF-*`, `Sec-*`, `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, and similar headers before the upstream fetch.

## State lifetime

The salt is generated once when a Worker/Deno isolate starts. Multiple concurrent isolates may therefore use different salts. Restoration does not depend on cross-request or cross-instance state: each response stream closes over its own request-local mapping.
