# Security notes

Reduct Proxy is a privacy boundary, so its default failure mode for request bodies is deliberately conservative.

- JSON parsing/redaction must finish before the upstream request is sent.
- Non-JSON request bodies with content are rejected.
- Redaction/body limits reject the request instead of bypassing redaction.
- Plaintext maps are request-local and are never written to logs or storage by this project.
- Network-origin headers are stripped before forwarding.
- For public deployments, configure `REDUCT_ALLOWED_HOSTS` to avoid operating an unrestricted forward proxy.
- Do not log request bodies, response bodies, the runtime salt, or the in-memory restoration map in platform observability code.

A random salt is created per Worker isolate / Deno or Node process startup. It is intentionally not durable. Restoration depends only on the map retained by the same in-flight request, so process persistence is not required.
