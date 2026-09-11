# Gitleaks compatibility note

The official Gitleaks defaults are not merely a list of JavaScript-compatible regexes. They are a generated configuration interpreted with Go/RE2 semantics and can use rule keywords, secret groups, entropy thresholds, allowlists, stopwords, and path conditions.

A Cloudflare Worker cannot invoke the native Gitleaks binary, and blindly passing current RE2 expressions to JavaScript `RegExp` is not correct: inline/scoped flags, POSIX character classes, end anchors, and other constructs differ.

For that reason the `G` flag in this repository uses a serverless-portable built-in rule pack for common secret families (AWS, Anthropic, GitHub, GitLab, Slack, Stripe, SendGrid, Google, package registries, Databricks, DigitalOcean, Shopify, Square, Vault, private keys, JWT-like credentials, and generic credential assignments), combined with the separate dynamic `H` detector when `H` is enabled.

This repository does **not** label that implementation as exact execution of every upstream Gitleaks rule. Exact parity should be implemented by compiling an RE2-compatible rule evaluator to WebAssembly and vendoring a pinned official Gitleaks configuration. That would increase the single-file artifact substantially and should be treated as a separate compatibility layer with its own conformance tests.
