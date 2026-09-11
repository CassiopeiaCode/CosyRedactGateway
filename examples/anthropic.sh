#!/usr/bin/env sh
set -eu
: "${PROXY_BASE:=http://127.0.0.1:8787}"
: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY}"
curl -N \
  -H 'content-type: application/json' \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H 'anthropic-version: 2023-06-01' \
  --data '{"model":"claude-sonnet-4-5","max_tokens":128,"messages":[{"role":"user","content":"contact alice@example.com"}],"stream":true}' \
  "$PROXY_BASE/E\$https://api.anthropic.com/v1/messages"
