#!/usr/bin/env sh
set -eu
: "${PROXY_BASE:=http://127.0.0.1:8787}"
: "${OPENAI_API_KEY:?set OPENAI_API_KEY}"
curl -N \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $OPENAI_API_KEY" \
  --data '{"model":"gpt-5-mini","input":"contact alice@example.com","stream":true}' \
  "$PROXY_BASE/E\$https://api.openai.com/v1/responses"
