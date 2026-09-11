import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const source=fs.readFileSync(new URL("../worker.js",import.meta.url),"utf8");

test("worker.js stays Web-API-only for Cloudflare/Deno portability",()=>{
  assert(!/from\s+["']node:|require\s*\(|\bBuffer\b|\bprocess\./.test(source));
  assert.match(source,/export default \{ fetch\(/);
  assert.match(source,/Deno\.serve/);
});
