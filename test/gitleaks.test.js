import test from "node:test";
import assert from "node:assert/strict";
import { GITLEAK_PORTABLE_RULE_COUNT, findSensitiveSpans, parseFlags } from "../worker.js";

const flags=parseFlags("G");
function matches(s){return findSensitiveSpans(s,flags).filter(x=>x.type==="gitleaks");}
function detected(s){return matches(s).length>0;}

test("G portable engine carries a broad upstream-compatible ruleset",()=>{
  assert.ok(GITLEAK_PORTABLE_RULE_COUNT >= 210, `portable rules=${GITLEAK_PORTABLE_RULE_COUNT}`);
});

test("G rule pack recognizes representative direct provider secret families",()=>{
  assert(detected("AKIA"+"A2B3C4D5E6F7G2H3"));
  assert(detected("ghp_"+"A".repeat(36)));
  assert(detected("glpat-"+"A2b3C4d5E6f7G8h9J0kL"));
  assert(detected("xoxb-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
  assert(detected("AIza"+"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8".slice(0,35)));
  assert(detected("dapi"+"0123456789abcdef".repeat(2)));
  assert(detected("SG."+"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCD"));
  assert(detected("sk-ant-api03-"+"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0E1f2G3h4I5j6K7l8M9n0P1q2R3s4T5u6V7w8X9y0Z1".slice(0,93)+"AA"));
});

test("G assignment rules extract only the secretGroup rather than the surrounding assignment",()=>{
  const secret="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
  const text=`cloudflare = ${secret}`;
  const hit=matches(text).find(x=>x.ruleId==="cloudflare-api-key");
  assert(hit);
  assert.equal(text.slice(hit.start,hit.end),secret);
});

test("G entropy threshold rejects low-entropy lookalikes but accepts high-entropy assignments",()=>{
  assert.equal(matches("adobe = "+"a".repeat(32)).some(x=>x.ruleId==="adobe-client-id"),false);
  assert.equal(matches("adobe = 0123456789abcdef0123456789abcdef").some(x=>x.ruleId==="adobe-client-id"),true);
});

test("G rule-level allowlist suppresses the official AWS EXAMPLE form",()=>{
  assert.equal(detected("AKIA"+"B2C3D4E5FEXAMPLE"),false);
});

test("G rule pack recognizes private keys and JWT-like credentials",()=>{
  assert(detected("-----BEGIN PRIVATE KEY-----\n"+"A".repeat(80)+"\n-----END PRIVATE KEY-----"));
  assert(detected("eyJabcdefgh.eyJijklmnop.abcdefghijklmnopQRSTUV"));
});

test("G generic credential assignment fallback still catches unknown API-style secrets",()=>{
  assert(detected("api_key=ABCDEFGH1234567890abcdef"));
});

test("G extended upstream ports catch additional direct and context rules",()=>{
  assert(detected("duffel_live_"+"Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2Yz3Aa4B".slice(0,43)));
  assert(detected("dt0c01."+"Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8".slice(0,24)+"."+"0123456789abcdef".repeat(4)));
  assert(detected("v1.0-"+"0123456789abcdef01234567"+"-"+("0123456789abcdef".repeat(10)).slice(0,146)));
  assert(detected("glcbt-A1_AbCdEfGhIjKlMnOpQrSt"));
  assert(detected("API-"+"A1B2C3D4E5F6G7H8I9J0K1L2M3".slice(0,26)));
  assert(detected("curl -H 'Authorization: Bearer AbCdEfGhIjKlMnOpQrStUvWxYz012345' https://example.invalid"));
  assert(detected("kind: Secret\ndata:\n  token: QWJjZEVmR2hJamsxMjM0NTY="));
});
