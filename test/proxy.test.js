import test from "node:test";
import assert from "node:assert/strict";
import { handleRequest, REDUCT_NOTICE } from "../worker.js";

const TOKEN = /\{\{reduct:[a-f0-9]{64}\}\}/;

function req(url, body, headers={}) {
  return new Request(url,{method:"POST",headers:{"content-type":"application/json",...headers},body:JSON.stringify(body)});
}

test("non-stream OpenAI Chat: key/header forwarding, notice, redaction, restoration", async () => {
  let seen;
  const fetchImpl = async (url, init) => {
    seen={url,init,body:JSON.parse(init.body)};
    const content=seen.body.messages.at(-1).content;
    const token=content.match(TOKEN)[0];
    return new Response(JSON.stringify({id:"x",choices:[{message:{role:"assistant",content:`I saw ${token}`}}]}),{headers:{"content-type":"application/json"}});
  };
  const request=req("https://proxy.example/E$https://api.example/v1/chat/completions",{model:"gpt",messages:[{role:"user",content:"my email is a@example.com"}]},{authorization:"Bearer upstream-secret","cf-connecting-ip":"203.0.113.9","x-forwarded-for":"203.0.113.9"});
  const response=await handleRequest(request,{}, {fetchImpl,salt:"fixed"});
  assert.equal(seen.url,"https://api.example/v1/chat/completions");
  assert.equal(seen.init.headers.get("authorization"),"Bearer upstream-secret");
  assert.equal(seen.init.headers.get("cf-connecting-ip"),null);
  assert.equal(seen.init.headers.get("x-forwarded-for"),null);
  assert.match(seen.body.messages[0].content,new RegExp("^"+REDUCT_NOTICE.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")));
  assert(!seen.body.messages[0].content.includes("a@example.com"));
  const out=await response.json();
  assert.equal(out.choices[0].message.content,"I saw a@example.com");
});

test("OpenAI Responses input string is redacted and notice-prefixed", async () => {
  let seen;
  const fetchImpl=async (_url,init)=>{
    seen=JSON.parse(init.body); const token=seen.input.match(TOKEN)[0];
    return new Response(JSON.stringify({output:[{type:"message",content:[{type:"output_text",text:token}]}]}),{headers:{"content-type":"application/json"}});
  };
  const response=await handleRequest(req("https://p/E$https://api.example/v1/responses",{model:"gpt",input:"contact a@example.com"}),{}, {fetchImpl,salt:"fixed"});
  assert.match(seen.input,/^We have redacted/); assert(!seen.input.includes("a@example.com"));
  assert.equal((await response.json()).output[0].content[0].text,"a@example.com");
});

test("Anthropic Messages string content is redacted and restored", async () => {
  let seen;
  const fetchImpl=async (_url,init)=>{
    seen=JSON.parse(init.body); const token=seen.messages[0].content.match(TOKEN)[0];
    return new Response(JSON.stringify({type:"message",role:"assistant",content:[{type:"text",text:`${token}!`}]}),{headers:{"content-type":"application/json"}});
  };
  const response=await handleRequest(req("https://p/E$https://api.anthropic.example/v1/messages",{model:"claude",max_tokens:20,messages:[{role:"user",content:"a@example.com"}]},{"x-api-key":"k","anthropic-version":"2023-06-01"}),{}, {fetchImpl,salt:"fixed"});
  assert.equal(seen.messages[0].content.startsWith("We have redacted"),true);
  assert.equal((await response.json()).content[0].text,"a@example.com!");
});

test("invalid JSON/non-JSON body fails closed instead of leaking to upstream", async () => {
  let called=false; const fetchImpl=async()=>{called=true;return new Response("no")};
  const bad=new Request("https://p/$https://api.example/v1/messages",{method:"POST",headers:{"content-type":"text/plain"},body:"secret"});
  const r=await handleRequest(bad,{}, {fetchImpl});
  assert.equal(r.status,415); assert.equal(called,false);
});

test("max redaction limit fails closed", async () => {
  let called=false; const fetchImpl=async()=>{called=true;return new Response("no")};
  const r=await handleRequest(req("https://p/E$https://api.example/v1/responses",{input:"a@x.com b@y.com"}),{REDUCT_MAX_REDACTIONS:"1"},{fetchImpl,salt:"x"});
  assert.equal(r.status,413); assert.equal(called,false);
});

test("optional upstream allow-list blocks other hosts", async () => {
  const r=await handleRequest(req("https://p/E$https://evil.example/v1/responses",{input:"hello"}),{REDUCT_ALLOWED_HOSTS:"api.example.com"},{fetchImpl:async()=>{throw new Error("must not call")}});
  assert.equal(r.status,403);
});
