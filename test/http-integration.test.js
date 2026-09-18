import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { handleRequest } from "../worker.js";

function listen(server){return new Promise(r=>server.listen(0,"127.0.0.1",()=>r(server.address().port)));}
function close(server){return new Promise(r=>server.close(r));}

test("real local HTTP upstream receives redacted JSON and client gets restored JSON", async () => {
  let upstreamBody, auth;
  const upstream=http.createServer((req,res)=>{
    auth=req.headers.authorization; let data="";
    req.setEncoding("utf8"); req.on("data",c=>data+=c); req.on("end",()=>{
      upstreamBody=JSON.parse(data); const token=upstreamBody.input.match(/\{\{Redact:[a-f0-9]{64}\}\}/)[0];
      res.setHeader("content-type","application/json"); res.end(JSON.stringify({output_text:`echo ${token}`}));
    });
  });
  const port=await listen(upstream);
  try{
    const u=`https://proxy.local/E$http://127.0.0.1:${port}/v1/responses`;
    const request=new Request(u,{method:"POST",headers:{"content-type":"application/json","authorization":"Bearer local-key"},body:JSON.stringify({model:"g",input:"a@example.com"})});
    const response=await handleRequest(request,{REDACT_BLOCK_PRIVATE_UPSTREAMS:"false"}, {salt:"fixed"});
    assert.equal(response.status,200); assert.equal(auth,"Bearer local-key");
    assert(!upstreamBody.input.includes("a@example.com")); assert.match(upstreamBody.input,/^Sensitive values are redacted/);
    assert.equal((await response.json()).output_text,"echo a@example.com");
  } finally { await close(upstream); }
});
