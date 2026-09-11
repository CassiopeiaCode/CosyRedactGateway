import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";

async function listen(server,port=0){server.listen(port,"127.0.0.1");await once(server,"listening");return server.address().port;}
async function close(server){await new Promise(r=>server.close(r));}
async function freePort(){const s=http.createServer();const p=await listen(s);await close(s);return p;}
async function waitFor(url){for(let i=0;i<80;i++){try{const r=await fetch(url);if(r.ok)return;}catch{}await new Promise(r=>setTimeout(r,25));}throw new Error("server did not start");}

test("node-server adapter proxies through a real HTTP socket", async (t)=>{
  let upstreamBody;
  const upstream=http.createServer((req,res)=>{
    let data=""; req.setEncoding("utf8"); req.on("data",c=>data+=c); req.on("end",()=>{
      upstreamBody=JSON.parse(data);
      const token=upstreamBody.input.match(/\{\{Redact:[a-f0-9]{64}\}\}/)[0];
      res.setHeader("content-type","application/json");
      res.end(JSON.stringify({output_text:`echo:${token}`}));
    });
  });
  const upstreamPort=await listen(upstream);
  const proxyPort=await freePort();
  const child=spawn(process.execPath,["node-server.mjs"],{
    cwd:new URL("..",import.meta.url),
    env:{...process.env,HOST:"127.0.0.1",PORT:String(proxyPort)},
    stdio:["ignore","pipe","pipe"]
  });
  t.after(async()=>{child.kill("SIGTERM"); await close(upstream);});
  await waitFor(`http://127.0.0.1:${proxyPort}/healthz`);
  const r=await fetch(`http://127.0.0.1:${proxyPort}/E$http://127.0.0.1:${upstreamPort}/v1/responses`,{
    method:"POST",headers:{"content-type":"application/json","authorization":"Bearer local"},
    body:JSON.stringify({model:"g",input:"mail a@example.com"})
  });
  assert.equal(r.status,200);
  assert(!upstreamBody.input.includes("a@example.com"));
  assert.match(upstreamBody.input,/^Sensitive values are redacted before forwarding/);
  assert.equal((await r.json()).output_text,"echo:a@example.com");
});
