import test from "node:test";
import assert from "node:assert/strict";
import { handleRequest } from "../worker.js";

const TOKEN=/\{\{reduct:[a-f0-9]{64}\}\}/;
function request(url,body){return new Request(url,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});}
function chunkedResponse(text, sizes=[1,2,3,5,8,13]){
  const enc=new TextEncoder(); let at=0,i=0;
  const body=new ReadableStream({pull(c){if(at>=text.length)return c.close();const n=sizes[i++%sizes.length];c.enqueue(enc.encode(text.slice(at,at+n)));at+=n;}});
  return new Response(body,{headers:{"content-type":"text/event-stream"}});
}
function sseData(text){
  const out=[];
  for(const event of text.replace(/\r\n/g,"\n").split("\n\n")){
    if(!event.trim())continue;
    const lines=event.split("\n"); const ds=lines.filter(x=>x.startsWith("data:")).map(x=>x.slice(5).trimStart()).join("\n");
    if(ds && ds!=="[DONE]") out.push(JSON.parse(ds));
  }
  return out;
}

test("OpenAI Chat SSE restores a placeholder split across logical SSE delta events and HTTP chunks", async()=>{
  const raw='a@example.com';
  const fetchImpl=async(_u,init)=>{
    const body=JSON.parse(init.body), token=body.messages[0].content.match(TOKEN)[0];
    const cut=17;
    const stream=`data: ${JSON.stringify({choices:[{index:0,delta:{content:"before "+token.slice(0,cut)}}]})}\n\n`+
      `data: ${JSON.stringify({choices:[{index:0,delta:{content:token.slice(cut)+" after"}}]})}\n\n`+
      `data: [DONE]\n\n`;
    return chunkedResponse(stream);
  };
  const r=await handleRequest(request("https://p/E$https://api.example/v1/chat/completions",{model:"g",stream:true,messages:[{role:"user",content:raw}]}),{}, {fetchImpl,salt:"fixed"});
  const text=await r.text(); assert(!TOKEN.test(text));
  const events=sseData(text); const combined=events.map(x=>x.choices?.[0]?.delta?.content||"").join("");
  assert.equal(combined,"before a@example.com after");
});

test("OpenAI Responses SSE restores delta split across events", async()=>{
  const raw='a@example.com';
  const fetchImpl=async(_u,init)=>{
    const b=JSON.parse(init.body), token=b.input.match(TOKEN)[0], cut=31;
    const a={type:"response.output_text.delta",output_index:0,content_index:0,delta:token.slice(0,cut)};
    const z={type:"response.output_text.delta",output_index:0,content_index:0,delta:token.slice(cut)};
    return chunkedResponse(`event: response.output_text.delta\ndata: ${JSON.stringify(a)}\n\nevent: response.output_text.delta\ndata: ${JSON.stringify(z)}\n\n`);
  };
  const r=await handleRequest(request("https://p/E$https://api.example/v1/responses",{model:"g",stream:true,input:raw}),{}, {fetchImpl,salt:"fixed"});
  const events=sseData(await r.text()); assert.equal(events.map(x=>x.delta||"").join(""),raw);
});

test("Anthropic SSE restores content_block_delta split across events", async()=>{
  const raw='a@example.com';
  const fetchImpl=async(_u,init)=>{
    const b=JSON.parse(init.body), token=b.messages[0].content.match(TOKEN)[0], cut=9;
    const a={type:"content_block_delta",index:0,delta:{type:"text_delta",text:token.slice(0,cut)}};
    const z={type:"content_block_delta",index:0,delta:{type:"text_delta",text:token.slice(cut)}};
    return chunkedResponse(`event: content_block_delta\ndata: ${JSON.stringify(a)}\n\nevent: content_block_delta\ndata: ${JSON.stringify(z)}\n\n`);
  };
  const r=await handleRequest(request("https://p/E$https://api.example/v1/messages",{model:"c",stream:true,max_tokens:20,messages:[{role:"user",content:raw}]}),{}, {fetchImpl,salt:"fixed"});
  const events=sseData(await r.text()); assert.equal(events.map(x=>x.delta?.text||"").join(""),raw);
});

test("SSE JSON stays valid when restored source contains a quote", async()=>{
  const raw='api_key="ABCDEFGH1234567890';
  const fetchImpl=async(_u,init)=>{
    const b=JSON.parse(init.body), token=b.messages[0].content.match(TOKEN)[0];
    const a={choices:[{index:0,delta:{content:token.slice(0,20)}}]}, z={choices:[{index:0,delta:{content:token.slice(20)}}]};
    return chunkedResponse(`data: ${JSON.stringify(a)}\n\ndata: ${JSON.stringify(z)}\n\n`);
  };
  const r=await handleRequest(request("https://p/G$https://api.example/v1/chat/completions",{model:"g",stream:true,messages:[{role:"user",content:raw}]}),{}, {fetchImpl,salt:"fixed"});
  const text=await r.text(); const events=sseData(text); // JSON.parse inside helper proves escaping is valid.
  assert.equal(events.map(x=>x.choices[0].delta.content).join(""),raw);
});

test("every possible placeholder split position is restored across Chat SSE events", async()=>{
  const raw="boundary@example.com";
  for(let cut=1; cut<75; cut++){
    const fetchImpl=async(_u,init)=>{
      const b=JSON.parse(init.body), token=b.messages[0].content.match(TOKEN)[0];
      assert.equal(token.length,75);
      const a={choices:[{index:0,delta:{content:token.slice(0,cut)}}]};
      const z={choices:[{index:0,delta:{content:token.slice(cut)}}]};
      return chunkedResponse(`data: ${JSON.stringify(a)}\n\ndata: ${JSON.stringify(z)}\n\n`,[(cut%7)+1,1,9,2]);
    };
    const r=await handleRequest(request("https://p/E$https://api.example/v1/chat/completions",{model:"g",stream:true,messages:[{role:"user",content:raw}]}),{}, {fetchImpl,salt:"fixed"});
    const events=sseData(await r.text());
    assert.equal(events.map(x=>x.choices[0].delta.content).join(""),raw,`cut=${cut}`);
  }
});
