import test from "node:test";
import assert from "node:assert/strict";
import {
  parseFlags, parseProxyTarget, tokenizeBlocks, RedactionContext,
  findSensitiveSpans, injectRedactNotice, detectProtocol, redactJson
} from "../worker.js";

const all = {highEntropy:true,phone:true,secret:true,identity:true,bank:true,email:true,gitleaks:true};

test("flags default to all and subsets are explicit", () => {
  assert.deepEqual(parseFlags(""), all);
  assert.deepEqual(parseFlags("eS"), {highEntropy:false,phone:false,secret:true,identity:false,bank:false,email:true,gitleaks:false});
  assert.throws(() => parseFlags("EX"), /Unknown flag/);
});

test("route preserves upstream path and query", () => {
  const t = parseProxyTarget("https://proxy.example/HPSE$https://api.openai.com/v1/responses?foo=a%20b&x=2");
  assert.equal(t.upstream.toString(), "https://api.openai.com/v1/responses?foo=a%20b&x=2");
  assert.equal(t.flags.email, true);
  assert.equal(t.flags.bank, false);
});

test("lossless-style block offsets split on whitespace/special characters", () => {
  assert.deepEqual(tokenizeBlocks("abc_def-123.foo"), [
    {value:"abc",start:0,end:3}, {value:"def",start:4,end:7},
    {value:"123",start:8,end:11}, {value:"foo",start:12,end:15}
  ]);
});

test("email, phone, sk, bank and Chinese ID candidates", () => {
  const sk = "sk-" + "A1".repeat(30);
  // Valid Visa test number and valid PRC checksum example used only as synthetic test data.
  const text = `a@example.com 13800138000 ${sk} 4111111111111111 11010519491231002X`;
  const types = findSensitiveSpans(text, all).map(x => x.type);
  assert(types.includes("email"));
  assert(types.includes("phone"));
  assert(types.includes("secret") || types.includes("gitleaks"));
  assert(types.includes("bank"));
  assert(types.includes("identity"));
});

test("same plaintext reuses token and restore is exact", async () => {
  const ctx = new RedactionContext({salt:"unit-test"});
  const flags = parseFlags("E");
  const out = await ctx.redactText("a@example.com / a@example.com", flags);
  const tokens = out.match(/\{\{Redact:[a-f0-9]{64}\}\}/g);
  assert.equal(tokens.length, 2);
  assert.equal(tokens[0], tokens[1]);
  assert.equal(ctx.restoreText(out), "a@example.com / a@example.com");
});

test("existing Redact-looking placeholder is not nested or restored", async () => {
  const original = "{{Redact:" + "a".repeat(64) + "}}";
  const ctx = new RedactionContext({salt:"unit-test"});
  const out = await ctx.redactText(original, parseFlags("H"));
  assert.equal(out, original);
  assert.equal(ctx.restoreText(out), original);
});

test("notice is injected after redaction for OpenAI Chat", async () => {
  const body = {model:"gpt-test",messages:[{role:"user",content:"mail a@example.com"}]};
  const ctx = new RedactionContext({salt:"unit-test"});
  const redacted = await redactJson(body, ctx, parseFlags("E"));
  const protocol = detectProtocol(redacted, new URL("https://api.example/v1/chat/completions"), new Headers());
  assert.equal(injectRedactNotice(redacted, protocol), true);
  assert.match(redacted.messages[0].content, /^Sensitive values are redacted before forwarding/);
  assert.match(redacted.messages[0].content, /\{\{Redact:[a-f0-9]{64}\}\}/);
  assert(!redacted.messages[0].content.includes("a@example.com"));
});

test("notice handles Responses string and content arrays", () => {
  const a = {input:"hello"};
  assert(injectRedactNotice(a,"openai_responses"));
  assert(a.input.endsWith("\n\nhello"));
  const b = {input:[{role:"user",content:[{type:"input_text",text:"hello"},{type:"input_image",image_url:"data:image/png;base64,AAAA"}]}]};
  assert(injectRedactNotice(b,"openai_responses"));
  assert.match(b.input[0].content[0].text,/^Sensitive values are redacted/);
});

test("notice can target the first user message for stable prefixes", () => {
  const body = { messages: [
    { role: "user", content: "first" },
    { role: "assistant", content: "answer" },
    { role: "user", content: "latest" }
  ] };
  assert.equal(injectRedactNotice(body, "openai_chat", { position: "first_user" }), true);
  assert.match(body.messages[0].content, /^Sensitive values are redacted/);
  assert.equal(body.messages[2].content, "latest");
  assert.equal(injectRedactNotice({ messages: [{ role: "user", content: "x" }] }, "openai_chat", { enabled: false }), false);
});

test("notice handles Anthropic content block without touching image data", async () => {
  const raw = "A".repeat(200);
  const body = {model:"claude-test",messages:[{role:"user",content:[{type:"image",source:{type:"base64",media_type:"image/png",data:raw}},{type:"text",text:"a@example.com"}]}]};
  const ctx = new RedactionContext({salt:"unit-test"});
  const redacted = await redactJson(body,ctx,parseFlags("HE"));
  assert.equal(redacted.messages[0].content[0].source.data,raw);
  injectRedactNotice(redacted,"anthropic_messages");
  assert.match(redacted.messages[0].content[1].text,/^Sensitive values are redacted/);
});

test("tool results are redacted before they are forwarded to the model", async () => {
  const body = {
    model:"gpt-test",
    messages:[
      {role:"user",content:"check the tool result"},
      {role:"tool",tool_call_id:"call_1",content:'{"email":"alice@example.com"}'}
    ]
  };
  const ctx = new RedactionContext({salt:"unit-test"});
  const redacted = await redactJson(body, ctx, parseFlags("E"));
  assert(!redacted.messages[1].content.includes("alice@example.com"));
  assert.match(redacted.messages[1].content, /\{\{Redact:[a-f0-9]{64}\}\}/);
});

test("Responses model-state items bypass request redaction only at input top level", async () => {
  const reasoning = {type:"reasoning",id:"rs_123",encrypted_content:"reasoning-state@example.test"};
  const compaction = {type:"compaction",encrypted_content:"compaction-state@example.test"};
  const body = {input:[
    reasoning,
    compaction,
    {role:"user",content:[{type:"input_text",text:"user@example.com"}]},
    {role:"user",content:[{type:"input_text",text:JSON.stringify({type:"reasoning",encrypted_content:"nested-state@example.test"})}]}
  ]};
  const ctx = new RedactionContext({salt:"unit-test"});
  const redacted = await redactJson(body,ctx,all,"openai_responses");
  assert.deepEqual(redacted.input[0],reasoning);
  assert.deepEqual(redacted.input[1],compaction);
  assert.match(redacted.input[2].content[0].text,/\{\{Redact:[a-f0-9]{64}\}\}/);
  assert(!redacted.input[3].content[0].text.includes("nested-state@example.test"));
  assert.equal(ctx.rawToToken.has("reasoning-state@example.test"),false);
  assert.equal(ctx.rawToToken.has("compaction-state@example.test"),false);
  assert.equal(ctx.rawToToken.has("nested-state@example.test"),true);
});

test("Anthropic assistant thinking bypass is role- and path-limited", async () => {
  const thinking = {type:"thinking",thinking:"thought@example.com",signature:"signature@example.com"};
  const redactedThinking = {type:"redacted_thinking",data:"opaque@example.com"};
  const body = {messages:[
    {role:"assistant",content:[thinking,redactedThinking,{type:"text",text:"assistant@example.com"}]},
    {role:"user",content:[{type:"thinking",thinking:"user@example.com"}]},
    {role:"tool",content:[{type:"redacted_thinking",data:"tool@example.com"}]}
  ]};
  const ctx = new RedactionContext({salt:"unit-test"});
  const redacted = await redactJson(body,ctx,all,"anthropic_messages");
  assert.deepEqual(redacted.messages[0].content[0],thinking);
  assert.deepEqual(redacted.messages[0].content[1],redactedThinking);
  assert.match(redacted.messages[0].content[2].text,/\{\{Redact:/);
  assert.match(redacted.messages[1].content[0].thinking,/\{\{Redact:/);
  assert.match(redacted.messages[2].content[0].data,/\{\{Redact:/);
});

test("Chat assistant reasoning fields bypass while user and normal content redact", async () => {
  const details = {state:"details@example.com"};
  const body = {messages:[
    {role:"assistant",reasoning_content:"reasoning@example.com",reasoning:["array@example.com"],reasoning_details:details,content:"normal@example.com"},
    {role:"user",reasoning_content:"user@example.com",content:JSON.stringify({reasoning_details:"nested@example.com"})},
    {role:"tool",reasoning:"tool@example.com"}
  ]};
  const redacted = await redactJson(body,new RedactionContext({salt:"unit-test"}),all,"openai_chat");
  assert.equal(redacted.messages[0].reasoning_content,"reasoning@example.com");
  assert.deepEqual(redacted.messages[0].reasoning,["array@example.com"]);
  assert.deepEqual(redacted.messages[0].reasoning_details,details);
  assert.match(redacted.messages[0].content,/\{\{Redact:/);
  assert.match(redacted.messages[1].reasoning_content,/\{\{Redact:/);
  assert(!redacted.messages[1].content.includes("nested@example.com"));
  assert.match(redacted.messages[2].reasoning,/\{\{Redact:/);
});

test("generic requests never enable reasoning bypass", async () => {
  const body = {input:[{type:"reasoning",encrypted_content:"generic-state@example.test"}],messages:[{role:"assistant",reasoning_content:"chat-state@example.test"}]};
  const redacted = await redactJson(body,new RedactionContext({salt:"unit-test"}),all,"generic");
  assert(!redacted.input[0].encrypted_content.includes("generic-state@example.test"));
  assert(!redacted.messages[0].reasoning_content.includes("chat-state@example.test"));
});

test("tool-call arguments containing placeholders restore to the original secret", async () => {
  const ctx = new RedactionContext({salt:"unit-test"});
  const redacted = await ctx.redactText("alice@example.com", parseFlags("E"));
  const response = {
    choices:[{
      message:{
        tool_calls:[{
          id:"call_1",
          type:"function",
          function:{name:"send_mail",arguments:JSON.stringify({email:redacted})}
        }]
      }
    }]
  };
  const { restoreJson } = await import("../worker.js");
  restoreJson(response, ctx);
  assert.equal(JSON.parse(response.choices[0].message.tool_calls[0].function.arguments).email, "alice@example.com");
});
