<p align="center">
  <picture>
    <source media="(max-width: 600px)" srcset="docs/readme/hero-mobile-zh.svg">
    <img src="docs/readme/hero-zh.svg" alt="代码交给 AI。凭据，不该跟着走。H 启发式 + 已知密钥规则。" width="1040">
  </picture>
</p>

<h1 align="center">Cosy Redact Gateway</h1>

<p align="center"><strong>不只防已知密钥，更要识别没有固定格式的随机凭据。</strong></p>

<p align="center">
  <a href="#h-layer"><img src="docs/readme/badge-h.svg" alt="H：不依赖已知前缀的启发式检测"></a>
  <a href="#quick-start"><img src="docs/readme/badge-all-on.svg" alt="全部启用：HPSIBEG"></a>
  <a href="#compatibility"><img src="docs/readme/badge-streaming.svg" alt="JSON 与 SSE 流式还原"></a>
  <a href="LICENSE"><img src="docs/readme/badge-license.svg" alt="MIT 许可证"></a>
</p>

<p align="center">
  <strong>简体中文</strong> · <a href="README.en.md">English</a>
  <br>
  <a href="#h-layer">为什么是 H</a> ·
  <a href="#quick-start">本地全开</a> ·
  <a href="#proof">验证检测</a> ·
  <a href="#integrations">接入应用</a> ·
  <a href="#security">安全边界</a>
</p>

凭据不一定以 `sk-` 开头。一个内部服务令牌，可能只是代码、配置、日志或工具结果里的一串随机字符。

**面向程序员的 LLM 凭据脱敏网关，多一层不依赖已知前缀的 H 启发式检测。** `H` 会对符合条件的文本块评分，不要求已知厂商格式，也不要求 `password=` 这样的赋值标签。**全功能启用时**，`H` 与结构化检测、Gitleaks 兼容密钥规则协同工作：命中内容在转发前替换为可逆占位符，并在普通响应、受支持的 SSE 流和工具调用参数中还原已知、未被修改的占位符。

**面向程序员的本地优先用法：把 Cosy 跑在本机，让受支持的 LLM 调用经过它。** 下方示例统一使用 `/$https://…`，启用全部检测器。

> **保护范围：** 检查经过网关的 JSON 文本，并替换命中的内容，不是拦截主机全部流量。检测仍可能漏检；上游认证凭据仍会转发。部署到云端时，云端网关会先接收到原始请求。[安全边界 →](#security)

<a id="h-layer"></a>
## 凭据没有标签，也不该少一道防线

固定格式规则检查文本是否匹配已配置的模式；**H 还会检查：符合条件的文本块，是否显著不像普通英文文本。** 因此，即使没有已知厂商前缀，也没有凭据赋值标签，随机形态的凭据仍多了一条被识别的路径。

| 检测层 | 带来的覆盖 |
| :--- | :--- |
| **已知格式与结构化规则** | 识别受支持的厂商密钥特征、凭据赋值形式和结构化个人信息。 |
| **H：不依赖前缀的启发式** | 对超过 8 个字符的 ASCII 字母数字块进行长度感知的英文二元字符交叉熵评分，并检查字符多样性；排除纯数字块。 |
| **全开：`HPSIBEG`** | 组合以上检测路径。标志位留空即启用全部检测器，不是“只开 H”。 |

**增加的是检测路径，不是“随机串必然是凭据”或“所有凭据都能拦截”的保证。** 实现与校准说明：[`worker.js`](worker.js)、[熵检测方法](docs/ENTROPY.md)。

<a id="how-it-works"></a>
### 固定规则之外，再检查一次

<p align="center">
  <picture>
    <source media="(prefers-reduced-motion: reduce) and (max-width: 600px)" srcset="docs/readme/h-layer-mobile-zh-poster.png">
    <source media="(prefers-reduced-motion: reduce)" srcset="docs/readme/h-layer-zh-poster.png">
    <source media="(max-width: 600px)" srcset="docs/readme/h-layer-mobile-zh.gif">
    <img src="docs/readme/h-layer-zh.gif" alt="机制示意：已知规则没有命中时，H 仍可对符合条件的随机文本块评分；命中后替换为占位符。不是与 maskit 的实测比较。" width="1040">
  </picture>
</p>

*这是机制示意，不是实测录屏或竞品基准测试。示例凭据为合成字符串，占位符经过缩写，不含真实凭据。*

| 阶段 | 示意文本 |
| :--- | :--- |
| **应用发出** | `检查这个值： q7X9v2L5m8N4r6T1w3Y0z5A8b2C9d7F4` |
| **该值被检测命中后，上游收到** | `检查这个值： {{Redact:…}}` |
| **模型原样返回占位符** | `这个值是 {{Redact:…}}` |
| **Cosy 为应用还原** | `这个值是 q7X9v2L5m8N4r6T1w3Y0z5A8b2C9d7F4` |

只有模型原样保留已知占位符时，原值才能恢复。真实占位符包含 64 个字符的 SHA-256 摘要。Cosy 也会还原工具参数，但**不会执行工具，也不负责授权工具动作**。[完整往返机制 →](docs/REFERENCE.md#lifecycle)

<details>
<summary><strong>展开查看：一次完整的脱敏与还原往返</strong></summary>

<p align="center">
  <picture>
    <source media="(prefers-reduced-motion: reduce) and (max-width: 600px)" srcset="docs/readme/round-trip-mobile-zh-poster.png">
    <source media="(prefers-reduced-motion: reduce)" srcset="docs/readme/round-trip-zh-poster.png">
    <source media="(max-width: 600px)" srcset="docs/readme/round-trip-mobile-zh.gif">
    <img src="docs/readme/round-trip-zh.gif" alt="机制示意：在可信网关中替换命中的邮箱；上游原样返回占位符后，网关为应用还原原值。" width="1040">
  </picture>
</p>

这是往返机制示意，使用合成数据；摘要与协议提示已缩略。只有当前请求中已知且未被改写的占位符才能还原。

</details>

<a id="proof"></a>
## 多出的这一层，可以自己验证

安全卖点应该能检查。仓库提供一个**纯本地、无需 API Key 的演示脚本**，直接调用仓库导出的检测与脱敏函数：

```bash
node scripts/demo-h.mjs
```

它会对同一个无标签的合成字符串，分别打印 **`PSIBEG`（关闭 H）、仅 `H`、空标志位／全开**时的实际结果，并检查精确还原以及 H 已说明的排除条件。脚本不联网，不调用模型；结果只描述这些样例，**不是 maskit 对照测试**。

仓库中更完整的回归与熵检测样本可这样运行：

```bash
npm test
npm run entropy-report
```

项目已发布的校准记录中，**30,000 个自然词拼接样本有 296 个（0.9867%）被判为高熵**；随机 hex/base62 样本的召回率随长度提高。这是合成样本结果，不是生产泄漏率，也不是本次 README 更新独立复测出的基准成绩。[校准方法](docs/ENTROPY.md) · [H 的证据、对比范围与限制](docs/H-DETECTION.md)

<details>
<summary><strong>与 maskit 已公开检测方式的区别</strong></summary>

maskit 公开说明了固定格式规则、自定义词和正则；既有对比资料查阅的规则还包括 Bearer Token 与凭据赋值检测，**不应将它描述为只能识别几个厂商前缀**。这里突出 Cosy 的差异是：额外提供了明确公开、**不要求已知前缀或凭据赋值标签的二元字符启发式 H**。既有对比资料中的 maskit 文档与规则片段未能确认有同类检测层。

这个差异支持有范围的架构对比，不等于“maskit 永远做不到”，也不等于“Cosy 在所有场景下都更安全”。该对比没有两边全开配置的受控基准结果。[查阅范围与来源 →](docs/H-DETECTION.md#comparison)

</details>

<a id="quick-start"></a>
## 本地运行，全部启用

### 1. 在自己主机上启动网关

需要 **Node.js 20+**、Git 和终端。网关无需安装运行时依赖。HTTP 示例使用 Bash 和 curl 7.76+。

```bash
git clone https://github.com/CassiopeiaCode/CosyRedactGateway.git
cd CosyRedactGateway
npm start
```

本地开发适配器默认监听 `http://127.0.0.1:8787`。此用法保持绑定本机回环地址。

### 2. 不接入模型，先在本地检查

另开一个终端，进入同一个仓库目录：

```bash
curl --fail --silent --show-error http://127.0.0.1:8787/healthz
node scripts/demo-h.mjs
```

第一条检查服务可用性；第二条离线检查合成检测样例。都不需要 API Key。

### 3. 使用全开策略发出请求

通过日常的密钥管理方式在环境中导出 `OPENAI_API_KEY`，并将 `OPENAI_MODEL` 导出为账户可用的模型。这会真实调用上游，可能产生费用。

```bash
: "${OPENAI_API_KEY:?Set OPENAI_API_KEY in this shell first}"
: "${OPENAI_MODEL:?Set OPENAI_MODEL to a model available to your account}"

node --input-type=module -e '
  const payload = {
    model: process.env.OPENAI_MODEL,
    messages: [{
      role: "user",
      content: "请原样返回这个值： q7X9v2L5m8N4r6T1w3Y0z5A8b2C9d7F4"
    }],
    stream: true
  };
  process.stdout.write(JSON.stringify(payload));
' | curl --fail-with-body --no-buffer \
  -H 'content-type: application/json' \
  -H "authorization: Bearer ${OPENAI_API_KEY}" \
  --data-binary @- \
  'http://127.0.0.1:8787/$https://api.openai.com/v1/chat/completions'
```


**`$` 前的标志位留空，等于启用 `HPSIBEG`：包括 H 在内的全部检测器。** 模型原样返回被检测值的占位符时，应用会收到还原后的原值；模型输出本身不保证确定。Shell 中的路由 URL 要使用单引号，避免 `$` 被展开。

提供商认证头仍会转发到指定上游。此示例检验的是请求正文内容的脱敏，不是隐藏用于认证该 API 调用的密钥。

<a id="integrations"></a>
## 给现有开发工具加上这层检测

保留上游 API Key、模型和请求结构，把目标地址改成 Cosy 路由。客户端需要完整保留嵌入的上游 URL，并正确追加 API 路径。

所有下方路由均启用全部检测器，包括 H。客户端必须真正把相关请求经过此网关。

### OpenAI Python SDK

在**应用环境**中安装 SDK，而不是给网关增加依赖：`python -m pip install openai`。在环境中导出 `OPENAI_API_KEY`、`OPENAI_MODEL` 并启动本地网关后：

```python
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url="http://127.0.0.1:8787/$https://api.openai.com/v1",
)

response = client.responses.create(
    model=os.environ["OPENAI_MODEL"],
    input="请原样返回这个值： q7X9v2L5m8N4r6T1w3Y0z5A8b2C9d7F4",
)
print(response.output_text)
```

预期路由路径以 `$https://api.openai.com/v1/responses` 结尾；Chat Completions 使用相同的 Base URL。[SDK 配置参考](https://github.com/openai/openai-python)

<details>
<summary><strong>Anthropic JavaScript SDK</strong></summary>

在应用中安装 `@anthropic-ai/sdk`。设置 `ANTHROPIC_API_KEY`，并将 `ANTHROPIC_MODEL` 设置为可用模型，然后将以下内容保存为 `.mjs` 文件运行：

```javascript
import Anthropic from '@anthropic-ai/sdk';

const apiKey = process.env.ANTHROPIC_API_KEY;
const model = process.env.ANTHROPIC_MODEL;
if (!apiKey || !model) {
  throw new Error('Set ANTHROPIC_API_KEY and ANTHROPIC_MODEL first.');
}

const client = new Anthropic({
  apiKey,
  baseURL: 'http://127.0.0.1:8787/$https://api.anthropic.com',
});

const message = await client.messages.create({
  model,
  max_tokens: 128,
  messages: [{
    role: 'user',
    content: '请原样返回这个值： q7X9v2L5m8N4r6T1w3Y0z5A8b2C9d7F4',
  }],
});
console.log(message.content);
```

SDK 会追加 `/v1/messages`；不要在这个 Base URL 后再添加 `/v1`。[SDK 源码与配置](https://github.com/anthropics/anthropic-sdk-typescript)

</details>

<details>
<summary><strong>IDE 助手、命令行工具与自定义 HTTP 客户端</strong></summary>

对于支持自定义 API Base URL 的工具，先确认它实际使用的协议：

| API 家族 | Base URL 示例 |
| :--- | :--- |
| 追加 `/chat/completions` 或 `/responses` 的 OpenAI 风格客户端 | `http://127.0.0.1:8787/$https://api.openai.com/v1` |
| 追加 `/v1/messages` 的 Anthropic 风格客户端 | `http://127.0.0.1:8787/$https://api.anthropic.com` |
| 自定义 HTTP 客户端 | 像 curl 示例一样，把完整上游端点放在 `$` 之后。 |

**支持协议，不等于完成了某个产品的兼容认证。** Cursor、Claude Code、Codex 等工具的版本、认证模式、URL 处理方式，以及请求实际发起的位置都可能不同。这里不作特定版本的端到端兼容承诺。接入敏感工作前，请用合成数据核对实际请求路径。远程执行的客户端无法访问你电脑上的 `127.0.0.1`。

</details>

<a id="why-cosy"></a>
## 多一层检测，不必换一套工作流

| 设计选择 | 对现有技术栈意味着什么 |
| :--- | :--- |
| **单文件核心** | 审阅或部署 `worker.js`；核心使用 Web Fetch、Web Streams 和 Web Crypto API。 |
| **协议透传** | 保留上游请求结构，而不是在不同 API 家族之间转换。 |
| **请求级映射** | 在当前请求中还原原值，无需持久化映射数据库。 |
| **理解流式边界** | 处理受支持的文本和工具参数增量，包括跨 SSE 事件、跨 HTTP chunk 的占位符。 |
| **显式检测策略** | 通过 URL 字母开关选择结构化检测、高熵检测与 Gitleaks 兼容规则。 |
| **MIT 许可证** | 阅读[许可证](LICENSE)与[第三方声明](THIRD_PARTY_NOTICES.md)，把隐私层留在自己的技术栈中。 |

<a id="detectors"></a>
## 全开为起点，再按数据调优

```text
https://<cosy-host>/<flags>$<full-upstream-url>
```

**开关部分留空，即启用全部检测器。** `HPSIBEG` 是显式全开写法。未知字母返回 HTTP `400`，而不是静默改变策略。

| 开关 | 检测器 | 范围 |
| :---: | :--- | :--- |
| `H` | 高熵文本块 | 长度超过 8 的 ASCII 字母数字块；使用与长度相关的二元字符评分，排除纯数字块。 |
| `P` | 电话号码 | 中国大陆手机号与国际 `+…` 格式。 |
| `S` | 长 `sk-` 密钥 | `sk-` 后至少 60 位 ASCII 字母数字；不代表覆盖所有服务商的密钥格式。 |
| `I` | 中国居民身份证 | 对候选身份证号码进行校验码验证。 |
| `B` | 银行卡候选号码 | 13–19 位数字并通过 Luhn 校验，包含常见分组形式。 |
| `E` | 邮箱地址 | 匹配邮箱格式，例如 `alice@example.com`。 |
| `G` | Gitleaks 兼容规则 | 文档中的规则集包含 218 条 JavaScript 条目，支持关键词、secret groups、熵检查与允许列表。 |

按数据特点选择开关，再评估误报与漏报。校验码命中不证明账户或身份真实存在。`G` 是适合 serverless 的兼容实现，不承诺与 Gitleaks CLI 完全等价。[检测器细节 →](docs/REFERENCE.md#detectors)

<a id="compatibility"></a>
## 协议与流式处理

| API 家族 | 请求处理 | 响应处理 |
| :--- | :--- | :--- |
| **OpenAI Chat Completions** | JSON 文本脱敏 + 用户消息 Notice | JSON；受支持的 SSE 文本与 tool/function 增量 |
| **OpenAI Responses** | 字符串或消息数组输入 + Notice | JSON；受支持的 SSE 文本与函数参数增量 |
| **Anthropic Messages** | 消息脱敏 + 用户消息 Notice | JSON；受支持的 SSE 文本与工具 partial-JSON 增量 |
| **其他 JSON 端点** | 通用字符串脱敏；仅在识别出受支持的请求家族时注入 Notice | 文本与 JSON 还原；不对任意流式 schema 作全面兼容承诺 |

Cosy 不会把 OpenAI 请求转换为 Anthropic 请求，反之亦然。带有非空、非 JSON 请求体的请求会返回 HTTP `415`，而不是绕过脱敏直接转发。为避免破坏请求，部分控制字段、URL 和图像／音频载荷字段会跳过文本脱敏。

### 流式能力，有测试路径可循

仓库文档列出的测试覆盖 **75 字节占位符的每一个切分位置**、**单字节 HTTP 传输块**、受支持的 SSE 格式、工具／推理增量，以及本地 HTTP 和 Node 适配器集成。实现见 [`worker.js`](worker.js)，测试用例见 [`test/`](test/)。

```bash
npm test
npm run entropy-report
```

文档中的熵检测 fixture 将 **30,000 个自然词拼接样本中的 296 个（0.9867%）**判为高熵；随机 hex/base62 字符串的召回率随长度上升。这些是**合成测试样本结果，不是真实业务隐私保证、吞吐性能基准或独立安全审计**。[方法与复现 →](docs/ENTROPY.md)

<details>
<summary><strong>展开动画：占位符跨 SSE 分段，也能还原</strong></summary>

<p align="center">
  <picture>
    <source media="(prefers-reduced-motion: reduce)" srcset="docs/readme/sse-restoration-zh-poster.png">
    <img src="docs/readme/sse-restoration-zh.gif" alt="中文机制示意：SSE 占位符分段到达，Cosy 缓冲不完整标记，收到完整且已知的占位符后还原原值。" width="1040">
  </picture>
</p>

机制示意，非实测录屏。摘要与 SSE 封装经过缩略；演示的是已知占位符的缓冲与还原，不代表任意流式格式都已通过兼容性验证。

</details>

<a id="deployment"></a>
## 部署在你信任的环境中

| 运行时 | 入口 | 使用方式 |
| :--- | :--- | :--- |
| **Cloudflare Workers** | `worker.js` | Module Worker；无需应用构建步骤 |
| **Deno** | `worker.js` | 直接运行，或作为 Deno Deploy 入口 |
| **Node.js 20+** | `node-server.mjs` | 本地开发适配器 |

<details>
<summary><strong>Cloudflare Workers</strong></summary>

配置好 Wrangler 与 Cloudflare 账号后，在仓库目录执行：

```bash
npm test
npx wrangler deploy
```

`wrangler.toml` 已指向 `worker.js`，也可以直接将文件上传为 Module Worker。请将上游允许列表配置为 **Worker 变量**；仅在本地 shell 中设置变量，并不会配置线上 Worker。

```text
REDACT_ALLOWED_HOSTS=api.openai.com,api.anthropic.com
```

需要时加入自己的上游主机名。Wrangler 是部署工具，不是网关的运行时依赖。开放公网流量前，还需添加访问控制并阅读[安全边界](#security)。

</details>

<details>
<summary><strong>Deno</strong></summary>

在可信环境中运行，并限制上游主机：

```bash
REDACT_ALLOWED_HOSTS=api.openai.com,api.anthropic.com \
  deno run --allow-net --allow-env worker.js
```

直接执行时会调用 `Deno.serve(...)` 并读取环境变量。同一模块也可作为 Deno Deploy 项目的入口；请在对应部署中配置环境变量与访问控制。

</details>

<a id="security"></a>
## 安全是一条边界，不是一枚徽章

**网关属于信任范围；上游不应获得已命中的敏感原文。** 原始请求、服务商凭证和替换映射会存在于网关运行时。部署到托管环境意味着信任该宿主，不等于所有处理都留在本机。

| Cosy 会做什么 | 不作哪些保证 |
| :--- | :--- |
| 转发前替换命中的文本 | 发现全部敏感值，或保持所有任务的回答质量不变 |
| 替换映射仅在当前请求中存在，不持久化 | 密码学意义的擦除、请求匿名化，或跨请求还原 |
| 还原未被修改的已知响应占位符 | 找回模型改写或凭空生成的占位符 |
| 拒绝不受支持的非 JSON 请求体 | 检查图像／音频内容，或脱敏所有 URL、请求头和控制字段 |
| 过滤代理／浏览器身份相关请求头 | 隐藏上游凭证：`Authorization` 和 `x-api-key` 会按设计转发 |

**对外开放部署前：** 配置 `REDACT_ALLOWED_HOSTS`，保留私有上游阻断，并添加外部认证／访问控制。主机允许列表限制目标地址，**不会**认证调用者。检查周边组件的请求日志与留存策略；不要把内置主机名检查当作完整的网络出口或 SSRF 防护。

默认限制为**每个请求体 16 MiB**、**每个请求最多 16,384 个不同原值替换**。默认 CORS 为 `*`，它不是访问控制。[全部运行时配置 →](docs/REFERENCE.md#settings) · [现有安全策略 →](SECURITY.md)

<a id="faq"></a>
## 几个重要问题

<details>
<summary><strong>“凭据留在本地”是否等于“主机没有任何凭据出网”？</strong></summary>

不等于。这表达的是本地部署下，对受检查正文中的命中凭据进行出网前替换的目标，不是整机零泄漏承诺。`Authorization`、`x-api-key` 等认证头会按设计发送给上游；跳过的字段、未命中的文本和绕过网关的流量不在这一承诺范围。云端 Worker 或远程 Deno 实例也不是你的本地主机。

</details>

<details>
<summary><strong>这是加密，或者不可逆匿名化吗？</strong></summary>

都不是。Cosy 用带运行时盐的哈希标识替换选定字符串，再用内存查找表反向恢复。周边提示词仍会发送给上游。哈希标识也不能消除所有推断与关联风险。

</details>

<details>
<summary><strong>“请求级映射”究竟是什么意思？</strong></summary>

原文到占位符的映射只属于当前请求及其响应流，结束后会被丢弃。盐按运行时／isolate 生成，不是每次请求生成；同一运行时内，相同原文可能产生相同占位符。旧请求中的占位符，只有在当前请求重新建立对应映射后才能还原。

</details>

<details>
<summary><strong>现有工作流一定保持原样吗？</strong></summary>

不一定。命中的文本会被替换；支持的用户消息会插入 Notice；部分请求头会被过滤；协议专用流式处理只覆盖已识别字段。需要原值参与的任务可能受影响，误报也可能移除有用上下文。先用合成样本测试自己的提示词和工具链。

</details>

<details>
<summary><strong>可以使用内网或本地上游吗？</strong></summary>

主机名规范化之后，默认会阻断字面形式的私有、回环和链路本地目标。仅在有意设计的可信私有部署中关闭 `REDACT_BLOCK_PRIVATE_UPSTREAMS`。允许列表和网络层出口限制仍然重要。[路由与错误 →](docs/REFERENCE.md#routing)

</details>

<a id="contributing"></a>
## 一起把这条边界做得更好

欢迎贡献检测器回归用例、误报／漏报报告、可复现的客户端接入验证，以及 SSE 边界案例。提交 [Issue](https://github.com/CassiopeiaCode/CosyRedactGateway/issues) 时，请说明运行时、协议、开关，以及**合成或已脱敏**的复现数据。不要附上真实凭证或私有提示词。提交修改前运行 `npm test`；安全问题报告请遵循 [SECURITY.md](SECURITY.md)。

### 延伸阅读

[路由、生命周期与运行时配置](docs/REFERENCE.md) · [熵检测校准](docs/ENTROPY.md) · [源码](worker.js) · [测试](test/) · [第三方声明](THIRD_PARTY_NOTICES.md)

### 致谢与许可证

URL 外壳沿用 [TransformVetter](https://github.com/CassiopeiaCode/TransformVetter) 的 `/{config}${upstream-url}` 约定；Cosy 不包含其协议转换或内容审核引擎。部分规则签名源自 Gitleaks，详见[第三方声明](THIRD_PARTY_NOTICES.md)。

感谢 [Linux.do](https://linux.do) 社区的支持。本项目使用 [MIT 许可证](LICENSE)。

<p align="center"><sub>代码交给 AI。凭据，不该跟着走。先在本地检查，再交给上游。</sub></p>
