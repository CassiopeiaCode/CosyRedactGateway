<p align="center">
  <picture>
    <source media="(max-width: 600px)" srcset="docs/readme/hero-mobile.svg">
    <img src="docs/readme/hero.svg" alt="Cosy Redact Gateway — 使用需要的 AI，减少不必要的敏感信息暴露。" width="1040">
  </picture>
</p>

<h1 align="center">Cosy Redact Gateway</h1>

<p align="center"><strong>用你需要的上游模型，保留它不需要知道的秘密。</strong></p>

<p align="center">
  <a href="LICENSE"><img src="docs/readme/badge-license.svg" alt="MIT 许可证"></a>
  <a href="worker.js"><img src="docs/readme/badge-core.svg" alt="单文件核心"></a>
  <a href="package.json"><img src="docs/readme/badge-dependencies.svg" alt="零运行时依赖"></a>
  <a href="#security"><img src="docs/readme/badge-mapping.svg" alt="请求级映射"></a>
  <a href="#compatibility"><img src="docs/readme/badge-streaming.svg" alt="JSON 与 SSE"></a>
</p>

<p align="center">
  <a href="README.md">English</a> · <strong>简体中文</strong>
  <br>
  <a href="#quick-start">快速开始</a> ·
  <a href="#how-it-works">看看脱敏过程</a> ·
  <a href="#integrations">接入现有应用</a> ·
  <a href="#security">安全边界</a> ·
  <a href="docs/REFERENCE.md">技术参考</a>
</p>

Cosy 是一个可自行部署的 LLM API 隐私中继：先替换**被检测器命中的敏感文本**，再转发请求；响应中的已知占位符被原样返回时，还原为原值——包括受支持的 SSE 流与工具调用参数。

**一个可部署的 `worker.js`，无需数据库，零运行时依赖。** 核心运行于 Cloudflare Workers 或 Deno；Node 20+ 适配器用于本地开发。保留原有上游协议。

> **先明确边界：** Cosy 会看到原文，请部署在可信环境。检测无法覆盖全部秘密，托管部署也不等于仅在本机处理。[阅读安全模型 →](#security)

<a id="how-it-works"></a>
## 看清哪些内容发给了模型

客服提示词中的邮箱、复制配置时带上的凭证、工具结果里的敏感值，都可能随一条普通 LLM 请求发送出去。Cosy 在请求到达上游前，增加一个替换命中内容的环节。

<p align="center">
  <picture>
    <source media="(max-width: 600px)" srcset="docs/readme/flow-mobile.svg">
    <img src="docs/readme/flow.svg" alt="应用 → Cosy 脱敏 → 上游模型 → Cosy 还原 → 应用。仅替换检测命中的文本；还原要求模型原样返回当前请求中的已知占位符。" width="1040">
  </picture>
</p>

| 阶段 | 内容示意 |
| :--- | :--- |
| **应用发送** | `请联系 alice@example.com。` |
| **上游看到** | `请联系 {{Redact:…}}。` |
| **模型返回** | `我会联系 {{Redact:…}}。` |
| **应用收到** | `我会联系 alice@example.com。` |

上面的占位符为便于阅读而缩写；真实占位符包含 64 位十六进制 SHA-256 摘要。模型需要原样保留它。示意中省略了协议提示 Notice。[查看完整生命周期 →](docs/REFERENCE.md#lifecycle)

<details>
<summary><strong>工具调用参数也可以完成同样的往返</strong></summary>

```text
客户端提交的工具结果
  {"email":"alice@example.com"}

发送给模型的脱敏内容
  {"email":"{{Redact:…}}"}

模型返回的工具调用参数
  {"email":"{{Redact:…}}"}

客户端收到的参数
  {"email":"alice@example.com"}
```

Cosy 负责恢复原值，**不会**执行工具，也不负责授权工具操作。工具内容在后续请求中再次提交时，会重新扫描；替换映射不会跨请求保留。

</details>

<a id="why-cosy"></a>
## 小，是一种设计选择

| 设计选择 | 对现有技术栈意味着什么 |
| :--- | :--- |
| **单文件核心** | 审阅或部署 `worker.js`；核心使用 Web Fetch、Web Streams 和 Web Crypto API。 |
| **协议透传** | 保留上游请求结构，而不是在不同 API 家族之间转换。 |
| **请求级映射** | 在当前请求中还原原值，无需持久化映射数据库。 |
| **理解流式边界** | 处理受支持的文本和工具参数增量，包括跨 SSE 事件、跨 HTTP chunk 的占位符。 |
| **显式检测策略** | 通过 URL 字母开关选择结构化检测、高熵检测与 Gitleaks 兼容规则。 |
| **MIT 许可证** | 阅读[许可证](LICENSE)与[第三方声明](THIRD_PARTY_NOTICES.md)，把隐私层留在自己的技术栈中。 |

<a id="quick-start"></a>
## 快速开始

### 1. 在本地启动

准备好 **Node.js 20+**、Git 和终端。HTTP 示例使用 Bash 与 curl 7.76+；也可以使用后面的 SDK 示例。网关没有需要安装的运行时依赖。

```bash
git clone https://github.com/CassiopeiaCode/CosyRedactGateway.git
cd CosyRedactGateway
npm start
```

开发适配器默认监听 `http://127.0.0.1:8787`。保持这个终端运行。

### 2. 确认服务已启动

在另一个终端执行：

```bash
curl --fail --silent --show-error http://127.0.0.1:8787/healthz
```

预期 JSON 响应（此处排版便于阅读）：

```json
{
  "ok": true,
  "service": "cosy-redact-gateway",
  "route": "/<flags>$<upstream-url>",
  "flags": "HPSIBEG",
  "defaultAll": true
}
```

这一步检查本地服务是否可用，不检查上游连通性或检测质量。**不需要 API Key。** 要运行仓库的回归测试，在项目目录执行 `npm test`。

### 3. 发出第一条脱敏请求

用你平时管理密钥的方式，在当前 shell 中设置 `OPENAI_API_KEY`。以下 Bash 示例使用 `gpt-4.1-mini`；接入自己的服务时，请选择账号可用的模型。

```bash
: "${OPENAI_API_KEY:?Set OPENAI_API_KEY in this shell first}"

curl --fail-with-body --no-buffer \
  -H 'content-type: application/json' \
  -H "authorization: Bearer ${OPENAI_API_KEY}" \
  --data '{
    "model": "gpt-4.1-mini",
    "messages": [{
      "role": "user",
      "content": "Repeat this email address exactly: alice@example.com"
    }],
    "stream": true
  }' \
  'http://127.0.0.1:8787/E$https://api.openai.com/v1/chat/completions'
```

`E` 只启用邮箱检测，便于观察效果。模型原样返回占位符时，客户端应收到恢复后的邮箱。这是一次**真实上游调用**，可能产生服务商费用；模型输出并非确定性的。

**开启全部检测器：** 把 `/E$https://` 改成 `/$https://`。在 shell 命令中，路由 URL 请使用**单引号**，避免 `$` 被展开。

<a id="integrations"></a>
## 接入你的现有应用

保留上游 API Key、模型和请求结构，把目标地址改成 Cosy 路由。客户端需要完整保留嵌入的上游 URL，并正确追加 API 路径。

### OpenAI Python SDK

在**应用环境**中安装 SDK，而不是给网关增加依赖：`python -m pip install openai`。设置好 `OPENAI_API_KEY` 并启动本地网关后：

```python
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url="http://127.0.0.1:8787/E$https://api.openai.com/v1",
)

response = client.responses.create(
    model="gpt-4.1-mini",
    input="Repeat this email address exactly: alice@example.com",
)
print(response.output_text)
```

预期路由路径以 `E$https://api.openai.com/v1/responses` 结尾；Chat Completions 使用相同的 Base URL。[SDK 配置参考](https://github.com/openai/openai-python)

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
  baseURL: 'http://127.0.0.1:8787/E$https://api.anthropic.com',
});

const message = await client.messages.create({
  model,
  max_tokens: 128,
  messages: [{
    role: 'user',
    content: 'Repeat this email address exactly: alice@example.com',
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
| 追加 `/chat/completions` 或 `/responses` 的 OpenAI 风格客户端 | `http://127.0.0.1:8787/E$https://api.openai.com/v1` |
| 追加 `/v1/messages` 的 Anthropic 风格客户端 | `http://127.0.0.1:8787/E$https://api.anthropic.com` |
| 自定义 HTTP 客户端 | 像 curl 示例一样，把完整上游端点放在 `$` 之后。 |

**支持协议，不等于完成了某个产品的兼容认证。** Cursor、Claude Code、Codex 等工具的版本、认证模式、URL 处理方式，以及请求实际发起的位置都可能不同。这里不作特定版本的端到端兼容承诺。接入敏感工作前，请用合成数据核对实际请求路径。远程执行的客户端无法访问你电脑上的 `127.0.0.1`。

</details>

<a id="detectors"></a>
## 选择要脱敏的内容

```text
https://<cosy-host>/<flags>$<full-upstream-url>
```

**开关部分留空，即启用全部检测器。** `HPSIBEG` 是显式全开写法。未知字母返回 HTTP `400`，而不是静默改变策略。

| 开关 | 检测器 | 范围 |
| :---: | :--- | :--- |
| `H` | 高熵文本块 | 长度超过 8 的 ASCII 字母数字块；使用与长度相关的 bigram 评分，排除纯数字块。 |
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

<p align="center"><sub>轻量的隐私层，清晰的信任边界，你原来的 LLM 技术栈。</sub></p>
