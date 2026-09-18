# 技术参考

[← 中文 README](../README.md) · [English reference](REFERENCE.en.md) · [English README](../README.en.md)

本文集中说明 README 背后的路由、脱敏生命周期、检测器、流式处理与部署配置。以 [`worker.js`](../worker.js) 的实现为准，并结合[测试用例](../test/)、[熵检测校准](ENTROPY.md)和[安全策略](../SECURITY.md)一起阅读。

**面向程序员的全开策略：** 使用 `/$https://…` 启用全部检测器，包括不依赖已知前缀的高熵凭据检测（配置开关 `H`）。本地部署会在转发前替换受检查正文中的命中内容，但不会隐藏上游认证头，也不保护主机的所有连接。[高熵检测：证据与边界](HIGH-ENTROPY.md)

<a id="routing"></a>
## 路由与错误

```text
https://<proxy-host>/<flags>$<full-upstream-url>
```

检测开关与上游目标都位于路径中。以下示例同时展示选定检测器和全开写法：

```text
https://proxy.example.com/HPSE$https://api.openai.com/v1/chat/completions
https://proxy.example.com/E$https://api.openai.com/v1/responses
https://proxy.example.com/P$https://api.anthropic.com/v1/messages
https://proxy.example.com/$https://api.example.com/v1/responses
```

`proxy.example.com` 与 `api.example.com` 是示意域名，不是项目提供的服务。请替换为自己控制或信任的部署。

开关留空等于启用 `HPSIBEG`。开关解析不区分大小写，未知字母会报错。上游查询参数会保留；目标只接受 HTTP 和 HTTPS，并拒绝 URL 中的用户认证信息。在 Shell 命令中为完整路由加单引号，确保 `$` 保持字面含义。中间代理和客户端也必须保留内嵌 URL，不能错误地规范化其中的 `//`。

| 状态码 | 网关中的含义 |
| :---: | :--- |
| `200` | `/` 或 `/healthz` 的健康响应；不表示上游可用性已经通过测试 |
| `400` | 开关或目标 URL 无效，或者请求体不是合法 JSON |
| `403` | 目标被 `REDACT_ALLOWED_HOSTS` 拒绝 |
| `404` | 非健康检查端点缺少正确的路由外壳 |
| `413` | 超过请求体或不同原值替换数量限制 |
| `415` | 非空请求体不是 JSON |
| `502` | 请求上游失败 |

除此之外，上游响应状态码会保留。网关不会跟随重定向，但客户端或反向代理可能有自己的重定向行为；不能把网关的设置视为完整的客户端策略。

### 请求头

上游认证与提供商请求头会转发，包括 `Authorization`、`x-api-key`、`anthropic-version`，以及 OpenAI 的组织／项目请求头。Cosy 的目标不是隐藏本次 API 调用用于上游认证的凭据。

逐跳请求头，以及代理／浏览器身份相关请求头会被过滤，包括 `Cookie`、`CF-*`、`Sec-*` 和转发 IP 请求头。JSON 改写后会调整请求内容长度。CORS 配置与调用者认证、上游授权是不同的控制。

<a id="lifecycle"></a>
## 脱敏生命周期

核心在运行时／isolate 启动时生成一个随机的 256 位盐；每个请求分别建立新的内存映射表。

```text
敏感原文
   ↓
SHA-256(original_text + runtime_salt)
   ↓
{{Redact:<64 位十六进制摘要>}}
```

完整占位符为 75 个 ASCII 字节。同一请求中的重复原文复用同一个占位符。同一运行时盐处理的不同请求，相同原文也会产生相同占位符，但各请求的查找表相互独立。盐不会在所有 Workers／Deno 实例之间保持全局一致。

还原使用当前请求中的“占位符 → 原文”映射，**不是对摘要进行解密**。请求及其响应流完成后，映射会被丢弃，不使用持久化替换数据库。这并不承诺密码学意义上的内存擦除，也不能控制宿主层日志与可观测性系统。

旧占位符若没有当前请求中的对应映射，就无法还原。如果在后续请求再次提交原文，它会重新接受扫描，并可能建立新的当前请求映射。

### Redact Notice：占位符保留提示

该提示始终启用，**不是** URL 开关。处理顺序是先脱敏，再向受支持的用户输入前添加简短的英文提示。下面保留原提示的英文内容，避免把文档翻译误当作运行时行为变更：

> Sensitive values are redacted before forwarding, including messages, tool inputs, and tool results. You may see {{Redact:sha256}} placeholders; treat them as opaque and preserve them exactly. Sensitive values you read appear as placeholders, and placeholders you emit in text or tool calls are restored to the original secrets.

对于 OpenAI Responses 的字符串 `input`，提示会加在字符串前面。对于受支持的消息数组，默认提示放在最后一条用户消息的文本内容前；设置 `REDACT_NOTICE_POSITION=first_user` 后会放在第一条用户消息前，从而在持续追加历史的 agent 会话中保持稳定的前缀位置。设置 `REDACT_NOTICE_ENABLED=false` 可完全关闭提示注入。没有用户消息时不会凭空添加用户消息。即使端点 URL 未知，只要请求体被识别为受支持的家族，仍可能收到该提示。

提示要求模型原样保留占位符，但不能强制模型遵守。模型改写或凭空生成占位符时，就无法保证还原。

### JSON 字符串与跳过的字段

启用 `REDACT_PARSE_NESTED_JSON` 时，看起来像 JSON 的字符串值会被递归解析、脱敏，再序列化回字符串，包括工具调用的 `arguments`。这保留 API 结构，但不一定保留原始 JSON 空白或逐字节表示。

为避免破坏请求，部分控制字段（如模型／角色／类型标识符）、URL 字段，以及较大的 base64 图像／音频载荷字段会被跳过。不检查二进制图像／音频内容；网关不提供“整个请求绝无数据泄漏”的保证。

<a id="streaming"></a>
## 流式还原

`text/event-stream` 响应会增量还原，并遵循下游背压。实现处理 OpenAI Chat Completions、OpenAI Responses 和 Anthropic Messages 中已识别的文本／增量通道，包括工具／函数参数增量及常见推理／文本字段。

如果数据块以可能的占位符前缀结束，流式层会保留该前缀，直到后续内容可以确认它是完整的已知占位符，或者不再可能组成占位符。这处理了 HTTP 传输块与逻辑 SSE 事件两种边界。

项目文档描述的测试覆盖 75 字节占位符的每一个切分位置，以及单字节传输块；还列出了工具／推理／partial-JSON 增量和本地 HTTP／Node 集成。在仓库运行 `npm test`，检查自己检出版本的测试结果。这不等于对未来或任意流式 schema 的全面兼容承诺。

<a id="detectors"></a>
## 检测器行为

| 开关 | 匹配行为 |
| :---: | :--- |
| `H` | 长度感知的高熵 ASCII 字母数字块；长度严格大于 8，排除纯数字 |
| `P` | 中国大陆手机号与国际 `+…` 电话格式 |
| `S` | `sk-` 后至少 60 位 ASCII 字母数字 |
| `I` | 带校验码验证的中国居民身份证候选号码 |
| `B` | 13–19 位数字、通过 Luhn 校验的银行卡候选号码，包含常见分组形式 |
| `E` | 邮箱地址格式匹配 |
| `G` | Gitleaks 兼容的 JavaScript 规则评估：关键词、secret groups、Shannon 熵阈值和允许列表 |

文档中的 `G` 规则集包含 **218 条 JavaScript 条目**。这是规则条目数，不是经过验证的提供商数量或召回保证。部分签名源自 Gitleaks，必须保留 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。该评估器不承诺与 Gitleaks CLI 的所有行为完全等价。

### 高熵检测的评分方式

`H` 按空白和特殊字符切分文本，并保留偏移量。它使用英文字符二元组的交叉熵模型对符合条件的文本块评分，而不只是普通的经验 Shannon 熵。阈值随长度变化，并在校准锚点之间线性插值。独立的字符多样性检查会排除重复字符串，纯数字块留给结构化检测器处理。

既有确定性本地校准样本记录如下：

| 样本类别 | 已记录的结果 |
| :--- | :--- |
| 自然词拼接 | `296 / 30000 = 0.9867%` 被判为高熵 |
| 随机 hex/base62，长度 9 | 召回率约 91–92% |
| 随机 hex/base62，长度 12 | 召回率约 96–98% |
| 随机 hex/base62，长度约 16 | 召回率高于 99% |
| 随机 hex/base62 样本集，长度 24／32 | 在相应样本集中为 100% |

这些数字描述特定校准下的合成样本，不代表系统整体精确率／召回率，不保证非英文内容的效果，也不是生产性能测量。参阅 [ENTROPY.md](ENTROPY.md)，并运行：

```bash
npm run entropy-report
```

<a id="settings"></a>
## 运行时配置

| 变量 | 默认值 | 含义 |
| :--- | :--- | :--- |
| `REDACT_ALLOWED_HOSTS` | 未设置 | 逗号分隔的上游主机名允许列表。未设置时允许任意主机，但仍受其他检查约束。 |
| `REDACT_BLOCK_PRIVATE_UPSTREAMS` | `true` | 在解析和规范化主机名后，拒绝已识别的私有、回环、链路本地和元数据目标。 |
| `REDACT_PARSE_NESTED_JSON` | `true` | 递归脱敏看起来像 JSON 的字符串，包括工具参数。 |
| `REDACT_MAX_BODY_BYTES` | `16777216`（16 MiB） | 用于 JSON 脱敏的最大缓冲请求体。 |
| `REDACT_MAX_REDACTIONS` | `16384` | 每个请求允许替换的不同原文数量上限。 |
| `REDACT_NOTICE_ENABLED` | `true` | 是否向支持的对话请求注入 Redact Notice；设为 `false`、`0`、`no` 或 `off` 可关闭。 |
| `REDACT_NOTICE_POSITION` | `last_user` | Notice 注入位置，可选 `last_user` 或 `first_user`；后者适合需要稳定前缀缓存的增长型 agent 历史。 |
| `REDACT_CORS_ORIGIN` | `*` | `Access-Control-Allow-Origin` 的值。 |
| `HOST` | `127.0.0.1` | 仅用于 Node 开发适配器。 |
| `PORT` | `8787` | 仅用于 Node 开发适配器。 |

变量应配置在实际执行网关的运行时。仅在本地部署 Shell 设置变量，不会自动填充线上 Cloudflare Worker 变量。直接执行 Deno 时通过 `Deno.env.toObject()` 读取环境；`--allow-env` 允许该访问。

转发前需要取得请求体以便解析和脱敏。在内存受限环境中应降低请求体和替换数量限制。这些限制不能替代外部请求体上限、并发控制或限流。

<a id="deployment-boundary"></a>
## 部署信任边界

**需要信任：** 客户端、Cosy 部署、运行时运营方，以及所有能够看到原始流量的周边基础设施。

**减少暴露：** 发往指定上游的已命中字符串原值。未命中文本、跳过字段、认证头和相关上下文，仍可能被上游看到。

对外开放前，配置上游允许列表、外部调用者认证／访问控制、适当的 CORS 策略、网络层出口限制，以及日志／留存控制。除非是有意设计的可信私有部署，否则保留私有上游阻断。

内置主机检查针对解析／规范化后的主机名，不是完整的 DNS 解析或网络层 SSRF 防护。允许列表不认证调用者，CORS 也不是访问控制。不能仅因启用了文本脱敏，就把不受限制的实例宣传为安全服务。

相同运行时内，相同原文可能产生重复占位符，周边提示词也仍可能暴露信息。无论工具参数是否已还原，应用都必须独立授权工具动作。

项目的安全报告与部署指导见 [SECURITY.md](../SECURITY.md)。

---

[返回中文 README](../README.md) · [English reference](REFERENCE.en.md) · [English README](../README.en.md)
