# 模块投稿台（MODULE·PANEL）

给中文 KernelSU / Magisk 玩机社区用的**纯静态投稿站**：在浏览器里把 zip 投进「人人共建的模块索引」，
同时作为这个索引的对外门面。直连你现有的 Cloudflare Worker，本站不带任何服务端。

界面全中文，窄屏可用（手机与电脑同一个地址同一个界面）。

---

## 1. 你只需要改一个文件

**`public/scripts/config.js`** —— 改完直接托管就生效，没有构建步骤。

| 待填 | 位置 | 说明 |
|---|---|---|
| **后端地址** | `config.js:13` `API_BASE` | Worker 根地址，结尾不带斜杠，例 `https://module-submit.xxx.workers.dev`。前端只请求 `${API_BASE}/check`、`${API_BASE}/submit`（以及下面第 4 项的核实端点）。**留空时投稿功能会被拦下并明确提示，不会静默失败。** |
| 公开索引地址 | `config.js:21` `INDEX_URL` | 「已收录模块」页直接 fetch 这个 MMRL JSON。不填则浏览页显示「索引地址待配置」，投稿功能不受影响。 |
| **反机器人校验** | `config.js:29-30` `TURNSTILE_SITEKEY` / `TURNSTILE_FIELD` | 留空 = 界面显示「待接入」说明，提交时只随表带一个空的 token 字段。填入 sitekey 后自动加载 Turnstile 脚本并渲染部件，token 用 `TURNSTILE_FIELD` 的字段名发出（后端字段名不同就只改这一行）。 |
| **酷安 UID 字段名** | `config.js:38` `COOLAPK_UID_FIELD` | 投稿人身份发两个字段：`uploader` = 昵称（索引里公开显示），`coolapkUid` = 酷安 UID 数字。后端约定的名字不同就改这一行。 |
| **酷安核实端点** | `config.js:49-50` `COOLAPK_USER_PATH` / `COOLAPK_VERIFY_REQUIRED` | 见下面第 2 节。路径留空 = 不核实，界面显示「未经核实」，投稿照常能提。`COOLAPK_VERIFY_REQUIRED: true` 则必须核实通过才放行。 |
| 一键加源 scheme | `config.js:60` `SCHEME_ADD_SOURCE` | 例 `kernelsu://mmrl?url=<你的 INDEX_URL>`，说明页会用它渲染加源按钮。 |
| 大小上限 | `config.js:55` `MAX_UPLOAD_BYTES` | 当前 `8 * 1024 * 1024`，**必须和服务端常量同步**，否则前端拦不住 / 前端误拦。 |
| 站名 | `config.js:63-64` | 只影响标题、导航铭牌与 `<title>`。 |

说明页（`#/about`）最后有一块「这个站自己的状态」，会把上面几项的实际接线情况显示出来 —— 你自己或别人打开就能看出哪里还没配。

## 2. 需要你在 Worker 侧配合的事（重要）

**跨域：`/submit` 我特意保持成「CORS 简单请求」。**
`multipart/form-data` 本身在 CORS 允许列表里，而且我在 `submitModule()`（`public/scripts/api.js:82` 起）
里**不设置任何自定义请求头**，所以浏览器不会发 `OPTIONS` 预检。因此你的 Worker 只需要：

- 给响应加 `Access-Control-Allow-Origin`（可以是 `*`，这个接口本来就公开）
- 给响应加 `Access-Control-Allow-Headers` 与 `OPTIONS` 预检处理作为保险（将来一旦有人给请求加头就需要）

`GET /check` 同理，只需 `Access-Control-Allow-Origin`。

我**没有**在前端做任何绕过（没改 `no-cors`、没上 JSONP、没加代理）。联调时若看到 CORS 报错，
那是后端响应头还没加，请在那里修。

**错误原因会被原样显示。** 文档写「失败返回 400 加中文原因」，我按两种形态都做了兼容
（`api.js:152` 的 `readReason` / `stripHtml`）：

- JSON：依次读 `error` → `message` → `reason` → `detail` 字段
- 纯文本：直接当原因显示（超过 300 字截断）；如果返回的是 HTML 错误页（Cloudflare 那种），
  则退化成 `服务端拒绝了这次投稿（HTTP 400）。`

**`/check` 只读 `status`，不看状态码**，四种值 `new / version_update / recorded / unknown` 的文案
都在 `api.js:20` 的 `CHECK_STATUS` 里。非 2xx 或 JSON 解析失败会走「查不了重」分支，
照样允许投稿，不阻塞。

### 新增端点：`GET /user?uid=<酷安UID>`（核实投稿人身份）

**这件事前端做不了，只能你加。** 我核实过：`api.coolapk.com` 不给浏览器开放跨域，
而且它的鉴权要 `X-App-Token` —— 那个 token 由 `AuthUtils` 的 **native 库**用设备指纹 +
时间戳 + MD5 生成（见 `daimiaopeng/coolapk-desktop` 的 `docs/COOLAPK_API_DOCUMENTATION.md`
第 1.2 / 1.3 节），把签名逻辑写进一个纯静态站等于把它公开，而且照样会被 CORS 拦死。
所以浏览器直连酷安只会「静默失败」，正是你文档里点名不要的那种绕法。

请在 Worker 上加一个转发端点，契约照 `/check` 的风格 —— **任何情况都回 HTTP 200，前端只读 `status`**：

```
GET ${API_BASE}/user?uid=2781460
  → {"status":"verified","uid":"2781460","nickname":"某某","avatar":"https://avatar.coolapk.com/..."}
  → {"status":"not_found"}      查无此人 —— 前端会拦住，不让提交
  → {"status":"unavailable"}    酷安不可达/超时 —— 前端只提示，不拦
```

服务端侧要查的接口（同一份文档第 5.1 / 5.2 节）：

- `GET https://api.coolapk.com/v6/user/space?uid=<UID>`（主页头部信息，含昵称）
- 或 `GET https://api.coolapk.com/v6/user/profile?uid=<UID>`（基本公开资料）
- 必带请求头：`X-App-Id: com.coolapk.market`、`X-App-Version`、`X-App-Code`、
  `X-Api-Version: 16`、`X-App-Device`、以及那个 `X-App-Token`；只读公共接口不用登录 Cookie
- 响应形如 `{"data":..., "message":"", "status":0}`，`status:0` 才是成功；
  用户不存在时酷安一般回 `status` 非 0 或 `data` 为空 —— 这两种都映射成你的 `not_found`
- **建议加缓存**（KV 里存 UID → 昵称，TTL 按天）：一是酷安对无登录态的高频请求会限流，
  二是同一个人反复投稿没必要每次打过去。这个端点同样需要 `Access-Control-Allow-Origin`。

前端行为（`api.js` 的 `lookupCoolapkUser` + `app.js` 的 `runUidCheck`）：UID 输入停止 500ms 后自动查，
核实通过会把昵称自动填进「投稿者署名」，并显示头像与 UID；`not_found` 会挡住提交按钮；
端点没接或不可达时只标「未经核实」，不把人拦在外面（`COOLAPK_VERIFY_REQUIRED: true` 可改成硬拦）。

### 出处现在只收酷安站内链接

`normalizeCoolapkUrl()`（`api.js:179`）用 `URL` 解析而不是字符串正则：必须 `http(s)` 协议、
主机是 `coolapk.com` 或其子域，`coolapk.com.evil.tld`、`https://evil.tld/https://www.coolapk.com`、
`javascript:` 都会被拒。用户只粘 `www.coolapk.com/feed/123` 时会自动补上 `https://`。
**服务端建议同样按这个规则校验一遍**，前端校验挡不住直接打接口的人。

## 3. 功能对照

| 需求 | 实现位置 |
|---|---|
| 选 zip → 自动解析预填（可改） | `zipread.js` + `moduleprop.js` + `app.js:intake()/applyProp()` |
| 填完 ID 与版本号自动查重、实时显示 | `app.js:runCheck()`（防抖 420ms），结果显示在 02 面板下方 |
| 出处 / 署名必填 + 明确说明为什么要填 | 面板 03「出处与身份」：出处限酷安站内链接、署名与酷安 UID 双字段；说明页 D 节解释为什么必须是 UID |
| 酷安 UID 核实（含端点未接入时的降级） | `api.js:lookupCoolapkUser()` + `app.js:runUidCheck()`，四种状态 verified / not_found / unavailable / off，通过后自动填昵称并显示头像 |
| 不可跳过的一屏确认，未勾选不能提交 | `#layer-confirm`，仿 Bootloader 解锁警告屏；三条勾选全中才解锁按钮 |
| 成功给 PR 链接 | `app.js:showSuccess()`，含「点进去看审核进度」与后续流程说明 |
| 失败显示中文原因且能重试 | `app.js:showFailure()`：表单内容与已选文件都留着，「重试提交」直接复用 |
| 已收录模块浏览页（MMRL） | `#view-index` + `api.js:fetchIndex()/normalizeIndex()`，搜索按 ID/名称/作者/描述过滤并高亮 |
| 预留 Turnstile token 字段 | `api.js` 始终 append 该字段；`config.js:29` 控制是否渲染真部件 |
| 上传大小 / zip 形态前端预检 | 超过上限、非 `.zip`、根目录无 `module.prop` 都在选文件那一刻就拒掉并把原因打出来 |

关于「版本更新需人工审核」这条，界面在三个地方如实说明了：查重结果 `version_update` 的提示、
确认屏第三条勾选、以及说明页的流程管线里把「人工审核」单独高亮。没有把投稿写成「提交即上线」。

## 4. 本地预览 / 自检

```bash
node tools/serve.mjs        # http://127.0.0.1:4321/   （PORT=xxxx 可换端口）
node tools/selftest.mjs     # zip 解析与 module.prop 预填的自检
node tools/build.mjs        # 复制 public/ -> dist/ ，供静态托管商当输出目录
node tools/fetch-fonts.mjs  # 换字体时才需要：重新下载 woff2 子集
```

只要 Node 18+，**零依赖**（没有 package 安装步骤，`package.json` 只用来声明 ESM 和脚本）。

`selftest.mjs` 会手搓真实字节（本地头 + 中央目录 + EOCD）喂给浏览器端同一份解析代码，覆盖：
deflate 与 stored 两种压缩、UTF-8 中文内容、`description` 里再出现 `=`、目录条目、
尾部注释导致 EOCD 要往回扫、`module.prop` 被套进子文件夹（要判为不可投并给出提示）、
以及非 zip 输入。另外还覆盖 MMRL 索引归一化（`versions` 乱序取最大 versionCode、缺字段回落、
非 MMRL 结构报错）和酷安规则（UID 位数/非数字、假域名 `coolapk.com.evil.tld`、
路径里藏域名、`javascript:` 协议、网盘链接不算出处、后端未接线时核实走 `off` 而不是抛错）。
共 37 项断言。

## 5. 部署

**Cloudflare Pages（你文档里的方案）**
直接以 `public/` 作为发布根目录即可（构建命令留空，输出目录填 `public`）；
或先 `node tools/build.mjs` 然后发布 `dist/`。项目还没有域名的话，用 `*.pages.dev` 子域名就行。

**Qoder Sites**
本项目当前就是走这条路发布：`node tools/build.mjs` 后以 `webDirectory: "dist"` 准备并发布。
同一份源码，两种托管都只要求「一个含 `index.html` 的静态目录」。

**注意**：站点与后端不同源，所以上面第 2 节的 CORS 响应头在哪个托管商下都必须有。

## 6. 技术选型与理由

- **零框架、零依赖的原生 ES Module**。需求是纯静态站，而且面向国内手机用户：
  不引入 React/打包器，产物就是 200 KB 出头的 HTML+CSS+JS+字体，源码可以直接读懂，
  以后你自己或者别人接手不需要装任何东西。
- **zip 前端解析自己写（`zipread.js`）而不是引 JSZip**。只用浏览器原生
  `DecompressionStream('deflate-raw')`（Chrome 80+ / Edge 84+ / Firefox 113+ / Safari 16.4+），
  少一个约 100 KB 的第三方包，也没有 CDN 依赖。不支持这个 API 的浏览器不会报错中断，
  而是退回「手动填表」并在开机读数里写明原因 —— 表单照常能用。
- **字体随站点静态托管**（`public/fonts/`，OFL 授权的 Chakra Petch + IBM Plex Mono 子集）。
  中文正文用系统字体栈（PingFang SC / HarmonyOS Sans / MiSans / 思源黑体 / 微软雅黑）：
  `fonts.googleapis.com` 在大陆不可达，如果依赖 CDN，整套视觉会在目标用户手机上直接塌成默认字体，
  而中文 webfont 动辄几 MB，不适合手机流量场景。
- **`/submit` 用 XMLHttpRequest 而不是 fetch**：只有这一个原因 —— fetch 拿不到上传进度，
  而这里最大要传 8 MB，没有进度条用户会以为页面卡死。`/check` 与索引仍用 fetch。
- **日/夜双主题**：全部颜色走 CSS 变量，`[data-theme="light"]` 只换色与氛围层，版式一套到底。
  默认跟随系统 `prefers-color-scheme`，用户点过右上角开关后写进 `localStorage`（键名 `panel-theme`）并固定下来；
  没手动选过时，系统换主题页面会跟着换。首帧不闪黑底靠 `index.html` 里那段 inline 脚本先设 `data-theme`
  （`app.js` 是 module、defer，等它就来不及了）。琥珀色分成两组变量：`--amber` 是**文字/描边**用的前景色
  （浅色模式下是深棕，保证对比度），`--amber-fill` 是**色块填充**（按钮底、勾选块、危险条纹、进度条），
  两者在夜间模式下同色、日间模式下不同色 —— 只用一个变量的话，浅色模式必然要么按钮文字看不清、要么正文对比度不够。
- **hash 路由（`#/submit` `#/index` `#/about`）**：静态托管上不需要 rewrite 规则就能刷新/深链接，
  拖到任何托管商都不用改配置。
- **索引/文件名/服务端错误等外部数据一律用 DOM 节点拼装**（`node()` + `textContent`，
  高亮走 `createTextNode` + `<mark>`），没有一处把外部内容塞进 `innerHTML`；
  下载链接和 PR 链接都过 `safeUrl()`，只放行 http/https。

## 7. 我看到的需求问题（按你说的，直接讲）

1. **`author` / `uploader` / `coolapkUid` 三者极易混淆**，含义完全不同：原作者、投稿人昵称、投稿人身份标识。
   现在分成两个面板 —— 「模块作者」留在 02 元数据里并标注「写原作者，不是投稿人」；
   03 面板专管身份，昵称（公开显示）与酷安 UID（审核与追责用）并排填，核实通过后昵称自动带入。
2. **`source` 现在限酷安站内链接**（按你的要求）。我用 `type=text` + 自己的 `normalizeCoolapkUrl()`
   而不是 `type=url`：`type=url` 会在浏览器层面拦住 `www.coolapk.com/feed/123` 这种漏写协议的粘帖，
   报错信息还是浏览器原生的英文提示，没法按我们的文案说话；现在会自动补 `https://` 并给出中文原因。
   代价是**这条规则前端挡不住直接打接口的人**，服务端必须同样校验一遍主机名。
3. **`versionCode` 用 `type=number`** 会带来滚轮改值、`e` 字符等输入意外。现在前端只接受
   `/^\d+$/`，非整数会明确报错；但服务端最好同样按整数解析（文档写「整数版本号」，默认你会处理）。
4. **查重结果不是提交的前置条件**：`unknown` 和「查不了重」都允许继续投稿（符合你文档
   「任何情况下都返回 200、客户端只读 status」的设计意图）。只有 `recorded`（已收录且不更新）
   我给的文案是「不需要再投稿」，但没有硬拦 —— 让服务端做最终判断更稳。
5. **一个后端侧建议**：`/submit` 现在无鉴权限流，而它会往 GitHub Release 写文件并开 PR。
   Turnstile 加上之前，建议先按 IP/署名做个粗限流，否则第一个被刷的会是 PR 队列而不是你预期的脏包。
6. 站点没有自己的 favicon 文件，用了一个内联 SVG data-URI，省一个请求也不会有 404。
