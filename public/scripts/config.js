// ===========================================================================
//  SITE CONFIG —— 部署前唯一需要改的文件
//  整个站点没有任何构建步骤，改完这个文件直接静态托管即可生效。
// ===========================================================================

export const CONFIG = {
  // --- 待填 ①：投稿后端（Cloudflare Worker）地址 -----------------------------
  // 填法：Worker 的根地址，结尾不要带斜杠。
  //   例：'https://module-submit.xxxxx.workers.dev'
  //   例：'https://api.你的域名.com'
  // 前端会请求 `${API_BASE}/check`、`${API_BASE}/user` 与 `${API_BASE}/submit`
  // （另外启动时问一次 `${API_BASE}/` 拿真实大小上限）。
  // 留空字符串时投稿页仍可正常填写，但 /check 与提交会被拦下并明确提示未配置。
  API_BASE: "https://sukisu-module-submit.lyfsearch.workers.dev",

  // --- 待填 ②：公开索引（MMRL JSON）地址 -------------------------------------
  // 「已收录模块」页直接 fetch 这个 URL。填 GitHub raw / jsDelivr / 自有 CDN 都行。
  //   例：'https://raw.githubusercontent.com/你的仓库/main/index.json'
  //   例：'https://cdn.jsdelivr.net/gh/你的用户名/你的仓库@main/index.json'
  // 注意：浏览器直连 raw.githubusercontent.com 在大陆不稳定，别把它当订阅地址。
  // 留空时浏览页显示「索引地址待配置」，不影响投稿功能。
  //
  // 这里填的是**自家 Worker 的镜像端点**，不是 jsDelivr。理由是一条实测：jsDelivr 对
  // `@分支` 形式的地址回 `Cache-Control: public, max-age=604800`（七天），源站清完边缘缓存之后，
  // 已经取过索引的浏览器 / 管理器里那份旧的还能留七天 —— 而「这个模块被下架了」恰恰是最不能
  // 拿旧数据回答的问题。镜像端点把头交回我们手里（`max-age=60` + 弱 ETag，回源由索引仓库
  // 合并后那次 purge 之外的另一条路径保证新鲜）。
  // jsDelivr 那条地址仍然可用，当作 Worker 挂掉时的备用订阅地址：
  //   'https://cdn.jsdelivr.net/gh/SukiSU-Community/modules-repo@main/json/modules.json'
  // 台账不用单独填：公示页按同目录换文件名推导出 /dispositions.json，那个端点也存在。
  INDEX_URL: "https://sukisu-module-submit.lyfsearch.workers.dev/index.json",

  // --- 处置台账（下架 / 拉黑）地址 -------------------------------------------
  // 这里是**留空**用的：留空就从 INDEX_URL 换文件名的到 —— 在索引仓库里
  // json/modules.json 与 json/dispositions.json 是同一目录下的两个文件，
  // 抄一整条 URL 只会多出一个会漂移的定义处。
  // 只有把台账放去了别处（另一个 CDN、另一个仓库）才需要显式填。
  //   例：'https://cdn.jsdelivr.net/gh/你的用户名/你的仓库@main/json/dispositions.json'
  DISPOSITIONS_URL: "",

  // --- 申诉与治理入口（索引仓库的 issue 列表）--------------------------------
  // 处置公示页（#/incidents）末尾那段「不服去哪儿说话」用的就是这个地址。
  // 为什么单独填、不从台账里某条 by 指针反推：一条处置的证据可以指向**别的**仓库的
  // issue（处置记录本来就允许引用别的讨论），拿它当「本仓库申诉入口」是猜的；
  // 而台账为空时更是根本无从反推。申诉入口是一个决定，不是一个派生值。
  // 留空时那一段会明说「地址还没配置」，并把每条自己的「证据」链接指回可查的地方。
  //   例：'https://github.com/你的用户名/你的仓库/issues'
  ISSUES_URL: "https://github.com/SukiSU-Community/modules-repo/issues",

  // --- 待填 ③：Cloudflare Turnstile -----------------------------------------
  // 后端目前无鉴权限流，这里只做「预留接入位」：
  //   TURNSTILE_SITEKEY 留空 → 界面显示一行「反机器人校验待接入」的说明，
  //   不加载任何部件、不做任何前端假验证码。
  //   填入 sitekey 后会自动加载 Turnstile 脚本，并把 token 以 TURNSTILE_FIELD
  //   为名一起 POST 到 /submit。届时 Worker 需在校验开关打开后要求该字段。
  TURNSTILE_SITEKEY: "",
  TURNSTILE_FIELD: "turnstile",
  // 若后端约定的字段名不同（例如 cf-turnstile-response），只改上面一行。

  // --- 待填 ④：酷安身份核实 ---------------------------------------------------
  // 投稿人必须给酷安 UID（https://www.coolapk.com/u/<UID> 末尾那串数字）。
  // 昵称与 UID 分两个字段发出：
  //   uploader    = 昵称（索引里公开展示）
  //   <UID_FIELD> = 酷安 UID 数字
  COOLAPK_UID_FIELD: "coolapkUid",
  // 若后端约定的字段名不同（例如 uid / coolapk_uid），只改上面一行。
  //
  // 真实性核实必须由后端做：api.coolapk.com 不给浏览器开放跨域，而且 X-App-Token
  // 要 native 签名算法，前端拿不到。前端只是调你 Worker 上的这个路径。
  //   期望契约（照 /check 的风格：任何情况都回 HTTP 200，只读 status）：
  //     GET ${API_BASE}/user?uid=2781460
  //     → {"status":"verified","uid":"2781460","nickname":"…","avatar":"…"}
  //       只有真的反查过酷安、确认昵称与 UID 对应，才允许回这个值
  //     → {"status":"self_reported","uid":"…"}
  //       后端只是原样回显，这次没核实（核实开关被运维关掉，或 UID 形状不对）
  //       —— 别把它写成核实过：界面必须说「未经核实」
  //     → {"status":"not_found"}      查无此人（前端会拦住，不让提交）
  //     → {"status":"unavailable"}    想核实但没核实成（酷安不可达/超时）
  // 界面会把 self_reported 与 unavailable 分开写：前者是「这条能力还没接」，
  // 后者是「这次没查到，等等可能就好」。混在一起就是在骗人。
  // 留空字符串 = 暂时不核实，界面显示「未经核实」，投稿照常可提交。
  COOLAPK_USER_PATH: "/user",
  COOLAPK_VERIFY_REQUIRED: false,

  // --- 文件大小上限的兜底值（字节）-------------------------------------------
  // 这里**不是**上限的定义处。真实上限由 Worker 通过 `GET ${API_BASE}/` 的
  // `maxBytes` 字段自报，页面启动时问一次（api.js 的 fetchServiceLimits）。
  // 这个值只在「后端没接 / 问不到 / 响应里没这个字段」时兜底显示与预检。
  // 之所以改成问而不是抄一份：抄出来的那一份一定会对不上（曾经前端写 8MB、
  // Worker 实际 2MB，用户传到一半被 400 拒，而页面还写着允许 8MB）。
  MAX_UPLOAD_BYTES: 8 * 1024 * 1024,

  // --- 管理器加源地址 ---------------------------------------------------------
  // 说明页「怎么加源」用它生成一键加源链接；留空则只显示文字说明。
  //   KernelSU 形如：kernelsu://mmrl?url=<INDEX_URL>
  // 这里给 url 参数做了百分号编码（嵌套 URL 不编码，`//` 会被不少解析器吃掉）。
  // ⚠️ 这一条**没在真机的管理器上验过**：编码形式是按惯例写的，装了 KernelSU 的人点一下
  //    才知道加源对话框里拿到的是什么。没验过就当没验过，别照着它宣传「一键加源」。
  SCHEME_ADD_SOURCE:
    "kernelsu://mmrl?url=https%3A%2F%2Fcdn.jsdelivr.net%2Fgh%2FSukiSU-Community%2Fmodules-repo%40main%2Fjson%2Fmodules.json",

  // --- 站点名称（只影响标题、导航与页脚铭牌）--------------------------------
  SITE_NAME: "模块投稿台",
  SITE_SUBTITLE: "人人共建的 KernelSU / Magisk 模块索引",
};

// 派生值，不要改这里以下的东西。
export const IS_API_CONFIGURED = CONFIG.API_BASE.trim() !== "";
export const IS_INDEX_CONFIGURED = CONFIG.INDEX_URL.trim() !== "";
export const IS_TURNSTILE_CONFIGURED = CONFIG.TURNSTILE_SITEKEY.trim() !== "";
export const IS_UID_VERIFY_ON =
  IS_API_CONFIGURED && CONFIG.COOLAPK_USER_PATH.trim() !== "";

export function url(path) {
  return `${CONFIG.API_BASE.replace(/\/+$/, "")}${path}`;
}
