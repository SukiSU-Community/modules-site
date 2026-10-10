// ===========================================================================
//  SITE CONFIG —— 部署前唯一需要改的文件
//  整个站点没有任何构建步骤，改完这个文件直接静态托管即可生效。
// ===========================================================================

export const CONFIG = {
  // --- 待填 ①：投稿后端（Cloudflare Worker）地址 -----------------------------
  // 填法：Worker 的根地址，结尾不要带斜杠。
  //   例：'https://module-submit.xxxxx.workers.dev'
  //   例：'https://api.你的域名.com'
  // 前端只会请求 `${API_BASE}/check` 与 `${API_BASE}/submit`。
  // 留空字符串时投稿页仍可正常填写，但 /check 与提交会被拦下并明确提示未配置。
  API_BASE: "",

  // --- 待填 ②：公开索引（MMRL JSON）地址 -------------------------------------
  // 「已收录模块」页直接 fetch 这个 URL。填 GitHub raw / jsDelivr / 自有 CDN 都行。
  //   例：'https://raw.githubusercontent.com/你的仓库/main/index.json'
  //   例：'https://cdn.jsdelivr.net/gh/你的用户名/你的仓库@main/index.json'
  // 注意：浏览器直连 raw.githubusercontent.com 在大陆不稳定，优先给 jsDelivr 这类镜像。
  // 留空时浏览页显示「索引地址待配置」，不影响投稿功能。
  INDEX_URL: "",

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
  //     → {"status":"not_found"}      查无此人（前端会拦住，不让提交）
  //     → {"status":"unavailable"}    酷安接口不可达/没配额（前端只提示，不拦）
  // 留空字符串 = 暂时不核实，界面显示「未经核实」，投稿照常可提交。
  COOLAPK_USER_PATH: "/user",
  COOLAPK_VERIFY_REQUIRED: false,

  // --- 与服务端一致的文件大小上限（字节）-------------------------------------
  // 当前后端常量是 8MB。前端提前拦一下，免得用户白传。
  // 服务端改了上限，这里同步改。
  MAX_UPLOAD_BYTES: 8 * 1024 * 1024,

  // --- 管理器加源地址 ---------------------------------------------------------
  // 说明页「怎么加源」用它生成一键加源链接；留空则只显示文字说明。
  //   KernelSU 形如：kernelsu://mmrl?url=<INDEX_URL>
  SCHEME_ADD_SOURCE: "",

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
