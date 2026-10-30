import {
  CONFIG,
  IS_API_CONFIGURED,
  IS_INDEX_CONFIGURED,
  IS_TURNSTILE_CONFIGURED,
  IS_UID_VERIFY_ON,
} from "./config.js";
import {
  CHECK_STATUS,
  USER_STATUS,
  BackendError,
  SHA256_HEX_RE,
  SUBMIT_ERROR_TEXT,
  checkModule,
  checkModulesBatch,
  submitContribution,
  fetchIndex,
  fetchServiceLimits,
  fetchDispositions,
  fetchEvidence,
  evidenceUrlFor,
  dispositionsUrl,
  byLink,
  bySeal,
  KIND_LABELS,
  REASON_LABELS,
  SELECTOR_LABELS,
  lookupCoolapkUser,
  isCoolapkUid,
  normalizeCoolapkUrl,
  reportModule,
  fetchReportQueue,
  fetchMine,
  issueIdentitySession,
  checkSession,
  revokeSession,
} from "./api.js";
import { canInflateRaw, listEntries, readEntry, inspectEntries } from "./zipread.js";
import { parseModuleProp } from "./moduleprop.js";
import {
  buildProofString,
  buildProofStringV2,
  canonicalProofSet,
  identityCommitment,
  identitySecret,
  makeNonce,
  sha256HexBytes,
} from "./proof.js";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const MB = 1024 * 1024;

const PREFILL_KEYS = ["id", "name", "version", "versionCode", "author", "description"];
/**
 * 字段按「属不属于那一枚」分成两张表 —— 批量上传把这条界线变成了契约的一部分：
 *   CARD_KEYS  = 每枚一份，进 manifest 的 `modules[]`（§17.3），在卡与视图之间来回搬；
 *   SHARED_KEYS = 一次上传一份，留在顶层 text fields（`pledge` / `nonce` / `coolapkUid` /
 *                `uploader` / turnstile），**不进卡、不进签名集合**。
 * 把 UID 与署名当 per-card 存是旧语义的残留（那时一枚一个请求、各自带 UID）；现在一次动作
 * 只有一个人，队列里 A 枚的 UID 和 B 枚的 UID 必须同时消失，所以它们根本没有「哪一枚的」这件事。
 * 判据仍然只有一份：这九个字段的 DOM 入口都在同一张表单里。
 */
const CARD_KEYS = [...PREFILL_KEYS, "source"];
const SHARED_KEYS = ["uploader", "coolapkUid"];
/** 表单里全部可编辑字段（fieldEls 就按这张表建）。 */
const FORM_KEYS = [...CARD_KEYS, ...SHARED_KEYS];
/** 每一枚自己必须齐的那些（ uploader / UID 是共享的，由 gateItems 单独一格判）。 */
const CARD_REQUIRED_KEYS = ["id", "name", "version", "versionCode", "source"];
const REQUIRED_KEYS = [...CARD_REQUIRED_KEYS, ...SHARED_KEYS];

const state = {
  /* 队列：一次上传动作 = 一整套模块。每枚一张卡，卡上放着**它自己的**那份来源（包、整包哈希）
     与它自己的那份结论（查重状态、后端逐枚回执）。
     下面那几个同名单值字段（file / zip / zipSha）是「当前卡」的镜像：视图与派生渲染读的是镜像，
     切卡时先 commitView() 把镜像写回旧卡，再 applyView() 装新卡。
     一份值只在一个地方是真的（卡），镜像只是投影 —— 反过来做就会出「上一枚的哈希挂到下一枚上」。

     nonce 与签名不在这里：v2 的签名一串覆盖整套（设计文档 §15），所以随机段是**一次上传一份**，
     不住在卡上。把它放回每枚一份就退回旧语义了 —— 那时 N 枚要 N 串、N 次签名、N 次提交。 */
  cards: [],
  active: "",
  file: null,
  zip: null, // { arrayBuffer, entries, inspect, prop }
  checkStatus: null,
  uidStatus: "idle", // idle | checking | off | verified | not_found | unavailable | self_reported | invalid
  uidInfo: null, // { uid, nickname, avatar }
  // 这一次上传那一枚一次性随机段：整套共用一句签名，所以它只有一份。
  nonce: "",
  /* 长效会话（90 天免改签名）：{ token, uid, nickname, avatar, level, expiresAt } | null。
     它只是「这个人已经证明过自己是这个 UID」的一张凭据 —— 有它就不用每次重抄签名，
     所以它不是签名的替代品，而是「这一次还要不要让用户改签名」这一个问题的答案。 */
  session: null,
  // 整包 sha256 = 当前卡那个文件的全部字节的 SHA-256（与 Worker ⑤-c 的 computedSha 同口径）。
  // 签名的两个来源是「这一整套的 (id, 整包 sha256) 集合」与 state.nonce 这**一个值**；
  // 那串文本永远由 buildProofStringV2(items, nonce) 现算，缓存它就等于让展示串和来源脱钩。
  zipSha: "",
  /* 三个上限全部来自后端 `GET /`（§17.6）：maxBytes = 单枚、maxTotalBytes = 整套、maxModules = 枚数。
     config.js 里不再有第二份拷贝（这个站漂过一次「前端 8MB、后端 2MB」）。问到几个算几个：
     没自报的那一条前端**不拦**，页面上明说「后端没自报这一条」，而不是拿一个猜出来的数顶上去。 */
  limits: { maxBytes: null, maxTotalBytes: null, maxModules: null, fields: {}, from: "pending" },
  // 解析链最近一次失败的原因（空串 = 没有失败）。它只服务于一件事：让「拖进去没反应」变成一句看得见的真话。
  intakeError: "",
  index: null,
  indexError: null,
  // 处置公示。ledgerTried 只用于「浏览页搜不到时顺手查一次公示」这条懒路径，
  // 避免每次搜不到都去发一次请求。
  ledger: null,
  ledgerError: null,
  ledgerLoading: false,
  ledgerTried: false,
  incQuery: "",
  incOpenUid: "",
  attempted: false,
  uploading: false,
  // 上一次发出去的那一整套载荷：重试要重发**同一套**，不是当前视图里的那几枚
  //（用户在失败弹窗打开期间又改了队列的话，改完的那套和被判失败的那套就不是同一套了）。
  lastBatch: null,
  // 整套一次提交的那一份结果：{ ok:true, pr, modules } | { ok:false, reason, code, owner }。
  // 它是「一次动作一个结论」那一格；卡上那份（card.ack）只装后端逐枚回执。
  batchResult: null,
  query: "",
  turnstileToken: "",
  // 解析期间的视图租约：一批包是一张一张解析的（applyProp 只有一份，它写的是表单），
  // 所以解析中点别的卡先记下来，等这次解析交出租约再兑现。
  parsing: false,
  pendingSwitch: "",
  skippedFiles: [], // 不合格的包不建卡，但它们被跳过这件事得说一句（见 renderQueueNote）
  // 批量查重那一条路本轮到底走没走过（措辞要能指得出是哪一种查的法子），以及走不通的原因。
  checkVia: "",
  checkWhy: "",
  /* 「我的模块」：`GET /mine` 的读数。
     rows 只放后端认下来的条目；asked 记的是**问过哪一串令牌** —— 会话换了、UID 换了都要重问，
     只按「有没有问过」判会拿上一张令牌的清单给下一个人看。
     degraded 单独留着：索引读不到时清单是空的，界面上那句「没读过索引」与「你确实还没有模块」
     必须说得不一样，否则一次索引抖动就变成一句关于用户的假话。 */
  mine: { asked: "", rows: [], degraded: false, loading: false },
  /* 身份闸的三档。初值由 index.html 那段首屏内联脚本按 localStorage 里有没有令牌先钉住
     （有 → pending，没有 → out），这里再兜一次底。它的意思是：
       pending —— 正在问后端「本地这串令牌还认不认」，**什么都还不能说**（表单先藏起来）；
       out     —— 没有有效会话：上传页/记录页一律送去身份页；
       in      —— 后端认下来了：身份页直接跳上传页，顶栏露出那个人。 */
  auth: document.documentElement.dataset.auth === "out" ? "out" : "pending",
  // 身份验证那一发在飞（按钮禁用 + 文案改口），以及上一次失败的原话（空串 = 没有错误）。
  idBusy: false,
  idError: "",
  /* 这一屏算出来的那串承诺（sha256(前缀 + 本机 secret) 的前 24 位）。缓存它只为一件事：
     「冷却 / 解锁」的指纹是 (uid, commit) 这一对，而 renderIdentityGate 是同步的、现算不了 sha256。
     它不是凭据 —— 每次验证照样从 secret 重算，这一格只是界面上那一份的投影。 */
  idCommit: "",
};

/* ------------------------------------------------------------------ 小工具 */

function fmtBytes(n) {
  if (!Number.isFinite(n)) return "—";
  if (n < 1024) return `${n} B`;
  if (n < MB) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / MB).toFixed(2)} MB`;
}

function fmtDate(ms) {
  if (!Number.isFinite(ms)) return "";
  const d = new Date(ms);
  const p = (x) => String(x).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(
    d.getMinutes()
  )}`;
}

function safeUrl(href) {
  try {
    const u = new URL(href, location.origin);
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : "";
  } catch {
    return "";
  }
}

/**
 * 头像地址抬到 https。
 *
 * 酷安给的是 `http://avatar.coolapk.com/...`；本站是 https 页面，http 图片会被当
 * mixed content 拦掉，头像于是永远不显示。同一路径的 https 可用，所以这里换协议。
 * 老会话（localStorage 里存着 http 地址）也靠这一步救回来。
 */
const SECURE_AVATAR_HOSTS = ["coolapk.com", "sinaimg.cn", "weibo.com"];
function secureAvatarUrl(raw) {
  const href = safeUrl(raw);
  if (!href || href.startsWith("https://")) return href;
  try {
    const u = new URL(href);
    const host = u.hostname.toLowerCase();
    const upgradable = SECURE_AVATAR_HOSTS.some((h) => host === h || host.endsWith("." + h));
    if (!upgradable) return href;
    u.protocol = "https:";
    return u.href;
  } catch {
    return href;
  }
}

function node(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined && text !== null) el.textContent = String(text);
  return el;
}

// 用节点拼装而不是 innerHTML：索引内容、文件名、服务端错误文案全是外部数据。
function highlight(container, text, q) {
  const needle = q.trim().toLowerCase();
  if (!needle) {
    container.textContent = text;
    return;
  }
  const lower = text.toLowerCase();
  let from = 0;
  let at = lower.indexOf(needle);
  while (at !== -1) {
    if (at > from) container.append(text.slice(from, at));
    container.append(node("mark", null, text.slice(at, at + needle.length)));
    from = at + needle.length;
    at = lower.indexOf(needle, from);
  }
  if (from < text.length) container.append(text.slice(from));
}

function debounce(fn, ms) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

const fieldEls = {};
for (const key of FORM_KEYS) {
  fieldEls[key] = $(`[data-k="${key}"]`);
}
const fieldValue = (key) => (fieldEls[key] ? fieldEls[key].value.trim() : "");
const fieldRaw = (key) => (fieldEls[key] ? fieldEls[key].value : "");

/* ------------------------------------------------------- 01-a 队列：一张卡一枚模块
   为什么要卡这个中间层：一整套中每一枚都有它自己要填的元数据、它自己的包体字节、它自己的整包哈希，
   而这些必须各自存住 —— 表单仍只有一个（一套校验、一套派生，不许写第二份），但它的内容属于
   「当前卡」，切卡时来回搬快照。
   反过来，**跨枚共享的那几样一份都不能变成 N 份**：签名 v2 是一串覆盖整套（§15），
   随机段因此一次上传一枚；承诺只勾一次；提交只发一次 POST。这三样住在 state 与表单顶层，
   不住在卡上。 */

let cardSeq = 0;

function emptyValues() {
  const v = {};
  for (const key of CARD_KEYS) v[key] = "";
  return v;
}

function makeCard(file) {
  return {
    key: `m${++cardSeq}`,
    file,
    zip: null,
    zipSha: "",
    checkStatus: null, // /check 给的那一档；来源一换就当作没有（见 checkOf）
    checkKey: "", // 这份结论属于哪个 (id, versionCode) 组合
    checkUid: "", // 以及它是在哪个酷安 UID 下问到的（换了号，归属那两格会变）
    checkRun: "", // 正在查的是哪个组合（用来区分「还没查」与「正在查」）
    checkWhy: "", // 查不成时的原话（服务端/网络给的原因）
    // 归属：后端 /check 带 uid 时回的 update_eligible / reason。null = 还没问 / 后端没这一格，
    // 一律当作「不知道」，绝不当成 true —— 猜 true 会放人去烧签名，猜 false 会诬告一次。
    updateEligible: null,
    updateReason: "",
    // 这张卡是从「我的模块」点「上传更新版」来的：它带着已收录那一版的读数，
    // 用来卡住「版本号必须大于当前值」这条，也用来在卡上写出「当前是第几版」。
    fromMine: null,
    values: emptyValues(),
    auto: {}, // 这一枚里哪些字段是被 module.prop 预填的（下一次预填可以覆盖它）
    term: [],
    ack: null, // 后端逐枚回执里属于它的那一条（§17.5 应答的 modules[]）
  };
}

const activeCard = () => state.cards.find((c) => c.key === state.active) || null;

/** 这一枚现在的答案：视图里正在敲的就是当前卡的值，所以当前卡一律读表单，别读它上次提交的快照。 */
function cardValues(card) {
  const v = emptyValues();
  if (!card) return v;
  if (card === activeCard()) {
    for (const key of CARD_KEYS) v[key] = fieldRaw(key).trim();
    return v;
  }
  return { ...v, ...card.values };
}

const checkKeyOf = (id, code) => `${id}\u0000${code}`;
const viewCheckKey = () => checkKeyOf(fieldValue("id"), fieldValue("versionCode"));

/**
 * 这一枚的查重结论还算不算数：只认「结论是那一对 (id, versionCode) 查回来的」。
 * id 或版本号一动，这个比较就当场上真 —— 不需要等下一次网络回来，也不许留着旧结论。
 * （这条站里有历史教训：派生值和来源脱钩在屏幕上完全看不出来。）
 */
function checkOf(card) {
  if (!card || !card.checkStatus) return null;
  const v = cardValues(card);
  return card.checkKey === checkKeyOf(v.id, v.versionCode) ? card.checkStatus : null;
}

/** 已经收录的那一枚 = 从签名、闸门清单、逐枚提交里全部摘出去的那一枚。 */
const isRecorded = (card) => checkOf(card) === "recorded";

/**
 * 「本次要投」的那几枚 = 签名里那一套 = manifest 里那几条 = 这一次 POST 带的 N 个 file part。
 * 闸门读数、签名那一串、提交那一层共用这**一个**判据 —— 各写一份 filter 迟早会漂成
 * 「清单说 3 枚、manifest 写 2 条、屏幕上那一串算的是另外 3 条」，而那三种数在批量这一头
 * 是同一个东西：签名绑的就是这套的全集（§15），少一枚都是另一串签名。
 * 两类枚不在这里：
 *   ① 被 /check 判为 recorded 的 —— 它不进集合、不进签名、不进 manifest；
 *   ② 已经拿到后端回执的（card.ack）—— 那几枚的字节已经在一个 PR 里了，跟着下一次再发一遍
 *      就是拿同一个 (id, versionCode) 撞第二次（§17.4 之外那一格：pending/CI 的重复）。
 *      它们留在队列里当这一屏的公示，想投新的就清空或移除，新选的那枚自成下一套。
 */
function submitTargets() {
  return state.cards.filter((c) => c.file && !isRecorded(c) && !c.ack);
}

/** 视图里那几行解析日志的内容；跟着当前卡走，切卡时来回搬（见 commitView / applyView）。 */
let termSnapshot = [];

/** 把视图（表单里属于这一枚的那几行 + 那三个单值字段）写回它当前所属的那张卡。 */
function commitView() {
  const card = activeCard();
  if (!card) return null;
  for (const key of CARD_KEYS) {
    const el = fieldEls[key];
    if (!el) continue;
    card.values[key] = el.value;
    if (el.dataset.auto === "1") card.auto[key] = true;
    else delete card.auto[key];
  }
  card.term = termSnapshot;
  return card;
}

/** 把一张卡装进视图。card 为 null 就是清空（没有卡时的样子和今天没选包一致）。 */
function applyView(card) {
  state.file = card ? card.file : null;
  state.zip = card ? card.zip : null;
  state.zipSha = card ? card.zipSha : "";
  state.checkStatus = card ? checkOf(card) : null;
  // 随机段不在这里搬：一次上传一份、整套共用（v2 的签名覆盖全集），它不属于任何一张卡。
  // 同样不搬的还有 uploader / coolapkUid —— 一次上传只有一个人，那两行是顶层共享字段。
  for (const key of CARD_KEYS) {
    const el = fieldEls[key];
    if (!el) continue;
    el.value = card ? card.values[key] || "" : "";
    if (card && card.auto[key]) {
      el.dataset.auto = "1";
      el.closest(".field").classList.add("is-pre");
    } else {
      delete el.dataset.auto;
      el.closest(".field").classList.remove("is-pre");
    }
  }
  $("#meta-src").textContent = card && card.zip && card.zip.prop ? "来自 module.prop" : "手动填写";
  termSnapshot = card && card.term ? card.term : [];
}

function renderTerm() {
  const lines = termSnapshot || [];
  const box = $("#term");
  if (!lines.length) {
    box.hidden = true;
    box.textContent = "";
    return;
  }
  termLines(lines);
}

/** paint = 要不要动屏幕。后台那几枚的解析结果只落卡，不许占住用户正在看的那一格。 */
function paintTerm(card, lines) {
  card.term = lines.slice();
  if (card === activeCard()) {
    termSnapshot = card.term;
    termLines(card.term);
  }
}

function selectCardNow(key) {
  commitView();
  const card = state.cards.find((c) => c.key === key) || null;
  state.active = card ? card.key : "";
  applyView(card);
  renderTerm();
  renderCheck();
  syncUploaderField();
  runUidCheck();
  if (card) scheduleCheck(card);
  renderProof();
  refreshGate();
  renderQueue();
}

/** 用户点队列里的一行。解析期间不立刻换手（视图租约在正在解析的那枚手上）。 */
function selectCard(key) {
  if (!state.cards.some((c) => c.key === key)) return;
  if (key === state.active) return;
  if (state.parsing) {
    state.pendingSwitch = key;
    return;
  }
  selectCardNow(key);
}

function dropCard(card) {
  const at = state.cards.indexOf(card);
  if (at === -1) return;
  state.cards.splice(at, 1);
  if (state.active !== card.key) {
    renderQueue();
    return;
  }
  // 这里绝不允许先把视图写回当前卡：视图正戴在这张被删的卡上，写一次就是把它的包塞给下一枚。
  const next = state.cards[Math.min(at, state.cards.length - 1)] || null;
  state.active = next ? next.key : "";
  applyView(next);
  renderTerm();
  renderCheck();
  syncUploaderField();
  renderProof();
  refreshGate();
  renderQueue();
}

/**
 * 随机段：一次上传**一份**，整套共用。
 * v1 时代它住在卡上（一枚一串、一枚一次提交），v2 把它收回到这里 ——
 * 一串签名覆盖一整套（§15），所以「一枚一份」现在是错形状：那会需要 N 次签名、N 次提交，
 * 而服务端第一次就把这串烧掉，后 N-1 次全被判「签名已用过」。
 */
function setNonce(value) {
  state.nonce = value;
}

/** 核实通过后补上那一份随机段；已经有了就一动不动（可能已经抄进签名里了）。 */
function ensureNonce() {
  if (!state.nonce) setNonce(makeNonce());
}

function setCheck(card, status, key, why) {
  if (!card) return;
  card.checkStatus = status || null;
  card.checkKey = key || "";
  card.checkWhy = why || "";
  if (card.checkRun === key) card.checkRun = "";
  if (card === activeCard()) state.checkStatus = status || null;
  // 后台那一枚被 /check 判成 recorded 时，它也必须当场从「这一套」里掉出去 ——
  // 而签名那一串是绑整套算的，集合一变串就变，所以这一句不加分支：谁的结论变了就重算一次串。
  renderProof();
  if (card === activeCard()) refreshGate();
  renderQueue();
}


/* ------------------------------------------------------- 路由：hash 三视图 */

// 六屏：上传、身份验证、上传记录、已收录、举报与处置、说明。
// 身份验证与上传记录不进导航 —— 它们是「验证」这条线的两站，入口在顶栏那个人身上。
const VIEWS = {
  submit: { el: "#view-submit", label: "上传" },
  identity: { el: "#view-identity", label: "身份验证" },
  records: { el: "#view-records", label: "上传记录" },
  index: { el: "#view-index", label: "已收录" },
  moderation: { el: "#view-moderation", label: "举报与处置" },
  about: { el: "#view-about", label: "说明" },
};

// 这两屏必须「已经验证过」才给看：上传要带签名与承诺，记录读的是本人的清单。
// 判据只认 state.auth（由 refreshSession 问过后端才定），**不认** localStorage 里有没有串 ——
// 有串不等于后端还认它，而「让一张过期令牌把表单铺出来」正是这次要修掉的那件事。
const GATED_VIEWS = ["submit", "records"];

// 举报与处置是同一屏的两半：tab 写在查询串里，永远显式（连默认的那一半也写），
// 这样刷新、收藏、贴给别人，落点都唯一。旧的两条地址只是入口，进来后会被 replaceState 收敛。
const MOD_TABS = ["ledger", "report"];
const LEGACY_VIEWS = {
  incidents: { tab: "ledger" },
  report: { tab: "report" },
};

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, search] = raw.split("?");
  const params = new URLSearchParams(search || "");
  const name = VIEWS[path] ? path : LEGACY_VIEWS[path] ? "moderation" : "submit";
  if (name === "moderation") {
    // 旧地址把 tab 编在路径里；新地址用 ?tab= 指定，缺省与非法值一律落在公示。
    const asked = LEGACY_VIEWS[path] ? LEGACY_VIEWS[path].tab : params.get("tab");
    const tab = MOD_TABS.includes(asked) ? asked : "ledger";
    params.set("tab", tab);
    return { name, params, tab, legacy: Boolean(LEGACY_VIEWS[path]) };
  }
  return { name, params };
}

// 把地址栏收敛成规范写法；别名只做一次性入口，不留在后退链上。
// tab 一律排在最前：同一屏的两个地址，只有这一格不同，排头才能一眼看出差异所在。
function canonicalHash(name, params) {
  const rest = new URLSearchParams();
  let tab = "";
  for (const [k, v] of params) {
    if (k === "tab") tab = v;
    else rest.append(k, v);
  }
  const parts = [];
  if (tab) parts.push(`tab=${encodeURIComponent(tab)}`);
  const q = rest.toString();
  if (q) parts.push(q);
  return `#/${name}${parts.length ? `?${parts.join("&")}` : ""}`;
}

// 不在 moderation 那一屏时返回空串：各处「晚到的数据该重画哪一半」都问这一句，
// 免得每个回调都自己拼 name + tab 两层判断。
function currentModTab() {
  const { name, tab } = parseHash();
  return name === "moderation" ? tab : "";
}

function renderRoute() {
  const parsed = parseHash();
  let { name, params, tab, legacy } = parsed;
  if (legacy || (name === "moderation" && location.hash !== canonicalHash(name, params))) {
    history.replaceState(null, "", canonicalHash(name, params));
  }
  // 身份闸只在这一处：进来的每一屏都先过它，别处不许再各判一次。
  //
  // 「pending」这一档什么地址都不改：正在问后端的时候，说「没验证」会闪一下身份页、
  // 说「验证过」会闪一下表单，两边都是错话。加载态由 paintAuth 藏表单、亮那一行字。
  if (state.auth === "pending") {
    if (name === "identity") {
      name = "submit";
      history.replaceState(null, "", "#/submit");
    }
  } else if (state.auth === "in") {
    // 已经验证过的人不需要身份页：那一屏要填的 UID 与签名，后端早就认过了。
    if (name === "identity") {
      name = "submit";
      history.replaceState(null, "", "#/submit");
    }
  } else if (GATED_VIEWS.includes(name)) {
    // 没有有效会话：这两屏一律先送去身份页，地址也一起改掉（replace，不留后退链）。
    name = "identity";
    history.replaceState(null, "", "#/identity");
  }
  // 版心按视图分档：数据密集的几屏在宽屏上放宽（见 panel.css「宽屏版心」），
  // 因此根元素上要挂一个「现在是哪一屏」，CSS 才有得选。文字为主的说明页不参与。
  document.documentElement.dataset.view = name;
  // 身份闸的档位也挂到根上：CSS 与调试都读得到，不必再去问模块里的 state。
  document.documentElement.dataset.auth = state.auth;
  for (const [key, view] of Object.entries(VIEWS)) {
    $(view.el).classList.toggle("is-active", key === name);
  }
  $$(".nav a").forEach((a) => {
    // 导航上那条写的是 `#/moderation?tab=ledger`，比对时只看路径那一半。
    const href = a.getAttribute("href") || "";
    const isNow = href.split("?")[0] === `#/${name}`;
    if (isNow) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  // 底栏只在「真能上传」的那一屏出现：加载态与未验证的人看见它只会点进一个空表单。
  $("#dock").hidden = name !== "submit" || state.auth !== "in";
  paintAuth();
  paintWho();
  // 状态表里有「实测状态」这种会随时间变的内容，进 about 时重画一次，别让人看到过期值
  if (name === "about") renderAbout();
  if (params.has("q")) {
    state.query = params.get("q") || "";
    $("#q").value = state.query;
    // 从上传页/浏览页跳到公示页时带的是同一个词，两个过滤框都按它起头
    state.incQuery = state.query;
    $("#q-inc").value = state.query;
  }
  if (name === "index") renderIndex();
  if (name === "records") {
    // 进来就问一次（同一串令牌只问一次，见 loadMine），标出加载态再画。
    paintMine();
    loadMine();
  }
  if (name === "moderation") {
    renderModerationTabs(tab);
    if (tab === "ledger") {
      renderIncidents();
    } else {
      // 从 02 那一屏「举报这一枚」进来时带着 id 与 versionCode：那是用户不必重打的两格，
      // 也是签名的两个来源 —— 预填错了就等于签名绑错，所以只认索引里真有的那一枚（reportTarget 判）。
      if (params.has("id")) $("#rp-id").value = params.get("id") || "";
      if (params.has("vc")) $("#rp-vc").value = params.get("vc") || "";
      if (!state.index) loadIndex();
      renderReport();
    }
  }
  window.scrollTo({ top: 0, behavior: "auto" });
}

/* ---------------------------------------- 举报与处置：两半的切换器（tabs） */

// 焦点在哪一半就跟着切哪一半：这是 tablist 的默认键盘约定（方向键即切换，不用先 Enter），
// 而 Tab 键仍然只是「从切换器走进这一半的内容」，不参与左右横跳。
function renderModerationTabs(tab) {
  const keepFocus = $("#mod-tabs")?.contains(document.activeElement);
  $$("#mod-tabs .seg__btn").forEach((btn) => {
    const isNow = btn.dataset.tab === tab;
    btn.setAttribute("aria-selected", isNow ? "true" : "false");
    btn.tabIndex = isNow ? 0 : -1;
    btn.classList.toggle("is-on", isNow);
    if (isNow && keepFocus) btn.focus();
  });
  const panelLedger = $("#panel-ledger");
  const panelReport = $("#panel-report");
  if (panelLedger) panelLedger.hidden = tab !== "ledger";
  if (panelReport) panelReport.hidden = tab !== "report";
}

function switchModerationTab(tab) {
  if (!MOD_TABS.includes(tab)) return;
  const { name, params } = parseHash();
  if (name !== "moderation") return;
  // 每一半只留自己看得懂的参数：举报认 id / vc，公示认 q。
  // 不剪的话会得到 `?tab=ledger&id=…` 这种「公示按某条记录过滤」的假象 —— 而公示根本不认 id。
  // 剪掉不影响填过的东西：表单值在 DOM 里，切回来还在。
  const keep = tab === "report" ? ["id", "vc"] : ["q"];
  for (const k of [...params.keys()]) {
    if (k !== "tab" && !keep.includes(k)) params.delete(k);
  }
  params.set("tab", tab);
  const next = canonicalHash(name, params);
  // 切 tab 写一条历史：浏览器后退能退回到另一半，这是「来回看一眼」的常规预期。
  // 但同一个 tab 不重复写，免得连点两下多出一条死记录。
  if (location.hash === next) return;
  location.hash = next.slice(1);
}

function wireModerationTabs() {
  const tabs = $$("#mod-tabs .seg__btn");
  if (!tabs.length) return;
  tabs.forEach((btn, i) => {
    btn.addEventListener("click", () => switchModerationTab(btn.dataset.tab));
    btn.addEventListener("keydown", (e) => {
      // Home / End 直接跳到两头：这两枚只是两半，但键盘约定照 APG 走，少一条就是一处「按了没反应」。
      if (e.key === "Home" || e.key === "End") {
        e.preventDefault();
        const next = tabs[e.key === "Home" ? 0 : tabs.length - 1];
        next.focus();
        switchModerationTab(next.dataset.tab);
        return;
      }
      const step =
        e.key === "ArrowRight" || e.key === "ArrowDown"
          ? 1
          : e.key === "ArrowLeft" || e.key === "ArrowUp"
            ? -1
            : 0;
      if (!step) return;
      e.preventDefault();
      const next = tabs[(i + step + tabs.length) % tabs.length];
      next.focus();
      switchModerationTab(next.dataset.tab);
    });
  });
}

window.addEventListener("hashchange", renderRoute);

/* ------------------------------------------------------------- 日/夜主题 */

const THEME_KEY = "panel-theme";
const readStoredTheme = () => {
  try {
    return localStorage.getItem(THEME_KEY);
  } catch {
    return null; // 隐私模式下 localStorage 会抛，跟着系统走就行
  }
};

function applyTheme(mode, animate) {
  const root = document.documentElement;
  if (animate && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
    root.classList.add("theming");
    setTimeout(() => root.classList.remove("theming"), 280);
  }
  root.setAttribute("data-theme", mode);
  $("#theme-txt").textContent = mode === "light" ? "日间" : "夜间";
  $("#theme").setAttribute("aria-label", `当前为${mode === "light" ? "日间" : "夜间"}模式，点击切换`);
  $("#theme-color").setAttribute("content", mode === "light" ? "#F5F3EE" : "#07080B");
}

function bindTheme() {
  let mode = document.documentElement.getAttribute("data-theme") || "dark";
  applyTheme(mode, false);

  $("#theme").addEventListener("click", () => {
    mode = mode === "light" ? "dark" : "light";
    try {
      localStorage.setItem(THEME_KEY, mode);
    } catch {
      /* 存不下就只在本次会话里生效 */
    }
    applyTheme(mode, true);
  });

  const mq = matchMedia("(prefers-color-scheme: light)");
  const follow = (event) => {
    if (readStoredTheme()) return; // 用户手动选过就不再跟系统
    mode = event.matches ? "light" : "dark";
    applyTheme(mode, true);
  };
  if (typeof mq.addEventListener === "function") mq.addEventListener("change", follow);
}

/* ------------------------------------------------------------ 01 文件与解包 */

function termLines(lines) {
  const term = $("#term");
  term.textContent = "";
  term.hidden = false;
  for (const [cls, text] of lines) term.append(node("div", cls, text));
}

/** 队列清空 = 视图清空。包没了，签名的那一套来源就一起归零，签名行跟着收起 ——
    屏幕上不许留着一串属于「已经不存在的那几枚包」的签名。 */
function clearQueue() {
  state.cards = [];
  state.active = "";
  state.skippedFiles = [];
  // 整套的结果跟着队列一起走：清空之后再投的是另一套，不许留上一次那个 PR 链接冒充这次的。
  state.batchResult = null;
  state.lastBatch = null;
  termSnapshot = [];
  applyView(null);
  $("#file").value = "";
  $("#term").hidden = true;
  $("#check").hidden = true;
  $("#meta-src").textContent = "手动填写";
  for (const key of PREFILL_KEYS) {
    const el = fieldEls[key];
    if (el.dataset.auto === "1") {
      el.value = "";
      delete el.dataset.auto;
      el.closest(".field").classList.remove("is-pre");
    }
  }
  renderQueue();
  refreshGate();
}

/**
 * 这个包不合格：不建卡（它连模块都不是，不该占队列里的一格），只把原因说清楚。
 * 队列里还有别的枚时，那几行前面带上文件名 —— 否则「这句说的是哪个包」就没人知道了。
 */
function rejectCard(card, lines) {
  const wasActive = card === activeCard();
  const named = state.cards.length > 1 ? [[null, `${card.file.name} ——`], ...lines] : lines;
  state.skippedFiles.push(card.file.name);
  dropCard(card);
  if (wasActive || !state.cards.length) {
    termSnapshot = named;
    termLines(named);
  }
  renderQueue();
}

/* ------------------------------------------------ 01-b 多选的排队与解析的租约
   一次选 N 个包：先各建一张卡（队列立刻看得见有几枚），再一张一张解析。
   解析期间视图的租约归正在解析的那一枚 —— applyProp() 全站只有一份，它写的是表单，
   一边解析后台那枚一边让用户编辑另一枚，两份数据会抢同一批输入框。
   用户在这期间点了别的卡，就记进 state.pendingSwitch，等这一次解析交出租约再兑现。 */
let parseChain = Promise.resolve();

/**
 * 队列与换包共用这一条串行链。**每一个链接都必须自带 catch**：
 * `p = p.then(f)` 一旦有一次 reject（包里读不出 module.prop、`POST /check` 那一次网络抖动），
 * 这条链就永久是 rejected，之后每一次 `.then()` 都被跳过 —— 用户看到的是「拖进去没反应」，
 * 而刷新页面之前没有任何出路。这一格不是假想：链式写法本身让失败变成静默。
 */
function scheduleIntake(files) {
  if (!files || !files.length) return;
  state.intakeError = "";
  parseChain = parseChain.then(() => intakeBatch(files)).catch(intakeFailed);
}

function intakeFailed(e) {
  state.intakeError = String((e && (e.message || e)) || '未知失败').slice(0, 180);
  refreshGate();
}

async function intakeBatch(files) {
  // 选了包就说明这个人多半要提交了 —— 这是加载人机校验最早又不浪费的时刻。
  ensureTurnstile();
  const prev = activeCard(); // 选这批包之前用户正在看的那一枚（没有就是空队列）
  const fresh = files.map((file) => {
    const card = makeCard(file);
    state.cards.push(card);
    return card;
  });
  // 核实早就通过了（先填 UID 再选包的人）：这次上传那份随机段该在这儿补上。
  if (state.uidStatus === "verified") ensureNonce();
  renderQueue();
  let pickedDuring = ""; // 用户在解析中途点过的那一枚 —— 批处理完了要还给他
  for (const card of fresh) {
    selectCardNow(card.key); // 解析要动视图与表单，所以一张一张来（租约见 selectCard）
    state.parsing = true;
    try {
      await intake(card.file);
    } finally {
      state.parsing = false;
    }
    renderQueue();
    if (state.pendingSwitch) {
      pickedDuring = state.pendingSwitch;
      state.pendingSwitch = "";
      if (state.cards.some((c) => c.key === pickedDuring)) selectCardNow(pickedDuring);
    }
  }
  // 一批解析完，视图回到用户本来在看的那一枚；中途他点过别的就回到点过的那一枚，
  // 原来队列是空的就回到这批的第一枚 —— 别把用户扔到最后一枚那儿去。
  const back =
    state.cards.find((c) => c.key === pickedDuring) ||
    (prev && state.cards.includes(prev) ? prev : fresh[0]);
  if (back && activeCard() !== back) selectCardNow(back.key);
  renderQueue();
  // 早期重复拦截就排在这一句：一批包一次问完，命中「已被上传过」的那一枚当场摘出去，
  // 不让它跟着走完填表、抄签名、提交这三步（那三步的代价由上传人付：一次签名修改 + 一次限流格）。
  await runBatchCheck(fresh.filter((c) => state.cards.includes(c)));
}

async function intake(file) {
  if (!file) return;
  const card = activeCard(); // 解析前 intakeBatch 已经把视图的租约交给这一枚
  if (!card) return;
  const out = [];
  state.file = file;
  state.zip = null;
  state.checkStatus = null;
  // 派生值在来源换掉的那一刻就得死：这里如果等到下面解析完才归零，读 B 的整段期间
  // 屏幕上挂的还是 A 的签名、门禁写着「已生成」，此时点提交就是 zip:B + sha256:A。
  // 同步清完立刻重画，B 的哈希到货前界面上说的是「还没选包」这句实话。
  state.zipSha = "";
  card.zip = null;
  card.zipSha = "";
  card.checkStatus = null;
  card.checkKey = "";
  card.checkWhy = "";
  renderProof();
  refreshGate();

  const limit = state.limits.maxBytes; // 单枚上限，后端自报的那一个（问不到就是 null）
  out.push([null, `读取 ${file.name} · ${fmtBytes(file.size)}`]);

  if (!/\.zip$/i.test(file.name)) {
    rejectCard(card, [
      out[0],
      ["miss", "这不像 zip 文件（扩展名不是 .zip）。管理器只认 zip，请先确认下载完整。"],
    ]);
    return;
  }
  // 「问到了才拦」：上限没自报时这里不拦，交给服务端（它会回 zip_too_large）。
  // 拿一个猜出来的数字当闸，就是这条站里被钉子盯过的那种假动作。
  if (limit !== null && file.size > limit) {
    rejectCard(card, [
      out[0],
      ["miss", `超过单枚上限：${fmtBytes(file.size)} > ${fmtBytes(limit)}（这个数是后端自报的）`],
      ["warn", "服务端会直接拒绝。如果确实是正常模块，压缩包里多半混进了无关的大文件。"],
    ]);
    return;
  }

  let arrayBuffer;
  try {
    arrayBuffer = await file.arrayBuffer();
  } catch {
    rejectCard(card, [
      out[0],
      ["miss", "文件读不出来，可能已经不在原来的位置了。重新选一次。"],
    ]);
    return;
  }

  // 解析回来的这一刻可能已经晚了：视图的租约中途没了（这一枚被移除、或整批被清空）。
  // 比的是**这一次开始时选中的那个 file 对象**（intake 顶部刚把它记进 state.file），
  // 不是名字也不是大小：中途换过包、清过、或重开过上传，就把这一次整条丢掉。
  // 不丢的话 state.zip 会指回旧包而 state.file 已是新包，旧包的摘要随后还能通过下面那道对象
  // 标识守卫贴到新包上 —— 屏幕上那一串就成了「新包的签名、旧包的字节」。
  if (state.file !== file) return;

  let entries;
  try {
    entries = listEntries(arrayBuffer);
  } catch (err) {
    rejectCard(card, [out[0], ["miss", err.message]]);
    return;
  }
  const inspect = inspectEntries(entries);
  out.push([null, `中央目录 ${entries.length} 个条目`]);

  if (!inspect.ok) {
    const lines = [out[0], ["miss", "根目录没有 module.prop —— 服务端会直接拒绝这个包"]];
    if (inspect.nestedPaths.length) {
      lines.push(["warn", `只在子目录里找到了：${inspect.nestedPaths.slice(0, 3).join(" 、")}`]);
      lines.push(["warn", "重新打包：进到那层文件夹里选中全部文件再压缩，别把外层文件夹一起压进去。"]);
    } else {
      lines.push(["warn", "这个包里没有任何 module.prop，它多半不是一个模块。"]);
    }
    rejectCard(card, lines);
    return;
  }

  // 视图与这一枚指向同一个解析结果对象：签名的来源因此只有一份，不会漂成两份。
  state.zip = { arrayBuffer, entries, inspect, prop: null };
  card.zip = state.zip;

  // 整包 sha256 是签名的第二个来源，每次换包都在这儿重算 —— 上一包的哈希对新包毫无意义。
  // 异步：几百毫秒内签名行按「还没算出来」显示（门禁说当时的实话），算完自己出现。
  // 算失败就留空：那一串根本不会显示，于是没人会抄一串对不上任何包的签名去填签名。
  const zipForThisFile = card.zip;
  state.zipSha = "";
  card.zipSha = "";
  sha256HexBytes(arrayBuffer).then(
    (hex) => {
      // 认对象不认值：这一枚已经换过包（或已清掉）就别把上一个文件的哈希贴到当前这个包上。
      if (card.zip !== zipForThisFile) return;
      card.zipSha = hex;
      // 视图的租约还在这一枚上才动视图那一格；切走了就只落卡 —— 切回来时读到的是卡上这份真值，
      // 而不是中途属于别人那枚的哈希。
      if (state.zip === zipForThisFile) state.zipSha = hex;
      renderProof();
      refreshGate();
      renderQueue();
    },
    () => {
      if (card.zip !== zipForThisFile) return;
      card.zipSha = "";
      if (state.zip === zipForThisFile) state.zipSha = "";
      renderProof();
      refreshGate();
      renderQueue();
    }
  );

  out.push(["found", "module.prop @ root  校验通过"]);

  if (!canInflateRaw()) {
    out.push(["warn", "这个浏览器不支持前端解压，元数据请手填（表单照常可用）"]);
    paintTerm(card, out);
    refreshGate();
    invalidateCheck(card);
    // 查重交给这一批末尾的 runBatchCheck（一批一次问完，一枚一次问是 N 次请求）。
    return;
  }

  try {
    const bytes = await readEntry(arrayBuffer, inspect.rootEntry);
    // 第二个 await，就得再认一次身份：上面那次比较通过之后到这里又是另一段时间，中途换过包的话
    // state.zip 已经是新包的对象，而 prop 还是旧包解出来的 —— applyProp 会把旧包的 id 盖进表单
    // （预填过的字段带 data-auto，本来就该被下一次预填覆盖），于是函数末尾那次 renderProof 会把
    // 「旧包的 id + 新包的整包哈希」这一串真算出来、画上屏幕、装进载荷。id 是签名的三个来源之一，
    // 来源换掉的那一刻这一串就得死，不能等下一回重画。
    if (state.file !== file) return;
    const prop = parseModuleProp(new TextDecoder("utf-8").decode(bytes));
    state.zip.prop = prop;
    const { filled, kept } = applyProp(prop);
    commitView(); // 预填的结果写进了视图，而这一刻视图就是这一枚的：立刻归它，别等下一次切换
    out.push([
      "found",
      `已读出 ${Object.keys(prop).length} 个字段，预填 ${filled} 项` +
        (kept ? `，保留你手填的 ${kept} 项` : ""),
    ]);
    for (const key of ["id", "name", "version", "versionCode"]) {
      if (prop[key]) out.push([null, `${key} = ${prop[key]}`]);
    }
    $("#meta-src").textContent = "来自 module.prop";
  } catch (err) {
    out.push(["warn", (err && err.message) || "module.prop 解压失败，请手填元数据"]);
  }

  paintTerm(card, out);
  refreshGate();
  // 包内 id 与用户原来填的那个 id 不一定是同一对：这一枚的查重结论当场作废。
  // 作废之后**不**在这里补一次单枚查询 —— 一批 N 枚由 runBatchCheck 一次问完（§17.6 的 POST /check），
  // 那条路走不通时它自己会退回逐枚 GET。在这儿顺手查一次就是两套判据各打各的请求。
  invalidateCheck(card);
  renderProof(); // module.prop 把 id 预填进来的这一下不触发 input 事件，签名得自己重算一次
  renderQueue();
}

function applyProp(prop) {
  let filled = 0;
  let kept = 0;
  for (const key of PREFILL_KEYS) {
    const el = fieldEls[key];
    const value = prop[key];
    if (!value || !el) continue;
    const wasAuto = el.dataset.auto === "1";
    if (el.value.trim() && !wasAuto) {
      kept++;
      continue;
    }
    el.value = value;
    el.dataset.auto = "1";
    el.closest(".field").classList.add("is-pre");
    filled++;
  }
  return { filled, kept };
}

function bindFile() {
  const drop = $("#drop");
  const input = $("#file");
  // 多选：change 给的是整个 FileList。这里当场把 input 的值清掉 —— 不清的话同一个包
  // 第二次选不中（files 没变化就不触发 change），而拖拽那条路本来就没有值可清。
  input.addEventListener("change", () => {
    const files = Array.from(input.files || []);
    input.value = "";
    scheduleIntake(files);
  });
  paintLimit();

  ["dragenter", "dragover"].forEach((type) =>
    drop.addEventListener(type, (e) => {
      e.preventDefault();
      drop.classList.add("is-over");
    })
  );
  ["dragleave", "drop"].forEach((type) =>
    drop.addEventListener(type, (e) => {
      e.preventDefault();
      drop.classList.remove("is-over");
    })
  );
  drop.addEventListener("drop", (e) => {
    // 拖到 input 本体上时浏览器会自己填 files 并触发 change，这里再调一次就是重复解析。
    if (e.target === input) return;
    const files = e.dataTransfer && e.dataTransfer.files ? Array.from(e.dataTransfer.files) : [];
    if (files.length) scheduleIntake(files);
  });
  // 没落在拖放区上的文件不能让整个页面被浏览器接管
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());
}

/* ----------------------------------------------------- 01-c 队列条（读与操作） */

/**
 * 这一枚现在的那一句状态。
 * 读数与「这一套里有几枚」用的是同一份判据（checkOf / submitTargets）—— 界面上说了 N 枚，
 * manifest 里就得是 N 条、签名得是这 N 条算出来的那一串。
 */
function statusOf(card) {
  if (state.uploading && submitTargets().includes(card)) return { tone: "idle", text: "随这套提交中" };
  if (card.ack) return { tone: "ok", text: "后端已回执" };
  const status = checkOf(card);
  if (status === "recorded") return { tone: "muted", text: "已被上传过 · 摘出" };
  // 版本更新与首投走同一套机器判据，过了就自动进索引 —— 所以它是「可上传」，不是「等审核」。
  // 但归属发不了的那一枚（update_eligible === false）不能跟着变绿：那一枚整单会被 403 拒掉，
  // 标成 ok 就是在教用户白抄一次签名。
  if (status === "version_update") {
    if (ownershipOf(card) === "other") return { tone: "warn", text: "版本更新 · 不是你的" };
    return { tone: "ok", text: "版本更新 · 可上传" };
  }
  if (status === "new") return { tone: "ok", text: "没收录 · 可上传" };
  if (status === "unknown") return { tone: "warn", text: "查重未确认" };
  if (card.checkRun) return { tone: "idle", text: "查重中" };
  if (card.checkWhy) return { tone: "warn", text: "查重没成" };
  return { tone: "muted", text: "待查重" };
}

/**
 * 这一枚离「能进这一套」还差什么：它自己的必填元数据 + 它的包体哈希 + 它有没有超单枚上限。
 * 整套一次提交 ⇒ 任何一枚没齐，整套就发不出去（服务端也是全有全无，§15 第 3 条）。
 * 这里点名到枚，是因为「还差一步」不说差在哪一枚就等于没说。
 */
function cardGaps(card) {
  const v = cardValues(card);
  const gaps = [];
  for (const key of CARD_REQUIRED_KEYS) if (!v[key]) gaps.push(FIELD_NAMES[key]);
  if (v.versionCode && !/^\d+$/.test(v.versionCode)) gaps.push("版本号不是整数");
  if (v.source && !normalizeCoolapkUrl(v.source)) gaps.push("出处不是酷安站内链接");
  // 版本更新这一档的版本号必须**大于**已收录那一版：后端按同一套判据拦，前端先拦一道，
  // 理由是签名一次性 —— 抄完再被拒，那一串就白烧了。等号也算不行（同版重发没有意义）。
  const base = card.fromMine ? Number(card.fromMine.versionCode) || 0 : 0;
  if (base && /^\d+$/.test(v.versionCode) && Number(v.versionCode) <= base) {
    gaps.push(`版本号要大于已收录的 ${base}`);
  }
  // 包体这一格分三种说法：没选包（预填卡就是这样）、选了但没解析成、解析成了但哈希还没算完。
  // 混成一句「包体没解析成功」会让从「我的模块」来的卡看起来像坏包，而它只是还没选包。
  if (!card.zipSha) {
    if (!card.file && !card.zip) gaps.push("还没选包");
    else gaps.push(card.zip ? "整包哈希还没算完" : "包体没解析成功");
  }
  const limit = state.limits.maxBytes;
  if (limit !== null && card.file && card.file.size > limit) gaps.push(`超出单枚上限 ${fmtBytes(card.file.size)}`);
  return gaps;
}

const FIELD_NAMES = {
  id: "模块 ID",
  name: "名称",
  version: "版本字符串",
  versionCode: "版本号",
  source: "模块出处",
};

/** 图标墙上那一枚 zip 的图形：24×24 的压缩包轮廓，全部由内联 SVG 画（不引图标库）。 */
function zipIconSvg() {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.5");
  svg.setAttribute("aria-hidden", "true");
  const shapes = [
    ["rect", { x: "3.5", y: "2.5", width: "17", height: "19", rx: "2.5" }],
    ["path", { d: "M10.5 2.5v19" }],
    ["path", { d: "M13 7h3M13 11h3M13 15h3" }],
  ];
  for (const [tag, attrs] of shapes) {
    const el = document.createElementNS(NS, tag);
    for (const [k, val] of Object.entries(attrs)) el.setAttribute(k, val);
    svg.append(el);
  }
  return svg;
}

/** 状态角标：外观复用 .chip，tone 与旧队列行那套映射一致（ok / warn / bad / idle）。 */
function chipToneClass(tone) {
  return tone === "ok" ? "chip--ok" : tone === "warn" ? "chip--warn" : tone === "bad" ? "chip--bad" : tone === "idle" ? "chip--idle" : "";
}

/**
 * 墙上的状态字：一格只有 148px 宽，整句「没收录 · 可上传」放不下 —— 这里只留最短的那个词，
 * 整句仍然挂在 title 上（悬停可看、读屏也能读到）。判据还是 statusOf 那一份，不另立一套。
 */
const SHORT_STATUS = {
  "随这套提交中": "提交中",
  "后端已回执": "已回执",
  "已被上传过 · 摘出": "已上传",
  "版本更新 · 可上传": "更新",
  "版本更新 · 不是你的": "非本人",
  "没收录 · 可上传": "可上传",
  "查重未确认": "未确认",
  "查重中": "查重中",
  "查重没成": "查重没成",
  "待查重": "待查重",
};

function shortStatus(text) {
  return SHORT_STATUS[text] || text;
}

/**
 * 图标墙里的一枚：一格 zip。
 * 它替掉了原来那一行文本（id / 名称 / code / 状态挤在一行里），所以每一格里只剩三样：
 * 图标、模块 ID（主标题）、版本与状态（次行）。点整块 = 把表单装成这一枚。
 */
function zipCard(card) {
  const v = cardValues(card);
  const box = node("div", "zipcard");
  box.dataset.key = card.key;
  if (card === activeCard()) box.classList.add("is-current");
  if (isRecorded(card)) box.classList.add("is-recorded");

  const pick = node("button", "zipcard__pick");
  pick.type = "button";
  pick.setAttribute("aria-label", `编辑 ${v.id || "这一枚"} 模块`);
  const ico = node("span", "zipcard__ico");
  ico.append(zipIconSvg());
  pick.append(ico);
  pick.append(node("span", "zipcard__id", v.id || "（还没解析出模块 ID）"));
  const meta = [v.version ? `v${v.version}` : "", v.versionCode ? `code ${v.versionCode}` : ""].filter(Boolean).join(" · ");
  pick.append(node("span", "zipcard__meta", meta || "—"));
  // 从「我的模块」来的那一枚要写出「它是从哪一版往上走」：只写新填的 code 101 而不说当前是 100，
  // 用户没法判断自己是不是跳错了版本 —— 这一行是那一格唯一的上下文。
  if (card.fromMine) {
    const was = [card.fromMine.version ? `v${card.fromMine.version}` : "", card.fromMine.versionCode ? `versionCode ${card.fromMine.versionCode}` : ""]
      .filter(Boolean)
      .join(" / ");
    pick.append(node("span", "zipcard__was", `当前已收录：${was || "（后端没给版本）"}`));
  }
  // 状态标签排在格子里（跟在版本行下面）：墙角放不下「没收录 · 可上传」这么长的字，
  // 贴角会压住图标 —— 所以走正常流，短文案上台面，整句留给 title 与读屏。
  const st = statusOf(card);
  const stEl = node("span", `chip zipcard__st${chipToneClass(st.tone) ? " " + chipToneClass(st.tone) : ""}`, shortStatus(st.text));
  stEl.title = st.text;
  pick.append(stEl);
  pick.addEventListener("click", () => selectCard(card.key));
  box.append(pick);

  // 还差什么：只在「没齐、而且它本来该进这一套」时才说 —— 已收录的那一枚不在这里重复解释。
  const gaps = cardGaps(card);
  if (gaps.length && !isRecorded(card)) {
    box.append(node("span", "zipcard__why", `还差：${gaps.join("、")}`));
  }

  const rm = node("button", "zipcard__x", "×");
  rm.type = "button";
  rm.setAttribute("aria-label", "移除这一枚");
  rm.addEventListener("click", () => {
    commitView();
    dropCard(card);
  });
  box.append(rm);

  // 重选这个包：换掉这一枚的字节。它跟 × 一起藏在墙角（同一套 hover 显隐），
  // 但放在右边 —— 左边那枚是「移除」，误点代价是丢一枚；换包只是重解析，放远一点更稳。
  // 换包 = 换一整套：这一枚的整包哈希是集合签名的输入之一，旧串当场作废重算（见 swapRun）。
  const sw = node("button", "zipcard__swap", "↻");
  sw.type = "button";
  sw.title = "给这一枚重选一个 zip";
  sw.setAttribute("aria-label", "给这一枚重选一个 zip");
  sw.addEventListener("click", () => requestSwap(card));
  box.append(sw);
  return box;
}

/**
 * 单独给一枚换包：借一个隐藏的 file input，换完只重解析那一枚。
 * 换包必须让签名那一串当场死掉 —— 那一枚的整包哈希是集合签名的输入之一，
 * 换一枚就是换一整套（§15），旧串对不上新字节，服务端会回 sha_mismatch / 签名对不上。
 */
let swapKey = "";
function requestSwap(card) {
  if (!card) return;
  commitView();
  swapKey = card.key;
  const input = $("#file-swap");
  if (!input) return;
  input.value = "";
  input.click();
}

function bindSwap() {
  const input = $("#file-swap");
  if (!input) return;
  input.addEventListener("change", () => {
    const file = input.files && input.files[0];
    const card = state.cards.find((c) => c.key === swapKey);
    swapKey = "";
    if (!file || !card || !state.cards.includes(card)) return;
    swapInto(card, file);
  });
}

/** 排在同一条解析链上：换包与选新包不能并发（applyProp 只有一份，它写的是表单）。 */
function swapInto(card, file) {
  // 同一个 catch 的理由：这条链一旦带着 rejection，之后选包与换包全部静默失效（见 scheduleIntake）。
  parseChain = parseChain.then(() => swapRun(card, file)).catch(intakeFailed);
}

async function swapRun(card, file) {
  // 先动卡上的那个 file 对象，再把视图的租约交给它：intake() 认的是 activeCard() 那一张卡，
  // 它归零的是这一枚自己的 zip / zipSha / 查重结论。名字一样但字节不同也照样重算 ——
  // 「整包哈希绑字节」这件事不允许因为文件名没变就被跳过。
  card.file = file;
  selectCardNow(card.key);
  state.parsing = true;
  try {
    await intake(file);
  } finally {
    state.parsing = false;
  }
  if (!state.cards.includes(card)) return; // 解析中被判不合格已经移除了，没什么可重查的
  renderQueue();
  await runBatchCheck([card]);
}

function renderQueue() {
  const bar = $("#queue");
  if (!bar) return;
  const wall = $("#zip-wall");
  const drop = $("#drop");
  if (!state.cards.length) {
    bar.hidden = true;
    if (wall) wall.textContent = "";
    $("#queue-count").textContent = "";
    $("#queue-note").textContent = "";
    // 空队列时上传框恢复成原来那个大方块：墙上没有卡了，就没必要给它让位。
    if (drop) drop.classList.remove("is-full");
    renderEditing();
    renderStage();
    return;
  }
  bar.hidden = false;
  // 有卡时上传框收窄成一条，把纵向空间全让给图标墙（CSS 的 .drop.is-full 那一档）。
  if (drop) drop.classList.add("is-full");
  if (wall) {
    wall.textContent = "";
    for (const card of state.cards) wall.append(zipCard(card));
  }
  paintQueueReadout();
  renderEditing();
  renderStage();
}

/**
 * 02 那一屏顶部的小字：表单现在装的是第几枚、共几枚。
 * 只有多于一枚时它才是信息 —— 单枚路径不加这种噪音（和队列条那一档 quiet 退化同一个理由）。
 * 它读的判据就是队列用的那一个（activeCard / state.cards），不是第二份状态。
 */
function renderEditing() {
  const box = $("#editing");
  if (!box) return;
  const cur = activeCard();
  const at = cur ? state.cards.indexOf(cur) : -1;
  if (!cur || state.cards.length < 2) {
    box.hidden = true;
    box.textContent = "";
    return;
  }
  const v = cardValues(cur);
  box.hidden = false;
  box.textContent = "";
  box.append(
    node("span", null, `正在编辑第 ${at + 1} / ${state.cards.length} 枚：${v.id || (cur.file ? cur.file.name : "还没选包")}`),
    " "
  );
  const nav = node("span", "editing__nav");
  for (const [label, delta] of [["上一枚", -1], ["下一枚", 1]]) {
    const b = node("button", "btn btn--ghost btn--sm", label);
    b.type = "button";
    const target = state.cards[at + delta];
    b.disabled = !target; // 到头了就点不动（这不是闸，是没有下一枚）
    if (target) b.addEventListener("click", () => selectCard(target.key));
    nav.append(b);
  }
  box.append(nav);
}

/** 队列底栏那两颗：继续加包 / 清空整条队列。 */
function bindQueueBar() {
  const add = $("#queue-add");
  if (add) add.addEventListener("click", () => {
    const input = $("#file");
    if (input) {
      input.value = "";
      input.click();
    }
  });
  const clear = $("#queue-clear");
  if (clear) clear.addEventListener("click", () => clearQueue());
}

/** 队列顶部那一句「这一套是几枚」；被摘出去的枚不进这里（说了 N 枚就得真发 N 个 file part）。 */
function paintQueueReadout() {
  const targets = submitTargets();
  const recorded = state.cards.filter((c) => isRecorded(c));
  const bar = $("#queue");
  const count = $("#queue-count");
  count.textContent = targets.length
    ? `这一套 ${targets.length} 枚 · 一次提交`
    : "这一套里没有要上传的枚";
  if (recorded.length) count.textContent += ` · ${recorded.length} 枚已被上传过，摘出了`;
  // 只有一枚、而且这一枚没被摘出去时，整条队列退化成一行：不写这套那两句边界话 ——
  // 那两句对只投一枚的人一个字都没多说。有摘出去的枚、或有被跳过的包时它才是信息。
  const quiet = state.cards.length <= 1 && !recorded.length && !state.skippedFiles.length;
  bar.dataset.quiet = quiet ? "1" : "0";
  const note = $("#queue-note");
  if (quiet) {
    note.textContent = "";
    return;
  }
  const bits = [
    "一次上传 = 一整套模块：签名只改一次（绑的是这一套的全集）、承诺只勾一次、POST 只发一次。增删任一枚、改任一枚的模块 ID、给任一枚重选包，都会让那一串变成另一串 —— 改完要重新抄进签名。",
    "查重这道闸只看公开索引里的模块 ID：索引里不带酷安 UID，所以它只能说「这个 id 已被上传过」，**分不清是谁上传的**；已经上传但还没合进索引的那些今天查不到 —— 要拦那一档得后端加一档状态，这一轮没做。",
  ];
  if (state.skippedFiles.length) {
    bits.unshift(
      `刚才跳过了 ${state.skippedFiles.length} 个不合格的包：${state.skippedFiles.slice(0, 3).join("、")}${
        state.skippedFiles.length > 3 ? " 等" : ""
      } —— 原因见上面那几行。`
    );
  }
  note.textContent = bits.join(" ");
  const ids = state.cards.map((c) => cardValues(c).id).filter(Boolean);
  const dupId = ids.find((id, i) => ids.indexOf(id) !== i);
  if (dupId) {
    note.append(
      node(
        "span",
        "queue__dup",
        ` 队列里有两枚模块 ID 都是 ${dupId}：同一套里同一个 ID 出现两次，服务端按 manifest 形状不对拒掉**整个这一次上传**（§16 的 normalizeDeclaredSet），不是只跳过那一枚 —— 把其中一枚移掉或改成别的 ID。`
      )
    );
  }
}


/* ------------------------------------------------------- 02 舞台（轮播换卡） */

/**
 * 舞台 = 02 区那张元数据表外面的一层壳：中间那张永远是当前这一枚，左右两侧各露一窄条
 * （看得出还有别的，但不抢注意力），底下圆点标位置。壳是纯装饰，表单本身一个字没动 ——
 * 所以切卡仍然是 selectCard()，这里只负责把「左右是谁、现在第几枚」画出来。
 */
let stageTimer = 0;

/** 循环取邻居：只有一枚时上一张和下一张都是它自己（那时舞台不出箭头，也没人来点）。 */
function stageNeighbor(delta) {
  const n = state.cards.length;
  if (!n) return null;
  const at = state.cards.indexOf(activeCard());
  const from = at === -1 ? 0 : at;
  return state.cards[(((from + delta) % n) + n) % n];
}

/** 把一张露头卡填成某一枚：没有那一枚时整块藏起来，三个 span 一起清空（不留上一枚的残字）。 */
function paintPeek(box, card) {
  if (!box) return;
  const parts = [".stage__peek-id", ".stage__peek-nm", ".stage__peek-ver"].map((sel) => box.querySelector(sel));
  if (!card) {
    box.hidden = true;
    for (const el of parts) if (el) el.textContent = "";
    return;
  }
  const v = cardValues(card);
  box.hidden = false;
  if (parts[0]) parts[0].textContent = v.id || "（没 ID）";
  if (parts[1]) parts[1].textContent = v.name || "—";
  if (parts[2]) parts[2].textContent = v.version ? `v${v.version}` : "";
}

function renderStage() {
  const stage = $("#stage");
  if (!stage) return;
  const multi = state.cards.length > 1;
  stage.classList.toggle("is-multi", multi);
  paintPeek($("#stage-peek-prev"), stageNeighbor(-1));
  paintPeek($("#stage-peek-next"), stageNeighbor(1));

  const prev = $("#stage-prev");
  const next = $("#stage-next");
  for (const btn of [prev, next]) if (btn) btn.disabled = !multi;

  const dots = $("#stage-dots");
  if (!dots) return;
  dots.textContent = "";
  const cur = activeCard();
  for (const card of state.cards) {
    const dot = node("button", "stage__dot" + (card === cur ? " is-on" : ""));
    dot.type = "button";
    dot.setAttribute("aria-label", `切到第 ${state.cards.indexOf(card) + 1} 枚`);
    dot.addEventListener("click", () => selectCard(card.key));
    dots.append(dot);
  }
}

/** 切到相邻的那一枚。加一个 is-switching 类让主卡先淡下去再换内容（220ms 后摘掉）。 */
function switchStage(delta) {
  const target = stageNeighbor(delta);
  if (!target || target.key === state.active) return;
  const stage = $("#stage");
  if (stage) {
    stage.classList.add("is-switching");
    clearTimeout(stageTimer);
    stageTimer = setTimeout(() => stage.classList.remove("is-switching"), 220);
  }
  selectCard(target.key);
}

/** 舞台上的三种手势：箭头 / 点露头 / 拖拽滑动；键盘左右另挂在 document 上。 */
function bindStage() {
  const stage = $("#stage");
  if (!stage) return;
  const prev = $("#stage-prev");
  const next = $("#stage-next");
  if (prev) prev.addEventListener("click", () => switchStage(-1));
  if (next) next.addEventListener("click", () => switchStage(1));
  const peekPrev = $("#stage-peek-prev");
  const peekNext = $("#stage-peek-next");
  if (peekPrev) peekPrev.addEventListener("click", () => switchStage(-1));
  if (peekNext) peekNext.addEventListener("click", () => switchStage(1));

  // 拖拽 / 滑动：按下记起点，松开比位移。40px 是「明显是想翻页」而不是「手抖了一下」的那一档。
  let startX = 0;
  let startY = 0;
  let tracking = false;
  stage.addEventListener("pointerdown", (e) => {
    // 鼠标只认左键；触摸与笔一律认。在箭头 / 圆点上按下不算拖（那是点击）。
    if (e.pointerType === "mouse" && e.button !== 0) return;
    // 输入框里的拖拽是「选文字」，不是翻页：textarea 里横向拖过 40px 就会被当成一次滑动，
    // 于是用户在 A 的「模块描述」里拖选，回来发现表单已经换成 B 了（焦点没动、内容换了）。
    if (e.target.closest && e.target.closest(".stage__arrow, .stage__dot, .stage__peek")) return;
    if (e.target.closest && e.target.closest("input, textarea, select, [contenteditable]")) return;
    startX = e.clientX;
    startY = e.clientY;
    tracking = true;
  });
  stage.addEventListener("pointermove", (e) => {
    if (!tracking) return;
    if (Math.abs(e.clientX - startX) > 8) stage.classList.add("is-dragging");
  });
  const endDrag = (e) => {
    if (!tracking) return;
    tracking = false;
    stage.classList.remove("is-dragging");
    const dx = e.clientX - startX;
    const dy = e.clientY - startY;
    // 竖着划走是滚页面，不是换卡：只在横向位移明显大于纵向时才算一次翻页。
    if (Math.abs(dx) < 40 || Math.abs(dx) <= Math.abs(dy)) return;
    switchStage(dx < 0 ? 1 : -1);
  };
  stage.addEventListener("pointerup", endDrag);
  stage.addEventListener("pointercancel", () => {
    tracking = false;
    stage.classList.remove("is-dragging");
  });

  // 键盘：焦点在这一屏里时左右键换卡。只认焦点在舞台内的情况 ——
  // 全局监听左右键会跟输入框里移动光标、跟浏览页的翻页抢按键。
  document.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    if (!stage.contains(document.activeElement)) return;
    // #stage-main 里装的全是输入框：在它们里面按左右键是移动光标，不是换卡。
    // 少了这一道，光标一动就把整张表单换成另一枚（switchStage → selectCard → selectCardNow
    // 会先 commitView 再 applyView），用户以为还在改 A，后面的字全写进 B。
    const el = document.activeElement;
    if (el && el.closest && el.closest("input, textarea, select, [contenteditable]")) return;
    if (state.cards.length < 2) return;
    e.preventDefault();
    switchStage(e.key === "ArrowRight" ? 1 : -1);
  });
}

/* ----------------------------------------------------------- 02 查重 /check */

function showCheck(tone, chip, title, desc) {
  const box = $("#check");
  box.hidden = false;
  box.className = `status${tone === "ok" ? " status--ok" : tone === "warn" ? " status--warn" : ""}`;
  const chipEl = $("#check-chip");
  chipEl.textContent = chip;
  const toneClass = { ok: "chip--ok", warn: "chip--warn", idle: "chip--idle" }[tone] || "";
  chipEl.className = `chip${toneClass ? " " + toneClass : ""}`;
  $("#check-t").textContent = title;
  $("#check-d").textContent = desc;
}

/**
 * 那两档边界要说给用户听的话（recorded / version_update）。
 * 为什么写在这儿而不是 api.js：CHECK_STATUS 是 /check 契约的措辞，本站只有后端那一份判据；
 * 这里加的是「这道前端预拦能做到什么、做不到什么」，属于本页的说明，不是第二份判据。
 *
 * 措辞的边界要说真话，三句都不能少：
 * ① 公开索引里没有上传人 UID（build-index 的投影层故意不带）⇒ 光看索引只能说「这个 id 已被上传过」，
 *    **不能从索引暗示归属**；归属只有一条来源：`/check` 带上 uid 之后后端回的 `update_eligible`。
 *    所以下面这段正文里仍然不写「别人传的」，那句话改由 gateNote() 按 update_eligible 说。
 * ② 正在待审（pending/ 里、还没合进索引）的同 id 今天查不到 ⇒ 这一档拦不住，得后端加一档状态；
 * ③ 摘出之后签名那一串会变 —— 签名绑的是这套的全集，少一枚就是另一个前缀。
 */
const CHECK_EXTRA = {
  recorded:
    " 这一枚已经从本次上传里摘出去了：不进 manifest、不进签名那一串、也不提交。" +
    "摘出去之后屏幕上那一串签名就按剩下的那几枚重算 —— 已经抄进签名的那串要重抄一次。" +
    "它只看公开索引里的模块 ID：索引里不带酷安 UID，所以分不清「已被上传过」那一条是谁上传的；" +
    "还在审核里、没合进索引的上传今天查不到。想留着看就由你留着，队列里点「移除」。" +
    "自己的模块不用在这一页猜：验证过 UID 之后，「我的模块」那一格列着它们，点「上传更新版」就接着发。",
  // 这句原来说「不会被自动合进索引」—— 那是假话（契约 §4.1 点名要改）。版本更新与首投走
  // 同一套机器判据，过了就自动进索引；页面从前教人「更新永远进不去」，而它其实进得去。
  version_update:
    " 这不是重复，所以它留在这一套里照常要上传 —— 版本更新会按同一套机器判据审核，通过后自动进索引。",
};

const checkTimers = new Map();

/** 每一枚各查各的：合并同一枚的连续按键（结论要落到各自的卡上）。批量那一条路见 runBatchCheck。 */
function scheduleCheck(card, delay = 420) {
  if (!card) return;
  clearTimeout(checkTimers.get(card.key));
  checkTimers.set(
    card.key,
    setTimeout(() => {
      checkTimers.delete(card.key);
      runCheckFor(card);
    }, delay)
  );
}

function cancelCheck(card) {
  clearTimeout(checkTimers.get(card.key));
  checkTimers.delete(card.key);
}

/**
 * 早期重复拦截（§17.6 的 `POST /check`）：一批包解析完就一次查完，命中「已被上传过」的那一枚
 * 当场标出来、摘出后续步骤 —— 不让它白走一遍填表、白抄一次签名、白占一次限流。
 *
 * 这条路走不通时（后端还没上批量那个入口、或网络失败）逐枚 `GET /check` 顶上：功能不降级，
 * 只是多打几个请求。两种来路都要在界面上说得出是哪一种 —— 「查过了」和「用另一种法子查的」
 * 不是同一句话，而这里说的边界（分不清归属、待审查不到）两种来路都一样。
 */
async function runBatchCheck(cards) {
  const list = (cards || [])
    .map((card) => ({ card, v: cardValues(card) }))
    .filter(({ v }) => v.id && /^\d+$/.test(v.versionCode))
    .map(({ card, v }) => ({ card, id: v.id, versionCode: v.versionCode }));
  if (!list.length) return;
  for (const row of list) cancelCheck(row.card);
  // 归属这一问要带上 uploader UID，和逐枚那条一个道理（`runCheckFor` 也是现读表单）。
  // 现读表单而不是读 `cardValues(card)`：coolapkUid 是整套共享的那一格（SHARED_KEYS），
  // 它不在卡上 —— 非当前卡的 `card.values` 里没有它，读卡的会恒拿到空串，
  // 于是批量这条路的归属永远问不出来（这正是这次要修的那个缺口）。
  const uid = fieldValue("coolapkUid");
  const r = await checkModulesBatch(list.map(({ id, versionCode }) => ({ id, versionCode, uid })));
  state.checkVia = r.via;
  if (r.via !== "batch") {
    // 批量那一条没走通 ⇒ 回到逐枚那一条。原因留着给清单与说明页说（不假装查过）。
    state.checkWhy = r.why || "";
    for (const row of list) scheduleCheck(row.card, 0);
    return;
  }
  for (const row of list) {
    if (!state.cards.includes(row.card)) continue;
    const got = r.statuses.get(row.id);
    // 后端没给这一枚的结论 == 这一枚没查到，不等于「没被投过」：交回逐枚那一条再问一次。
    if (!got) {
      scheduleCheck(row.card, 0);
      continue;
    }
    // 归属三态跟着 status 一起落卡（同一次判定，不许分两处写）：
    // 它决定闸门清单里那一发会不会被拦，而批量这条路正是「一键更新」走的那一条。
    row.card.checkUid = uid;
    row.card.updateEligible = got.updateEligible;
    row.card.updateReason = got.updateReason || "";
    setCheck(row.card, got.status, checkKeyOf(row.id, row.versionCode), "");
  }
  renderQueue();
  refreshGate();
}

/**
 * 来源一动就先作废，不等那 420ms 的 debounce，也不等下一次网络回来。
 * 「这一枚已经收录了」的结论挂在改了 ID 的表单上，就等于屏幕上写着一句关于上一个 ID 的话。
 */
function invalidateCheck(card) {
  if (!card) return;
  card.checkStatus = null;
  card.checkKey = "";
  card.checkWhy = "";
  if (card === activeCard()) {
    state.checkStatus = null;
    $("#check").hidden = true;
  }
  renderQueue();
  if (card === activeCard()) refreshGate();
}

async function runCheckFor(card) {
  if (!card || !state.cards.includes(card)) return;
  const v = cardValues(card);
  const id = v.id;
  const code = v.versionCode;
  // 归属这一问要带上上传人 UID：后端只有在拿到 uid 且 status 是 version_update 时才会答
  // 「这一版该不该由你发」。
  //
  // **必须现读表单**，不能走 `cardValues(card).coolapkUid` —— 它是 `SHARED_KEYS` 里那一格，
  // 不在 `CARD_KEYS` 里，而 `cardValues()` 只按 `CARD_KEYS` 建（当前卡）或从 `card.values`
  // 拷（别的卡）。两条路都拿不到它，`v.coolapkUid` 恒为 `undefined` ⇒ uid 恒为空串 ⇒
  // 后端永远只会回 `update_eligible: null`，归属闸在这条路上从来没生效过（批量那条同病，一起修）。
  const uid = fieldValue("coolapkUid");
  const isActive = card === activeCard();
  if (!id || !/^\d+$/.test(code)) {
    setCheck(card, null, "", "");
    if (isActive) $("#check").hidden = true;
    return;
  }
  const key = checkKeyOf(id, code);
  // uid 也是这一问的输入：换了账号而 (id, versionCode) 没变，结论照样会变。
  // 所以缓存命中要连 uid 一起比 —— 只比 (id, versionCode) 会让「换号之后界面还写着别人能发」。
  if (card.checkStatus && card.checkKey === key && (card.checkUid || "") === uid) {
    if (isActive) renderCheck();
    return; // 这一对 (id, versionCode, uid) 已经查过了，切回来不再打一次
  }
  card.checkRun = key;
  card.checkWhy = "";
  if (isActive) showCheck("idle", "checking", "正在查重…", `检查 ${id} 是否已在公开索引里。`);
  renderQueue();
  let status = null;
  let eligible = null;
  let gateReason = "";
  let why = "";
  try {
    const out = await checkModule(id, code, uid);
    status = out.status;
    eligible = out.updateEligible;
    gateReason = out.updateReason || "";
  } catch (err) {
    why = err instanceof BackendError ? err.message : "查重请求失败，不影响你继续上传。";
  }
  // 这一枚在等回包期间被移除了就什么都不做；结论落卡，视图只在租约还在时跟着动。
  if (!state.cards.includes(card)) return;
  card.checkUid = uid;
  card.updateEligible = eligible;
  card.updateReason = gateReason;
  setCheck(card, status, key, why);
  if (isActive) {
    if (status) {
      const meta = CHECK_STATUS[status];
      showCheck(
        meta.tone === "ok" ? "ok" : meta.tone === "warn" ? "warn" : "muted",
        meta.label,
        meta.title,
        meta.hint + (CHECK_EXTRA[status] || "") + gateNote(card)
      );
    } else {
      showCheck("warn", "未确认", "现在查不了重", why);
    }
  }
  renderQueue();
}

/**
 * 归属那一格的补充说明（契约 §3.1 的 `update_eligible` 三态）。
 *
 * 三态必须分得开，因为它们对用户的意思完全不同：
 *   true  —— 是你的模块，可以发更新（不用多说，正文已经讲了怎么发）；
 *   false —— 不是你的：现在就该说清「别白抄签名了」，而不是等他填完一整页再被 403 打回来；
 *   null  —— 不知道（没填 UID / 后端还没这一格 / 请求失败）。**不许猜成 true 或 false**：
 *            猜 true 会让人白走一趟，猜 false 会诬告一次「这不是你的模块」。
 *
 * 这里多一道 `checkUid` 比对，理由与闸门清单那一格相同：归属结论是**某一次带着某个 UID
 * 的询问**的产物，换了账号它就是上一个账号的答案。
 */
function ownershipOf(card) {
  if (!card || card.updateEligible === null) return null;
  if ((card.checkUid || "") !== fieldValue("coolapkUid")) return null;
  return card.updateEligible === true ? "mine" : "other";
}

function gateNote(card) {
  if (ownershipOf(card) !== "other") return "";
  const why = card.updateReason ? `（服务端原话：「${card.updateReason}」）` : "";
  return (
    " 但这一版**发不了**：这个模块已被别人收录，按现在的归属规则不接受他人发版" +
    why +
    "。整单提交会被 403 拒掉 —— 先确认「酷安 UID」填的是当初首发那个账号；不是你的模块就别试了。"
  );
}

/** 视图切到某一枚之后，把它的查重结论原样画回那一格（没有就收起）。 */
function renderCheck() {
  const card = activeCard();
  const status = card ? checkOf(card) : null;
  if (!status) {
    $("#check").hidden = true;
    return;
  }
  const meta = CHECK_STATUS[status];
  showCheck(
    meta.tone === "ok" ? "ok" : meta.tone === "warn" ? "warn" : "muted",
    meta.label,
    meta.title,
    meta.hint + (CHECK_EXTRA[status] || "") + gateNote(card)
  );
}

function bindCheck() {
  for (const key of ["id", "versionCode"]) {
    // 第一下就作废旧结论，然后再排一次查询 —— 顺序反了就会有一段时间屏幕上挂着旧的那句。
    fieldEls[key].addEventListener("input", () => {
      const card = commitView();
      invalidateCheck(card);
      renderProof();
      scheduleCheck(card);
    });
  }
  // 签名文本是 (id, 整包 sha256, nonce) 的派生值，id 一动就得重算 —— 与查重同一个触发点。
  // 另一个来源（包）在 intake 里到货，那里算完哈希自己再渲染一次。
  fieldEls.id.addEventListener("input", renderProof);
  fieldEls.coolapkUid.addEventListener("input", () => {
    // 「这个昵称属于上一串 UID」在按键那一刻就已经成立，等不到 debounce 后的核实结果
    syncUploaderField();
    runUidCheck();
    // 归属那一问的输入是 (id, versionCode, uid)：UID 一改，上一轮的「能不能发更新」就过期了。
    // 不作废的话，换号之后界面上还挂着「这一版发不了」—— 那句话说的是上一个账号。
    const card = commitView();
    invalidateCheck(card);
    scheduleCheck(card);
  });
  fieldEls.source.addEventListener("blur", () => {
    // 很多人会直接粘 www.coolapk.com/feed/…，补上协议再存，省一次报错
    const fixed = normalizeCoolapkUrl(fieldEls.source.value);
    if (fixed && fixed !== fieldEls.source.value.trim()) fieldEls.source.value = fixed;
  });
  for (const el of Object.values(fieldEls)) {
    if (!el) continue;
    el.addEventListener("input", () => {
      if (el.dataset.auto !== "1" && el.value.trim()) el.closest(".field").classList.remove("is-bad");
      refreshGate();
    });
    el.addEventListener("blur", () => {
      if (state.attempted) paintFieldErrors();
    });
  }
  $("#meta-note").insertAdjacentElement(
    "afterend",
    (() => {
      const p = node("p", "field__help");
      p.append("想先确认有没有人上传过？", " ");
      const a = node("a", null, "按当前 ID 搜已收录列表");
      a.href = "#";
      a.addEventListener("click", (e) => {
        e.preventDefault();
        const id = fieldValue("id") || "";
        location.hash = `#/index?q=${encodeURIComponent(id)}`;
      });
      p.append(a);
      return p;
    })()
  );
}

/* -------------------------------------------------- 04 门禁清单与校验状态 */

/**
 * 整套那份齐没齐 —— 一次提交一整套，所以这里判的是「这一套发得出去吗」，不是「当前这一枚」。
 * 当前卡的那份单值镜像（state.zip / state.zipSha）只用来决定屏幕上那一串现不现（见 gateItems
 * 里那条 shown），**它不是判据**：判据是每一枚各自的卡，判据只有一份（cardGaps）。
 */
function collect() {
  const targets = submitTargets();
  const missing = SHARED_KEYS.filter((k) => !fieldValue(k));
  const badUid = fieldValue("coolapkUid") && !isCoolapkUid(fieldValue("coolapkUid"));
  return {
    zipOk: targets.length > 0 && targets.every((c) => c.zip && c.zip.inspect && c.zip.inspect.ok),
    missing,
    badCode: targets.some((c) => {
      const v = cardValues(c);
      return v.versionCode && !/^\d+$/.test(v.versionCode);
    }),
    badUid: Boolean(badUid),
    badSource: targets.some((c) => {
      const v = cardValues(c);
      return v.source && !normalizeCoolapkUrl(v.source);
    }),
    targets,
  };
}

function uidBlocked() {
  if (!IS_UID_VERIFY_ON) return false;
  if (state.uidStatus === "not_found" || state.uidStatus === "invalid") return true;
  // 只有「查无此人」和「UID 形状不对」算不是本人。核实没接上 / 酷安抖动是「平台没核实成」，
  // 不是「你不是本人」，所以放行 —— 签名成不成由 Worker 判，前端不加第二道闸。
  return false;
}

/* 签名只在「UID 核实通过」那一刻拿到随机段（赋值集中在 setNonce 这一个函数里：核实通过补空缺、
   签名烧掉换串两个调用点），所以这条没过时，
   原因可能在站点这边（核实根本没接），也可能在流程还没走完（正在查 / 还没查）。两者写成同一句
   「签名没生成」，被拦住的人就只剩一个说不清为什么的坏按钮 —— 状态文案必须说清卡在谁手上。
   随机段就位之后还差两个来源：模块 ID 和整包 sha256。签名串绑的是它们三个（设计文档 §14.1），
   所以哈希没算完的那一刻不能说「已生成」—— 那时屏幕上还没有可抄进签名的一串。
   注意这里改的全是说明文字：ok 只看 Boolean(state.nonce)，前端不加第二条闸，判定在 Worker。
   说明文字一律先说「还差什么」再说已有什么 —— 底栏那句「全部就绪」也由这些句子代写，
   签名还没出现在屏幕上时它不许说就绪（见 refreshGate 里那段 shown）。 */
const NONCE_WHY = {
  off: "后端没配置酷安身份核实，签名生成不了 —— 上传通道未开放，这一步要站点来接",
  self_reported: "后端收到了 UID 但没核实它，签名生成不了 —— 上传通道未开放，这一步要站点来接",
  unavailable: "这次没核实成，签名还没生成 —— 把 UID 重敲一遍会再查；一直不通是后端没接上核实",
  checking: "正在核实 UID —— 通过后随机段就位，这一串还要有模块 ID 和整包 sha256 才算得出",
};

function gateItems() {
  const targets = submitTargets();
  const recorded = state.cards.filter((c) => isRecorded(c));
  const acked = state.cards.filter((c) => c.ack);
  const spent = acked.length > 0;
  const missingShared = SHARED_KEYS.filter((k) => !fieldValue(k));
  const badUid = fieldValue("coolapkUid") && !isCoolapkUid(fieldValue("coolapkUid"));
  const badSource = targets.filter((c) => {
    const v = cardValues(c);
    return v.source && !normalizeCoolapkUrl(v.source);
  });
  const incomplete = targets.filter((c) => cardGaps(c).length > 0);
  const metaKeys = ["id", "name", "version", "versionCode"];
  // 这一整套的 (id, 整包 sha256) 能不能算出规范串 —— `canonicalProofSet` 拒「同一个模块 id 出现
  // 两次」（服务端 normalizeDeclaredSet 同样整单拒，§16）。这种时候屏幕上那一格写的是「这一套
  // 现在算不出签名」，所以底栏那句「全部就绪」与下面那条清单都得跟着这同一个判据走 ——
  // 判据只有一份，不在这里另发明第二条闸（按钮的 enable 条件一个字不动）。
  const idsInSet = targets.map((c) => cardValues(c).id).filter(Boolean);
  const dupId = new Set(idsInSet).size !== idsInSet.length;
  const metaBad = targets.filter((c) => {
    const v = cardValues(c);
    return metaKeys.some((k) => !v[k]) || (v.versionCode && !/^\d+$/.test(v.versionCode));
  });
  const overCount = overModuleCount(targets.length);
  const overTotal = overTotalBytes(targets);
  // 归属闸（契约 §3.3）：这一套里有模块的更新权不属于当前 UID。
  // 只有后端**明确**回了 false 才算 —— updateEligible 是 null（没填 UID / 后端还没这一格 /
  // 这一枚不是版本更新）时一律不进这一格：猜一个 false 就是诬告一次「这不是你的模块」。
  // 拦在这里而不是等提交被 403：签名是一次性的，白抄一次就烧掉了。
  //
  // 还要比 `checkUid`：`invalidateCheck` 只清 status/key/why，不清这一格（清了也没用 ——
  // 它和 status 是同一次判定的产物）。换了账号而没重查时，上一轮那句「不是你的」说的是
  // 上一个 UID 的事；只认「这个结论是在当前这个 UID 下问到的」才准许它拦人。
  // 判据收在 ownershipOf 一处 —— 队列那枚 chip 与这道闸各写一份，迟早会漂成
  // 「清单说能发、屏幕说不是你的」。那个函数在这里声明在后面，但函数声明有提升。
  const notMine = targets.filter((c) => cardValues(c).versionCode && ownershipOf(c) === "other");

  // 下面每一格说的都是**这一整套**，不是「当前这一枚」—— 因为提交是整套一次。
  // 所以每一格都要点不出「是哪一枚」（枚数一多，「还差一步」不说差在哪一枚就等于没说）。
  const items = [
    // 解析链的失败必须自己说话。这一格存在的理由写在 scheduleIntake 的注释里：
    // 链一旦 reject 过，之后每一次选包都会被静默跳过 —— 没有这一行，用户的界面就是「点了没反应」。
    ...(state.intakeError
      ? [
          {
            ok: false,
            text:
              `刚才那一批包没被队列收下：${state.intakeError}。` +
              "把那个包再拖一次就行；反复出现请把这一句原样发给站点（这是浏览器侧的解析失败，不是你的包被判了恶意）。",
          },
        ]
      : []),
    {
      ok: targets.length > 0 && incomplete.length === 0,
      text: incomplete.length
        ? `这一套里有 ${incomplete.length} 枚还没齐：${namesOf(incomplete)} —— 每枚的模块 ID / 名称 / 版本 / 版本号 / 出处都要填，整包哈希也要算出来`
        : targets.length
        ? `这一套 ${targets.length} 枚的 zip 都选了、根目录都含 module.prop、元数据都齐了`
        : "还没选包：一次上传可以只传一枚，也可以一整套一起传，先把包拖进来",
    },
    {
      ok: metaBad.length === 0 && targets.length > 0,
      text: metaBad.length
        ? `版本号要整数、四个必填都要有：${namesOf(metaBad)}`
        : "每一枚的模块 ID / 名称 / 版本 / 版本号 齐全（版本号为整数）",
    },
    {
      ok: badSource.length === 0 && targets.length > 0,
      text: badSource.length
        ? `出处必须是酷安站内链接：${namesOf(badSource)}`
        : "每一枚的模块出处都是酷安站内链接",
    },
    {
      ok: !missingShared.includes("uploader"),
      text: "上传人酷安昵称已取得（一次上传一份署名，这套里每一枚都用它）",
    },
    {
      ok: !missingShared.includes("coolapkUid") && !badUid,
      text: "酷安 UID 已填，且是 4-12 位纯数字（一次上传一份，不用逐枚填）",
    },
  ];
  if (IS_UID_VERIFY_ON) {
    const label =
      state.uidStatus === "verified"
        ? "酷安用户已核实"
        : uidBlocked()
        ? "酷安用户核实没通过"
        // 「这条不拦你」只说自己这一条，不承诺整张清单放行 —— 核实没成时签名也不会有，
        // 于是下一条才是真正按住按钮的那条。两句并排时必须各说各的范围，否则互相打脸。
        : "酷安用户核实（这一条不拦你；签名要核实通过才生成）";
    items.push({ ok: !uidBlocked(), text: label });
  }
  // 三条上限全部来自后端自报（§17.6）：问到才拦，问不到就不假装拦 —— 前端猜一个数字当闸，
  // 就是这个站漂过「前端 8MB、后端 2MB」那一类的形状。
  if (overCount !== null) {
    items.push({
      ok: false,
      text: `这一套有 ${targets.length} 枚，超过后端自报的单次枚数上限（${overCount} 枚）—— 拆成两次上传。`,
    });
  }
  if (overTotal !== null) {
    items.push({
      ok: false,
      text: `这一套合计 ${fmtBytes(totalBytes(targets))}，超过后端自报的整套上限（${fmtBytes(overTotal)}）—— 把大的一枚拆到下一次上传去。`,
    });
  }
  if (notMine.length) {
    // 措辞只说后端答了什么，不替它编原因：updateReason 是服务端原话，有就带上。
    // 「整单会被拒」这句是真的 —— 归属闸在「已算出 rows、准备开 PR」之前，任一枚不符就整单 403。
    const why = notMine[0].updateReason ? `（服务端原话：「${notMine[0].updateReason}」）` : "";
    items.push({
      ok: false,
      text:
        `${namesOf(notMine)} 的更新权不属于当前这个酷安 UID：已收录模块只接受原作者发更新，` +
        `整单会被归属闸拒掉，一枚都发不出去${why}。` +
        "先确认「酷安 UID」填的是当初首发那个账号；不是你的模块就只能走举报，别在这里重试 —— 重试只烧签名。",
    });
  }
  if (spent && !targets.length) {
    // 这一套已经提交掉了（每一枚都拿到回执）：签名在服务端记过账了，再发只会回一句「用过」。
    // 随机段在成功那一刻就换过了，所以这里说的不是「你不能再用这一串」，而是「这一套已经交了」。
    items.push({
      ok: false,
      text: `${namesOf(acked)} 已经随这一次上传提交掉了（PR 已开）—— 同一套不能连发两次；要上传别的包就再选一批进来。`,
    });
  } else {
    const card = activeCard();
    const proofId = fieldValue("id");
    // 长效会话那一档：这一次不用抄任何一串（renderProof 把签名那一格整个收起了），
    // 于是「屏幕上有没有一串可抄」这个问题的答案换成「手里这张令牌还成不成立」。
    // 判据仍是 sessionFor 那一份 —— 不在这里另发明第二条，也不改按钮的 enable 条件。
    const viaSession = sessionFor(fieldValue("coolapkUid"));
    let nonceText;
    if (viaSession) {
      nonceText = state.cards.length > 1
        ? `这一套 ${targets.length} 枚走长效会话（90 天内免改签名）—— 这一次不用改签名、也不用抄任何一串`
        : "走长效会话（90 天内免改签名）—— 这一次不用改签名、也不用抄任何一串";
    } else if (!state.nonce) {
      nonceText =
        NONCE_WHY[state.uidStatus] ||
        "签名串还没生成 —— UID 核实通过、填上模块 ID、包也选好了，这一串才出现";
    } else if (recorded.length && !targets.length) {
      nonceText = "这一套里没有要上传的枚了：都被「已被上传过」那一档摘出去了，所以没有签名可生成，签名里也不用抄任何东西。";
    } else if (!proofId && card && !isRecorded(card)) {
      nonceText = "签名串还差：填上模块 ID —— 校验段已生成，但这一串要模块 ID 和整包哈希才算得出";
    } else if (incomplete.length) {
      // 两句各说一个来源缺哪一样：没选包是「还没得选」，选了包是「正在算 / 没算出来」。
      // 都不写「正在算」的肯定语气 —— 算失败时那句话就成假话了。
      const noZip = incomplete.filter((c) => !c.zip);
      const noSha = incomplete.filter((c) => c.zip && !c.zipSha);
      nonceText = noZip.length
        ? "签名串还差：还没选包 —— 签名绑的是这套的字节，先把包选上，这一串才算得出来"
        : noSha.length
        ? `签名串还差：整包哈希还没算完 —— 校验段已生成，这一串要等它（稍等会自己出现；一直没出现就给${namesOf(noSha)}重选一次包）`
        : `签名串还差：${namesOf(incomplete)} 的模块信息没齐 —— 签名是按整套算的，少任何一枚的信息就没有可抄的一串`;
    } else if (dupId) {
      // 三个来源都在，但这一套的形状本身算不出串：两枚模块 ID 相同 ⇒ canonicalProofSet 抛。
      // 这一句必须存在，否则下面那句「共用一串签名」就成了屏幕上的一句假话。
      nonceText =
        "签名串还差：队列里有两枚的模块 ID 是同一个 —— 同一套里同一个 ID 出现两次时这一串算不出来" +
        "（服务端也会按 manifest 形状不对拒掉整个这一次上传），把其中一枚移掉或改成别的 ID";
    } else {
      nonceText = state.cards.length > 1
        ? `这一套 ${targets.length} 枚共用一串签名（填进酷安签名，只改这一次）`
        : "签名串已生成（请填进酷安签名）";
    }
    // shown 说的是「屏幕上现在有没有一串可抄进签名」。v2 那一串的来源是「整套的 (id, 整包 sha256)」
    // 加这一枚随机段，所以当前这枚少 id 或少哈希时屏幕上根本没有可抄的东西 —— 那一格不许自称就绪。
    // 集合形状不对（两枚同一个模块 ID）时同样没有：renderProof 那时候画的是「算不出签名」那一行，
    // 而下面这格还在说「已生成」—— 那就正是这条钉子要抓的现场。
    // 它不参与 ready，也就不参与按钮 —— 全局约束是前端不加第二条闸，判据在 Worker。
    // 它只改底栏那两句：少一个来源时那里写的是这一条的实话，而不是「全部就绪，可以确认」。
    items.push({
      ok: viaSession || Boolean(state.nonce),
      shown: viaSession
        ? targets.length > 0 && incomplete.length === 0 && !dupId
        : Boolean(state.nonce && proofId && state.zipSha) && targets.length > 0 && incomplete.length === 0 && !dupId,
      text: nonceText,
    });
  }
  // 人机校验：Worker 那边没令牌就是 403，所以它必须自己占一格 —— 否则用户会被放进那个
  // 全屏确认层，勾完确认才吃到一个 403，再被退回来找这个部件。
  // ok 落进 ready（就绪判据还是唯一的 items.every），「上传前确认」跟着灭；
  // shown 说的是「这一格在不在屏幕上」：部件是按需加载的，还没到加载时机（没选包、没开确认层）
  // 时先不显示，免得首屏就写一句「还没完成」。
  // 没配 sitekey 时不 push：那时后端也不校验，写一条 ok 恒假的条目等于把整页锁死。
  if (IS_TURNSTILE_CONFIGURED) {
    items.push({
      ok: turnstileOk(),
      shown: Boolean(turnstileStarted),
      text: turnstileOk()
        ? "人机校验已完成"
        : turnstileStarted
        ? "人机校验还没完成 —— 04 区那个部件要等它转出「成功」才给令牌；没加载出来就点它重试"
        : "人机校验还没开始 —— 选好包会自动加载，也可以点一下 04 区那块地方先加载",
    });
  }
  items.push({ ok: IS_API_CONFIGURED, text: "后端 API_BASE 已配置" });
  if (recorded.length) {
    // 早期重复拦截：这几枚已经被摘出这一套 —— 不进 manifest、不进签名那一串、也不提交。
    // 判据是后端 /check 给的那一档，前端没有另判一份「这个包合不合规」。
    // 措辞的边界：只能说「这个 id 已被上传过」—— 公开索引里没有上传人 UID，分不清是谁投的；
    // 还在待审（pending/）里的同 id 今天查不到，那一档这一轮拦不住。
    //
    // `ok: true` 是这一格的关键，不是笔误：要的是「不再参与接下来的步骤」，不是「把剩下几枚
    // 一起扣下」。`ready = items.every(i => i.ok)` 是唯一的就绪判据，这里写 ok:false 就等于
    // 让一枚已收录的老模块挡住整套提交 —— 而这一句明明写着「已摘出、不进这次提交」，
    // 红着灯说这句话是自相矛盾的。它得看得见，所以走 note 那一档：黄点、不拦人、也不算通过。
    items.push({
      ok: true,
      note: true,
      text: `${namesOf(recorded)}：这个 id 已被上传过，已从这一套里摘出去 —— 它不进 manifest，` +
        `签名那一串按剩下的 ${targets.length} 枚算（所以摘之前抄进签名的那串要重抄一次）；` +
        `这道闸分不清是谁上传的，也查不到还在待审的那一份。`,
    });
  }
  if (state.cards.length > 1) {
    // 队列读数与「这一套有几枚」必须是同一个判据（submitTargets）：说 3 枚就得真在 manifest 里
    // 写 3 条、真发 3 个 file part、签名真按 3 枚算 —— 差一枚就是界面在骗人。
    const n = submitTargets().length;
    items.push({
      ok: true,
      shown: n > 0,
      text: n
        ? `队列里本次要上传 ${n} 枚 —— 一整套一次提交：签名改一次、只提交一次`
        : "队列里没有要上传的枚：都被已收录那一档摘出去了，或者已经传完",
    });
  }
  return items;
}

/** 点名的时候要说得出是哪一枚 —— 卡上填的那个 id，没解析出来就用文件名。 */
function namesOf(cards) {
  return cards
    .map((c) => {
      const v = cardValues(c);
      return v.id || (c.file ? c.file.name : c.key);
    })
    .join("、");
}

function totalBytes(cards) {
  return cards.reduce((n, c) => n + (c.file ? Number(c.file.size) || 0 : 0), 0);
}

/** 超出后端自报的枚数上限时返回那个上限，否则 null（没自报 == 不判，而不是判成一个猜的数）。 */
function overModuleCount(n) {
  const max = state.limits.maxModules;
  return max !== null && n > max ? max : null;
}

/** 超出后端自报的整套上限时返回那个上限，否则 null。 */
function overTotalBytes(cards) {
  const max = state.limits.maxTotalBytes;
  if (max === null) return null;
  return totalBytes(cards) > max ? max : null;
}

function refreshGate() {
  const list = $("#gate");
  const items = gateItems();
  list.textContent = "";
  for (const item of items) {
    // 三档而不是两档：note 那一格不拦提交（它的 ok 为真），但画成 ✓ 就成了「这一项通过了」，
    // 而它讲的是「有一枚被摘出去了」。
    const cls = item.note ? "note" : item.ok ? "pass" : "";
    const li = node("li", cls, item.text);
    list.append(li);
  }
  const ready = items.every((i) => i.ok);
  $$("[data-open-confirm]").forEach((btn) => (btn.disabled = !ready));
  const firstBad = items.find((i) => !i.ok);
  // 底栏那句「全部就绪」必须是真话。清单里那条签名行自己不拦人（ok 为真、按钮照常亮），
  // 但屏幕上还没有一串可抄进签名的东西 —— 这时候说就绪就是把假话写在了最显眼的地方。
  // 所以这里排在 firstBad 之后、成功语之前插一段「还差什么」，enable 条件一个字没动。
  const firstNotShown = firstBad ? null : items.find((i) => i.ok && i.shown === false);
  const blocking = firstBad || firstNotShown;
  $("#dock-t").textContent = blocking ? blocking.text : "全部就绪，可以确认";
  $("#dock-s").textContent = blocking ? "还差这一步" : "点「去确认」勾一下";
  $("#gate-note").textContent = ready && !firstNotShown ? "上传前确认还没勾" : "先把上面几项填齐";
  if (state.attempted) paintFieldErrors();
  // 身份页那颗「验证并继续」的亮灭与这一处同一口感：都是「还差什么」——
  // 所以挂在 refreshGate 尾巴上，凡是会改这些输入的地方都不必各自记得再叫一次。
  renderIdentityGate();
}

const FIELD_MSGS = {
  versionCode: (v) => (v ? "必须是整数" : "请填写版本号（整数，来自 module.prop）"),
  coolapkUid: (v) => (v ? "UID 应是 4-12 位纯数字，不带 https 和 /" : "请填写你的酷安 UID"),
  source: (v) =>
    v ? "必须是酷安站内链接，如 https://www.coolapk.com/feed/65432100" : "请填写模块出处",
  uploader: (v) => (v ? "" : "这一项没取到昵称，请自己填一个署名"),
  id: (v) => (v ? "" : "请填写模块 ID"),
  name: (v) => (v ? "" : "请填写模块名称"),
  version: (v) => (v ? "" : "请填写版本字符串"),
};

function paintFieldErrors() {
  for (const key of REQUIRED_KEYS) {
    const el = fieldEls[key];
    if (!el) continue;
    const field = el.closest(".field");
    const value = el.value.trim();
    let bad = !value;
    if (value && key === "versionCode") bad = !/^\d+$/.test(value);
    if (value && key === "coolapkUid") bad = !isCoolapkUid(value);
    if (value && key === "source") bad = !normalizeCoolapkUrl(value);
    field.classList.toggle("is-bad", bad);
    const err = field.querySelector(`[data-err="${key}"]`);
    // 只换文案，可见性交给 .field.is-bad 的 CSS：内联 display 会把这套规则盖掉
    if (err && FIELD_MSGS[key]) err.textContent = FIELD_MSGS[key](value);
  }
}

/* ------------------------------------------------------ 酷安 UID 核实状态 */

function showUid(tone, chip, title, desc, avatar) {
  const box = $("#uid-check");
  box.hidden = false;
  box.className = `status${tone === "ok" ? " status--ok" : tone === "warn" ? " status--warn" : ""}`;
  // 核实通过那一下给勾号描边与头像淡入一个触发点：动画全在 CSS 里（.status.is-verified），
  // 这里只负责把类加上/摘掉 —— 别的档位（含 checking 重查）必须摘掉，否则上一次的勾还留着。
  box.classList.toggle("is-verified", tone === "ok");
  const chipEl = $("#uid-chip");
  chipEl.textContent = chip;
  chipEl.className = `chip${tone === "bad" ? " chip--bad" : tone === "ok" ? " chip--ok" : tone === "warn" ? " chip--warn" : tone === "idle" ? " chip--idle" : ""}`;
  const img = $("#uid-avatar");
  if (avatar) {
    img.src = secureAvatarUrl(avatar);
    img.hidden = false;
    // 头像的淡入也挂在同一个判据上（.uid__avatar.is-verified），两处必须同步：
    // 勾号动、头像不动就是「验过了但没验过」两种说法。
    img.classList.toggle("is-verified", tone === "ok");
    img.addEventListener(
      "error",
      () => {
        img.hidden = true;
      },
      { once: true }
    );
  } else {
    img.hidden = true;
    img.classList.remove("is-verified");
    img.removeAttribute("src");
  }
  $("#uid-t").textContent = title;
  $("#uid-d").textContent = desc;
}

// 昵称不是要填的字段，是按 UID 反查回来的结果，所以整行默认藏起来：取到了才出现、只读显示，
// 想改署名只能改 UID —— 这样「UID 是 A、署名写 B」这种组合根本进不了索引。
// 只有一种情况例外：这次没取到昵称。Worker 那边 uploader 空着直接 400，而酷安抖动、核实被运维
// 关掉都不该把真人挡在上传之外，所以这时把同一行放开成可填，并写明是哪一种原因 ——
// 能被任何人复核的锚点从来是 UID，不是这个随便能起的昵称。
const UPLOADER_FALLBACK = {
  not_found: "这个 UID 在酷安查不到，所以取不到昵称。改对 UID 会自动带出；急着提交也可以先自己填一个署名。",
  unavailable: "这次没从酷安取到昵称（接口没响应或被风控）。先自己填一个 —— 出问题时按「你自己报的」处理。",
  self_reported: "后端当前没有核实这个 UID，昵称取不到。先自己填一个 —— 它会按「你自己报的」处理。",
  off: "后端还没接核实，昵称取不到。先自己填一个 —— 它会按「你自己报的」处理。",
};

function syncUploaderField() {
  const el = fieldEls.uploader;
  if (!el) return;
  const field = el.closest(".field");
  const row = $("#nick-field");
  const tag = $("#uploader-tag");
  const help = $("#uploader-help");
  // 只认「输入框里这串 UID」反查回来的昵称 —— verified 的结果可能属于上一串数字。
  const nickname =
    state.uidStatus === "verified" &&
    state.uidInfo &&
    state.uidInfo.uid === fieldValue("coolapkUid")
      ? state.uidInfo.nickname
      : "";
  // UID 刚改过、debounce 还没把核实跑完：这时说「需要你填」是假的，正在重查。
  const rechecking = state.uidStatus === "verified" && !nickname;

  if (nickname) {
    el.value = nickname; // 以反查结果为准
    el.dataset.auto = "1";
    el.readOnly = true;
    field.classList.add("is-pre");
    if (row) row.hidden = false;
    if (tag) tag.textContent = "已按 UID 取到";
    if (help) help.textContent = "已从酷安取回这个 UID 对应的昵称并锁定 —— 想改署名，只能改 UID。";
    return;
  }

  el.readOnly = false;
  field.classList.remove("is-pre");
  // 只要现在没有反查到的昵称，上一个 UID 带出来的那份就必须消失 —— 放在藏行之前，
  // 因为「正在查」的时候也能提交（核实没接 / 酷安抖动都不该拦人），清空晚一步就漏进索引。手填的不动。
  if (el.dataset.auto === "1") {
    el.value = "";
    delete el.dataset.auto;
  }
  // 还没填 / 正在查 / 形状不对：这一行没有可说的，别占位
  if (state.uidStatus === "idle" || state.uidStatus === "checking" || state.uidStatus === "invalid") {
    if (row) row.hidden = true;
    return;
  }
  if (row) row.hidden = false;
  if (tag) tag.textContent = rechecking ? "正在按新 UID 重查" : "需要你填";
  if (help)
    help.textContent = rechecking
      ? "UID 改过了，上一个 UID 的昵称不能沿用 —— 等新结果回来。"
      : UPLOADER_FALLBACK[state.uidStatus] || "这次没从酷安取到昵称，请自己填一个署名。";
}

/**
 * 这一套的签名来源：每一枚的 (模块 ID, 整包 sha256)，加那一枚共用的一次性随机段。
 * 被 recorded 摘出去的、以及这一次已经提交掉的那些都不在这里：它们不进 manifest，
 * 让它们留在集合里等于骗人抄一串永远用不上的字符 —— 而 v2 那一串绑的就是「这套的全集」，
 * 多一枚、少一枚算出来的都是另一个前缀（§15）。
 * 当前卡读视图（用户刚敲的那一下就是它的值），其余读它自己那张卡的快照。
 */
function proofTargets() {
  const out = [];
  const cur = activeCard();
  for (const card of submitTargets()) {
    const live = card === cur;
    const id = live ? fieldValue("id") : cardValues(card).id;
    const zipSha = live ? state.zipSha : card.zipSha;
    out.push({ card, id, zipSha, live });
  }
  return out;
}

/** 这一套现在能不能算出签名：每一枚都得有 id 与整包哈希，少一枚都算不出那一串。 */
function setSources() {
  const targets = proofTargets();
  return {
    targets,
    items: targets.map((t) => ({ id: t.id, zipSha: t.zipSha })),
    incomplete: targets.filter((t) => !t.id || !SHA256_HEX_RE.test(String(t.zipSha || ""))),
    nonce: state.nonce,
  };
}

// 派生显示：签名 = sha256("sukisu-proof-v2:" + 规范串) 前 12 位 + "-" + 那一枚随机段，
// 每次都在这里现算整套的来源，屏幕上那一串永远跟着队列里当前这几枚的 id 与字节走 ——
// 缓存派生值迟早和来源脱钩，而「换了包还拿着旧签名抄」正是这条闸要封死的那件事。
// v2 的规范串按 **id 升序（同 id 再按整包哈希升序）**排，与用户选的次序无关（§15）：
// 前端按选的次序、Worker 按 multipart 到达的次序，两边不同序就会算出两个前缀，
// 而「对不上」在那条闸里读起来跟「你不是本人」一模一样。
async function renderProof() {
  const box = $("#proof-field");
  const id = fieldValue("id");
  const zipSha = state.zipSha;
  const nonce = state.nonce;
  const set = setSources();
  // 走长效会话的那一次上传不需要改签名 —— 这一整格收起（连同它上面那句「去酷安改签名」）。
  // 判据与核实那一步同一份：会话属于输入框里这串 UID，就别让人白抄一次签名。
  if (sessionFor(fieldValue("coolapkUid"))) {
    box.hidden = true;
    $("#proof-cap").textContent = "";
    $("#proof-list").textContent = "";
    return;
  }
  if (!nonce || !set.targets.length) {
    // 随机段来自 UID 核实，没有它就没有任何一串；整套是空的也没有可绑的东西。整格收起。
    box.hidden = true;
    $("#proof-cap").textContent = "";
    return;
  }
  if (!id || !zipSha) {
    // 当前卡这两个来源少任何一个，就没有属于这一枚的那一份 ⇒ 那一串算不出来。
    // （别的枚齐不齐不影响这一句：签名绑的是全集，少一枚就没有串。）
    if (!set.items.length) {
      box.hidden = true;
      $("#proof-cap").textContent = "";
      return;
    }
  }
  // 来源一动就得当场把那一行抹掉，不等下面 await 回来换串 ——
  // 那几十毫秒里屏幕上挂着一串属于上一个 id / 上一个包的签名，正是这条闸要封死的那件事。
  killStaleProofRows();
  let text = "";
  let bad = "";
  if (set.incomplete.length) {
    // 这一套还没齐：不拿「齐了的那几枚」算一串出来 —— 那一串对不上将要提交的那一套，
    // 用户抄进签名就是白改一次签名，而且提交会撞 sha/集合对不上。
    text = "";
    bad = `这套里还差 ${set.incomplete.length} 枚的模块 ID 或整包哈希（${namesOf(set.incomplete.map((t) => t.card))}）`;
  } else {
    try {
      text = await buildProofStringV2(set.items, nonce);
    } catch (err) {
      // canonicalProofSet 那三条拒绝（空集 / 形状不对的 sha / 同 id 两次）都是客户端可控的输入，
      // 不是内部不可能状态：这里必须把它显示成一句人话，而不是让那一串停在旧值上。
      bad = `这一套现在算不出签名：${(err && err.message) || "集合形状不对"}`;
    }
  }
  // 来源在 await 期间动过都不许贴这一串：连打 id / 连着换包时先发的请求可能后到，
  // 而失败换串（showFailure 里那次重掷）也可能正好落在等待中间（runUidCheck 里同一类竞态踩过一次）。
  const now = setSources();
  if (
    state.nonce !== nonce ||
    now.targets.length !== set.targets.length ||
    now.items.some((it, i) => !set.items[i] || it.id !== set.items[i].id || it.zipSha !== set.items[i].zipSha)
  ) {
    return;
  }
  paintProofs(now, text, bad);
}

/** 那一行记住自己是按哪一套算的：整套的规范串 + 随机段。这两个东西一换，那一行就当场死。 */
function proofSrc(canonical, nonce) {
  return `${canonical}\u0000${nonce}`;
}

function setFingerprint(items, nonce) {
  try {
    return proofSrc(canonicalProofSet(items), nonce);
  } catch {
    // 形状不对时没有「规范串」可记 —— 用不可能等于任何合法来源串的那个值，
    // 于是那一行一定被抹掉，屏幕上不会留一串属于别的集合的签名。
    return "\u0000invalid\u0000";
  }
}

/**
 * 那一行按 data-src 记住自己是按哪一套算出来的；来源一换，那一行当场消失，不等下一次渲染。
 * 被摘出去的枚、已经提交掉的那一套同样在这里当场没 —— 集合一变就是另一串，屏幕上不许留上一串。
 */
function killStaleProofRows() {
  const list = $("#proof-list");
  const set = setSources();
  const src = set.incomplete.length ? "\u0000invalid\u0000" : setFingerprint(set.items, state.nonce);
  for (const row of Array.from(list.children)) {
    if (String(row.dataset.src || "") !== src) row.remove();
  }
}

function paintProofs(set, text, bad) {
  const list = $("#proof-list");
  const box = $("#proof-field");
  list.textContent = "";

  const row = node("div", "proof");
  row.dataset.src = text ? setFingerprint(set.items, state.nonce) : "\u0000invalid\u0000";
  if (text) {
    const code = node("code", "mono proof__txt", text);
    row.append(code);
    const copy = node("button", "btn btn--ghost btn--sm proof__copy", "复制这一串");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        copy.textContent = "已复制";
      } catch {
        copy.textContent = "浏览器不让复制，请自己选中";
      }
      setTimeout(() => (copy.textContent = "复制这一串"), 1500);
    });
    row.append(copy);
  } else {
    row.append(node("span", "proof__pending", bad || "这一套现在还算不出签名。"));
  }
  list.append(row);

  // 签名绑的是这一套的全集 ⇒ 必须把这 N 枚点名出来，否则「这一串顶的是哪几枚」没人知道，
  // 而摘进/摘出一枚就会悄悄换掉屏幕上这一串。
  const roster = node("div", "proof__set");
  roster.append(node("span", "proof__set-k", `这一串绑的是这套 ${set.targets.length} 枚`));
  for (const t of set.targets) {
    roster.append(node("span", "proof__m", t.id || (t.card.file ? t.card.file.name : "（没 ID）")));
  }
  const rec = state.cards.filter((c) => isRecorded(c));
  if (rec.length) roster.append(node("span", "proof__out", `不含：${namesOf(rec)}`));
  list.append(roster);

  const cap = $("#proof-cap");
  // 容量这一格说现行的事实：一串 19 字符、覆盖整套、与枚数无关（§15 第 4 条把前缀从 8 位扩到 12 位
  // 正是为了这个）。旧那份「一次大约放 3 条、改一次投一枚」的读数是 v1 的账，已经作废 ——
  // 留着它就是让界面在用户已经不需要改 N 次签名的时候继续骗他改 N 次。
  cap.textContent =
    `这一串 ${text.length || 19} 个字符，覆盖本次这一整套（${set.targets.length} 枚），酷安签名上限实测 60 个字符 —— ` +
    "只改一次签名、一次提交整套。它绑的是这套的全集：增删任一枚、改任一枚的模块 ID、给任一枚重选包，" +
    "这一串就变成另一串，要重新抄进签名并保存；签名里还是旧的那串时，服务端会按「签名里没有本次签名」拒。";
  box.hidden = false;
}

/* ------------------------------------------------- 长效会话（90 天免改签名） */

/**
 * 会话令牌 = 「这个账号已经证明过自己是这个 UID」的一张凭据。
 * 有它的时候，核实那一步不用再打酷安、随机段也不用再发 —— 于是这一次上传根本不需要
 * 让人去改酷安签名。它不替代签名（签名那一串仍然照算照显示），只是把「还要不要改签名」
 * 这一个问题的答案换成「不用」。
 *
 * 三处判据只有一份：state.session.uid === 输入框里那串 UID。别的地方一律读这个判断，
 * 不许各自 `state.session && ...` 半句话 —— 那迟早会漂成「核实说不用、签名那格说要改」。
 */
const SESSION_KEY = "sukisu-session";

/** 会话属于现在输入框里这串 UID 吗。空会话、空输入都算「不属于」。 */
function sessionFor(uid) {
  return Boolean(state.session && uid && state.session.uid === uid);
}

function loadSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const obj = JSON.parse(raw);
    const token = obj && typeof obj.token === "string" ? obj.token : "";
    if (!/^[0-9a-f]{64}$/.test(token)) return null;
    const expiresAt = Number(obj.expiresAt) || 0;
    // 本地就能判过期：过了期还留着它，页面会先说「90 天内免改签名」再被后端打回来一次。
    if (expiresAt && expiresAt <= Date.now()) return null;
    return { token, expiresAt };
  } catch {
    // localStorage 被禁（隐私模式）/ 存进去的不是 JSON —— 都按「没有会话」处理，别让它把首屏搞崩。
    return null;
  }
}

function saveSession(s) {
  if (!s || !s.token) return;
  try {
    localStorage.setItem(SESSION_KEY, JSON.stringify({ token: s.token, expiresAt: Number(s.expiresAt) || 0 }));
  } catch {
    // 存不进去只是「下次还得改签名」，不该报错给用户看。
  }
}

/**
 * 收下「这一次提交」带回来的会话令牌。
 *
 * 只在提交成功那一支调：那一支的应答是 `{ ok, pr, modules, session? }`。没有 session 键
 * （后端还没上线这一档、或这一档按策略没发）就什么都不做 —— 页面照旧「每次都要改签名」，
 * 这不是失败，是今天的正常形态。
 *
 * uid / nickname 不从令牌里读：令牌只是一串随机数，后端认回来的是它记着的那个人；
 * 这里填的是**这一次提交用的**那两样（输入框里的 UID 与昵称），与令牌一一对应。
 */
function adoptSession(res) {
  const s = res && res.session;
  if (!s || typeof s.token !== "string" || !/^[0-9a-f]{64}$/.test(s.token)) return;
  const uid = fieldValue("coolapkUid");
  if (!uid) return;
  state.session = {
    token: s.token,
    uid,
    nickname: fieldValue("uploader") || (state.uidInfo && state.uidInfo.nickname) || "",
    avatar: (state.uidInfo && state.uidInfo.avatar) || "",
    expiresAt: Number(s.expiresAt) || 0,
  };
  // 后端刚给了令牌 = 这一刻起这趟浏览器算「已验证」，闸要跟着开（否则下次刷新还会被送回来）。
  state.auth = "in";
  saveSession(state.session);
  paintSession();
  // 会话一到手，「我的模块」当场可以问了 —— 刚提交成功的人正是最想看见自己那几枚的人。
  loadMine();
  // 会话一到手，签名那一格当场收起（renderProof 的判据就是 sessionFor），清单也要跟着改口。
  renderProof();
  refreshGate();
}

function clearSession() {
  state.session = null;
  // 清单一并作废：它属于刚才那串令牌。留着的话，下一个人验证完会在 paintMine 之前
  // 先看见上一个人的模块 —— asked 为空正好让 loadMine 重问一次。
  state.mine = { asked: "", rows: [], degraded: false, loading: false };
  try {
    localStorage.removeItem(SESSION_KEY);
  } catch {
    // 同上：清不掉本地那份也只是下次多改一次签名。
  }
}

/* ---------------------------------------------------- 顶栏：那个人与他的菜单 */

/**
 * 顶栏右上角那一个人：验证过之后露出头像 + 昵称，点开是「上传记录 / 退出」。
 *
 * 读的是 state.session，不是输入框里那串 UID：这个控件回答的是「这张浏览器上现在是谁」，
 * 而身份页那一格输入框是**草稿** —— 让草稿决定顶栏显示谁，一改输入框头像就跟着换人。
 */
function paintWho() {
  const box = $("#who");
  if (!box) return;
  const s = state.session;
  // pending 时不露：此刻还不知道这串令牌算不算数，先露头像等于替后端答应了。
  const on = state.auth === "in" && Boolean(s && s.token);
  box.hidden = !on;
  if (!on) {
    closeWhoMenu();
    return;
  }
  const mono = $("#who-mono");
  if (mono) mono.textContent = (s.nickname || s.uid || "?").trim().slice(0, 1).toUpperCase();
  const name = $("#who-name");
  if (name) name.textContent = s.nickname || (s.uid ? `UID ${s.uid}` : "已验证");
  const avatar = $("#who-avatar");
  const src = secureAvatarUrl(s.avatar || "");
  if (avatar) {
    if (src) {
      avatar.hidden = false;
      if (avatar.getAttribute("src") !== src) avatar.setAttribute("src", src);
      // 头像取自酷安那边，跨域加载失败是常态之一：退回「首字」那一枚，别留一个破图标。
      avatar.onerror = () => {
        avatar.hidden = true;
        if (mono) mono.hidden = false;
      };
      if (mono) mono.hidden = true;
    } else {
      avatar.hidden = true;
      if (mono) mono.hidden = false;
    }
  }
  const btn = $("#who-btn");
  if (btn) btn.setAttribute("aria-label", `已登录：${s.nickname || s.uid || "已验证"}，打开菜单`);
}

function closeWhoMenu() {
  const menu = $("#who-menu");
  const btn = $("#who-btn");
  if (menu) menu.hidden = true;
  if (btn) btn.setAttribute("aria-expanded", "false");
}

function toggleWhoMenu(open) {
  const menu = $("#who-menu");
  const btn = $("#who-btn");
  if (!menu) return;
  const want = open === undefined ? menu.hidden : Boolean(open);
  menu.hidden = !want;
  if (btn) btn.setAttribute("aria-expanded", want ? "true" : "false");
  if (want) {
    const first = menu.querySelector(".who__item");
    if (first) first.focus();
  }
}

/** 菜单是浮层：点外面 / 按 Esc 都得收起来，否则它会一直压着下面的按钮。 */
function bindWho() {
  const btn = $("#who-btn");
  if (btn) {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleWhoMenu();
    });
  }
  document.addEventListener("click", (e) => {
    const box = $("#who");
    if (box && !box.hidden && !box.contains(e.target)) closeWhoMenu();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    const menu = $("#who-menu");
    if (!menu || menu.hidden) return;
    closeWhoMenu();
    const b = $("#who-btn");
    if (b) b.focus();
  });
  // 「上传记录」点了就收起浮层（跳转本身由 hash 完成）。
  const records = $("#who-records");
  if (records) records.addEventListener("click", () => closeWhoMenu());
}

/** 身份闸的加载态：pending 时把上传表单整个藏起来，只留那一行字。 */
function paintAuth() {
  const pending = state.auth === "pending";
  const form = $("#form");
  if (form) form.hidden = pending;
  const wait = $("#auth-wait");
  if (wait) wait.hidden = !pending;
}

/** 会话条：只在真有会话、且它属于输入框里这串 UID 时出现。 */
function paintSession() {
  const bar = $("#session-bar");
  const uid = fieldValue("coolapkUid");
  const on = sessionFor(uid);
  if (bar) {
    bar.hidden = !on;
    if (on) {
      const t = $("#session-t");
      const d = $("#session-d");
      if (t) t.textContent = `已验证：${state.session.nickname || uid}`;
      if (d) d.textContent = "90 天内再投稿不用改签名。换账号请点「退出」。";
    }
  }
  paintWho();
}

/**
 * 页面启动时问一次：本地那串令牌还有效吗。
 *
 * 这个函数**不抛错**（checkSession 已经把网络/超时/非 JSON 都归到 ok:false）：
 * 后端抖一下就抛，等于让一次与用户无关的刷新把整个上传页按成红的 ——
 * 失效方向必须是「按没会话处理」，多抄一次签名只是麻烦，把能用的页面报成坏的是骗人。
 *
 * 但「这一次按没会话处理」与「把令牌销毁」是两件事。checkSession 的 transient 档说的就是
 * 前一种：断网、超时、5xx、读不懂的应答 —— 那一次只是没问到答案，令牌本身可能好得很。
 * 只有非 transient（服务端明确说这串不能用）才 clearSession；transient 时只把会话条藏起来，
 * localStorage 里那份原封不动留着，等下一次刷新再问。
 */
async function refreshSession() {
  const saved = loadSession();
  if (!saved) {
    // 本地没有可用的串（没有 / 形状不对 / 已过期）：直接判「没验证」，闸会把上传页送去身份页。
    state.auth = "out";
    paintSession();
    paintMine();
    renderRoute();
    return;
  }
  const res = await checkSession(saved.token);
  if (!res || !res.ok) {
    // 「问不到答案」那一档（断网 / 超时 / 5xx / 非 JSON）与「服务端看了并拒了」必须分开：
    // 前者一次抖动就销毁 90 天令牌，比让用户多改一次签名贵得多。
    const transient = Boolean(res && res.transient);
    // 只有服务端明确说了「不认这串」才清本地 —— 这一行的形状被 selftest 钉住，别拆成块。
    if (!res || !res.transient) clearSession();
    if (transient) {
      // 按「还是已登录」撑住：uid / 昵称 / 头像这一档拿不到，先按本地那串把闸撑起来。
      state.session = {
        token: saved.token,
        uid: "",
        nickname: "",
        avatar: "",
        level: null,
        expiresAt: saved.expiresAt,
      };
      state.auth = "in";
    } else {
      // 服务端看了这串并拒了：判「没验证」，地址由闸收敛到身份页。
      state.auth = "out";
    }
    paintSession();
    paintMine();
    refreshGate();
    renderRoute();
    return;
  }
  state.auth = "in";
  state.session = {
    token: saved.token,
    uid: res.uid ? String(res.uid) : "",
    nickname: res.nickname || "",
    avatar: res.avatar || "",
    level: res.level,
    expiresAt: res.expiresAt || saved.expiresAt,
  };
  // 把 UID 填进表单并派发 input：核实那一步会走 session 那条近路（见 runUidCheck），
  // 也就是「一次上传一份署名」那两格仍然有值可读 —— 提交载荷里的 coolapkUid 就是它。
  const el = fieldEls.coolapkUid;
  if (el && state.session.uid && !el.value.trim()) {
    el.value = state.session.uid;
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }
  paintSession();
  refreshGate();
  // 已经有会话了：身份页不必再看（renderRoute 会把 #/identity 收敛到 #/submit）。
  renderRoute();
  // 令牌刚被后端认下来：顺手把「我的模块」问一次（同一串令牌只问一次，见 loadMine）。
  // 不 await —— 这一格是便利，它慢不该让会话条的刷新跟着慢。
  loadMine();
}

/**
 * 退出验证：注销令牌（幂等，失败也照样清本地）+ 把 UID 一起清掉，回到「每次改签名」那一档。
 *
 * 判「退出成功」不认网络：令牌注销那一发只是让服务端也忘掉这串，退不出去也要退 ——
 * 本地那份留着才是真问题（下次刷新又会自称「已验证」，而顶栏还会挂着别人的昵称）。
 */
async function logout() {
  const token = state.session ? state.session.token : "";
  if (token) {
    try {
      await revokeSession(token);
    } catch {
      // 注销失败照样往下走：本地这份必须清掉，见上面的注释。
    }
  }
  clearSession();
  state.auth = "out";
  state.idError = "";
  const el = fieldEls.coolapkUid;
  if (el) {
    el.value = "";
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }
  closeWhoMenu();
  paintSession();
  // 退出验证 = 换人：确认层那一枚勾是上一个人点过的，跟着一起复原，
  // 别让下一个人一进确认层就看见「我已知晓」已经勾好（openConfirm 故意不清零，见那里的注释）。
  const ack = $("#ck-confirm");
  if (ack) ack.checked = false;
  const goBtn = $("#confirm-go");
  if (goBtn) goBtn.disabled = true;
  // 立刻收起来，不等 runUidCheck 那 500ms 的防抖 —— 退出验证之后还挂着自己的模块清单，
  // 是那种「看起来已经退出了其实没有」的界面。
  paintMine();
  renderProof();
  refreshGate();
  // 地址先落地再画：闸看到 auth=out 会把 #/submit 与 #/records 都收敛到身份页。
  if (location.hash !== "#/identity") history.replaceState(null, "", "#/identity");
  renderRoute();
}

function bindSession() {
  const forget = $("#session-forget");
  if (!forget) return;
  forget.addEventListener("click", async () => {
    forget.disabled = true;
    try {
      await logout();
    } finally {
      forget.disabled = false;
    }
  });
}

/* ------------------------------------------------- 我的模块（GET /mine，契约 §4.2） */

/**
 * 这一格是**便利**，不是闸 —— 这条原则决定了下面每一处「出错怎么办」：
 * 读不到索引（degraded）、令牌失效、清单为空，全都只是「这一格没东西可看」，
 * 绝不许弹错、绝不许挡住首投。首投的人根本不该知道这里有这么一格。
 *
 * 反过来，只要后端说了话就照实说：degraded 时清单可能不全，这一句必须写出来 ——
 * 「你确实没有模块」与「这次没读到索引」是两件完全不同的事，混成一句就是拿一次索引抖动
 * 去骗用户说他没投过东西。
 */
function paintMine() {
  // 记录页那一格空态跟着这一条线走：清单的三种「没东西」由它说清，别处不再各判一次。
  paintRecords();
  const bar = $("#mine-bar");
  if (!bar) return;
  const uid = fieldValue("coolapkUid");
  const mine = state.mine;
  // 会话成立（属于输入框这个人）才有资格看这一格；loading 时也先占位，避免闪一下才出现。
  const show = sessionFor(uid) && (mine.loading || mine.rows.length > 0 || mine.degraded);
  if (!show) {
    bar.hidden = true;
    // 藏起来也要把内容清掉：退出验证之后 state.mine 已经重置，DOM 里却还留着上一个人的模块名。
    // 现在它们是 hidden 的，但任何一处「只切 hidden」的将来改动都会把别人的清单露出来 —— 不留这个雷。
    const stale = $("#mine-list");
    if (stale) stale.textContent = "";
    const staleNote = $("#mine-note");
    if (staleNote) staleNote.textContent = "";
    const staleN = $("#mine-n");
    if (staleN) staleN.textContent = "";
    return;
  }
  bar.hidden = false;
  const n = $("#mine-n");
  if (n) n.textContent = mine.loading ? "正在读…" : mine.rows.length ? `${mine.rows.length} 枚已收录` : "";
  const list = $("#mine-list");
  if (list) {
    list.textContent = "";
    for (const row of mine.rows) list.append(mineRow(row));
  }
  const note = $("#mine-note");
  if (note) {
    if (mine.loading) note.textContent = "";
    else if (mine.degraded) note.textContent = "这次没读到公开索引，清单可能不全 —— 不影响你继续上传。";
    else if (mine.rows.length)
      note.textContent =
        "点「上传更新版」会把 ID / 名称 / 作者 / 出处填好、版本号预填成当前值 +1，接着让你选包。";
    else note.textContent = "";
  }
}

function mineRow(row) {
  const li = node("li", "mine__row");
  const head = node("div", "mine__head");
  head.append(node("span", "mine__id", row.id));
  // 模块名是记录页最想先看到的那一格：没有它，一行「abcdef12」认不出是哪一枚。
  if (row.name) head.append(node("span", "mine__name", row.name));
  li.append(head);
  const bits = [];
  bits.push(
    row.version ? `当前收录 v${row.version}${row.versionCode ? `（code ${row.versionCode}）` : ""}` : "当前收录版本未知"
  );
  // 历史版本与提交时间、PR 链接后端今天都还没回 —— 有就显示，没有就一个字都不编。
  if (Array.isArray(row.versions) && row.versions.length) bits.push(`投过的版本 ${row.versions.join(" / ")}`);
  if (row.submittedAt) bits.push(`最近提交 ${row.submittedAt}`);
  li.append(node("span", "mine__meta", bits.join(" · ")));
  const pr = row.pr ? safeUrl(row.pr) : "";
  if (pr) {
    const link = node("a", "mine__link", "看这次 PR");
    link.href = pr;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    li.append(link);
  }
  const go = node("button", "mine__go", "上传更新版");
  go.type = "button";
  go.setAttribute("aria-label", `给 ${row.id} 上传更新版`);
  go.addEventListener("click", () => {
    // 复用上传页那条「为已收录模块挑新版」的路：ID / 名称 / 作者 / 出处预填、版本号 +1。
    prefillFromMine(row);
    if (location.hash !== "#/submit") history.replaceState(null, "", "#/submit");
    renderRoute();
  });
  li.append(go);
  return li;
}

/**
 * 去问一次清单。同一串令牌只问一次：refreshSession 与提交成功都会叫到这里，
 * 每次都问等于每回一次页面就打一次网络。`asked` 记的是**哪一串令牌**问过，
 * 不是「问过没有」—— 换号换令牌之后必须重问，否则会把上一个人的清单摆给下一个人看。
 */
async function loadMine() {
  const token = state.session ? state.session.token : "";
  if (!token) {
    state.mine = { asked: "", rows: [], degraded: false, loading: false };
    paintMine();
    return;
  }
  if (state.mine.asked === token) {
    paintMine();
    return;
  }
  state.mine.asked = token;
  state.mine.loading = true;
  paintMine();
  const res = await fetchMine(token);
  // 等回包期间会话被退出或换成了别人：这份清单不属于现在这个人，丢掉。
  if ((state.session ? state.session.token : "") !== token) return;
  state.mine.loading = false;
  if (!res || !res.ok) {
    // 静默降级：**不清**会话（那是 refreshSession 的判决，这里没有资格越权），
    // 也不弹错。清掉 asked 让下一次会话刷新还能再问一遍。
    state.mine.rows = [];
    state.mine.degraded = false;
    state.mine.asked = "";
    paintMine();
    return;
  }
  state.mine.rows = res.modules || [];
  state.mine.degraded = res.degraded === true;
  paintMine();
}

/**
 * 一键更新（契约 §4.3）：把已收录那一版的读数填成一张新卡。
 *
 * 三处留白都是有意的：
 * ① `version` 留空 —— 新版本串只能由作者写（`2.1.0`、`v2.1`、`2026.10.26` 都合法），
 *    替他猜一个等于替他发错版；
 * ② `versionCode` = 当前 +1 —— 这是唯一能算出来的一格；手改之后还有一道「必须更大」的拦（见 cardGaps）；
 * ③ `file` 留 null —— `submitTargets()` 的过滤式一个字没动，所以这张卡在选包之前
 *    根本不进提交集，签名也不会提前算出来。
 */
function prefillFromMine(row) {
  const base = Number(row.versionCode) || 0;
  const card = makeCard(null);
  card.fromMine = { id: row.id, version: row.version || "", versionCode: base };
  card.values = {
    ...emptyValues(),
    id: row.id,
    name: row.name || "",
    author: row.author || "",
    source: row.source || "",
    version: "",
    versionCode: base ? String(base + 1) : "",
  };
  state.cards.push(card);
  selectCardNow(card.key);
  renderQueue();
  // 就在这次点击里把选包对话框打开（同一个用户手势，浏览器不会拦）：
  // 「上传更新版」之后紧接着要做的唯一一件事就是选包，多一步点击只是多一次卡壳的机会。
  // 取消也不要紧 —— 卡留在队列里，之后点这一枚右边的 ↻ 还能把包选上。
  requestSwap(card);
}

/**
 * 「我的模块」里那几颗按钮是每次 paintMine 现建的，所以这里没有逐颗绑定的活；
 * 保留这个函数是为了让 init() 里那一串 bind 的形状一致 —— 也留一个将来接「刷新清单」的挂点。
 */
function bindMine() {
  const bar = $("#mine-bar");
  if (!bar) return;
  // 点这一格里的空白不该把焦点带跑（它是面板，不是链接）；键盘用户走 Tab 到按钮即可。
  bar.addEventListener("mousedown", (e) => {
    if (e.target === bar) e.preventDefault();
  });
}

/* -------------------------------------------------------- 身份验证（#/identity） */

/**
 * 本机那枚 secret 的存储键（契约 v2 §5）。它一经生成就不再变 —— 页面上没有换一串的入口了。
 *
 * 为什么非存下来不可：要填进酷安签名的承诺串是从 secret 现算的（commit = sha256(前缀+secret)
 * 前 24 位）。secret 一丢，commit 就变成另一串，用户得到酷安再改一次签名 —— 而我们承诺的是
 * 「验过之后 90 天内不用再碰签名」。存储只在这一台浏览器里，别处没有副本。
 * （清站点数据、换设备、换浏览器仍会换一串：那是本机凭据的边界，这一屏补不了，也不该假装能补。）
 */
const IDENTITY_SECRET_KEY = "sukisu.identity.secret";

function readIdentitySecret() {
  try {
    const saved = localStorage.getItem(IDENTITY_SECRET_KEY) || "";
    return /^[0-9a-f]{32}$/.test(saved) ? saved : "";
  } catch {
    return "";
  }
}

function saveIdentitySecret(secret) {
  try {
    localStorage.setItem(IDENTITY_SECRET_KEY, secret);
  } catch {
    // 无痕 / 存储被禁：这一串只活到这次刷新。承诺照样算得出、验证照样过，
    // 只是下次进来会换一串、得再去改一次签名 —— 那是浏览器的限制，不该把整页拦下来。
  }
}

/** 取本机这一串；没有或形状不对就现生成一枚并落盘。 */
function ensureIdentitySecret() {
  const saved = readIdentitySecret();
  if (saved) return saved;
  const fresh = identitySecret();
  saveIdentitySecret(fresh);
  return fresh;
}

/* -------------------------------------------------- 身份闸的两枚本地记忆（冷却 / 等级死局）

   两条键都落在本机 localStorage，键名写进自检钉子，改名等于把用户手里那一份锁丢掉：

   - sukisu.identity.cooldown     同一个指纹（uid + commit）连续失败后的截止时刻与失败次数
   - sukisu.identity.levelBlocked 「等级不足」这个死局记的那个 uid

   冷却为什么必须落盘：刷新一次页面就清零的话，这道门等于没有 —— 它挡的正是「拿同一对
   uid + 签名串每三秒撞一次后端」这种白烧额度的折腾法。而指纹里带上 commit 是故意的：
   换 uid 或换 secret 都是**另一个人/另一把钥匙**，不该被上一轮的失败连坐。 */
const IDENTITY_COOLDOWN_KEY = "sukisu.identity.cooldown";
const IDENTITY_LEVEL_BLOCKED_KEY = "sukisu.identity.levelBlocked";

/* 同一个指纹连续失败：第 1 次等 30s、第 2 次 60s、第 3 次 120s、之后 300s 封顶。
   成功一次就整段清掉（见 submitIdentity）。服务端那边自有限流，这一层只负责别让
   同一个人在同一个输入上连点 —— 所以它宁可短，不要长。 */
const IDENTITY_COOLDOWN_STEPS = [30, 60, 120, 300];

/**
 * 读回那一份冷却。形状不对一律当「没有」：这枚键躺在用户可编辑的 localStorage 里，
 * 一个手改出来的 until: "明天" 不该让这一屏永远点不动。
 */
function readIdentityCooldown() {
  try {
    const raw = localStorage.getItem(IDENTITY_COOLDOWN_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    const fp = typeof parsed.fp === "string" ? parsed.fp : "";
    const fails = Number(parsed.fails);
    const until = Number(parsed.until);
    if (!fp || !Number.isFinite(fails) || fails < 1 || !Number.isFinite(until)) return null;
    return { fp, fails, until };
  } catch {
    return null;
  }
}

/** 写回（传 null 就是清掉）。存储被禁时静默退化 —— 这一层是节流，不是安全边界。 */
function saveIdentityCooldown(cd) {
  try {
    if (cd) {
      localStorage.setItem(
        IDENTITY_COOLDOWN_KEY,
        JSON.stringify({ fp: cd.fp, fails: cd.fails, until: cd.until })
      );
    } else {
      localStorage.removeItem(IDENTITY_COOLDOWN_KEY);
    }
  } catch {
    // 无痕 / 存储被禁：退化成「每次都能点」。不该为了节流把整屏拦下来。
  }
}

/** 那一枚「等级不足」的 uid；空串 = 没有死局。 */
function readIdentityLevelBlocked() {
  try {
    return localStorage.getItem(IDENTITY_LEVEL_BLOCKED_KEY) || "";
  } catch {
    return "";
  }
}

function markIdentityLevelBlocked(uid) {
  try {
    localStorage.setItem(IDENTITY_LEVEL_BLOCKED_KEY, uid);
  } catch {
    // 同上：存不下就只在这次刷新里生效。
  }
}

function clearIdentityLevelBlocked() {
  try {
    localStorage.removeItem(IDENTITY_LEVEL_BLOCKED_KEY);
  } catch {
    // 同上。
  }
}

/**
 * 指纹 = uid + ":" + commit。commit 还没算出来时返回空串 —— 那不是「不在冷却里」，
 * 而是「现在还判不了」：真正的判据在 submitIdentity 里现算一次（那里 wait 秒数就是真的）。
 *
 * 分隔符用 ":" 是因为左半边恒为纯数字、右半边恒为小写十六进制，拼起来不可能撞车。
 */
function identityFingerprint(uid, commit) {
  const u = uid === undefined ? fieldValue("coolapkUid") : uid;
  const c = commit === undefined ? state.idCommit : commit;
  return u && c ? `${u}:${c}` : "";
}

/** 这个指纹还剩几秒冷却（0 = 没有冷却 / 已经过了）。 */
function identityCooldownRemaining(fp) {
  if (!fp) return 0;
  const cd = readIdentityCooldown();
  if (!cd || cd.fp !== fp) return 0;
  const left = Math.ceil((cd.until - Date.now()) / 1000);
  return left > 0 ? left : 0;
}

/**
 * 记一次失败并给出这一轮的冷却秒数；同一个指纹第 N 次失败 ⇒ STEPS[N-1] 秒（末档封顶）。
 *
 * 「连续」的意思是：成功一次才清零。冷却过了但没成功，下一次失败仍按下一档算 ——
 * 否则每过 30 秒就又能白撞一次，档位永远停在第一档。
 */
function countIdentityFailure(fp) {
  if (!fp) return 0;
  const prev = readIdentityCooldown();
  const fails = (prev && prev.fp === fp ? prev.fails : 0) + 1;
  const secs = IDENTITY_COOLDOWN_STEPS[Math.min(fails, IDENTITY_COOLDOWN_STEPS.length) - 1];
  saveIdentityCooldown({ fp, fails, until: Date.now() + secs * 1000 });
  return secs;
}

/**
 * 指纹变了（改了 uid 或换了 secret）就把上一轮的失败计数与冷却一起丢掉：那把锁锁的是
 * 另一个输入，不该连坐到眼前这个人身上。
 *
 * commit 还没算出来的那一瞬间什么都不做 —— 否则每次刷新都会在得知 commit 之前
 * 把刚存下的冷却误清掉，那这道门只在「算完 commit 之前」有效，等于没有。
 */
function dropIdentityCooldownIfStale() {
  const cd = readIdentityCooldown();
  if (!cd) return;
  const fp = identityFingerprint();
  if (fp && cd.fp !== fp) saveIdentityCooldown(null);
}

/** 这个 uid 是不是正卡在「等级不足」的死局里。 */
function identityLevelBlocked() {
  const uid = fieldValue("coolapkUid");
  return Boolean(uid) && readIdentityLevelBlocked() === uid;
}

/* 每秒把「请 N 秒后再试」往下数一格的那条定时器。全局一条而不是每次重画新建一条：
   renderIdentityGate 是被所有输入触发的，新建就会在打字时堆出一串定时器。 */
let identityCooldownTimer = 0;

function syncIdentityCooldownTicker() {
  const running = Boolean(identityCooldownTimer);
  if (identityCooldownRemaining(identityFingerprint()) > 0) {
    if (running) return;
    identityCooldownTimer = setInterval(() => {
      // 数到 0 时 renderIdentityGate 里的这一句会把它停掉，之后的空闲期不留后台动作。
      renderIdentityGate();
    }, 1000);
    return;
  }
  if (running) {
    clearInterval(identityCooldownTimer);
    identityCooldownTimer = 0;
  }
}


/**
 * 画出第二段那一串承诺（24 位小写十六进制）。
 *
 * 派生值每次现算、不缓存：页面回来了都重画一遍，于是屏幕上这一串与 localStorage 里
 * 那一枚在结构上不可能脱钩。算出来顺手记进 state.idCommit —— 冷却是按 (uid, commit)
 * 这一对认人的，而闸是同步画的。
 */
async function paintIdentityCommit() {
  const code = $("#identity-commit");
  if (!code) return;
  const secret = ensureIdentitySecret();
  try {
    const commit = await identityCommitment(secret);
    // sha256 是异步的：这中间 localStorage 里那一串要是被另一个标签页换掉了，就别画过期的。
    if (readIdentitySecret() !== secret) return;
    state.idCommit = commit;
    code.textContent = commit;
    // 指纹刚齐：冷却的锁与「请 N 秒后再试」都要靠它才画得出来。
    renderIdentityGate();
  } catch {
    code.textContent = "（这一串算不出来，刷新一次试试）";
  }
}

/**
 * 身份页的闸：那颗「验证并继续」亮不亮、还差什么。
 *
 * 它挂在 refreshGate() 的尾巴上（那条链已经被所有输入触发），所以这里只负责读现状，
 * 不自己找人调 —— 少一处「改了值忘了重画」的机会。
 * v2 之后这一屏不再需要包：凭据只有「UID + 签名里那一串 + 一条承诺」。
 *
 * 三档「点不了」各有各的说法，不许混成一句通用话：等级不足是死局（要先升等级，或者点
 * 「我已升级」）、冷却是等一会儿自己就过去、其余是还没填齐。按钮亮不亮只有这一处判。
 */
function renderIdentityGate() {
  const btn = $("#id-verify");
  const note = $("#id-note");
  if (!btn) return;
  const uid = fieldValue("coolapkUid");
  const pledge = $("#ck-pledge");
  // 指纹变了就解锁；commit 还没算出来的那一瞬间它什么都不做（见 dropIdentityCooldownIfStale）。
  dropIdentityCooldownIfStale();
  const blocked = identityLevelBlocked();
  const wait = identityCooldownRemaining(identityFingerprint());
  const ready = Boolean(
    !state.idBusy && !blocked && wait <= 0 && isCoolapkUid(uid) && pledge && pledge.checked
  );
  btn.disabled = !ready;
  // 死局的提示与手动出路：那一格只在 block 成立时出场（升完级点一下才解除，不自动解除）。
  const block = $("#id-level-block");
  if (block) block.hidden = !blocked;
  const recheck = $("#id-level-recheck");
  if (recheck) recheck.hidden = !blocked;
  if (note) {
    if (state.idBusy) note.textContent = "正在跟后端核对…";
    else if (!uid) note.textContent = "先填你的酷安 UID";
    else if (!isCoolapkUid(uid)) note.textContent = "UID 应是 4-12 位纯数字";
    else if (blocked) note.textContent = "先去酷安升级，再回来点「我已升级，重新验证」";
    else if (wait > 0) note.textContent = `请 ${wait} 秒后再试`;
    else if (!pledge || !pledge.checked) note.textContent = "把下面那条承诺勾上";
    else note.textContent = "可以去验证了";
  }
  // 冷却中才留一条每秒的定时器，数到 0 自己停。
  syncIdentityCooldownTicker();
}

function paintIdentityError() {
  const box = $("#id-err");
  if (!box) return;
  box.hidden = !state.idError;
  box.textContent = state.idError || "";
}

/**
 * 验证并继续：拿「UID + 本机 secret + 一条承诺」换一张 90 天会话（契约 v2 §2）。
 *
 * 发上去的是 secret 本身；签名里那一串是这个 secret 的哈希承诺 —— 所以这条信道里
 * 只会出现 secret 一次，而酷安签名那个**公开可读**的字段里永远只有抄不走的前 24 位。
 *
 * 成功之后做两件容易被漏掉的事：
 * ① 把 uid / 昵称写回那两格输入框并走一次 syncUploaderField —— 上传页的提交载荷读的就是它们；
 * ② 清掉「待问清单」的缓存（state.mine.asked），让记录页按新的身份重问一次。
 */
async function submitIdentity() {
  if (state.idBusy) return;
  const uid = fieldValue("coolapkUid");
  const pledge = $("#ck-pledge");
  if (!isCoolapkUid(uid) || !pledge || !pledge.checked) {
    refreshGate();
    return;
  }
  // 等级死局没解除之前这一发不必发：服务端会照原样再回一次 level_too_low。
  if (identityLevelBlocked()) {
    refreshGate();
    return;
  }
  const secret = ensureIdentitySecret();
  /* 冷却判据是 (uid, commit) 这一对，而 commit 得现算 —— 所以先算完再决定发不发。
     按钮那层禁用已经挡了一道，这里再判一次：键盘、书签脚本、另一个标签页都能绕过 DOM 状态。 */
  let fp = "";
  try {
    state.idCommit = await identityCommitment(secret);
    fp = identityFingerprint(uid, state.idCommit);
  } catch {
    fp = "";
  }
  if (identityCooldownRemaining(fp) > 0) {
    // 屏幕上那句「请 N 秒后再试」已经把话说完了，这里只负责别把这一发送出去。
    renderIdentityGate();
    return;
  }
  state.idBusy = true;
  state.idError = "";
  paintIdentityError();
  renderIdentityGate();
  try {
    const res = await issueIdentitySession({
      coolapkUid: uid,
      secret,
      pledge: "pledge-v2",
    });
    /* 成功一次就清零：这一对 (uid, commit) 的连续失败到此为止。
       顺手清掉「等级不足」那把锁 —— 能走到这里说明服务端这一次认了等级，而同一个 uid
       卡着锁时按钮根本点不动，所以这条锁记的只可能是**另一个人**（换号验证成功）。
       留着它只会在换回那个号时莫名其妙地锁住 —— 那不是「不自动解除」，那是锁错了人。 */
    saveIdentityCooldown(null);
    if (readIdentityLevelBlocked()) clearIdentityLevelBlocked();
    state.session = {
      token: res.session.token,
      uid: res.identity.uid || uid,
      nickname: res.identity.nickname || "",
      avatar: res.identity.avatar || "",
      level: res.identity.level,
      expiresAt: res.session.expiresAt,
    };
    saveSession(state.session);
    state.auth = "in";
    // v2 的 secret 是**长期**凭据（90 天内复用的就是这一串），所以这里不清它 ——
    // 清了就等于让人每次都去酷安改一次签名。上传页那枚包绑定 nonce 与它无关，也不动。
    state.uidStatus = "verified";
    state.uidInfo = {
      uid: state.session.uid,
      nickname: state.session.nickname,
      avatar: state.session.avatar,
    };
    const el = fieldEls.coolapkUid;
    if (el && state.session.uid) el.value = state.session.uid;
    const nick = fieldEls.uploader;
    if (nick && state.session.nickname) nick.value = state.session.nickname;
    showUid("ok", "已验证", state.session.nickname || state.session.uid, "这张凭据 90 天内有效，再投稿不用再改签名。");
    syncUploaderField();
    renderProof();
    // 换了人就是换了清单：asked 清空让 loadMine 重问一次。
    state.mine = { asked: "", rows: [], degraded: false, loading: false };
    paintSession();
    paintMine();
    refreshGate();
    if (location.hash !== "#/submit") history.replaceState(null, "", "#/submit");
    renderRoute();
    loadMine();
  } catch (err) {
    if (err && err.code === "level_too_low") {
      /* 等级不足是死局，不是「再试一次」能过的：把这个 uid 记下来、锁住按钮，
         只有用户自己升完级点「我已升级，重新验证」才解除（见 clearIdentityLevelBlock）。
         这一次照样记进冷却 —— 解除之后若等级还没到，他又能连点，那正是要节流的那只手。 */
      markIdentityLevelBlocked(uid);
      countIdentityFailure(fp);
      // 这句话由 #id-level-block 那一格说（它常驻、窄屏也不藏），这里不再重复一遍。
      state.idError = "";
    } else {
      // backendFailure 已经把那句中文写好了（含服务端原话），这里原样显示，不改写。
      state.idError = err && err.message ? err.message : "验证没有成功，稍后再试一次。";
      // 任何失败都记数（断网 / 超时 / 被拒）：不记的话「再点一次」就能无限绕过冷却。
      countIdentityFailure(fp);
    }
  } finally {
    state.idBusy = false;
    paintIdentityError();
    renderIdentityGate();
  }
}

/**
 * 「复制这串」：写进剪贴板，按钮上回一句结果。
 *
 * 不能假定 clipboard 一定在：非安全上下文（拿内网 http 地址调试时）navigator.clipboard 是
 * undefined，静默失败最糟 —— 那时退回「把这段字选中」，让用户自己按一次 Ctrl+C。
 */
async function copyIdentityCommit(btn) {
  const code = $("#identity-commit");
  const text = code ? code.textContent.trim() : "";
  if (!text) return;
  const label = btn ? btn.textContent : "";
  let ok = false;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      ok = true;
    }
  } catch {
    ok = false;
  }
  if (!ok) {
    try {
      const range = document.createRange();
      range.selectNodeContents(code);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    } catch {
      // 选不中也算了：24 位字就在屏幕上，手抄一条不算什么。
    }
  }
  if (btn) {
    btn.textContent = ok ? "已复制" : "请按 Ctrl+C";
    setTimeout(() => (btn.textContent = label), 1500);
  }
}

/**
 * 「我已升级，重新验证」：把「这个 uid 等级不够」那条死局手动解开，按钮交回用户。
 *
 * 不在这一下自动发一次验证：升没升级只有他本人知道，替他去撞一次后端只会在还是 Lv1 时
 * 再吃一个 level_too_low（而那一次也进冷却）。解开之后屏幕上那句「可以去验证了」立刻回来。
 */
function clearIdentityLevelBlock() {
  clearIdentityLevelBlocked();
  refreshGate();
}

function bindIdentity() {
  const pledge = $("#ck-pledge");
  if (pledge) pledge.addEventListener("change", () => refreshGate());
  const verify = $("#id-verify");
  if (verify) verify.addEventListener("click", () => submitIdentity());
  const copy = $("#identity-copy");
  if (copy) copy.addEventListener("click", () => copyIdentityCommit(copy));
  // 等级死局唯一的手动出路。
  const recheck = $("#id-level-recheck");
  if (recheck) recheck.addEventListener("click", () => clearIdentityLevelBlock());
  paintIdentityError();
  renderIdentityGate();
  paintIdentityCommit();
}

/* -------------------------------------------------------- 上传记录（#/records） */

/**
 * 记录页那一格空态：加载中 / 一条都没有 / 索引读不到 / 没验证，四种说法不许混。
 *
 * 有内容时由 paintMine() 的清单说话（那一格已经是本页主体），这里只补它不说话的那一格：
 * 「你还没投过模块」**不是**错误，而「这次没读到索引」也**不是**「你没投过」。
 */
function paintRecords() {
  const box = $("#records-state");
  if (!box) return;
  const mine = state.mine;
  const on = state.auth === "in" && Boolean(state.session && state.session.token);
  let text = "";
  if (!on) {
    text = "这一页要先看过身份 —— 回身份页验证一次，这里就会列出你投过的每一枚。";
  } else if (!mine.loading && !mine.rows.length && !mine.degraded) {
    text = "你还没投过模块。上传第一枚之后，这里会列出它的当前收录版本，也能直接接着发更新版。";
  }
  box.hidden = !text;
  box.textContent = text;
}

/**
 * 「我的模块」那一格现在是记录页的主体（它搬到了 #/records），所以这里没有额外的绑定；
 * 保留这个钩子是为了让 init() 里那一串 bind 与其它视图形状一致。
 */
function bindRecords() {
  paintRecords();
}

const runUidCheck = debounce(async () => {
  const uid = fieldValue("coolapkUid");
  // 会话条跟着输入框走：手改或清空 UID 时这里是唯一会被叫醒的地方。
  // 不在这里重画，会话属于旧 UID、输入框已换成别人时，条子会一直挂着说「已验证」。
  paintSession();
  // 「我的模块」也挂在同一条线上：它认的就是「输入框这串 UID 有没有会话」。
  paintMine();
  if (!uid || !isCoolapkUid(uid)) {
    state.uidStatus = uid ? "invalid" : "idle";
    state.uidInfo = null;
    $("#uid-check").hidden = true;
    syncUploaderField();
    refreshGate();
    return;
  }
  // 同一个 UID 刚核实过（切回另一枚、或把这枚改回原值）就别再打一次网络：
  // 结果本来就只认「这一串 UID 反查回来的那一份」（见 syncUploaderField）。
  if (state.uidStatus === "verified" && state.uidInfo && state.uidInfo.uid === uid) {
    syncUploaderField();
    refreshGate();
    return;
  }
  // 有会话就不用再核实：这张凭据本身就是「这个人已经证明过自己是这个 UID」。
  // 于是这一档也不发随机段（ensureNonce）—— 走会话的人这一次根本不用改签名，
  // 屏幕上也就没有那一串要抄；签名那一格由 renderProof 收起。
  if (sessionFor(uid)) {
    state.uidStatus = "verified";
    state.uidInfo = { uid, nickname: state.session.nickname || "", avatar: state.session.avatar || "" };
    const meta = USER_STATUS.verified;
    showUid(
      "ok",
      meta.label,
      meta.title,
      `UID ${uid}${state.session.nickname ? ` · ${state.session.nickname}` : ""}。90 天内的长效会话，这一次不用改签名。`,
      state.session.avatar || ""
    );
    syncUploaderField();
    renderProof();
    refreshGate();
    // 会话属于这串 UID：清单该有内容了。asked 是「问过哪串令牌」，所以这里不会重复打网络。
    loadMine();
    return;
  }
  state.uidStatus = "checking";
  showUid("idle", "checking", "正在核实酷安用户…", `查询 UID ${uid} 是否对应一个真实账号。`);
  refreshGate();

  const result = await lookupCoolapkUser(uid);
  // 用户在你等回包的时候又改了 UID，就别把旧结果贴上去
  if (fieldValue("coolapkUid") !== uid) return;
  state.uidStatus = result.status;
  // 核实通过才发随机段，而且**一次上传一份**：这一整套共用一串签名（v2 绑的是全集）。
  // 一枚一份是 v1 的形状，那时 N 枚要 N 条不同签名、N 次各自带凭据的 POST。
  if (result.status === "verified") ensureNonce();
  state.uidInfo = result.status === "verified" ? result : null;
  const meta = USER_STATUS[result.status] || USER_STATUS.unavailable;
  const desc =
    result.status === "verified"
      ? `UID ${result.uid}${result.nickname ? ` · ${result.nickname}` : ""}。${meta.hint}`
      : meta.hint;
  showUid(
    meta.tone === "ok" ? "ok" : meta.tone === "bad" ? "bad" : meta.tone === "warn" ? "warn" : "muted",
    meta.label,
    meta.title,
    desc,
    result.avatar
  );

  syncUploaderField();
  renderProof(); // 第一次核实通过才生成 nonce，签名行到这一步才有东西可显示
  refreshGate();
}, 500);

/* --------------------------------------------------------- 上传前确认逻辑 */

let lastFocus = null;

function openConfirm() {
  const { zipOk } = collect();
  const targets = submitTargets();
  if (!zipOk || !IS_API_CONFIGURED || !targets.length) return;
  // 兜底：万一是手填一切、没走过选包那条路，进确认层时补上。
  ensureTurnstile();
  // 人机校验没过就别开层。这个全屏层 position:fixed; z-index:80 会把 04 区的校验部件
  // 整个盖住：用户在这儿勾完确认、点确认，才吃一个 403，再被「返回修改」退出来找部件。
  // 按钮平时已经是 disabled（ready 由 items.every 决定），这里是给强行调用的兜底，
  // 顺便把人往部件那儿送一下。
  if (!turnstileOk()) {
    refreshGate();
    $("#turnstile-slot").scrollIntoView?.({ block: "center" });
    return;
  }
  commitView();
  lastFocus = document.activeElement;
  const layer = $("#layer-confirm");
  layer.hidden = false;
  layer.classList.add("is-open");
  document.body.style.overflow = "hidden";
  // 确认层现在只有一枚勾（#ck-confirm）。它**不在这里清零**：Escape 关掉多半只是想再看一眼
  // 清单，回来时勾还在是合理的；真正的复原放在提交成功之后（resetForm）与退出登录之后。
  // 「确认并上传」的亮灭跟着这一枚的当前值走，不再无条件灭。
  const ack = $("#ck-confirm");
  $("#confirm-go").disabled = !(ack && ack.checked);
  $("#confirm-go").textContent =
    targets.length > 1 ? `确认并上传这一整套（${targets.length} 枚）` : "确认并上传";

  const sum = $("#warn-sum");
  sum.textContent = "";
  // 一次动作只有一个人、一个承诺、一枚签名 —— 这三样在整套之上，逐枚列就是把它们说成 N 份。
  const shared = [
    ["上传人酷安昵称", fieldValue("uploader")],
    ["酷安 UID", uidLine()],
    [
      "签名的校验段",
      sessionFor(fieldValue("coolapkUid"))
        ? "（走长效会话，这一次不用改签名）"
        : state.nonce || "（还没生成）",
    ],
    ["本次要提交", `${targets.length} 枚 · 合计 ${fmtBytes(totalBytes(targets))} · 一个 PR`],
  ];
  for (const [k, v] of shared) {
    const line = node("div", "warn__shared");
    line.append(`${k}: `, node("b", null, v));
    sum.append(line);
  }
  // 逐枚那一份：确认之前必须能看见「这一次发出去的是哪几枚、每一枚发的是什么字段」。
  // manifest 就按这份写、file part 就按这份数 —— 这里说 3 枚，线上就得是 3 条 + 3 个包。
  for (const [i, card] of targets.entries()) {
    const v = cardValues(card);
    const block = node("div", "warn__mod");
    const head = node("div", "warn__mod-hd");
    head.append(node("b", null, `第 ${i + 1} 枚 · ${v.id || "（没 ID）"}`));
    head.append(node("span", null, `${v.name || "—"} · ${v.version || "—"} · code ${v.versionCode || "—"} · ${card.file ? fmtBytes(card.file.size) : "—"}`));
    block.append(head);
    block.append(node("div", "warn__mod-sub", `文件 ${card.file ? card.file.name : "—"} · 出处 ${v.source || "—"}`));
    block.append(node("div", "warn__mod-sub", `整包 sha256 ${card.zipSha ? `${card.zipSha.slice(0, 16)}…` : "还没算出来"}`));
    sum.append(block);
  }
  // 签名是提交前最后一道能核对的东西：整套就这一串，列一次，别让人以为还要逐枚抄。
  // 但走长效会话时这一行**整行不渲染** —— 会话档本来就不生成随机段（proofTextOf 无 nonce 返回 ""），
  // 硬画出来只会落到「这一套还差来源…现在没有可抄的一串」，跟上面那句「这一次不用改签名」自相矛盾。
  const viaSession = sessionFor(fieldValue("coolapkUid"));
  if (!viaSession) {
    const proofVal = node("b", null, "…");
    const proofLine = node("div", "warn__proof");
    proofLine.append("这一整套共用的签名: ", proofVal);
    sum.append(proofLine);
    proofTextOf().then((t) => {
      proofVal.textContent = t || "这一套还差来源（某一枚的模块 ID / 整包哈希 / 随机段），现在没有可抄的一串";
    });
  }
  const rec = state.cards.filter((c) => isRecorded(c));
  if (rec.length) {
    sum.append(
      node(
        "p",
        "warn__queue",
        `队列里另有 ${rec.length} 枚（${namesOf(rec)}）被「已被上传过」那一档摘出了：它们不进这一次提交，` +
          "签名那串里也没有它们。要留着看就留着，要重新上传就先移除再重选包。"
      )
    );
  }
  $("#confirm-back").focus();
}

/**
 * 上传前确认那一格要说清这一整套用的是哪一串：签名是「整套的 (id, 整包 sha256) 集合 + 随机段」
 * 的现算派生值，不缓存 —— 所以这里算完还要再认一次来源，中途动过就不许写进确认格。
 */
async function proofTextOf() {
  const set = setSources();
  if (!set.nonce || !set.targets.length || set.incomplete.length) return "";
  const items = set.items.map((i) => ({ ...i }));
  const nonce = set.nonce;
  let text;
  try {
    text = await buildProofStringV2(items, nonce);
  } catch {
    return "";
  }
  // 这中间用户又改了某一枚的 id / 换了包 / 重掷了串，就不许把这行写进上传前确认
  //（它已经不属于现在这份载荷了）。
  const now = setSources();
  if (
    now.nonce !== nonce ||
    now.items.length !== items.length ||
    now.items.some((it, i) => it.id !== items[i].id || it.zipSha !== items[i].zipSha)
  ) {
    return "";
  }
  return text;
}

function closeConfirm() {
  const layer = $("#layer-confirm");
  layer.classList.remove("is-open");
  layer.hidden = true;
  document.body.style.overflow = "";
  if (lastFocus && lastFocus.focus) lastFocus.focus();
}

function bindConfirm() {
  $$("[data-open-confirm]").forEach((btn) => btn.addEventListener("click", openConfirm));
  $("#confirm-back").addEventListener("click", closeConfirm);
  // 确认层只有一枚勾（#ck-confirm）：勾上就亮「确认并上传」，取消就灭。仍然用 $$ 取一遍而不是
  // 写死 id —— 万一将来有人再加一条，至少不会因为漏绑而让按钮在没勾时亮着。
  const boxes = $$("#layer-confirm input[type=checkbox]");
  boxes.forEach((box) =>
    box.addEventListener("change", () => {
      $("#confirm-go").disabled = !boxes.every((b) => b.checked);
    })
  );
  $("#layer-confirm").addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      closeConfirm();
      return;
    }
    if (e.key !== "Tab") return;
    const focusable = $$(
      '#layer-confirm button:not([disabled]), #layer-confirm input[type=checkbox]'
    ).filter((el) => el.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  });
  $("#confirm-go").addEventListener("click", () => {
    closeConfirm();
    uploadBatch();
  });
}

/**
 * 这一整套的载荷。发给服务端的字段集合与请求形状是后端契约（§17.3），一个都不许多、
 * 一个都不能换形状（见 api.js 的 submitContribution 与它的 multipart 字段），要加东西得先改后端。
 * 派生的签名串不发：后端自己按这一套重算，前端这份只用来显示。
 *
 * 逐枚那四样（zip / id / name / version / versionCode / author / description / source + sha256）
 * 进 manifest 的 `modules[]`；共享那几样（uploader / coolapkUid / pledge / nonce / turnstile）
 * 留在顶层 —— 一次上传只有一个人、一个承诺、一枚签名，这是 §17.3 的分工，不是排版偏好。
 */
function batchPayload() {
  const targets = submitTargets();
  return {
    modules: targets.map((card) => {
      const v = cardValues(card);
      return {
        card: card.key,
        zip: card.file,
        id: v.id,
        name: v.name,
        version: v.version,
        versionCode: v.versionCode,
        author: v.author,
        description: v.description,
        source: normalizeCoolapkUrl(v.source) || v.source,
        // 闸前移之后这一枚的声明值就是签名前缀的输入之一（§16 第 1 句），所以它**必须有**：
        // 缺任何一枚的 sha256，api.js 那一层直接不发这个请求（发出去也必然是 manifest_invalid）。
        // 落盘口径不在这里 —— 服务端逐枚实算，公开记录里只落实算那一份。
        sha256: card.zipSha,
      };
    }),
    uploader: fieldValue("uploader"),
    coolapkUid: fieldValue("coolapkUid"),
    // 承诺文本的版本号：一次整套勾一次那四条，所以它是顶层那一个字段，不逐枚重复。
    pledge: "pledge-v2",
    // 签名的随机部分：一次上传一份，覆盖这一整套。派生串不在这里算 —— 后端自己重算。
    nonce: state.nonce,
    // 长效会话令牌（90 天免改签名）：属于输入框里这串 UID 才发。判据只有 sessionFor 一份，
    // 与「签名那一格收不收」是同一个 —— 两处各判一次迟早漂成「页面说不用改、后端说没有凭据」。
    session: sessionFor(fieldValue("coolapkUid")) && state.session ? state.session.token : "",
    turnstile: state.turnstileToken,
  };
}

/* ------------------------------------------------------------ 上传与结果 */

function openRun(kicker, title) {
  const layer = $("#layer-run");
  layer.hidden = false;
  layer.classList.add("is-open");
  document.body.style.overflow = "hidden";
  $("#run-kicker").textContent = kicker;
  const ttl = $("#run-ttl");
  ttl.textContent = title;
  ttl.className = "done__ttl";
  $("#run-progress").hidden = false;
  $("#run-result").hidden = true;
  $("#run-result").textContent = "";
  $("#run-ft").textContent = "";
  $("#run-fill").style.width = "0%";
  $("#run-pct").textContent = "0%";
  $("#run-bytes").textContent = "0 B / 0 B";
}

function closeRun() {
  const layer = $("#layer-run");
  layer.classList.remove("is-open");
  layer.hidden = true;
  document.body.style.overflow = "";
}

/**
 * 提交**这一整套**：一次 POST、一个 manifest、N 个 zip、一串签名、一个 PR。
 * 语义是「全有全无」（§15 第 3 条已拍）：任一枚不过 ⇒ 整单拒、零 GitHub 写入、签名不烧。
 * 所以这一层不再有「这一枚成功了、那一枚失败了」那种半屏结果 —— 一个动作就一个结论。
 *
 * Turnstile 那一层反而更顺了：部件给的令牌是一次性的，旧那份逐枚提交要在 N 次 POST 之间
 * 续 N 次题（而这件事在本地验不了，本站不许拿真上传去验）；现在整套一次提交只解一次。
 */
async function uploadBatch() {
  if (state.uploading) return;
  const payload = batchPayload();
  if (!payload.modules.length) return;
  state.attempted = true;
  state.lastBatch = payload;
  state.uploading = true;
  state.batchResult = null;
  for (const card of state.cards) card.ack = null;
  renderQueue();
  openRun("UPLOADING", `正在上传这一整套（${payload.modules.length} 枚）…`);

  try {
    const { pr, modules, session } = await submitContribution(payload, {
      onProgress: (loaded, total) => {
        const pct = total ? Math.min(100, Math.round((loaded / total) * 100)) : 0;
        $("#run-fill").style.width = `${pct}%`;
        $("#run-pct").textContent = `${pct}%`;
        $("#run-bytes").textContent = `${fmtBytes(loaded)} / ${fmtBytes(total)}`;
      },
    });
    $("#run-fill").style.width = "100%";
    $("#run-pct").textContent = "100%";
    state.batchResult = { ok: true, pr, modules, at: Date.now() };
    // 后端认下了这个人 ⇒ 顺手把长效会话收下：以后 90 天内再投稿不用改签名。
    // 应答里没有 `session`（后端还没上线这一档）就什么都不做 —— 页面照旧每次改签名。
    // 走令牌来的这一笔后端不重签（`session` 是 null），adoptSession 见到 null 就原样留着旧令牌。
    adoptSession({ session });
    // 逐枚回执按 id 落回各自的卡：应答里那个 sha256 是**服务端实算**的那一份（§16 第 3 句），
    // 落在卡上上传人才拿得到「我这个字节被算成了什么」，而不是只对着一句「已受理」。
    const acked = new Map();
    for (const m of modules || []) if (m && typeof m.id === "string") acked.set(m.id, m);
    for (const entry of payload.modules) {
      const card = state.cards.find((c) => c.key === entry.card);
      if (card) card.ack = acked.get(entry.id) || { id: entry.id };
    }
    // 这一次成功了 ⇒ 这一串签名在服务端记过账了（用过即废）。随机段当场换掉：
    // 留着它，下一套（新选的包）会拿一串已经烧掉的签名去提交，永远回同一句「用过」。
    if (state.nonce) setNonce(makeNonce());
    // 人机校验令牌是一次性的：这一次已经把它交上去了，服务端（真开了 TURNSTILE_SECRET 时）
    // 也已经验过。留在 state 里，下一套包会拿同一枚去撞「timeout-or-duplicate」，
    // 用户看到的却是「人机校验未通过，请重试」——重试多少次都一样。
    // 顺手让部件回到未解状态：令牌都没了，屏幕上还打着一个绿勾就是骗人。
    dropTurnstileToken();
    resetTurnstileWidget();
    showSuccess(state.batchResult);
  } catch (err) {
    state.batchResult = { ok: false, reason: failReason(err), code: errCode(err), owner: errOwner(err) };
    // 失败路径也要把令牌收回去。Token 是**一次性**的：这次提交失败时它多半已经被
    // siteverify 消费掉了（服务端那句「人机校验未通过，请重试」就是它被用过的样子），
    // 留着它，点「重试」发出去的是同一枚废令牌 —— 用户会看到同一句失败，永远出不来。
    // 网络失败（请求压根没到 Worker）时它其实还活着，但这时让用户重解一次，比让他
    // 反复撞 403 便宜。
    dropTurnstileToken();
    resetTurnstileWidget();
    showFailure(err);
  } finally {
    state.uploading = false;
    renderQueue();
    // 提交掉的那一套不该再出现在签名那一格里：那串已经在服务端记过账了，
    // 屏幕上留着一串还能提交的字符就是让它被再烧一次。
    renderProof();
    refreshGate();
  }
}

/** 失败原因一律用服务端原话（api.js 已经把 error/message/reason/detail 都捞出来了）。 */
function failReason(err) {
  return err instanceof BackendError
    ? err.message
    : err && err.message
    ? err.message
    : "未知的失败，服务端没给原因。";
}

/** 后端回的机器可读码（api.js 从响应体的 code 取；不是 JSON 就没有）。 */
function errCode(err) {
  return err instanceof BackendError ? err.code : "";
}

/** 这一句该谁去修：'you' 改这一套 / 'us' 改本站或后端 / 'both' / 'unknown'。 */
function errOwner(err) {
  if (err instanceof BackendError) {
    if (err.kind === "network" || err.kind === "not-configured" || err.kind === "bad-response") return "us";
    return err.owner || "unknown";
  }
  return "unknown";
}

const OWNER_LABEL = {
  you: { chip: "是你的包或字段的问题", cls: "chip--bad" },
  us: { chip: "是我们这一侧的问题", cls: "chip--warn" },
  both: { chip: "两边都要看一眼", cls: "chip--warn" },
  unknown: { chip: "归属没能判定", cls: "" },
};

function retryBatch() {
  // 重试发的是**上一次那一套**（state.lastBatch）还是当前队列那一套？
  // 答案：当前队列 —— 但必须重新凑齐才发得出去。用 lastBatch 重试的风险是它里面的 File 对象
  // 可能已经被换掉/移除，那时发出去的集合与签名那串不是同一套（闸前移之后声明进判据，
  // 这种错位就是 sha_mismatch / batch_incomplete 的来源）。凑不齐就回表单去，不硬发。
  const targets = submitTargets();
  if (!targets.length) {
    closeRun();
    openConfirm();
    return;
  }
  // 令牌在上一次失败时已经被收回去了（uploadBatch 的 catch 里清的），而 Worker 那边
  // 没令牌就是 403。硬发一次只会让用户再读一遍同一句失败，所以先把他送回 04 区去解。
  if (!turnstileOk()) {
    closeRun();
    const slot = $("#turnstile-slot");
    slot.hidden = false;
    slot.scrollIntoView?.({ block: "center" });
    ensureTurnstile();
    refreshGate();
    return;
  }
  uploadBatch();
}

function resultBody() {
  $("#run-progress").hidden = true;
  const box = $("#run-result");
  box.hidden = false;
  box.textContent = "";
  return box;
}

function showSuccess(res) {
  const url_ = safeUrl(res.pr);
  const n = (res.modules && res.modules.length) || (state.lastBatch ? state.lastBatch.modules.length : 0);
  $("#run-kicker").textContent = "PR OPENED";
  const ttl = $("#run-ttl");
  ttl.textContent = n > 1 ? `这一整套 ${n} 枚已受理，一个 PR 已开` : "上传已受理，PR 已开";
  ttl.classList.add("ok");

  const box = resultBody();
  box.append(node("p", null, "服务端已经存下这一整套的每一个包，并自动开了一个只含元数据 JSON 的 PR："));
  const link = node("a", null, url_ || "（没拿到 PR 链接）");
  if (url_) {
    link.href = url_;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.className = "mono";
  }
  box.append(link);
  // 逐枚回执：这一格要说得出「哪一枚落成了什么」。服务端应答里的 sha 是**它自己实算**那一份
  //（§16 第 3 句：公开记录只落实算），把它显示出来，用户才能拿它对着自己那个文件核一遍。
  if (res.modules && res.modules.length) {
    const ul = node("ul", "run__mods");
    for (const m of res.modules) {
      const bits = [];
      if (m.versionCode !== undefined) bits.push(`code ${m.versionCode}`);
      if (m.assetName) bits.push(m.assetName);
      if (m.sha256) bits.push(`服务端实算 sha256 ${String(m.sha256).slice(0, 16)}…`);
      ul.append(node("li", null, `${m.id || "（没给 id）"} · ${bits.join(" · ") || "已受理"}`));
    }
    box.append(node("p", "done__kicker", `这一次落盘的 ${res.modules.length} 枚`));
    box.append(ul);
  }

  const ul = node("ul", "next");
  // 第 4 条说的是「签名接下来怎么办」，两条路走的是两件事：
  // 会话档这一次根本没发签名（batchPayload 里 session 那一格顶掉了签名校验段），
  // 说「签名已经记账、要再改一次」就是假话 —— 用户会去找那一串根本不存在的签名。
  const viaSession = Boolean(state.lastBatch && state.lastBatch.session);
  for (const text of [
    "点进 PR 能看到审核进度，以及这一整套每一枚的完整元数据。",
    // 这句原来说「对已收录模块的版本更新不会自动合入」—— 与契约 §4.1 同源的假话。
    // 新模块与版本更新走的是同一套机器判据，过了都自动进索引；差别只在「这一枚是不是你的」。
    "新模块与版本更新走同一套机器判据：没命中拦截名单就可能自动通过。版本更新还多一道归属闸 —— 只有原作者能发。",
    "PR 合并之后，这些模块才会出现在公开索引里，所有人才能在管理器里搜到并一键安装。",
    viaSession
      ? "这一趟走的是长效会话（90 天内免改签名），你的酷安签名这一次没有被动过；下次上传仍然不用改。"
      : "这一串签名已经随这一次上传记账了（用过即废）。要再上传别的包，页面会给你新的一串 —— 签名要再改一次。",
  ])
    ul.append(node("li", null, text));
  box.append(node("p", "done__kicker", "接下来"));
  box.append(ul);

  const ft = $("#run-ft");
  const again = node("button", "btn btn--go", "清掉这一套，传下一套");
  again.type = "button";
  again.addEventListener("click", () => {
    closeRun();
    resetForm();
  });
  ft.append(again);
  const stay = node("button", "btn btn--ghost", "关闭");
  stay.type = "button";
  stay.addEventListener("click", closeRun);
  ft.append(stay);
}


/**
 * 服务端只有两种说法意味着这一串签名真的被烧掉了：用过它，或者它可能已经变成了一条上传。
 * 只有这两种才重掷随机段。其余失败（400 字段问题、403 平台侧读不出记录）不轮换 ——
 * 签名绑包体之后重试同一个签名是有效的（Task 9），无故轮换等于让用户白抄一次签名。
 *
 * 判据首选机器可读的失败码：Worker 已给「签名已用过」这条回 `code: "proof_used"` —— 就写在
 * used-nonce 命中的那条 403 响应体字面量里（contrib/worker/src/index.ts:2318）。跨仓库自检在
 * --require-backend 下刮后端源码里的失败码集合与本文件逐字对齐，本机走的是真检查、不是 skip：
 * 码这一半已经两头对上。
 * 文案匹配（NONCE_SPENT_RE）继续留着当退路 —— 码随部署到达线上之前，以及响应体不是 JSON 的
 * 场合，它仍是唯一信号。两个判据并起来才是这次要的：后端改文案时不再静默停止轮换，后端没回
 * code 时行为与今天一致。
 * 如实标注其中一支：`可能已(?:经)?提交成功` 今天没有任何可发的后端文案与之对应（整个
 * worker/src 搜不到「可能已」「提交成功」这两个说法）。真正的「可能已经提交成功」发生在客户端
 * —— 网络失败、上传中断、看不懂的应答，而这些按上面的判据刻意不轮换：重试若真撞上 used-nonce，
 * 由 proof_used 码当场接住。留着这一支是前向兼容钩子：服务端将来真发这类说法时两端当场一起转，
 * 不需要谁记得回来改这个正则。
 */
const NONCE_SPENT_RE = /口令已(?:经)?用过|可能已(?:经)?提交成功/;

/** 从后端响应体里取机器可读的失败码；响应不是 JSON（网关的 HTML、纯文本）时返回空串。 */
function backendCode(err) {
  const raw = err instanceof BackendError && typeof err.detail === "string" ? err.detail : "";
  if (!raw) return "";
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return "";
  }
  return parsed && typeof parsed.code === "string" ? parsed.code : "";
}

/** 这一串签名是不是真的被烧掉了：码优先，文案兜底。 */
function proofWasSpent(err, reason) {
  return backendCode(err) === "proof_used" || NONCE_SPENT_RE.test(reason);
}

function showFailure(err) {
  $("#run-kicker").textContent = "REJECTED";
  const ttl = $("#run-ttl");
  const n = state.lastBatch ? state.lastBatch.modules.length : 0;
  ttl.textContent = n > 1 ? `这一整套 ${n} 枚都没提交上去` : "这次没提交上去";
  ttl.classList.add("bad");

  const box = resultBody();
  const reason = failReason(err);
  const owner = errOwner(err);
  const label = OWNER_LABEL[owner] || OWNER_LABEL.unknown;
  // 先说这一句该谁去修，再贴服务端原话。「是你的包的问题」与「是我们的服务的问题」
  // 混成同一句是这个站写过的那种假话：两种失败要用户做的事正好相反。
  const head = node("div", "reason__hd");
  head.append(node("span", `chip${label.cls ? " " + label.cls : ""}`, label.chip));
  const code = errCode(err) || (err && err.code) || "";
  if (code) head.append(node("span", "reason__code", `code: ${code}`));
  box.append(head);
  box.append(node("p", null, "后端返回的原因："));
  box.append(node("div", "reason", reason));

  // 全有全无不是「保守起见」那种口彩，是 §15 第 3 条拍下的语义：说清楚它意味着什么。
  box.append(
    node(
      "p",
      "run__scope",
      `这一次是**整套一次提交**，语义全有全无：任何一枚没过 ⇒ 整单拒、一个 GitHub 写入都没发生、` +
        `签名也没被烧掉。所以${n > 1 ? `这 ${n} 枚` : "这一枚"}要么一起上线、要么一起还留在你手上 —— 页面上不会出现「一半传上了」那种状态。`
    )
  );

  let proofRotated = false;
  if (proofWasSpent(err, reason)) {
    // 这一串确实烧掉了：重掷那**一份**随机段（整套就一份），签名行现算新的一串，清单跟着刷新。
    setNonce(makeNonce());
    // 重试按钮复用上一份载荷，不同步的话它会带着已经烧掉的那串再打一次，永远回同一句指控。
    if (state.lastBatch) state.lastBatch = { ...state.lastBatch, nonce: state.nonce };
    renderProof();
    refreshGate();
    renderQueue();
    proofRotated = true;
  }

  if (err instanceof BackendError && (err.kind === "network" || err.kind === "not-configured")) {
    const hint = node("p");
    hint.append(
      "这类失败通常不用改上传内容：先确认 ",
      node("code", null, "config.js"),
      " 里的 API_BASE 填了、后端 Worker 在跑，并且它已经给响应加上 Access-Control-Allow-Origin。"
    );
    box.append(hint);
  } else if (owner === "us") {
    box.append(
      node(
        "p",
        null,
        "这一句不该由你改包来修：包、字段、签名都不用动。稍后重试一次，还是这样就这一屏的内容找站点 —— 表单与选中的包本页都给你留着。"
      )
    );
  } else {
    box.append(
      node(
        "p",
        null,
        "表单内容与选中的包我都留着了，改完可以直接重试这一整套，不用重新填一遍、也不用重新选文件。"
      )
    );
  }

  // 换串这件事必须让用户当场看见：签名里那串已经不通过了，不重抄一次就永远 403。
  if (proofRotated)
    box.append(
      node(
        "p",
        null,
        "签名换了一串 —— 表单里「上传签名」那一行现在是新的，上一串已经作废。" +
          "先把新串抄进酷安签名并保存，再回来点重试；签名没改就重试，后端还会说这一串不对。" +
          "换的是这一整套共用的那**一串**：一次上传只改一次签名。"
      )
    );

  const ft = $("#run-ft");
  const retry = node("button", "btn btn--go", n > 1 ? `重试这一整套（${n} 枚）` : "重试提交");
  retry.type = "button";
  retry.addEventListener("click", () => retryBatch());
  ft.append(retry);
  const back = node("button", "btn btn--ghost", "返回修改");
  back.type = "button";
  back.addEventListener("click", () => {
    closeRun();
    $("#f-id").focus();
  });
  ft.append(back);
}

function uidLine() {
  const uid = fieldValue("coolapkUid");
  if (!uid) return "未填";
  const local = { idle: "未核实", checking: "核实中…", invalid: "格式不对" };
  const label = local[state.uidStatus] || USER_STATUS[state.uidStatus]?.title || state.uidStatus;
  const nick = state.uidInfo && state.uidInfo.nickname ? `${state.uidInfo.nickname} · ` : "";
  return `${nick}${uid} · ${label}`;
}

function resetForm() {
  $("#form").reset();
  clearQueue();
  state.attempted = false;
  state.uidStatus = "idle";
  state.uidInfo = null;
  state.nonce = "";
  state.zipSha = ""; // 两个来源一起归零：nonce 与整包哈希（clearQueue 那份是包没了就清，这里是换上传）
  $("#uid-check").hidden = true;
  renderProof(); // nonce 清空后这一行跟着收起，别留一串还能提交的旧签名在屏幕上
  syncUploaderField(); // 顺手把 readOnly / 标签 / 说明一起还原，别留一个锁着的空框
  $$(".field").forEach((f) => f.classList.remove("is-bad", "is-pre"));
  // 上传成功后再传一枚：确认层那一枚勾要复原成未勾，别把上一轮的「我已知晓」带进下一次。
  // （Escape 关层不清勾，所以复原只能放在这里 —— 那是「还没传成」与「传成了」的分界。）
  const ack = $("#ck-confirm");
  if (ack) ack.checked = false;
  const goBtn = $("#confirm-go");
  if (goBtn) goBtn.disabled = true;
  refreshGate();
  location.hash = "#/submit";
}

/* ------------------------------------------------------- 02 已收录模块视图 */

function renderIndex() {
  const list = $("#mods");
  const shell = $("#index-state");

  if (!IS_INDEX_CONFIGURED) {
    list.textContent = "";
    $("#count").textContent = "";
    $("#index-readout").textContent = "INDEX_URL 未配置 · 浏览页暂时拿不到数据";
    $("#index-readout").classList.add("bad");
    shell.hidden = false;
    shell.textContent = "";
    shell.append(node("div", "empty__t", "索引地址还没配置"));
    shell.append(
      node(
        "p",
        null,
        "浏览页会直接请求 config.js 里的 INDEX_URL。填好公开索引 JSON 的地址，这里就会显示全部已收录模块。"
      )
    );
    const go = node("a", "btn btn--ghost btn--sm", "看看这个站现在接了什么");
    go.href = "#/about";
    shell.append(go);
    return;
  }

  if (state.indexError) {
    list.textContent = "";
    $("#index-readout").textContent = "索引读取失败";
    $("#index-readout").classList.add("bad");
    shell.hidden = false;
    shell.textContent = "";
    shell.append(node("div", "empty__t", "拉不到公开索引"));
    shell.append(node("p", null, state.indexError));
    const retry = node("button", "btn btn--ghost btn--sm", "重试");
    retry.type = "button";
    retry.addEventListener("click", loadIndex);
    shell.append(retry);
    return;
  }

  if (!state.index) {
    $("#index-readout").textContent = "正在读取索引…";
    shell.hidden = false;
    shell.textContent = "";
    shell.append(node("div", "empty__t", "读取中"));
    loadIndex();
    return;
  }

  const { name, lastUpdate, modules } = state.index;
  const idxReadout = $("#index-readout");
  idxReadout.classList.remove("bad");
  // 日期包成 .nb 块整体不断行（「更新 2026-10-」/「11 11:02」拆开读起来像两段）
  idxReadout.replaceChildren(
    `${name || "索引"} · ${modules.length} 个模块`,
    ...(lastUpdate ? [" · 更新 ", node("span", "nb", fmtDate(lastUpdate))] : [])
  );

  const q = state.query;
  const low = q.trim().toLowerCase();
  const shown = low
    ? modules.filter((m) =>
        [m.id, m.name, m.author, m.description].some((v) => String(v).toLowerCase().includes(low))
      )
    : modules;

  $("#count").textContent = "";
  const c = $("#count");
  c.append(node("b", null, shown.length));
  c.append(` 个 / 共 ${modules.length}`);

  list.textContent = "";
  if (!shown.length) {
    list.hidden = true;
    shell.hidden = false;
    shell.textContent = "";
    shell.append(node("div", "empty__t", `索引里没有匹配「${q}」的模块`));
    const hit = ledgerHitFor(q);
    if (hit) {
      shell.append(
        node(
          "p",
          null,
          `这个查询命中了一条处置记录：${incTitle(hit)}（${KIND_LABELS[hit.kind] || hit.kind || "处置"}）` +
            ` —— ${REASON_LABELS[hit.reason] || hit.reason || "理由见条目"}。` +
            "它不是没被上传过，是被下架或拒收了，所以不会出现在索引里。"
        )
      );
      const why = node("a", "btn btn--ghost btn--sm", "去看这条处置");
      why.href = `#/moderation?tab=ledger&q=${encodeURIComponent(q)}`;
      shell.append(why);
      return;
    }
    shell.append(node("p", null, "没找到不等于没被上传过 —— 查重以模块 ID 为准。确认自己手上的包还没收录的话，可以直接上传。"));
    const go = node("a", "btn btn--go btn--sm", "去上传");
    go.href = "#/submit";
    shell.append(go);
    // 公示没查过才去查一次：查回来之后这条空态可能升级成「命中了一条处置」。
    if (!state.ledgerTried) loadLedger();
    return;
  }
  list.hidden = false;
  shell.hidden = true;
  for (const m of shown) list.append(modRow(m, q));
}

function modRow(m, q) {
  const li = node("li", "mod");
  const hd = node("div", "mod__hd");
  hd.append(node("span", "mod__nm", m.name));
  const idEl = node("span", "mod__id");
  highlight(idEl, m.id, q);
  hd.append(idEl);
  if (m.verified) hd.append(node("span", "chip chip--ok", "verified"));
  li.append(hd);

  if (m.description) {
    const ds = node("p", "mod__ds");
    highlight(ds, m.description, q);
    li.append(ds);
  }

  const ft = node("div", "mod__ft");
  const latest = m.latest;
  const bits = [];
  if (latest) bits.push(`v${latest.version || "?"} · code ${latest.versionCode ?? "?"}`);
  const size = Number(latest && latest.size);
  if (latest && latest.size !== "" && Number.isFinite(size) && size > 0) bits.push(fmtBytes(size));
  if (latest && latest.time) bits.push(fmtDate(Number(latest.time)));
  if (m.author) bits.push(`by ${m.author}`);
  for (const text of bits) ft.append(node("span", null, text));

  const link = latest && safeUrl(latest.zipUrl);
  if (link) {
    const a = node("a", "mod__dl sp", "下载 zip");
    a.href = link;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    ft.append(a);
  }
  // 举报从「就是这一枚」这一格进去：带着 id 与 versionCode，签名的两个来源就不用用户手打。
  if (latest && SHA256_HEX_RE.test(String(latest.sha256 || ""))) {
    const rep = node("a", "mod__rep", "举报这一枚");
    rep.href = `#/moderation?tab=report&id=${encodeURIComponent(m.id)}&vc=${encodeURIComponent(latest.versionCode)}`;
    ft.append(rep);
  }
  li.append(ft);
  return li;
}

async function loadIndex() {
  const shell = $("#index-state");
  shell.hidden = true;
  $("#index-readout").textContent = "正在读取索引…";
  $("#index-readout").classList.remove("bad");
  state.indexError = null;
  try {
    state.index = await fetchIndex();
  } catch (err) {
    state.indexError =
      err instanceof BackendError ? err.message : "索引读取失败，可能是网络或格式问题。";
  }
  renderIndex();
  // 索引是签名的来源之一：它晚到一步，04 那一屏上「算不出签名」那句就得当场改口。
  if (currentModTab() === "report") refreshReportForm();
}

/* ------------------------------------------- 举报那一半（报已上架的模块）
   这条路的硬门槛只有一句：实名 + 在包里逐字定位到。判据全在服务端（worker 的 handleReport），
   页面只做两件谁都不肯替它做的事：把「实名」那一串签名算出来给人抄进签名，以及把两种相反的
   失败分开说 —— 「你引用的那段不在包里」（要他改材料）与「这个包我们读不出来」（要我们补能力）。
   一次成功的举报会烧掉签名里那一串签名（用过即废），所以签名的三个来源任何一动都必须重算。 */

const report = {
  nonce: "",
  evidence: [""],
  busy: false,
  result: null,
  /** 服务端那一次的原文（过码表之后）。它活到下一次提交为止 —— 否则重画一次就把人刚看到的那句擦了。 */
  error: "",
};

/** 被举报的那一枚：签名绑 (id, 索引里那一版的 sha256)，这一格算不出来就没有可提交的签名。 */
function reportTarget() {
  const id = $("#rp-id").value.trim();
  if (!id) return { ok: false, why: "还没填模块 ID：签名那一串绑的就是那一枚的 id 与包体 sha256。" };
  if (!state.index) {
    return { ok: false, why: "公开索引还没读出来。签名要绑的那串 sha256 只在索引里，读不到就算不出那一串。" };
  }
  const m = state.index.modules.find((x) => x.id === id);
  if (!m) {
    return {
      ok: false,
      why: `索引里没有 id=${id} 的模块。举报只管已经上架的模块 —— 请从 02 那一屏复制那一行小灰字，别手打。`,
    };
  }
  const rawVc = $("#rp-vc").value.trim();
  let version = null;
  if (rawVc) {
    version = m.versions.find((v) => Number(v.versionCode) === Number(rawVc)) || null;
    if (!version) {
      const known = m.versions.map((v) => v.versionCode).sort((a, b) => a - b).join(", ");
      return { ok: false, why: `这一版不在索引里；索引里这一枚有 versionCode=${known}。填其中一个，或者留空按最新那一枚判。` };
    }
  } else {
    version = m.latest || m.versions[0] || null;
  }
  if (!version) return { ok: false, why: "索引里这一枚没有任何版本条目 —— 那是索引自己的形状问题（本站的事）。" };
  if (!SHA256_HEX_RE.test(String(version.sha256 || ""))) {
    return { ok: false, why: "索引里那一枚没有 64 位的包体 sha256，签名算不出来 —— 本站索引的问题，你不需要改任何东西。" };
  }
  return { ok: true, module: m, version, id, sha: String(version.sha256).toLowerCase(), assumed: !rawVc };
}

function reportEvidenceLimits() {
  // 数字只在服务端自报时才有：没自报就什么都不说，绝不在这儿抄一份默认值当第二本账。
  const r = state.limits && state.limits.report;
  return r && r.maxEvidenceItems ? r : null;
}

function paintEvidence() {
  const box = $("#rp-ev-list");
  const lim = reportEvidenceLimits();
  box.textContent = "";
  report.evidence.forEach((quote, i) => {
    const row = node("div", "field");
    const ta = node("textarea", "mono");
    ta.rows = 2;
    ta.id = `rp-ev-${i}`;
    ta.value = quote;
    ta.placeholder = i === 0 ? "从包里原样复制的那一行，例如 curl … | sh" : "再一条（同样要逐字）";
    ta.addEventListener("input", () => {
      report.evidence[i] = ta.value;
      refreshReportForm();
    });
    row.append(ta);
    if (report.evidence.length > 1) {
      const rm = node("button", "btn btn--ghost btn--sm", "去掉这一条");
      rm.type = "button";
      rm.addEventListener("click", () => {
        report.evidence.splice(i, 1);
        paintEvidence();
        refreshReportForm();
      });
      row.append(rm);
    }
    box.append(row);
  });
  const count = $("#rp-ev-count");
  count.textContent = lim
    ? `${report.evidence.length} / ${lim.maxEvidenceItems} 条 · 每条至少 ${lim.minQuoteBytes} 字节`
    : `${report.evidence.length} 条`;
  const add = $("#rp-ev-add");
  add.disabled = Boolean(lim && report.evidence.length >= lim.maxEvidenceItems);
}

function refreshReportForm() {
  const target = reportTarget();
  const uid = $("#rp-uid").value.trim();
  const nick = $("#rp-nick").value.trim();
  const reason = $("#rp-reason").value.trim();
  const quotes = report.evidence.map((q) => q.replace(/\r/g, "")).filter((q) => q.trim());
  const lim = reportEvidenceLimits();
  const shortQuote = lim ? quotes.some((q) => new TextEncoder().encode(q).length < lim.minQuoteBytes) : false;
  const longReason = lim && lim.maxReasonChars ? [...reason].length > lim.maxReasonChars : false;
  const ok =
    target.ok &&
    isCoolapkUid(uid) &&
    Boolean(nick) &&
    Boolean(reason) &&
    quotes.length > 0 &&
    !shortQuote &&
    !longReason &&
    !report.busy;
  $("#rp-submit").disabled = !ok;
  $("#rp-vc-help").textContent = target.ok
    ? `按这一枚判：versionCode=${target.version.versionCode}${target.assumed ? "（索引里最新那一版，留空时的默认）" : ""} · sha256 ${target.sha.slice(0, 12)}…`
    : "读者装在身上的一般是最新那一版，所以留空是默认答案；要指旧那一版就填它的 code。";
  paintProof(target);
  const err = $("#rp-error");
  // 三种话只能显示一种，且都不许被无条件 hidden 掉：
  //   ① 本地能判的形状问题（引用太短）② 签名来源不齐（索引给不出那一枚）③ 服务端那一次的原文。
  // ②只在用户已经打了 id 之后才说 —— 空表单上追着人喊「索引里没有 id=」是噪音，不是提示。
  const local = shortQuote
    ? `有一条引用短于 ${lim.minQuoteBytes} 字节：太短的串在任何包里都找得到，那条门槛就形同虚设。请复制完整那一行。`
    : !target.ok && $("#rp-id").value.trim()
      ? target.why
      : "";
  const shown = local || report.error;
  err.hidden = !shown;
  err.textContent = shown;
  return ok;
}

/** 签名那一串：派生值，每次渲染现算 —— id / 那一版 / 换过的 nonce 任一动，串就换。 */
function paintProof(target) {
  const list = $("#rp-proof-list");
  list.textContent = "";
  const help = $("#rp-proof-help");
  if (!target.ok) {
    help.textContent = "签名串还差：上面那一格说清了差的是哪一件。";
    return;
  }
  const row = node("div", "proof");
  const code = node("code", "mono proof__txt", "正在算这一串…");
  row.append(code);
  list.append(row);
  const expected = `${target.id}|${target.sha}|${report.nonce}`;
  buildProofString(target.id, target.sha, report.nonce).then(
    (text) => {
      // 异步回来时来源可能已经动了（改 id / 换版 / 换 nonce）—— 只认还在绑那一套的那份结果。
      const now = reportTarget();
      if (!now.ok || `${now.id}|${now.sha}|${report.nonce}` !== expected) return;
      code.textContent = text;
      const copy = node("button", "btn btn--ghost btn--sm proof__copy", "复制这一串");
      copy.type = "button";
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(text);
          copy.textContent = "已复制";
        } catch {
          copy.textContent = "浏览器不让复制，请自己选中";
        }
        setTimeout(() => (copy.textContent = "复制这一串"), 1500);
      });
      row.append(copy);
      help.textContent = `这一串绑的是 id=${target.id} 与 versionCode=${target.version.versionCode} 那一枚的包体 sha256（${target.sha.slice(0, 16)}…）。`;
    },
    () => {
      code.textContent = "这一串算不出来（浏览器不支持 SHA-256）";
    }
  );
}

function paintReportResult() {
  const box = $("#rp-result");
  const r = report.result;
  box.hidden = !r;
  box.textContent = "";
  if (!r) return;
  const hd = node("h3", null, r.established ? "这条举报成立，已记下待办" : "这条举报没有成立");
  box.append(hd);
  const kv = node("ul", "mono");
  const add = (k, v) => {
    const li = node("li");
    li.append(node("span", "mod__id", k), " ", v);
    kv.append(li);
  };
  add("判定", String(r.verdict || "（服务端没给）"));
  add("是谁的事", r.owner === "us" ? "本站的（你不需要改任何东西）" : r.owner === "you" ? "举报材料的（照着下面那句改）" : String(r.owner || "（没给）"));
  add("公开动作", String(r.publicAction || "（没给）") + " —— 公开索引一个字都没动");
  if (r.reportId) add("记录号", r.reportId);
  box.append(kv);
  box.append(node("p", "field__help", String(r.nextStep || "服务端没给下一步 —— 这一句该由服务端说，缺它是本站的问题。")));
  // 受理了但留在举报这一半（自动跳过去会让人以为「怎么没有我这条」），
  // 所以给一个自己决定的出口：点它才切到公示那一半看队列读数。
  if (r.established) {
    const jump = node("button", "btn btn--ghost btn--sm", "去看处置公示");
    jump.type = "button";
    jump.addEventListener("click", () => switchModerationTab("ledger"));
    box.append(jump);
  }
}

async function submitReport() {
  if (report.busy) return;
  const target = reportTarget();
  if (!target.ok) return;
  const quotes = report.evidence.map((q) => q.replace(/\r/g, "")).filter((q) => q.trim());
  report.busy = true;
  report.error = "";
  $("#rp-submit").disabled = true;
  $("#rp-readout").textContent = "正在提交：服务端要读一次索引、取一次归档，再在你签名的那一串里核对签名。";
  try {
    const json = await reportModule({
      id: target.id,
      versionCode: target.version.versionCode,
      reason: $("#rp-reason").value.trim(),
      evidence: quotes,
      coolapkUid: $("#rp-uid").value.trim(),
      uploader: $("#rp-nick").value.trim(),
      nonce: report.nonce,
    });
    report.result = json;
    // 受理之后就换一串：签名用过即废，同一串再发一次只会撞「已用过」那一句。
    report.nonce = makeNonce();
    paintReportResult();
    $("#rp-readout").textContent = json.established
      ? "这条举报成立并记下了待办；公开索引这一刻还没动。下架由本站的自动流程按批提出（没有人工签字那一步），" +
        "排到哪一格，切到「处置公示」那一半看顶部的队列读数 —— 那一格没显示数字就是读数还没到位，不等于没受理。"
      : "这条举报没有成立，但同样留下了待办记录；下面那句是服务端给的下一步。";
  } catch (err) {
    report.result = null;
    paintReportResult();
    report.error = err instanceof BackendError ? err.message : `这一发没打出去：${String((err && err.message) || err)}`;
    $("#rp-readout").textContent = "这次举报没有受理。它没消耗你的签名 —— 签名不用改，改完下面那一句说的那件事再来一次。";
  } finally {
    report.busy = false;
    refreshReportForm();
  }
}

function renderReport() {
  if (!report.nonce) report.nonce = makeNonce();
  paintEvidence();
  paintReportResult();
  refreshReportForm();
}

function bindReport() {
  ["#rp-id", "#rp-vc", "#rp-reason", "#rp-uid", "#rp-nick"].forEach((sel) => {
    const el = $(sel);
    const on = () => refreshReportForm();
    el.addEventListener("input", on);
    el.addEventListener("change", on);
  });
  $("#rp-ev-add").addEventListener("click", () => {
    const lim = reportEvidenceLimits();
    if (lim && report.evidence.length >= lim.maxEvidenceItems) return;
    report.evidence.push("");
    paintEvidence();
    refreshReportForm();
  });
  $("#rp-nonce-renew").addEventListener("click", () => {
    report.nonce = makeNonce();
    refreshReportForm();
    $("#rp-proof-help").textContent = "换了新的一串：把上面这一串抄进签名并保存，之前那一串就作废了。";
  });
  $("#rp-submit").addEventListener("click", () => {
    submitReport();
  });
}

function bindSearch() {
  const input = $("#q");
  const apply = debounce(() => {
    state.query = input.value;
    if (parseHash().name === "index") renderIndex();
  }, 140);
  input.addEventListener("input", apply);
}

function bindIncSearch() {
  const input = $("#q-inc");
  const apply = debounce(() => {
    state.incQuery = input.value;
    if (currentModTab() === "ledger") renderIncidents();
  }, 140);
  input.addEventListener("input", apply);
}

/* ----------------------------------------------------- 处置公示那一半 */

// kind / reason / 选择器三张表在 api.js（仓库侧那份的键由 selftest 对），
// 这里只留一条注释说明它们为什么不在这里：公示页和读取层要同一套词。

/** 一条处置命中的主体，拿来当行标题。 */
function incTitle(item) {
  const sel = Object.fromEntries(item.selectors);
  if (sel.id) return sel.id;
  if (sel.coolapkUid) return `酷安 UID ${sel.coolapkUid}`;
  if (sel.sha256) return `${sel.sha256.slice(0, 16)}…`;
  return "（这条没写命中条件）";
}

function incSelText(item) {
  if (!item.selectors.length) return "没有命中条件";
  return item.selectors.map(([k, v]) => `${SELECTOR_LABELS[k] || k}=${v}`).join(" · ");
}

function incRow(item, q) {
  const li = node("li", "mod");
  const hd = node("div", "mod__hd");
  hd.append(node("span", "mod__nm", KIND_LABELS[item.kind] || item.kind || "处置"));
  if (!KIND_LABELS[item.kind]) hd.append(node("span", "chip chip--warn", "未知的处置种类"));
  const idEl = node("span", "mod__id");
  highlight(idEl, incTitle(item), q);
  hd.append(idEl);
  li.append(hd);

  const ds = node("p", "mod__ds");
  highlight(ds, incSelText(item), q);
  li.append(ds);
  if (item.note) {
    const noteEl = node("p", "mod__ds");
    highlight(noteEl, item.note, q);
    li.append(noteEl);
  }

  // 多带一个 mod__ft--inc：手机档要靠它把这个页脚折成「时间 + 举报并排、证据独占一行」
  // （见 panel.css 末尾那一节）。已收录那一屏的页脚结构不同，用不上，所以是加类而不是改 .mod__ft。
  const ft = node("div", "mod__ft mod__ft--inc");
  ft.append(node("span", null, item.atMs === null ? `时间：${item.at || "没写"}` : `时间：${fmtDate(item.atMs)}`));
  // 标签与值分开两个节点：highlight 是清空容器再写的，标签和值在同一个节点里会被它抹掉。
  const href = byLink(item.by);
  if (href) {
    const wrap = node("span", "inc__by");
    wrap.append(node("span", "inc__k", "证据："));
    const a = node("a", "inc__proof", href);
    a.href = href;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    wrap.append(a);
    ft.append(wrap);
  } else {
    ft.append(incLabeled("证据：", item.by || "没写", q, "inc__by"));
  }
  if (item.verify) ft.append(incLabeled("复核：", item.verify, q, "inc__by"));
  // 这一条是按模块 ID 命中的，就给一个直达举报的入口：id 带过去，versionCode 留空 ——
  // 举报管的默认是「索引里最新那一枚」，正好是这一条要判的那一枚。
  const hitId = (item.selectors || []).find(([k]) => k === "id");
  if (hitId && hitId[1]) {
    const rep = node("a", "mod__rep", "举报这一枚");
    rep.href = `#/moderation?tab=report&id=${encodeURIComponent(hitId[1])}`;
    ft.append(rep);
  }
  li.append(ft);
  return li;
}

function incLabeled(label, value, q, cls) {
  const wrap = node("span", cls);
  wrap.append(node("span", "inc__k", label));
  const val = node("span");
  highlight(val, value, q);
  wrap.append(val);
  return wrap;
}

function renderIncAppeal() {
  const host = $("#inc-appeal-where");
  // 和图例一样只填一次：这一段是静态文案，只有地址来自 config。
  if (!host || host.childElementCount) return;
  const u = (CONFIG.ISSUES_URL || "").trim();
  host.append(node("span", "inc__k", "去哪儿说："));
  if (!u) {
    // 不假装有一条走不通的路。每条记录自己的「证据」链接仍然点得开，所以不配也不瞎。
    host.append(
      node(
        "span",
        "inc-appeal__unset",
        "这个站还没配置索引仓库的 issue 地址 —— 先按上面那条记录的「证据」链接回到它自己的讨论。"
      )
    );
    return;
  }
  const a = node("a", "inc-appeal__link", u);
  a.href = u;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  host.append(a);
}

function renderIncLegend() {
  const host = $("#inc-legend");
  if (!host || host.childElementCount) return;
  const rows = [
    ["下架 / 拒收", "下架挡住的是这一段内容（按模块 ID、ID+versionCode 或包的 sha256 命中）；拒收挡住的是一个人或一个 ID 未来上传的任何包。"],
    ["命中条件", "同一条里的多个条件是「且」的关系，不是「或」——写了 ID 又写 versionCode，就只命中那一个版本。"],
    ["证据（by）", "新版是一枚机器章：`ci:audit@<提交>`，写的是这条处置被哪一次运行钉死，旁边那条复核命令任何人都能重跑一遍。它不是链接 —— 章里不带仓库地址，硬拼一个点得开的地址就是这一页在替它编一个它并不知道的去向。main 上还有换代前留下的记录，那一类的 by 是一条能点开的评论，照旧给链接。两种形状都认，因为只认新的那一种会把已经发生过的处置念成「没有证据」。形状不对的指针原样显示成文本。这一页显示的就是公示原文，判定发生在索引推导与 CI 里，前端不另判一份。"],
    ["复核（verify）", "有这一项时任何人都能自己跑一遍确认这条处置成立，而不是只能相信页面上写的。"],
    ["时间", "带时区的那一刻，不是「大概哪天」。"],
  ];
  for (const [k, v] of rows) {
    const li = node("li");
    li.append(node("span", "nm", k));
    li.append(node("span", "val", v));
    host.append(li);
  }
}

/* =====================================================================
 * 公示页 · 人卡层（spec §6.1 骨架 A「以人为主」/ §6.2 三层证据卡 / §5.4 高仿主页头卡）
 *
 * 第一屏是按人聚的卡墙，按条流水降为第二层 —— 但**一条都不会丢**：聚合成卡的条件是
 * 公示条目带 `subject`，历史条目（v1）没有这个键，它们只出现在按条那一层，
 * 而卡墙末尾那句话会替这一层交代清楚有多少条没聚进卡（§10「不空白不报错」）。
 * ===================================================================== */

/** 把酷安那些时间字段归一到毫秒：实测里秒与毫秒都出现过，差一档就是 1970 年。 */
function msOf(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  return n >= 1e12 ? n : n * 1000;
}

function agoText(ms) {
  if (ms === null) return "";
  const diff = Date.now() - ms;
  if (diff < 0) return "刚刚";
  const m = Math.floor(diff / 60000);
  if (m < 1) return "刚刚";
  if (m < 60) return `${m} 分钟前`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} 小时前`;
  const d = Math.floor(h / 24);
  if (d < 365) return `${d} 天前`;
  return `${Math.floor(d / 365)} 年前`;
}

function daysSince(ms) {
  if (ms === null) return null;
  const d = Math.floor((Date.now() - ms) / 86400000) + 1;
  return d > 0 ? d : null;
}

/**
 * 按 `subject.coolapkUid` 聚合。键在**前端**造，不新增存储：被处置者集合本来就只有几条。
 * 没带 subject 的条目直接不进这里 —— 它们由按条那一层负责，页面末尾那句计数替它们说话。
 */
function groupPeople(items) {
  const by = new Map();
  let unkeyed = 0;
  for (const it of items) {
    const uid = it.subject && String(it.subject.coolapkUid || "").trim();
    if (!uid) {
      unkeyed += 1;
      continue;
    }
    if (!by.has(uid)) by.set(uid, { uid, username: String(it.subject.username || ""), items: [], lastAtMs: null });
    const p = by.get(uid);
    p.items.push(it);
    if (it.atMs !== null && (p.lastAtMs === null || it.atMs > p.lastAtMs)) p.lastAtMs = it.atMs;
    if (!p.username && it.subject.username) p.username = String(it.subject.username);
  }
  return { people: [...by.values()].sort((a, b) => (b.lastAtMs ?? 0) - (a.lastAtMs ?? 0)), unkeyed };
}

function personCard(person, q) {
  const card = node("article", "pc");
  card.dataset.uid = person.uid;

  const cover = node("div", "pc__cover");
  const idrow = node("div", "pc__idrow");
  const av = node("span", "pc__av", person.username ? Array.from(person.username)[0] : "?");
  idrow.append(av);
  const names = node("div", "pc__names");
  const nm = node("div", "pc__nm");
  highlight(nm, person.username || `UID ${person.uid}`, q);
  names.append(nm);
  const uidLine = node("div", "pc__uid");
  highlight(uidLine, `coolapk.com/u/${person.uid}`, q);
  names.append(uidLine);
  idrow.append(names);
  const badge = node("span", "pc__badge", person.items.some((i) => i.kind === "deny") ? "已拉黑" : "已处置");
  idrow.append(badge);
  cover.append(idrow);
  card.append(cover);

  const meta = node("div", "pc__meta");
  meta.append(node("span", "pc__n", `${person.items.length} 条处置`));
  meta.append(node("span", null, person.lastAtMs === null ? "最近处置时间没写" : `最近 ${fmtDate(person.lastAtMs)}`));
  const kinds = [...new Set(person.items.map((i) => i.kind || ""))].filter(Boolean);
  for (const k of kinds) meta.append(node("span", "pc__kind", KIND_LABELS[k] || k));
  card.append(meta);

  const reasons = [...new Set(person.items.map((i) => REASON_LABELS[i.reason] || i.reason || "没写理由分类"))];
  const rs = node("div", "pc__reasons");
  for (const r of reasons) rs.append(node("span", "pc__reason", r));
  card.append(rs);

  const btn = node("button", "btn btn--ghost btn--sm pc__open", state.incOpenUid === person.uid ? "收起证据" : "展开三层证据");
  btn.type = "button";
  btn.addEventListener("click", () => togglePerson(person, q));
  card.append(btn);
  return card;
}

function togglePerson(person, q) {
  state.incOpenUid = state.incOpenUid === person.uid ? "" : person.uid;
  renderIncidents();
}

/** 高仿主页头卡：字段全列，缺的**明说没有**，不填 0、不填「—」冒充采到过（§10）。 */
function coolapkHeadCard(subject, identity) {
  const wrap = node("div", "ck");
  const cover = node("div", "ck__cover");
  const row = node("div", "ck__row");
  const idn = identity && typeof identity === "object" ? identity : null;
  const avatar = idn && idn.userBigAvatar ? String(idn.userBigAvatar) : "";
  const av = avatar && safeUrl(avatar)
    ? (() => {
        const img = document.createElement("img");
        img.className = "ck__av";
        img.src = safeUrl(avatar);
        img.alt = "";
        img.referrerPolicy = "no-referrer";
        img.loading = "lazy";
        // 头像是一个**外部 CDN 的 URL**，取不到是常态（防盗链、图床改动、离线看）。
        // 裂开的图标比没有图标更坏：它看起来像「我们采到了但坏了」。
        img.addEventListener("error", () => {
          const ph = node("span", "ck__av ck__av--none", "?");
          img.replaceWith(ph);
        });
        return img;
      })()
    : node("span", "ck__av ck__av--none", idn ? "?" : "");
  row.append(av);
  const col = node("div", "ck__col");
  const nmRow = node("div", "ck__nmrow");
  nmRow.append(node("span", "ck__nm", String((idn && (idn.displayUsername || idn.username)) || subject.username || "")));
  nmRow.append(node("span", "ck__lv", idn && idn.level !== undefined ? `Lv.${idn.level}` : "等级没采到"));
  col.append(nmRow);
  const stats = node("div", "ck__stats");
  for (const [label, key] of [["获赞", "be_like_num"], ["关注", "follow"], ["粉丝", "fans"]]) {
    const s = node("span", "ck__stat");
    s.append(node("b", null, idn && idn[key] !== undefined ? String(idn[key]) : "没采到"));
    s.append(node("i", null, label));
    stats.append(s);
  }
  col.append(stats);
  row.append(col);
  cover.append(row);

  const loginMs = idn ? msOf(idn.logintime) : null;
  const regMs = idn ? msOf(idn.regdate) : null;
  const pills = node("div", "ck__pills");
  pills.append(node("span", "ck__pill", loginMs === null ? "活跃时间没采到" : `${agoText(loginMs)}活跃`));
  const days = daysSince(regMs);
  pills.append(node("span", "ck__pill", days === null ? "注册天数算不出（没采到 regdate）" : `酷安第 ${days} 天`));
  if (idn && idn.verify_title) pills.append(node("span", "ck__pill ck__pill--v", String(idn.verify_title)));
  cover.append(pills);
  wrap.append(cover);

  const bio = node("div", "ck__bio");
  bio.append(node("span", "ck__bio-k", "签名"));
  bio.append(node("span", "ck__bio-v", idn && idn.bio ? String(idn.bio) : "没有采到签名（这条处置早于身份快照落盘）"));
  wrap.append(bio);

  const foot = node("div", "ck__foot");
  foot.append(node("span", null, regMs === null ? "注册日期没采到" : `注册 ${fmtDate(regMs)}`));
  foot.append(node("span", null, idn && idn.capturedAt ? `快照 ${fmtDate(msOf(idn.capturedAt))}` : "没有快照时刻"));
  const u = `https://www.coolapk.com/u/${encodeURIComponent(subject.coolapkUid)}`;
  const a = node("a", "ck__replay", "任何人可重放：coolapk.com/u/" + subject.coolapkUid);
  a.href = u;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  foot.append(a);
  wrap.append(foot);
  return wrap;
}

/** 三层里的一层。kind 决定边框（01 实线 / 02 虚线灰底 / 03 琥珀左杠）——「谁说的」在版面上不许混淆。 */
function layer(cls, num, title, note) {
  const box = node("div", `ec__layer ${cls}`);
  const hd = node("div", "ec__hd");
  hd.append(node("span", "ec__num", num));
  hd.append(node("span", "ec__t", title));
  if (note) hd.append(node("span", "ec__note", note));
  box.append(hd);
  return box;
}

function kvRow(cls, pairs) {
  const dl = node("div", `ec__kv ${cls}`);
  for (const [k, v, href] of pairs) {
    const r = node("div", "ec__r");
    r.append(node("span", "ec__k", k));
    if (href && safeUrl(href)) {
      const a = node("a", "ec__v ec__link", String(v));
      a.href = safeUrl(href);
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      r.append(a);
    } else {
      r.append(node("span", "ec__v", v === null || v === undefined || v === "" ? "没写" : String(v)));
    }
    dl.append(r);
  }
  return dl;
}

function factsLayer(item, ev) {
  const box = layer("ec__layer--facts", "01", "FACTS", "能被任何人重跑的那一层");
  const sel = Object.fromEntries(item.selectors);
  const pkg = ev && ev.package ? ev.package : null;
  const pend = ev && ev.pending && ev.pending.record ? ev.pending.record : null;
  const v = pend && Array.isArray(pend.versions) ? pend.versions[0] || {} : {};
  const pairs = [
    ["模块 ID", sel.id || (pkg && pkg.id) || "这条处置没按 ID 命中", ""],
    ["versionCode", sel.versionCode || v.versionCode || "没按版本命中", ""],
    ["包体 sha256", sel.sha256 || (pkg && pkg.sha256) || v.sha256 || "没按哈希命中", ""],
    ["包在哪", pkg && (pkg.zipUrl || pkg.assetName) ? pkg.assetName || pkg.zipUrl : "没有固化过，包体位置只能从索引历史里查", pkg && pkg.zipUrl ? pkg.zipUrl : ""],
    ["大小", pkg && pkg.size !== undefined && pkg.size !== null ? `${pkg.size} B` : "没采到", ""],
    ["上传时刻", pkg && pkg.submittedAt ? String(pkg.submittedAt) : "没采到", ""],
    ["模块出处", (pkg && pkg.source) || "没采到", pkg && pkg.source ? String(pkg.source) : ""],
  ];
  box.append(kvRow("ec__kv--2", pairs));
  if (!ev) box.append(node("p", "ec__miss", "这一条没有固化过的证据文件：页面上这些格子只剩公示自己写的那几个选择器。"));
  return box;
}

function machineLayer(item, ev) {
  const box = layer("ec__layer--machine", "02", "MACHINE", "机器初判，不是结论");
  const two = node("div", "ec__two");
  const left = node("div", "ec__colbox");
  left.append(node("h4", "ec__colt", "他于那一刻承诺"));
  const pend = ev && ev.pending && ev.pending.record ? ev.pending.record : null;
  const pledge = pend && pend.pledge ? pend.pledge : null;
  const own = pend && pend.ownership ? pend.ownership : null;
  if (pledge || own) {
    /* 「验证方式」那一格要说人话：pending 里存的是机器可读码 —— `bio` 是今天那条单枚签名（v1），
       `bio-set` 是 §15/§16 那套「一次上传共用一串集合签名」。把 `bio-set` 原样印到公示页，
       读者只会当成一个没见过的错误码，而这一格存在的意义正是让人核对「凭什么说这是你」。
       未知值不编说法：原样印出来并标一句不认识 —— 新值出现的正确反应是改这张表，
       不是让页面替后端猜一个听起来合理的解释。 */
    const VIA_LABELS = {
      bio: "酷安个性签名（单枚签名 v1）",
      "bio-set": "酷安个性签名（整套共用一串签名 v2）",
    };
    const viaRaw = own && own.via ? String(own.via) : "";
    const viaText = !viaRaw
      ? "没写"
      : VIA_LABELS[viaRaw] || `${viaRaw}（不认识的验证方式，原样列出）`;
    left.append(kvRow("ec__kv--1", [
      ["承诺文本", pledge && pledge.version ? String(pledge.version) : "没写版本", ""],
      ["承诺时刻", pledge && pledge.atMs ? fmtDate(msOf(pledge.atMs)) : "没写", ""],
      ["所有权证明前缀", own && own.proofPrefix ? String(own.proofPrefix) : "没写（这条早于签名方案）", ""],
      ["验证方式", viaText, ""],
      ["核验时刻", own && own.verifiedAt ? fmtDate(msOf(own.verifiedAt)) : "没写", ""],
    ]));
  } else {
    left.append(node("p", "ec__miss", "没有承诺与所有权的快照 —— 这条处置早于 P0 那道闸上线。"));
  }
  two.append(left);

  const right = node("div", "ec__colbox");
  right.append(node("h4", "ec__colt", "机器扫出"));
  const ai = ev && ev.report && ev.report.packages && ev.report.packages.length ? ev.report.packages[0].ai : null;
  if (ai) {
    const f = Array.isArray(ai.findings) ? ai.findings : [];
    right.append(kvRow("ec__kv--1", [
      ["静态等级", ai.staticRiskLevel ? String(ai.staticRiskLevel) : "没写", ""],
      ["AI 之后", ai.levelAfterAi ? String(ai.levelAfterAi) : "没写", ""],
      ["AI 是否同意静态", ai.agree === true ? "同意" : ai.agree === false ? "不同意（只允许抬级）" : "没写", ""],
      ["命中条数", `${f.length} 条`, ""],
    ]));
    if (f.length) {
      const ul = node("ul", "ec__finds");
      for (const one of f.slice(0, 5)) {
        const li = node("li", null);
        li.append(node("span", "ec__fid", String(one.id || one.rule || "没写规则号")));
        li.append(node("span", "ec__fse", String(one.severity || one.level || "")));
        li.append(node("span", "ec__floc", `${one.file || "没写文件"}:${one.line === undefined ? "?" : one.line}`));
        ul.append(li);
      }
      if (f.length > 5) ul.append(node("li", "ec__more", `另有 ${f.length - 5} 条，见证据原件`));
      right.append(ul);
    }
  } else {
    const why = !ev
      ? "这条没有固化过的证据文件，机器层的读数只留在那条 PR 的评论里。"
      : ev.report === null
        ? `证据里没有审核评论：${ev.reportWhy || "原因没写"}`
        : "证据里的审核评论没能解析出 AI 那一块（评论里的产物被截断或格式不是这一版认的）。";
    right.append(node("p", "ec__miss", why));
  }
  two.append(right);
  box.append(two);
  return box;
}

function sealLayer(item) {
  // 这一层原来那个版位写的是「03 HUMAN」——两个人看过并签了。本站已没有这一格，但版位不能空着：
  // 它现在讲的是**这条处置被哪一次运行钉死**，语义整个换掉了，不是把旧文案改个词。
  const sha = bySeal(item.by);
  const href = byLink(item.by);
  // main 上还有 5 条旧形状的记录，标题不能替它们说「机器章」——那是它们没有的东西。
  const box = layer(
    "ec__layer--seal",
    "03",
    sha ? "SEAL" : "PROOF",
    sha ? "机器章：哪一次运行把这条处置钉死的" : "旧版处置的证据：一条能点开的评论（换代之前下的那一条）"
  );
  const pairs = [
    ["处置", KIND_LABELS[item.kind] || item.kind || "未知的种类", ""],
    ["理由分类", REASON_LABELS[item.reason] || item.reason || "没写理由分类", ""],
    ["说明", item.note || "没写", ""],
    ["时间", item.atMs === null ? item.at || "没写" : fmtDate(item.atMs), ""],
    [
      "证据",
      sha
        ? `机器章钉在提交 ${sha.slice(0, 12)} 上 —— 要点开看，用下面那条命令`
        : href
          ? item.by
          : item.by || "没写",
      href,
    ],
    ["复核命令", item.verify || "这条没留可复验命令", ""],
  ];
  box.append(kvRow("ec__kv--1", pairs));
  return box;
}

function sealBlock(ref, ev, url) {
  const box = node("div", "es");
  const hd = node("div", "es__hd");
  hd.append(node("span", "es__t", "证据框"));
  hd.append(node("span", "es__at", ref.at ? `固化 ${fmtDate(msOf(ref.at))}` : "固化时刻没写"));
  box.append(hd);
  const name = node("div", "es__file");
  name.append(node("span", "es__k", "原件（文件名 = 它自己字节的 sha256）："));
  name.append(node("span", "es__hash", ref.file));
  box.append(name);
  const links = node("div", "es__links");
  if (url) {
    const a = node("a", "es__link", "读原件");
    a.href = url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    links.append(a);
  }
  if (ref.pr) {
    const b = node("a", "es__link", `承载它的 PR #${ref.pr}`);
    b.href = ev && ev.pr && ev.pr.url ? ev.pr.url : `https://github.com/SukiSU-Community/modules-repo/pull/${ref.pr}`;
    b.target = "_blank";
    b.rel = "noopener noreferrer";
    links.append(b);
  }
  if (ev && ev.pending && ev.pending.commitSha) {
    links.append(node("span", "es__sha", `pending 落在提交 ${String(ev.pending.commitSha).slice(0, 9)}`));
  }
  if (ev && ev.report && ev.report.commentUrl) {
    const c = node("a", "es__link", "审核评论");
    c.href = ev.report.commentUrl;
    c.target = "_blank";
    c.rel = "noopener noreferrer";
    links.append(c);
  }
  box.append(links);
  if (ev && ev.integrity && ev.integrity.note) box.append(node("p", "es__note", ev.integrity.note));
  return box;
}

/** 一条处置 = 一张三层卡；三层各自的数据来源不同，边框也不同，见 §6.2。 */
function dispositionCard(item, q) {
  const card = node("article", "ec");
  const hd = node("div", "ec__title");
  const t = node("span", "ec__title-t");
  highlight(t, incTitle(item), q);
  hd.append(t);
  hd.append(node("span", "ec__title-s", incSelText(item)));
  // 结论摘要提到标题这一行：下面三层的编号是 01→03，正文按这个顺序读下来，
  // 让人一眼看到的第一个词仍然是「这条是什么处置、为什么」。
  const k = node("span", "ec__title-k", (KIND_LABELS[item.kind] || item.kind || "处置") + " · " + (REASON_LABELS[item.reason] || item.reason || "理由见条目"));
  hd.append(k);
  if (!KIND_LABELS[item.kind] || !REASON_LABELS[item.reason]) hd.append(node("span", "chip chip--warn", "本页不认识的分类"));
  card.append(hd);
  card.append(factsLayer(item, null));
  card.append(machineLayer(item, null));
  card.append(sealLayer(item));
  const holder = node("div", "ec__seals");
  card.append(holder);
  // 证据文件是**按需**取的：一张卡最多几条引用，而每条几十 KB。
  loadRefs(item, card, holder);
  return card;
}

async function loadRefs(item, card, holder) {
  const refs = (item.evidence || []).filter((r) => r && r.file);
  if (!refs.length) {
    holder.append(node("p", "ec__miss", "这条处置没有 attached 的证据文件 —— 它下的时候 §8 固化还没上线，或当时什么都没捞到。"));
    return;
  }
  for (const ref of refs) {
    const url = evidenceUrlFor(ref.file);
    const res = await fetchEvidence(ref.file);
    if (res.ok) {
      // 把三层里 01/02 那两格换成有证据的版本：先摘掉旧的再重画，避免两套读数并存在同一张卡上。
      const f = card.querySelector(".ec__layer--facts");
      const m = card.querySelector(".ec__layer--machine");
      if (f) f.replaceWith(factsLayer(item, res.data));
      if (m) m.replaceWith(machineLayer(item, res.data));
      const head = card.querySelector(".ck");
      if (!head) card.querySelector(".ec__title").after(coolapkHeadCard(item.subject, res.data.pending && res.data.pending.record ? res.data.pending.record.identity : null));
      holder.append(sealBlock(ref, res.data, url));
    } else {
      const box = node("div", "es es--miss");
      box.append(node("div", "es__hd", "证据框"));
      box.append(node("p", "ec__miss", `${ref.file} —— ${res.reason}`));
      if (url) {
        const a = node("a", "es__link", "这个站会去取的那个地址");
        a.href = url;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        box.append(a);
      }
      holder.append(box);
    }
  }
}

function renderPeopleWall(items, q) {
  const host = $("#inc-people");
  host.textContent = "";
  const { people, unkeyed } = groupPeople(items);
  if (!people.length) {
    host.append(node("p", "pc-wall__none", "这份公示里还没有任何一条处置带 `subject`（按人聚合的键）—— 所以下面按条那一层就是全部。带 subject 的条目由 §8 固化那一步填进来，不是这里能补的。"));
    return { people: 0, unkeyed };
  }
  const hd = node("div", "pc-wall__hd");
  hd.append(node("span", "pc-wall__t", `被处置的人 · ${people.length} 个`));
  hd.append(node("span", "pc-wall__s", unkeyed ? `另有 ${unkeyed} 条处置没有身份键，只在下面按条那一层列出` : "公示里每一条都聚进了这张墙"));
  host.append(hd);
  const wall = node("div", "pc__wall-grid");
  for (const p of people) wall.append(personCard(p, q));
  host.append(wall);
  const open = people.find((p) => p.uid === state.incOpenUid);
  if (open) renderPersonDetail(open, q);
  return { people: people.length, unkeyed };
}

function renderPersonDetail(person, q) {
  const host = $("#inc-detail");
  host.hidden = false;
  host.textContent = "";
  const hd = node("div", "pc-detail__hd");
  hd.append(node("span", "pc-detail__t", `展开：${person.username || person.uid}`));
  const close = node("button", "btn btn--ghost btn--sm", "收起");
  close.type = "button";
  close.addEventListener("click", () => {
    state.incOpenUid = "";
    renderIncidents();
  });
  hd.append(close);
  host.append(hd);
  if (!person.items.some((i) => i.subject && i.subject.coolapkUid === person.uid)) return;
  for (const it of [...person.items].sort((a, b) => (b.atMs ?? 0) - (a.atMs ?? 0))) host.append(dispositionCard(it, q));
}

/* ------------------------------------------------------- 下架队列那一格
   数据只有一个来源：服务端定时器每跑完一轮写下的那一次读数（`GET /reports`）。
   为什么这一格值得占公示页一行：「举报了但没人管」与「举报了，正在排下一轮」在页面上
   原本长得一模一样 —— 前者是本站失信，后者是本站在动。写出来之后，停住的时候用户看得见
   （那个「截至」停在昨天），本站也没法假装它还在动。
   拿不到可信的数时这里**什么都不显示**：一个兜出来的 0 与真的空在页面上无法区分，
   而那两句是相反的话。 */

const reportQueue = { loading: false, data: null, loaded: false };

async function loadReportQueue(force = false) {
  if (reportQueue.loading) return;
  if (reportQueue.loaded && !force) {
    paintReportQueue();
    return;
  }
  reportQueue.loading = true;
  const q = await fetchReportQueue();
  reportQueue.data = q;
  reportQueue.loaded = true;
  reportQueue.loading = false;
  paintReportQueue();
}

function paintReportQueue() {
  const box = document.getElementById("inc-queue");
  if (!box) return;
  box.textContent = "";
  box.classList.remove("bad");
  box.hidden = true;
  const q = reportQueue.data;
  if (!q) return;
  const bits = [];
  // 报的是**枚数**（要摘几个包），后面括一句这是几条举报压出来的：同一枚包可以被几个人举报，
  // 两个数不一样时不说清就像「有三个人的模块要下架」。
  bits.push(
    q.artifacts === 0
      ? "下架队列：现在没有排队的模块"
      : `下架队列：还有 ${q.artifacts} 枚在等下架（由 ${q.reports} 条成立的举报压过来）`
  );
  const at = Number(Date.parse(q.at));
  bits.push(`截至 ${Number.isFinite(at) ? fmtDate(at) : "（读数没给时刻）"}`);
  if (q.truncated) bits.push("队列比这一轮翻到的更长，这两个数只到这儿");
  box.append(bits.join(" · "));
  box.hidden = false;
}

function renderIncidents() {
  const list = $("#inc-groups");
  const shell = $("#inc-state");
  const readout = $("#inc-readout");
  const count = $("#inc-count");
  renderIncLegend();
  renderIncAppeal();
  // 队列那一格独立于公示：它说的是「下架那条链还在不在动」，而公示读失败的时候恰恰最需要这句话。
  // 放在最前面，是为了让下面那几条 early return（没配公示地址 / 公示读失败 / 正在加载）都不把它一起带走。
  loadReportQueue();

  const clear = () => {
    list.textContent = "";
    count.textContent = "";
    // 人卡那一层与展开的详情跟着一起清：留着就会出现「公示读不到但墙上还挂着两个人」，
    // 而这一页唯一的价值是它列出的每条处置都可回访。
    const people = $("#inc-people");
    const detail = $("#inc-detail");
    if (people) people.textContent = "";
    if (detail) {
      detail.hidden = true;
      detail.textContent = "";
    }
    const head = $("#inc-list-head");
    if (head) head.hidden = true;
  };

  if (!dispositionsUrl()) {
    clear();
    readout.textContent = "公示地址还没确定 · 公示页暂时读不到数据";
    readout.classList.add("bad");
    shell.hidden = false;
    shell.textContent = "";
    shell.append(node("div", "empty__t", "处置公示的地址来自公开索引地址"));
    shell.append(
      node(
        "p",
        null,
        "这一页直接读索引仓库里的 json/dispositions.json，路径按 config.js 的 INDEX_URL 同目录推导。索引地址填好之后这里就有内容；公示为空时它会明说「目前没有任何处置记录」。"
      )
    );
    const go = node("a", "btn btn--ghost btn--sm", "看看这个站现在接了什么");
    go.href = "#/about";
    shell.append(go);
    return;
  }

  if (state.ledgerError) {
    clear();
    readout.textContent = "处置公示读取失败";
    readout.classList.add("bad");
    shell.hidden = false;
    shell.textContent = "";
    shell.append(node("div", "empty__t", "拉不到处置公示"));
    shell.append(node("p", null, state.ledgerError));
    const retry = node("button", "btn btn--ghost btn--sm", "重试");
    retry.type = "button";
    retry.addEventListener("click", () => {
      state.ledgerLoading = false;
      loadLedger();
    });
    shell.append(retry);
    return;
  }

  if (!state.ledger) {
    clear();
    readout.classList.remove("bad");
    readout.textContent = state.ledgerLoading ? "正在读取处置公示…" : "正在读取处置公示…";
    shell.hidden = false;
    shell.textContent = "";
    shell.append(node("div", "empty__t", "读取中"));
    loadLedger();
    return;
  }

  shell.hidden = true;
  const { items, lastUpdate, schemaKnown } = state.ledger;
  readout.classList.remove("bad");
  // 同上：公示日期包 .nb 不拆行
  readout.replaceChildren(
    `${items.length} 条处置记录`,
    ...(lastUpdate ? [" · 公示更新 ", node("span", "nb", fmtDate(lastUpdate))] : []),
    ...(schemaKnown ? [] : [" · 这份公示的 schema 标记本页不认识，按原文列出"])
  );

  const q = state.incQuery;
  const low = q.trim().toLowerCase();
  const shown = low
    ? items.filter((it) =>
        [
          incTitle(it),
          incSelText(it),
          it.note,
          it.by,
          it.verify,
          it.reason,
          it.kind,
          // 「按人聚」之后，人那一侧也要能搜：只搜得到 UID 选择器、搜不到 subject 的昵称，
          // 就等于第一屏有卡而搜不出那张卡。
          it.subject ? `${it.subject.coolapkUid || ""} ${it.subject.username || ""}` : "",
        ].some((v) => String(v).toLowerCase().includes(low))
      )
    : items;

  count.textContent = "";
  // 空公示时「0 条 / 共 0」是噪声，下面那句空态说得更清楚
  if (items.length) {
    const c = count;
    c.append(node("b", null, shown.length));
    c.append(` 条 / 共 ${items.length}`);
  }

  // 第一屏：按人聚的卡墙（spec §6.1 骨架 A）。它画的是**过滤后**的那一组，
  // 不然搜某个 UID 时墙上还挂着全部人，那一格搜索就成了装饰。
  renderPeopleWall(shown, q);

  if (!shown.length) {
    list.hidden = true;
    shell.hidden = false;
    shell.textContent = "";
    if (!items.length) {
      shell.append(node("div", "empty__t", "目前没有任何处置记录"));
      shell.append(
        node(
          "p",
          null,
          "空的公示是正常状态：还没有内容被下架或拒收过。这一页存在的意义是「处置必须留痕且公开」，所以它什么时候有东西，取决于什么时候真的出过事。"
        )
      );
      return;
    }
    shell.append(node("div", "empty__t", `公示里没有匹配「${q}」的记录`));
    shell.append(node("p", null, "查不到这条处置，不等于它没被收录过 —— 处置只写被挡掉的那些。"));
    return;
  }

  const order = Object.keys(REASON_LABELS);
  const orderOf = (r) => {
    const i = order.indexOf(r);
    return i < 0 ? order.length : i;
  };
  const groups = new Map();
  for (const it of shown) {
    if (!groups.has(it.reason)) groups.set(it.reason, []);
    groups.get(it.reason).push(it);
  }
  const keys = [...groups.keys()].sort(
    (a, b) => orderOf(a) - orderOf(b) || String(a).localeCompare(String(b))
  );

  list.hidden = false;
  const layerHead = $("#inc-list-head");
  if (layerHead) layerHead.hidden = false;
  list.textContent = "";
  for (const key of keys) {
    const box = node("div", "inc__grp");
    const hd = node("div", "inc__hd");
    hd.append(node("span", "inc__hd-t", REASON_LABELS[key] || key || "没写理由分类"));
    if (!REASON_LABELS[key]) hd.append(node("span", "chip chip--warn", "公示里有本页不认识的分类"));
    hd.append(node("span", "inc__hd-n", `${groups.get(key).length} 条`));
    box.append(hd);
    const ul = node("ul", "mods");
    // 新的处置排前面：这一页是拿来查「刚下了什么」的，按时间倒序比按字母有用。
    for (const it of [...groups.get(key)].sort((a, b) => (b.atMs ?? 0) - (a.atMs ?? 0))) {
      ul.append(incRow(it, q));
    }
    box.append(ul);
    list.append(box);
  }
}

async function loadLedger() {
  if (state.ledgerLoading) return;
  state.ledgerLoading = true;
  state.ledgerTried = true;
  state.ledgerError = null;
  try {
    state.ledger = await fetchDispositions();
  } catch (err) {
    state.ledgerError =
      err instanceof BackendError ? err.message : "处置公示读取失败，可能是网络或格式问题。";
  }
  state.ledgerLoading = false;
  if (currentModTab() === "ledger") renderIncidents();
  // 浏览页那句「搜不到但公示里有」依赖公示，到货后重画一次
  if (parseHash().name === "index") renderIndex();
  if (parseHash().name === "about") renderAbout();
}

/**
 * 浏览页搜不到时，看看这个查询是不是撞在了一条处置上。
 * 只按命中条件精确匹配 —— 这里是给「我的模块怎么不见了」一个确定答案的地方，
 * 模糊匹配会把无关条目说成是被下架，那就成了诬告。
 */
function ledgerHitFor(q) {
  if (!state.ledger) return null;
  const low = String(q).trim().toLowerCase();
  if (!low) return null;
  return (
    state.ledger.items.find((it) =>
      it.selectors.some(([k, v]) => (k === "id" || k === "coolapkUid" || k === "sha256") && v.toLowerCase() === low)
    ) || null
  );
}

/* ---------------------------------------------------------------- 说明页 */

function renderAbout() {
  const checks = [
    { k: "API_BASE", v: CONFIG.API_BASE || "未配置", ok: IS_API_CONFIGURED },
    { k: "INDEX_URL", v: CONFIG.INDEX_URL || "未配置", ok: IS_INDEX_CONFIGURED },
    {
      k: "处置公示（公示页数据源）",
      v: dispositionsUrl()
        ? `${dispositionsUrl()}${CONFIG.DISPOSITIONS_URL.trim() ? "" : "（由 INDEX_URL 同目录推导）"}`
        : "INDEX_URL 与 DISPOSITIONS_URL 都是空的，公示页没有数据来源",
      ok: Boolean(dispositionsUrl()),
    },
    {
      k: "TURNSTILE_SITEKEY",
      v: IS_TURNSTILE_CONFIGURED ? "已配置" : "未配置（提交时只带空 token 字段）",
      ok: IS_TURNSTILE_CONFIGURED,
    },
    {
      k: "上传上限（三个数都只从后端读）",
      v: limitsReadout(),
      ok: state.limits.from === "backend",
    },
    {
      k: "批量上传形状",
      v:
        "前端发的是 §17.3 那份 manifest + N 个 name=\"zip\" 的 file part（manifest 排第一个 part），签名走 v2 集合串。" +
        "⚠ 这条要求后端已经认 `manifest`（§17.1）—— 还没上线时这一套会被旧版单枚逻辑读成缺字段，" +
        "失败不是静默的，会原样回 4xx 与 code。",
      ok: true,
    },
    {
      k: CONFIG.COOLAPK_UID_FIELD,
      v: IS_UID_VERIFY_ON
        ? state.uidStatus === "idle"
          ? `${CONFIG.COOLAPK_USER_PATH}?uid= 已接，填入 UID 后显示实测结果`
          : `${CONFIG.COOLAPK_USER_PATH}?uid= 已接，实测：${USER_STATUS[state.uidStatus]?.title || state.uidStatus}`
        : "只校验格式，不核实账号是否存在",
      // 这一行问的是「接线了没有」，所以端点在就算 OK；能不能真的核实由上面的实测文案说话
      ok: IS_UID_VERIFY_ON,
    },
    {
      k: "前端解压能力",
      v: canInflateRaw() ? "支持 DecompressionStream" : "不支持，元数据需手填",
      ok: canInflateRaw(),
    },
  ];
  const list = $("#selfcheck");
  list.textContent = "";
  for (const { k, v, ok } of checks) {
    const li = node("li");
    li.append(node("span", "nm", k));
    li.append(node("span", "val", v));
    li.append(node("span", ok ? "chip chip--ok" : "chip chip--warn", ok ? "OK" : "待填"));
    list.append(li);
  }

  const add = $("#addsrc");
  add.textContent = "";
  if (CONFIG.SCHEME_ADD_SOURCE) {
    const a = node("a", "btn btn--go btn--sm", "一键加源");
    a.href = CONFIG.SCHEME_ADD_SOURCE;
    add.append(a);
  }
  if (IS_INDEX_CONFIGURED) {
    const p = node("p", null, "在管理器的「仓库 / Repository」里添加下面这个订阅地址即可：");
    const code = node("div", "term");
    code.append(node("div", null, CONFIG.INDEX_URL));
    const copy = node("button", "btn btn--ghost btn--sm", "复制地址");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(CONFIG.INDEX_URL);
        copy.textContent = "已复制";
      } catch {
        copy.textContent = "浏览器不让复制，请手动选中文本";
      }
      setTimeout(() => (copy.textContent = "复制地址"), 2200);
    });
    add.append(p, code, node("br"), copy);
  } else {
    add.append(
      node(
        "span",
        null,
        "索引地址填进 config.js 的 INDEX_URL 之后，这里会自动出现订阅地址与一键加源按钮。"
      )
    );
  }
}

/* -------------------------------------------------------------------- 启动 */

/**
 * 把「当前生效的三个上限」画到界面上。数字是问后端要的，异步到货，
 * 所以三处显示（拖放区提示、上传规格、说明页状态）都必须能从这一个函数重画。
 * 问不到的那一条写「后端没自报」而不是写一个猜出来的数 —— 页面上的数字是用户行动的依据。
 */
function paintLimit() {
  const L = state.limits;
  const one = L.maxBytes === null ? null : Math.round(L.maxBytes / MB);
  const total = L.maxTotalBytes === null ? null : Math.round(L.maxTotalBytes / MB);
  const hint = $("#drop-hint");
  if (hint) {
    hint.textContent =
      (one === null ? "单枚上限：后端没自报" : `单枚上限 ${one} MB`) +
      (total === null ? "" : ` · 整套 ${total} MB`) +
      (L.maxModules === null ? "" : ` · 一次最多 ${L.maxModules} 枚`) +
      " · 不要多套一层文件夹";
  }
  // 上传规格那一格只有地方放两个数（四格 2×2 是钉住的布局），所以写「单枚 + 一次几枚」，
  // 整套那一格由拖放区提示与闸门清单说。
  const spec = $("#spec-max");
  if (spec) {
    spec.replaceChildren(
      one === null ? node("span", null, "问后端中…") : node("b", null, one),
      one === null ? "" : " MB / 枚",
      ...(one === null ? [] : L.maxModules !== null ? [` · 一次最多 `, node("b", null, L.maxModules), ` 枚`] : [])
    );
  }
}

/** 说明页那一行：三个数各自到没到货，逐条说清 —— 「后端自报了上限」这一句在只自报一条时是假的。 */
function limitsReadout() {
  const L = state.limits;
  if (L.from !== "backend") {
    return `没问到（${L.from === "not-configured" ? "API_BASE 未配置" : L.from === "unreachable" ? "后端没应答" : "后端应答里没有这三个字段"}）—— 单枚 / 整套 / 枚数三条前端都不拦，全部由服务端拒。`;
  }
  const bits = [
    L.fields.maxBytes ? `单枚 ${fmtBytes(L.maxBytes)}` : "单枚上限后端没自报",
    L.fields.maxTotalBytes ? `整套 ${fmtBytes(L.maxTotalBytes)}` : "整套上限后端没自报（这一条前端不拦）",
    L.fields.maxModules ? `一次 ${L.maxModules} 枚` : "枚数上限后端没自报（这一条前端不拦）",
  ];
  return `${bits.join(" · ")} —— 数字只有后端一个定义处，config.js 里没有拷贝。`;
}

/**
 * 问后端它自己的三个上限。
 *
 * 这一步存在的理由很具体：前端曾经抄了一份 8MB，而后端常量是 2MB，于是用户按页面上的数字
 * 传到一半被 400 拒掉，界面还写着「允许 8MB」。抄来的常量一定会漂移，所以这次连兜底值都删了：
 * 三个数只有 Worker 一份，问到几条算几条，没问到的那条前端**不拦**。
 */
async function syncLimits() {
  const r = await fetchServiceLimits();
  const changed =
    r.maxBytes !== state.limits.maxBytes ||
    r.maxTotalBytes !== state.limits.maxTotalBytes ||
    r.maxModules !== state.limits.maxModules ||
    r.from !== state.limits.from ||
    // 举报那几格（一次几条、单条几字节起）也走同一个自报：晚到要重画 04，否则条数上限是猜的。
    (r.report ? JSON.stringify(r.report) : "") !== (state.limits.report ? JSON.stringify(state.limits.report) : "");
  state.limits = r;
  if (!changed) return;
  paintLimit();
  refreshGate(); // 枚数与整套字节这两格依赖它，到货之后清单要说真话
  if (currentModTab() === "report") renderReport();
  renderAbout();
}

function init() {
  $("#brand-zh").textContent = CONFIG.SITE_NAME;
  // 英文名可选：老配置里没有这个字段时保留 HTML 里的兜底文案，不要写成 undefined。
  // 它要两端分别贴住 logo 左边和中文名右边，所以按词拆进两个槽位：第一个词靠左，
  // 其余全归右边那个；只有一个词时也放得下（右槽留空，仍然左对齐）。
  if (CONFIG.SITE_NAME_EN) {
    const words = CONFIG.SITE_NAME_EN.trim().split(/\s+/);
    const slots = $$("#brand-lat [data-w]");
    if (slots.length >= 2) {
      slots[0].textContent = words[0] || "";
      slots[1].textContent = words.slice(1).join(" ");
    } else {
      $("#brand-lat").textContent = CONFIG.SITE_NAME_EN;
    }
  }
  document.title = `${CONFIG.SITE_NAME} · ${CONFIG.SITE_SUBTITLE}`;
  paintLimit();
  syncLimits();

  // 反机器人校验是提交前最后一道，不是首屏的一部分：这里只在没接后端时说清为什么空着，
  // 真加载留给 ensureTurnstile()（第一次选包 / 打开确认时才插 challenges.cloudflare.com 的脚本）。
  // 以前无条件在这里加载，实测拖慢首屏 FCP 27%（桌面 4G）/ 41%（手机档），load 43% / 36%。
  if (!IS_TURNSTILE_CONFIGURED) {
    const slot = $("#turnstile-slot");
    slot.hidden = false;
    slot.textContent =
      "反机器人校验：后端接入 Cloudflare Turnstile 后，把 sitekey 填进 config.js 这里就会出现部件。在此之前，提交时只随表发送一个空的 token 字段，不做任何假验证码。";
  }

  bindFile();
  bindSwap();
  bindQueueBar();
  bindCheck();
  bindConfirm();
  bindSearch();
  bindIncSearch();
  bindReport();
  bindTheme();
  bindStage();
  bindSession();
  bindMine();
  bindWho();
  bindIdentity();
  bindRecords();
  wireModerationTabs(); // 切换器是静态的两枚，绑一次就够，不随路由重绑
  renderQueue(); // 一开始是空队列：整条收起，上传页与今天一模一样
  // 先把「还不知道」那一档画出来（表单藏起、露出一行字），免得身份区先闪一下再消失。
  paintAuth();
  // 会话刷新是异步的，不 await：本地那串令牌有没有效，不该拦住首屏。
  refreshSession();
  renderAbout();
  renderRoute();

  $("#form").addEventListener("submit", (e) => e.preventDefault());
}

/**
 * 人机校验部件是「提交前」才用得上的东西，不该占首屏带宽。
 * 第一次真正有可能要提交时（选包、或打开确认层）调一次，之后是幂等的空转。
 * 那个第三方脚本会连带一条 challenge-platform 请求，都是百毫秒级；放在首屏等于让每个
 * 只是来看一眼已收录列表的人，替真要上传的人付这笔钱。
 */
let turnstileStarted = false;

/** 拿到令牌的唯一判据。门禁条目、确认层放行、重试前的检查都读它，别处不再各判一次。 */
function turnstileOk() {
  return Boolean(state.turnstileToken);
}

/** 令牌作废（过期 / 超时 / 出错 / 上传失败）统一走这里：清空 + 重画门禁。 */
function dropTurnstileToken() {
  state.turnstileToken = "";
  refreshGate();
}

/**
 * 让部件回到「没解」的样子。失败路径上 holder 可能已经被 turnstileFailed 拆掉了，
 * 那时 turnstile.reset(null) 会打一条控制台错，所以先确认它在。
 */
function resetTurnstileWidget() {
  const holder = $("#turnstile-widget");
  if (holder) window.turnstile?.reset?.(holder);
}

function ensureTurnstile() {
  if (turnstileStarted || !IS_TURNSTILE_CONFIGURED) return;
  turnstileStarted = true;
  const slot = $("#turnstile-slot");
  slot.hidden = false;
  slot.textContent = "下面完成人机校验后才能提交。";
  slot.onclick = null;
  slot.style.cursor = "";
  loadTurnstile();
}

/**
 * 加载失败（断网、被插件拦、脚本 15 秒还不来）必须有出口：复位 turnstileStarted，
 * 把半成品（script 标签、空 holder）拆掉，槽位换成可点重试的提示。
 * 否则 turnstileStarted 一旦为 true 就永远是 true，用户除了刷新页面没有第二条路。
 */
function turnstileFailed() {
  turnstileStarted = false;
  const slot = $("#turnstile-slot");
  $("#turnstile-widget")?.remove();
  slot.hidden = false;
  slot.textContent =
    "人机校验没能加载出来（可能是网络不通，或插件拦了 challenges.cloudflare.com）。点这里重试。";
  slot.style.cursor = "pointer";
  slot.onclick = () => ensureTurnstile();
  refreshGate();
}

function loadTurnstile() {
  const slot = $("#turnstile-slot");
  const script = document.createElement("script");
  script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
  script.async = true;
  script.defer = true;
  const holder = node("div");
  holder.id = "turnstile-widget";
  let settled = false;
  let wait = null;
  let watchdog = null;
  // 收尾只跑一次：成功就停掉两个计时器；失败把半成品拆干净并交回可重试的槽位。
  const finish = (ok) => {
    if (settled) return;
    settled = true;
    clearInterval(wait);
    clearTimeout(watchdog);
    if (ok) return;
    script.remove();
    holder.remove();
    turnstileFailed();
  };
  script.onerror = () => finish(false);
  document.head.append(script);
  slot.append(holder);
  // 15 秒还不出现 window.turnstile 就当它加载不出来 —— 这脚本正常是百毫秒级。
  watchdog = setTimeout(() => finish(false), 15000);
  wait = setInterval(() => {
    if (!window.turnstile) return;
    finish(true);
    try {
      window.turnstile.render(holder, {
        sitekey: CONFIG.TURNSTILE_SITEKEY,
        callback: (token) => {
          state.turnstileToken = token;
          refreshGate();
        },
        // 令牌是有寿命的：过期、交互超时、校验本身出错，都得把令牌收回去，
        // 否则门禁还以为「已通过」，用户拿着一个废令牌去撞 403。
        "expired-callback": () => dropTurnstileToken(),
        "timeout-callback": () => dropTurnstileToken(),
        "error-callback": () => dropTurnstileToken(),
      });
    } catch {
      // render 自己抛（sitekey 与当前域名对不上、holder 被别处动过）：同样要交回可重试的槽位，
      // 不然 turnstileStarted 卡在 true，页面就永远停在「下面完成人机校验后才能提交」。
      turnstileFailed();
    }
  }, 200);
}

init();
