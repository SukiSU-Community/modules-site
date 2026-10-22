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
} from "./api.js";
import { canInflateRaw, listEntries, readEntry, inspectEntries } from "./zipread.js";
import { parseModuleProp } from "./moduleprop.js";
import { buildProofString, buildProofStringV2, canonicalProofSet, makeNonce, sha256HexBytes } from "./proof.js";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const MB = 1024 * 1024;

const PREFILL_KEYS = ["id", "name", "version", "versionCode", "author", "description"];
/**
 * 字段按「属不属于那一枚」分成两张表 —— 批量上传把这条界线变成了契约的一部分：
 *   CARD_KEYS  = 每枚一份，进 manifest 的 `modules[]`（§17.3），在卡与视图之间来回搬；
 *   SHARED_KEYS = 一次上传一份，留在顶层 text fields（`pledge` / `nonce` / `coolapkUid` /
 *                `uploader` / turnstile），**不进卡、不进口令集合**。
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

     nonce 与口令不在这里：v2 的口令一串覆盖整套（设计文档 §15），所以随机段是**一次上传一份**，
     不住在卡上。把它放回每枚一份就退回旧语义了 —— 那时 N 枚要 N 串、N 次签名、N 次提交。 */
  cards: [],
  active: "",
  file: null,
  zip: null, // { arrayBuffer, entries, inspect, prop }
  checkStatus: null,
  uidStatus: "idle", // idle | checking | off | verified | not_found | unavailable | self_reported | invalid
  uidInfo: null, // { uid, nickname, avatar }
  // 这一次上传那一枚一次性随机段：整套共用一句口令，所以它只有一份。
  nonce: "",
  // 整包 sha256 = 当前卡那个文件的全部字节的 SHA-256（与 Worker ⑤-c 的 computedSha 同口径）。
  // 口令的两个来源是「这一整套的 (id, 整包 sha256) 集合」与 state.nonce 这**一个值**；
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
  // 处置台账。ledgerTried 只用于「浏览页搜不到时顺手查一次台账」这条懒路径，
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
   反过来，**跨枚共享的那几样一份都不能变成 N 份**：口令 v2 是一串覆盖整套（§15），
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
    checkRun: "", // 正在查的是哪个组合（用来区分「还没查」与「正在查」）
    checkWhy: "", // 查不成时的原话（服务端/网络给的原因）
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

/** 已经收录的那一枚 = 从口令、闸门清单、逐枚提交里全部摘出去的那一枚。 */
const isRecorded = (card) => checkOf(card) === "recorded";

/**
 * 「本次要投」的那几枚 = 口令里那一套 = manifest 里那几条 = 这一次 POST 带的 N 个 file part。
 * 闸门读数、口令那一串、提交那一层共用这**一个**判据 —— 各写一份 filter 迟早会漂成
 * 「清单说 3 枚、manifest 写 2 条、屏幕上那一串算的是另外 3 条」，而那三种数在批量这一头
 * 是同一个东西：口令绑的就是这套的全集（§15），少一枚都是另一串口令。
 * 两类枚不在这里：
 *   ① 被 /check 判为 recorded 的 —— 它不进集合、不进口令、不进 manifest；
 *   ② 已经拿到后端回执的（card.ack）—— 那几枚的字节已经在一个 PR 里了，跟着下一次再发一遍
 *      就是拿同一个 (id, versionCode) 撞第二次（§17.4 之外那一格：pending/CI 的重复）。
 *      它们留在队列里当这一屏的台账，想投新的就清空或移除，新选的那枚自成下一套。
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
  // 随机段不在这里搬：一次上传一份、整套共用（v2 的口令覆盖全集），它不属于任何一张卡。
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
 * 一串口令覆盖一整套（§15），所以「一枚一份」现在是错形状：那会需要 N 次签名、N 次提交，
 * 而服务端第一次就把这串烧掉，后 N-1 次全被判「口令已用过」。
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
  // 而口令那一串是绑整套算的，集合一变串就变，所以这一句不加分支：谁的结论变了就重算一次串。
  renderProof();
  if (card === activeCard()) refreshGate();
  renderQueue();
}


/* ------------------------------------------------------- 路由：hash 三视图 */

const VIEWS = {
  submit: { el: "#view-submit", label: "上传" },
  index: { el: "#view-index", label: "已收录" },
  incidents: { el: "#view-incidents", label: "处置公示" },
  report: { el: "#view-report", label: "举报" },
  about: { el: "#view-about", label: "说明" },
};

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, search] = raw.split("?");
  const name = VIEWS[path] ? path : "submit";
  const params = new URLSearchParams(search || "");
  return { name, params };
}

function renderRoute() {
  const { name, params } = parseHash();
  for (const [key, view] of Object.entries(VIEWS)) {
    $(view.el).classList.toggle("is-active", key === name);
  }
  $$(".nav a").forEach((a) => {
    const isNow = a.getAttribute("href") === `#/${name}`;
    if (isNow) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  $("#dock").hidden = name !== "submit";
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
  if (name === "incidents") renderIncidents();
  if (name === "report") {
    // 从 02 那一屏「举报这一枚」进来时带着 id 与 versionCode：那是用户不必重打的两格，
    // 也是口令的两个来源 —— 预填错了就等于口令绑错，所以只认索引里真有的那一枚（reportTarget 判）。
    if (params.has("id")) $("#rp-id").value = params.get("id") || "";
    if (params.has("vc")) $("#rp-vc").value = params.get("vc") || "";
    if (!state.index) loadIndex();
    renderReport();
  }
  window.scrollTo({ top: 0, behavior: "auto" });
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

/** 队列清空 = 视图清空。包没了，口令的那一套来源就一起归零，口令行跟着收起 ——
    屏幕上不许留着一串属于「已经不存在的那几枚包」的口令。 */
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
  // 屏幕上挂的还是 A 的口令、门禁写着「已生成」，此时点提交就是 zip:B + sha256:A。
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
  // 标识守卫贴到新包上 —— 屏幕上那一串就成了「新包的口令、旧包的字节」。
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

  // 视图与这一枚指向同一个解析结果对象：口令的来源因此只有一份，不会漂成两份。
  state.zip = { arrayBuffer, entries, inspect, prop: null };
  card.zip = state.zip;

  // 整包 sha256 是口令的第二个来源，每次换包都在这儿重算 —— 上一包的哈希对新包毫无意义。
  // 异步：几百毫秒内口令行按「还没算出来」显示（门禁说当时的实话），算完自己出现。
  // 算失败就留空：那一串根本不会显示，于是没人会抄一串对不上任何包的口令去填签名。
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
    // 「旧包的 id + 新包的整包哈希」这一串真算出来、画上屏幕、装进载荷。id 是口令的三个来源之一，
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
  renderProof(); // module.prop 把 id 预填进来的这一下不触发 input 事件，口令得自己重算一次
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
 * manifest 里就得是 N 条、口令得是这 N 条算出来的那一串。
 */
function statusOf(card) {
  if (state.uploading && submitTargets().includes(card)) return { tone: "idle", text: "随这套提交中" };
  if (card.ack) return { tone: "ok", text: "后端已回执" };
  const status = checkOf(card);
  if (status === "recorded") return { tone: "muted", text: "已被上传过 · 摘出" };
  if (status === "version_update") return { tone: "warn", text: "版本更新" };
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
  if (!card.zipSha) gaps.push(card.zip ? "整包哈希还没算完" : "包体没解析成功");
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

function queueRow(card) {
  const li = node("li", "qrow" + (card === activeCard() ? " is-current" : ""));
  li.dataset.key = card.key;

  const pick = node("button", "qrow__pick");
  pick.type = "button";
  pick.setAttribute("aria-label", "编辑这一枚模块");
  const v = cardValues(card);
  pick.append(node("span", "qrow__id", v.id || "（还没解析出模块 ID）"));
  pick.append(node("span", "qrow__nm", v.name || "—"));
  pick.append(node("span", "qrow__code", v.versionCode ? `code ${v.versionCode}` : "code —"));
  const st = statusOf(card);
  pick.append(
    node("span", `chip qrow__st${st.tone === "ok" ? " chip--ok" : st.tone === "warn" ? " chip--warn" : st.tone === "bad" ? " chip--bad" : st.tone === "idle" ? " chip--idle" : ""}`, st.text)
  );
  pick.addEventListener("click", () => selectCard(card.key));
  li.append(pick);

  // 这一枚的两句实话：差哪些字段（红字）/ 它在不在这一套里（口令那一串到底按几枚算）。
  const sub = node("div", "qrow__sub");
  const gaps = cardGaps(card);
  if (gaps.length && !isRecorded(card)) {
    sub.append(node("span", "qrow__why", `还差：${gaps.join("、")}`));
  } else if (isRecorded(card)) {
    sub.append(node("span", "qrow__skip", "这一枚不进这一套：口令按剩下的枚算，manifest 里也没有它"));
  } else if (card.zipSha && submitTargets().includes(card)) {
    sub.append(node("span", "qrow__in", "在这套里 · " + fmtBytes(card.file ? card.file.size : 0)));
  }
  if (card.ack) {
    const bits = [];
    if (card.ack.versionCode !== undefined) bits.push(`code ${card.ack.versionCode}`);
    if (card.ack.assetName) bits.push(card.ack.assetName);
    if (card.ack.sha256) bits.push(`${String(card.ack.sha256).slice(0, 12)}…`);
    sub.append(node("span", "qrow__ack", `服务端落盘口径：${bits.join(" · ") || "已受理"}`));
  }
  if (sub.childNodes.length) li.append(sub);

  const acts = node("div", "qrow__acts");
  const swap = node("button", "qrow__swap", "重选这个包");
  swap.type = "button";
  swap.setAttribute("aria-label", `给 ${v.id || "这一枚"} 重新选一个 zip`);
  swap.addEventListener("click", () => requestSwap(card));
  acts.append(swap);

  const rm = node("button", "qrow__rm", "移除");
  rm.type = "button";
  rm.setAttribute("aria-label", "把这枚从队列里移除");
  rm.addEventListener("click", () => {
    commitView();
    dropCard(card);
  });
  acts.append(rm);
  li.append(acts);
  return li;
}

/**
 * 单独给一枚换包：借一个隐藏的 file input，换完只重解析那一枚。
 * 换包必须让口令那一串当场死掉 —— 那一枚的整包哈希是集合口令的输入之一，
 * 换一枚就是换一整套（§15），旧串对不上新字节，服务端会回 sha_mismatch / 口令对不上。
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
  const list = $("#queue-list");
  if (!state.cards.length) {
    bar.hidden = true;
    list.textContent = "";
    $("#queue-count").textContent = "";
    $("#queue-note").textContent = "";
    renderEditing();
    return;
  }
  bar.hidden = false;
  list.textContent = "";
  for (const card of state.cards) list.append(queueRow(card));
  paintQueueReadout();
  renderEditing();
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
    node("span", null, `正在编辑第 ${at + 1} / ${state.cards.length} 枚：${v.id || cur.file.name}`),
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
    "一次上传 = 一整套模块：口令只有一串（绑的是这套的全集）、承诺只勾一次、签名只改一次、POST 只发一次。增删任一枚、改任一枚的模块 ID、给任一枚重选包，都会让那一串变成另一串 —— 改完要重新抄进签名。",
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
 * ① 公开索引里没有上传人 UID（build-index 的投影层故意不带）⇒ 只能说「这个 id 已被上传过」，
 *    **不能暗示归属** —— 说成「你投过了」或「别人投过了」都是猜；
 * ② 正在待审（pending/ 里、还没合进索引）的同 id 今天查不到 ⇒ 这一档拦不住，得后端加一档状态；
 * ③ 摘出之后口令那一串会变 —— 口令绑的是这套的全集，少一枚就是另一个前缀。
 */
const CHECK_EXTRA = {
  recorded:
    " 这一枚已经从本次上传里摘出去了：不进 manifest、不进口令那一串、也不提交。" +
    "摘出去之后屏幕上那一串口令就按剩下的那几枚重算 —— 已经抄进签名的那串要重抄一次。" +
    "它只看公开索引里的模块 ID：索引里不带酷安 UID，所以分不清「已被上传过」那一条是谁上传的；" +
    "还在审核里、没合进索引的上传今天查不到。想留着看就由你留着，队列里点「移除」。",
  version_update:
    " 这不是重复，所以它留在这一套里照常要上传 —— 只是「对已收录模块的版本更新」不会被自动合进索引。",
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
  const r = await checkModulesBatch(list.map(({ id, versionCode }) => ({ id, versionCode })));
  state.checkVia = r.via;
  if (r.via !== "batch") {
    // 批量那一条没走通 ⇒ 回到逐枚那一条。原因留着给清单与说明页说（不假装查过）。
    state.checkWhy = r.why || "";
    for (const row of list) scheduleCheck(row.card, 0);
    return;
  }
  for (const row of list) {
    if (!state.cards.includes(row.card)) continue;
    const status = r.statuses.get(row.id);
    // 后端没给这一枚的结论 == 这一枚没查到，不等于「没被投过」：交回逐枚那一条再问一次。
    if (!status) {
      scheduleCheck(row.card, 0);
      continue;
    }
    setCheck(row.card, status, checkKeyOf(row.id, row.versionCode), "");
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
  const isActive = card === activeCard();
  if (!id || !/^\d+$/.test(code)) {
    setCheck(card, null, "", "");
    if (isActive) $("#check").hidden = true;
    return;
  }
  const key = checkKeyOf(id, code);
  if (card.checkStatus && card.checkKey === key) {
    if (isActive) renderCheck();
    return; // 这一对 (id, versionCode) 已经查过了，切回来不再打一次
  }
  card.checkRun = key;
  card.checkWhy = "";
  if (isActive) showCheck("idle", "checking", "正在查重…", `检查 ${id} 是否已在公开索引里。`);
  renderQueue();
  let status = null;
  let why = "";
  try {
    status = await checkModule(id, code);
  } catch (err) {
    why = err instanceof BackendError ? err.message : "查重请求失败，不影响你继续上传。";
  }
  // 这一枚在等回包期间被移除了就什么都不做；结论落卡，视图只在租约还在时跟着动。
  if (!state.cards.includes(card)) return;
  setCheck(card, status, key, why);
  if (isActive) {
    if (status) {
      const meta = CHECK_STATUS[status];
      showCheck(
        meta.tone === "ok" ? "ok" : meta.tone === "warn" ? "warn" : "muted",
        meta.label,
        meta.title,
        meta.hint + (CHECK_EXTRA[status] || "")
      );
    } else {
      showCheck("warn", "未确认", "现在查不了重", why);
    }
  }
  renderQueue();
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
    meta.hint + (CHECK_EXTRA[status] || "")
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
  // 口令文本是 (id, 整包 sha256, nonce) 的派生值，id 一动就得重算 —— 与查重同一个触发点。
  // 另一个来源（包）在 intake 里到货，那里算完哈希自己再渲染一次。
  fieldEls.id.addEventListener("input", renderProof);
  fieldEls.coolapkUid.addEventListener("input", () => {
    // 「这个昵称属于上一串 UID」在按键那一刻就已经成立，等不到 debounce 后的核实结果
    syncUploaderField();
    runUidCheck();
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
  // 不是「你不是本人」，所以放行 —— 口令成不成由 Worker 判，前端不加第二道闸。
  return false;
}

/* 口令只在「UID 核实通过」那一刻拿到随机段（赋值集中在 setNonce 这一个函数里：核实通过补空缺、
   口令烧掉换串两个调用点），所以这条没过时，
   原因可能在站点这边（核实根本没接），也可能在流程还没走完（正在查 / 还没查）。两者写成同一句
   「口令没生成」，被拦住的人就只剩一个说不清为什么的坏按钮 —— 状态文案必须说清卡在谁手上。
   随机段就位之后还差两个来源：模块 ID 和整包 sha256。口令串绑的是它们三个（设计文档 §14.1），
   所以哈希没算完的那一刻不能说「已生成」—— 那时屏幕上还没有可抄进签名的一串。
   注意这里改的全是说明文字：ok 只看 Boolean(state.nonce)，前端不加第二条闸，判定在 Worker。
   说明文字一律先说「还差什么」再说已有什么 —— 底栏那句「全部就绪」也由这些句子代写，
   口令还没出现在屏幕上时它不许说就绪（见 refreshGate 里那段 shown）。 */
const NONCE_WHY = {
  off: "后端没配置酷安身份核实，口令生成不了 —— 上传通道未开放，这一步要站点来接",
  self_reported: "后端收到了 UID 但没核实它，口令生成不了 —— 上传通道未开放，这一步要站点来接",
  unavailable: "这次没核实成，口令还没生成 —— 把 UID 重敲一遍会再查；一直不通是后端没接上核实",
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
  // 现在算不出口令」，所以底栏那句「全部就绪」与下面那条清单都得跟着这同一个判据走 ——
  // 判据只有一份，不在这里另发明第二条闸（按钮的 enable 条件一个字不动）。
  const idsInSet = targets.map((c) => cardValues(c).id).filter(Boolean);
  const dupId = new Set(idsInSet).size !== idsInSet.length;
  const metaBad = targets.filter((c) => {
    const v = cardValues(c);
    return metaKeys.some((k) => !v[k]) || (v.versionCode && !/^\d+$/.test(v.versionCode));
  });
  const overCount = overModuleCount(targets.length);
  const overTotal = overTotalBytes(targets);

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
        // 「这条不拦你」只说自己这一条，不承诺整张清单放行 —— 核实没成时口令也不会有，
        // 于是下一条才是真正按住按钮的那条。两句并排时必须各说各的范围，否则互相打脸。
        : "酷安用户核实（这一条不拦你；口令要核实通过才生成）";
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
  if (spent && !targets.length) {
    // 这一套已经提交掉了（每一枚都拿到回执）：口令在服务端记过账了，再发只会回一句「用过」。
    // 随机段在成功那一刻就换过了，所以这里说的不是「你不能再用这一串」，而是「这一套已经交了」。
    items.push({
      ok: false,
      text: `${namesOf(acked)} 已经随这一次上传提交掉了（PR 已开）—— 同一套不能连发两次；要上传别的包就再选一批进来。`,
    });
  } else {
    const card = activeCard();
    const proofId = fieldValue("id");
    let nonceText;
    if (!state.nonce) {
      nonceText =
        NONCE_WHY[state.uidStatus] ||
        "上传口令还没生成 —— UID 核实通过、填上模块 ID、包也选好了，这一串才出现";
    } else if (recorded.length && !targets.length) {
      nonceText = "这一套里没有要上传的枚了：都被「已被上传过」那一档摘出去了，所以没有口令可生成，签名里也不用抄任何东西。";
    } else if (!proofId && card && !isRecorded(card)) {
      nonceText = "口令还差：填上模块 ID —— 随机段已生成，但这一串要模块 ID 和整包哈希才算得出";
    } else if (incomplete.length) {
      // 两句各说一个来源缺哪一样：没选包是「还没得选」，选了包是「正在算 / 没算出来」。
      // 都不写「正在算」的肯定语气 —— 算失败时那句话就成假话了。
      const noZip = incomplete.filter((c) => !c.zip);
      const noSha = incomplete.filter((c) => c.zip && !c.zipSha);
      nonceText = noZip.length
        ? "口令还差：还没选包 —— 口令绑的是这套的字节，先把包选上，这一串才算得出来"
        : noSha.length
        ? `口令还差：整包哈希还没算完 —— 随机段已生成，这一串要等它（稍等会自己出现；一直没出现就给${namesOf(noSha)}重选一次包）`
        : `口令还差：${namesOf(incomplete)} 的模块信息没齐 —— 口令是按整套算的，少任何一枚的信息就没有可抄的一串`;
    } else if (dupId) {
      // 三个来源都在，但这一套的形状本身算不出串：两枚模块 ID 相同 ⇒ canonicalProofSet 抛。
      // 这一句必须存在，否则下面那句「共用一串口令已生成」就成了屏幕上的一句假话。
      nonceText =
        "口令还差：队列里有两枚的模块 ID 是同一个 —— 同一套里同一个 ID 出现两次时这一串算不出来" +
        "（服务端也会按 manifest 形状不对拒掉整个这一次上传），把其中一枚移掉或改成别的 ID";
    } else {
      nonceText = state.cards.length > 1
        ? `这一套 ${targets.length} 枚共用一串口令已生成（填进酷安签名，只改这一次）`
        : "上传口令已生成（填进酷安签名）";
    }
    // shown 说的是「屏幕上现在有没有一串可抄进签名」。v2 那一串的来源是「整套的 (id, 整包 sha256)」
    // 加这一枚随机段，所以当前这枚少 id 或少哈希时屏幕上根本没有可抄的东西 —— 那一格不许自称就绪。
    // 集合形状不对（两枚同一个模块 ID）时同样没有：renderProof 那时候画的是「算不出口令」那一行，
    // 而下面这格还在说「已生成」—— 那就正是这条钉子要抓的现场。
    // 它不参与 ready，也就不参与按钮 —— 全局约束是前端不加第二条闸，判据在 Worker。
    // 它只改底栏那两句：少一个来源时那里写的是这一条的实话，而不是「全部就绪，可以确认」。
    items.push({
      ok: Boolean(state.nonce),
      shown: Boolean(state.nonce && proofId && state.zipSha) && targets.length > 0 && incomplete.length === 0 && !dupId,
      text: nonceText,
    });
  }
  items.push({ ok: IS_API_CONFIGURED, text: "后端 API_BASE 已配置" });
  if (recorded.length) {
    // 早期重复拦截：这几枚已经被摘出这一套 —— 不进 manifest、不进口令那一串、也不提交。
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
        `口令那一串按剩下的 ${targets.length} 枚算（所以摘之前抄进签名的那串要重抄一次）；` +
        `这道闸分不清是谁上传的，也查不到还在待审的那一份。`,
    });
  }
  if (state.cards.length > 1) {
    // 队列读数与「这一套有几枚」必须是同一个判据（submitTargets）：说 3 枚就得真在 manifest 里
    // 写 3 条、真发 3 个 file part、口令真按 3 枚算 —— 差一枚就是界面在骗人。
    const n = submitTargets().length;
    items.push({
      ok: true,
      shown: n > 0,
      text: n
        ? `队列里本次要上传 ${n} 枚 —— 一整套一次提交：口令一串、签名改一次、POST 发一次`
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
  // 底栏那句「全部就绪」必须是真话。清单里那条口令行自己不拦人（ok 为真、按钮照常亮），
  // 但屏幕上还没有一串可抄进签名的东西 —— 这时候说就绪就是把假话写在了最显眼的地方。
  // 所以这里排在 firstBad 之后、成功语之前插一段「还差什么」，enable 条件一个字没动。
  const firstNotShown = firstBad ? null : items.find((i) => i.ok && i.shown === false);
  const blocking = firstBad || firstNotShown;
  $("#dock-t").textContent = blocking ? blocking.text : "全部就绪，可以确认";
  $("#dock-s").textContent = blocking ? "还差这一步" : "点「去确认」勾完四项";
  $("#gate-note").textContent = ready && !firstNotShown ? "四项上传前确认还没勾" : "先把上面几项填齐";
  if (state.attempted) paintFieldErrors();
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
  const chipEl = $("#uid-chip");
  chipEl.textContent = chip;
  chipEl.className = `chip${tone === "bad" ? " chip--bad" : tone === "ok" ? " chip--ok" : tone === "warn" ? " chip--warn" : tone === "idle" ? " chip--idle" : ""}`;
  const img = $("#uid-avatar");
  if (avatar) {
    img.src = avatar;
    img.hidden = false;
    img.addEventListener(
      "error",
      () => {
        img.hidden = true;
      },
      { once: true }
    );
  } else {
    img.hidden = true;
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
 * 这一套的口令来源：每一枚的 (模块 ID, 整包 sha256)，加那一枚共用的一次性随机段。
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

/** 这一套现在能不能算出口令：每一枚都得有 id 与整包哈希，少一枚都算不出那一串。 */
function setSources() {
  const targets = proofTargets();
  return {
    targets,
    items: targets.map((t) => ({ id: t.id, zipSha: t.zipSha })),
    incomplete: targets.filter((t) => !t.id || !SHA256_HEX_RE.test(String(t.zipSha || ""))),
    nonce: state.nonce,
  };
}

// 派生显示：口令 = sha256("sukisu-proof-v2:" + 规范串) 前 12 位 + "-" + 那一枚随机段，
// 每次都在这里现算整套的来源，屏幕上那一串永远跟着队列里当前这几枚的 id 与字节走 ——
// 缓存派生值迟早和来源脱钩，而「换了包还拿着旧口令抄」正是这条闸要封死的那件事。
// v2 的规范串按 **id 升序（同 id 再按整包哈希升序）**排，与用户选的次序无关（§15）：
// 前端按选的次序、Worker 按 multipart 到达的次序，两边不同序就会算出两个前缀，
// 而「对不上」在那条闸里读起来跟「你不是本人」一模一样。
async function renderProof() {
  const box = $("#proof-field");
  const id = fieldValue("id");
  const zipSha = state.zipSha;
  const nonce = state.nonce;
  const set = setSources();
  if (!nonce || !set.targets.length) {
    // 随机段来自 UID 核实，没有它就没有任何一串；整套是空的也没有可绑的东西。整格收起。
    box.hidden = true;
    $("#proof-cap").textContent = "";
    return;
  }
  if (!id || !zipSha) {
    // 当前卡这两个来源少任何一个，就没有属于这一枚的那一份 ⇒ 那一串算不出来。
    // （别的枚齐不齐不影响这一句：口令绑的是全集，少一枚就没有串。）
    if (!set.items.length) {
      box.hidden = true;
      $("#proof-cap").textContent = "";
      return;
    }
  }
  // 来源一动就得当场把那一行抹掉，不等下面 await 回来换串 ——
  // 那几十毫秒里屏幕上挂着一串属于上一个 id / 上一个包的口令，正是这条闸要封死的那件事。
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
      bad = `这一套现在算不出口令：${(err && err.message) || "集合形状不对"}`;
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
    // 于是那一行一定被抹掉，屏幕上不会留一串属于别的集合的口令。
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
    row.append(node("span", "proof__pending", bad || "这一套现在还算不出口令。"));
  }
  list.append(row);

  // 口令绑的是这一套的全集 ⇒ 必须把这 N 枚点名出来，否则「这一串顶的是哪几枚」没人知道，
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
    "这一串就变成另一串，要重新抄进签名并保存；签名里还是旧的那串时，服务端会按「签名里没有本次口令」拒。";
  box.hidden = false;
}

const runUidCheck = debounce(async () => {
  const uid = fieldValue("coolapkUid");
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
  state.uidStatus = "checking";
  showUid("idle", "checking", "正在核实酷安用户…", `查询 UID ${uid} 是否对应一个真实账号。`);
  refreshGate();

  const result = await lookupCoolapkUser(uid);
  // 用户在你等回包的时候又改了 UID，就别把旧结果贴上去
  if (fieldValue("coolapkUid") !== uid) return;
  state.uidStatus = result.status;
  // 核实通过才发随机段，而且**一次上传一份**：这一整套共用一串口令（v2 绑的是全集）。
  // 一枚一份是 v1 的形状，那时 N 枚要 N 条不同口令、N 次各自带凭据的 POST。
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
  renderProof(); // 第一次核实通过才生成 nonce，口令行到这一步才有东西可显示
  refreshGate();
}, 500);

/* --------------------------------------------------------- 上传前确认逻辑 */

let lastFocus = null;

function openConfirm() {
  const { zipOk } = collect();
  const targets = submitTargets();
  if (!zipOk || !IS_API_CONFIGURED || !targets.length) return;
  commitView();
  lastFocus = document.activeElement;
  const layer = $("#layer-confirm");
  layer.hidden = false;
  layer.classList.add("is-open");
  document.body.style.overflow = "hidden";
  $$("#layer-confirm input[type=checkbox]").forEach((c) => (c.checked = false));
  $("#confirm-go").disabled = true;
  $("#confirm-go").textContent =
    targets.length > 1 ? `确认并上传这一整套（${targets.length} 枚）` : "确认并上传";

  const sum = $("#warn-sum");
  sum.textContent = "";
  // 一次动作只有一个人、一个承诺、一枚口令 —— 这三样在整套之上，逐枚列就是把它们说成 N 份。
  const shared = [
    ["上传人酷安昵称", fieldValue("uploader")],
    ["酷安 UID", uidLine()],
    ["口令的随机段", state.nonce || "（还没生成）"],
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
  // 口令是提交前最后一道能核对的东西：整套就这一串，列一次，别让人以为还要逐枚抄。
  const proofVal = node("b", null, "…");
  const proofLine = node("div", "warn__proof");
  proofLine.append("这一整套共用的口令: ", proofVal);
  sum.append(proofLine);
  proofTextOf().then((t) => {
    proofVal.textContent = t || "这一套还差来源（某一枚的模块 ID / 整包哈希 / 随机段），现在没有可抄的一串";
  });
  const rec = state.cards.filter((c) => isRecorded(c));
  if (rec.length) {
    sum.append(
      node(
        "p",
        "warn__queue",
        `队列里另有 ${rec.length} 枚（${namesOf(rec)}）被「已被上传过」那一档摘出了：它们不进这一次提交，` +
          "口令那串里也没有它们。要留着看就留着，要重新上传就先移除再重选包。"
      )
    );
  }
  $("#confirm-back").focus();
}

/**
 * 上传前确认那一格要说清这一整套用的是哪一串：口令是「整套的 (id, 整包 sha256) 集合 + 随机段」
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
 * 派生的口令串不发：后端自己按这一套重算，前端这份只用来显示。
 *
 * 逐枚那四样（zip / id / name / version / versionCode / author / description / source + sha256）
 * 进 manifest 的 `modules[]`；共享那几样（uploader / coolapkUid / pledge / nonce / turnstile）
 * 留在顶层 —— 一次上传只有一个人、一个承诺、一枚口令，这是 §17.3 的分工，不是排版偏好。
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
        // 闸前移之后这一枚的声明值就是口令前缀的输入之一（§16 第 1 句），所以它**必须有**：
        // 缺任何一枚的 sha256，api.js 那一层直接不发这个请求（发出去也必然是 manifest_invalid）。
        // 落盘口径不在这里 —— 服务端逐枚实算，公开记录里只落实算那一份。
        sha256: card.zipSha,
      };
    }),
    uploader: fieldValue("uploader"),
    coolapkUid: fieldValue("coolapkUid"),
    // 承诺文本的版本号：一次整套勾一次那四条，所以它是顶层那一个字段，不逐枚重复。
    pledge: "pledge-v1",
    // 口令的随机部分：一次上传一份，覆盖这一整套。派生串不在这里算 —— 后端自己重算。
    nonce: state.nonce,
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
 * 提交**这一整套**：一次 POST、一个 manifest、N 个 zip、一串口令、一个 PR。
 * 语义是「全有全无」（§15 第 3 条已拍）：任一枚不过 ⇒ 整单拒、零 GitHub 写入、口令不烧。
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
    const { pr, modules } = await submitContribution(payload, {
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
    // 逐枚回执按 id 落回各自的卡：应答里那个 sha256 是**服务端实算**的那一份（§16 第 3 句），
    // 落在卡上上传人才拿得到「我这个字节被算成了什么」，而不是只对着一句「已受理」。
    const acked = new Map();
    for (const m of modules || []) if (m && typeof m.id === "string") acked.set(m.id, m);
    for (const entry of payload.modules) {
      const card = state.cards.find((c) => c.key === entry.card);
      if (card) card.ack = acked.get(entry.id) || { id: entry.id };
    }
    // 这一次成功了 ⇒ 这一串口令在服务端记过账了（用过即废）。随机段当场换掉：
    // 留着它，下一套（新选的包）会拿一串已经烧掉的口令去提交，永远回同一句「用过」。
    if (state.nonce) setNonce(makeNonce());
    showSuccess(state.batchResult);
  } catch (err) {
    state.batchResult = { ok: false, reason: failReason(err), code: errCode(err), owner: errOwner(err) };
    showFailure(err);
  } finally {
    state.uploading = false;
    renderQueue();
    // 提交掉的那一套不该再出现在口令那一格里：那串已经在服务端记过账了，
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
  // 可能已经被换掉/移除，那时发出去的集合与口令那串不是同一套（闸前移之后声明进判据，
  // 这种错位就是 sha_mismatch / batch_incomplete 的来源）。凑不齐就回表单去，不硬发。
  const targets = submitTargets();
  if (!targets.length) {
    closeRun();
    openConfirm();
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
  for (const text of [
    "点进 PR 能看到审核进度，以及这一整套每一枚的完整元数据。",
    "新模块若未命中拦截名单可能自动通过；对已收录模块的版本更新不会自动合入，本站没有人工放行这一格。",
    "PR 合并之后，这些模块才会出现在公开索引里，所有人才能在管理器里搜到并一键安装。",
    "这一串口令已经随这一次上传记账了（用过即废）。要再上传别的包，页面会给你新的一串 —— 签名要再改一次。",
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
 * 服务端只有两种说法意味着这一串口令真的被烧掉了：用过它，或者它可能已经变成了一条上传。
 * 只有这两种才重掷随机段。其余失败（400 字段问题、403 平台侧读不出记录）不轮换 ——
 * 口令绑包体之后重试同一个口令是有效的（Task 9），无故轮换等于让用户白抄一次签名。
 *
 * 判据首选机器可读的失败码：Worker 已给「口令已用过」这条回 `code: "proof_used"` —— 就写在
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

/** 这一串口令是不是真的被烧掉了：码优先，文案兜底。 */
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
        `口令也没被烧掉。所以${n > 1 ? `这 ${n} 枚` : "这一枚"}要么一起上线、要么一起还留在你手上 —— 页面上不会出现「一半传上了」那种状态。`
    )
  );

  let proofRotated = false;
  if (proofWasSpent(err, reason)) {
    // 这一串确实烧掉了：重掷那**一份**随机段（整套就一份），口令行现算新的一串，清单跟着刷新。
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
        "口令换了一串 —— 表单里「上传口令」那一行现在是新的，上一串已经作废。" +
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
  renderProof(); // nonce 清空后这一行跟着收起，别留一串还能提交的旧口令在屏幕上
  syncUploaderField(); // 顺手把 readOnly / 标签 / 说明一起还原，别留一个锁着的空框
  $$(".field").forEach((f) => f.classList.remove("is-bad", "is-pre"));
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
      why.href = `#/incidents?q=${encodeURIComponent(q)}`;
      shell.append(why);
      return;
    }
    shell.append(node("p", null, "没找到不等于没被上传过 —— 查重以模块 ID 为准。确认自己手上的包还没收录的话，可以直接上传。"));
    const go = node("a", "btn btn--go btn--sm", "去上传");
    go.href = "#/submit";
    shell.append(go);
    // 台账没查过才去查一次：查回来之后这条空态可能升级成「命中了一条处置」。
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
  // 举报从「就是这一枚」这一格进去：带着 id 与 versionCode，口令的两个来源就不用用户手打。
  if (latest && SHA256_HEX_RE.test(String(latest.sha256 || ""))) {
    const rep = node("a", "mod__rep", "举报这一枚");
    rep.href = `#/report?id=${encodeURIComponent(m.id)}&vc=${encodeURIComponent(latest.versionCode)}`;
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
  // 索引是口令的来源之一：它晚到一步，04 那一屏上「算不出口令」那句就得当场改口。
  if (parseHash().name === "report") refreshReportForm();
}

/* ------------------------------------------------------- 04 举报（已上架的模块）
   这条路的硬门槛只有一句：实名 + 在包里逐字定位到。判据全在服务端（worker 的 handleReport），
   页面只做两件谁都不肯替它做的事：把「实名」那一串口令算出来给人抄进签名，以及把两种相反的
   失败分开说 —— 「你引用的那段不在包里」（要他改材料）与「这个包我们读不出来」（要我们补能力）。
   一次成功的举报会烧掉签名里那一串口令（用过即废），所以口令的三个来源任何一动都必须重算。 */

const report = {
  nonce: "",
  evidence: [""],
  busy: false,
  result: null,
  /** 服务端那一次的原文（过码表之后）。它活到下一次提交为止 —— 否则重画一次就把人刚看到的那句擦了。 */
  error: "",
};

/** 被举报的那一枚：口令绑 (id, 索引里那一版的 sha256)，这一格算不出来就没有可提交的口令。 */
function reportTarget() {
  const id = $("#rp-id").value.trim();
  if (!id) return { ok: false, why: "还没填模块 ID：口令那一串绑的就是那一枚的 id 与包体 sha256。" };
  if (!state.index) {
    return { ok: false, why: "公开索引还没读出来。口令要绑的那串 sha256 只在索引里，读不到就算不出那一串。" };
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
    return { ok: false, why: "索引里那一枚没有 64 位的包体 sha256，口令算不出来 —— 本站索引的问题，你不需要改任何东西。" };
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
  //   ① 本地能判的形状问题（引用太短）② 口令来源不齐（索引给不出那一枚）③ 服务端那一次的原文。
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

/** 口令那一串：派生值，每次渲染现算 —— id / 那一版 / 换过的 nonce 任一动，串就换。 */
function paintProof(target) {
  const list = $("#rp-proof-list");
  list.textContent = "";
  const help = $("#rp-proof-help");
  if (!target.ok) {
    help.textContent = "口令还差：上面那一格说清了差的是哪一件。";
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
}

async function submitReport() {
  if (report.busy) return;
  const target = reportTarget();
  if (!target.ok) return;
  const quotes = report.evidence.map((q) => q.replace(/\r/g, "")).filter((q) => q.trim());
  report.busy = true;
  report.error = "";
  $("#rp-submit").disabled = true;
  $("#rp-readout").textContent = "正在提交：服务端要读一次索引、取一次归档，再在你签名的那一串里核对口令。";
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
    // 受理之后就换一串：口令用过即废，同一串再发一次只会撞「已用过」那一句。
    report.nonce = makeNonce();
    paintReportResult();
    $("#rp-readout").textContent = json.established
      ? "这条举报成立并记下了待办；公开索引这一刻还没动。下架由本站的自动流程按批提出（没有人工签字那一步），" +
        "排到哪一格看「处置公示」那一页顶部的队列读数 —— 那一格没显示数字就是读数还没到位，不等于没受理。"
      : "这条举报没有成立，但同样留下了待办记录；下面那句是服务端给的下一步。";
  } catch (err) {
    report.result = null;
    paintReportResult();
    report.error = err instanceof BackendError ? err.message : `这一发没打出去：${String((err && err.message) || err)}`;
    $("#rp-readout").textContent = "这次举报没有受理。它没消耗你的口令 —— 签名不用改，改完下面那一句说的那件事再来一次。";
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
    if (parseHash().name === "incidents") renderIncidents();
  }, 140);
  input.addEventListener("input", apply);
}

/* ------------------------------------------------------------- 处置公示 */

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

  const ft = node("div", "mod__ft");
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
    ["证据（by）", "新版是一枚机器章：`ci:audit@<提交>`，写的是这条处置被哪一次运行钉死，旁边那条复核命令任何人都能重跑一遍。它不是链接 —— 章里不带仓库地址，硬拼一个点得开的地址就是这一页在替它编一个它并不知道的去向。main 上还有换代前留下的记录，那一类的 by 是一条能点开的评论，照旧给链接。两种形状都认，因为只认新的那一种会把已经发生过的处置念成「没有证据」。形状不对的指针原样显示成文本。这一页显示的就是台账原文，判定发生在索引推导与 CI 里，前端不另判一份。"],
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
 * 台账条目带 `subject`，历史条目（v1）没有这个键，它们只出现在按条那一层，
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
  if (!ev) box.append(node("p", "ec__miss", "这一条没有固化过的证据文件：页面上这些格子只剩台账自己写的那几个选择器。"));
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
    /* 「验证方式」那一格要说人话：pending 里存的是机器可读码 —— `bio` 是今天那条单枚口令（v1），
       `bio-set` 是 §15/§16 那套「一次上传共用一串集合口令」。把 `bio-set` 原样印到公示页，
       读者只会当成一个没见过的错误码，而这一格存在的意义正是让人核对「凭什么说这是你」。
       未知值不编说法：原样印出来并标一句不认识 —— 新值出现的正确反应是改这张表，
       不是让页面替后端猜一个听起来合理的解释。 */
    const VIA_LABELS = {
      bio: "酷安个性签名（单枚口令 v1）",
      "bio-set": "酷安个性签名（整套共用一串口令 v2）",
    };
    const viaRaw = own && own.via ? String(own.via) : "";
    const viaText = !viaRaw
      ? "没写"
      : VIA_LABELS[viaRaw] || `${viaRaw}（不认识的验证方式，原样列出）`;
    left.append(kvRow("ec__kv--1", [
      ["承诺文本", pledge && pledge.version ? String(pledge.version) : "没写版本", ""],
      ["承诺时刻", pledge && pledge.atMs ? fmtDate(msOf(pledge.atMs)) : "没写", ""],
      ["所有权证明前缀", own && own.proofPrefix ? String(own.proofPrefix) : "没写（这条早于口令方案）", ""],
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
    host.append(node("p", "pc-wall__none", "这份台账里还没有任何一条处置带 `subject`（按人聚合的键）—— 所以下面按条那一层就是全部。带 subject 的条目由 §8 固化那一步填进来，不是这里能补的。"));
    return { people: 0, unkeyed };
  }
  const hd = node("div", "pc-wall__hd");
  hd.append(node("span", "pc-wall__t", `被处置的人 · ${people.length} 个`));
  hd.append(node("span", "pc-wall__s", unkeyed ? `另有 ${unkeyed} 条处置没有身份键，只在下面按条那一层列出` : "台账里每一条都聚进了这张墙"));
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
  // 队列那一格独立于台账：它说的是「下架那条链还在不在动」，而台账读失败的时候恰恰最需要这句话。
  // 放在最前面，是为了让下面那几条 early return（没配台账地址 / 台账读失败 / 正在加载）都不把它一起带走。
  loadReportQueue();

  const clear = () => {
    list.textContent = "";
    count.textContent = "";
    // 人卡那一层与展开的详情跟着一起清：留着就会出现「台账读不到但墙上还挂着两个人」，
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
    readout.textContent = "台账地址还没确定 · 公示页暂时读不到数据";
    readout.classList.add("bad");
    shell.hidden = false;
    shell.textContent = "";
    shell.append(node("div", "empty__t", "处置台账的地址来自公开索引地址"));
    shell.append(
      node(
        "p",
        null,
        "这一页直接读索引仓库里的 json/dispositions.json，路径按 config.js 的 INDEX_URL 同目录推导。索引地址填好之后这里就有内容；台账为空时它会明说「目前没有任何处置记录」。"
      )
    );
    const go = node("a", "btn btn--ghost btn--sm", "看看这个站现在接了什么");
    go.href = "#/about";
    shell.append(go);
    return;
  }

  if (state.ledgerError) {
    clear();
    readout.textContent = "处置台账读取失败";
    readout.classList.add("bad");
    shell.hidden = false;
    shell.textContent = "";
    shell.append(node("div", "empty__t", "拉不到处置台账"));
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
    readout.textContent = state.ledgerLoading ? "正在读取处置台账…" : "正在读取处置台账…";
    shell.hidden = false;
    shell.textContent = "";
    shell.append(node("div", "empty__t", "读取中"));
    loadLedger();
    return;
  }

  shell.hidden = true;
  const { items, lastUpdate, schemaKnown } = state.ledger;
  readout.classList.remove("bad");
  // 同上：台账日期包 .nb 不拆行
  readout.replaceChildren(
    `${items.length} 条处置记录`,
    ...(lastUpdate ? [" · 台账更新 ", node("span", "nb", fmtDate(lastUpdate))] : []),
    ...(schemaKnown ? [] : [" · 这份台账的 schema 标记本页不认识，按原文列出"])
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
  // 空台账时「0 条 / 共 0」是噪声，下面那句空态说得更清楚
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
          "空的台账是正常状态：还没有内容被下架或拒收过。这一页存在的意义是「处置必须留痕且公开」，所以它什么时候有东西，取决于什么时候真的出过事。"
        )
      );
      return;
    }
    shell.append(node("div", "empty__t", `台账里没有匹配「${q}」的记录`));
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
    if (!REASON_LABELS[key]) hd.append(node("span", "chip chip--warn", "台账里有本页不认识的分类"));
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
      err instanceof BackendError ? err.message : "处置台账读取失败，可能是网络或格式问题。";
  }
  state.ledgerLoading = false;
  if (parseHash().name === "incidents") renderIncidents();
  // 浏览页那句「搜不到但台账里有」依赖台账，到货后重画一次
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
      k: "处置台账（公示页数据源）",
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
        "前端发的是 §17.3 那份 manifest + N 个 name=\"zip\" 的 file part（manifest 排第一个 part），口令走 v2 集合串。" +
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
  if (parseHash().name === "report") renderReport();
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

  if (IS_TURNSTILE_CONFIGURED) {
    const slot = $("#turnstile-slot");
    slot.hidden = false;
    slot.textContent = "下面完成人机校验后才能提交。";
    loadTurnstile();
  } else {
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
  renderQueue(); // 一开始是空队列：整条收起，上传页与今天一模一样
  renderAbout();
  renderRoute();

  $("#form").addEventListener("submit", (e) => e.preventDefault());
}

function loadTurnstile() {
  const s = document.createElement("script");
  s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
  s.async = true;
  s.defer = true;
  document.head.append(s);
  const holder = node("div");
  holder.id = "turnstile-widget";
  $("#turnstile-slot").append(holder);
  const wait = setInterval(() => {
    if (!window.turnstile) return;
    clearInterval(wait);
    window.turnstile.render(holder, {
      sitekey: CONFIG.TURNSTILE_SITEKEY,
      callback: (token) => {
        state.turnstileToken = token;
      },
    });
  }, 200);
}

init();
