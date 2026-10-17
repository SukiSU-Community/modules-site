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
  checkModule,
  submitModule,
  fetchIndex,
  fetchServiceLimits,
  fetchDispositions,
  fetchEvidence,
  evidenceUrlFor,
  dispositionsUrl,
  byLink,
  KIND_LABELS,
  REASON_LABELS,
  SELECTOR_LABELS,
  lookupCoolapkUser,
  isCoolapkUid,
  normalizeCoolapkUrl,
} from "./api.js";
import { canInflateRaw, listEntries, readEntry, inspectEntries } from "./zipread.js";
import { parseModuleProp } from "./moduleprop.js";
import { buildProofString, makeNonce, sha256HexBytes } from "./proof.js";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const MB = 1024 * 1024;

const PREFILL_KEYS = ["id", "name", "version", "versionCode", "author", "description"];
const REQUIRED_KEYS = ["id", "name", "version", "versionCode", "source", "uploader", "coolapkUid"];

const state = {
  file: null,
  zip: null, // { arrayBuffer, entries, inspect, prop }
  checkStatus: null,
  uidStatus: "idle", // idle | checking | off | verified | not_found | unavailable | self_reported | invalid
  uidInfo: null, // { uid, nickname, avatar }
  nonce: "", // 所有权口令的随机部分
  // 整包 sha256 = 用户选中的那个文件的全部字节的 SHA-256（与 Worker ⑤-c 的 computedSha 同口径）。
  // 口令的两个来源是 nonce 与 zipSha 这两个**值本身**；那串文本永远由
  // buildProofString(id, zipSha, nonce) 现算，缓存它就等于让展示串和来源脱钩。
  zipSha: "",
  // 上限由后端自报（api.js 的 fetchServiceLimits）；config.js 那份只是问不到时的兜底。
  maxBytes: CONFIG.MAX_UPLOAD_BYTES,
  maxBytesFrom: "config", // config | backend | unreachable | no-field
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
  lastFields: null,
  query: "",
  turnstileToken: "",
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
for (const key of [...PREFILL_KEYS, "source", "uploader", "coolapkUid"]) {
  fieldEls[key] = $(`[data-k="${key}"]`);
}
const fieldValue = (key) => (fieldEls[key] ? fieldEls[key].value.trim() : "");

/* ------------------------------------------------------- 路由：hash 三视图 */

const VIEWS = {
  submit: { el: "#view-submit", label: "投稿" },
  index: { el: "#view-index", label: "已收录" },
  incidents: { el: "#view-incidents", label: "处置公示" },
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
    // 从投稿页/浏览页跳到公示页时带的是同一个词，两个过滤框都按它起头
    state.incQuery = state.query;
    $("#q-inc").value = state.query;
  }
  if (name === "index") renderIndex();
  if (name === "incidents") renderIncidents();
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

function clearFile() {
  state.file = null;
  state.zip = null;
  // 包没了，这一串口令的来源就少一个：整包哈希当场归零，口令行跟着收起。
  // 不在这里清的话，屏幕上会留着一串属于「已经不存在的那个包」的口令。
  state.zipSha = "";
  state.checkStatus = null;
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
  refreshGate();
}

function rejectFile(lines) {
  clearFile();
  termLines(lines);
}

async function intake(file) {
  if (!file) return;
  const out = [];
  state.file = file;
  state.zip = null;
  // 派生值在来源换掉的那一刻就得死：这里如果等到下面解析完才归零，读 B 的整段期间
  // 屏幕上挂的还是 A 的口令、门禁写着「已生成」，此时点提交就是 zip:B + sha256:A。
  // 同步清完立刻重画，B 的哈希到货前界面上说的是「还没选包」这句实话。
  state.zipSha = "";
  renderProof();
  refreshGate();

  const limit = state.maxBytes;
  out.push([null, `读取 ${file.name} · ${fmtBytes(file.size)}`]);

  if (!/\.zip$/i.test(file.name)) {
    rejectFile([["miss", "这不像 zip 文件（扩展名不是 .zip）。管理器只认 zip，请先确认下载完整。"]]);
    return;
  }
  if (file.size > limit) {
    rejectFile([
      out[0],
      ["miss", `超过上限：${fmtBytes(file.size)} > ${fmtBytes(limit)}`],
      ["warn", "服务端会直接拒绝。如果确实是正常模块，压缩包里多半混进了无关的大文件。"],
    ]);
    return;
  }

  let arrayBuffer;
  try {
    arrayBuffer = await file.arrayBuffer();
  } catch {
    rejectFile([out[0], ["miss", "文件读不出来，可能已经不在原来的位置了。重新选一次。"]]);
    return;
  }

  // 解析回来的这一刻可能已经晚了：intake() 不串行，连着换两个包时两次解析会重叠，而下面那句
  // state.zip 赋值是无条件的。比的是**这一次开始时选中的那个 file 对象**（intake 顶部刚把它记进
  // state.file），不是名字也不是大小：中途换过包、清过、或重开过投稿，就把这一次整条丢掉。
  // 不丢的话 state.zip 会指回旧包而 state.file 已是新包，旧包的摘要随后还能通过下面那道对象
  // 标识守卫贴到新包上 —— 屏幕上那一串就成了「新包的口令、旧包的字节」。
  if (state.file !== file) return;

  let entries;
  try {
    entries = listEntries(arrayBuffer);
  } catch (err) {
    rejectFile([out[0], ["miss", err.message]]);
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
    rejectFile(lines);
    return;
  }

  state.zip = { arrayBuffer, entries, inspect, prop: null };

  // 整包 sha256 是口令的第二个来源，每次换包都在这儿重算 —— 上一包的哈希对新包毫无意义。
  // 异步：几百毫秒内口令行按「还没算出来」显示（门禁说当时的实话），算完自己出现。
  // 算失败就留空：那一串根本不会显示，于是没人会抄一串对不上任何包的口令去填签名。
  const zipForThisFile = state.zip;
  state.zipSha = "";
  sha256HexBytes(arrayBuffer).then(
    (hex) => {
      // 认对象不认值：换过包（或已清掉）就别把上一个文件的哈希贴到当前这个包上。
      if (state.zip !== zipForThisFile) return;
      state.zipSha = hex;
      renderProof();
      refreshGate();
    },
    () => {
      if (state.zip !== zipForThisFile) return;
      state.zipSha = "";
      renderProof();
      refreshGate();
    }
  );

  out.push(["found", "module.prop @ root  校验通过"]);

  if (!canInflateRaw()) {
    out.push(["warn", "这个浏览器不支持前端解压，元数据请手填（表单照常可用）"]);
    termLines(out);
    refreshGate();
    runCheck();
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

  termLines(out);
  refreshGate();
  runCheck();
  renderProof(); // module.prop 把 id 预填进来的这一下不触发 input 事件，口令得自己重算一次
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
  input.addEventListener("change", () => intake(input.files && input.files[0]));
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
    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) intake(file);
  });
  // 没落在拖放区上的文件不能让整个页面被浏览器接管
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());
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

const runCheck = debounce(async () => {
  const id = fieldValue("id");
  const code = fieldValue("versionCode");
  if (!id || !/^\d+$/.test(code)) {
    state.checkStatus = null;
    $("#check").hidden = true;
    refreshGate();
    return;
  }
  showCheck("idle", "checking", "正在查重…", `检查 ${id} 是否已在公开索引里。`);
  try {
    const status = await checkModule(id, code);
    state.checkStatus = status;
    const meta = CHECK_STATUS[status];
    showCheck(
      meta.tone === "ok" ? "ok" : meta.tone === "warn" ? "warn" : "muted",
      meta.label,
      meta.title,
      meta.hint
    );
  } catch (err) {
    state.checkStatus = null;
    showCheck(
      "warn",
      "未确认",
      "现在查不了重",
      err instanceof BackendError ? err.message : "查重请求失败，不影响你继续投稿。"
    );
  }
  refreshGate();
}, 420);

function bindCheck() {
  for (const key of ["id", "versionCode"]) {
    fieldEls[key].addEventListener("input", runCheck);
  }
  // 口令文本是 (id, 整包 sha256, nonce) 的派生值，id 一动就得重算 —— 与 runCheck 同一个触发点。
  // 另一个来源（包）在 intake 里到货，那里算完哈希自己再渲染一次。
  fieldEls.id.addEventListener("input", renderProof);
  $("#proof-copy").addEventListener("click", async () => {
    const t = $("#proof-text").textContent;
    if (!t || t === "…") return;
    await navigator.clipboard.writeText(t);
    $("#proof-copy").textContent = "已复制";
    setTimeout(() => ($("#proof-copy").textContent = "复制"), 1500);
  });
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
      p.append("想先确认有没有人投过？", " ");
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

function collect() {
  const zipOk = Boolean(state.zip && state.zip.inspect.ok);
  const missing = REQUIRED_KEYS.filter((k) => !fieldValue(k));
  const badCode = fieldValue("versionCode") && !/^\d+$/.test(fieldValue("versionCode"));
  const badUid = fieldValue("coolapkUid") && !isCoolapkUid(fieldValue("coolapkUid"));
  const badSource = fieldValue("source") && !normalizeCoolapkUrl(fieldValue("source"));
  return { zipOk, missing, badCode, badUid, badSource };
}

function uidBlocked() {
  if (!IS_UID_VERIFY_ON) return false;
  if (state.uidStatus === "not_found" || state.uidStatus === "invalid") return true;
  // 只有「查无此人」和「UID 形状不对」算不是本人。核实没接上 / 酷安抖动是「平台没核实成」，
  // 不是「你不是本人」，所以放行 —— 口令成不成由 Worker 判，前端不加第二道闸。
  return false;
}

/* 口令只在「UID 核实通过」那一刻拿到随机段（runUidCheck 里那一行是唯一赋值点），所以这条没过时，
   原因可能在站点这边（核实根本没接），也可能在流程还没走完（正在查 / 还没查）。两者写成同一句
   「口令没生成」，被拦住的人就只剩一个说不清为什么的坏按钮 —— 状态文案必须说清卡在谁手上。
   随机段就位之后还差两个来源：模块 ID 和整包 sha256。口令串绑的是它们三个（设计文档 §14.1），
   所以哈希没算完的那一刻不能说「已生成」—— 那时屏幕上还没有可抄进签名的一串。
   注意这里改的全是说明文字：ok 只看 Boolean(state.nonce)，前端不加第二条闸，判定在 Worker。
   说明文字一律先说「还差什么」再说已有什么 —— 底栏那句「全部就绪」也由这些句子代写，
   口令还没出现在屏幕上时它不许说就绪（见 refreshGate 里那段 shown）。 */
const NONCE_WHY = {
  off: "后端没配置酷安身份核实，口令生成不了 —— 投稿通道未开放，这一步要站点来接",
  self_reported: "后端收到了 UID 但没核实它，口令生成不了 —— 投稿通道未开放，这一步要站点来接",
  unavailable: "这次没核实成，口令还没生成 —— 把 UID 重敲一遍会再查；一直不通是后端没接上核实",
  checking: "正在核实 UID —— 通过后随机段就位，这一串还要有模块 ID 和整包 sha256 才算得出",
};

function gateItems() {
  const { zipOk, missing, badCode, badUid, badSource } = collect();
  const metaKeys = ["id", "name", "version", "versionCode"];
  const metaMissing = missing.filter((k) => metaKeys.includes(k));
  const items = [
    { ok: zipOk, text: "zip 已选择，且根目录含 module.prop" },
    {
      ok: !metaMissing.length && !badCode,
      text: "模块 ID / 名称 / 版本 / 版本号 齐全（版本号为整数）",
    },
    { ok: !missing.includes("source") && !badSource, text: "模块出处是酷安站内链接" },
    { ok: !missing.includes("uploader"), text: "投稿人酷安昵称已取得" },
    { ok: !missing.includes("coolapkUid") && !badUid, text: "酷安 UID 已填，且是 4-12 位纯数字" },
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
  const proofId = fieldValue("id");
  let nonceText;
  if (!state.nonce) {
    nonceText =
      NONCE_WHY[state.uidStatus] ||
      "投稿口令还没生成 —— UID 核实通过、填上模块 ID、包也选好了，这一串才出现";
  } else if (!proofId) {
    nonceText = "口令还差：填上模块 ID —— 随机段已生成，但这一串要模块 ID 和整包哈希才算得出";
  } else if (!state.zipSha) {
    // 两句各说一个来源缺哪一样：没选包是「还没得选」，选了包是「正在算 / 没算出来」。
    // 都不写「正在算」的肯定语气 —— 算失败时那句话就成假话了。
    nonceText = state.zip
      ? "口令还差：整包哈希还没算完 —— 随机段已生成，这一串要等它（稍等会自己出现；一直没出现就重新选一次包）"
      : "口令还差：还没选包 —— 口令绑的是这个包的字节，先把包选上，这一串才算得出来";
  } else {
    nonceText = "投稿口令已生成（填进酷安签名）";
  }
  // shown 说的是「屏幕上现在有没有一串可抄进签名」，三个来源齐了才有。
  // 它不参与 ready，也就不参与按钮 —— 全局约束是前端不加第二条闸，判据在 Worker。
  // 它只改底栏那两句：少一个来源时那里写的是这一条的实话，而不是「全部就绪，可以确认」。
  items.push({
    ok: Boolean(state.nonce),
    shown: Boolean(state.nonce && proofId && state.zipSha),
    text: nonceText,
  });
  items.push({ ok: IS_API_CONFIGURED, text: "后端 API_BASE 已配置" });
  return items;
}

function refreshGate() {
  const list = $("#gate");
  const items = gateItems();
  list.textContent = "";
  for (const item of items) {
    const li = node("li", item.ok ? "pass" : "", item.text);
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
// 关掉都不该把真人挡在投稿之外，所以这时把同一行放开成可填，并写明是哪一种原因 ——
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

// 派生显示：口令 = sha256(当前 id + 整包 sha256) 前 8 位 + "-" + state.nonce，
// 每次都在这里现算三个来源，界面上那串字符串永远跟着输入框里的 id 和当前这个包的字节走 ——
// 缓存派生值迟早和来源脱钩，而换包不换口令正是这条闸要封死的那件事。
async function renderProof() {
  const box = $("#proof-field");
  const id = fieldValue("id");
  const zipSha = state.zipSha;
  const nonce = state.nonce;
  if (!nonce || !id || !zipSha) {
    box.hidden = true;
    return;
  }
  const text = await buildProofString(id, zipSha, nonce);
  // 三个来源里任何一个在 await 期间动过都不许贴这一串：连打 id / 连着换包时先发的请求可能后到，
  // 而失败换串（showFailure 里那次重掷）也可能正好落在等待中间（runUidCheck 里同一类竞态踩过一次）。
  if (fieldValue("id") !== id || state.zipSha !== zipSha || state.nonce !== nonce) return;
  $("#proof-text").textContent = text;
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
  state.uidStatus = "checking";
  showUid("idle", "checking", "正在核实酷安用户…", `查询 UID ${uid} 是否对应一个真实账号。`);
  refreshGate();

  const result = await lookupCoolapkUser(uid);
  // 用户在你等回包的时候又改了 UID，就别把旧结果贴上去
  if (fieldValue("coolapkUid") !== uid) return;
  state.uidStatus = result.status;
  if (result.status === "verified" && !state.nonce) state.nonce = makeNonce();
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
  if (!zipOk || !IS_API_CONFIGURED) return;
  lastFocus = document.activeElement;
  const layer = $("#layer-confirm");
  layer.hidden = false;
  layer.classList.add("is-open");
  document.body.style.overflow = "hidden";
  $$("#layer-confirm input[type=checkbox]").forEach((c) => (c.checked = false));
  $("#confirm-go").disabled = true;

  const sum = $("#warn-sum");
  sum.textContent = "";
  const rows = [
    ["文件", `${state.file ? state.file.name : "—"} · ${state.file ? fmtBytes(state.file.size) : "—"}`],
    ["条目", state.zip ? `${state.zip.entries.length}` : "—"],
    ["模块", `${fieldValue("name")} (${fieldValue("id")})`],
    ["版本", `${fieldValue("version")} · versionCode ${fieldValue("versionCode")}`],
    ["作者", fieldValue("author") || "未填"],
    ["出处", fieldValue("source")],
    ["投稿人酷安昵称", fieldValue("uploader")],
    ["酷安 UID", uidLine()],
  ];
  for (const [k, v] of rows) {
    const line = node("div");
    line.append(`${k}: `, node("b", null, v));
    sum.append(line);
  }
  $("#confirm-back").focus();
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
    upload(currentFields());
  });
}

function currentFields() {
  return {
    zip: state.file,
    id: fieldValue("id"),
    name: fieldValue("name"),
    version: fieldValue("version"),
    versionCode: fieldValue("versionCode"),
    author: fieldValue("author"),
    description: fieldValue("description"),
    source: normalizeCoolapkUrl(fieldValue("source")) || fieldValue("source"),
    uploader: fieldValue("uploader"),
    coolapkUid: fieldValue("coolapkUid"),
    // 承诺文本的版本号 + 整包 sha256 + 口令的随机部分。派生串不在这里算 —— 后端自己重算，
    // 前端算出来的那份只用来显示。
    // sha256 交出去的理由：Worker 的 ⑤-c 会拿它和实算值对一遍。前端把自己算的哈希交过去，
    // 是为了让「口令对不上」和「哈希对不上」保持成两种可分辨的失败，而不是第三种。
    // 哈希还没算出来时发的是空串 —— ⑤-c 对空串跳过（老客户端同一条路），判不判由服务端定。
    pledge: "pledge-v1",
    sha256: state.zipSha,
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

async function upload(fields) {
  state.attempted = true;
  state.lastFields = fields;
  state.uploading = true;
  openRun("UPLOADING", "正在上传…");

  try {
    const { pr } = await submitModule(fields, {
      onProgress: (loaded, total) => {
        const pct = total ? Math.min(100, Math.round((loaded / total) * 100)) : 0;
        $("#run-fill").style.width = `${pct}%`;
        $("#run-pct").textContent = `${pct}%`;
        $("#run-bytes").textContent = `${fmtBytes(loaded)} / ${fmtBytes(total)}`;
      },
    });
    $("#run-fill").style.width = "100%";
    $("#run-pct").textContent = "100%";
    showSuccess(pr);
  } catch (err) {
    showFailure(err);
  } finally {
    state.uploading = false;
  }
}

function resultBody() {
  $("#run-progress").hidden = true;
  const box = $("#run-result");
  box.hidden = false;
  box.textContent = "";
  return box;
}

function showSuccess(pr) {
  const url_ = safeUrl(pr);
  $("#run-kicker").textContent = "PR OPENED";
  const ttl = $("#run-ttl");
  ttl.textContent = "投稿已受理，PR 已开";
  ttl.classList.add("ok");

  const box = resultBody();
  const p = node("p", null, "服务端已经存下这个包，并自动开了一个只含元数据 JSON 的 PR：");
  box.append(p);
  const link = node("a", null, url_ || "（没拿到 PR 链接）");
  if (url_) {
    link.href = url_;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.className = "mono";
  }
  box.append(link);

  const ul = node("ul", "next");
  for (const text of [
    "点进 PR 能看到审核进度，以及这个投稿的完整元数据。",
    "新模块若风险较低可能自动通过；对已收录模块的版本更新一律人工审核，可能要等。",
    "PR 合并之后，这个模块才会出现在公开索引里，所有人才能在管理器里搜到并一键安装。",
  ])
    ul.append(node("li", null, text));
  box.append(node("p", "done__kicker", "接下来"));
  box.append(ul);

  const ft = $("#run-ft");
  const again = node("button", "btn btn--go", "再投一个");
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
 * 服务端只有两种说法意味着这一串口令真的被烧掉了：用过它，或者它可能已经变成了一条投稿。
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
  ttl.textContent = "这次没提交上去";
  ttl.classList.add("bad");

  const box = resultBody();
  const reason =
    err instanceof BackendError
      ? err.message
      : err && err.message
      ? err.message
      : "未知的失败，服务端没给原因。";
  box.append(node("p", null, "后端返回的原因："));
  box.append(node("div", "reason", reason));

  let proofRotated = false;
  if (proofWasSpent(err, reason)) {
    // 这一串确实烧掉了：重掷随机段，口令行现算新的一串，门禁清单跟着刷新。
    state.nonce = makeNonce();
    // 重试按钮复用上一份载荷，不同步的话它会带着已经烧掉的那串再打一次，永远回同一句指控。
    // 整包哈希一并同步：上一份可能是在哈希到货之前取的，那时发出去的是空串。
    if (state.lastFields) {
      state.lastFields = { ...state.lastFields, nonce: state.nonce, sha256: state.zipSha };
    }
    renderProof();
    refreshGate();
    proofRotated = true;
  }

  if (err instanceof BackendError && (err.kind === "network" || err.kind === "not-configured")) {
    const hint = node("p");
    hint.append(
      "这类失败通常不用改投稿内容：先确认 ",
      node("code", null, "config.js"),
      " 里的 API_BASE 填了、后端 Worker 在跑，并且它已经给响应加上 Access-Control-Allow-Origin。"
    );
    box.append(hint);
  } else {
    box.append(
      node(
        "p",
        null,
        "表单内容我都留着了，改完可以直接重试，不用重新填一遍、也不用重新选文件。"
      )
    );
  }

  // 换串这件事必须让用户当场看见：签名里那串已经不通过了，不重抄一次就永远 403。
  if (proofRotated)
    box.append(
      node(
        "p",
        null,
        "口令换了一串 —— 表单里「投稿口令」那一行现在是新的，上一串已经作废。" +
          "先把新串抄进酷安签名并保存，再回来点重试；签名没改就重试，后端还会说这一串不对。"
      )
    );

  const ft = $("#run-ft");
  const retry = node("button", "btn btn--go", "重试提交");
  retry.type = "button";
  retry.addEventListener("click", () => {
    if (state.lastFields && state.lastFields.zip) {
      upload(state.lastFields);
    } else {
      closeRun();
      openConfirm();
    }
  });
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
  clearFile();
  state.attempted = false;
  state.uidStatus = "idle";
  state.uidInfo = null;
  state.nonce = "";
  state.zipSha = ""; // 两个来源一起归零：nonce 与整包哈希（clearFile 那份是包没了就清，这里是换投稿）
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
  $("#index-readout").classList.remove("bad");
  $("#index-readout").textContent =
    `${name || "索引"} · ${modules.length} 个模块` + (lastUpdate ? ` · 更新 ${fmtDate(lastUpdate)}` : "");

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
            "它不是没被投过，是被下架或拒收了，所以不会出现在索引里。"
        )
      );
      const why = node("a", "btn btn--ghost btn--sm", "去看这条处置");
      why.href = `#/incidents?q=${encodeURIComponent(q)}`;
      shell.append(why);
      return;
    }
    shell.append(node("p", null, "没找到不等于没被投过 —— 查重以模块 ID 为准。确认自己手上的包还没收录的话，可以直接投稿。"));
    const go = node("a", "btn btn--go btn--sm", "去投稿");
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
    ["下架 / 拒收", "下架挡住的是这一段内容（按模块 ID、ID+versionCode 或包的 sha256 命中）；拒收挡住的是一个人或一个 ID 未来投来的任何包。"],
    ["命中条件", "同一条里的多个条件是「且」的关系，不是「或」——写了 ID 又写 versionCode，就只命中那一个版本。"],
    ["证据（by）", "指向一条公开可查的评论，谁下的处置看那条评论的作者 —— 名字不在台账里重复一份，因为那是个会过期的抄本。形状不对的指针原样显示成文本，不猜成链接。这一页显示的就是台账原文，判定发生在索引推导与 CI 里，前端不另判一份。"],
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
    ["投稿时刻", pkg && pkg.submittedAt ? String(pkg.submittedAt) : "没采到", ""],
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
    left.append(kvRow("ec__kv--1", [
      ["承诺文本", pledge && pledge.version ? String(pledge.version) : "没写版本", ""],
      ["承诺时刻", pledge && pledge.atMs ? fmtDate(msOf(pledge.atMs)) : "没写", ""],
      ["所有权证明前缀", own && own.proofPrefix ? String(own.proofPrefix) : "没写（这条早于口令方案）", ""],
      ["验证方式", own && own.via ? String(own.via) : "没写", ""],
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

function humanLayer(item) {
  const box = layer("ec__layer--human", "03", "HUMAN", "人工结论，由两个有写权限的人签");
  const href = byLink(item.by);
  const pairs = [
    ["处置", KIND_LABELS[item.kind] || item.kind || "未知的种类", ""],
    ["理由分类", REASON_LABELS[item.reason] || item.reason || "没写理由分类", ""],
    ["说明", item.note || "没写", ""],
    ["时间", item.atMs === null ? item.at || "没写" : fmtDate(item.atMs), ""],
    ["证据评论", href ? item.by : item.by || "没写", href],
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
  card.append(humanLayer(item));
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

function renderIncidents() {
  const list = $("#inc-groups");
  const shell = $("#inc-state");
  const readout = $("#inc-readout");
  const count = $("#inc-count");
  renderIncLegend();
  renderIncAppeal();

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
  readout.textContent =
    `${items.length} 条处置记录` +
    (lastUpdate ? ` · 台账更新 ${fmtDate(lastUpdate)}` : "") +
    (schemaKnown ? "" : " · 这份台账的 schema 标记本页不认识，按原文列出");

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
      k: "上传上限",
      v:
        state.maxBytesFrom === "backend"
          ? `${fmtBytes(state.maxBytes)}（后端自报，与服务端一致）`
          : `${fmtBytes(state.maxBytes)}（后端未自报 maxBytes，这里用的是 config.js 的兜底值，可能与服务端实际值不一致）`,
      ok: state.maxBytesFrom === "backend",
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
 * 把「当前生效的上限」画到界面上。上限是问后端要的，异步到货，
 * 所以两处显示（拖放区提示与投稿规格）都必须能从这一个函数重画。
 */
function paintLimit() {
  const mb = Math.round(state.maxBytes / MB);
  const hint = $("#drop-hint");
  if (hint) hint.textContent = `上限 ${mb} MB · 不要多套一层文件夹`;
  const spec = $("#spec-max");
  if (spec) spec.replaceChildren(node("b", null, mb), " MB");
}

/**
 * 问后端它自己的真实上限。
 *
 * 这一步存在的理由很具体：前端曾经抄了一份 8MB，而后端常量是 2MB，
 * 于是用户按页面上的数字传到一半被 400 拒掉，界面还写着「允许 8MB」。
 * 抄来的常量一定会漂移，所以让它只有后端一个定义处，前端这份退化成兜底。
 */
async function syncLimits() {
  const r = await fetchServiceLimits();
  const changed = r.maxBytes !== state.maxBytes || r.from !== state.maxBytesFrom;
  state.maxBytes = r.maxBytes;
  state.maxBytesFrom = r.from;
  if (!changed) return;
  paintLimit();
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
  bindCheck();
  bindConfirm();
  bindSearch();
  bindIncSearch();
  bindTheme();
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
