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
  dispositionsUrl,
  KIND_LABELS,
  REASON_LABELS,
  SELECTOR_LABELS,
  lookupCoolapkUser,
  isCoolapkUid,
  normalizeCoolapkUrl,
} from "./api.js";
import { canInflateRaw, listEntries, readEntry, inspectEntries } from "./zipread.js";
import { parseModuleProp } from "./moduleprop.js";

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
  submit: { el: "#view-submit", label: "投稿台" },
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

/* --------------------------------------------------------------- 开机读数 */

function typeReadout() {
  const bits = ["面板就绪"];
  bits.push(IS_API_CONFIGURED ? `后端 ${CONFIG.API_BASE}` : "后端 API_BASE 未配置");
  bits.push(IS_INDEX_CONFIGURED ? "索引地址已接" : "索引 INDEX_URL 未配置");
  bits.push(`上限 ${Math.round(state.maxBytes / MB)} MB${state.maxBytesFrom === "backend" ? "" : "（后端未自报，用兜底值）"}`);
  if (!canInflateRaw()) bits.push("本浏览器读不了 zip，元数据需手填");
  const text = bits.join(" · ");
  const el = $("#boot");
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  el.classList.toggle("bad", !IS_API_CONFIGURED);

  if (reduce) {
    el.textContent = text;
    el.append(node("span", "cur"));
    return;
  }
  el.textContent = "";
  const out = node("span");
  const cur = node("span", "cur");
  el.append(out, cur);
  let i = 0;
  const timer = setInterval(() => {
    out.textContent = text.slice(0, ++i);
    if (i >= text.length) clearInterval(timer);
  }, 16);
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
  state.checkStatus = null;
  $("#file").value = "";
  $("#term").hidden = true;
  $("#check").hidden = true;
  $("#check-where").hidden = false;
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
    $("#check-where").hidden = false;
    refreshGate();
    return;
  }
  $("#check-where").hidden = true;
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
  fieldEls.coolapkUid.addEventListener("input", runUidCheck);
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
  return Boolean(CONFIG.COOLAPK_VERIFY_REQUIRED) && state.uidStatus !== "verified";
}

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
    { ok: !missing.includes("uploader"), text: "投稿者署名已填" },
    { ok: !missing.includes("coolapkUid") && !badUid, text: "酷安 UID 已填，且是 4-12 位纯数字" },
  ];
  if (IS_UID_VERIFY_ON) {
    const label =
      state.uidStatus === "verified"
        ? "酷安用户已核实"
        : uidBlocked()
        ? "酷安用户核实没通过"
        : "酷安用户核实（接口不可用时不拦你）";
    items.push({ ok: !uidBlocked(), text: label });
  }
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
  $("#dock-t").textContent = firstBad ? firstBad.text : "全部就绪，可以确认";
  $("#dock-s").textContent = firstBad ? "还差这一步" : "三道确认跳不过去";
  $("#gate-note").textContent = ready ? "确认屏里还有三道勾" : "先把上面几项填齐";
  if (state.attempted) paintFieldErrors();
}

const FIELD_MSGS = {
  versionCode: (v) => (v ? "必须是整数" : "请填写版本号（整数，来自 module.prop）"),
  coolapkUid: (v) => (v ? "UID 应是 4-12 位纯数字，不带 https 和 /" : "请填写你的酷安 UID"),
  source: (v) =>
    v ? "必须是酷安站内链接，如 https://www.coolapk.com/feed/65432100" : "请填写模块出处",
  uploader: (v) => (v ? "" : "请填写投稿者署名"),
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

const runUidCheck = debounce(async () => {
  const uid = fieldValue("coolapkUid");
  if (!uid || !isCoolapkUid(uid)) {
    state.uidStatus = uid ? "invalid" : "idle";
    state.uidInfo = null;
    $("#uid-check").hidden = true;
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

  if (result.status === "verified" && result.nickname) {
    const el = fieldEls.uploader;
    if (el && (!el.value.trim() || el.dataset.auto === "1")) {
      el.value = result.nickname;
      el.dataset.auto = "1";
      el.closest(".field").classList.add("is-pre");
    }
  }
  refreshGate();
}, 500);

/* ------------------------------------------------------------- 确认屏逻辑 */

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
    ["署名", fieldValue("uploader")],
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
  $("#uid-check").hidden = true;
  const up = fieldEls.uploader;
  if (up.dataset.auto === "1") {
    up.value = "";
    delete up.dataset.auto;
    up.closest(".field").classList.remove("is-pre");
  }
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
  ft.append(incLabeled("处置人：", item.by || "没写", q, "inc__by"));
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

function renderIncLegend() {
  const host = $("#inc-legend");
  if (!host || host.childElementCount) return;
  const rows = [
    ["下架 / 拒收", "下架挡住的是这一段内容（按模块 ID、ID+versionCode 或包的 sha256 命中）；拒收挡住的是一个人或一个 ID 未来投来的任何包。"],
    ["命中条件", "同一条里的多个条件是「且」的关系，不是「或」——写了 ID 又写 versionCode，就只命中那一个版本。"],
    ["处置人（by）", "指向公开可查的证据，不是自动生成的名字。这一页显示的就是台账原文，判定发生在索引推导与 CI 里，前端不另判一份。"],
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

function renderIncidents() {
  const list = $("#inc-groups");
  const shell = $("#inc-state");
  const readout = $("#inc-readout");
  const count = $("#inc-count");
  renderIncLegend();

  const clear = () => {
    list.textContent = "";
    count.textContent = "";
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
        [incTitle(it), incSelText(it), it.note, it.by, it.verify, it.reason, it.kind].some((v) =>
          String(v).toLowerCase().includes(low)
        )
      )
    : items;

  count.textContent = "";
  // 空台账时「0 条 / 共 0」是噪声，下面那句空态说得更清楚
  if (items.length) {
    const c = count;
    c.append(node("b", null, shown.length));
    c.append(` 条 / 共 ${items.length}`);
  }

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
  // 开机读数那段是打字机动画，只在数字真的变了时重打一次，否则白白打断阅读
  typeReadout();
}

function init() {
  $("#brand-zh").textContent = CONFIG.SITE_NAME;
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
  typeReadout();

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
