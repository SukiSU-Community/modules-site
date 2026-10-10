import {
  CONFIG,
  url,
  IS_API_CONFIGURED,
  IS_TURNSTILE_CONFIGURED,
  IS_UID_VERIFY_ON,
} from "./config.js";

export class BackendError extends Error {
  constructor(kind, message, detail) {
    super(message);
    this.name = "BackendError";
    this.kind = kind; // 'not-configured' | 'network' | 'rejected' | 'bad-response'
    this.detail = detail || "";
  }
}

// /check 的四种 status，以及对应的界面提示。
// 这个端点任何情况都返回 HTTP 200，客户端只读 status，不看状态码。
export const CHECK_STATUS = {
  new: {
    tone: "ok",
    label: "new",
    title: "这是个新模块，索引里还没有",
    hint: "欢迎投稿。审核通过后所有人就能在管理器里搜到它。",
  },
  version_update: {
    tone: "warn",
    label: "version_update",
    title: "已有同名模块，你的是更新版本",
    hint: "可以投稿，但「对已收录模块的版本更新」一律需要人工审核，不会提交完就立刻上线。",
  },
  recorded: {
    tone: "muted",
    label: "recorded",
    title: "已经收录了，不需要再投",
    hint: "索引里已有这个 id，且线上版本不比你的旧。",
  },
  unknown: {
    tone: "muted",
    label: "unknown",
    title: "没能确认是否已收录",
    hint: "服务端查不到（网络问题、索引本身挂了等）。可以继续投稿。",
  },
};

const NETWORK_HINT =
  "连不上后端。可能是 config.js 里的 API_BASE 还没填、Worker 没启动，" +
  "或它还没返回 Access-Control-Allow-Origin（跨域被浏览器拦下）。";

export async function checkModule(id, versionCode) {
  if (!IS_API_CONFIGURED) {
    throw new BackendError("not-configured", "后端地址还没配置，暂时无法查重。");
  }
  const qs = new URLSearchParams({ id, versionCode: String(versionCode) });
  let res;
  try {
    res = await fetch(`${url("/check")}?${qs.toString()}`, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
  } catch {
    throw new BackendError("network", NETWORK_HINT);
  }
  let status = "unknown";
  try {
    const json = await res.json();
    if (typeof json.status === "string" && CHECK_STATUS[json.status]) status = json.status;
  } catch {
    status = "unknown";
  }
  return status;
}

/**
 * 提交投稿。用 XMLHttpRequest 而不是 fetch，只有一个原因：
 * fetch 拿不到上传进度，而这里最大要传 8MB，没有进度条用户会以为页面卡死。
 * 故意不设置任何自定义请求头，让 POST 保持「CORS 简单请求」形态（multipart/form-data
 * 本身在允许列表里），这样后端只需要补 Access-Control-Allow-Origin，
 * 连 OPTIONS 预检都不会触发。请不要在这里加 header 来「试试」。
 */
export function submitModule(fields, { onProgress } = {}) {
  if (!IS_API_CONFIGURED) {
    return Promise.reject(
      new BackendError("not-configured", "后端地址还没配置：请在 config.js 填入 API_BASE 后再提交。")
    );
  }

  const form = new FormData();
  form.append("zip", fields.zip, fields.zip.name);
  form.append("id", fields.id);
  form.append("name", fields.name);
  form.append("version", fields.version);
  form.append("versionCode", fields.versionCode);
  form.append("author", fields.author || "");
  form.append("description", fields.description || "");
  form.append("source", fields.source);
  form.append("uploader", fields.uploader);
  // 署名昵称与酷安 UID 分两个字段：前者给人看，后者是唯一可追责的标识。
  form.append(CONFIG.COOLAPK_UID_FIELD, fields.coolapkUid);
  // Turnstile 预留位：没接入时也是发空字符串，不做任何前端假验证码。
  form.append(CONFIG.TURNSTILE_FIELD, IS_TURNSTILE_CONFIGURED ? fields.turnstile || "" : "");

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url("/submit"));
    xhr.responseType = "text";
    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable && onProgress) onProgress(event.loaded, event.total);
    });
    xhr.addEventListener("load", () => {
      const body = (xhr.responseText || "").trim();
      if (xhr.status >= 200 && xhr.status < 300) {
        let json;
        try {
          json = JSON.parse(body);
        } catch {
          reject(
            new BackendError("bad-response", "后端返回了看不懂的响应（HTTP " + xhr.status + "）。", body)
          );
          return;
        }
        if (json && json.ok === true && json.pr) {
          resolve({ pr: json.pr });
        } else {
          reject(new BackendError("rejected", readReason(json) || "服务端没有接受这次投稿。", body));
        }
        return;
      }
      // 失败：服务端给的是中文原因，原样显示，别改写成英文兜底句。
      let json;
      try {
        json = JSON.parse(body);
      } catch {
        json = null;
      }
      const reason = (json && readReason(json)) || stripHtml(body);
      reject(
        new BackendError(
          "rejected",
          reason || `服务端拒绝了这次投稿（HTTP ${xhr.status}）。`,
          body
        )
      );
    });
    xhr.addEventListener("error", () => reject(new BackendError("network", NETWORK_HINT)));
    xhr.addEventListener("abort", () => reject(new BackendError("network", "上传已中断。")));
    xhr.send(form);
  });
}

function readReason(json) {
  if (!json || typeof json !== "object") return "";
  for (const key of ["error", "message", "reason", "detail"]) {
    const value = json[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function stripHtml(text) {
  if (!text) return "";
  if (/^\s*</.test(text)) return ""; // Cloudflare 的错误页之类，不拿来当原因
  return text.length > 300 ? `${text.slice(0, 300)}…` : text;
}

/* ------------------------------------------------------- 酷安身份与出处规则 */

// UID 就是 https://www.coolapk.com/u/<UID> 末尾那串数字。4 位起收，避免把
// 「1」「123」这种明显不是 UID 的输入当成合法值送去核实。
const UID_RE = /^\d{4,12}$/;

export function isCoolapkUid(value) {
  return UID_RE.test(String(value || "").trim());
}

// 出处只收酷安站内的链接（www / m / api 等子域都行）。
// 用 URL 解析而不是正则匹配字符串，避免 coolapk.com.evil.tld 这类假通过。
export function normalizeCoolapkUrl(raw) {
  const v = String(raw || "").trim();
  if (!v) return "";
  let u;
  try {
    u = new URL(/^https?:\/\//i.test(v) ? v : `https://${v}`);
  } catch {
    return "";
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return "";
  const host = u.hostname.toLowerCase();
  if (host !== "coolapk.com" && !host.endsWith(".coolapk.com")) return "";
  return u.href;
}

export const USER_STATUS = {
  off: {
    tone: "muted",
    label: "not checked",
    title: "署名未经核实",
    hint: "后端还没接酷安核实接口，这次投稿的 UID 只是格式对，没有确认存在。",
  },
  verified: {
    tone: "ok",
    label: "verified",
    title: "酷安用户已核实",
    hint: "已确认这个 UID 对应一个真实的酷安账号，昵称会随署名一起进索引。",
  },
  not_found: {
    tone: "bad",
    label: "not_found",
    title: "酷安查不到这个 UID",
    hint: "打开酷安 App「我的」，主页链接末尾那串数字才是 UID。填对的再提交。",
  },
  unavailable: {
    tone: "warn",
    label: "unavailable",
    title: "暂时无法核实",
    hint: "酷安接口没响应或后端核实不可用。不影响你继续投稿，但署名会标为未核实。",
  },
  // 后端明确告诉我们「只收到、没核实」。和 unavailable（想核实但没核实成）不同，
  // 这一档是后端目前压根没有核实能力 —— 界面必须说清楚是哪一种，
  // 否则投稿人会以为「显示未核实」只是网络抖动，而实际上是这条能力还没接。
  self_reported: {
    tone: "muted",
    label: "self reported",
    title: "署名未经核实",
    hint:
      "后端收到了 UID，但目前没有核实它对应哪个真实酷安账号。" +
      "投稿照常，只是这个署名属于「你自己报的」，出问题时公示按自报处理。",
  },
};

/**
 * 核实投稿人的酷安 UID。契约照 /check 的风格：任何情况都回 HTTP 200，
 * 前端只读 status，所以 Worker 挂了也不会让表单卡死。
 */
export async function lookupCoolapkUser(uid) {
  if (!IS_UID_VERIFY_ON) return { status: "off" };
  if (!isCoolapkUid(uid)) return { status: "invalid" };
  let res;
  try {
    res = await fetch(`${url(CONFIG.COOLAPK_USER_PATH)}?uid=${encodeURIComponent(uid)}`, {
      headers: { Accept: "application/json" },
    });
  } catch {
    return { status: "unavailable" };
  }
  if (!res.ok) {
    // 非 2xx（最常见是 404：后端压根还没实现这个端点）意味着「没有核实能力」，
    // 不是「这次没核实成」。两者在界面上必须分开：前者要写「未经核实」，
    // 后者才写「暂时无法核实」。混在一起会让人以为再等等就好。
    return { status: "self_reported", uid };
  }
  let json;
  try {
    json = await res.json();
  } catch {
    return { status: "unavailable" };
  }
  if (!json || typeof json !== "object") return { status: "unavailable" };
  if (json.status === "verified") {
    return {
      status: "verified",
      uid: String(json.uid || uid),
      nickname: typeof json.nickname === "string" ? json.nickname : "",
      avatar: httpUrl(json.avatar),
    };
  }
  if (json.status === "not_found") return { status: "not_found" };
  // Worker 只做原样回显时给的就是这个值 —— 它诚实，所以照原样呈现，不升格成 verified
  if (json.status === "self_reported") return { status: "self_reported", uid: String(json.uid || uid) };
  return { status: "unavailable" };
}

/**
 * 问后端要它自己的真实上限。
 *
 * 为什么要问而不是在 config.js 里抄一份：抄出来的那一份一定会有人对不上 ——
 * 前端写过 8MB、Worker 实际 2MB，于是用户按 8MB 传，传到一半被 400 拒掉，
 * 而页面上明明还写着「允许 8MB」。现在上限只有 Worker 一个定义处，
 * config.js 的那份退化成「问不到时的兜底值」。
 *
 * 失败不抛错：这个站要能在后端没接的时候照常浏览与填表，问不到就用兜底值。
 * from 字段给说明页的「这个站自己的状态」用，让人看得出接线到哪一档。
 */
export async function fetchServiceLimits() {
  const fallback = { maxBytes: CONFIG.MAX_UPLOAD_BYTES, from: "config" };
  if (!IS_API_CONFIGURED) return fallback;
  let res;
  try {
    res = await fetch(url("/"), { method: "GET", headers: { Accept: "application/json" } });
  } catch {
    return { ...fallback, from: "unreachable" };
  }
  if (!res.ok) return { ...fallback, from: "unreachable" };
  let json;
  try {
    json = await res.json();
  } catch {
    return { ...fallback, from: "unreachable" };
  }
  const n = Number(json?.maxBytes);
  if (!Number.isFinite(n) || n <= 0) return { ...fallback, from: "no-field" };
  return { maxBytes: Math.floor(n), from: "backend" };
}

function httpUrl(value) {
  if (typeof value !== "string" || !value) return "";
  try {
    const u = new URL(value);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : "";
  } catch {
    return "";
  }
}

/** 拉公开索引（MMRL 格式）并归一化。 */export async function fetchIndex() {
  if (!CONFIG.INDEX_URL.trim()) {
    throw new BackendError("not-configured", "公开索引地址还没配置：请在 config.js 填入 INDEX_URL。");
  }
  let res;
  try {
    res = await fetch(CONFIG.INDEX_URL, { method: "GET" });
  } catch {
    throw new BackendError(
      "network",
      "拉不到公开索引。可能是地址写错、该主机不允许浏览器跨域读取，或网络不通。"
    );
  }
  if (!res.ok) throw new BackendError("bad-response", `索引返回 HTTP ${res.status}。`);
  let json;
  try {
    json = await res.json();
  } catch {
    throw new BackendError("bad-response", "索引不是合法 JSON，没法解析。");
  }
  return normalizeIndex(json);
}

export function normalizeIndex(json) {
  if (!json || typeof json !== "object" || !Array.isArray(json.modules)) {
    throw new BackendError("bad-response", "索引 JSON 里没有 modules 数组，不像 MMRL 格式。");
  }
  return {
    name: typeof json.name === "string" ? json.name : "",
    lastUpdate: typeof json.lastUpdate === "number" ? json.lastUpdate : null,
    modules: json.modules.map((m) => {
      const versions = Array.isArray(m.versions) ? m.versions : [];
      const latest = versions.reduce(
        (best, v) => (best && Number(best.versionCode) >= Number(v.versionCode) ? best : v),
        null
      );
      return {
        id: String(m.id || ""),
        name: String(m.name || m.id || ""),
        author: String(m.author || ""),
        description: String(m.description || ""),
        verified: Boolean(m.verified),
        versions,
        latest,
      };
    }),
  };
}
