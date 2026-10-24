import {
  CONFIG,
  url,
  IS_API_CONFIGURED,
  IS_TURNSTILE_CONFIGURED,
  IS_UID_VERIFY_ON,
} from "./config.js";

export class BackendError extends Error {
  constructor(kind, message, detail, extra) {
    super(message);
    this.name = "BackendError";
    this.kind = kind; // 'not-configured' | 'network' | 'rejected' | 'bad-response'
    this.detail = detail || "";
    // 后端回的机器可读码，与由此判出的归属（'you' 改包 / 'us' 改服务 / 'both' / 'unknown'）。
    // 放这儿是因为 app.js 的失败格要说清「这一句该谁去修」，而不是因为它好取。
    this.code = extra && typeof extra.code === "string" ? extra.code : "";
    this.owner = (extra && extra.owner) || "unknown";
  }
}

/** 整包 sha256 的形状：64 位小写十六进制。批量声明里逐枚强制（§16 第 1 句）。 */
export const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

// /check 的四种 status，以及对应的界面提示。
// 这个端点任何情况都返回 HTTP 200，客户端只读 status，不看状态码。
export const CHECK_STATUS = {
  new: {
    tone: "ok",
    label: "new",
    title: "这是个新模块，索引里还没有",
    hint: "欢迎上传。审核通过后所有人就能在管理器里搜到它。",
  },
  version_update: {
    tone: "warn",
    label: "version_update",
    title: "已有同名模块，你的是更新版本",
    hint: "可以上传，但「对已收录模块的版本更新」不会被自动合进索引 —— 本站只有机器审核，没有人可以签它进来。",
  },
  recorded: {
    tone: "muted",
    label: "recorded",
    title: "已经收录了，不需要再上传",
    hint: "索引里已有这个 id，且线上版本不比你的旧。",
  },
  unknown: {
    tone: "muted",
    label: "unknown",
    title: "没能确认是否已收录",
    hint: "服务端查不到（网络问题、索引本身挂了等）。可以继续上传。",
  },
};

const NETWORK_HINT =
  "连不上后端。可能是 config.js 里的 API_BASE 还没填、Worker 没启动，" +
  "或它还没返回 Access-Control-Allow-Origin（跨域被浏览器拦下）。";

/**
 * 单枚查重：`GET /check?id=&versionCode=` —— §17.6 明写「一字不改」，因为 App 在读它，
 * 而这个端点任何情况都回 HTTP 200、客户端只读 status。批量那一头见下面的 checkModulesBatch。
 */
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
 * 提交**一整套**（§17.1：`POST /submit` 里存在名为 `manifest` 的 text field ⇒ 走批量）。
 * 形状逐条对着设计文档 §17.2 / §17.3，一个字段都不许多、一个都不能换形状。
 *
 * 为什么一次动作只发一个请求（而不是像以前那样一枚发一次）：签名串 v2 把绑的对象从
 * 「(模块 id, 整包 sha256) 这一对」换成「这一次上传的整套」，而 `used-nonce` 用过即废 ⇒
 * 签名串只有在**一个请求带整套**时语义才干净。拆成 N 次的话要么第一次就把这串烧掉
 * （后 N-1 次全被当成「这一串已经用过了」拒掉），要么把记账降成一枚一次，那攻击者读到串就能逐枚预占。
 * 这条不是省事，是 §15 写下来的硬约束：「不能只做前端」。
 *
 * 三条规矩各自守一件会静默坏掉的事：
 * ① manifest 排成 FormData 的**第一个 part** —— §17.2：闸前移之后签名串的输入来自这份声明，
 *    解析器若在读到 manifest 之前就看见 file part ⇒ 400 `manifest_late`。FormData 的插入序
 *    就是线上的 part 序（浏览器按 append 顺序编码边界，实测过，见本文件末尾那条注释），
 *    所以这一条在客户端能真做到，不是「应该没问题」。
 * ② 逐枚必须带 sha256，缺一枚就不发请求 —— §16 第 1 句：声明从「顺手上报的元信息」升级成
 *    「判据的输入」，缺声明的批量在服务端是 `manifest_invalid`，而那种失败在页面上完全看不出
 *    是哪一枚没算出来。这里拦的是「已知必然被拒的请求」，不是后端的一条安全闸（判定仍在 Worker）。
 * ③ 一个 `zip` file part 都不缺 —— 少一枚是 `batch_incomplete`（少递），整单拒、零 GitHub 写入。
 *    客户端在发之前就凑不齐，说明这一枚的字节根本还没读进来，那发出去就是白烧一次限流格。
 *
 * ⚠ 线上部署次序（§15「换代次序」）：Worker 先读 v1∪v2 并上线，**前端这份才能切过来** ——
 *   现在这份发给还没接 `manifest` 的后端会失败。失败不是静默的：本函数会原样回 4xx 与 code。
 */
export function submitContribution(batch, { onProgress } = {}) {
  if (!IS_API_CONFIGURED) {
    return Promise.reject(
      new BackendError("not-configured", "后端地址还没配置：请在 config.js 填入 API_BASE 后再提交。")
    );
  }
  const modules = Array.isArray(batch.modules) ? batch.modules : [];
  if (!modules.length) {
    return Promise.reject(new BackendError("rejected", "本次要上传的整套是空的 —— 一个包都没选中，没什么可发的。"));
  }
  const noSha = modules.filter((m) => !SHA256_HEX_RE.test(String(m.sha256 || "")));
  if (noSha.length) {
    return Promise.reject(
      new BackendError(
        "rejected",
        `有 ${noSha.length} 枚的整包 sha256 还没算出来（${noSha.map((m) => m.id || "（没模块 ID）").join("、")}）—— ` +
          "批量上传逐枚必须声明整包哈希，缺任何一枚服务端都会按 manifest 不合法拒掉这一整套。"
      )
    );
  }
  const noFile = modules.filter((m) => !m.zip);
  if (noFile.length) {
    return Promise.reject(
      new BackendError("rejected", "队列里有枚还没拿到包体字节，这一整套发不出去 —— 重新选一次那个文件。")
    );
  }

  const form = new FormData();
  // ① manifest 必须是第一个 part，早于任何一个 file part。
  form.append("manifest", buildManifest(modules));
  // 共享字段留在顶层，不进 manifest（§17.3）：一次上传只有一个人、一个承诺、一份签名串。
  form.append("uploader", batch.uploader || "");
  form.append(CONFIG.COOLAPK_UID_FIELD, batch.coolapkUid || "");
  form.append("pledge", batch.pledge || "");
  form.append("nonce", batch.nonce || "");
  // Turnstile 预留位：没接入时也是发空字符串，不做任何前端假验证码。
  // 一次 POST 一份令牌 —— 整套一次提交只需要解一次题，比逐枚提交少 N-1 次。
  form.append(CONFIG.TURNSTILE_FIELD, IS_TURNSTILE_CONFIGURED ? batch.turnstile || "" : "");
  // 长效会话令牌：手里有就带上（这一次不用改签名），没有就发空串（照旧走签名那条路）。
  // 必须排在第一个 file part 之前 —— 与上面那几个共享字段同一条规矩（见 ① 与 manifest_late）。
  form.append("session", batch.session || "");
  // ③ N 个 name="zip" 的 file part，按 manifest 的顺序追加（配对不看顺序、看包内 module.prop
  //   的 id，§17.3；但顺序一致能让失败文案里的「第几枚」对得上用户认得出的那一枚）。
  let totalBytes = 0;
  for (const m of modules) {
    form.append("zip", m.zip, m.zip.name);
    totalBytes += Number(m.zip.size) || 0;
  }

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url("/submit"));
    xhr.responseType = "text";
    // 进度按**这一整套**的字节数走（xhr.upload 给的就是整个请求体的进度），
    // 所以那根条现在说的是这一批，不再假装是一枚。
    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable && onProgress) onProgress(event.loaded, event.total, totalBytes);
    });
    xhr.addEventListener("load", () => {
      const body = (xhr.responseText || "").trim();
      let json = null;
      try {
        json = JSON.parse(body);
      } catch {
        json = null;
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        if (json && json.ok === true && json.pr) {
          // §17.5：应答是 { ok, pr, modules:[{ id, versionCode, sha256, assetName }] }。
          // `pr` 键名与今天逐字兼容；单枚批量时 `modules` 也有一份 ⇒ 前端只写一条处理路径。
          // 会话令牌随成功应答一起回来（`session` 恒有这个键：签成了是 { token, expiresAt }，
          // 走令牌来的这一笔不重签、是 null）。在这里丢掉它，等于让「90 天免改签名」在页面上
          // 根本不存在 —— 令牌只留在 localStorage 里，从来没有被发出去过。
          resolve({
            pr: json.pr,
            modules: Array.isArray(json.modules) ? json.modules : [],
            session: json.session ?? null,
          });
        } else {
          reject(backendFailure(xhr.status, json, body));
        }
        return;
      }
      reject(backendFailure(xhr.status, json, body));
    });
    xhr.addEventListener("error", () => reject(new BackendError("network", NETWORK_HINT)));
    xhr.addEventListener("abort", () => reject(new BackendError("network", "上传已中断。")));
    xhr.send(form);
  });
}

/** §17.3 那份 JSON：`{ version:'batch-v1', modules:[{ id, sha256, name, version, versionCode, author, description, source }] }`。 */
function buildManifest(modules) {
  return JSON.stringify({
    version: "batch-v1",
    modules: modules.map((m) => ({
      id: String(m.id || "").trim(),
      sha256: String(m.sha256 || "").trim().toLowerCase(),
      name: String(m.name || "").trim(),
      version: String(m.version || "").trim(),
      versionCode: Number(m.versionCode),
      author: String(m.author || ""),
      description: String(m.description || ""),
      source: String(m.source || ""),
    })),
  });
}

/* ------------------------------------------------ §17.4 错误码 → 说人话
   这张表守的是一句很具体的话：**「是你的包的问题」与「是我们的服务的问题」不许混成同一句**。
   两者要用户做的事相反 —— 前者改包/改字段再来一次，后者什么都别改、等站点修好再来一次。
   混起来写过一次：网关没接 CORS 时页面说「提交内容不合法」，用户来回改了半小时字段。
   所以每条带 owner：'you'（这一套里要改的东西）/ 'us'（本站或后端要动的东西）/ 'both'。
   后端没回 code（旧网关的 HTML、纯文本、还没发码的旧部署）时不许编一条原因 ——
   那时只能用服务端原话，并明说是「我们没能把它归到哪一种」。 */
export const SUBMIT_ERROR_TEXT = {
  zip_too_large: {
    owner: "you",
    text: "这一套里有枚超过服务端自报的单枚上限，服务端在收字节的这一格就拒了。哪一枚超了页面上已经标出来 —— 换那一枚的包，或者把它拆成单独一次上传。",
  },
  batch_too_large: {
    owner: "you",
    text: "这一套的总字节超过服务端自报的整套上限。这不是你包坏了：把这一整套拆成两次上传就行（每次改一次签名、只放得下的那几枚）。",
  },
  too_many_modules: {
    owner: "you",
    text: "一次上传带的枚数超过服务端自报的上限。拆成两次上传，其余的包留着下次选就行。",
  },
  manifest_invalid: {
    owner: "us",
    text: "服务端没能把这份 manifest 读成它要的形状。**这一条多半是我们的问题**：前端的字段形状与设计文档 §17.3 不一致，或后端还没上线批量这一条路。你不需要改包，也别再抄签名 —— 把这一句原样发给站点。",
  },
  manifest_late: {
    owner: "us",
    text: "服务端说 manifest 没排在第一个文件之前 —— 而前端是把 manifest 作为第一个 part 发出去的（FormData 的插入序）。两边对不上时是后端解析器的问题，你什么都不用改。",
  },
  batch_incomplete: {
    owner: "you",
    text: "声明的那一套与递上来的字节对不上：少一枚、多一枚、同一枚重复都会回这一句，服务端整单拒。先在页面上核对队列里有几枚、模块 ID 分别是什么，再重试；还不行就是前端把集合算错了，把这一句发给站点。",
  },
  sha_mismatch: {
    owner: "you",
    text: "某一枚的字节与声明的整包 sha256 不一致：选完之后那个文件被改过、或下载不完整最常见。把那一枚重新选一次文件再来。若你确定包没动过，那是前端哈希口径与后端不一致 —— 属于站点的 bug，把这一句一起发出来。",
  },
  proof_used: {
    owner: "you",
    text: "这一串签名已经在服务端记过账了（用过即废）。前端会自动换一新一串，你需要先把新串抄进酷安签名并保存，再回来点重试 —— 签名没改就重试，还会撞同一句。",
  },
  /* ── POST /report（举报入口，下架侧第一步）那九条 ──────────────────────────
     同一条规矩（§17.7）：后端加一个 code，这张表必须同轮加一条，否则页面只能拿一句通用
     文案去糊两种相反的失败。举报这一格最要紧的分别是：
       · 「你引用的那段不在包里」（要他改材料）
       · 「这个包我们读不出来」（要我们补能力）—— 两者的修法完全相反，混一次就是一条
         对具体的人的假结论。
     这一片的应答一律 publicAction:「none」：判定只落一份待办记录，公开索引一个字都没改。
     04 那一屏（举报页）读的就是这张表 —— 后端加一个码而这里少一条，页面就只能拿一句通用文案
     去糊两种相反的失败，所以 tools/selftest.mjs 有一根跨端钉子按后端源码里出现的 code 逐条对账。 */
  not_in_index: {
    owner: "you",
    text: "服务端说这个模块 id 不在公开索引里，所以没有可下架的东西。举报这条路只管已经上架的模块：先在索引页确认 id 那一字不差（复制，不要手打）。如果它还没上架，那要走的是上传那一步，不是举报。",
  },
  version_not_in_index: {
    owner: "you",
    text: "你填的 versionCode 不在公开索引里那一枚的版本清单里，服务端会点名它有哪几个。填其中一个，或者干脆不填 —— 不填时服务端按最新那一枚判（记录里会写明它是按假设挑的）。",
  },
  index_unavailable: {
    owner: "us",
    text: "服务端读不出公开索引，或索引里那一枚没有可用的 sha256/zipUrl —— **这是本站的问题**。你不需要改任何东西，稍后再试一次；一直如此就把服务端那句原话发给站点。",
  },
  no_evidence_cited: {
    owner: "you",
    text: "这条举报没有成立：逐字门槛要的是「包里那一段字节」，而这次没有可定位的引用（截图、转述、你自己的描述都不算）。把要指控的那一行从包里原样复制出来再来一次。",
  },
  evidence_not_in_package: {
    owner: "you",
    text: "与包体不符：服务端把这个归档的每一条条目都读出来了，你引用的那段字节不在里面。请把那一行从包里**原样复制**（改动过的文本、全半角标点之差、被换行拆开的那一行都不算逐字）。这一条不会被写成对作者的指控。",
  },
  package_unreadable: {
    owner: "us",
    text: "这个包我们读不出来（有条目解不开，或归档取不到）—— **不是你的材料问题**，服务端不会在这时候说「不在包里」。这条举报已记下待办，落点是站点维护者按记录里的清单补读取能力；你不需要改任何东西。",
  },
  archive_digest_mismatch: {
    owner: "us",
    text: "归档里取回的字节与公开索引里那条 sha256 不是同一枚 —— 这是索引或归档自己的故障，与你的材料无关。这条举报已记下待办，由维护者核对那一枚 asset；稍后重试或直接发给站点。",
  },
  located: {
    owner: "us",
    text: "这条举报成立：举报人过了实名闸，且引用的那段字节在归档里逐字定位到了。下一步不在这一片 —— 由机器 seal 写台账、开下架 PR；在那之前公开索引一个字都没改（publicAction 就是「none」）。",
  },
  report_record_failed: {
    owner: "us",
    text: "服务端判完了但没能把这条举报记进账（自家 KV 写不进去）。它**不算已经受理** —— 判定不落账就等于没发生过。重试一次；反复如此就把服务端那句原话发给站点。",
  },
};

/**
 * 把服务端的失败分成三格：你的包 / 我们的服务 / 说不清。
 * 归类只认后端回的 code（机器可读），中文文案原样跟着显示，**不在这里改写它**。
 */
function backendFailure(status, json, body) {
  const code = json && typeof json.code === "string" ? json.code : "";
  const known = SUBMIT_ERROR_TEXT[code];
  const reason = (json && readReason(json)) || stripHtml(body) || "";
  const detail = known ? known.text : serviceSideHint(status, reason);
  return new BackendError(
    "rejected",
    `${detail}${reason ? ` —— 服务端原话：「${reason}」` : `（HTTP ${status}，服务端没给原因）`}`,
    body,
    { code, owner: known ? known.owner : status >= 500 ? "us" : "unknown" }
  );
}

/** 没有 code 时**不许替用户猜原因**：按 HTTP 段说是哪一侧的问题，剩下的交回服务端原话。 */
function serviceSideHint(status, reason) {
  if (status >= 500) {
    return "后端自己出错了（5xx）。**这是我们的问题**：你的包与签名都不用动，稍后再试一次，一直这样就把这一句发给站点。";
  }
  if (reason) return "服务端拒了这一次上传，这一条我们没能归到具体哪一种。";
  return "服务端拒绝了这次上传。";
}

/**
 * GET /reports（举报队列的读数）。
 *
 * 返回 `null` 的意思是「这一格现在没有可信的数」—— 后端没配、网络失败、HTTP 非 2xx、
 * 以及后端自己回 `available:false`（定时器还没跑过第一轮 / 那一格读不懂 / 不是定时器写的）
 * 全归到这里来。调用方拿 null 就**什么都不显示**。
 *
 * 为什么这里不许兜一个 0：这一格的用处是让人看出「自动下架那条链还在动」。
 * 一个假的 0 与一个真的空在页面上长得一模一样，于是它把「下架停住了」伪装成「没人被举报」。
 * 数字的来源只有那一定时器（`by` 不是它就整格作废），这条链上没有第二个能写它的人。
 */
export async function fetchReportQueue() {
  if (!IS_API_CONFIGURED) return null;
  let json = null;
  try {
    const res = await fetch(url("/reports"), { method: "GET", headers: { Accept: "application/json" } });
    if (!res.ok) return null;
    json = await res.json();
  } catch {
    return null;
  }
  if (!json || json.available !== true) return null;
  // 来源与版本也在这儿认一遍：后端 `reportQueueStats` 已经挡过一次，但这一格要写进一个
  // 对公众的页面 —— 万一后端那层校验哪天漂了，页面不该跟着把一个来路不明的数显示成结论。
  if (json.schema !== "sukisu-report-queue-v1" || json.by !== "ledger-cron") return null;
  const n = (v) => (Number.isInteger(Number(v)) && Number(v) >= 0 ? Number(v) : null);
  const artifacts = n(json.artifacts);
  const reports = n(json.reports);
  // 两个数缺任何一个都不显示：这一页宁可少说一句，也不把「我们不知道」说成一个数。
  if (artifacts === null || reports === null) return null;
  return {
    artifacts,
    reports,
    opened: n(json.opened) ?? 0,
    at: typeof json.at === "string" ? json.at : "",
    pr: typeof json.pr === "string" ? json.pr : "",
    truncated: json.truncated === true,
  };
}

/**
 * POST /report（04 那一屏的举报）。成功形状：
 * `{ ok, established, verdict, owner, reportId, publicAction, nextStep }` —— 判定成立与否都在 200 里，
 * 因为「不成立」不是请求失败，而是一条要如实展示的结论（把不成立报成 HTTP 4xx 会让人以为没提交成功）。
 * 失败那一侧照走 `backendFailure`：那九个码各有一条人话，而这里最要不得的两种失败
 * （「你引用的那段不在包里」要他改材料 / 「这个包我们读不出来」要我们补能力）修法相反。
 *
 * 这一发会消耗服务端的一次实名额度，也可能烧掉你填进酷安签名的那一串（受理之后才烧，
 * 判「我们读不出」那一档不烧）—— 所以调用方必须先把签名串的来源逐字确认过：
 * 被举报 id、索引里那一版的 sha256、nonce，三者任一不对，签名就对不上。
 */
export async function reportModule(body) {
  if (!IS_API_CONFIGURED) {
    throw new BackendError("not-configured", "后端地址还没配置：请在 config.js 填入 API_BASE 后再举报。");
  }
  let res;
  let text = "";
  try {
    res = await fetch(url("/report"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    text = await res.text();
  } catch {
    throw new BackendError("network", NETWORK_HINT);
  }
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  if (!res.ok) throw backendFailure(res.status, json, text);
  return json;
}

/**
 * 批量查重（§17.6）：`POST /check` 收 `{ modules:[{ id, versionCode }] }` ⇒ `{ results:[{ id, status }] }`，
 * `status` 沿用今天那四个值。上面那条 `GET /check` 一字没动 —— App 在读它。
 *
 * 读回来的形状逐条判过才认：非 2xx、不是 JSON、results 不是数组、status 不在那四个值里，
 * 任何一种都算「这一档没判成」而不是「没重复」。失效方向必须是**不拦**：
 * 把「读不懂」说成「已被上传过」，就是把一个查不到的东西说成查到了。
 * 逐枚落状态用 `single` 那条路兜底（上面那个端点今天就在跑），所以后端还没上批量这一条时
 * 这里退回逐枚 GET，功能不降级、只是多打几个请求。
 */
export async function checkModulesBatch(modules) {
  if (!IS_API_CONFIGURED) {
    return { statuses: new Map(), why: "后端地址还没配置，查重没打成 —— 已收录那一条暂时拦不了。", via: "single" };
  }
  const payload = {
    modules: (Array.isArray(modules) ? modules : [])
      .filter((m) => m && String(m.id || "").trim())
      .map((m) => ({ id: String(m.id).trim(), versionCode: m.versionCode })),
  };
  if (!payload.modules.length) return { statuses: new Map(), why: "", via: "single" };
  try {
    const res = await fetch(url("/check"), {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      // 404/405 最常见的原因是后端还没上这一条路 ⇒ 交回逐枚那条，不是「查不到」。
      return { statuses: new Map(), why: `批量查重回 HTTP ${res.status}`, via: "single" };
    }
    const json = await res.json();
    const rows = json && Array.isArray(json.results) ? json.results : null;
    if (!rows) return { statuses: new Map(), why: "批量查重的响应里没有 results 数组", via: "single" };
    const statuses = new Map();
    for (const row of rows) {
      if (!row || typeof row.id !== "string") continue;
      if (typeof row.status === "string" && CHECK_STATUS[row.status]) statuses.set(row.id, row.status);
    }
    return { statuses, why: "", via: "batch" };
  } catch {
    return { statuses: new Map(), why: NETWORK_HINT, via: "single" };
  }
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
    hint: "后端还没接酷安核实接口，这次上传的 UID 只是格式对，没有确认存在。",
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
    hint: "在酷安 App「我的」→ 点头像进个人主页 → 右上角三点 → 「查看我的资料」里找用户 UID。填对的再提交。",
  },
  unavailable: {
    tone: "warn",
    label: "unavailable",
    title: "暂时无法核实",
    hint:
      "酷安接口没响应或后端核实不可用。署名会标为未核实；签名串要核实通过才生成，所以现在还提交不了 —— " +
      "把 UID 重敲一遍会再查，一直不通是后端还没接上核实。",
  },
  // 后端明确告诉我们「只收到、没核实」。和 unavailable（想核实但没核实成）不同，
  // 这一档是后端目前压根没有核实能力 —— 界面必须说清楚是哪一种，
  // 否则上传人会以为「显示未核实」只是网络抖动，而实际上是这条能力还没接。
  self_reported: {
    tone: "muted",
    label: "self reported",
    title: "署名未经核实",
    hint:
      "后端收到了 UID，但目前没有核实它对应哪个真实酷安账号。" +
      "这个署名属于「你自己报的」，出问题时公示按自报处理；核实这条没接上，签名串也就生成不了，" +
      "上传通道此时是关着的 —— 要站点把核实接上才会开。",
  },
};

/**
 * 核实上传人的酷安 UID。契约照 /check 的风格：任何情况都回 HTTP 200，
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

/* --------------------------------------------- 长效会话令牌（90 天免改签名） */

// 会话令牌的形状与整包 sha256 恰好同形（64 位小写十六进制），但**不共用** SHA256_HEX_RE：
// 那一条的名字与注释说的都是「整包哈希」，两条口径将来谁动都不该牵动另一条。
const SESSION_TOKEN_RE = /^[0-9a-f]{64}$/;

// 这两条会话请求是**页面启动时**发的，不是用户点了什么才发 —— 后端抖动时它俩不能把首屏吊住。
// 8 秒是「够它自己回来、又不至于让人盯着白屏」的那一档；超时按「这次没有会话」处理，
// 用户最多多改一次签名，而不会被卡在上传页门口。
const SESSION_TIMEOUT_MS = 8000;

/**
 * 带超时的 fetch。这个文件里此前没有超时工具（上传走 XHR、其余 fetch 都不设闸），
 * 所以这里补一个最小的：到点 abort，异常照常往上抛，由调用方归到 `{ ok: false }`。
 */
async function fetchWithTimeout(target, options, ms) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  try {
    return await fetch(target, { ...options, signal: ctl.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 校验长效会话令牌（90 天免改签名）。
 *
 * 为什么「恒 200、只读 ok」：契约照 /check 那一套 —— **令牌过期、被注销、后端压根不认这一串，
 * 都是 HTTP 200 里的一条结论**，不是一次请求失败。状态码在这一格没有信息量：
 * 401 与 404 会把「这个令牌不能用了」和「这个端点还没上线」混成同一种，而这两件事对页面的
 * 意思正好相反 —— 前者要让人重改签名，后者要照常按「每次都得改签名」走。
 *
 * 为什么失败也返回 `{ ok: false }` 而不是抛：这个函数是**页面启动时**调的，它只回答
 * 「这一次还要不要让用户改签名」。后端抖一下就抛，等于让一次与用户无关的刷新把整个上传页
 * 按成红的 —— 多抄一次签名只是麻烦，把能用的页面报成坏的是骗人。失效方向必须是「按没会话处理」。
 */
export async function checkSession(token) {
  const t = String(token || "").trim();
  // 形状不对的令牌不发请求：它不可能换来 ok，白打一次请求只会让后端多一条无意义的账。
  if (!SESSION_TOKEN_RE.test(t)) return { ok: false };
  if (!IS_API_CONFIGURED) return { ok: false };
  let res;
  try {
    res = await fetchWithTimeout(
      url("/session/check"),
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: t }),
      },
      SESSION_TIMEOUT_MS
    );
  } catch {
    return { ok: false }; // 网络断了 / 超时 / 跨域被拦，都归到「这次没有会话」
  }
  if (!res.ok) return { ok: false };
  let json;
  try {
    json = await res.json();
  } catch {
    return { ok: false }; // 回的不是 JSON（网关错误页之类）＝这一格读不懂，不当成有会话
  }
  if (!json || json.ok !== true) return { ok: false };
  // 后端在这一格里回了整张记录（uid / nickname / avatar / level / expiresAt）—— 它不是
  // 装饰，refreshSession 靠 `uid` 判「这张令牌是不是属于输入框里这串 UID」。只把 ok 往上
  // 传，等于让 sessionFor 永远为假：页面会一直说「每次都得改签名」，令牌等于没生效。
  return {
    ok: true,
    uid: json.uid === undefined || json.uid === null ? "" : String(json.uid),
    nickname: typeof json.nickname === "string" ? json.nickname : "",
    avatar: typeof json.avatar === "string" ? json.avatar : "",
    level: json.level === undefined || json.level === null ? null : json.level,
    expiresAt: Number(json.expiresAt) || 0,
  };
}

/**
 * 注销长效会话令牌（幂等）。
 *
 * 幂等：同一个令牌注销两次，第二次照样算成功 —— 服务端认的是「这一串现在不能用了」，
 * 不是「我刚刚删掉了它」。所以这里不区分「删掉了」与「本来就没有」，只看 ok。
 * 失败照样返回 `{ ok: false }` 不抛：退不出去就退不出去，页面上一句「没退成，再试一次」
 * 比一个红错更有用，而这个函数本来就拿不到给用户看的那句话。
 */
export async function revokeSession(token) {
  const t = String(token || "").trim();
  if (!SESSION_TOKEN_RE.test(t)) return { ok: false };
  if (!IS_API_CONFIGURED) return { ok: false };
  let res;
  try {
    res = await fetchWithTimeout(
      url("/session/revoke"),
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: t }),
      },
      SESSION_TIMEOUT_MS
    );
  } catch {
    return { ok: false }; // 网络断了 / 超时 / 跨域被拦
  }
  if (!res.ok) return { ok: false };
  let json;
  try {
    json = await res.json();
  } catch {
    return { ok: false };
  }
  return { ok: json && json.ok === true };
}

/**
 * 问后端要它自己的三个上限（§17.6）：
 *   `maxBytes` = **单枚**上限（键名不动，今天的前端在读）、`maxTotalBytes` = 整套、`maxModules` = 枚数。
 *
 * 为什么要问而不是在 config.js 里抄一份：抄出来的那一份一定会有人对不上 ——
 * 前端写过 8MB、Worker 实际 2MB，于是用户按 8MB 传，传到一半被 400 拒掉，而页面上明明还写着
 * 「允许 8MB」。这一轮把那个兜底值也删了：三个数**只有后端一个定义处**，问到几个算几个。
 *
 * 问不到就是问不到，不许拿一个好看的数字顶上去：`fields` 逐条记着哪一条自报了、哪一条没有。
 * 没自报的那一条前端**不拦**（拦就是替服务端编一个上限），页面上写「后端没自报这一条，
 * 由服务端拒」—— 这一句是真话，而「按 8MB 兜底」不是。
 *
 * 失败不抛错：这个站要能在后端没接的时候照常浏览与填表。
 * from 字段给说明页的「这个站自己的状态」用，让人看得出接线到哪一档。
 */
export async function fetchServiceLimits() {
  const empty = { maxBytes: null, maxTotalBytes: null, maxModules: null, fields: {}, from: "not-configured" };
  if (!IS_API_CONFIGURED) return empty;
  let res;
  try {
    res = await fetch(url("/"), { method: "GET", headers: { Accept: "application/json" } });
  } catch {
    return { ...empty, from: "unreachable" };
  }
  if (!res.ok) return { ...empty, from: "unreachable" };
  let json;
  try {
    json = await res.json();
  } catch {
    return { ...empty, from: "unreachable" };
  }
  // 只收「正整数」那一种值：NaN、字符串、0、负数都算没自报，不算「上限 0」。
  const pick = (key) => {
    const n = Number(json?.[key]);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : null;
  };
  const out = {
    maxBytes: pick("maxBytes"),
    maxTotalBytes: pick("maxTotalBytes"),
    maxModules: pick("maxModules"),
    from: "backend",
  };
  /* 举报那一格的限制由同一个 GET / 自报（`reportLimits`）。前端不许抄第二份：
     后端把「一次几条引用」「单条至少几字节」改一个数，页面还在教用户按旧的门槛填材料，
     而那些填法会一条条撞上「不算逐字」—— 这是把自家改动写成用户的错。 */
  const rl = json && typeof json.reportLimits === "object" ? json.reportLimits : null;
  const pickIn = (src, key) => {
    const n = Number(src?.[key]);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : null;
  };
  out.report = rl
    ? {
        maxEvidenceItems: pickIn(rl, "maxEvidenceItems"),
        minQuoteBytes: pickIn(rl, "minQuoteBytes"),
        maxQuoteChars: pickIn(rl, "maxQuoteChars"),
        maxReasonChars: pickIn(rl, "maxReasonChars"),
        maxBodyBytes: pickIn(rl, "maxBodyBytes"),
        perIpPerHour: pickIn(rl, "perIpPerHour"),
        perUidPerHour: pickIn(rl, "perUidPerHour"),
      }
    : null;
  out.fields = {
    maxBytes: out.maxBytes !== null,
    maxTotalBytes: out.maxTotalBytes !== null,
    maxModules: out.maxModules !== null,
  };
  // 三条一条都没有 == 后端根本没自报上限（旧部署），from 要说成 no-field 而不是 backend，
  // 否则说明页会写「与后端一致」而其实什么都没一致。
  if (!Object.values(out.fields).some(Boolean)) return { ...empty, from: "no-field" };
  return out;
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

/**
 * 读索引与读台账都必须绕过本地缓存。
 *
 * 实测：jsDelivr 对 `@分支` 形式的地址回的是 `Cache-Control: public, max-age=604800`
 * —— 七天。也就是说源站清完缓存之后，**浏览器/管理器里那份旧索引还能留七天**，
 * 而「这个模块被下架了」恰恰是最不能拿旧数据回答的问题。`no-cache` 是「每次问服务器
 * 要不要重取」，配合对方给的弱 ETag 通常只是一个 304，代价很小。
 * 订阅端（管理器 App 自己发的那个请求）不归本站管，所以这一层只能把本站自己的页面钉住。
 */
const FRESH = { method: "GET", cache: "no-cache" };

/** 拉公开索引（MMRL 格式）并归一化。 */export async function fetchIndex() {
  if (!CONFIG.INDEX_URL.trim()) {
    throw new BackendError("not-configured", "公开索引地址还没配置：请在 config.js 填入 INDEX_URL。");
  }
  let res;
  try {
    res = await fetch(CONFIG.INDEX_URL, FRESH);
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

/* ---------------------------------------------------------- 处置台账（公示） */

/** 台账的 schema 标识（写入侧那一档）。与 contrib/repo/scripts/dispositions.mjs 的 DISPOSITIONS_SCHEMA 同值。 */
export const LEDGER_SCHEMA = "sukisu-dispositions-v2";
/**
 * 认得的 schema 全集 —— v1 的条目是 v2 的子集（少了两个可选字段），历史数据不改。
 * 这一份集合必须与索引仓库、Worker 两处同值；`tools/selftest.mjs --require-backend`
 * 拿仓库那份逐字比一次，漂了就红（这里漂了不会红，只会让公示页把已经认识的台账
 * 标成「不认识的 schema」，而那句提示正是给人看「这份数据不该被信任」的）。
 */
export const KNOWN_LEDGER_SCHEMAS = ["sukisu-dispositions-v2", "sukisu-dispositions-v1"];

/**
 * 台账的读取地址：显式填的优先，没填就从 INDEX_URL 换掉文件名。
 *
 * 为什么可以换文件名：索引和台账在索引仓库里就是同目录下的两个 json，只有 CDN 前缀
 * 会不同。把这个约定写成第二份完整 URL，就等于再造一个会和第一份漂移的定义处 ——
 * 后端 Worker 的 dispositionsRawUrl 是同一个理由、同一个做法。
 * 索引地址上挂的 query 原样保留：有些 CDN 靠它鉴权，去掉就变成拉不到。
 */
export function dispositionsUrl() {
  const direct = CONFIG.DISPOSITIONS_URL.trim();
  if (direct) return direct;
  const index = CONFIG.INDEX_URL.trim();
  if (!index) return "";
  let u;
  try {
    u = new URL(index);
  } catch {
    return "";
  }
  const segs = u.pathname.split("/");
  segs[segs.length - 1] = "dispositions.json";
  u.pathname = segs.join("/");
  u.hash = "";
  return u.href;
}

/** 台账条目上可能出现的命中条件。与仓库侧选择器同名同集合。 */
export const SELECTOR_KEYS = ["id", "versionCode", "sha256", "coolapkUid"];

/**
 * 三张说人话的表。集合本身（有哪些 kind / reason / 选择器）是索引仓库定义的，
 * 这里只负责中文措辞与分组顺序，所以 tools/selftest.mjs 会拿仓库那份把键对一遍 ——
 * 仓库新增一个 reason 而这里没有，公示页就会把它归到「不认识的分类」，那不该发生。
 */
export const SELECTOR_LABELS = {
  id: "模块 ID",
  versionCode: "versionCode",
  sha256: "包 sha256",
  coolapkUid: "酷安 UID",
};

export const KIND_LABELS = { revoke: "下架", deny: "拒收" };

/** 键的顺序就是分组顺序。 */
export const REASON_LABELS = {
  "test-probe": "流水线验证留下的探针包",
  malware: "恶意行为",
  policy: "违反本站收录规则",
  copyright: "版权 / 授权争议",
  impersonation: "冒充他人或既有模块",
  security: "会损坏设备或系统",
  abandoned: "作者要求下架或长期无人维护且有害",
  other: "其他（理由写在每条的说明里）",
};

/**
 * 归一化一份台账用于公示。
 *
 * 这里的失效方向和 CI 那份**相反**，而且是故意的：仓库侧读不懂就抛错、整次推导停住，
 * 因为那里「跳过一条坏条目」等于让被下架的模块复活。这里只是给浏览器读的一份展示，
 * 停住整页没有意义，所以未知 schema / 未知 kind / 缺字段都保留原样标出来，一条都不丢。
 * 「这条我看不懂」必须显示出来 —— 悄悄丢掉就等于公示漏了一项处置。
 */
export function normalizeDispositions(json) {
  if (!json || typeof json !== "object") {
    throw new BackendError("bad-response", "处置台账不是 JSON 对象。");
  }
  if (!Array.isArray(json.dispositions)) {
    throw new BackendError("bad-response", "处置台账里没有 dispositions 数组，格式不对。");
  }
  const items = json.dispositions.map((d) => {
    const raw = d && typeof d === "object" ? d : {};
    const at = typeof raw.at === "string" ? Date.parse(raw.at) : NaN;
    return {
      kind: String(raw.kind || ""),
      reason: String(raw.reason || ""),
      by: String(raw.by || ""),
      at: String(raw.at || ""),
      note: String(raw.note || ""),
      // 复核命令：任何人可以照着跑一遍来自己确认这条处置成立。公示页把它显示出来，
      // 否则「可复验」只写在 by 那个指针里，普通人手上没有仓库就复验不了。
      verify: String(raw.verify || ""),
      atMs: Number.isFinite(at) ? at : null,
      // v2 的两个字段：这一层不校验、不重排，原样带过去给公示页用（校验是索引仓库与 Worker 那两份判据的活）。
      // 缺就是 null / 空数组 —— 历史条目一个都没有，页面必须照旧渲染（spec §10），不许空白不许报错。
      subject: raw.subject && typeof raw.subject === "object" && !Array.isArray(raw.subject) ? raw.subject : null,
      evidence: Array.isArray(raw.evidence) ? raw.evidence : [],
      // 选择器按固定顺序取，缺的不显示；一个都没有的条目也照样列出来（它是台账的一条）
      selectors: SELECTOR_KEYS.filter((k) => raw[k] !== undefined && raw[k] !== null && raw[k] !== "")
        .map((k) => [k, String(raw[k])]),
    };
  });
  return {
    schema: typeof json.schema === "string" ? json.schema : "",
    schemaKnown: KNOWN_LEDGER_SCHEMAS.includes(
      typeof json.schema === "string" ? json.schema : ""
    ),
    lastUpdate: typeof json.lastUpdate === "number" ? json.lastUpdate : null,
    items,
  };
}

/**
 * 处置指针 → 能点的链接。
 *
 * 只有「GitHub 上某条 issue 评论的永久链接」这一种形状才给链接。其它一律原样显示成文本：
 * 猜出来的链接比不链接更坏 —— 点进去是 404 或别人的讨论，等于公示页在替一条它并不知道的
 * 证据背书。
 *
 * 这一条今天只服务**旧台账**：main 上还有 5 条 `by` 是评论 URL 的记录（2026-10-21 之前下的），
 * 新版写入端改的是机器章（见下面的 bySeal），读的一侧因此必须同时认两种形状 ——
 * 只认新的那一种，公示页就会把已经发生过的处置念成「没有证据」。
 */
export function byLink(value) {
  const s = String(value || "").trim();
  return /^https:\/\/github\.com\/[^/\s]+\/[^/\s]+\/issues\/\d+#issuecomment-\d+$/.test(s) ? s : "";
}

/**
 * 处置指针 → 机器章。返回那一枚 commit 的 sha，不是章就返回空串。
 *
 * 形状的定义只有**写入端那一处**（索引仓库 `scripts/revoke.mjs` 的 `MACHINE_SEAL_RE`）；
 * 这里抄一份是因为跨仓库拿不到它（fork 里没有 contrib），漂移由 modules-web 的 selftest
 * 在两条仓库都在的机器上对一次。
 *
 * 章不是链接：`ci:audit@<sha>` 里不带 owner/repo，公示页拼不出一个能点的地址。
 * 所以这一格显示的是「哪一次运行钉的」这串文字，点开要看的是同一条记录里的 `verify` 命令 —— 把
 * 它做成一个看起来像链接的东西，比不给链接更坏。
 */
export function bySeal(value) {
  const m = /^ci:audit@([0-9a-f]{40})$/.exec(String(value || "").trim());
  return m ? m[1] : "";
}

/**
 * 证据文件名 → 能取的地址。
 *
 * 台账里的 `evidence[].file` 是仓库根相对路径（`evidence/<64 hex>.json`），而这一页拿到的是
 * **台账**的地址，两种部署各差一层目录：
 *   - 镜像端点 `https://host/dispositions.json` → 证据在 `https://host/evidence/<sha>.json`；
 *   - 直给仓库 `…/<owner>/<repo>/<ref>/json/dispositions.json` → 证据在 `…/<ref>/evidence/<sha>.json`。
 * 所以规则是「换掉文件名，并越过 `json` 这一层到仓库根」，而不是原地换名 —— 后者在直给仓库那一档
 * 会拼出一个不存在的 `json/evidence/…`，而它看起来完全像对的。
 *
 * ⚠️ 先验形状再拼 URL：台账是**签名之前由人写进 PR 的**数据，`file` 这一格如果被写成
 * `https://别处/x.json` 或 `../../`，原地拼接就等于让公示页替上传者发一次跨站请求。
 * 不匹配的那个正则的形状一律不取。
 */
export const LEDGER_EVIDENCE_FILE_RE = /^evidence\/[0-9a-f]{64}\.json$/;

export function evidenceUrlFor(file) {
  const f = String(file || "").trim();
  if (!LEDGER_EVIDENCE_FILE_RE.test(f)) return "";
  const base = dispositionsUrl();
  if (!base) return "";
  let u;
  try {
    u = new URL(base);
  } catch {
    return "";
  }
  const segs = u.pathname.split("/");
  segs.pop(); // 去掉文件名本身
  if (segs.length && segs[segs.length - 1] === "json") segs.pop(); // 再越过 json/ 这一层
  u.pathname = `${segs.join("/")}/${f}`.replace(/\/{2,}/g, "/");
  u.hash = "";
  return u.href;
}

const evidenceCache = new Map();

/**
 * 取一份固化证据。**只在真的要看的时候取**（点开某个人卡的那一层），
 * 一份动辄几十 KB，第一屏不该为它发 N 个请求。
 * 失败分两类报：形状不对（台账里那格被写坏了）与取不到（还没合进 main、镜像端点没这条路、网络）。
 */
export async function fetchEvidence(file) {
  const f = String(file || "").trim();
  if (!LEDGER_EVIDENCE_FILE_RE.test(f)) {
    return { ok: false, reason: "台账里这一格的文件名不是 `evidence/<64 位十六进制>.json` 的形状，本页不去取它。" };
  }
  if (evidenceCache.has(f)) return evidenceCache.get(f);
  const url = evidenceUrlFor(f);
  if (!url) {
    const r = { ok: false, reason: "处置台账的地址还没确定，证据文件也就没有可推的目录。" };
    evidenceCache.set(f, r);
    return r;
  }
  let out;
  try {
    const res = await fetch(url, FRESH);
    if (!res.ok) {
      out = { ok: false, reason: `取不到 ${f}（HTTP ${res.status}）。可能是那条处置的证据还没合进默认分支，或镜像端点还没有这一条路。`, url };
    } else {
      out = { ok: true, data: await res.json(), url };
    }
  } catch {
    out = { ok: false, reason: `取 ${f} 时请求没成功（网络或跨域）。`, url };
  }
  evidenceCache.set(f, out);
  return out;
}

export async function fetchDispositions() {
  const target = dispositionsUrl();
  if (!target) {
    throw new BackendError(
      "not-configured",
      "处置台账地址还没确定：请在 config.js 填入 INDEX_URL（台账按同目录推导）或 DISPOSITIONS_URL。"
    );
  }
  let res;
  try {
    res = await fetch(target, FRESH);
  } catch {
    throw new BackendError(
      "network",
      "拉不到处置台账。可能是地址写错、该主机不允许浏览器跨域读取，或网络不通。"
    );
  }
  if (!res.ok) throw new BackendError("bad-response", `处置台账返回 HTTP ${res.status}。`);
  let json;
  try {
    json = await res.json();
  } catch {
    throw new BackendError("bad-response", "处置台账不是合法 JSON，没法解析。");
  }
  return normalizeDispositions(json);
}
