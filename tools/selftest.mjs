// zip 解析与 module.prop 预填的自检：手搓真实字节喂给浏览器端的解析代码。
// Node 18+ 也有 DecompressionStream / Blob / Response，所以 public/scripts 里的
// 实现可以原样在这里跑，不需要为测试另写一份。
// 用法：node tools/selftest.mjs [--require-backend]
//   --require-backend 把「找不到后端源码」从跳过升级为失败，CI 用这个。
import zlib from "node:zlib";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { CONFIG } from "../public/scripts/config.js";
import {
  ZipError,
  canInflateRaw,
  listEntries,
  readEntry,
  inspectEntries,
} from "../public/scripts/zipread.js";
import { parseModuleProp, missingRequired } from "../public/scripts/moduleprop.js";

const REQUIRE_BACKEND = process.argv.includes("--require-backend");

let pass = 0;
let fail = 0;
let skipped = 0;
function check(name, ok, extra) {
  if (ok) {
    pass++;
    console.log(`  ok   ${name}`);
  } else {
    fail++;
    console.log(`  FAIL ${name}${extra ? " —— " + extra : ""}`);
  }
}

/**
 * 跳过的检查必须出现在总结里。
 * 上一版把「后端源码不在本机」做成静默跳过，结果 contrib 目录一搬家，
 * 6 条跨仓库字段名校验（当时是 5 条）就再也不跑了，而输出仍然写着「全部通过」——
 * 这正是最坏的一种绿：契约检查消失了，而没人看见它消失。
 */
function skip(name, why) {
  skipped++;
  console.log(`  SKIP ${name} —— ${why}`);
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** 生成一个真正的 zip：本地头 + deflate/stored + 中央目录 + EOCD，可选尾部注释。 */
function makeZip(files, { comment = "" } = {}) {
  const parts = [];
  const central = [];
  let offset = 0;

  for (const file of files) {
    const name = Buffer.from(file.name, "utf8");
    const raw = Buffer.from(file.content, "utf8");
    const stored = file.stored === true;
    const comp = stored ? raw : zlib.deflateRawSync(raw);
    const sum = crc32(raw);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6); // 文件名是 utf-8
    local.writeUInt16LE(stored ? 0 : 8, 8);
    local.writeUInt16LE(0x3000, 10);
    local.writeUInt16LE(0x5a1c, 12);
    local.writeUInt32LE(sum, 14);
    local.writeUInt32LE(comp.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    parts.push(local, name, comp);

    const dir = Buffer.alloc(46);
    dir.writeUInt32LE(0x02014b50, 0);
    dir.writeUInt16LE(20, 4);
    dir.writeUInt16LE(20, 6);
    dir.writeUInt16LE(0x0800, 8);
    dir.writeUInt16LE(stored ? 0 : 8, 10);
    dir.writeUInt16LE(0x3000, 12);
    dir.writeUInt16LE(0x5a1c, 14);
    dir.writeUInt32LE(sum, 16);
    dir.writeUInt32LE(comp.length, 20);
    dir.writeUInt32LE(raw.length, 24);
    dir.writeUInt16LE(name.length, 28);
    dir.writeUInt16LE(0, 30);
    dir.writeUInt16LE(0, 32);
    dir.writeUInt16LE(0, 34);
    dir.writeUInt16LE(0, 36);
    dir.writeUInt32LE(0, 38);
    dir.writeUInt32LE(offset, 42);
    central.push(dir, name);

    offset += local.length + name.length + comp.length;
  }

  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(Buffer.byteLength(comment, "utf8"), 20);

  return Buffer.concat([...parts, cd, eocd, Buffer.from(comment, "utf8")]);
}

function toArrayBuffer(buf) {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

const PROP = [
  "id=kernelsu-next",
  "name=KSU Next 加速模块",
  "version=v1.2.0",
  "versionCode=12",
  "author=some_coolapk_dev",
  "description=给 A15 优化动画=省电, 别和别家同用",
  "",
].join("\r\n");

async function main() {
  console.log(`DecompressionStream 可用：${canInflateRaw()}`);

  console.log("\n[1] 规范模块包（根目录 module.prop，deflate）");
  const good = makeZip([
    { name: "module.prop", content: PROP },
    { name: "customize.sh", content: "ui_print hello\n" },
    { name: "system/bin/tool", content: "binary-ish content ".repeat(60) },
  ]);
  const goodBuf = toArrayBuffer(good);
  const entries = listEntries(goodBuf);
  check("条目数 = 3", entries.length === 3, `实际 ${entries.length}`);
  const look = inspectEntries(entries);
  check("判定为可投稿（根目录有 module.prop）", look.ok === true);
  check("没有误报嵌套路径", look.nestedPaths.length === 0, JSON.stringify(look.nestedPaths));

  const text = new TextDecoder().decode(await readEntry(goodBuf, look.rootEntry));
  check("解压出来的内容与原文件逐字节一致", text === PROP);
  const prop = parseModuleProp(text);
  check("id 解析正确", prop.id === "kernelsu-next", prop.id);
  check("versionCode 解析正确", prop.versionCode === "12", prop.versionCode);
  check("描述里第二个 '=' 没被当成分隔符", prop.description === "给 A15 优化动画=省电, 别和别家同用", prop.description);
  check("必填项无缺失", missingRequired(prop).length === 0, missingRequired(prop).join(","));
  check("非 module.prop 条目也能定位", entries[1].dataOffset > 0);

  console.log("\n[2] module.prop 被套在一层文件夹里（服务端会拒）");
  const nestedBuf = toArrayBuffer(
    makeZip([
      { name: "MyModule/", content: "" },
      { name: "MyModule/module.prop", content: PROP },
    ])
  );
  const nested = inspectEntries(listEntries(nestedBuf));
  check("判定为不可投稿", nested.ok === false);
  check("报告出嵌套路径", nested.nestedPaths.includes("MyModule/module.prop"), JSON.stringify(nested.nestedPaths));

  console.log("\n[3] stored（未压缩）的 module.prop");
  const storedBuf = toArrayBuffer(makeZip([{ name: "module.prop", content: PROP, stored: true }]));
  const storedLook = inspectEntries(listEntries(storedBuf));
  const storedText = new TextDecoder().decode(await readEntry(storedBuf, storedLook.rootEntry));
  check("stored 条目原样读出", storedText === PROP);

  console.log("\n[4] 带尾部注释的 zip（EOCD 要往回扫）");
  const cmtBuf = toArrayBuffer(makeZip([{ name: "module.prop", content: PROP }], { comment: "made by 7-Zip, plus a comment" }));
  check("仍然找到条目", listEntries(cmtBuf).length === 1);

  console.log("\n[5] 不是 zip");
  const junk = toArrayBuffer(Buffer.from("this is definitely not a zip file at all"));
  let threw = null;
  try {
    listEntries(junk);
  } catch (err) {
    threw = err;
  }
  check("抛出 ZipError/not-zip", threw instanceof ZipError && threw.code === "not-zip", String(threw && threw.code));
  check("报错文案是中文（会直接给用户看）", threw && /zip/.test(threw.message));

  console.log("\n[6] 空的 module.prop（缺必填）");
  const sparse = parseModuleProp("id=only-id\n");
  check("缺失必填项被点名", missingRequired(sparse).join(",") === "name,version,versionCode", missingRequired(sparse).join(","));

  console.log("\n[7] MMRL 索引归一化（浏览页的数据层）");
  const { normalizeIndex, BackendError } = await import("../public/scripts/api.js");
  const mmrl = normalizeIndex({
    name: "人人共建模块索引",
    lastUpdate: 1760000000000,
    modules: [
      {
        id: "kernelsu-next",
        name: "KSU Next",
        author: "某作者",
        description: "描述",
        verified: false,
        versions: [
          { version: "v1.0.0", versionCode: 10, zipUrl: "https://dl/a.zip", size: 1200, time: 1750000000000 },
          { version: "v1.2.0", versionCode: 12, zipUrl: "https://dl/b.zip", size: 8000000, time: 1759000000000 },
          { version: "v1.1.0", versionCode: 11, zipUrl: "https://dl/c.zip", size: 40000, time: 1755000000000 },
        ],
      },
      { id: "no-versions", name: "没有版本数组" },
      { id: "empty-versions", name: "空数组", versions: [] },
    ],
  });
  check("索引名与更新时间读出", mmrl.name === "人人共建模块索引" && mmrl.lastUpdate === 1760000000000);
  check("模块数 3", mmrl.modules.length === 3);
  const first = mmrl.modules[0];
  check("versions 乱序也挑出版本号最大的作 latest", first.latest.versionCode === 12 && first.latest.version === "v1.2.0", JSON.stringify(first.latest));
  check("verified 归一成布尔", first.verified === false);
  check("缺字段不炸，name 回落 id", mmrl.modules[1].name === "没有版本数组" && mmrl.modules[2].name === "空数组");
  check("无 versions 时 latest 为 null", mmrl.modules[1].latest === null && mmrl.modules[2].latest === null);
  let bad = null;
  try {
    normalizeIndex({ name: "x" });
  } catch (err) {
    bad = err;
  }
  check("非 MMRL 结构报 BackendError", bad instanceof BackendError, String(bad && bad.name));

  console.log("\n[8] 酷安 UID 与出处规则");
  const { isCoolapkUid, normalizeCoolapkUrl, lookupCoolapkUser, USER_STATUS, fetchServiceLimits } =
    await import("../public/scripts/api.js");
  check("2781460 是合法 UID", isCoolapkUid("2781460") === true);
  check("带空格也认", isCoolapkUid("  2781460 ") === true);
  check("拒绝带链接前缀", isCoolapkUid("https://www.coolapk.com/u/2781460") === false);
  check("拒绝非数字", isCoolapkUid("27a1460") === false);
  check("拒绝过短/过长", isCoolapkUid("123") === false && isCoolapkUid("1".repeat(13)) === false);

  check(
    "补协议：www.coolapk.com/feed/1 → https",
    normalizeCoolapkUrl("www.coolapk.com/feed/123456") === "https://www.coolapk.com/feed/123456",
    normalizeCoolapkUrl("www.coolapk.com/feed/123456")
  );
  check("m 子域接受", normalizeCoolapkUrl("https://m.coolapk.com/net/654321").length > 0);
  check("主域接受", normalizeCoolapkUrl("https://coolapk.com/u/1") === "https://coolapk.com/u/1");
  check("假域名拒绝", normalizeCoolapkUrl("https://coolapk.com.evil.tld/u/1") === "");
  check("路径里藏域名拒绝", normalizeCoolapkUrl("https://evil.tld/https://www.coolapk.com/u/1") === "");
  check("javascript 协议拒绝", normalizeCoolapkUrl("javascript:alert(1)//coolapk.com") === "");
  check("网盘链接不算出处", normalizeCoolapkUrl("https://pan.baidu.com/s/abc") === "");
  check("空输入返回空", normalizeCoolapkUrl("   ") === "");

  // 「后端未接线时走 off」这条**测不出行为**了：IS_UID_VERIFY_ON 是 config.js 加载时算好的
  // 派生值，而 API_BASE 现在填的是真地址 —— 测试进程里改 CONFIG 不会让它重算，硬调一次就是
  // 真发一个网络请求（本仓库的测试规矩是不联网）。所以钉三件真能钉的：
  // 派生规则、早退语句还在、以及形状不对时确实不发请求。
  const { IS_UID_VERIFY_ON } = await import("../public/scripts/config.js");
  check(
    "核实开关的派生规则：API_BASE 与核实路径都非空才算开着",
    IS_UID_VERIFY_ON === (CONFIG.API_BASE.trim() !== "" && CONFIG.COOLAPK_USER_PATH.trim() !== "")
  );
  const apiSrc = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../public/scripts/api.js"), "utf8");
  check(
    "未接线时核实走 off 而不是报错卡死（早退语句钉住）",
    /if \(!IS_UID_VERIFY_ON\) return \{ status: "off" \};/.test(apiSrc)
  );
  const realFetch = globalThis.fetch;
  globalThis.fetch = () => {
    throw new Error("这条测试不该发出任何请求");
  };
  let invalid;
  try {
    invalid = await lookupCoolapkUser("123"); // 位数不够，不是合法 UID
  } finally {
    globalThis.fetch = realFetch;
  }
  check("UID 形状不对时直接判 invalid，一个请求都不发", invalid.status === "invalid", JSON.stringify(invalid));

  console.log("\n[9] 处置台账公示（下架 / 拉黑）");
  const {
    normalizeDispositions,
    dispositionsUrl,
    byLink,
    LEDGER_SCHEMA,
    KIND_LABELS,
    REASON_LABELS,
    SELECTOR_KEYS,
  } = await import("../public/scripts/api.js");

  const ledger = normalizeDispositions({
    schema: LEDGER_SCHEMA,
    lastUpdate: 1791687753247,
    dispositions: [
      {
        kind: "revoke",
        reason: "test-probe",
        by: "gh:yufeng-liang@issuecomment-6104846280",
        at: "2026-10-11T03:02:31.612Z",
        note: "流水线验证留下的探针包",
        id: "e2e_probe_loop2",
      },
      {
        kind: "deny",
        reason: "malware",
        by: "gh:mod@example.com",
        at: "2026-10-12T00:00:00+08:00",
        coolapkUid: "2781460",
        id: "bad.module",
        versionCode: 3,
      },
    ],
  });
  check("台账条数读出", ledger.items.length === 2);
  check("schema 认得", ledger.schemaKnown === true);
  check("带时区偏移的 at 解析成同一个时刻", Number.isFinite(ledger.items[1].atMs) && ledger.items[1].atMs === Date.parse("2026-10-11T16:00:00Z"), String(ledger.items[1].atMs));
  check("选择器按固定顺序取出，id+versionCode 是一条而不是两条", ledger.items[1].selectors.map(([k]) => k).join(",") === "id,versionCode,coolapkUid", JSON.stringify(ledger.items[1].selectors));
  check("缺 note 不炸", ledger.items[1].note === "");

  // 读取层的失效方向和 CI 那份相反，这条必须钉住：这里丢掉一条台账 == 公示漏一项处置。
  const weird = normalizeDispositions({
    schema: "sukisu-dispositions-v2",
    dispositions: [
      { kind: "quarantine", reason: "brand-new-case", at: "不是时间", id: "x" },
      { kind: "revoke", reason: "malware", by: "b", at: "2026-10-11T00:00:00Z", id: "y" },
      "不是对象",
    ],
  });
  check("未知 schema 标出来而不是当空台账", weird.schemaKnown === false);
  check("未知 kind / reason / 坏时间 / 非对象条目一条都不丢", weird.items.length === 3 && weird.items[0].atMs === null && (weird.items[2]?.selectors.length ?? -1) === 0, `${weird.items.length} 条`);
  let ledErr = null;
  try {
    normalizeDispositions({ schema: LEDGER_SCHEMA });
  } catch (e) {
    ledErr = e;
  }
  check("没有 dispositions 数组时报错而不是显示空公示", ledErr instanceof BackendError, String(ledErr && ledErr.name));

  // 公示页的数据源只有一个定义处：INDEX_URL。显式 DISPOSITIONS_URL 才覆盖它。
  // 存回去而不是清成空：config.js 现在填的是真地址，测试把它抹了会让后面的检查
  // 跑在一个「谁都没配置」的假现场上。
  const savedIndex = CONFIG.INDEX_URL;
  const savedDisp = CONFIG.DISPOSITIONS_URL;
  try {
    CONFIG.DISPOSITIONS_URL = "";
    CONFIG.INDEX_URL = "";
    check("两个地址都没填时不猜地址", dispositionsUrl() === "");
    CONFIG.INDEX_URL = "https://cdn.jsdelivr.net/gh/o/r@main/json/modules.json";
    check("按 INDEX_URL 同目录推导台账地址", dispositionsUrl() === "https://cdn.jsdelivr.net/gh/o/r@main/json/dispositions.json", dispositionsUrl());
    CONFIG.INDEX_URL = "https://raw.githubusercontent.com/o/r/main/json/modules.json?v=3";
    check("索引地址上的 query 保留（有些 CDN 靠它鉴权）", dispositionsUrl().endsWith("/json/dispositions.json?v=3"), dispositionsUrl());
    CONFIG.DISPOSITIONS_URL = "https://mirror.example.com/d.json";
    check("显式配置优先于推导", dispositionsUrl() === "https://mirror.example.com/d.json");
  } finally {
    CONFIG.INDEX_URL = savedIndex;
    CONFIG.DISPOSITIONS_URL = savedDisp;
  }

  // 指针只在形状确实是 GitHub 评论永久链接时才点得开；猜出来的链接等于公示页替一条
  // 它并不知道去向的证据背书。
  const PROOF = "https://github.com/o/r/issues/33#issuecomment-123456";
  check("永久链接形状的证据给链接", byLink(PROOF) === PROOF);
  check("旧形状 / 缺评论锚点 / 明文 / 假域名 / 只换 host 的钓鱼地址都不给链接",
    [
      "gh:me@issuecomment-123456",
      "https://github.com/o/r/issues/33",
      "http://github.com/o/r/issues/33#issuecomment-1",
      "https://github.com.evil.tld/o/r/issues/33#issuecomment-1",
      "https://evil.example.com/o/r/issues/33#issuecomment-1",
      "https://github.com/o/r/pull/33#issuecomment-1",
      "",
      undefined,
    ].every((v) => byLink(v) === ""),
    [
      "https://github.com/o/r/pull/33#issuecomment-1",
      "https://github.com.evil.tld/o/r/issues/33#issuecomment-1",
    ].map((v) => `${v}->${byLink(v)}`).join(" ")
  );

  // 前端不判台账（判据在仓库那份），所以这里只钉两件事：视图接上了，
  // 以及浏览页搜不到时会去问台账 —— 那条「不是没被投过，是被下架了」是本页的意义。
  const appSrc = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../public/scripts/app.js"), "utf8");
  check("公示页接进了路由", /incidents: \{ el: "#view-incidents"/.test(appSrc));
  // 索引与台账两处读取都必须绕本地缓存：jsDelivr 对 @分支 回 max-age=604800（七天），
  // 源站清完缓存之后浏览器里那份旧的还能留七天 —— 而「这个模块被下架了」最不能用旧数据答。
  check(
    "索引与台账两处读取都带 cache: no-cache（不吃那七天的本地缓存）",
    /const FRESH = \{ method: "GET", cache: "no-cache" \};/.test(apiSrc) &&
      /fetch\(CONFIG\.INDEX_URL, FRESH\)/.test(apiSrc) &&
      /fetch\(target, FRESH\)/.test(apiSrc)
  );
  check("浏览页搜不到时会去查台账，命中就说明是被处置了", /ledgerHitFor\(q\)/.test(appSrc) && /它不是没被投过，是被下架或拒收了/.test(appSrc));

  /* ------------------------------------------------ 与后端的字段名/契约对齐     这一节防的是「两边各自改了常量，直到线上报错才发现」。曾经前端发 turnstile、
     后端读 cf-turnstile-response；前端写 8MB、后端实际 2MB。两个都是静默失效。 */

  check(
    "人机校验字段名在后端认的范围内",
    CONFIG.TURNSTILE_FIELD === "turnstile" || CONFIG.TURNSTILE_FIELD === "cf-turnstile-response",
    CONFIG.TURNSTILE_FIELD
  );
  check("酷安 UID 字段名与后端约定一致", CONFIG.COOLAPK_UID_FIELD === "coolapkUid", CONFIG.COOLAPK_UID_FIELD);
  check("前端不再自己决定上限：上限改为问后端", typeof fetchServiceLimits === "function");
  check(
    "核实状态里有诚实的 self_reported（不拿「暂时无法核实」糊弄「这条能力没接」）",
    Boolean(USER_STATUS.self_reported) && USER_STATUS.self_reported.tone !== "ok"
  );

  /* ------------------------------------------------------- 投稿者昵称的来源
     昵称不是投稿人自己敲的，而是后端按酷安 UID 反查回来的结果 —— 这条改了就不是文案问题：
     它决定「UID 是 A、署名写 B」这种组合能不能进索引。所以显隐、锁定、退路三样都要钉住。 */
  const formHtml = readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "../public/index.html"),
    "utf8"
  );
  check(
    "昵称整行默认不出现，出现时叫「投稿人酷安昵称」且不挂必填星号",
    /id="nick-field" hidden/.test(formHtml) &&
      /<label for="f-uploader">投稿人酷安昵称<\/label>/.test(formHtml) &&
      !/for="f-uploader">投稿人酷安昵称<span class="req">/.test(formHtml)
  );
  // 界面上只有「投稿人」这一个称呼（about 页早就这么写了），混用会让人以为是两个人
  check(
    "UID 那栏点名是「投稿人酷安 UID」，且全站不再出现「投稿者」",
    /<label for="f-uid">投稿人酷安 UID<span class="req">\*<\/span><\/label>/.test(formHtml) &&
      !formHtml.includes("投稿者") &&
      !appSrc.includes("投稿者")
  );
  check(
    "硬性条件是 2×2 四格，且 app.js 要写的 #spec-max 还在其中一格",
    (formHtml.match(/class="spec__cell"/g) || []).length === 4 &&
      !formHtml.includes("spec__row") &&
      (formHtml.match(/id="spec-max"/g) || []).length === 1
  );
  // 窄屏保持两列是用户明确要的（四条硬条件要一眼看完），代价改由字号承担。
  const panelCss = readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "../public/styles/panel.css"),
    "utf8"
  );
  check(
    "任何屏宽下 .spec 都是两列（窄屏只收字号内边距，不许退回 1fr）",
    /grid-template-columns: repeat\(2, minmax\(0, 1fr\)\)/.test(panelCss) &&
      !/\.spec\s*\{[^}]*grid-template-columns:\s*1fr/.test(panelCss)
  );
  check(
    "昵称那一行排在 UID 输入框之后（用户只填 UID，结果跟在后面）",
    formHtml.indexOf('data-k="coolapkUid"') > 0 &&
      formHtml.indexOf('id="nick-field"') > formHtml.indexOf('data-k="coolapkUid"')
  );
  check(
    "取到昵称时锁定输入框，取不到时才放开（两条都在）",
    /function syncUploaderField\(\)/.test(appSrc) &&
      /el\.readOnly = true;/.test(appSrc) &&
      /el\.readOnly = false;/.test(appSrc)
  );
  check(
    "还没填 / 正在查 / UID 形状不对时，这一行继续藏着（不占位也不误导）",
    /state\.uidStatus === "idle" \|\| state\.uidStatus === "checking" \|\| state\.uidStatus === "invalid"/.test(appSrc) &&
      /row\.hidden = true;/.test(appSrc)
  );
  check(
    "昵称以反查结果为准，且只认「当前这串 UID」的那一次结果",
    /state\.uidStatus === "verified" &&\s*\n\s*state\.uidInfo &&\s*\n\s*state\.uidInfo\.uid === fieldValue\("coolapkUid"\)/.test(appSrc) &&
      /el\.value = nickname;/.test(appSrc)
  );
  check(
    "改 UID 的第一下就同步昵称，不等 debounce 里的核实回来",
    /syncUploaderField\(\);\s*\n\s*runUidCheck\(\);/.test(appSrc)
  );
  check(
    "UID 改过、还没重查完时写的是「正在按新 UID 重查」，不是「需要你填」",
    /const rechecking = state\.uidStatus === "verified" && !nickname;/.test(appSrc) &&
      /rechecking \? "正在按新 UID 重查" : "需要你填"/.test(appSrc)
  );
  // 改了 UID 却没取到新昵称时，上一个 UID 的昵称必须消失 —— 而且要赶在「把这一行藏起来」
  // 之前：COOLAPK_VERIFY_REQUIRED=false 时「正在查」也允许提交，清空晚一步就漏进索引。
  const syncBody = appSrc.slice(
    appSrc.indexOf("function syncUploaderField()"),
    appSrc.indexOf("\n}", appSrc.indexOf("function syncUploaderField()"))
  );
  check(
    "取不到昵称时先抹掉自动带出的旧昵称，再删记号（手填的不受影响）",
    /if \(el\.dataset\.auto === "1"\) \{\s*\n\s*el\.value = "";\s*\n\s*delete el\.dataset\.auto;/.test(syncBody) &&
      syncBody.indexOf('el.value = "";') < syncBody.indexOf('state.uidStatus === "idle"'),
    "清空缺失，或被排到了藏行之后（checking 状态漏）"
  );
  // 取不到昵称有四种原因，界面必须分别说清是哪一种 —— 混起来就是骗人（与 self_reported 同理）
  check(
    "取不到昵称的四种状态各有自己的文案",
    ["not_found", "unavailable", "self_reported", "off"].every((k) => new RegExp(`^  ${k}: "`, "m").test(appSrc)),
    "UPLOADER_FALLBACK 少了状态"
  );
  check(
    "runUidCheck 的两个出口都会同步昵称状态（早退时不留下一个锁着的空框）",
    (appSrc.match(/^\s+syncUploaderField\(\);/gm) || []).length >= 3,
    `出现 ${(appSrc.match(/syncUploaderField\(\);/g) || []).length} 次`
  );
  check(
    "「抄自谁的帖子就写谁」这句已删，UID 路径写的是 App 内的实际点法",
    !formHtml.includes("抄自谁的帖子就写谁") &&
      /查看我的资料/.test(formHtml) &&
      /用户 UID/.test(formHtml)
  );
  // 删 DOM 节点必须连脚本引用一起删：留一个 $("#boot") 就是开机直接抛异常、整页不初始化
  check(
    "删掉的三处（查重提示、开机读数、举个例子）在标记与脚本里都没有残留",
    ["check-where", "boot", "举个例子"].every((k) => !formHtml.includes(k) && !appSrc.includes(k))
  );

  // 后端仓库在同一台机器上时，直接把它的源码当契约的另一端来读。
  // 路径靠猜迟早会像 contrib 从 H:\刷机包 搬到 H:\sukisu 那样一次搬家就全哑掉，
  // 所以显式环境变量优先：WORKER_SRC=/path/to/worker/src/index.ts npm test
  const here = dirname(fileURLToPath(import.meta.url));
  const workerCandidates = [
    process.env.WORKER_SRC,
    "../../sukisu/contrib/worker/src/index.ts",
    "../contrib/worker/src/index.ts",
  ].filter(Boolean);
  const workerPath = workerCandidates.map((p) => resolve(here, p)).find((p) => existsSync(p));
  if (!workerPath) {
    const msg = `找不到后端源码（试过：${workerCandidates.join(" / ")}）`;
    if (REQUIRE_BACKEND) {
      check("后端源码必须存在（--require-backend）", false, msg);
    } else {
      skip("后端源码那组跨仓库契约校验", msg);
    }
  } else {
    console.log(`  后端契约另一端：${workerPath}`);
    const worker = readFileSync(workerPath, "utf8");
    check("后端确实读 turnstile 这个字段名", /fields\["?'?turnstile'?\"?\]/.test(worker) || /fields\['turnstile'\]/.test(worker));
    check("后端确实读 coolapkUid 并写进 pending JSON", /fields\.coolapkUid/.test(worker) && /coolapkUid:/.test(worker));
    check("后端自报 maxBytes 给前端", /maxBytes:\s*MAX_TOTAL_BYTES/.test(worker));
    check("后端只信 cf-connecting-ip（不再信任可伪造的 x-forwarded-for）", !/headers\.get\(["']x-forwarded-for["']\)/i.test(worker));
    check("后端自己校验出处主机名", /coolapk\.com\.evil\.tld|endsWith\(["']\.coolapk\.com["']\)/.test(worker));
    // ⑤-a：包内 module.prop 与表单的一致性只能在提交阶段判（索引的键取自表单，安装器读的是包内文件）。
    // 前端故意不重复这条规则，所以这里必须钉住「后端真的在判」，否则两边就都没人了。
    check(
      "后端在提交阶段核对包内 module.prop 的 id 与 versionCode（⑤-a）",
      /zipReadRootFile\(zipBytes, size, ['"]module\.prop['"]\)/.test(worker) &&
        /prop\.id !== id/.test(worker) &&
        /prop\.versionCode && Number\(prop\.versionCode\) !== versionCode/.test(worker),
    );
    // ⑤-e：下架 / 拉黑的 intake 那道。前端不判台账（台账在索引仓库，前端也不该有第二份判据），
    // 所以这里钉两件事：后端真的在判，以及它的失效方向必须是**放行** ——
    // 取不到台账就拒投稿，等于 raw 抖一下所有人都投不了稿。
    check(
      "后端在提交阶段核对处置台账（⑤-e），且取不到台账时放行而不是挡",
      /loadDispositions\(env, deps\)/.test(worker) &&
        /matchAny\(ledger, \{ id, versionCode, sha256, coolapkUid \}\)/.test(worker) &&
        /if \(!res\.ok\) return null;/.test(worker),
    );
    // INDEX_URL 现在指着后端的镜像端点。这条钉的是「那个端点真的在，而且头是短的」——
    // 它一旦被删掉或把 max-age 抄回别人 CDN 的七天，浏览页与公示页就会静默吃到过期索引。
    check(
      "后端提供 /index.json 与 /dispositions.json 镜像，且公开缓存头与内部 TTL 同源",
      /'\/index\.json': indexRawUrl/.test(worker) &&
        /'\/dispositions\.json': dispositionsRawUrl/.test(worker) &&
        /`public, max-age=\$\{MIRROR_MAX_AGE_S\}`/.test(worker) &&
        /deps\.now\(\) - entry\.at >= MIRROR_MAX_AGE_S \* 1000/.test(worker),
    );
    check(
      "镜像在上游失败时绝不发 200 错误体（MMRL 客户端会把 body 当索引进食）",
      /status: 502/.test(worker) && /'cache-control': 'no-store'/.test(worker),
    );
  }

  /* ------------------------------------------- 处置台账词汇与索引仓库对齐
     公示页的分类词表必须跟索引仓库那份封闭集合一致。仓库新增一个 reason 而这里没有，
     公示页就会把那一组标成「不认识的分类」——公示还在，但没人看得懂，这是静默的一半对。 */
  const dispCandidates = [
    process.env.REPO_DISPOSITIONS_SRC,
    "../../sukisu/contrib/repo/scripts/dispositions.mjs",
    "../contrib/repo/scripts/dispositions.mjs",
  ].filter(Boolean);
  const dispPath = dispCandidates.map((p) => resolve(here, p)).find((p) => existsSync(p));
  if (!dispPath) {
    const msg = `找不到索引仓库的台账判据（试过：${dispCandidates.join(" / ")}）`;
    if (REQUIRE_BACKEND) check("索引仓库台账模块必须存在（--require-backend）", false, msg);
    else skip("处置台账词汇与指针那组跨仓库校验", msg);
  } else {
    console.log(`  台账契约另一端：${dispPath}`);
    const repo = await import(pathToFileURL(dispPath).href);
    const missReason = repo.REASONS.filter((r) => !(r in REASON_LABELS));
    const missKind = repo.KINDS.filter((k) => !(k in KIND_LABELS));
    check("仓库的每个 reason 在公示页都有人话标题", missReason.length === 0, missReason.join(","));
    check("仓库的每个 kind 在公示页都有人话标题", missKind.length === 0, missKind.join(","));
    check("schema 标识两边同值", repo.DISPOSITIONS_SCHEMA === LEDGER_SCHEMA, `${repo.DISPOSITIONS_SCHEMA} / ${LEDGER_SCHEMA}`);
    // 选择器集合从仓库那份的**归一化输出**里取，不抄常量：它才是「台账里可能出现哪些命中条件」的定义。
    const norm = repo.parseDispositions({
      schema: repo.DISPOSITIONS_SCHEMA,
      dispositions: [{ kind: "revoke", reason: "other", by: "b", at: "2026-10-11T00:00:00Z", id: "a", versionCode: 1, sha256: "f".repeat(64), coolapkUid: "2781460" }],
    })[0];
    const repoSel = ["id", "versionCode", "sha256", "coolapkUid", "kind", "reason", "by", "at", "note", "verify"].filter((k) => k in norm);
    const frontSel = SELECTOR_KEYS.filter((k) => repoSel.includes(k));
    check("公示页取的选择器与仓库那份归一化结果同名同集合", frontSel.length === SELECTOR_KEYS.length && SELECTOR_KEYS.every((k) => repoSel.includes(k)), repoSel.join(","));

    // 证据指针的形状：写入端（revoke.mjs）与展示端（byLink）必须判得完全一致。
    // 漂移的两种后果都不是红，而是台账里出现「写着像链接却点不开」或「能点却不给点」。
    const revokePath = resolve(dirname(dispPath), "revoke.mjs");
    const revoke = existsSync(revokePath) ? await import(pathToFileURL(revokePath).href) : null;
    if (!revoke?.PROOF_URL_RE) {
      // 写入端还没有这条规则 == contrib/repo 的工作树停在还没合入它的分支上。
      // 跳过而不是放行：skip 会出现在总结里，而 --require-backend 会把它升级成失败。
      skip("指针形状两端一致", "写入端 revoke.mjs 还没有导出 PROOF_URL_RE（索引仓库那边尚未合入）");
    } else {
      const PROOF = "https://github.com/o/r/issues/33#issuecomment-123456";
      check("写入端接受的证据链接，公示页一定点得开", revoke.PROOF_URL_RE.test(PROOF) && byLink(PROOF) === PROOF);
      const drift = [
        PROOF,
        "gh:me@issuecomment-123456",
        "https://github.com/o/r/issues/33",
        "https://github.com/o/r/issues/abc#issuecomment-1",
        "http://github.com/o/r/issues/33#issuecomment-1",
        "https://github.com.evil.tld/o/r/issues/33#issuecomment-1",
        "https://evil.example.com/o/r/issues/33#issuecomment-1",
        "https://github.com/o/r/pull/33#issuecomment-1",
        "",
      ].filter((s) => revoke.PROOF_URL_RE.test(s) !== Boolean(byLink(s)));
      check("指针形状在写入端与公示页判得完全一致", drift.length === 0, drift.join(" | "));
    }
  }

  /* ------------------------------------------------ P4：申诉入口与双签文案
     公示页那段「不服去哪儿说话」把审核端的标记原样抄给了用户。用户照抄的那串字符必须
     就是 assertMergeApproved 认的那串 —— 文案漂了不会有任何报错，只会让人写一条没人读的评论，
     而他已经等在那儿了。 */
  const html = readFileSync(resolve(here, "../public/index.html"), "utf8");
  check(
    "公示页的申诉段存在，地址由脚本从 config 填",
    html.includes('id="inc-appeal-where"') && /renderIncAppeal\(\)/.test(appSrc) && /CONFIG\.ISSUES_URL/.test(appSrc)
  );
  check(
    "申诉地址没配置时写的是「还没配置」，不给假链接",
    /还没配置索引仓库的 issue 地址/.test(appSrc)
  );
  check(
    "config 里的申诉地址要么为空、要么是一条 https 的 issues 列表",
    CONFIG.ISSUES_URL.trim() === "" || /^https:\/\/[^\s]+\/issues\/?$/.test(CONFIG.ISSUES_URL.trim()),
    CONFIG.ISSUES_URL
  );

  const pubCandidates = [
    process.env.REPO_PUBLISH_SRC,
    "../../sukisu/contrib/repo/scripts/publish-from-main.mjs",
    "../contrib/repo/scripts/publish-from-main.mjs",
  ].filter(Boolean);
  const pubPath = pubCandidates.map((p) => resolve(here, p)).find((p) => existsSync(p));
  if (!pubPath) {
    const msg = `找不到索引仓库的盖章脚本（试过：${pubCandidates.join(" / ")}）`;
    if (REQUIRE_BACKEND) check("索引仓库盖章脚本必须存在（--require-backend）", false, msg);
    else skip("双签文案与审核端一致性校验", msg);
  } else {
    console.log(`  双签契约另一端：${pubPath}`);
    const pub = await import(pathToFileURL(pubPath).href);
    check(
      "文案里让用户写的标记就是审核端认的那个",
      html.includes(pub.HUMAN_APPROVAL_MARKER),
      pub.HUMAN_APPROVAL_MARKER
    );
    const CN_NUM = { 1: "一", 2: "两", 3: "三", 4: "四", 5: "五" };
    check(
      "文案里的人数就是当前要求的签数",
      html.includes(`${CN_NUM[pub.REQUIRED_SIGNERS] ?? pub.REQUIRED_SIGNERS}个不同的人`),
      `REQUIRED_SIGNERS=${pub.REQUIRED_SIGNERS}`
    );
  }

  const summary = `${fail === 0 ? "全部通过" : "有失败项"}：${pass} passed, ${fail} failed`;
  console.log(`\n${skipped ? `${summary}，跳过 ${skipped} 组` : summary}`);
  if (skipped && !REQUIRE_BACKEND) {
    console.log("注意：跳过的这些是跨仓库契约校验。CI 里请用 npm test -- --require-backend，别让它们静默消失。");
  }
  if (fail) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
