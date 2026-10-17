// zip 解析与 module.prop 预填的自检：手搓真实字节喂给浏览器端的解析代码。
// Node 18+ 也有 DecompressionStream / Blob / Response，所以 public/scripts 里的
// 实现可以原样在这里跑，不需要为测试另写一份。
// 用法：node tools/selftest.mjs [--require-backend]
//   --require-backend 把「找不到后端源码」从跳过升级为失败，CI 用这个。
//   带这个开关时要 Node ≥ 22.6：跨仓库那组直接 import worker/src/proof.ts，靠类型擦除；
//   package.json 的 engines.node 钉的就是这条下限（接 CI 时 node-version 别抄 20）。
import zlib from "node:zlib";
import { createHash } from "node:crypto";
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
import {
  sha256Hex,
  sha256HexBytes,
  proofPrefixFor,
  buildProofString,
  makeNonce,
} from "../public/scripts/proof.js";

const REQUIRE_BACKEND = process.argv.includes("--require-backend");

/* ----------------------------------------------------------------- 口令黄金值
   公式（设计文档 §14.1，三处实现必须逐字符一致）：
     proofPrefix = sha256(UTF-8(`${模块id}:${整包sha256}`)) 的十六进制前 8 位
     proofString = proofPrefix + "-" + nonce，nonce 是 6 位小写字母数字，整串 15 字符

   下面这些期望值由 node:crypto 与 coreutils sha256sum 各自独立推得，**不是从被测实现里算的**：
   拿实现自己生成的串去断言实现，红了也只是自我循环，什么都判不出来。

   为什么要把它抄进本文件，而不是只留「前后端两份实现同值」那条：跨仓库那组要
   ../../sukisu/contrib/worker/src/proof.ts 在场才跑得起来，而公开模板仓库的 fork 里它永远是
   skip —— 于是 fork 里「公式」一条都不钉，谁改错拼接顺序都不会红，直到真投稿时把每个口令
   判成假的。有了这张表，public/scripts/proof.js 单独就能被逐条判死。
   两边同值那条照旧保留：在装了 contrib 的机器上它更硬（它判的是「两份拷贝锁在一起」）。 */
const ZIP_SHA_A = "e37287b0ddbda7edb55845acc6de4244cd82e14df5824bdd71007a452a7cbaab"; // = sha256("zip-a")
const ZIP_SHA_B = "2898d907fba3a01bbe9e078e73fb9c20c33a69fc322d062c61e826f2798e3621"; // = sha256("zip-b")
const ZIP_SHA_CN = "4c0811ae6205a89d3a741861d8883c9c58687f1a268f7cffd028e37c5ca202e4"; // = sha256("包体内容")
const ZIP_SHA_ZERO = "0".repeat(64); // 形状合法的占位：不是任何真实包的摘要

const PROOF_GOLDENS = [
  // (id, zipSha) -> proofPrefix。第 4、5 行是同一条占位哈希配两个不同 id：
  // 只绑包体不绑 id 的话这两行会算出同一个前缀，id 那一半就白绑了。
  { id: "demo", zipSha: ZIP_SHA_A, prefix: "4f91ceb8" },
  { id: "sukisu_proof_vector_1", zipSha: ZIP_SHA_B, prefix: "e66e7d33" },
  { id: "含中文的模块id", zipSha: ZIP_SHA_CN, prefix: "002be46d" }, // 非 ASCII：钉的是 UTF-8 字节序
  { id: "x", zipSha: ZIP_SHA_ZERO, prefix: "cbaaf85b" },
  { id: "demo", zipSha: ZIP_SHA_ZERO, prefix: "4fd67254" },
];

/* 「口令已用过」的兜底文案判据，本文件复写一份（app.js 里那份没法 import：模块一加载就碰 DOM）。
   下面第一条先要求两边字面逐字符相同，才拿这份复写跑正反例 —— 否则过了我的例子也证明不了它。
   Worker 源码里那条判据的机器可读码已经是 code: 'proof_used'（contrib/worker/src/index.ts:2318
   的 used-nonce 分支，--require-backend 那组跨仓库核对的就是它）；码到达线上部署之前文案仍是
   唯一信号，之后它是退路。第二支 `可能已…提交成功` 今天没有任何可发的后端文案与之对应，是前向
   兼容钩子 —— 客户端侧真正的「可能已提交」（网络失败/中断/读不懂）按判据刻意不轮换。
   写进检查名的理由：后端只改一次措辞，前端就会静默停止重掷随机段。 */
const SPENT_TEXT_RE_FALLBACK = /口令已(?:经)?用过|可能已(?:经)?提交成功/;

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
 *
 * count 传这组里**本来会跑几条**：只报「跳过 1 组」的话，一组十条和一组一条
 * 在总结行里长得一模一样，而 fork 里丢掉的恰恰是那组最硬的口令同值校验。
 */
function skip(name, why, count = 1) {
  skipped += count;
  console.log(`  SKIP ${name} —— ${why}（这组少 ${count} 条）`);
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
  check("99999999 是合法 UID", isCoolapkUid("99999999") === true);
  check("带空格也认", isCoolapkUid("  99999999 ") === true);
  check("拒绝带链接前缀", isCoolapkUid("https://www.coolapk.com/u/99999999") === false);
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
    evidenceUrlFor,
    LEDGER_EVIDENCE_FILE_RE,
    LEDGER_SCHEMA,
    KNOWN_LEDGER_SCHEMAS,
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
        coolapkUid: "99999999",
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

  // v2 的两个可选字段：读的一侧原样带过去，缺字段的历史条目仍然是完整的一条。
  const v2 = normalizeDispositions({
    schema: LEDGER_SCHEMA,
    lastUpdate: 1791687753247,
    dispositions: [
      {
        kind: "revoke", reason: "malware", by: "gh:b@1", at: "2026-10-17T00:00:00Z", id: "mod_x",
        subject: { coolapkUid: "99999999", username: "被处置的人" },
        evidence: [{ file: `evidence/${"f".repeat(64)}.json`, pr: 53 }],
      },
      { kind: "deny", reason: "policy", by: "gh:b@2", at: "2026-10-18T00:00:00Z", coolapkUid: "88888888" },
    ],
  });
  check("v2 认得，subject / evidence 原样带出来", v2.schemaKnown === true
    && v2.items[0].subject?.coolapkUid === "99999999" && v2.items[0].evidence.length === 1);
  check("v1 形状（没有这两个键）不被补出空壳，页面按缺字段降级渲染", v2.items[1].subject === null
    && Array.isArray(v2.items[1].evidence) && v2.items[1].evidence.length === 0);

  // 读取层的失效方向和 CI 那份相反，这条必须钉住：这里丢掉一条台账 == 公示漏一项处置。
  const weird = normalizeDispositions({
    schema: "sukisu-dispositions-v99",
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
  // placeholder 是全站都会渲染出来的字符串，往里塞一个真实 UID 等于把它贴公开。
  check(
    "输入框 placeholder 里不许出现纯数字示例（UID 那栏写的是规则不是号码）",
    !/placeholder="\d{4,}"/.test(formHtml) && /id="f-uid"[^>]*placeholder="4-12 位数字"/.test(formHtml)
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
  // 四格之间是十字线，不是四张卡片：外框一条 + 中间一横一竖，缝里不许有 gap。
  check(
    "硬性条件用十字线分格：.spec 无 gap、格子无琥珀内描边、右/下两条线在 nth-child 处收口",
    !/\.spec\s*\{[^}]*\bgap:/.test(panelCss) &&
      !panelCss.includes("inset 2px 0 0 var(--amber-line)") &&
      /\.spec__cell:nth-child\(2n\)\s*\{\s*\n\s*border-right: 0;/.test(panelCss) &&
      /\.spec__cell:nth-child\(n \+ 3\)\s*\{\s*\n\s*border-bottom: 0;/.test(panelCss)
  );
  // 标题与导语的重点标记共用一份声明：分两处写，改一处忘一处就是迟早的事。
  check(
    "导语的「搜到并一键安装」与标题的「好模块」是同一套下划线标记",
    /h1 \.hi,\s*\n\.hero__lede \.hl \{/.test(panelCss) &&
      /h1 \.hi::after,\s*\n\.hero__lede \.hl::after \{/.test(panelCss) &&
      !/\.hero__lede \.hl \{[^}]*text-decoration/.test(panelCss)
  );
  // 上一轮把 .hl 并进来时，旧的 h1 .hi::after 没删干净 —— 两份一模一样的声明并排，
  // 改其中一份就分叉。所以钉「只有一份」，而不只是钉「共用的那份在」。
  // 禁 90deg 只禁 wash→edge 这一对（标记的签名）：别处还有 wash→transparent 的横向淡出，
  // 那是装饰，不该被这条误伤。
  check(
    "琥珀标记只有一份声明，且底是 105deg + skewX(-12deg) 往右斜投影",
    (panelCss.match(/h1 \.hi::after/g) || []).length === 1 &&
      (panelCss.match(/linear-gradient\(105deg, var\(--amber-wash\), var\(--amber-edge\)\)/g) || []).length ===
        1 &&
      !panelCss.includes("linear-gradient(90deg, var(--amber-wash), var(--amber-edge))") &&
      (panelCss.match(/transform: skewX\(-12deg\);/g) || []).length === 1
  );
  // 顶栏与标语各踩过一次「窄屏另有硬编码，clamp 白写」：这两条钉的就是那两个坑。
  check(
    "铭牌每段都不从中间断行；「确认屏」这个说法已整体换成「上传前确认」",
    /\.nameplate span \{\s*\n\s*white-space: nowrap;/.test(panelCss) &&
      !formHtml.includes("确认屏") &&
      !appSrc.includes("确认屏") &&
      formHtml.includes("上传前确认")
  );

  /* ------------------------------------------------------- 两个浏览页的导语
     公示页的导语是拿来威慑的，不是拿来解释的 —— 追责那半句一旦被人当啰嗦删掉，
     这一页就退化成流水账。已收录页的导语是用户点名删掉的，删掉就别让它长回来。
     另一条不在页面上看不出来：.hero__lede .hl 是 nowrap，标记短语一长就在 320px 撑破。 */
  const idxSlice = formHtml.slice(
    formHtml.indexOf('id="view-index"'),
    formHtml.indexOf('id="view-incidents"')
  );
  check(
    "已收录页没有导语段落（「公开索引里的全部内容」那句已删，不许自己长回来）",
    idxSlice.length > 0 && !idxSlice.includes("hero__lede") && !formHtml.includes("公开索引里的全部内容")
  );
  const incLede = /id="view-incidents"[\s\S]*?<p class="hero__lede">([\s\S]*?)<\/p>/.exec(formHtml);
  check(
    "公示页导语留着威慑的四要素：root 权限 / 可核对的凭据 / 向公安机关报案 / 依法追究法律责任",
    !!incLede &&
      ["root 权限", "可核对的凭据", "向公安机关报案", "依法追究法律责任"].every((k) =>
        incLede[1].includes(k)
      )
  );
  const incMark = incLede && /<span class="hl">([^<]*)<\/span>/.exec(incLede[1]);
  check(
    "公示页导语里的琥珀短语不超过 12 字（.hl 是 nowrap，长了窄屏撑破）",
    !!incMark && incMark[1].length <= 12
  );

  check(
    "顶栏窄屏不换行（.bezel__in 用 nowrap 覆盖默认的 wrap）",
    /\.bezel__in\s*\{[^}]*flex-wrap: nowrap/.test(panelCss)
  );
  check(
    "标语字号只由 clamp 决定，没有任何媒体查询再用固定 px 把它压回去",
    /h1 \{[^}]*font-size: clamp\((3[6-9]|[4-9][0-9])px/.test(panelCss) &&
      !/h1 \{[^}]*font-size: \d+px/.test(panelCss)
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
  // 之前：核实没接 / 酷安抖动时「正在查」也允许提交，清空晚一步就漏进索引。
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

  /* ------------------------------------------------------- 所有权口令（P0）
     公示页要指向人，前提是投稿人控制着他填的那个 UID。这条链子上有三个地方会静默断掉，
     而且断掉时都不会报错，只会让口令看起来照常生成：
     ① 前后端两份算法漂移（Worker 复核时把每个真口令判成假的）；
     ② 展示的字符串与模块 id 脱钩（改了 id 还显示旧口令，用户抄进签名的那串就废了）；
     ③ 那条「能关掉安全闸」的配置开关被人加回来（能关的闸不是闸）。 */
  const configSrc = readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "../public/scripts/config.js"),
    "utf8"
  );
  // 自己的 WebCrypto 实现不配自证：拿 node:crypto 当独立 oracle 对一次整条哈希。
  // 这条钉的是摘要本身（十六进制补零、UTF-8 编码），下面那条钉的才是截断与拼接。
  check(
    "口令算法与 node:crypto 一致（不信任自己的实现）",
    (await sha256Hex("sukisu_proof_vector_1")) ===
      createHash("sha256").update("sukisu_proof_vector_1", "utf8").digest("hex")
  );
  // 上面那条把 zipSha 那几个字面量当已知输入用，所以这里先拿独立 oracle 把输入本身复算一遍：
  // 表腐烂了要当场看得见，不能等到某条黄金值对不上时才去猜「是公式错了还是常量错了」。
  check(
    "黄金值表的输入复算：三个 zipSha 字面量确实等于那三段明文的 sha256（node:crypto）",
    createHash("sha256").update("zip-a", "utf8").digest("hex") === ZIP_SHA_A &&
      createHash("sha256").update("zip-b", "utf8").digest("hex") === ZIP_SHA_B &&
      createHash("sha256").update("包体内容", "utf8").digest("hex") === ZIP_SHA_CN
  );
  // 前端算整包摘要走的是 sha256HexBytes（File.arrayBuffer() 出来的那串字节），不是文本版。
  // 两条路径必须是同一个口径：Worker 的 contentId 对 zip 全部字节算，口令绑的就是这个值。
  // 这条红 == 「展示的口令绑的是另一种东西」，界面上完全看不出来。
  const zipBytesA = Buffer.from("zip-a", "utf8");
  check(
    "整包摘要口径一致：sha256HexBytes 对 Uint8Array / ArrayBuffer 与 node:crypto 同值",
    (await sha256HexBytes(zipBytesA)) === ZIP_SHA_A &&
      (await sha256HexBytes(zipBytesA.buffer.slice(zipBytesA.byteOffset, zipBytesA.byteOffset + zipBytesA.byteLength))) === ZIP_SHA_A &&
      (await sha256HexBytes(zipBytesA)) === (await sha256Hex("zip-a")),
    await sha256HexBytes(zipBytesA)
  );
  // 逐向量一条检查，不是一个循环里 AND 起来：变异之后要说得出红的是哪一对，
  // 而「五个里有一个红」和「五个全红」是不同的事故。
  for (const [i, v] of PROOF_GOLDENS.entries()) {
    const got = await proofPrefixFor(v.id, v.zipSha);
    check(
      `内嵌黄金值 ${i + 1}/${PROOF_GOLDENS.length}：proofPrefixFor(${JSON.stringify(v.id)}, ${
        v.zipSha === ZIP_SHA_ZERO ? "64 个 0" : JSON.stringify(v.zipSha.slice(0, 12)) + "…"
      }) = ${v.prefix}（fork 里没有 contrib 也要咬）`,
      got === v.prefix,
      got
    );
  }
  // 同一批向量再拿 node:crypto 按公式复算一遍。与上面那张表是两条独立的路：
  // 表钉的是「答案不许改」，这条钉的是「算式的形状」，改测试里的期望表达式骗不过字面量，
  // 改实现里的字面量骗不过独立复算。缺任何一条，另一半都可能在没人看见时漂走。
  const oracleDrift = [];
  for (const v of [...PROOF_GOLDENS, { id: "a".repeat(200), zipSha: ZIP_SHA_A, prefix: "" }]) {
    const want = createHash("sha256").update(`${v.id}:${v.zipSha}`, "utf8").digest("hex").slice(0, 8);
    const got = await proofPrefixFor(v.id, v.zipSha);
    if (got !== want) oracleDrift.push(`${v.id.slice(0, 12)}: 实现=${got} node=${want}`);
    if (v.prefix && got !== v.prefix) oracleDrift.push(`${v.id.slice(0, 12)}: 与黄金表不一致`);
  }
  check(
    "公式形状独立复算：前缀 = sha256(UTF-8(id + ':' + zipSha)) 前 8 位（含 200 字节长 id）",
    oracleDrift.length === 0,
    oracleDrift.join(" | ")
  );
  // 整串的最后一环：分隔符与「谁在前」。Worker 是拿整串去签名里找的，
  // 分隔符换成 "_"、或者 nonce 跑到前面，都会让每条真口令被判成假的。
  check(
    "内嵌黄金值：整串口令 = 期望前缀 + '-' + nonce（buildProofString 三个来源都算进去）",
    (await buildProofString("demo", ZIP_SHA_ZERO, "ab12cd")) === "4fd67254-ab12cd" &&
      (await buildProofString("x", ZIP_SHA_ZERO, "ab12cd")) === "cbaaf85b-ab12cd",
    await buildProofString("demo", ZIP_SHA_ZERO, "ab12cd")
  );
  // 形状是 Worker 那边的判据之一（它拿 id 重算整串再去签名里找），所以 8 位前缀、那个连字符、
  // 6 位随机段一个都不能漂；整串 15 字符也是设计上限（酷安签名实测 60 的一半以下）。
  const proofSample = await buildProofString("any", ZIP_SHA_ZERO, "ab12cd");
  check(
    "整串口令 15 字符，形状固定：8 位十六进制 + '-' + 6 位小写字母数字",
    /^[0-9a-f]{8}-[a-z0-9]{6}$/.test(proofSample) && proofSample.length === 15,
    proofSample
  );
  // 口令是一次性的：makeNonce 退化成定值就等于全站共用一个 nonce，重放窗口重新打开，
  // 而这在界面上完全看不出来 —— 只有跨模块 id 的签名会撞车。
  const nonceSamples = new Set();
  for (let i = 0; i < 200; i++) nonceSamples.add(makeNonce());
  check(
    "makeNonce 产出合法形状且不是定值",
    [...nonceSamples].every((n) => /^[a-z0-9]{6}$/.test(n)) && nonceSamples.size > 150,
    `${nonceSamples.size}/200 个不同，首个 ${[...nonceSamples][0]}`
  );
  // 派生值一旦进 state，就和来源脱钩了：改了 id / 换了包还缓存着旧口令。只准缓存三个来源。
  // 反例写成 state.proof 的前缀匹配（不带 \b）：state.proofText / state.proofString 一样是缓存派生串。
  // 来源从两个变成三个（口令绑整包 sha256），所以这里连 zipSha 的取值点一起钉住 ——
  // 只钉 nonce 的话，把 zipSha 换成一个缓存下来的旧哈希，这条还是绿的。
  check(
    "前端只缓存来源不缓存派生串：口令文本由 (id, state.zipSha, state.nonce) 现算",
    /state\.nonce/.test(appSrc) &&
      /const zipSha = state\.zipSha;/.test(appSrc) &&
      /const nonce = state\.nonce;/.test(appSrc) &&
      /buildProofString\(id, zipSha, nonce\)/.test(appSrc) &&
      !/state\.proof/.test(appSrc)
  );
  // 载荷里没这三项时后端只能把「没承诺」判成「承诺过」、把「没声明哈希」判成「哈希一致」——
  // 静默放行，前端界面还一切正常。sha256 是 ⑤-c 的输入，也是口令的第二个来源：
  // 它一旦不再进 FormData，「绑包体」就只剩下屏幕上那串好看的文字。
  // 引号样式不管：钉的是「这三个字段真的进了 FormData」，不是钉 api.js 怎么写字符串。
  check(
    "提交载荷带上 pledge、nonce 与整包 sha256",
    /form\.append\(\s*["']pledge["']/.test(apiSrc) &&
      /form\.append\(\s*["']nonce["']/.test(apiSrc) &&
      /form\.append\(\s*["']sha256["']/.test(apiSrc)
  );
  // 派生串不发：前端算出来的那一份只用来显示，发过去等于让前端替后端定结论，
  // 也等于把「口令」这个本该由 Worker 重算的判据降级成一个自报字段。
  check(
    "载荷里不发派生出来的口令串（后端自己重算，前端只展示）",
    !/form\.append\(\s*["'](proof|proofString|proofText|proofPrefix)["']/.test(apiSrc)
  );

  /* -------------------------------------------- 口令的来源齐了才算「就绪」（状态措辞）
     口令行只在三个来源（nonce / id / 整包 sha256）都齐时才把串贴到屏幕上；少任何一个，屏幕上
     根本没有可抄进签名的东西。而全局约束不许前端为此加第二条闸 —— 判定在 Worker，按钮照常亮。
     这个夹缝里唯一能钉的就是状态描述：清单那条要说不清还差什么，底栏不许说「全部就绪，可以确认」。
     Task 10 的走查实测到过这个假现场：整包哈希还在算的时候门禁全绿、底栏写就绪、口令行是空的。
     下面两条故意分开放：一条钉「说的是实话」，一条钉「按钮没顺手变严」。后者不是形式主义 ——
     前端加闸会把判定从 Worker 挪回浏览器（那是另一种坏），而且它会伪装成「修好了这个诚实问题」。 */
  const gateBody = appSrc.slice(
    appSrc.indexOf("function gateItems()"),
    appSrc.indexOf("function refreshGate()")
  );
  const refreshBody = appSrc.slice(
    appSrc.indexOf("function refreshGate()"),
    appSrc.indexOf("\n}", appSrc.indexOf("function refreshGate()"))
  );
  check(
    "口令行的三个来源齐了才算 shown（屏幕上没串可抄时不许自称就绪）",
    /shown: Boolean\(state\.nonce && proofId && state\.zipSha\)/.test(gateBody) &&
      /if \(!nonce \|\| !id \|\| !zipSha\) \{/.test(appSrc),
    gateBody.includes("shown:") ? "shown 在，但 renderProof 的显示条件变了" : "gateItems 里没有 shown"
  );
  check(
    "还差哪个来源就点名哪个：清单三条各说一种「口令还差」",
    ["口令还差：填上模块 ID", "口令还差：整包哈希还没算完", "口令还差：还没选包"].every((k) => gateBody.includes(k)) &&
      !gateBody.includes("随机段已生成 —— 填上模块 ID"),
    "口令行的文案又回到先报「已生成」后报缺什么"
  );
  check(
    "底栏那句「全部就绪」由 shown 把关：有 ok 但未 shown 的行时不许说就绪",
    /i\.ok && i\.shown === false/.test(refreshBody) &&
      /blocking \? blocking\.text : "全部就绪，可以确认"/.test(refreshBody),
    refreshBody.includes("全部就绪") ? "全部就绪还在，但没让 shown 先过一遍" : "底栏不再写「全部就绪」"
  );
  check(
    "这条诚实不许变成第二道闸：确认按钮的 enable 条件仍只看 ok，ok 仍只看 state.nonce",
    /const ready = items\.every\(\(i\) => i\.ok\);/.test(refreshBody) &&
      /btn\.disabled = !ready/.test(refreshBody) &&
      /ok: Boolean\(state\.nonce\)/.test(gateBody) &&
      !/disabled = !(ready && state\.zipSha)/.test(refreshBody)
  );

  /* ------------------------ 派生值的来源一换，屏幕上那一串就得当场死（intake 那一路）
     上面几条钉的是「说了什么」，这一组钉的是「什么时候死的」。①②④ 全是顺序断言而不是抄整行字面量：
     注释重排、引号换样式都不该让钉子悄悄松开，而把顺序挪回 await 之后、或删掉一道比较，必须当场红。
     ③ 是反向的一条：修谎不许顺手变成前端第二道闸。
     ① 上一轮的修复（换包那一刻同步归零 + 立刻重画）此前一条都没钉着——fix1 报告 §6 第 2 条要的就是它。
     ② 这一轮的串行化：intake() 不串行，连着选 A、B 时两次解析重叠，而 state.zip 的赋值原先是无条件的；
        A 的解析晚到就会让 state.zip 指回 A 而 state.file 已是 B，于是 A 的摘要还能通过 digest 那侧
        的对象标识守卫贴到 B 上——同一类谎的另一条到达路径。 */
  const intakeAt = appSrc.indexOf("async function intake(");
  // intake() 里嵌套的 } 全部带缩进，第一个顶格的 } 就是函数结束（与上面 refreshBody 同一个取法）。
  const intakeSrc = intakeAt === -1 ? "" : appSrc.slice(intakeAt, appSrc.indexOf("\n}", intakeAt));
  const iAwait = intakeSrc.search(/\bawait\b/);
  // 第一个 await 之前那一段是同步跑完的：这一段之外用户看得见中间状态，那一串就必须已经死了。
  const intakeSync = iAwait > 0 ? intakeSrc.slice(0, iAwait) : "";
  const iFileSet = intakeSync.indexOf("state.file = file");
  const iShaClear = intakeSync.indexOf('state.zipSha = ""');
  check(
    "换包那一刻整包哈希当场归零：state.zipSha 的清空排在 state.file = file 之后、第一个 await 之前，且同一段里就重画口令行与门禁",
    iFileSet !== -1 &&
      iShaClear > iFileSet &&
      intakeSync.includes("renderProof()") &&
      intakeSync.includes("refreshGate()"),
    intakeSync
      ? `state.file=${iFileSet} / state.zipSha=${iShaClear} / await=${iAwait} / 同步段 ${intakeSync.length} 字符`
      : "切不出 intake() 第一个 await 之前的那一段"
  );
  /* intake() 里每一处 await 续点都得在**写 state 之前**再认一次 file 身份。下面两条按「离那次写入
     最近的一道比较」判，而不是数一共有几道 —— 删掉哪一道就红它管的那次写入，变异能逐条对上号。
     ② 第一个续点（读整包字节回来）：让 state.zip 指回旧包而 state.file 已是新包的那一次赋值。
     ④ 第二个续点（读 module.prop 回来）：第一道比较管不到它 —— 旧包解出的 prop 会盖掉新包
        预填的 id（applyProp 见 data-auto 就该覆盖），而 id 是口令的三个来源之一，于是「旧包的 id +
        新包的整包哈希」这一串会被真算出来、画上屏幕、装进载荷；这一次不只是显示，id 真的发出去了。 */
  const iZipSet = intakeSrc.search(/\n\s*state\.zip\s*=\s*\{/);
  const iReadAwait = intakeSrc.search(/\bawait\s+readEntry/);
  const iPropWrite = intakeSrc.search(/state\.zip\.prop\s*=/);
  const guardIdx = [
    ...intakeSrc.matchAll(/(?:state\.file\s*!==\s*file|file\s*!==\s*state\.file)/g),
  ].map((m) => m.index);
  const guardBefore = (upto) => guardIdx.filter((i) => i < upto).pop();
  check(
    "第一个续点认 file 的对象身份：state.zip 的赋值之前最近的一道 state.file 比较，排在第一个 await 之后",
    iZipSet !== -1 && guardBefore(iZipSet) !== undefined && guardBefore(iZipSet) > iAwait,
    `await=${iAwait} / state.zip 赋值=${iZipSet} / 赋值前最近的比较=${guardBefore(iZipSet)} / 全部比较=${JSON.stringify(guardIdx)}`
  );
  check(
    "第二个续点再认一次：写 state.zip.prop 之前最近的一道 state.file 比较，排在 await readEntry 之后",
    iPropWrite !== -1 &&
      iReadAwait !== -1 &&
      guardBefore(iPropWrite) !== undefined &&
      guardBefore(iPropWrite) > iReadAwait,
    `await readEntry=${iReadAwait} / state.zip.prop=${iPropWrite} / 赋值前最近的比较=${guardBefore(iPropWrite)} / 全部比较=${JSON.stringify(guardIdx)}`
  );
  /* 这一轮修的是一句谎（屏幕上那串对不上要上传的字节），不是「前端该多拦一道」——判定在 Worker，
     前端加闸会把判据挪回浏览器，而且它会伪装成「已经把诚实问题修好了」。所以反向再钉一条：
     全站 .disabled 的赋值条件里不许出现口令的三个来源。length 先卡住，免得匹配不到任何东西时
     every() 空集为真、这条绿得毫无意义。 */
  const disabledRhs = [...appSrc.matchAll(/\.disabled\s*=\s*([^;\n]*)/g)].map((m) => m[1]);
  check(
    "归零与串行化没顺手变成第二道闸：任何 .disabled 的赋值条件里都没有整包哈希 / 随机段 / file / zip 这些前端状态",
    disabledRhs.length >= 3 &&
      disabledRhs.every((rhs) => !/zipSha|proofId|nonce|state\.file|state\.zip|buildProofString/.test(rhs)),
    disabledRhs.join("  |  ")
  );

  /* ----------------------------------------------- 口令烧掉的判据：码优先，文案兜底
     后端只改一句中文就能让前端静默停止重掷随机段（用户拿废串反复重试，永远撞同一句指控）。
     Worker 源码已回 code: 'proof_used'（contrib/worker/src/index.ts:2318 的 used-nonce 分支），
     这里钉「前端两条判据都在、且没把文案那条删掉」；码与后端的同值由下面 --require-backend
     那组跨仓库检查真跑 —— 本机走的是检查分支，不是 skip。 */
  check(
    "口令轮换的判据两条都在：code === 'proof_used' 优先，中文文案兜底",
    /backendCode\(err\) === "proof_used"/.test(appSrc) &&
      /NONCE_SPENT_RE\.test\(reason\)/.test(appSrc) &&
      /if \(proofWasSpent\(err, reason\)\)/.test(appSrc),
    "只剩文案时，后端改一次措辞就会静默停止轮换"
  );
  // 「读不出记录」那句是平台故障，不是「你用过了」——误判成烧掉会让用户白抄一次签名。
  // 轮换判据扩到码那一侧时最容易顺手把这两种混起来，所以把兜底文案的正反例都钉一遍。
  // 这里复写一份判据而不是 import app.js 的那份（app.js 一加载就要碰 DOM）：
  // 所以下面第一条先要求两边字面完全相同，否则「过了我的正反例」什么也没证明。
  const nonceSpentLiteral = /const NONCE_SPENT_RE = (\/.*\/[a-z]*);/.exec(appSrc)?.[1] ?? "";
  check(
    "兜底文案判据与本文件复写的那份同字面（app.js 里的 NONCE_SPENT_RE 不许偷偷换词）",
    nonceSpentLiteral === SPENT_TEXT_RE_FALLBACK.toString(),
    `app.js: ${nonceSpentLiteral}`
  );
  check(
    "平台侧「读不出本次投稿的口令记录」不算口令烧掉（兜底判据只认那两种说法）",
    [
      "这个口令已经用过，请重新生成后再提交",
      // 第二支钉的是正则里的前向兼容钩子：Worker 今天没有任何可发的文案与之匹配（整个
      // worker/src 搜不到「可能已」「提交成功」）—— 这条正例证明钩子还挂着，不证明后端会发。
      // 客户端真正的「可能已提交」（网络失败/中断/读不懂应答）按判据刻意不轮换，归码那边兜底。
      "口令可能已提交成功，请刷新索引后确认",
    ].every((s) => SPENT_TEXT_RE_FALLBACK.test(s)) &&
      [
        // 9d66cd8 换掉旧文案「酷安核实没通过（口令记录读不出来）」后的现行句子（index.ts 的
        // KV 读失败分支原样）：失败的是自家记账，不是「你用过了」，绝不许触发轮换。
        "服务端读不出本次投稿的口令记录（自家记账的 KV 没有应答），本次未提交 —— 请稍后重试",
        "酷安核实没通过（连接超时），本次未提交 —— 与你是不是本人无关，请稍后重试",
        "投稿需要酷安等级 Lv2 及以上",
      ].every((s) => !SPENT_TEXT_RE_FALLBACK.test(s))
  );
  // 四条勾选是「逐条知情」的载体，而解锁按钮数的是真的 checkbox 元素（app.js 里
  // $$("#layer-confirm input[type=checkbox]")）：勾少一条，04 那条承诺就再没人被要过，
  // 按钮却照常亮 —— 这是静默的一半对，界面看着还是四条文字。
  // 反过来 <label for> 指着不存在的 input 时，那条勾点不动，文字还在但收不到确认，所以两条分开钉。
  const ticks = [...formHtml.matchAll(/<label[^>]*class="tick"[^>]*for="(ck\d)">([\s\S]*?)<\/label>/g)].map(
    (m) => ({ id: m[1], body: m[2] })
  );
  // checkbox 那侧按标签整取，不写死属性顺序与自闭合写法：钉的是「有四条点得动的勾」，不是钉我排版。
  const tickInputs = new Set(
    [...formHtml.matchAll(/<input\b[^>]*>/g)]
      .map((m) => m[0])
      .filter((tag) => /type="checkbox"/.test(tag))
      .map((tag) => /\bid="(ck\d)"/.exec(tag)?.[1])
      .filter(Boolean)
  );
  check(
    "确认弹窗是四条勾选（label 与 checkbox 都是四条），最后一条是 04 / MALICE 的承诺",
    ticks.length === 4 &&
      tickInputs.size === 4 &&
      /04 \/ MALICE/.test(ticks[3].body) &&
      /不含恶意代码/.test(ticks[3].body),
    `label ${ticks.length} 条 / checkbox ${tickInputs.size} 个`
  );
  check(
    "每条勾选的 label 与 checkbox 成对（孤儿 label 那条勾点不动）",
    ticks.every((t) => tickInputs.has(t.id)) && tickInputs.size === ticks.length,
    `label ${ticks.map((t) => t.id).join(",")} / input ${[...tickInputs].join(",")}`
  );
  check("「三项」这种旧文案没有残留（第四勾加上了）", !formHtml.includes("三项") && !appSrc.includes("三项") && !formHtml.includes("三道"));
  /* 承诺的版本号与那段文案必须绑在一起。
     归档里那句「他接受过承诺」以后是要被人拿出来的，它的可辩护性全靠「pledge-v1 指的是哪段话」
     还答得出来：文案改了而版本号照旧，归档就写着「他接受过 pledge-v1」，而 pledge-v1 今天指的
     已经不是用户当时勾的那段话 —— 这一句就成了假话，且没有任何一处会报错。
     所以两条必须**同时**成立，缺一条就算红；版本字面量也在本文件里钉死一份，
     不让它靠「和 Worker 同值」那条跨仓库检查来兜 —— fork 里那条根本不跑。 */
  const pledgeSent = /pledge:\s*["']([^"']+)["']/.exec(appSrc)?.[1] ?? "";
  check(
    "承诺版本字面量与 ck4 那段文案绑在一起：pledge-v1 与「不含恶意代码」必须同时存在",
    pledgeSent === "pledge-v1" &&
      ticks.length === 4 &&
      /04 \/ MALICE/.test(ticks[3].body) &&
      ticks[3].body.includes("不含恶意代码"),
    `app.js 发的 pledge=${JSON.stringify(pledgeSent)}，ck4 文案里有「不含恶意代码」=${ticks[3]?.body.includes("不含恶意代码") ?? "无 ck4"}`
  );
  check(
    "COOLAPK_VERIFY_REQUIRED 被彻底删除 —— 能关掉安全闸的开关本身就是洞",
    !configSrc.includes("COOLAPK_VERIFY_REQUIRED") &&
      !appSrc.includes("COOLAPK_VERIFY_REQUIRED") &&
      !apiSrc.includes("COOLAPK_VERIFY_REQUIRED") &&
      !readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../README.md"), "utf8").includes("COOLAPK_VERIFY_REQUIRED")
  );

  // 后端仓库在同一台机器上时，直接把它的源码当契约的另一端来读。
  // 路径靠猜迟早会像 contrib 从 H:\刷机包 搬到 H:\sukisu 那样一次搬家就全哑掉，
  // 所以显式环境变量优先：WORKER_SRC=/path/to/worker/src/index.ts npm test
  //
  // fork 里这一整组都是 skip —— 这正是本文件要内嵌黄金值的理由（见文件顶部那张表）：
  // 公开模板仓库的 fork 没有 contrib，而公式的正确性不该取决于这台机器上有没有第二个仓库。
  // skip 的条数按「这组本来会跑几条」如实报出，总结行里要看得见，不许伪装成全通过。
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
      skip("后端源码那组跨仓库契约校验", msg, 9);
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

  /* ------------------------------------------------ 所有权口令：两份实现的同值（跨仓库）
     public/scripts/proof.js 与 worker/src/proof.ts 是同一个算法的两份拷贝，这是故意的：
     前端要拿它显示，Worker 要拿它复核，而 Worker 那份不能被浏览器读到。故意的东西不会自己
     保持一致 —— 一边改了另一边不报错，只在真投稿时把每个口令判成假的，而界面上一切正常。
     所以这里不比对文本、不数正则，直接把两边各跑一遍逐条对：能调代码就调代码，grep 源码的
     「同值」钉的只是字符串长得像。proof.ts 就放在 index.ts 同目录，路径从上面那条已经解析
     成功的 workerPath 推 —— 再抄一遍候选列表，等于再埋一次「contrib 一搬家就全哑」。 */
  const workerProofPath = workerPath ? resolve(dirname(workerPath), "proof.ts") : "";
  if (!workerProofPath || !existsSync(workerProofPath)) {
    const msg = workerProofPath ? `找不到 ${workerProofPath}` : "后端源码整组不可用（见上一条跳过 / 失败）";
    if (REQUIRE_BACKEND) {
      check("后端那份口令实现必须存在（--require-backend）", false, msg);
    } else {
      skip("前后端口令算法同值那组跨仓库校验", msg, 4);
    }
  } else {
    console.log(`  口令契约另一端：${workerProofPath}`);
    // proof.ts 只有可擦除的 TS 语法、没有 import，Node ≥ 22.6 的类型擦除直接跑得起。
    // 读不动就是运行时太老，不是契约破了 —— 按这个文件既有的规矩报成 skip（总结里看得见，
    // --require-backend 把它升级成失败），绝不退化成 grep 源码：那钉的只是字符串长得像。
    let wp = null;
    let loadErr = "";
    try {
      wp = await import(pathToFileURL(workerProofPath).href);
    } catch (err) {
      loadErr = err && err.message ? err.message : String(err);
    }
    if (!wp) {
      const msg = `这个运行时加载不了 ${workerProofPath}（需要 Node ≥ 22.6 的类型擦除）—— ${loadErr}`;
      if (REQUIRE_BACKEND) check("后端那份口令实现必须可加载（--require-backend）", false, msg);
      else skip("前后端口令算法同值那组跨仓库校验", msg, 4);
    } else if (typeof wp.proofPrefixFor !== "function" || typeof wp.buildProofString !== "function") {
      // 加载成功却没有这三个导出 == 后端那份换回了旧签名（只吃 id 的 proofPrefixForId）。
      // 这不是「这台机器没条件判」，是条件齐全地判出了坏结果 —— 所以必须红，不许混进 skip。
      check(
        "后端导出的是新签名：proofPrefixFor(id, zipSha) / buildProofString(id, zipSha, nonce)（旧名字不许活着）",
        false,
        `实际导出：${Object.keys(wp).join(", ") || "(空)"}`
      );
    } else {
      /* 向量从 (id) 升到 (id, zipSha) 对。
         旧那四个只喂 id 的向量在绑包体之后已经判不出东西了：两份实现可以「逐条相同」而全都
         算错公式。所以现在四对黄金值 + 保留旧向量里那条 200 字节长 id（覆盖面一条都不许丢）：
         两边各跑一遍，先横着比（两份拷贝锁在一起），再竖着比（各自命中内嵌黄金值）。
         竖着那一条是新加的，它补的是横着那条的结构洞：两份实现同轮一起漂的时候，只有它们
         都对不上这张表才会红 —— 而这张表来自 node:crypto，不属于任何一份实现。 */
      const vectors = [...PROOF_GOLDENS, { id: "a".repeat(200), zipSha: ZIP_SHA_A, prefix: "" }];
      const nonce = "ab12cd";
      const drift = [];
      const workerWrong = [];
      for (const v of vectors) {
        const tag = `${v.id.slice(0, 10)}|${v.zipSha.slice(0, 8)}`;
        const webPrefix = await proofPrefixFor(v.id, v.zipSha);
        const workerPrefix = await wp.proofPrefixFor(v.id, v.zipSha);
        if (webPrefix !== workerPrefix) drift.push(`${tag}: web=${webPrefix} worker=${workerPrefix}`);
        const webFull = await buildProofString(v.id, v.zipSha, nonce);
        const workerFull = await wp.buildProofString(v.id, v.zipSha, nonce);
        if (webFull !== workerFull) drift.push(`${tag}: 整串 web=${webFull} worker=${workerFull}`);
        if (v.prefix && workerPrefix !== v.prefix) {
          workerWrong.push(`${tag}: worker=${workerPrefix} 黄金值=${v.prefix}`);
        }
      }
      check("前后端算出的口令前缀逐条相同（两份实现必须锁在一起）", drift.length === 0, drift.join(" | "));
      check(
        "后端那份逐条命中内嵌黄金值（两边一起漂也算红，不只靠互相对账）",
        workerWrong.length === 0,
        workerWrong.join(" | ")
      );
      // 承诺版本的字面值用的是上面从前端源码里取的那一份，不在这儿抄：
      // 前端发的必须是 Worker 认账的集合里的一个。取不到字面值（比如改成了常量引用）也算红。
      check(
        "前端发的承诺版本在 Worker 承认的集合里，且等级下限没被调低（写死的 2）",
        pledgeSent !== "" && wp.PLEDGE_VERSIONS.includes(pledgeSent) && wp.MIN_COOLAPK_LEVEL === 2,
        `pledge=${JSON.stringify(pledgeSent)} 后端集合=${JSON.stringify([...wp.PLEDGE_VERSIONS])} 下限=${wp.MIN_COOLAPK_LEVEL}`
      );
      // 随机段的字母表也是契约：前端换成大写或符号，Worker 的 PROOF_NONCE_RE 会把每条口令判非法。
      const badNonce = Array.from({ length: 60 }, () => makeNonce()).find((n) => !wp.PROOF_NONCE_RE.test(n));
      check("前端生成的 nonce 过后端的形状校验（两边字母表同值）", !badNonce, badNonce);
      /* 「口令已用过」的机器可读失败码：后端源码里已经有了（contrib/worker/src/index.ts:2318，
         used-nonce 命中的 403 响应体字面量），所以本机走进下面的是真检查那一支 —— 前后端的码
         逐字对齐，这是验证过的半边，不是未兑现的承诺。skip 支本身留着：contrib 工作树若退在
         这条落地之前，就如实报 skip —— 不许没得对也写成 pass，也不许干脆不提。 */
      const workerIndexSrc = readFileSync(workerPath, "utf8");
      const workerCodes = [...workerIndexSrc.matchAll(/code:\s*["']([^"']+)["']/g)].map((m) => m[1]);
      if (workerCodes.includes("proof_used")) {
        check(
          "后端对「口令已用过」回了机器可读码，且前端认的就是这同一个码",
          /backendCode\(err\) === "proof_used"/.test(appSrc),
          `后端 code=proof_used / 前端认的码=${JSON.stringify(/backendCode\(err\) === "([^"]+)"/.exec(appSrc)?.[1] ?? "(无)")}`
        );
      } else {
        skip(
          "口令已用过的失败码前后端同值",
          `后端源码里的失败码只有 ${JSON.stringify(workerCodes)} —— 没有 proof_used（contrib 工作树停在这条落地之前）；` +
            "前端的码判据本机未验证，目前靠文案兜底",
          1
        );
      }
    }
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
    else skip("处置台账词汇与指针那组跨仓库校验", msg, 4);
  } else {
    console.log(`  台账契约另一端：${dispPath}`);
    const repo = await import(pathToFileURL(dispPath).href);
    const missReason = repo.REASONS.filter((r) => !(r in REASON_LABELS));
    const missKind = repo.KINDS.filter((k) => !(k in KIND_LABELS));
    check("仓库的每个 reason 在公示页都有人话标题", missReason.length === 0, missReason.join(","));
    check("仓库的每个 kind 在公示页都有人话标题", missKind.length === 0, missKind.join(","));
    check("schema 标识两边同值", repo.DISPOSITIONS_SCHEMA === LEDGER_SCHEMA, `${repo.DISPOSITIONS_SCHEMA} / ${LEDGER_SCHEMA}`);
    // 认的集合也要同值，不只当前那一档：v1 的历史台账在 Worker 那一侧读不动的话，
    // 它的失效方向是「放行」——公示页还在显示下架，投稿已经不再被挡了。
    const repoKnown = [...repo.KNOWN_DISPOSITIONS_SCHEMAS].sort().join(",");
    const frontKnown = [...KNOWN_LEDGER_SCHEMAS].sort().join(",");
    check("两边认的 schema 集合逐字同值", repoKnown === frontKnown, `${repoKnown} / ${frontKnown}`);
    check("v1 仍在认的集合里（线上 json/dispositions.json 今天还是 v1）",
      repo.KNOWN_DISPOSITIONS_SCHEMAS.includes("sukisu-dispositions-v1")
      && KNOWN_LEDGER_SCHEMAS.includes("sukisu-dispositions-v1"));
    check("v2 的两个新字段仓库那份认、公示页也带得出来", (() => {
      const [n] = repo.parseDispositions({
        schema: repo.DISPOSITIONS_SCHEMA,
        dispositions: [{
          kind: "revoke", reason: "malware", by: "gh:b@1", at: "2026-10-17T00:00:00Z", id: "mod_x",
          subject: { coolapkUid: "99999999" }, evidence: [{ file: `evidence/${"f".repeat(64)}.json` }],
        }],
      });
      const view = normalizeDispositions({
        schema: repo.DISPOSITIONS_SCHEMA,
        dispositions: [{ kind: "revoke", reason: "malware", by: "gh:b@1", at: "2026-10-17T00:00:00Z", id: "mod_x", subject: n.subject, evidence: n.evidence }],
      });
      return n.subject?.coolapkUid === "99999999" && n.evidence.length === 1
        && view.items[0].subject?.coolapkUid === "99999999" && view.items[0].evidence.length === 1;
    })());
    // 证据文件的形状：写入端（§8 固化那一步）与展示端（这一页）认的必须是同一个正则。
    check("证据文件名那把正则两端同值", repo.EVIDENCE_FILE_RE.source === LEDGER_EVIDENCE_FILE_RE.source,
      `${repo.EVIDENCE_FILE_RE.source} / ${LEDGER_EVIDENCE_FILE_RE.source}`);

    // 这一组是「真生产者 → 公示页消费者」的闭环：拿索引仓库那份固化模块产出的**真实字节**，
    // 走台账校验，再走这一页的 URL 推导。三处任何一处漂移，这里就红，而不是页面上少一块。
    const harvestPath = resolve(dirname(dispPath), "harvest-evidence.mjs");
    if (!existsSync(harvestPath)) {
      skip("§8 固化的产物进得了台账、也推得出地址", "索引仓库那边还没有 harvest-evidence.mjs（该分支尚未合入）");
    } else {
      const hv = await import(pathToFileURL(harvestPath).href);
      const match = {
        filePath: "pending/probe_mod/7.json",
        commitSha: "0123456789abcdef0123456789abcdef01234567",
        commitSubject: "pending: probe_mod 7 (#999)",
        pr: 999,
        prUrl: "https://github.com/o/r/pull/999",
        record: {
          id: "probe_mod", name: "P", author: "p", description: "d",
          versions: [{ version: "v7", versionCode: 7, zipUrl: "https://x/y.zip", size: 10, sha256: "a".repeat(64) }],
          source: "https://www.coolapk.com/feed/1", uploader: "p", coolapkUid: "99999999",
          pledge: { version: "pledge-v1", atMs: 1 }, ownership: { nonce: "n", proofPrefix: "p", via: "bio", verifiedAt: 1 },
          identity: { username: "pnickname", level: 3 }, storage: "github-release-asset",
          releaseTag: "assets-v1", assetName: `${"a".repeat(64)}.zip`, submittedAt: "2026-10-12T00:00:00.000Z",
        },
      };
      const obj = hv.buildEvidence({ match, packages: null, reportWhy: "夹具：不取评论" });
      const bytes = hv.canonicalBytes(obj);
      const file = hv.evidencePathFor(bytes);
      check("固化的产物文件名过两端那把正则", repo.EVIDENCE_FILE_RE.test(file) && LEDGER_EVIDENCE_FILE_RE.test(file), file);
      const fields = hv.ledgerFieldsFrom({ ok: true, files: [{ path: file, bytes, evidence: obj }] }, new Date("2026-10-17T00:00:00Z"));
      const entry = {
        kind: "revoke", reason: "malware", by: "https://github.com/o/r/issues/3#issuecomment-1",
        at: "2026-10-17T00:00:00Z", id: "probe_mod", coolapkUid: "99999999", ...fields,
      };
      let normEntry = null;
      let normErr = "";
      try {
        [normEntry] = repo.parseDispositions({ schema: repo.DISPOSITIONS_SCHEMA, dispositions: [entry] }, "selftest");
      } catch (e) {
        normErr = e.message;
      }
      check("固化的产物填进台账后，索引仓库那份判得动", !!normEntry && normEntry.evidence[0].file === file, normErr);
      const view = normalizeDispositions({ schema: repo.DISPOSITIONS_SCHEMA, dispositions: [normEntry || entry] });
      check("公示页把同一条的 subject 与 evidence 原样带出来",
        view.items[0].subject?.coolapkUid === "99999999" && view.items[0].evidence[0]?.file === file,
        JSON.stringify(view.items[0].evidence));

      // URL 推导：两种部署各一档，再加「形状不对的一律不取」（台账是人在 PR 里写的，
      // 那一格要是能写 `https://别处/x.json`，公示页就替投稿者发了一次跨站请求）。
      const saved = CONFIG.DISPOSITIONS_URL;
      try {
        CONFIG.DISPOSITIONS_URL = "https://api.example.dev/dispositions.json";
        check("镜像部署下证据地址推成 /evidence/<sha>.json",
          evidenceUrlFor(file) === `https://api.example.dev/${file}`, evidenceUrlFor(file));
        CONFIG.DISPOSITIONS_URL = "https://raw.example.com/o/r/main/json/dispositions.json";
        check("直给仓库部署下证据地址越过 json/ 那一层",
          evidenceUrlFor(file) === `https://raw.example.com/o/r/main/${file}`, evidenceUrlFor(file));
        CONFIG.DISPOSITIONS_URL = "https://api.example.dev/dispositions.json";
        const bad = ["https://evil.tld/evidence/x.json", "evidence/../x.json", "evidence/" + "a".repeat(63) + ".json", "", null, "evidence/" + "a".repeat(64) + ".json?x=1"];
        check("形状不对的证据指针一律推不出地址", bad.every((b) => evidenceUrlFor(b) === ""), bad.filter((b) => evidenceUrlFor(b) !== "").join(","));
      } finally {
        CONFIG.DISPOSITIONS_URL = saved;
      }
    }

    // 高仿头卡读的字段必须在 Worker 那份白名单里：不在就等于那一格永远显示「没采到」，
    // 而页面看起来仍然是对的（这一条就是 goods_count 那三个字段被发现没进快照的方式）。
    const workerIdx = [process.env.WORKER_INDEX_SRC, "../../sukisu/contrib/worker/src/index.ts", "../contrib/worker/src/index.ts"]
      .filter(Boolean).map((p) => resolve(here, p)).find((p) => existsSync(p));
    if (!workerIdx) {
      skip("头卡读的字段都在后端采到的那份白名单里", "找不到 worker/src/index.ts");
    } else {
      const src = readFileSync(workerIdx, "utf8");
      const m = src.match(/const IDENTITY_KEYS = \[([\s\S]*?)\] as const/);
      const keys = m ? [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]) : [];
      const PAGE_FIELDS = ["username", "displayUsername", "level", "bio", "regdate", "logintime", "userBigAvatar", "follow", "fans", "be_like_num"];
      const missing = PAGE_FIELDS.filter((k) => !keys.includes(k));
      check("头卡读的字段都在后端采到的那份白名单里", !!m && missing.length === 0, m ? missing.join(",") : "没找到 IDENTITY_KEYS 那个常量");
    }


    // 选择器集合从仓库那份的**归一化输出**里取，不抄常量：它才是「台账里可能出现哪些命中条件」的定义。
    const norm = repo.parseDispositions({
      schema: repo.DISPOSITIONS_SCHEMA,
      dispositions: [{ kind: "revoke", reason: "other", by: "b", at: "2026-10-11T00:00:00Z", id: "a", versionCode: 1, sha256: "f".repeat(64), coolapkUid: "99999999" }],
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
  // 第一屏那一层是新加的，但它只在自己被画出来的时候才存在：容器、调用点、降级那三格的措辞
  // 都在源码里钉一遍 —— 少一条就是页面上少一块而 selftest 仍然是绿的。
  check(
    "公示页的人卡层三件齐：容器、渲染调用、按条那一层的分界",
    html.includes('id="inc-people"') && html.includes('id="inc-detail"') && html.includes('id="inc-list-head"')
      // 这一条是**文本判据**，所以必须挡住「把调用注释掉」这种形状：只看 `renderPeopleWall(` 在不在，
      // 注释掉它的那一发变异照样绿（2026-10-17 实测到）。负向断言把注释行排除掉。
      && /^(?! *\/\/) *renderPeopleWall\(shown, q\);/m.test(appSrc) && /groupPeople/.test(appSrc)
  );
  check(
    "没有 subject 的条目走降级那一格，措辞不是「没有处置」",
    /pc-wall__none/.test(appSrc) && /所以下面按条那一层就是全部/.test(appSrc) && /只在下面按条那一层列出/.test(appSrc)
  );
  check(
    "证据取不到时说的是取不到，不是一片空白",
    /es--miss/.test(appSrc) && /取不到 \$\{ref\.file\}（\$\{res\.reason\}）|—— \$\{res\.reason\}/.test(appSrc)
  );
  const cssSrc = readFileSync(resolve(here, "../public/styles/panel.css"), "utf8");
  check(
    "高仿头卡固定用那套配色，不跟随站点主题（spec §6.2）",
    /\.ck__cover \{[\s\S]{0,400}?#131a22/.test(cssSrc) && /\.ck__lv \{[\s\S]{0,200}?#23c76a/.test(cssSrc)
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
    else skip("双签文案与审核端一致性校验", msg, 2);
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

  // 总结行不许把跳过藏进后缀。fork 里没有 contrib，跨仓库那几组永远不跑，
  // 而「全部通过」四个字会让所有人以为公式被验过 —— 恰恰在钉最少的地方写得最像钉住了。
  // 所以：有跳过时不说「全部通过」，且把缺席的条数写在同一行里。
  const head = fail === 0 ? (skipped ? "跑到的全通过" : "全部通过") : "有失败项";
  const summary = `${head}：${pass} passed, ${fail} failed${skipped ? `, 跳过 ${skipped} 条跨仓库检查` : ""}`;
  console.log(`\n${summary}`);
  if (skipped && !REQUIRE_BACKEND) {
    console.log(
      "注意：跳过的这些是跨仓库契约校验，在没有 contrib 的 fork 里一条都不跑。" +
        "口令公式在 fork 里只剩上面那组内嵌黄金值守着 —— CI 里请用 npm test -- --require-backend，别让它们静默消失。"
    );
  }
  if (fail) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
