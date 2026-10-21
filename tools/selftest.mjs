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
  proofPrefixV2,
  buildProofStringV2,
  canonicalProofSet,
  PROOF_PREFIX_LEN_V2,
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

/* 口令 v2 的黄金值表（设计文档 §15 第 4 条 + §17.3）—— 一串覆盖「这一次投稿的整套」：
     canon  = 各枚按 id 升序（同 id 再按整包 sha 升序）逐枚写 `id:zipSha`，用 `,` 连接
     prefix = sha256(UTF-8("sukisu-proof-v2:" + canon)) 的十六进制前 12 位
     proof  = prefix + "-" + nonce  ⇒ 恒 19 字符，与枚数无关
   下面五个期望值不是从被测实现里算的：它们与 contrib/worker/src/proof.test.ts 那五条
   「v2 黄金值 / 少一枚 / 换字节」逐字相同，而那两个仓库各自独立内嵌、各自命中同一批 node:crypto
   推出来的数。为什么这张表要抄进本文件（而不只靠跨仓库那条对跑）：fork 里没有 contrib 时
   跨仓库那组永远是 skip，于是 v2 的公式在 fork 里一条都不钉 —— 谁改了排序键或前缀串都不会红。
   这五条挑的是**集合语义**那一面：单枚 / 两枚 / 少一枚 / 换字节 / 非 ASCII id。
   少一枚与换字节那两条是 §16 等价性论证的两条路（口令绑整套 ⇒ 换一套就是另一个前缀），
   它们判的是「多一枚、少一枚必须算出另一串」，这是 v1 那批向量完全判不到的新覆盖面。 */
const PROOF_V2_GOLDENS = [
  { name: "单枚", items: [{ id: "demo", zipSha: ZIP_SHA_A }], prefix: "ffa3c61131d2" },
  {
    name: "两枚",
    items: [
      { id: "aaa", zipSha: ZIP_SHA_A },
      { id: "bbb", zipSha: ZIP_SHA_B },
    ],
    prefix: "c9bdcc965344",
  },
  {
    name: "少一枚",
    items: [{ id: "aaa", zipSha: ZIP_SHA_A }],
    prefix: "7fb2c80c863a",
  },
  {
    name: "换字节",
    items: [
      { id: "aaa", zipSha: ZIP_SHA_B },
      { id: "bbb", zipSha: ZIP_SHA_B },
    ],
    prefix: "271699b8bbd7",
  },
  { name: "中文 id", items: [{ id: "含中文的模块id", zipSha: ZIP_SHA_CN }], prefix: "4ce4c553abc5" },
];

/** 规范串的第二份算法，写在测试里是故意的（上面那条「公式形状独立复算」同一个理由）：
 *  拿 canonicalProofSet 自己去复算 canon，改了排序键也测不出来。 */
function canonOracle(items) {
  return [...items]
    .sort((a, b) => (a.id === b.id ? (a.zipSha < b.zipSha ? -1 : a.zipSha > b.zipSha ? 1 : 0) : a.id < b.id ? -1 : 1))
    .map((i) => `${i.id}:${i.zipSha}`)
    .join(",");
}
const prefixV2Oracle = (items) =>
  createHash("sha256").update(`sukisu-proof-v2:${canonOracle(items)}`, "utf8").digest("hex").slice(0, 12);

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

/**
 * 把整行注释与块注释摘掉，只留下会真的被执行 / 真的被画到屏幕上的那部分。
 * 为什么需要它：闸门与口令那几条钉的是「屏幕上说的那句话」，而那句话的边界恰好是最容易被
 * 一句解释性注释喂绿的地方 —— 变异实测过：把 gateItems 里那句「这道闸分不清是谁投的」从
 * 模板串里删掉，同一格的注释里还留着同一句话，钉子照样绿。那是假绿，不是覆盖。
 * 只用于「判据必须落在文案上」那几条；代码形状类的判据照旧在原图上比，免得把有用的注释也切掉。
 */
function painted(src) {
  return src.replace(/^[ \t]*\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
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
    fetchEvidence,
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
  check("浏览页搜不到时会去查台账，命中就说明是被处置了", /ledgerHitFor\(q\)/.test(appSrc) && /它不是没被上传过，是被下架或拒收了/.test(appSrc));

  check(
    "举报那一行错误有三个来源（本地形状 / 口令来源不齐 / 服务端原文），且 hidden 由内容决定",
    /const shown = local \|\| report\.error;[\s\S]{0,80}err\.hidden = !shown;/.test(appSrc) &&
      !/err\.hidden = true;/.test(appSrc) &&
      /!target\.ok && \$\("#rp-id"\)\.value\.trim\(\)/.test(appSrc),
    "浏览器里真撞过一次：无条件 hidden = true 让「索引给不出那一枚」那句真话永远不出现"
  );
  check(
    "服务端那一句失败活到下一次提交（写进 report.error，由重画统一显示），不许在重画路径之外另擦一次",
    /report\.busy = true;\s*\n\s*report\.error = "";\s*\n\s*\$\("#rp-submit"\)\.disabled = true;/.test(appSrc) &&
      /catch \(err\) \{\s*\n\s*report\.result = null;[\s\S]{0,120}report\.error =/.test(appSrc) &&
      (appSrc.match(/\$\("#rp-error"\)/g) || []).length === 1,
    "在 catch 里直接写那个节点、又在 finally 重画里清一遍，等于刚显示就擦掉"
  );

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
    "昵称整行默认不出现，出现时叫「上传人酷安昵称」且不挂必填星号",
    /id="nick-field" hidden/.test(formHtml) &&
      /<label for="f-uploader">上传人酷安昵称<\/label>/.test(formHtml) &&
      !/for="f-uploader">上传人酷安昵称<span class="req">/.test(formHtml)
  );
  // 界面上只有「上传人」这一个称呼（about 页早就这么写了），混用会让人以为是两个人
  check(
    "UID 那栏点名是「上传人酷安 UID」，且全站不再出现第二种称呼",
    /<label for="f-uid">上传人酷安 UID<span class="req">\*<\/span><\/label>/.test(formHtml) &&
      !formHtml.includes("投稿人") &&
      !appSrc.includes("投稿人") &&
      !formHtml.includes("上传者") &&
      !appSrc.includes("上传者")
  );
  // placeholder 是全站都会渲染出来的字符串，往里塞一个真实 UID 等于把它贴公开。
  check(
    "输入框 placeholder 里不许出现纯数字示例（UID 那栏写的是规则不是号码）",
    !/placeholder="\d{4,}"/.test(formHtml) && /id="f-uid"[^>]*placeholder="4-12 位数字"/.test(formHtml)
  );

  /* ------------------------------------------------------- 04 举报那一屏
     这条路是站内第二个要「实名」的入口（第一个是上传）：它也会烧掉签名里那一串口令，但只在
     受理之后烧。它同时是第一个拿服务端自报门槛（一次几条引用、单条几字节起）驱动界面判据的屏，
     所以这一组钉子盯三件会静默坏掉的事：抄第二本账、派生值与来源脱钩、两种相反的失败糊成一句。 */
  const rpHtml = (formHtml.match(/<section class="view" id="view-report"[\s\S]*?<\/section>/) || [""])[0];
  check(
    "04 举报三处齐：nav 里有入口且编号唯一、VIEWS 指对容器、section 自己有 aria-labelledby",
    /<a href="#\/report"><i>04<\/i>举报<\/a>/.test(formHtml) &&
      /report: \{ el: "#view-report"/.test(appSrc) &&
      /id="view-report" aria-labelledby="h-report"/.test(rpHtml) &&
      /<h1 id="h-report">/.test(rpHtml) &&
      (formHtml.match(/<i>04<\/i>/g) || []).length === 1,
    "nav/VIEWS/section 任一处缺就是这一屏进不去，或编号有两种说法"
  );
  /* 这一格盯的不是「有没有写 \|\| 8」这种形状，而是那个函数体里**一个数字都不许出现**：
     抄一份默认值可以写成 `{ maxEvidenceItems: 8 }`、可以写成三元、也可以写成参数默认值 ——
     盯形状只会挡住我此刻想到的那一种写法。 */
  const rpLimitsBody = (appSrc.match(/function reportEvidenceLimits\(\) \{[\s\S]*?\n\}/) || [""])[0];
  check(
    "举报页不抄第二本账：条数与单条字节下界都从 state.limits.report 取，取值那一段里一个数字都没有",
    /state\.limits && state\.limits\.report/.test(appSrc) &&
      /maxEvidenceItems: pickIn\(rl, "maxEvidenceItems"\)/.test(apiSrc) &&
      /minQuoteBytes: pickIn\(rl, "minQuoteBytes"\)/.test(apiSrc) &&
      rpLimitsBody.length > 40 &&
      !/[0-9]/.test(rpLimitsBody.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "")),
    `取值那一段=${rpLimitsBody.slice(0, 120) || "(切不到)"}`
  );
  check(
    "口令是派生值：每次渲染现算，异步回来时来源一动就丢弃（id / 那一版 / nonce 任一一动）",
    /buildProofString\(target\.id, target\.sha, report\.nonce\)/.test(appSrc) &&
      /if \(!now\.ok \|\| `\$\{now\.id\}\|\$\{now\.sha\}\|\$\{report\.nonce\}` !== expected\) return;/.test(appSrc) &&
      !/const report = \{[^}]*proof:/.test(appSrc),
    "把算出来的串存进 state 迟早和来源脱钩 —— 屏幕上是 A 的口令、发出去的是 B 的那一枚"
  );
  check(
    "索引里给不出那一枚就不许提交：enable 判据含 reportTarget().ok，缺哪一样说哪一样的真话",
    /const ok =\s*\n?\s*target\.ok &&/.test(appSrc) &&
      /\$\("#rp-submit"\)\.disabled = !ok;/.test(appSrc) &&
      /举报只管已经上架的模块/.test(appSrc) &&
      /没有 64 位的包体 sha256/.test(appSrc) &&
      /这一版不在索引里/.test(appSrc)
  );
  /* 「不许在失败那一支里轮换 nonce」这一条不能拿「往后数 400 个字符里没有 makeNonce」来判：
     窗口会漂到下一个函数（renderReport 里就有轮换），改了代码结构就假红。切那一段 catch 体本身。 */
  const rpCatchBody = (appSrc.match(/catch \(err\) \{[\s\S]*?\n  \} finally \{/) || [""])[0];
  check(
    "受理之后才换 nonce；没受理的那一次明说「不消耗你的口令」，且失败那一支里一个 nonce 都不生成",
    /report\.result = json;[\s\S]{0,160}report\.nonce = makeNonce\(\);/.test(appSrc) &&
      rpCatchBody.length > 40 &&
      !/makeNonce/.test(rpCatchBody) &&
      /它没消耗你的口令/.test(appSrc)
  );
  check(
    "举报只 POST /report，失败一律过那张码表；「不成立」留在 200 里当结论而不是当请求失败",
    /fetch\(url\("\/report"\)/.test(apiSrc) &&
      /if \(!res\.ok\) throw backendFailure\(res\.status, json, text\);/.test(apiSrc) &&
      !/established === false[\s\S]{0,120}throw new BackendError/.test(apiSrc),
    "把「没有成立」做成 4xx 会让人以为没提交成功，而它其实是这条路上最常见、也最该被如实展示的那一条结论"
  );
  check(
    "举报入口只在索引给得出 64 位 sha256 时才出现（口令来源不齐就别许诺这枚报得了）",
    /if \(latest && SHA256_HEX_RE\.test\(String\(latest\.sha256 \|\| ""\)\)\) \{[\s\S]{0,220}#\/report\?id=/.test(appSrc)
  );
  check(
    "举报页把「这一片不动公开状态」写在界面上，而不是只写在服务端应答里",
    /publicAction: none/.test(rpHtml) &&
      /举报不会让任何模块下架/.test(rpHtml) &&
      /与上传那 5 格\/小时是分开的两本账/.test(rpHtml)
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

  /* ---------------------------------------------- 口令 v2：一串覆盖整套（§15 / §17.3）
     上面那批 v1 向量一条都不许删：Worker 的 matchProofInBio 是**先 v1 后 v2**，旧版 App 还在发
     v1，换代次序是「Worker 先读 v1∪v2 并部署 ⇒ 前端切 v2 ⇒ App 择期」（§15、§17.1）。
     下面这组是加出来的第二套判据，不是把第一套换掉。 */
  const v2Wrong = [];
  for (const g of PROOF_V2_GOLDENS) {
    const got = await proofPrefixV2(g.items);
    if (got !== g.prefix) v2Wrong.push(`${g.name}: 实现=${got} 黄金值=${g.prefix}`);
    const want = prefixV2Oracle(g.items);
    if (got !== want) v2Wrong.push(`${g.name}: 实现=${got} node:crypto=${want}`);
  }
  check(
    "v2 内嵌黄金值 5/5 且 node:crypto 独立复算同值：前缀 = sha256(\"sukisu-proof-v2:\" + canon) 前 12 位",
    v2Wrong.length === 0,
    v2Wrong.join(" | ")
  );
  // 顺序是「这一套」定义的一部分：前端按用户选的次序、Worker 按 multipart 到达的次序，
  // 两边不同序就会算出两个前缀，而「对不上」在那条闸里读起来跟「你不是本人」一模一样。
  const v2Order = [
    { id: "aaa", zipSha: ZIP_SHA_A },
    { id: "bbb", zipSha: ZIP_SHA_B },
  ];
  check(
    "v2 的规范串与调用方给的次序无关（正序、乱序、同 id 再按 sha 排都算出同一串）",
    canonicalProofSet([...v2Order].reverse()) === canonicalProofSet(v2Order) &&
      (await proofPrefixV2([...v2Order].reverse())) === (await proofPrefixV2(v2Order)) &&
      canonicalProofSet(v2Order) === canonOracle(v2Order),
    canonicalProofSet(v2Order)
  );
  // 「恒 19 字符、与枚数无关」是这次换代的**全部意义**（§15：v1 那 15 字符 × N 串放不下 60 的签名）。
  // 它必须被算出来而不是被说出来：枚数一多就变长的实现，界面上的容量文案照样能写得很好看。
  const v2Lens = [];
  let v2Shape = "";
  for (let n = 1; n <= 8; n++) {
    const items = Array.from({ length: n }, (_, i) => ({ id: `m${i}`, zipSha: ZIP_SHA_A }));
    const s = await buildProofStringV2(items, "ab12cd");
    v2Lens.push(s.length);
    v2Shape = s;
  }
  check(
    "v2 整串口令恒 19 字符、与枚数无关（1..8 枚各算一遍），形状 = 12 位十六进制 + '-' + 6 位小写字母数字",
    PROOF_PREFIX_LEN_V2 === 12 &&
      v2Lens.every((l) => l === 19) &&
      /^[0-9a-f]{12}-[a-z0-9]{6}$/.test(v2Shape) &&
      new Set(v2Lens).size === 1,
    `各枚数长度=${v2Lens.join(",")} 首个样例=${v2Shape} 前缀长度常量=${PROOF_PREFIX_LEN_V2}`
  );
  // canonicalProofSet 那三条拒绝判的都是**客户端可控**的边界输入（空集、非小写十六进制、同 id 两次），
  // 不是内部不可能状态。放过去就是把形状问题推到「口令对不上」那一格，而那一格的文案是「你不是本人」。
  const v2Rejects = [];
  const mustThrow = (label, fn, re) => {
    try {
      fn();
      v2Rejects.push(`${label} 没抛错`);
    } catch (err) {
      if (!re.test(err.message)) v2Rejects.push(`${label} 抛的不是那一句：${err.message}`);
    }
  };
  mustThrow("空集合", () => canonicalProofSet([]), /不能为空/);
  mustThrow("同一个 id 两次", () => canonicalProofSet([{ id: "dup", zipSha: ZIP_SHA_A }, { id: "dup", zipSha: ZIP_SHA_B }]), /出现两次/);
  mustThrow("大写 sha", () => canonicalProofSet([{ id: "x", zipSha: ZIP_SHA_A.toUpperCase() }]), /小写十六进制/);
  mustThrow("短 sha", () => canonicalProofSet([{ id: "x", zipSha: "deadbeef" }]), /小写十六进制/);
  mustThrow("空 id", () => canonicalProofSet([{ id: "", zipSha: ZIP_SHA_A }]), /空模块 id/);
  check(
    "v2 集合的形状闸只拒坏输入、不做静默规范化（空集 / 重复 id / 大写或短 sha / 空 id 各一条）",
    v2Rejects.length === 0,
    v2Rejects.join(" | ")
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
  // 派生值一旦进 state，就和来源脱钩了：改了 id / 换了包还缓存着旧口令。只准缓存来源。
  /* 旧断言（v1）钉的是 `buildProofString(id, zipSha, nonce)` 那三个来源。§15 之后口令绑的不再是
     「一枚的那一对」，而是「这一整套的 (id, 整包 sha256) 集合」+ 一枚随机段 ⇒ 来源换了名字：
     集合本身就是来源，少一枚、多一枚、换一枚字节都是另一个来源。**守的性质一个字没动**，
     所以这里是改写成等价断言而不是删掉：删掉就等于允许有人把那一串存进 state（某一枚换了包，
     屏幕上还挂着上一串的口令），而那正是这条闸要封死的那件事。
     新增的两条子判据是 v2 才有的面：算串只准发生在展示那两处（renderProof / 上传前确认），
     载荷组装那一层一次都不许碰它 —— 载荷里一旦有派生串，就是前端替后端定了结论。 */
  const batchPayloadSrc = appSrc.slice(
    appSrc.indexOf("function batchPayload()"),
    appSrc.indexOf("\n}", appSrc.indexOf("function batchPayload()"))
  );
  check(
    "前端只缓存来源不缓存派生串（v2）：口令串由「整套的 (id, zipSha) 集合 + state.nonce」在展示处现算，载荷里不碰它",
    /state\.nonce/.test(appSrc) &&
      /const zipSha = state\.zipSha;/.test(appSrc) &&
      /const nonce = state\.nonce;/.test(appSrc) &&
      /text = await buildProofStringV2\(set\.items, nonce\);/.test(appSrc) &&
      /function setSources\(\)[\s\S]{0,600}?items: targets\.map\(\(t\) => \(\{ id: t\.id, zipSha: t\.zipSha \}\)\)/.test(appSrc) &&
      !/state\.proof/.test(appSrc) &&
      !/buildProofStringV2|proofText|canonicalProofSet/.test(batchPayloadSrc) &&
      (appSrc.match(/^\s*text = await buildProofStringV2\(/gm) || []).length === 2,
    `展示处算串的次数=${(appSrc.match(/^\s*text = await buildProofStringV2\(/gm) || []).length}（期望 2：renderProof 与上传前确认）`
  );
  // 载荷里没这三项时后端只能把「没承诺」判成「承诺过」、把「没声明哈希」判成「哈希一致」——
  // 静默放行，前端界面还一切正常。
  /* 旧断言（v1）要求顶层出现一个 `sha256` 字段。§17.3 之后批量载荷的形状变了：逐枚的
     id 与 sha256 进了 `manifest.modules[]`（它们是 §16 那条闸的判据输入），顶层只留共享的
     pledge / nonce / coolapkUid / uploader / turnstile ——「一次投稿只有一个人、一个承诺、一枚口令」。
     sha256 没有从载荷里消失，它从「一枚一个顶层字段」变成「一整套 N 条声明」，而且比 v1 **更硬**：
     缺任何一枚的声明就干脆不发这个请求。v1 那回 ⑤-c 的「没传就回退用服务端自己算的」必须删干净
     （§16 第 1 句 + §18 那条新钉子：它一旦活过来，口令就退化成只绑模块 id，而现有测试一条都不红）。 */
  check(
    "提交载荷带上 pledge、nonce 与逐枚的整包 sha256（v2：sha256 在 manifest.modules[] 里，缺一枚就不发这个请求）",
    /form\.append\(\s*["']pledge["']/.test(apiSrc) &&
      /form\.append\(\s*["']nonce["']/.test(apiSrc) &&
      /form\.append\(\s*["']manifest["']/.test(apiSrc) &&
      /sha256:\s*String\(m\.sha256 \|\| ""\)\.trim\(\)\.toLowerCase\(\)/.test(apiSrc) &&
      /id:\s*String\(m\.id \|\| ""\)\.trim\(\)/.test(apiSrc) &&
      /const noSha = modules\.filter\(\(m\) => !SHA256_HEX_RE\.test\(String\(m\.sha256 \|\| ""\)\)\)/.test(apiSrc) &&
      /if \(noSha\.length\)/.test(apiSrc) &&
      apiSrc.includes('SHA256_HEX_RE = /^[0-9a-f]{64}$/')
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
  /* 旧断言第二句钉的是 renderProof 里那一句 `if (!nonce || !id || !zipSha)`（v1：三个来源就是三个值）。
     v2 里「少一个来源」不再是少一个值，而是「这一整套里有任何一枚不齐」⇒ 同一件事在代码里长成两个分支：
     !nonce 或集合是空的 ⇒ 整格收起；集合里还差枚 ⇒ 宁可不说出一串（拿「齐了的那几枚」算一串，
     那一串对不上将要提交的那一套，用户抄进签名就是白改一次签名）。两句都还在，判据一个字没放宽。
     本机改写这条时实测出一个**真缺陷**（已修 app.js，不是改尺子放过它）：两枚模块 ID 相同时
     canonicalProofSet 直接抛，屏幕上那一格写的是「这一套现在算不出口令」，而 gateItems 的 shown
     只看「每一枚的字段齐不齐」—— 那一格没齐，底栏照样说「全部就绪，可以确认」。
     所以新增 `dupId` 这一条，并把 shown 与清单那句文案一起挂到它上面：屏幕上没有一串可抄的东西时，
     任何一处都不许自称就绪。这一条不许再放宽 —— 它守的就是这条钉子的原始事故（Task 10 走查那条假现场）。 */
  /* 串行解析链的两个链接都必须自带 catch（app.js 的 scheduleIntake 与 swapInto）。
     理由不是风格：`p = p.then(f)` 只要有一次 reject（包里读不出 module.prop、`POST /check`
     那一次网络抖动），这条链就**永久**是 rejected，之后每一次选包与换包都被静默跳过 ——
     界面上的表现正是「把包拖进去没反应」，而唯一的出路是刷新页面，页面上没有任何一句话说明过这件事。
     所以这条钉子同时钉四处：两处 catch、把失败写进 state 的那一格、以及门禁清单里那一条真的读它。 */
  check(
    "解析链两处链接都自带 catch，失败会写进 state 并进门禁清单（不许再有「拖进去没反应」这种静默）",
    /parseChain = parseChain\.then\(\(\) => intakeBatch\(files\)\)\.catch\(intakeFailed\)/.test(appSrc) &&
      /parseChain = parseChain\.then\(\(\) => swapRun\(card, file\)\)\.catch\(intakeFailed\)/.test(appSrc) &&
      /function intakeFailed\(e\)/.test(appSrc) &&
      /intakeError: ""/.test(appSrc) &&
      /\.\.\.\(state\.intakeError/.test(appSrc),
    "app.js 里这四格少任何一格，一次解析失败就会把整条队列永久打死"
  );

  check(
    "口令行的来源齐了才算 shown（v2：整套每一枚的 id 与整包哈希 + 那一枚随机段；屏幕上没串可抄时不许自称就绪）",
    /shown: Boolean\(state\.nonce && proofId && state\.zipSha\)/.test(gateBody) &&
      /&& targets\.length > 0 && incomplete\.length === 0 && !dupId/.test(gateBody) &&
      /const idsInSet = targets\.map\(\(c\) => cardValues\(c\)\.id\)\.filter\(Boolean\);/.test(gateBody) &&
      /if \(!nonce \|\| !set\.targets\.length\) \{/.test(appSrc) &&
      /if \(set\.incomplete\.length\) \{/.test(appSrc) &&
      painted(gateBody).includes("队列里有两枚的模块 ID 是同一个"),
    `shown 主式在=${/shown: Boolean\(state\.nonce && proofId && state\.zipSha\)/.test(gateBody)} 集合那一半=${/&& targets\.length > 0 && incomplete\.length === 0 && !dupId/.test(gateBody)} renderProof 两分支=${/if \(!nonce \|\| !set\.targets\.length\) \{/.test(appSrc) && /if \(set\.incomplete\.length\) \{/.test(appSrc)}`
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
    "平台侧「读不出本次上传的口令记录」不算口令烧掉（兜底判据只认那两种说法）",
    [
      "这个口令已经用过，请重新生成后再提交",
      // 第二支钉的是正则里的前向兼容钩子：Worker 今天没有任何可发的文案与之匹配（整个
      // worker/src 搜不到「可能已」「提交成功」）—— 这条正例证明钩子还挂着，不证明后端会发。
      // 客户端真正的「可能已提交」（网络失败/中断/读不懂应答）按判据刻意不轮换，归码那边兜底。
      "口令可能已提交成功，请刷新索引后确认",
    ].every((s) => SPENT_TEXT_RE_FALLBACK.test(s)) &&
      [
        // 9d66cd8 换掉旧文案「酷安核实没通过（口令记录读不出来）」后的现行句子（index.ts 的
        // KV 读失败分支原样，2026-10-21 站内语域改成「上传」之后一起跟着换）：失败的是自家记账，
        // 不是「你用过了」，绝不许触发轮换。
        "服务端读不出本次上传的口令记录（自家记账的 KV 没有应答），本次未提交 —— 请稍后重试",
        "酷安核实没通过（连接超时），本次未提交 —— 与你是不是本人无关，请稍后重试",
        "上传需要酷安等级 Lv2 及以上",
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

  /* =================== 多模块队列：一次填表、多枚排队、整套一次提交
     这一组守的始终是同一件事：「界面上的 N 与网络上的 N 是同一个 N」。变的是 N 落在哪：
     v1（§15 之前）口令 = sha256(模块id + 整包sha256) 前 8 位 + "-" + 6 位随机段，一枚一串，
     `used-nonce` 用过即废 ⇒ N 枚必然是 N 条串、N 次各自带凭据的 POST。
     v2（§15 拍板、§17 定线上契约）一串覆盖整套、恒 19 字符、与枚数无关，一次动作只有一个 POST
     带 N 个 zip + 一份 manifest + 那**一枚**共享的 nonce ⇒ 于是这个 N 同时是三样东西的 N：
     闸门与队列那句读数、口令绑的那个集合、manifest 里那几条与 file part 的个数。
     三处任何一处糊在一起（一个读数两套判据、被摘出去的枚还进口令集合、切卡把上一枚的来源带过去、
     顶层 part 的次序漂到 file part 之后），页面上都看不出来，坏的是投稿人烧掉的签名与限流格。
     下面每一条都留了一行「旧断言为什么不再适用」——没有那一行，下一轮没人分得出这是放宽还是修正。 */
  const submitAt = apiSrc.indexOf("export function submitContribution(");
  const submitBody = submitAt === -1 ? "" : apiSrc.slice(submitAt, apiSrc.indexOf("\n}", submitAt));
  // 字段名有两种写法都要认：字面量（"id"）与从 config 取的派生名（CONFIG.COOLAPK_UID_FIELD）——
  // 后者本来就只有一个定义处，不许在测试里再抄一份字符串，那正是这个站反对的做法。
  const sentFields = [...submitBody.matchAll(/form\.append\(\s*(?:"([^"]+)"|'([^']+)'|([A-Za-z_$][\w.]*))\s*,/g)]
    .map((m) => m[1] ?? m[2] ?? m[3]);
  const manifestBody = apiSrc.slice(
    apiSrc.indexOf("function buildManifest("),
    apiSrc.indexOf("\n}", apiSrc.indexOf("function buildManifest("))
  );
  /* 旧断言钉的是「一枚一个请求」那份逐枚字段集合：zip/id/name/version/versionCode/author/
     description/source/uploader/<UID字段>/sha256/pledge/nonce/<turnstile字段>。§17.1 之后
     「存在名为 manifest 的 text field ⇒ 走批量」，那八个逐枚字段搬进了 manifest.modules[]，
     顶层只剩五个共享字段 —— 一次投稿只有一个人、一个承诺、一枚口令（§17.3）。
     字段一个都没少发，只是换了住处，所以这里两头都钉：顶层 part 的**集合与次序**逐字，
     加上 manifest 里那八项的集合逐字。次序是新长出来的一条判据：§17.2 说 manifest 晚于
     第一个 file part 就是 400 manifest_late，而闸前移之后口令的输入来自这份声明 ——
     插入序漂到文件之后，整套会一发都发不出去。 */
  check(
    "提交请求的 part 集合与次序（§17.2 / §17.3 批量契约）：manifest 排在第一个 file part 之前，其后 uploader/<UID字段>/pledge/nonce/<turnstile字段>，最后 N 个 zip",
    submitAt !== -1 &&
      sentFields.join(",") ===
        ["manifest", "uploader", "CONFIG.COOLAPK_UID_FIELD", "pledge", "nonce", "CONFIG.TURNSTILE_FIELD", "zip"].join(",") &&
      submitBody.indexOf('form.append("manifest"') !== -1 &&
      submitBody.indexOf('form.append("manifest"') < submitBody.indexOf('form.append("zip"') &&
      submitBody.indexOf('form.append("zip"') > submitBody.indexOf("CONFIG.TURNSTILE_FIELD") &&
      (submitBody.match(/form\.append\("zip"/g) || []).length === 1,
    `顶层 part=${sentFields.join(",")} manifest位置=${submitBody.indexOf('form.append("manifest"')} 第一个zip=${submitBody.indexOf('form.append("zip"')}`
  );
  // manifest 里那八项是 §17.3 的原文形状，也是 §16 那条闸的判据输入；多一项少一项都算两边形状不一。
  check(
    "manifest 的形状逐字对着 §17.3：version='batch-v1' + modules[] 里 id/sha256/name/version/versionCode/author/description/source 八项，共享字段不在里面",
    /version: "batch-v1"/.test(manifestBody) &&
      ["id:", "sha256:", "name:", "version:", "versionCode:", "author:", "description:", "source:"].every((k) =>
        manifestBody.includes(k)
      ) &&
      !/nonce|pledge|turnstile|coolapkUid|uploader/.test(manifestBody),
    manifestBody.slice(0, 60)
  );
  // 这条**不是**契约变更，是尺子指错了名字：函数从 submitModule 改叫 submitContribution，
  // 而它守的性质一个字节都没松 —— 加了任何一个自定义请求头，这个跨站 POST 就不再是
  // CORS 简单请求，浏览器会先发 preflight，而那个 OPTIONS 没人接得住（网关只放行 GET/POST），
  // 于是页面上一句「网络错误」，实际是请求根本没出去。判据只收紧不放宽：
  // 上面那条 submitAt !== -1 现在同时是这两条的前置，函数改名或整条被删都会当场红，不会退化成空断言。
  check(
    "提交仍然保持 CORS 简单请求：submitContribution 里一个 setRequestHeader 都不许加，发出去的是 FormData 本体",
    submitAt !== -1 && submitBody.length > 200 && !/setRequestHeader/.test(submitBody) && /xhr\.send\(form\)/.test(submitBody),
    `submitContribution 起点=${submitAt} 体长=${submitBody.length}`
  );

  // 「本次要投 N 枚」这句话与队列读数是两份判据的话迟早会漂 —— 所以钉死它们同源。
  const targetsBody = appSrc.slice(
    appSrc.indexOf("function submitTargets()"),
    appSrc.indexOf("\n}", appSrc.indexOf("function submitTargets()"))
  );
  const readoutBody = appSrc.slice(
    appSrc.indexOf("function paintQueueReadout()"),
    appSrc.indexOf("\n}", appSrc.indexOf("function paintQueueReadout()"))
  );
  const refreshBody2 = appSrc.slice(
    appSrc.indexOf("function refreshGate()"),
    appSrc.indexOf("\n}", appSrc.indexOf("function refreshGate()"))
  );
  // 口令那一套的来源函数（挪到这里是因为下面两条都要按函数体切，而不是在全文件里找同一句话：
  // 「for (const card of submitTargets())」在别处出现不该算这条通过）。
  const targetsFn = appSrc.slice(
    appSrc.indexOf("function proofTargets()"),
    appSrc.indexOf("\n}", appSrc.indexOf("function proofTargets()"))
  );
  /* 这条守的性质没变，而且比 v1 更要紧：批量之后「界面上的 N」同时是三样东西的 N ——
     闸门清单那句读数、口令绑的那个集合、manifest 里那几条与 file part 的个数。
     v1 时 N 只影响一句话，v2 时 N 漂一枚就是一串对不上要提交那一套的口令。
     旧断言里改了两条子判据：① `submitTargets` 的形参从 card 改成了 c（箭头函数的变量名，
     不是判据），这里按新名字逐字钉住它仍然过 isRecorded，并且多钉一条 —— 批量之后还得多摘
     一类「已经拿到回执的枚」（card.ack），同一套连发两次服务端会回口令已用过；
     ② `submitTargets().filter((c) => c !== card).length` 是逐枚提交那一版里「还剩几枚」那个读数，
     整套一次提交之后这个数没有意义了（不存在按枚剩余），所以换成同一判据必须喂给
     paintQueueReadout / batchPayload / proofTargets 这三处 —— 少喂一处就是那一处在自己数 N。 */
  check(
    "闸门清单里那句「本次要上传 N 枚」与队列读数、载荷、口令集合同用一个 submitTargets()：读数与真提交的枚数不会漂",
    /const n = submitTargets\(\)\.length;/.test(gateBody) &&
      /const targets = submitTargets\(\);/.test(readoutBody) &&
      /const targets = submitTargets\(\);/.test(batchPayloadSrc) &&
      /for \(const card of submitTargets\(\)\)/.test(targetsFn) &&
      /c\.file && !isRecorded\(c\) && !c\.ack/.test(targetsBody) &&
      /const isRecorded = \(card\) => checkOf\(card\) === "recorded";/.test(appSrc) &&
      (appSrc.match(/submitTargets\(\)/g) || []).length >= 5,
    `submitTargets 体=${targetsBody.slice(0, 90)}…`
  );
  /* 旧断言（v1，逐枚那一版）要求 proofTargets 里自己再 `if (isRecorded(card)) continue;` 一遍，
     因为那时口令是一枚一串、摘出去的那一枚会单独生成一条没人能用的串。
     v2 之后一串覆盖整套 ⇒ 「那一枚不生成口令」这句话本身不成立了 —— 等价的要求变成：
     **摘出去的那一枚不许进口令绑的那个集合**（多一枚少一枚都是另一个前缀，§15/§16），
     而且屏幕上那一串必须说得出它不含谁。旧那份在循环里重写的第二道 filter 反而是要不得的：
     两处判据迟早漂成「清单说 3 枚、口令按 4 枚算」。所以这里钉的是同源（走 submitTargets）
     + 那一格点名不含谁，一条判据都不减。 */
  check(
    "被 recorded 摘出去的那一枚不进口令绑的那个集合：口令那一串与提交用同一个 submitTargets() 判据，并在屏幕上点名它不含谁",
    /for \(const card of submitTargets\(\)\)/.test(targetsFn) &&
      /!isRecorded\(c\)/.test(targetsBody) &&
      /const rec = state\.cards\.filter\(\(c\) => isRecorded\(c\)\);[\s\S]{0,200}不含：/.test(appSrc) &&
      /const zipSha = live \? state\.zipSha : card\.zipSha;/.test(appSrc),
    `proofTargets 起点=${appSrc.indexOf("function proofTargets()")} roster那一句在=${/不含：/.test(appSrc)}`
  );
  /* 旧的两条字面量（「不算在本次投稿里」「口令不生成，签名里不用抄它」）是逐枚提交那一版的说法：
     那时摘出一枚只是少发一个请求。v2 摘出一枚会**换掉屏幕上那一串口令**（集合变了前缀就变了），
     所以这一句要说的三件事也换了：点名是哪一枚、它不进 manifest、剩下那几枚算出来的才是新的一串。
     措辞的边界按 §17.6 与本轮的实测说真话，一条都不许多：公开索引里不带投稿人 UID ⇒ 分不清是谁投的；
     还在 pending/ 里的同 id 今天查不到 ⇒ 那一档这一轮拦不住。这两句必须留在那一行里，
     否则「已被投稿过」这五个字会被读成「有人证明了我不是第一个投的」——那不是这台闸能说的话。 */
  const recordedLine = painted(
    gateBody.slice(gateBody.indexOf("if (recorded.length)"), gateBody.indexOf("if (state.cards.length > 1)"))
  );
  check(
    "已收录那一档拦下来时闸门点的是那一枚、说的是这个 id 已被上传过：那条行写在 gateItems 里，并说清它分不清谁上传的",
    recordedLine.includes("这个 id 已被上传过") &&
      recordedLine.includes("已从这一套里摘出去") &&
      recordedLine.includes("它不进 manifest") &&
      recordedLine.includes("口令那一串按剩下的") &&
      recordedLine.includes("分不清是谁上传的") &&
      recordedLine.includes("查不到还在待审的那一份") &&
      /namesOf\(recorded\)/.test(recordedLine),
    `那一段剥掉注释之后=${recordedLine.slice(0, 80).replace(/\s+/g, " ") || "(切不到)"}`
  );
  /* 「已收录」那一格不许挡住剩下的几枚 —— 这是用户给这条拦截的原话（「不再参与接下来的步骤」），
     不是「把整套扣下来」。而 ready 的唯一判据是 items.every(i => i.ok)：那一格写成 ok:false
     就和它自己那句「已摘出、不进这次提交」互相打脸（一枚老模块挡住了整套）。
     用 painted() 而不是裸 appSrc：那一格上方的注释里就出现着 `ok:false` 这四个字符，
     拿源码当尺子会把这条负断言变成永远红 / 永远绿两种假话之一。
     三处同时钉：items 那一格、refreshGate 的第三档映射、panel.css 真给了它一档 ——
     少钉一处，将来就能在一处悄悄退回去。 */
  const recordedBlock = painted(
    gateBody.slice(gateBody.indexOf("if (recorded.length)"), gateBody.indexOf("if (state.cards.length > 1)"))
  );
  const cssGate = readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "../public/styles/panel.css"), "utf8"
  );
  check(
    "已收录那一格不拦整套提交：ok 为真、走 note 第三档，CSS 也真给了它一档（黄点，既不是 ✓ 也不是 ✗）",
    /ok: true,\s*note: true,/.test(recordedBlock) &&
      !/ok: false/.test(recordedBlock) &&
      /const cls = item\.note \? "note" : item\.ok \? "pass" : "";/.test(appSrc) &&
      /\.gate li\.note::before \{[\s\S]{0,120}?"!"/.test(cssGate) &&
      /\.gate li\.note::before \{[\s\S]{0,140}?var\(--amber\)/.test(cssGate),
    `那一格剥注释后=${recordedBlock.slice(0, 60).replace(/\s+/g, " ") || "(切不到)"} cls=${/item\.note \? "note"/.test(appSrc)} css=${/\.gate li\.note/.test(cssGate)}`
  );
  /* 这条整句作废于 §15「不能只做前端」那一段：一串口令只有在**一个请求带整套**时语义才干净。
     仍是 N 次 POST 的话，要么第一次就把这串烧掉（后 N-1 次全被判口令已用过），要么把记账
     降成一枚一次 —— 那攻击者读到串后可以逐枚预占。所以「按枚走」不是被放宽了，是被反过来了：
     现在钉的是「一次动作恰好一个 POST、整套一起走」，并且把「出现第二个 await submitContribution(
     就要先说清它凭什么能连着发」这条原始追问原样搬过来 —— 判据的强度没降。
     应答那一半按 §17.5 的形状钉：{ ok, pr, modules[] }，整套一个结论 + 逐枚明细。 */
  check(
    "提交是整套走的：一次动作只发一个 POST，带那一份共用的 nonce 与逐枚声明的 sha256；出现第二个 await submitContribution( 就要先说清它凭什么能连着发",
    /async function uploadBatch\(\)/.test(appSrc) &&
      /const \{ pr, modules \} = await submitContribution\(payload, \{/.test(appSrc) &&
      (appSrc.match(/await submitContribution\(/g) || []).length === 1 &&
      /nonce: state\.nonce,/.test(batchPayloadSrc) &&
      /sha256: card\.zipSha,/.test(batchPayloadSrc) &&
      !/await submitModule\(/.test(appSrc) &&
      !/nonce: card\.nonce,/.test(appSrc),
    `await submitContribution 次数=${(appSrc.match(/await submitContribution\(/g) || []).length}`
  );

  // 派生值绑死来源：这一枚的口令换了 id 或换了包就必须当场死（站里踩过三次的那件事）。
  const renderProofFn = appSrc.slice(
    appSrc.indexOf("async function renderProof()"),
    appSrc.indexOf("\n}", appSrc.indexOf("async function renderProof()"))
  );
  /* 旧断言的四条子判据全是 v1 逐枚那一版的形状：每一枚自己那一行有一个 (id, zipSha, nonce)，
     少任何一个就 `continue` 跳过那一行，来源在 await 期间动过就 return 不贴那一行。
     v2 之后随机段不再是「每一枚一份」而是一次投稿一份，那一行也不再是 N 行而是 1 行覆盖整套
     ⇒ 前两条的等价物搬进了 setSources()：判「这一套齐不齐」而不是判「这一枚齐不齐」，
     少任何一枚的 id 或整包哈希就没有串（拿齐了的那几枚算一串是有害的：那一串对不上要提交的那一套）。
     后两条守的东西一个字没动 —— 那就是这条钉子的原始目的：await 期间来源动过（改 id、换包、
     重掷随机段、摘进/摘出一枚）就不许把上一串贴上去。现在它比较的是整套：nonce + 枚数 +
     逐枚的 id 与 zipSha，一条都比 v1 那三条多而不是少。 */
  check(
    "口令那一串按整套的来源现算（不缓存串），await 期间集合或随机段动过就不许贴：少一枚 id / 少一枚整包哈希就没有串",
    /incomplete: targets\.filter\(\(t\) => !t\.id \|\| !SHA256_HEX_RE\.test\(String\(t\.zipSha \|\| ""\)\)\)/.test(appSrc) &&
      /text = await buildProofStringV2\(set\.items, nonce\);/.test(renderProofFn) &&
      /const now = setSources\(\);/.test(renderProofFn) &&
      /state\.nonce !== nonce \|\|[\s\S]{0,120}now\.targets\.length !== set\.targets\.length/.test(renderProofFn) &&
      /it\.id !== set\.items\[i\]\.id \|\| it\.zipSha !== set\.items\[i\]\.zipSha/.test(renderProofFn) &&
      !/buildProofString\(id, zipSha, nonce\)/.test(appSrc),
    renderProofFn.slice(0, 80)
  );
  check(
    "查重结论绑死 (id, versionCode)：checkOf 现算比较，id 改一下结论就当场上真",
    /function checkOf\(card\)/.test(appSrc) &&
      /card\.checkKey === checkKeyOf\(v\.id, v\.versionCode\)/.test(appSrc) &&
      /function invalidateCheck\(card\)/.test(appSrc)
  );
  check(
    "id / versionCode 的第一下 input 就先作废旧结论，再排下一次查询（顺序反了就是屏幕上那句假话）",
    /fieldEls\[key\]\.addEventListener\("input", \(\) => \{[\s\S]{0,200}?invalidateCheck\(card\);[\s\S]{0,120}?scheduleCheck\(card\);/.test(appSrc)
  );
  // 口令那一行也必须「第一下就死」：等 await 回来再换串的那几十毫秒，屏幕上挂的还是上一串
  // —— 而那一串属于已经不存在的组合。所以清行排在 await **之前**（顺序断言，不是数出现次数）。
  const renderProofSrc = appSrc.slice(
    appSrc.indexOf("async function renderProof()"),
    appSrc.indexOf("\n}", appSrc.indexOf("async function renderProof()"))
  );
  /* 这条是本轮唯一「看着像前端把清理逻辑写丢了」的一条，实测结论是：**清理没丢，是尺子的模式没了**。
     旧模式找的是 `await Promise.all` —— 那是逐枚那一版并发算 N 串口令的那一次 await；
     v2 只算一串，那一处换成 `await buildProofStringV2(...)`，于是 indexOf 回 -1，
     读数「await=-1」看着像整个等待点消失了。这里把模式改成「renderProof 里第一个真 await」，
     并且不许再用 `\bawait\b` 那种一抓就中的写法：函数里两处中文注释（「不等下面 await 回来换串」
     「来源在 await 期间动过」）都先于真正的续点出现，用它量出来的顺序是假的。
     判据本身一条都不放宽 —— 「派生值必须绑死来源输入、来源一换那一行当场不许再贴」是安全性质：
     屏幕上挂着一串属于上一个集合的口令，用户抄进签名，烧的是一次签名修改机会加一格限流。
     后半段换成 v2 的那一份身份：data-src 记的是「整套的规范串 + 那枚随机段」，
     形状算不出规范串时（同一个 id 出现两次）记的是那个不可能等于任何合法来源的哨兵值 ——
     于是那一行一定被抹掉，屏幕上不会留一串属于别的集合的口令。这条比 v1 更硬，不是更松。 */
  const killAt = renderProofSrc.indexOf("killStaleProofRows();");
  const killAwait = renderProofSrc.search(/\bawait\s+[A-Za-z_$(]/);
  check(
    "口令行按 data-src 记住自己是按哪一套算的，集合或随机段一换当场抹掉那一行（清行排在第一个真 await 之前）",
    killAt !== -1 &&
      killAwait !== -1 &&
      killAt < killAwait &&
      /row\.dataset\.src = text \? setFingerprint\(set\.items, state\.nonce\)/.test(appSrc) &&
      /function setFingerprint\(items, nonce\)[\s\S]{0,300}?return proofSrc\(canonicalProofSet\(items\), nonce\)/.test(appSrc) &&
      /if \(String\(row\.dataset\.src \|\| ""\) !== src\) row\.remove\(\);/.test(appSrc) &&
      /set\.incomplete\.length \? "[^"]*invalid[^"]*" : setFingerprint\(set\.items, state\.nonce\)/.test(appSrc) &&
      /return "[^"]*invalid[^"]*";/.test(appSrc.slice(appSrc.indexOf("function setFingerprint"), appSrc.indexOf("function killStaleProofRows"))),
    `清行=${killAt} / 第一个真 await=${killAwait} / 记身份=${/row\.dataset\.src = text \? setFingerprint/.test(appSrc)}`
  );
  check(
    "后台那一枚被 /check 判成 recorded 时，它的口令行同样当场消失（setCheck 不加分支就重画列表）",
    /function setCheck\(card, status, key, why\)[\s\S]{0,700}?\n\s*renderProof\(\);/.test(appSrc)
  );

  // 两枚之间不许互相串数据：切卡要先写回旧卡、再装新卡。
  const selectBody = appSrc.slice(
    appSrc.indexOf("function selectCardNow(key)"),
    appSrc.indexOf("\n}", appSrc.indexOf("function selectCardNow(key)"))
  );
  check(
    "点队列切卡：先 commitView() 写回正在编辑的那一枚，再 applyView 装新的（用户已输入的内容不许丢）",
    /commitView\(\);/.test(selectBody) && /applyView\(card\);/.test(selectBody) && /state\.active = /.test(selectBody)
  );
  const dropBody = appSrc.slice(
    appSrc.indexOf("function dropCard(card)"),
    appSrc.indexOf("\n}", appSrc.indexOf("function dropCard(card)"))
  );
  check(
    "移除当前那枚时不许 commitView —— 视图正戴在被删的卡上，写一次就是把它的包塞给下一枚",
    /state\.active !== card\.key/.test(dropBody) && !/commitView\(\)/.test(dropBody)
  );

  /* 旧断言钉的是 v1 那本容量账：一串 15 字符、签名 60 字符、一次大约放 3 条、超过就改几次签名。
     §15 第 4 条把前缀从 8 位扩到 12 位、一串覆盖整套之后，那三句全部作废 —— 界面继续说它
     就是在骗已经不需要改 N 次签名的人。「一次大约放 3 条」这一句尤其要死：它是 v1 多模块投稿
     「结构上崩掉」的那个读数，留着就是让投稿人以为 4 枚要分两次投。
     等价断言按新契约写成两句：那一格说的是 19 个字符 / 覆盖这一整套 / 签名上限实测 60 /
     只改一次签名；而那本旧账不许再出现在**画到屏幕上的那一句**里（源码注释里引用它是为说明
     为什么作废，屏幕上的话才是用户照做的依据 —— 所以切片切在 cap.textContent 那一段）。
     「恒 19、与枚数无关」不是靠这句文案自证的，它由上面那组 v2 黄金值真算过 1..8 枚。 */
  const paintBody = appSrc.slice(
    appSrc.indexOf("function paintProofs("),
    appSrc.indexOf("\n}", appSrc.indexOf("function paintProofs("))
  );
  const capPaint = paintBody.slice(paintBody.indexOf("cap.textContent ="), paintBody.indexOf("box.hidden = false;"));
  check(
    "口令那一格说清容量（v2）：一串 19 个字符、覆盖本次这一整套、签名上限实测 60 个字符、只改一次签名",
    capPaint.includes("cap.textContent =") &&
      /\|\| 19\} 个字符/.test(capPaint) &&
      /覆盖本次这一整套（\$\{set\.targets\.length\} 枚）/.test(capPaint) &&
      /酷安签名上限实测 60 个字符/.test(capPaint) &&
      /只改一次签名、一次提交整套/.test(capPaint) &&
      /增删任一枚/.test(capPaint) &&
      !/一次大约放 3 条|改一次投一枚|15 个字符/.test(capPaint),
    capPaint.slice(0, 100)
  );
  // 两条边界不许藏：一条写在代码注释里，一条写在界面小字里。
  check(
    "边界的两条都写着：代码注释有 pending/ 那一条（要后端加一档状态，本轮不做）",
    /pending\//.test(appSrc) && /要拦那一档得后端加一档状态/.test(appSrc)
  );
  check(
    "边界的两条也写在界面小字里：索引不带酷安 UID（分不清谁投的）+ 没合进索引的查不到",
    /索引里不带酷安 UID/.test(appSrc) &&
      /已经上传但还没合进索引的那些今天查不到/.test(appSrc) &&
      /queue-note/.test(appSrc) &&
      /id="queue-note"/.test(formHtml)
  );
  check(
    "限流的格数与上限字节都不在前端抄第二份：app.js 里不许出现「每小时几格」这种数",
    !/每小时\s*\d|限流\s*\d|\d+\s*格/.test(appSrc) && /fetchServiceLimits\(\)/.test(appSrc)
  );
  /* §17.6 末句把这条写成了硬规矩：**三个**上限一律从 `GET ${API_BASE}/` 取，不在 config.js 抄第二份
     （单枚 maxBytes、整套 maxTotalBytes、枚数 maxModules —— 「8MB / 2MB」那次漂移就是这么来的）。
     批量这一头新增的两个数最容易再漂一次，因为前端要拿它们判「这一套发得出去吗」，
     而猜出来的那个数在页面上与真上限长得一模一样。所以钉三件事：
     ① api.js 只从那次 GET 的 JSON 里取这三个键，取不到就是 null（不是 0、不是猜的数）；
     ② config.js 里连「兜底值」都不许留（本轮已把 MAX_UPLOAD_BYTES 整条删掉，反向钉一次不许回来）；
     ③ app.js 那两格超限判据读的是 state.limits，而不是任何写死的数字。 */
  check(
    "三个上限都只从 GET / 取（maxBytes / maxTotalBytes / maxModules），config.js 里一个数字都不留",
    /export async function fetchServiceLimits\(\)/.test(apiSrc) &&
      /fetch\(url\("\/"\), \{ method: "GET"/.test(apiSrc) &&
      /maxBytes: pick\("maxBytes"\)/.test(apiSrc) &&
      /maxTotalBytes: pick\("maxTotalBytes"\)/.test(apiSrc) &&
      /maxModules: pick\("maxModules"\)/.test(apiSrc) &&
      /return Number\.isFinite\(n\) && n > 0 \? Math\.floor\(n\) : null;/.test(apiSrc) &&
      !/MAX_UPLOAD_BYTES/.test(configSrc) &&
      !/1024 \* 1024/.test(configSrc) &&
      /const max = state\.limits\.maxModules;/.test(appSrc) &&
      /const max = state\.limits\.maxTotalBytes;/.test(appSrc) &&
      /max !== null && n > max \? max : null/.test(appSrc) &&
      !/8 \* 1024 \* 1024|64 \* MB/.test(appSrc),
    `config 里还有 1024 \\* 1024 吗=${/1024 \* 1024/.test(configSrc)} app 里 maxModules 读数=${/const max = state\.limits\.maxModules;/.test(appSrc)}`
  );
  /* 旧断言（v1）说的是「没有『本次投稿已提交』这种整体结论，按枚报」——那时 N 枚是 N 个请求、
     每一枚有自己的成败，一个整体结论必然是假话。§17.4 把语义拍成全有全无、§17.5 把应答拍成
     `{ ok, pr, modules:[{id,versionCode,sha256,assetName}] }` ⇒ 现在**确实有**一个整体结论
     （这一整套受理了 / 整单拒了），而它必须带得起逐枚明细。所以这条按 §17.5 反过来钉三头：
     一个结论说得出是整套的（一个 PR），明细说得出每一枚落成了什么、且那份 sha256 是服务端实算的
     （§16 第 3 句：公开记录只落实算），失败那一格说得出「要么一起上线要么一起还留在你手上」。
     「失败只算在这一枚上」这句旧话反过来钉一次不许回来：全有全无之下它会把零写入说成
     「别的枚已经上了」，那是另一种假话。原始目的没动 —— 界面上的结论与网络上真发生的事说同一件事。 */
  check(
    "整套的诚实说法（§17.4 / §17.5）：一个结论说整套 + 逐枚报明细（落盘 sha256 是服务端实算那份），不许出现「一半传上了」那种状态",
    !/本次投稿已提交|已经全部提交完成/.test(appSrc) &&
      !/失败只算在这一枚上/.test(appSrc) &&
      /const \{ pr, modules \} = await submitContribution\(payload/.test(appSrc) &&
      /枚已受理，一个 PR 已开/.test(appSrc) &&
      /这一次落盘的 \$\{res\.modules\.length\} 枚/.test(appSrc) &&
      /服务端实算 sha256/.test(appSrc) &&
      /语义全有全无/.test(appSrc) &&
      /整单拒、一个 GitHub 写入都没发生/.test(appSrc) &&
      /页面上不会出现「一半传上了」那种状态/.test(appSrc),
    `逐枚明细=${/这一次落盘的/.test(appSrc)} 全有全无那一句=${/语义全有全无/.test(appSrc)}`
  );

  // 单枚路径的体验不能被这套队列弄啰嗦。
  // 单枚路径的体验不能被这套队列弄啰嗦。
  check(
    "解析是串行的（一批一枚一枚解），中途点卡只记下来不抢租约",
    /for \(const card of fresh\)/.test(appSrc) &&
      /state\.parsing = true;/.test(appSrc) &&
      /if \(state\.parsing\) \{\s*\n\s*state\.pendingSwitch = key;/.test(appSrc)
  );
  check(
    "单枚不出现「本次要上传 N 枚」这种噪音：队列那一行只在 cards.length > 1 时进清单",
    /if \(state\.cards\.length > 1\) \{[\s\S]{0,260}?队列里本次要上传 \$\{n\} 枚/.test(gateBody)
  );
  check(
    "只有一枚时队列条退化成一行：安静档由 cards.length<=1 且没有摘出去的枚决定，标题与边界小字一起收（CSS 也在那一档）",
    /const quiet = state\.cards\.length <= 1 && !recorded\.length && !state\.skippedFiles\.length;/.test(readoutBody) &&
      /bar\.dataset\.quiet = quiet \? "1" : "0";/.test(readoutBody) &&
      /\.queue\[data-quiet="1"\] \.queue__hd,\s*\n\.queue\[data-quiet="1"\] \.queue__note \{\s*\n\s*display: none;/.test(panelCss)
  );
  const singleProof = /nonceText = state\.cards\.length > 1/.test(gateBody);
  check(
    "只有一枚时口令那句仍是原来那一句（「上传口令已生成（填进酷安签名）」原样留着）",
    singleProof && gateBody.includes('"上传口令已生成（填进酷安签名）"'),
    "单枚的口令文案被改写了"
  );
  check(
    "文件选择确实开了多选，拖拽也按 FileList 走（不是只取 files[0]）",
    /id="file"[^>]*multiple/.test(formHtml) &&
      /Array\.from\(input\.files \|\| \[\]\)/.test(appSrc) &&
      /Array\.from\(e\.dataTransfer\.files\)/.test(appSrc)
  );
  check(
    "口令那一格改成列表了，但旧的单串结构没留第二份：#proof-text / #proof-copy 都已不存在",
    formHtml.includes('id="proof-list"') && !formHtml.includes('id="proof-text"') && !formHtml.includes('id="proof-copy"')
  );
  check(
    "示例与占位里不许出现真实酷安 UID 或真实 handle：新增的 placeholder 全是文字规则（钉的是纯数字占位这条老规矩）",
    !/placeholder="\d{4,}"/.test(formHtml)
  );
  check(
    "队列条窄屏有自己那一档（四列在 360px 会把 id 压断字），且极窄档登记在断点地图里",
    /\.qrow__pick \{\s*\n\s*grid-template-columns: minmax\(0, 1fr\) auto;/.test(panelCss) &&
      /队列行折两行/.test(panelCss)
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
      // 这个数要等于 else 分支里 check() 的**调用点总数**，不许沿用旧值：整组跳过时报「跳了 4 条」
      // 而实际有 19 条判据没跑，就是把「这台机器没验到」说得比真实情况更轻。
      // 口径与复算：`grep -c "check(" ` 数这个块，或把整个仓拷到没有同级 contrib 的目录里跑一遍看总数。
      // 13 = 原来那 11 条 + §17.6 的三个上限 + §17.4 的错误码配对（本轮批量契约加的两条）。
      skip("后端源码那组跨仓库契约校验", msg, 13);
    }
  } else {
    console.log(`  后端契约另一端：${workerPath}`);
    const worker = readFileSync(workerPath, "utf8");
    check("后端确实读 turnstile 这个字段名", /fields\["?'?turnstile'?\"?\]/.test(worker) || /fields\['turnstile'\]/.test(worker));
    check("后端确实读 coolapkUid 并写进 pending JSON", /fields\.coolapkUid/.test(worker) && /coolapkUid:/.test(worker));
    check("后端自报 maxBytes 给前端", /maxBytes:\s*MAX_TOTAL_BYTES/.test(worker));
    /* §17.6 把批量那一头新增的两个数也放进了同一个应答，并且写死「三个上限一律从这里取，
       不在 config.js 抄第二份」。前端这一侧已经改对了（见上面那条「三个上限都只从 GET / 取」），
       少的是另一端：后端把那个键删掉或改名，前端只会安静地读到 null，于是「这套超了没有」
       这一格从「按后端真值拦」退化成「不拦」—— 页面上看不出任何异常。
       这里只钉键名在不在 GET / 那一段里，不钉它等的是哪个常量：后端此刻还在改，
       把值名钉进来得到的只会是一次假红（假红与真红混在一起，下一轮就没人信这条了）。 */
    const capability = worker.slice(
      worker.indexOf("service: 'sukisu-module-submit'"),
      worker.indexOf("mirrorMaxAgeSeconds")
    );
    check(
      "后端在 GET / 上把三个上限都自报了（maxBytes=单枚 / maxModules=枚数 / maxTotalBytes=整套，§17.6）",
      /\bmaxBytes:/.test(capability) && /\bmaxModules:/.test(capability) && /\bmaxTotalBytes:/.test(capability) &&
        /'POST \/check'/.test(capability),
      `那一段里的键=${(capability.match(/\b(maxBytes|maxModules|maxTotalBytes):/g) || []).join(",") || "(一个都没找到)"}`
    );
    /* §17.7 点名的那一对：「后端新增一个 code」与「前端刮码表加一项」必须同轮，
       否则后端已经回 batch_incomplete，而页面还在用一句通用文案 ——「你的包不对」与
       「我们这边坏了」混成同一句，这两种失败要用户做的事正好相反（改包 vs 等着）。
       判据方向：后端能回的每一个码前端都必须有人话条目；前端多几条（先写文案后等码到达）不算坏。 */
    const errTable = apiSrc.slice(
      apiSrc.indexOf("export const SUBMIT_ERROR_TEXT"),
      apiSrc.indexOf("\n};", apiSrc.indexOf("export const SUBMIT_ERROR_TEXT"))
    );
    const backCodes = [...new Set([...worker.matchAll(/code:\s*["']([a-z0-9_]+)["']/g)].map((m) => m[1]))];
    const frontCodes = [...new Set([...errTable.matchAll(/^ {2}([a-z_][a-z0-9_]*): \{/gm)].map((m) => m[1]))];
    const unmapped = backCodes.filter((c) => !frontCodes.includes(c));
    check(
      "§17.4 错误码两端配对：后端能回的每一个 code 在 api.js 那张表里都有人话条目与 owner",
      unmapped.length === 0 && backCodes.length >= 8,
      `后端没被映射的码=${unmapped.join(",") || "无"}；后端码=${backCodes.join(",")}`
    );
    check("后端只信 cf-connecting-ip（不再信任可伪造的 x-forwarded-for）", !/headers\.get\(["']x-forwarded-for["']\)/i.test(worker));
    /* 站内语域（2026-10-21 owner 拍「投稿」全站换「上传」）：后端回给人的句子是页面**原样显示**的，
       它一处留着旧词，整页就同时有两种说法，而用户分不清哪句是自己该改的。
       扫的是服务端源码里「会进应答字符串」的那部分，三样刻意排除：注释（不显示给人）、
       日志（运维看的）、以及 PR 正文与标题那一份 git 侧文案（它由审核端的词表另外钉着，
       改它要连 GOVERNANCE 与 audit 那侧一起动，不在这条规矩里）。 */
    const GIT_SIDE = /prBody|body: `-|'### 模块投稿'|投稿者：|首次投稿|一次投稿一套|title: `|`投稿：|zip 存放区|console\.(warn|error|log|info)/;
    const staleRegister = worker
      .split(/\r?\n/)
      .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
      .map((l) => l.split("//")[0])
      .filter((l) => l.includes("投稿"))
      .filter((l) => !GIT_SIDE.test(l));
    check(
      "后端回给人的句子不许再出现「投稿」：站内语域统一到上传（注释/日志/PR 正文那三份不在这一格）",
      staleRegister.length === 0,
      `还在用旧词的行=${staleRegister.map((l) => l.trim().slice(0, 90)).join(" | ") || "无"}`
    );
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
      // 钉在**同一个构造点**上，不是「全文件里找得到 502、找得到 no-store」。
      // 全文件口径会被两处无关文本喂绿：注释里出现 `status: 502`、或把 no-store 从错误应答上摘掉
      // 只挂到 200 那一支 —— 两种都实测过，钉子照样绿，那就是假钉子。
      // 这一格真正守的是「一次都没成功过时不能发 200」；发旧副本那一条本来就是 200 + 旧正文（故意的，
      // 由 `x-mirror: stale` + `max-age=5, must-revalidate` 那条规则管），不在这句断言的范围里。
      /error: upstreamNotFound \? 'not_found' : 'upstream_unavailable' \}\), \{\s*status: upstreamNotFound \? 404 : 502,[\s\S]{0,200}'cache-control': 'no-store'/.test(
        worker
      ),
    );
    // 网关的 include 名单是这些镜像路径的**隐形闸**：Worker 有这条路而网关没放行时，Pages 自己回一个
    // 空正文 404（连 `x-mirror` 都没有），看着像「源站没这个文件」，其实是请求根本没到 Worker。
    // 2026-10-17 上线 `/evidence/*` 那天撞的就是这一格，而当时全套测试没有一个字提到这个文件。
    // workerPath 落在 `worker/src/`，网关在它的**上一级**目录里（`worker/gateway/`）——
    // 少算一层的话这里会红在「找不到文件」，而那是本钉子的假红，不是被测面的问题。
    const gatewayPath = resolve(dirname(workerPath), "..", "gateway", "public", "_routes.json");
    if (!existsSync(gatewayPath)) {
      check("网关 _routes.json 必须读得到（Worker 每条镜像路的隐形闸）", false, `找不到 ${gatewayPath}`);
    } else {
      const include = JSON.parse(readFileSync(gatewayPath, "utf8")).include || [];
      const missing = ["index.json", "dispositions.json", "evidence/*"].filter(
        (p) => !include.includes(`/${p}`)
      );
      // 两个方向都要对：网关少一条 = 线上静默 404；Worker 少一条而网关放着 = 放行一条不存在的路，
      // 白名单在这里没有意义，所以只比"名字都在两边"，不比顺序、不比别的路径。
      const workerHas = ["index.json", "dispositions.json", "evidence/*"].every(
        (p) =>
          p === "evidence/*"
            ? /MIRROR_EVIDENCE_RE/.test(worker) && /evidenceRawUrl/.test(worker)
            : new RegExp(`'\\/${p.replace(".", "\\.")}':`).test(worker)
      );
      check(
        "网关 include 与 Worker 镜像路两侧对齐（少一条就是一次「测试全绿而线上 404」）",
        missing.length === 0 && workerHas,
        `网关缺：${missing.join(", ") || "无"}；Worker 侧三条齐全=${workerHas}`
      );
      /* 同一族的另一根，方向不同：这次比的是 **Worker 自报的那张端点表**（GET / 里的 endpoints）。
         2026-10-21 加 POST /report 就撞过一次——Worker 路由在、432 条用例全绿，而浏览器那一侧
         打进来拿到的是 Pages 的静态 404，因为用户走的入口从来不是 Worker 本身，是这层网关。
         `<sha256>.json` 那种占位段折成 `*` 再比：include 里写的就是通配形状。
         `advertised.length >= 8` 是正例控制：那张表读不到时必须红，不许空对空地绿。 */
      const epBlock = /endpoints: \[([^\]]*)\]/.exec(worker)?.[1] ?? "";
      const advertised = [...epBlock.matchAll(/'(?:[A-Z]+ )?(\/[^']+)'/g)].map((m) => m[1].replace(/<[^>]+>/g, "*"));
      // include 里的 `/x/*` 按 Pages 自己的语义匹配「该前缀下的任何一条」，不是字面量相等：
      // 自报表里那一条写的是 `/evidence/<sha256>.json`，拿字符串比必然假红。
      const covered = (p) => include.some((inc) => (inc.endsWith("*") ? p.startsWith(inc.slice(0, -1)) : p === inc));
      const gwMissing = advertised.filter((p) => !covered(p));
      check(
        "Worker 自报的每一个端点都在网关 include 里（新端点漏一条就是一次「测试全绿而入口 404」）",
        advertised.length >= 8 && gwMissing.length === 0,
        `自报表=${JSON.stringify(advertised)}；网关缺=${gwMissing.join(", ") || "无"}`
      );
    }
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
      // 这组的条数跟着 else 分支里 check() 的调用点走：v1 那 4 条（前缀同值 / 后端命中黄金值 /
      // 承诺集合 / nonce 字母表）+ v2 新加的 3 条（两份实现逐条同值 / 恒 19 后端那份也算得出 /
      // 前缀长度常量同值）= 7。proof_used 那一条有自己的 skip 分支，不计在这里。
      skip("前后端口令算法同值那组跨仓库校验", msg, 7);
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
      else skip("前后端口令算法同值那组跨仓库校验", msg, 7);
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
      /* v2 那一套同样两头对跑，一条都不许只靠 grep 源码：批量投稿的口令前缀绑的是整套集合，
         两份实现漂一点的后果比 v1 更坏 —— v1 漂了是「这一枚的口令判成假的」，
         v2 漂了是「整套 N 枚一起被判成不是你」，而签名里那一串看起来完全正常。
         这里跑三种：黄金值（竖着比后端自己命中内嵌表）、乱序与同 id 再按 sha 排（横着比两份
         canonicalProofSet）、1..8 枚的串长（比的是「恒 19」这条这次换代的全部理由）。
         ⚠ 后端此刻还在动，所以这一组里任何一条红了先分清是「另一端还没修完」还是「这一端漂了」，
         别拿改前端去凑后端。 */
      const v2Drift = [];
      const v2WorkerWrong = [];
      for (const g of PROOF_V2_GOLDENS) {
        const web = await proofPrefixV2(g.items);
        const back = await wp.proofPrefixV2(g.items);
        if (web !== back) v2Drift.push(`${g.name}: web=${web} worker=${back}`);
        if (web !== g.prefix) v2Drift.push(`${g.name}: web=${web} 黄金值=${g.prefix}`);
        if (back !== g.prefix) v2WorkerWrong.push(`${g.name}: worker=${back} 黄金值=${g.prefix}`);
        const canonWeb = canonicalProofSet(g.items);
        const canonBack = wp.canonicalProofSet(g.items);
        if (canonWeb !== canonBack) v2Drift.push(`${g.name}: 规范串 web≠worker`);
        if (canonWeb !== canonOracle(g.items)) v2Drift.push(`${g.name}: 规范串与 node:crypto 复算不一致`);
      }
      const shuffled = [
        { id: "bbb", zipSha: ZIP_SHA_B },
        { id: "aaa", zipSha: ZIP_SHA_A },
      ];
      const ordered = [
        { id: "aaa", zipSha: ZIP_SHA_A },
        { id: "bbb", zipSha: ZIP_SHA_B },
      ];
      if ((await wp.canonicalProofSet(shuffled)) !== (await wp.canonicalProofSet(ordered)))
        v2Drift.push("worker 的规范串仍然受调用方给的次序影响");
      if ((await canonicalProofSet(shuffled)) !== (await canonicalProofSet(ordered)))
        v2Drift.push("web 的规范串仍然受调用方给的次序影响");
      const v2BackLens = [];
      for (let n = 1; n <= 8; n++) {
        const items = Array.from({ length: n }, (_, i) => ({ id: `m${i}`, zipSha: ZIP_SHA_A }));
        v2BackLens.push((await wp.buildProofStringV2(items, "ab12cd")).length);
        const w = await buildProofStringV2(items, "ab12cd");
        const b = await wp.buildProofStringV2(items, "ab12cd");
        if (w !== b) v2Drift.push(`${n} 枚: 整串 web=${w} worker=${b}`);
      }
      check(
        "v2 两份实现逐条同值 + 两边都命中内嵌黄金值（规范串、次序无关、少一枚换一枚都是另一串）",
        typeof wp.proofPrefixV2 === "function" && typeof wp.canonicalProofSet === "function" && v2Drift.length === 0,
        v2Drift.join(" | ") || "后端缺 proofPrefixV2 / canonicalProofSet 导出"
      );
      check(
        "v2 的「恒 19 字符、与枚数无关」是后端那份也算出来的（1..8 枚各跑一遍，不是文案说的）",
        new Set(v2BackLens).size === 1 && v2BackLens.every((l) => l === 19),
        `后端各枚数长度=${v2BackLens.join(",")}`
      );
      check(
        "两边认的前缀长度常量同值（12）：把它改回 8 位，前端那一串与 Worker 重算的那一串就永远对不上",
        wp.PROOF_PREFIX_LEN_V2 === PROOF_PREFIX_LEN_V2 && wp.PROOF_PREFIX_LEN_V2 === 12,
        `worker=${wp.PROOF_PREFIX_LEN_V2} web=${PROOF_PREFIX_LEN_V2}`
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
      /* §17.4 码表的**反方向**：前端那张「说人话」表里不许留着后端不会回的码。
         正方向（后端每个 code 都得有人话条目与 owner）上面那一发已经钉了，两条尺子各管一边 ——
         合成一条的话一次变异会报两条同因的红，下一次没人分得清是哪一格真的坏了。
         为什么这一向也要钉：后端加过码又改掉/删掉时，前端那条 owner/文案不会报错，只是**永远读不到**。
         那张表看起来八面玲珑，其实有一格是死的 —— 「看起来有覆盖」比明着的缺口更贵。
         码的集合来自刮后端源码，不来自抄文档：抄来的那份一定漂（前端 8MB / 后端 2MB 就是同一类）。 */
      const apiSrcCodes = readFileSync(
        resolve(dirname(fileURLToPath(import.meta.url)), "../public/scripts/api.js"), "utf8"
      );
      const errTextTbl = /export const SUBMIT_ERROR_TEXT = \{([\s\S]*?)\n\};/.exec(apiSrcCodes);
      const frontCodes = errTextTbl
        ? [...new Set([...errTextTbl[1].matchAll(/^ {2}([a-z_]+): \{/gm)].map((m) => m[1]))].sort()
        : [];
      const backCodes = [...new Set(workerCodes)];
      const deadFrontCodes = frontCodes.filter((c) => !backCodes.includes(c));
      check(
        "§17.4 码表反方向：前端那张表里没有后端不会回的死角（后端源码一个 code 都没刮到时如实 skip）",
        backCodes.length > 0 && Boolean(errTextTbl) && frontCodes.length > 0 && deadFrontCodes.length === 0,
        `前端有、后端不会回的码=${deadFrontCodes.join(",") || "无"} / 两边条数=${backCodes.length}/${frontCodes.length}`
      );
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
    // 同上：这一组实际有 19 个 check() 调用点，旧值 4 是好几轮加格之后没跟着改的。
    else skip("处置台账词汇与指针那组跨仓库校验", msg, 19);
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

        // 上面那条只证明「函数返回空串」。真正要守的是**调用点不发请求** —— 拿空串去 `fetch("")`
        // 会打到当前页面所在的主机，那种形状下台账页就在替一条它并不认识的证据发跨站请求。
        // 所以这里换成假 fetch，直接数它被调用了几次、打到哪儿。
        const calls = [];
        const realFetch = globalThis.fetch;
        globalThis.fetch = async (u) => {
          calls.push(String(typeof u === "string" ? u : u.url));
          return new Response('{"schema":"sukisu-evidence-v1"}', { status: 200, headers: { "content-type": "application/json" } });
        };
        try {
          const miss = await fetchEvidence("https://evil.tld/evidence/" + "a".repeat(64) + ".json");
          const miss2 = await fetchEvidence("evidence/" + "b".repeat(63) + ".json");
          const good = "evidence/" + "c".repeat(64) + ".json";
          const hit = await fetchEvidence(good);
          check(
            "取证据：形状不对一次请求都不发；形状对才打到推导出来的那个地址",
            calls.length === 1 &&
              miss.ok === false && miss2.ok === false && hit.ok === true &&
              calls[0] === `https://api.example.dev/${good}`,
            `calls=${JSON.stringify(calls)} miss=${String(miss.reason).slice(0, 24)} miss2=${String(miss2.reason).slice(0, 24)}`
          );
          await fetchEvidence(good);
          check("同一枚证据第二次取用缓存，不再打网络", calls.length === 1, `calls=${calls.length}`);
        } finally {
          globalThis.fetch = realFetch;
        }
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
