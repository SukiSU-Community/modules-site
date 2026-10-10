// zip 解析与 module.prop 预填的自检：手搓真实字节喂给浏览器端的解析代码。
// Node 18+ 也有 DecompressionStream / Blob / Response，所以 public/scripts 里的
// 实现可以原样在这里跑，不需要为测试另写一份。
// 用法：node tools/selftest.mjs
import zlib from "node:zlib";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CONFIG } from "../public/scripts/config.js";
import {
  ZipError,
  canInflateRaw,
  listEntries,
  readEntry,
  inspectEntries,
} from "../public/scripts/zipread.js";
import { parseModuleProp, missingRequired } from "../public/scripts/moduleprop.js";

let pass = 0;
let fail = 0;
function check(name, ok, extra) {
  if (ok) {
    pass++;
    console.log(`  ok   ${name}`);
  } else {
    fail++;
    console.log(`  FAIL ${name}${extra ? " —— " + extra : ""}`);
  }
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

  // API_BASE 未配置时不发任何请求，直接回 off —— 界面据此显示「未经核实」而不是报错卡死
  const off = await lookupCoolapkUser("2781460");
  check("后端未接线时核实返回 off 而不是抛错", off.status === "off", JSON.stringify(off));

  /* ------------------------------------------------ 与后端的字段名/契约对齐
     这一节防的是「两边各自改了常量，直到线上报错才发现」。曾经前端发 turnstile、
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

  // 后端仓库在同一台机器上时，直接把它的源码当契约的另一端来读；不在就跳过。
  // 这不是跨仓库依赖——缺后端时这段自动放行，测试照样绿。
  const here = dirname(fileURLToPath(import.meta.url));
  const workerCandidates = [
    "../../刷机包/contrib/worker/src/index.ts",
    "../contrib/worker/src/index.ts",
  ];
  const workerPath = workerCandidates.map((p) => resolve(here, p)).find((p) => existsSync(p));
  if (!workerPath) {
    console.log("  skip 后端源码不在本机，跳过字段名交叉校验");
  } else {
    const worker = readFileSync(workerPath, "utf8");
    check("后端确实读 turnstile 这个字段名", /fields\["?'?turnstile'?\"?\]/.test(worker) || /fields\['turnstile'\]/.test(worker));
    check("后端确实读 coolapkUid 并写进 pending JSON", /fields\.coolapkUid/.test(worker) && /coolapkUid:/.test(worker));
    check("后端自报 maxBytes 给前端", /maxBytes:\s*MAX_TOTAL_BYTES/.test(worker));
    check("后端只信 cf-connecting-ip（不再信任可伪造的 x-forwarded-for）", !/headers\.get\(["']x-forwarded-for["']\)/i.test(worker));
    check("后端自己校验出处主机名", /coolapk\.com\.evil\.tld|endsWith\(["']\.coolapk\.com["']\)/.test(worker));
  }

  console.log(`\n${fail === 0 ? "全部通过" : "有失败项"}：${pass} passed, ${fail} failed`);
  if (fail) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
