// public/ 是源码也是产物形状：构建时整套复制进 dist/，再对 JS / CSS 做一次压缩。
// 压缩放在构建期而不是依赖托管商的自动压缩：Pages 不保证开启，且压缩后的体积在本地可核对。
import { cp, rm, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, extname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FROM = join(ROOT, "public");
const TO = join(ROOT, "dist");

await rm(TO, { recursive: true, force: true });
await mkdir(TO, { recursive: true });
await cp(FROM, TO, { recursive: true });

// esbuild 的 transform 只做单文件改写，不打包、不改模块边界：
// import 语句原样保留，浏览器仍然按模块图加载，调试时的文件名也不变。
const { transform } = await import("esbuild");

async function walk(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(full)));
    else out.push(full);
  }
  return out;
}

const report = [];
for (const file of await walk(TO)) {
  const ext = extname(file);
  if (ext !== ".js" && ext !== ".css") continue;
  const source = await readFile(file, "utf8");
  const result = await transform(source, {
    loader: ext === ".js" ? "js" : "css",
    minify: true,
    charset: "utf8",
    legalComments: "none",
    target: ext === ".js" ? "es2020" : "chrome100"
  });
  await writeFile(file, result.code);
  report.push([file.slice(TO.length + 1), source.length, result.code.length]);
}

const saved = report.reduce((n, [, a, b]) => n + a - b, 0);
for (const [name, before, after] of report.sort((a, b) => b[1] - a[1])) {
  console.log(`${name.padEnd(30)} ${String(before).padStart(7)} → ${String(after).padStart(6)}`);
}
console.log(`dist/ 已就绪（压缩 ${report.length} 个文件，省 ${(saved / 1024).toFixed(1)} KB）`);
