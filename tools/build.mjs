// public/ 就是产物，部署前只需要把它原样复制进 dist/。
// 之所以要 dist/：静态托管商（含 Qoder Sites）要求指定一个输出目录，
// 不接受项目根，避免把 tools/、README 这些源码杂物一起发布。
import { cp, rm, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FROM = join(ROOT, "public");
const TO = join(ROOT, "dist");

await rm(TO, { recursive: true, force: true });
await mkdir(TO, { recursive: true });
await cp(FROM, TO, { recursive: true });
console.log("dist/ 已就绪");
