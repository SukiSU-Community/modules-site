// 本地预览服务器：只监听 127.0.0.1，把 public/ 当静态根目录。
// 站点没有构建步骤，这个脚本唯一的额外价值是给出正确的 MIME ——
// .js 必须是 text/javascript，否则浏览器会以 classic script 解析 ES module 而报错。
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, dirname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "public");
const PORT = Number(process.env.PORT || 4321);
const HOST = "127.0.0.1";

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".woff2": "font/woff2",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
};

const server = createServer(async (req, res) => {
  const path = decodeURIComponent((req.url || "/").split("?")[0]);
  const rel = normalize(path === "/" ? "/index.html" : path).replace(/^([/\\])+/, "");
  const file = join(ROOT, rel);

  // 只允许 public/ 以内的路径
  if (file !== ROOT && !file.startsWith(ROOT + sep)) {
    res.writeHead(403).end("forbidden");
    return;
  }
  try {
    const info = await stat(file);
    if (info.isDirectory()) throw new Error("dir");
    const body = await readFile(file);
    res.writeHead(200, {
      "Content-Type": TYPES[extname(file).toLowerCase()] || "application/octet-stream",
      "Cache-Control": "no-store",
    });
    res.end(body);
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }).end("404 not found");
  }
});

server.listen(PORT, HOST, () => {
  console.log(`本地预览：http://${HOST}:${PORT}/`);
});
