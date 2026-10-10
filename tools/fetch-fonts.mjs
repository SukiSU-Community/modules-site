// 把 Google Fonts 的 latin 子集下载进 public/fonts/，并生成 fonts.css。
// 站点面向国内玩机社区，fonts.googleapis.com 在大陆不可达，字体必须随站点静态托管，
// 否则整套视觉在手机端直接退化成系统字体。产物已提交进仓库，只在换字体时需要重跑。
// 用法：node tools/fetch-fonts.mjs
import { writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = join(ROOT, "public", "fonts");

// Chrome UA 是关键：否则 Google 返回 ttf 而不是 woff2。
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";

const FAMILIES = [
  { name: "Chakra Petch", weights: [600, 700], slug: "chakrapetch" },
  { name: "IBM Plex Mono", weights: [400, 500, 600], slug: "plexmono" },
];

function latinUrlFrom(css) {
  const latinBlock = css.split("/* latin */")[1];
  if (!latinBlock) throw new Error("响应里没有 latin 子集");
  const match = latinBlock.match(/src:\s*url\(([^)]+)\)/);
  if (!match) throw new Error("latin 子集里没有 src");
  return match[1];
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  const faces = [];

  for (const family of FAMILIES) {
    for (const weight of family.weights) {
      const cssUrl =
        `https://fonts.googleapis.com/css2?family=` +
        encodeURIComponent(family.name) +
        `:wght@${weight}&display=block`;
      const css = await (await fetch(cssUrl, { headers: { "User-Agent": UA } })).text();
      const url = latinUrlFrom(css);
      const file = `${family.slug}-${weight}.woff2`;
      const buf = Buffer.from(await (await fetch(url)).arrayBuffer());
      await writeFile(join(OUT_DIR, file), buf);
      faces.push(
        [
          "@font-face {",
          `  font-family: '${family.name}';`,
          "  font-style: normal;",
          `  font-weight: ${weight};`,
          "  font-display: swap;",
          `  src: url('./${file}') format('woff2');`,
          "}",
        ].join("\n")
      );
      console.log(`${file}  ${(buf.length / 1024).toFixed(1)} KB`);
    }
  }

  await writeFile(join(OUT_DIR, "fonts.css"), faces.join("\n") + "\n");
  console.log("fonts.css 已生成");
}

main().catch((err) => {
  console.error(String(err && err.stack ? err.stack : err));
  process.exitCode = 1;
});
