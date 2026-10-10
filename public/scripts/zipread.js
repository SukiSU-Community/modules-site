// 在浏览器里读 zip：解析中央目录，解压单个条目，只用原生能力（DecompressionStream）。
// 为什么要在前端解包：服务端要求「module.prop 必须在 zip 根目录」，且 id / name / version /
// versionCode / author / description 全部来自它。前端先解一次，既能在用户传 8MB 之前
// 就告诉他格式不对，也能把那六个输入框自动填掉。
// 依赖 DecompressionStream('deflate-raw')：Chrome 80+ / Edge 84+ / Firefox 113+ / Safari 16.4+。
// 不支持时不报错中断，只退回「手动填表」，功能不因此消失。

export class ZipError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ZipError";
    this.code = code;
  }
}

const EOCD_SIG = 0x06054b50;
const EOCD64_LOCATOR_SIG = 0x07064b50;
const EOCD64_SIG = 0x06064b50;
const CD_SIG = 0x02014b50;
const MAX_COMMENT = 65535;

export function canInflateRaw() {
  return (
    typeof DecompressionStream !== "undefined" &&
    typeof Response !== "undefined" &&
    typeof Blob !== "undefined"
  );
}

/** 找 EOCD（压缩包结束记录），返回其起始偏移；zip64 时返回真实条目数与目录偏移。 */
function readEocd(view) {
  const size = view.byteLength;
  if (size < 22) throw new ZipError("too-small", "文件太小，不是有效的 zip 包");
  const floor = Math.max(0, size - 22 - MAX_COMMENT);
  let eocd = -1;
  for (let i = size - 22; i >= floor; i--) {
    if (view.getUint32(i, true) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) {
    throw new ZipError("not-zip", "没找到 zip 结束标记：这个文件可能不是 zip，或者已经损坏");
  }

  let total = view.getUint16(eocd + 10, true);
  let cdOffset = view.getUint32(eocd + 16, true);

  // 0xFFFF / 0xFFFFFFFF 是 zip64 的哨兵值，真实数字在 EOCD64 里。
  if (total === 0xffff || cdOffset === 0xffffffff) {
    const locator = eocd - 20;
    if (locator >= 0 && view.getUint32(locator, true) === EOCD64_LOCATOR_SIG) {
      const eocd64 = Number(view.getBigUint64(locator + 8, true));
      if (view.getUint32(eocd64, true) !== EOCD64_SIG) {
        throw new ZipError("zip64", "zip64 记录损坏，前端读不了，请重新打包后再投");
      }
      total = Number(view.getBigUint64(eocd64 + 32, true));
      cdOffset = Number(view.getBigUint64(eocd64 + 48, true));
    }
  }
  return { total, cdOffset };
}

/** 列出所有条目：{ name, method, compSize, uncompSize, dataOffset } */
export function listEntries(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  const { total, cdOffset } = readEocd(view);
  const decoder = new TextDecoder("utf-8");
  const entries = [];
  let p = cdOffset;

  for (let i = 0; i < total; i++) {
    if (p + 46 > view.byteLength) break;
    if (view.getUint32(p, true) !== CD_SIG) break;

    const method = view.getUint16(p + 10, true);
    // 中央目录里 crc 占 16..19，压缩后大小在 20、原始大小在 24（跟本地文件头差 2 字节）
    const compSize = view.getUint32(p + 20, true);
    const uncompSize = view.getUint32(p + 24, true);
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commentLen = view.getUint16(p + 32, true);
    const localOffset = view.getUint32(p + 42, true);
    const name = decoder.decode(new Uint8Array(arrayBuffer, p + 46, nameLen));
    const isDir = name.endsWith("/") || name.endsWith("\\");

    // 数据真正的位置由「本地文件头」决定，它的名字/扩展长度可以和中央目录不同。
    let dataOffset = -1;
    if (!isDir) {
      const sig = view.getUint32(localOffset, true);
      if (sig !== 0x04034b50) throw new ZipError("corrupt", `条目 ${name} 的本地文件头损坏`);
      const lName = view.getUint16(localOffset + 26, true);
      const lExtra = view.getUint16(localOffset + 28, true);
      dataOffset = localOffset + 30 + lName + lExtra;
    }

    entries.push({ name, method, compSize, uncompSize, dataOffset, isDir });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/** 取出一个条目的字节；method 8 走原生 raw-deflate 解压。 */
export async function readEntry(arrayBuffer, entry) {
  if (entry.isDir) return new Uint8Array(0);
  const bytes = new Uint8Array(arrayBuffer, entry.dataOffset, entry.compSize);

  if (entry.method === 0) return bytes; // stored，没压缩，直接给
  if (entry.method !== 8) {
    throw new ZipError(
      "unsupported-method",
      `条目 ${entry.name} 用了前端不支持的压缩算法（method ${entry.method}）`
    );
  }
  if (!canInflateRaw()) {
    throw new ZipError("no-inflate", "这个浏览器不支持 zip 解压，请手动填写模块信息");
  }

  // 注意传视图本身而不是 bytes.buffer：后者是整个 zip 的 ArrayBuffer。
  const stream = new Blob([bytes])
    .stream()
    .pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * 投稿要求的规范形态：根目录直接含 module.prop。
 * 返回 { ok, rootEntry, nestedPaths, entryCount }
 */
export function inspectEntries(entries) {
  const root = entries.find((e) => !e.isDir && e.name === "module.prop");
  // 反斜杠分隔符的包（少数 Windows 打包工具）也要给出提示，尽管它本身同样不合格。
  const nested = entries
    .filter((e) => !e.isDir && /(^|[\\/])module\.prop$/i.test(e.name) && e.name !== "module.prop")
    .map((e) => e.name);
  return {
    ok: Boolean(root),
    rootEntry: root || null,
    nestedPaths: nested,
    entryCount: entries.length,
  };
}
