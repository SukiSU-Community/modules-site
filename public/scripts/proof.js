// 所有权口令 —— 与 worker/src/proof.ts 是同一套算法的第二份实现。
// 两边各写一份不是疏忽：前端要拿它生成展示串，Worker 要拿它复核，而 Worker 的那份不能
// 被浏览器读到。哪一边改了都会让另一边对不上，所以 selftest 有一条跨仓库校验专门盯着它。
//
// 口令绑的是「模块 id + 整包 sha256」，不只绑模块 id（设计文档 §14.1）。理由只有一句：
// 这条信道的性质是**先公开、后消费** —— 投稿人必须先把这串填进一个公开可读的字段（酷安签名），
// 之后才在浏览器里提交，中间那段时间里任何人都能读到它。只绑 id 时，读到的人拿自己的恶意包
// 加同一个模块 id 就能抢投，被归档的却是受害者的身份；绑了包体之后，复用这串口令就必须提交
// 受害者那个一模一样的文件 —— 那已经不是攻击。
//
// 只缓存两个来源（state.nonce 与 state.zipSha），口令文本每次渲染都现算 ——
// 于是结构上不可能出现「id 改了 / 包换了，展示的口令还是旧的」这种派生值和来源脱钩。
const enc = new TextEncoder();
const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

function toHex(digest) {
  let out = "";
  for (const b of new Uint8Array(digest)) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * 整包 sha256：对用户选中的那个文件的**全部字节**做 SHA-256，出 64 位小写十六进制。
 * 与 Worker 的 `contentId()` 同口径（⑤-c 就是拿这两个值对的），所以这里不另发明一份算法：
 * 文本版 `sha256Hex` 就是它的一层 UTF-8 编码，两条路径共用同一个摘要与同一套补零。
 */
export async function sha256HexBytes(bytes) {
  return toHex(await crypto.subtle.digest("SHA-256", bytes));
}

export async function sha256Hex(text) {
  return sha256HexBytes(enc.encode(text));
}

export async function proofPrefixFor(id, zipSha) {
  return (await sha256Hex(`${id}:${zipSha}`)).slice(0, 8);
}

export async function buildProofString(id, zipSha, nonce) {
  return `${await proofPrefixFor(id, zipSha)}-${nonce}`;
}

export function makeNonce() {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += ALPHABET[b % ALPHABET.length];
  return out;
}
