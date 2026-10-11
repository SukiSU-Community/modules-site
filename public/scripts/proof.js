// 所有权口令 —— 与 worker/src/proof.ts 是同一套算法的第二份实现。
// 两边各写一份不是疏忽：前端要拿它生成展示串，Worker 要拿它复核，而 Worker 的那份不能
// 被浏览器读到。哪一边改了都会让另一边对不上，所以 selftest 有一条跨仓库校验专门盯着它。
//
// 只缓存随机部分（state.nonce），口令文本每次渲染都从「当前的模块 id」重算 ——
// 于是结构上不可能出现「id 改了、展示的口令还是旧的」这种派生值和来源脱钩。
const enc = new TextEncoder();
const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

export async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(text));
  let out = "";
  for (const b of new Uint8Array(buf)) out += b.toString(16).padStart(2, "0");
  return out;
}

export async function proofPrefixForId(id) {
  return (await sha256Hex(id)).slice(0, 8);
}

export async function buildProofString(id, nonce) {
  return `${await proofPrefixForId(id)}-${nonce}`;
}

export function makeNonce() {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += ALPHABET[b % ALPHABET.length];
  return out;
}
