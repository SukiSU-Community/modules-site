// 所有权口令 —— 与 worker/src/proof.ts 是同一套算法的第二份实现。
// 两边各写一份不是疏忽：前端要拿它生成展示串，Worker 要拿它复核，而 Worker 的那份不能
// 被浏览器读到。哪一边改了都会让另一边对不上，所以 selftest 有一条跨仓库校验专门盯着它。
//
// 口令绑的是「模块 id + 整包 sha256」，不只绑模块 id（设计文档 §14.1）。理由只有一句：
// 这条信道的性质是**先公开、后消费** —— 上传人必须先把这串填进一个公开可读的字段（酷安签名），
// 之后才在浏览器里提交，中间那段时间里任何人都能读到它。只绑 id 时，读到的人拿自己的恶意包
// 加同一个模块 id 就能抢投，被归档的却是受害者的身份；绑了包体之后，复用这串口令就必须提交
// 受害者那个一模一样的文件 —— 那已经不是攻击。
//
// 只缓存来源、不缓存派生串，口令文本每次渲染都现算 ——
// 于是结构上不可能出现「id 改了 / 包换了 / 这套少了一枚，展示的口令还是旧的」这种派生值和来源脱钩。
// v1 的三个来源是 (id, zipSha, nonce)；v2 的来源是「这一整套的 (id, zipSha) 集合」+ 一枚 nonce。
// 缓存派生值迟早和来源脱钩，而换包不换口令正是这条闸要封死的那件事。
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

/* --------------------------------------------------------------- 口令 v2
   一串覆盖「这一次上传的整套模块」，长度恒 19 字符、与枚数无关（设计文档 §15 / §17）。

   为什么要换：v1 的前缀绑「(模块 id, 整包 sha256) 这一对」⇒ N 枚就是 N 串，而酷安个性签名上限
   实测 60 字符、一串 15 字符 ⇒ 一次只放得下 3-4 串，多模块上传不是麻烦而是放不下。
   安全前提一个字没改：这条信道是「先公开、后消费」，v2 只是把绑的对象从"一对"换成"这一整套"——
   复用同一句理由，复用这串口令就必须提交同一整套（同 id 同字节），少一枚、多一枚、换一枚都算出
   另一个前缀，签名里那串就对不上。

   v1 这三行**不许删**：旧版 App 还在发 v1，后端 `matchProofInBio` 是先试 v1 再试 v2
   （换代次序：Worker 先读 v1∪v2 并部署 ⇒ 前端切 v2 ⇒ App 择期）。selftest 那份跨仓库
   parity 检查拿的就是这两个函数与 worker/src/proof.ts 逐条对跑。

   下面三个函数与 worker/src/proof.ts 的同名导出**逐字同算法**（排序键、分隔符、那三条拒绝
   一模一样）。两边的对跑由 tools/selftest.mjs 钉住 —— 这里漂了不会报错，只会把每个真口令
   判成假的，而界面上一切正常。 */

export const PROOF_PREFIX_LEN_V2 = 12;

/** 一套里的一枚：模块 id 与整包 sha256（64 位小写十六进制）。 */

const cmpStr = (x, y) => (x < y ? -1 : x > y ? 1 : 0);

/**
 * 规范串：按 id 升序（同 id 再按 zipSha 升序）逐枚写 `id:zipSha`，用 `,` 连接。
 *
 * 顺序必须是这套的一部分，不能靠调用方自觉：前端按用户选的次序、Worker 按 multipart 里出现的
 * 次序，两边不同序就会算出两个前缀，而「对不上」在那条闸里读起来跟「你不是本人」一模一样。
 * 那三条拒绝（空集、非 64 位小写十六进制、同 id 重复）都是客户端可控的边界输入，不是内部
 * 不可能状态：放过去就等于把形状问题推到「口令对不上」那一格去。
 */
export function canonicalProofSet(items) {
  const list = [...items];
  if (list.length === 0) throw new Error("口令集合不能为空");
  for (const it of list) {
    if (!it || typeof it.id !== "string" || it.id === "") throw new Error("口令集合里有空模块 id");
    if (typeof it.zipSha !== "string" || !/^[0-9a-f]{64}$/.test(it.zipSha)) {
      throw new Error(`这一枚的整包 sha256 不是 64 位小写十六进制：${it.id}`);
    }
  }
  if (new Set(list.map((i) => i.id)).size !== list.length) throw new Error("同一套里同一个模块 id 出现两次");
  list.sort((a, b) => (a.id === b.id ? cmpStr(a.zipSha, b.zipSha) : cmpStr(a.id, b.id)));
  return list.map((i) => `${i.id}:${i.zipSha}`).join(",");
}

export async function proofPrefixV2(items) {
  const canon = canonicalProofSet(items);
  return (await sha256Hex(`sukisu-proof-v2:${canon}`)).slice(0, PROOF_PREFIX_LEN_V2);
}

export async function buildProofStringV2(items, nonce) {
  return `${await proofPrefixV2(items)}-${nonce}`;
}

export function makeNonce() {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += ALPHABET[b % ALPHABET.length];
  return out;
}

/* ------------------------------------------- 身份承诺（哈希承诺，设计文档 v2 §1.1）

   身份证明不再借用「包」：本机生成一枚 32 位十六进制的 secret（128 bit，只在本地，
   除了发给 /session/issue 复核之外不写进任何地方），要填进酷安签名的是它的哈希承诺：

     commit = sha256(UTF-8("sukisu-identity-v2:" + secret)) 的前 24 位小写十六进制

   为什么发承诺而不是发 secret 本身：酷安签名是**公开可读**的字段，任何人随时能看到。
   签名里只放 commit，冒充者就得先反推 sha256 的原像（2^128 次），而这种「先公开、后消费」
   的信道里唯一的攻击面就是读到它的人能不能复用 —— 复用需要原像，抄不走。
   服务端因此也不需要记任何状态：它只做「重算一遍 sha256，看前 24 位对不对」。
   与上面的包绑定口令一样，这里只提供纯函数，派生值每次现算、不缓存。 */

export const IDENTITY_COMMIT_LEN = 24;

/** 本机生成一枚 secret：16 字节随机 → 32 位小写十六进制。 */
export function identitySecret() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/** secret → 承诺串（24 位小写十六进制）。形如不合法就抛，绝不返回半截值。
 *  这里**不做**大小写规范化：Worker 侧按 `/^[0-9a-f]{32}$/` 判，前端替它「顺手改成小写」
 *  只会造出两种口径 —— 界面上算得出、发上去却被判 identity_invalid。 */
export async function identityCommitment(secret) {
  const s = typeof secret === "string" ? secret.trim() : "";
  if (!/^[0-9a-f]{32}$/.test(s)) throw new Error("secret 必须是 32 位小写十六进制");
  return (await sha256Hex(`sukisu-identity-v2:${s}`)).slice(0, IDENTITY_COMMIT_LEN);
}
