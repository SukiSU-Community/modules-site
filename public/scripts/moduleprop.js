// module.prop 解析：形如 key=value，值里可能再次出现 '='（描述里常见），
// 所以只按第一个 '=' 切。兼容 CRLF 与 BOM。
const KEYS = ["id", "name", "version", "versionCode", "author", "description"];

export function parseModuleProp(text) {
  const clean = text.replace(/^\uFEFF/, "");
  const out = {};
  for (const rawLine of clean.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    if (value) out[key] = value;
  }
  return out;
}

/** 六个可预填字段里缺了哪些（服务端必填的四项单独标出）。 */
export function missingRequired(prop) {
  const required = ["id", "name", "version", "versionCode"];
  return required.filter((k) => !prop[k]);
}

export function prefillable(prop) {
  const found = KEYS.filter((k) => prop[k]);
  return { keys: found, missing: KEYS.filter((k) => !prop[k]) };
}

export { KEYS as MODULE_PROP_KEYS };
