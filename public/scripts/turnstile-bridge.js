// ===========================================================================
//  Turnstile 令牌页 —— 给 Android App 的 WebView 内嵌用（public/turnstile.html）
//
//  App 侧 JS 接口契约（页面加载前注入 window.TurnstileBridge）：
//    TurnstileBridge.onToken(String token)    校验通过。token 一次性，交给后端 /submit。
//    TurnstileBridge.onError(String message)  失败 / 过期 / 超时。message 可直接展示。
//
//  Android 侧（Kotlin / Java）大致是：
//    webView.addJavascriptInterface(bridge, "TurnstileBridge");
//    class Bridge {
//      @JavascriptInterface fun onToken(token: String) { ... }
//      @JavascriptInterface fun onError(message: String) { ... }
//    }
//  接口方法可能被调用多次（令牌刷新时 onToken 会再来一次），取最后一次即可。
//  onToken / onError 都只是“通知”，页面不会等待返回值。
//
//  为什么必须同源：这把 sitekey 绑定在 cool-module.pages.dev（另含 localhost /
//  127.0.0.1）。App 用 https://cool-module.pages.dev/turnstile 加载本页
//  （/turnstile.html 会 308 到这里）；
//  换域名 Cloudflare 会直接拒绝出题。
//
//  这里没有 secret：只有公开 sitekey（config.js），也没有任何其它网络请求。
// ===========================================================================

// config.js 用动态 import：静态 import 一旦 404，整个模块直接不执行，
// 连 onError 都送不出去，App 只能干等到自己的超时。
let CONFIG = null;

async function loadConfig() {
  if (CONFIG) return CONFIG;
  const mod = await import("./config.js");
  CONFIG = mod.CONFIG;
  return CONFIG;
}

const API_SRC =
  "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=__turnstileReady";

const slot = document.getElementById("slot");
const statusEl = document.getElementById("status");
const retryBtn = document.getElementById("retry");
const noBridge = document.getElementById("no-bridge");

let widgetId = null;
let lastError = "";

// --- 与 App 的桥 ------------------------------------------------------------
function hasBridge() {
  const b = window.TurnstileBridge;
  return !!b && typeof b.onToken === "function";
}

function notifyToken(token) {
  // 契约写法：window.TurnstileBridge && window.TurnstileBridge.onToken(token)
  try {
    window.TurnstileBridge && window.TurnstileBridge.onToken(String(token));
  } catch (err) {
    console.error("[turnstile] onToken 调用失败", err);
  }
}

function notifyError(message) {
  try {
    window.TurnstileBridge && window.TurnstileBridge.onError(String(message));
  } catch (err) {
    console.error("[turnstile] onError 调用失败", err);
  }
}

// --- 界面 -------------------------------------------------------------------
function setStatus(text, tone) {
  statusEl.textContent = text;
  statusEl.classList.toggle("is-ok", tone === "ok");
  statusEl.classList.toggle("is-bad", tone === "bad");
}

function fail(message, { retry = true } = {}) {
  setStatus(message, "bad");
  retryBtn.hidden = !retry;
  // error-callback 与 timeout-callback 可能连着来；同一条消息只报一次。
  if (message !== lastError) {
    lastError = message;
    notifyError(message);
  }
}

// --- 加载 Cloudflare 脚本（显式渲染，只加载一次）-----------------------------
let apiPromise = null;

function loadApi() {
  if (window.turnstile) return Promise.resolve();
  // 只留一份在飞：重试时不能每点一次就多塞一个 script 标签。
  if (apiPromise) return apiPromise;

  apiPromise = new Promise((resolve, reject) => {
    let settled = false;
    let script = null;

    const done = (ok, err) => {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog);
      if (!ok) {
        // 失败的标签留着只会让下一次重试再等一遍同一个死连接。
        script?.remove();
        script = null;
        apiPromise = null;
      }
      if (ok) resolve();
      else reject(err);
    };

    // 脚本被拦时 onerror 不一定来（DNS 黑洞就是一直挂着），兜一层硬超时。
    const watchdog = setTimeout(() => done(false, new Error("timeout")), 15000);

    window.__turnstileReady = () => done(true);

    script = document.createElement("script");
    script.src = API_SRC;
    script.async = true;
    script.defer = true;
    script.onerror = () => done(false, new Error("network"));
    document.head.append(script);
  });

  return apiPromise;
}

// --- 渲染部件 ---------------------------------------------------------------
function renderWidget() {
  try {
    widgetId = window.turnstile.render(slot, {
      sitekey: CONFIG.TURNSTILE_SITEKEY.trim(),
      // managed 模式：站点现有上传页没传 mode，用的就是默认 managed。
      theme: "auto",
      language: "zh-cn",
      callback: (token) => {
        if (!token) return;
        lastError = "";
        retryBtn.hidden = true;
        setStatus("校验通过，正在返回 App…", "ok");
        notifyToken(token);
      },
      "error-callback": (code) => {
        fail(`人机校验失败${code ? `（错误码 ${code}）` : ""}，请重试。`);
      },
      "expired-callback": () => {
        fail("校验已过期，请重新完成。");
      },
      "timeout-callback": () => {
        fail("校验超时，请重新完成。");
      },
    });
  } catch (err) {
    console.error("[turnstile] render 失败", err);
    fail("校验组件初始化失败，请重试。");
  }
}

async function start() {
  setStatus("正在加载校验组件…");
  retryBtn.hidden = true;
  try {
    await loadApi();
    setStatus("请完成人机校验");
    renderWidget();
  } catch (err) {
    fail(
      err && err.message === "timeout"
        ? "校验组件加载超时，请检查网络后重试。"
        : "校验组件加载失败，请检查网络后重试。"
    );
  }
}

// --- 重试 -------------------------------------------------------------------
retryBtn.addEventListener("click", () => {
  lastError = "";
  retryBtn.hidden = true;
  if (widgetId !== null && window.turnstile) {
    setStatus("请完成人机校验");
    try {
      window.turnstile.reset(widgetId);
      return;
    } catch {
      // reset 失败就整块重来；先把旧部件摘掉，别让第二个叠在同一个槽里。
      try {
        window.turnstile.remove(widgetId);
      } catch {
        // 已经不在 DOM 里也无所谓
      }
      widgetId = null;
      slot.textContent = "";
    }
  }
  start();
});

// --- 启动：先等 App 注入桥，再向 Cloudflare 要题 ------------------------------
async function begin() {
  try {
    await loadConfig();
  } catch (err) {
    console.error("[turnstile] config.js 加载失败", err);
    slot.hidden = true;
    // 重试也读不到同一份配置，给一个按钮只会让用户原地转圈。
    fail("校验页配置加载失败，请更新 App 后重试。", { retry: false });
    return;
  }
  if (!CONFIG.TURNSTILE_SITEKEY.trim()) {
    slot.hidden = true;
    fail("站点还没配置 Turnstile sitekey，暂时无法校验。", { retry: false });
    return;
  }
  slot.hidden = false;
  start();
}

(function boot() {
  let waited = 0;
  const tick = setInterval(() => {
    if (hasBridge()) {
      clearInterval(tick);
      noBridge.hidden = true;
      void begin();
      return;
    }
    waited += 250;
    if (waited === 1000) {
      // 浏览器直接打开时立刻说清楚；先收起转圈，别让它一直转。
      noBridge.hidden = false;
      slot.hidden = true;
      setStatus("请在 App 内打开本页。");
    }
    if (waited >= 15000) {
      clearInterval(tick);
      setStatus("未检测到 App 桥接，无法把校验结果交回去。", "bad");
    }
  }, 250);
})();
