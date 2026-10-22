/* WOLFICH · зеркало API в Yandex Cloud Functions (Node.js 18+).
   Боты из России, у которых не открывается Cloudflare, обращаются сюда:
     ?p=unlock | status | cmd | push  — пересылаем на Worker (ответы маленькие, ограничение 16 КБ их не задевает)
     ?p=report                        — тоже на Worker: из Yandex Cloud Telegram недоступен, а Cloudflare открывается
     ?p=diag                          — проверка: заданы ли переменные, открываются ли Worker и Telegram
     ?p=al | row                      — сайт: альянс и планер (wolfich-license)
     ?p=nt&r=<имя>                    — сайт: вход, профиль, напоминания (wolfich-notify; переменная NOTIFY_URL, по умолчанию wolfich-notify.wolfichplay.workers.dev)
   Переменные окружения функции:
     WORKER_URL  — https://wolfich-license.wolfichplay.workers.dev
     MODULE_PASS — пароль модуля (ключ владельца), как в Worker
     TG_TOKEN, TG_CHAT — как в Worker (для баг-репортов)  */
const CORS = { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type", "access-control-allow-methods": "GET,POST,OPTIONS", "content-type": "application/json; charset=utf-8" };
const out = (o, st) => ({ statusCode: st || 200, headers: CORS, body: JSON.stringify(o) });

async function worker(path, method, body) {
  const base = E("WORKER_URL").replace(/\/+$/, "");
  const ac = new AbortController(), tm = setTimeout(() => ac.abort(), 15000);
  try {
    const r = await fetch(base + path, { method, headers: { "content-type": "application/json" }, body: method === "POST" ? body : undefined, signal: ac.signal });
    return await r.text();
  } finally { clearTimeout(tm); }
}

const E = (k) => String(process.env[k] || "").trim();   // в переменных бывают лишние пробелы и переводы строк

async function report(b) {
  const env = { TG_TOKEN: E("TG_TOKEN"), TG_CHAT: E("TG_CHAT"), MODULE_PASS: E("MODULE_PASS") };
  if (!env.TG_TOKEN || !env.TG_CHAT) return out({ ok: false, err: "баг-репорты не настроены на сервере" });
  const key = String(b.key || "");
  let who;
  if (env.MODULE_PASS && key === env.MODULE_PASS) who = "владелец";
  else {
    let st = null, why = "";
    try { st = JSON.parse(await worker("/status", "POST", JSON.stringify({ keys: [key] }))); } catch (e) { why = String(e && e.message || e); }
    const k = st && st.list && st.list[0];
    if (!k) return out({ ok: false, err: "зеркало: нет связи с сервером ключей (" + why + ")" });
    if (!k.ok) return out({ ok: false, err: k.err || "неверный ключ" });
    if (k.revoked) return out({ ok: false, err: "ключ отозван" });
    if (k.exp && Date.now() > k.exp) return out({ ok: false, err: "срок ключа истёк" });
    who = "ключ " + k.id;
  }
  const text = String(b.text || "").slice(0, 2000), info = String(b.info || "").slice(0, 600), log = String(b.log || "").slice(-200000);
  const dev = String(b.device || "").slice(0, 16);
  const head = "🐞 Баг-репорт · " + who + (dev ? " · ПК " + dev : "") + " · через зеркало\n" + info;
  const tg = (m, f) => fetch("https://api.telegram.org/bot" + env.TG_TOKEN + "/" + m, { method: "POST", body: f }).then((r) => r.json())
    .catch((e) => { throw new Error("Telegram недоступен из Yandex Cloud: " + (e && e.message || e)); });
  let f = new FormData(); f.append("chat_id", env.TG_CHAT); f.append("text", (head + "\n\n📝 " + text).slice(0, 4096));
  const r = await tg("sendMessage", f);
  if (!r.ok) return out({ ok: false, err: "Telegram: " + (r.description || "ошибка") });
  const m = /^data:image\/(jpeg|png|webp);base64,(.+)$/.exec(String(b.img || ""));
  if (m) {
    f = new FormData(); f.append("chat_id", env.TG_CHAT); f.append("caption", "Снимок игры · " + who);
    f.append("photo", new Blob([Buffer.from(m[2], "base64")], { type: "image/" + m[1] }), "screen." + (m[1] === "jpeg" ? "jpg" : m[1]));
    await tg("sendPhoto", f);
  }
  f = new FormData(); f.append("chat_id", env.TG_CHAT); f.append("caption", "Журнал бота · " + who);
  f.append("document", new Blob([head + "\n\n" + text + "\n\n— журнал —\n" + log], { type: "text/plain;charset=utf-8" }), "wolfich-log.txt");
  await tg("sendDocument", f);
  return out({ ok: true });
}

module.exports.handler = async function (event) {
  const method = (event.httpMethod || "GET").toUpperCase();
  if (method === "OPTIONS") return { statusCode: 204, headers: CORS, body: "" };
  const p = String((event.queryStringParameters || {}).p || "").replace(/[^a-z]/g, "");
  let body = event.body || "";
  if (event.isBase64Encoded) body = Buffer.from(body, "base64").toString("utf8");
  try {
    if (p === "ping") return out({ ok: true, mirror: true });
    if (p === "diag") {   // проверка настроек: переменные и связь с Worker и Telegram (без секретов)
      const t0 = Date.now(), d = { env: { WORKER_URL: !!E("WORKER_URL"), MODULE_PASS: !!E("MODULE_PASS"), TG_TOKEN: !!E("TG_TOKEN"), TG_CHAT: !!E("TG_CHAT") } };
      try { d.worker = JSON.parse(await worker("/cmd", "GET")).ok ? "ok " + (Date.now() - t0) + " мс" : "ответ без ok"; } catch (e) { d.worker = "ошибка: " + (e && e.message || e) + (e && e.cause ? " / " + e.cause.message : ""); }
      const t1 = Date.now();
      try { const r = await fetch("https://api.telegram.org/bot" + E("TG_TOKEN") + "/getMe").then((r) => r.json()); d.telegram = r.ok ? "ok @" + r.result.username + " " + (Date.now() - t1) + " мс" : "ответ: " + r.description; } catch (e) { d.telegram = "ошибка: " + (e && e.message || e) + (e && e.cause ? " / " + e.cause.message : ""); }
      return out(d);
    }
    // Telegram из Yandex Cloud не открывается, а Worker на Cloudflare — да: отчёт тоже пересылаем на Worker (он сам шлёт в Telegram)
    if (["unlock", "status", "push", "report", "tglink", "tgstat", "notify", "tgsetup", "app", "rchello", "rcpoll", "rcack", "rcnote"].indexOf(p) >= 0 && method === "POST") return { statusCode: 200, headers: CORS, body: await worker("/" + p, "POST", body) };
    if (p === "cmd") return { statusCode: 200, headers: CORS, body: await worker("/cmd", "GET") };
    // сайт: альянс и планер (wolfich-license /al и /row) — когда Cloudflare из России не открывается
    if ((p === "al" || p === "row") && method === "POST") return { statusCode: 200, headers: CORS, body: await worker("/" + p, "POST", body) };
    // сайт: вход через Telegram/Google, профиль, напоминания (wolfich-notify ?r=…) — код ответа передаём как есть (401 / 409 важны)
    if (p === "nt" && method === "POST") {
      const r = String((event.queryStringParameters || {}).r || "").replace(/[^a-z]/g, "");
      const base = (E("NOTIFY_URL") || "https://wolfich-notify.wolfichplay.workers.dev").replace(/\/+$/, "");
      const ac = new AbortController(), tm = setTimeout(() => ac.abort(), 20000);
      try {
        const res = await fetch(base + "/?r=" + r, { method: "POST", headers: { "content-type": "text/plain;charset=UTF-8" }, body, signal: ac.signal });
        return { statusCode: res.status, headers: CORS, body: await res.text() };
      } finally { clearTimeout(tm); }
    }
    return out({ ok: false, err: "not found" }, 404);
  } catch (e) {
    return out({ ok: false, net: true, err: "зеркало: " + (e && e.message || e) + (e && e.cause ? " / " + e.cause.message : "") });
  }
};
