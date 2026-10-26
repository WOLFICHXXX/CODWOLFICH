/* WOLFICH · лицензии автопохода (Cloudflare Worker «wolfich-license»).
   Секреты Worker:  LICENSE_SECRET — секрет подписи ключей (тот же, что в генераторе)
                    MODULE_PASS    — пароль модуля бота (owner.bin)
                    OWNER_KEYS     — дополнительные ключи владельца WLO-… через запятую (необязательно)
   KV (binding LIC): rev:<id> — ключ отозван;  dev:<id> — привязанный компьютер;  act:<id> — момент активации (ключи v2)
   POST /unlock  {key, device}  →  {ok, exp, pass}  или  {ok:false, err}
   POST /status  {keys:[…]}     →  {ok, list:[{key, id, ok, days, act, exp, ext, bound, revoked, err}]}  — для генератора
   POST /extend  {id, min, ts, sig}  →  {ok, ext}  — генератор добавляет время ключу без нового ключа;
                 sig = hex(HMAC(LICENSE_SECRET, "extend|id|min|ts")), KV ext:<id> — сколько добавлено всего (мс)
   POST /report  {key, device, text, info, log, img}  →  {ok}  — баг-репорт из бота в Telegram владельца
   POST /push    {key, txt}  →  {ok, upd}  — только ключ владельца: «важное обновление» с описанием для всех ботов
   GET  /cmd                 →  {ok, upd, txt}  — боты спрашивают раз в 15 минут, не было ли такого объявления
   Секреты для баг-репортов: TG_TOKEN — токен Telegram-бота (от @BotFather), TG_CHAT — ваш chat id  */
const enc = new TextEncoder();
const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";   // Crockford base32: без I, L, O, U
function b32dec(s) {
  s = s.toUpperCase().replace(/[^0-9A-Z]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
  let bits = 0, val = 0; const out = [];
  for (const ch of s) { const v = B32.indexOf(ch); if (v < 0) return null; val = (val << 5) | v; bits += 5; if (bits >= 8) { bits -= 8; out.push((val >> bits) & 255); } }
  return new Uint8Array(out);
}
async function hmac(secret, data) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}
/* ключ = WLF- + base32( payload(13 байт) + подпись(10 байт) )
   v1: [0]=1, [1..4] id, [5..8] выдан (дни от 2024-01-01), [9..12] истекает (минуты от 2024-01-01) — срок от выдачи
   v2: [0]=2, [1..4] id, [5..8] выдан (дни от 2024-01-01), [9..10] срок в днях, [11..12] резерв — срок от первой активации  */
const EPOCH = Date.UTC(2024, 0, 1);
async function parseKey(key, secret) {
  const raw = b32dec(String(key || "").replace(/^WLF-?/i, ""));
  if (!raw || raw.length < 23 || (raw[0] !== 1 && raw[0] !== 2)) return { err: "неверный ключ" };
  const pay = raw.slice(0, 13), sig = raw.slice(13, 23);
  const want = (await hmac(secret, pay)).slice(0, 10);
  let diff = 0; for (let i = 0; i < 10; i++) diff |= want[i] ^ sig[i];
  if (diff) return { err: "неверный ключ" };
  const dv = new DataView(pay.buffer, pay.byteOffset);
  const id = dv.getUint32(1).toString(16).padStart(8, "0"), issued = EPOCH + dv.getUint32(5) * 86400000;
  if (raw[0] === 1) return { id, issued, exp: EPOCH + dv.getUint32(9) * 60000 };
  return { id, issued, days: dv.getUint16(9) };   // v2: срок посчитаем от активации
}
/* дополнительные ключи владельца (без срока, права владельца): здесь — SHA-256 самих ключей; ещё можно перечислить ключи
   в переменной OWNER_KEYS (через запятую). Отозвать ключ — удалить его хеш отсюда и задеплоить. */
const OWNER_HASHES = ["0fc8fae8e556ad4f2e11404fb758f8e7202a7dbfc39bea73f45ac9eaabd0c337"];
async function isOwner(key, env) {
  if (!key) return false;
  if (env.MODULE_PASS && key === env.MODULE_PASS) return true;
  if (String(env.OWNER_KEYS || "").split(/[\s,]+/).filter(Boolean).indexOf(key) >= 0) return true;
  const h = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)))).map((b) => b.toString(16).padStart(2, "0")).join("");
  return OWNER_HASHES.indexOf(h) >= 0;
}
const extOf = async (env, id) => (env.LIC ? (+(await env.LIC.get("ext:" + id)) || 0) : 0);   // добавленное генератором время (мс)
const json = (o, st) => new Response(JSON.stringify(o), { status: st || 200, headers: { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*", "access-control-allow-headers": "content-type" } });
export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return json({ ok: true });
    const url = new URL(req.url);
    if (url.pathname === "/status" && req.method === "POST") {   // статус ключей: только по самим ключам (без пароля модуля)
      let b = {}; try { b = await req.json(); } catch (e) {}
      const keys = Array.isArray(b.keys) ? b.keys.slice(0, 100) : [];
      const list = [];
      for (const key of keys) {
        const k = await parseKey(key, env.LICENSE_SECRET);
        if (k.err) { list.push({ key, ok: false, err: k.err }); continue; }
        const act = k.days != null && env.LIC ? (+(await env.LIC.get("act:" + k.id)) || 0) : 0;
        const ext = await extOf(env, k.id);
        const exp = k.days != null ? (act ? act + k.days * 86400000 + ext : 0) : k.exp + ext;
        list.push({ key, id: k.id, ok: true, days: k.days != null ? k.days : null, act: act || null, exp: exp || null, ext,
          bound: env.LIC ? !!(await env.LIC.get("dev:" + k.id)) : null, revoked: env.LIC ? !!(await env.LIC.get("rev:" + k.id)) : null });
      }
      return json({ ok: true, now: Date.now(), list });
    }
    if (url.pathname === "/extend" && req.method === "POST") {   // добавить время ключу (подпись секретом генератора)
      let b = {}; try { b = await req.json(); } catch (e) {}
      if (!env.LIC || !env.LICENSE_SECRET) return json({ ok: false, err: "сервер ключей не настроен" });
      const id = String(b.id || "").toLowerCase(), min = Math.round(+b.min || 0), ts = Math.round(+b.ts || 0), sig = String(b.sig || "").toLowerCase();
      if (!/^[0-9a-f]{8}$/.test(id) || !min || Math.abs(min) > 5 * 525600) return json({ ok: false, err: "неверные данные" });
      if (Math.abs(Date.now() - ts) > 600000) return json({ ok: false, err: "время на компьютере сбито больше чем на 10 минут" });
      const want = Array.from(await hmac(env.LICENSE_SECRET, enc.encode("extend|" + id + "|" + min + "|" + ts)), (x) => x.toString(16).padStart(2, "0")).join("");
      if (want !== sig) return json({ ok: false, err: "подпись не подходит — в генераторе другой секрет" });
      if (await env.LIC.get("exts:" + sig)) return json({ ok: false, err: "этот запрос уже выполнен" });
      await env.LIC.put("exts:" + sig, "1", { expirationTtl: 1200 });
      const ext = Math.max(-5 * 525600 * 60000, (await extOf(env, id)) + min * 60000);
      await env.LIC.put("ext:" + id, String(ext));
      return json({ ok: true, id, ext });
    }
    if (url.pathname === "/report" && req.method === "POST") return report(req, env);
    // уведомления о капче в Telegram: привязка чата к ключу, отправка, вебхук бота
    if (url.pathname === "/tg" && req.method === "POST") return tgHook(req, env);
    if (["/tglink", "/tgstat", "/notify", "/tgsetup"].indexOf(url.pathname) >= 0 && req.method === "POST") return tgApi(url, req, env);
    if (url.pathname === "/app" && req.method === "POST") return appApi(req, env);   // мини-приложение «Пульт» в Telegram
    if (["/rchello", "/rcpoll", "/rcack", "/rcnote"].indexOf(url.pathname) >= 0 && req.method === "POST") return rcApi(url, req, env);   // программа ↔ пульт
    if (url.pathname === "/al" && req.method === "POST") return alApi(req, env);
    if (url.pathname === "/row" && req.method === "POST") return rowApi(req, env);   // сайт: личные планеры RoW   // сайт: альянсы (сбор данных участников)
    if (url.pathname === "/cmd") return json({ ok: true, upd: env.LIC ? (+(await env.LIC.get("cmd:upd")) || 0) : 0, txt: env.LIC ? ((await env.LIC.get("cmd:txt")) || "") : "" });
    if (url.pathname === "/push" && req.method === "POST") {
      let b = {}; try { b = await req.json(); } catch (e) {}
      if (!(await isOwner(String(b.key || ""), env))) return json({ ok: false, err: "только для владельца" });
      if (!env.LIC) return json({ ok: false, err: "сервер ключей не настроен (нет хранилища LIC)" });
      const upd = Date.now(); await env.LIC.put("cmd:txt", String(b.txt || "").slice(0, 1500)); await env.LIC.put("cmd:upd", String(upd));
      return json({ ok: true, upd });
    }
    if (url.pathname !== "/unlock" || req.method !== "POST") return json({ ok: false, err: "not found" }, 404);
    let body = {}; try { body = await req.json(); } catch (e) {}
    if (await isOwner(String(body.key || ""), env)) {   // дополнительный ключ владельца: без срока, права владельца
      return json({ ok: true, owner: true, exp: Date.UTC(2100, 0, 1), pass: env.MODULE_PASS });
    }
    if (/^WLO-/i.test(String(body.key || ""))) return json({ ok: false, err: "неверный ключ" });
    const k = await parseKey(body.key, env.LICENSE_SECRET);
    if (k.err) return json({ ok: false, err: k.err });
    if (k.days != null && !env.LIC) return json({ ok: false, err: "сервер ключей не настроен (нет хранилища LIC)" });
    if (env.LIC && await env.LIC.get("rev:" + k.id)) return json({ ok: false, err: "ключ отозван" });
    const dev = String(body.device || "").slice(0, 64);
    if (env.LIC && dev) {   // привязка к первому компьютеру (запись хранится всегда)
      const bound = await env.LIC.get("dev:" + k.id);
      if (bound && bound !== dev) return json({ ok: false, err: "ключ уже используется на другом компьютере" });
    }
    const ext = await extOf(env, k.id);   // время, добавленное в генераторе
    let exp = k.exp + ext, activated = false;
    if (k.days != null) {   // v2: срок идёт с первой активации
      let act = +(await env.LIC.get("act:" + k.id)) || 0;
      if (!act) { act = Date.now(); activated = true; }
      exp = act + k.days * 86400000 + ext;
      if (Date.now() > exp) return json({ ok: false, err: "срок ключа истёк", exp });
      if (activated) await env.LIC.put("act:" + k.id, String(act));
    }
    if (Date.now() > exp) return json({ ok: false, err: "срок ключа истёк", exp });
    if (env.LIC && dev && !(await env.LIC.get("dev:" + k.id))) await env.LIC.put("dev:" + k.id, dev);
    return json({ ok: true, id: k.id, exp, activated, pass: env.MODULE_PASS });
  },
};

/* баг-репорт: принимаем только от действующего ключа (WLF-… или ключ владельца), не чаще раза в минуту с одного ключа */
async function report(req, env) {
  if (!env.TG_TOKEN || !env.TG_CHAT) return json({ ok: false, err: "баг-репорты не настроены на сервере" });
  let b = {}; try { b = await req.json(); } catch (e) { return json({ ok: false, err: "слишком большой отчёт" }); }
  const key = String(b.key || "");
  let who, rid;
  if (await isOwner(key, env)) { who = key === env.MODULE_PASS ? "владелец" : "владелец (доп. ключ)"; rid = "owner"; }
  else {
    const k = await parseKey(key, env.LICENSE_SECRET);
    if (k.err) return json({ ok: false, err: k.err });
    if (env.LIC && await env.LIC.get("rev:" + k.id)) return json({ ok: false, err: "ключ отозван" });
    who = "ключ " + k.id; rid = k.id;
  }
  if (env.LIC) {
    if (await env.LIC.get("rl:" + rid)) return json({ ok: false, err: "подождите минуту перед следующим отчётом" });
    await env.LIC.put("rl:" + rid, "1", { expirationTtl: 60 });
  }
  const text = String(b.text || "").slice(0, 2000), info = String(b.info || "").slice(0, 600), log = String(b.log || "").slice(-200000);
  const dev = String(b.device || "").slice(0, 16);
  const head = "🐞 Баг-репорт · " + who + (dev ? " · ПК " + dev : "") + "\n" + info;
  const tg = (method, form) => fetch("https://api.telegram.org/bot" + env.TG_TOKEN + "/" + method, { method: "POST", body: form }).then((r) => r.json());
  // 1) шапка и описание (текстом — до 4096 символов)
  let f = new FormData(); f.append("chat_id", env.TG_CHAT); f.append("text", (head + "\n\n📝 " + text).slice(0, 4096));
  let r = await tg("sendMessage", f);
  if (!r.ok) return json({ ok: false, err: "Telegram: " + (r.description || "ошибка") });
  // 2) снимок игры
  const m = /^data:image\/(jpeg|png|webp);base64,(.+)$/.exec(String(b.img || ""));
  if (m && m[2].length < 8000000) {
    const bin = Uint8Array.from(atob(m[2]), (c) => c.charCodeAt(0));
    f = new FormData(); f.append("chat_id", env.TG_CHAT); f.append("caption", "Снимок игры · " + who);
    f.append("photo", new Blob([bin], { type: "image/" + m[1] }), "screen." + (m[1] === "jpeg" ? "jpg" : m[1]));
    await tg("sendPhoto", f);
  }
  // 3) журнал бота файлом
  f = new FormData(); f.append("chat_id", env.TG_CHAT); f.append("caption", "Журнал бота · " + who);
  f.append("document", new Blob([head + "\n\n" + text + "\n\n— журнал —\n" + log], { type: "text/plain;charset=utf-8" }), "wolfich-log.txt");
  await tg("sendDocument", f);
  return json({ ok: true });
}

/* ---------- Telegram: уведомления о капче для всех ключей ----------
   Владелец получает их в TG_CHAT (как баг-репорты). Пользователь ключа WLF один раз нажимает «Подключить Telegram» в боте:
   сервер выдаёт ссылку t.me/<бот>?start=<код>, пользователь жмёт «Старт» в Telegram — чат запоминается за ключом (KV tg:<id>).
   Остальные сообщения боту от пользователей игнорируются: им доступны только уведомления о капче. */
async function who(key, env) {
  if (env.MODULE_PASS && key === env.MODULE_PASS) return { rid: "owner", owner: true, main: true, name: "владелец" };
  if (await isOwner(key, env)) {   // дополнительный владелец: права владельца, но свой Telegram (привязывается как у пользователей)
    const h = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)))).map((b) => b.toString(16).padStart(2, "0")).join("");
    return { rid: "own" + h.slice(0, 12), owner: true, main: false, name: "владелец (доп. ключ)" };
  }
  const k = await parseKey(key, env.LICENSE_SECRET);
  if (k.err) return { err: k.err };
  if (env.LIC && await env.LIC.get("rev:" + k.id)) return { err: "ключ отозван" };
  return { rid: k.id, owner: false, name: "ключ " + k.id };
}
const tgCall = (env, method, form) => fetch("https://api.telegram.org/bot" + String(env.TG_TOKEN).trim() + "/" + method, form ? { method: "POST", body: form } : { method: "GET" })
  .then((r) => r.json()).catch((e) => ({ ok: false, description: "нет связи с Telegram: " + (e && e.message || e) }));
async function hookSecret(env) { const h = await hmac(env.TG_TOKEN, new TextEncoder().encode("wolfich-hook")); return Array.from(h.slice(0, 16)).map((b) => b.toString(16).padStart(2, "0")).join(""); }
async function tgApi(url, req, env) {
  if (!env.TG_TOKEN || !env.LIC) return json({ ok: false, err: "Telegram не настроен на сервере" });
  let b = {}; try { b = await req.json(); } catch (e) { return json({ ok: false, err: "неверный запрос" }); }
  const w = await who(String(b.key || ""), env);
  if (w.err) return json({ ok: false, err: w.err });
  const p = url.pathname;
  if (p === "/tgsetup") {   // владелец: подключить вебхук бота к этому серверу (один раз)
    if (!w.owner) return json({ ok: false, err: "только владелец" });
    const f = new FormData(); f.append("url", url.origin + "/tg"); f.append("secret_token", await hookSecret(env)); f.append("allowed_updates", JSON.stringify(["message"]));
    const r = await tgCall(env, "setWebhook", f);
    const mb = new FormData(); mb.append("menu_button", JSON.stringify({ type: "web_app", text: "Пульт", web_app: { url: appUrl(env) } }));
    await tgCall(env, "setChatMenuButton", mb);
    return json({ ok: !!r.ok, err: r.ok ? "" : (r.description || "Telegram не ответил") });
  }
  if (p === "/tgstat") return json({ ok: true, owner: !!w.main, who: w.name, linked: w.main ? !!env.TG_CHAT : !!(await env.LIC.get("tg:" + w.rid)) });
  if (p === "/tglink") {
    if (w.main) return json({ ok: true, owner: true });
    let bot = await env.LIC.get("tg:botname");
    let why = "";
    if (!bot) { const me = await tgCall(env, "getMe", null); bot = me && me.ok ? me.result.username : ""; why = me && me.description || ""; if (bot) await env.LIC.put("tg:botname", bot, { expirationTtl: 86400 }); }
    if (!bot) return json({ ok: false, err: "Telegram не ответил" + (why ? ": " + why : "") });
    const code = Array.from(crypto.getRandomValues(new Uint8Array(9))).map((x) => "abcdefghijkmnpqrstuvwxyz23456789"[x % 32]).join("");
    await env.LIC.put("tgc:" + code, w.rid, { expirationTtl: 900 });
    return json({ ok: true, url: "https://t.me/" + bot + "?start=" + code });
  }
  if (p === "/notify") {
    if (b.kind !== "captcha") return json({ ok: false, err: "неизвестное уведомление" });
    const chat = w.main ? env.TG_CHAT : await env.LIC.get("tg:" + w.rid);
    if (!chat) return json({ ok: false, err: "Telegram не подключён" });
    if (await env.LIC.get("rln:" + w.rid)) return json({ ok: true, skipped: true });   // не чаще раза в 5 минут
    await env.LIC.put("rln:" + w.rid, "1", { expirationTtl: 300 });
    const text = ("⚠️ Капча в игре — бот остановлен\n" + String(b.text || "").slice(0, 500)).slice(0, 1000);
    const img = String(b.img || "");
    let r;
    if (/^data:image\/(jpeg|png);base64,/.test(img) && img.length < 4000000) {
      const bin = Uint8Array.from(atob(img.split(",")[1]), (c) => c.charCodeAt(0));
      const f = new FormData(); f.append("chat_id", chat); f.append("caption", text); f.append("photo", new Blob([bin], { type: "image/jpeg" }), "captcha.jpg");
      r = await tgCall(env, "sendPhoto", f);
    }
    if (!r || !r.ok) { const f = new FormData(); f.append("chat_id", chat); f.append("text", text); r = await tgCall(env, "sendMessage", f); }
    return json({ ok: !!r.ok, to: w.main ? "owner" : "linked", who: w.name, err: r.ok ? "" : (r.description || "Telegram не ответил") });
  }
  return json({ ok: false, err: "not found" }, 404);
}
async function tgHook(req, env) {
  if (!env.TG_TOKEN || !env.LIC) return new Response("ok");
  if (req.headers.get("x-telegram-bot-api-secret-token") !== await hookSecret(env)) return new Response("forbidden", { status: 403 });
  let u = {}; try { u = await req.json(); } catch (e) { return new Response("ok"); }
  const m = u.message; if (!m || !m.chat) return new Response("ok");
  const chat = String(m.chat.id), text = String(m.text || "");
  const ownerChat = !!env.TG_CHAT && chat === String(env.TG_CHAT);
  const say = (t) => { const f = new FormData(); f.append("chat_id", chat); f.append("text", t); return tgCall(env, "sendMessage", f); };
  const mm = /^\/start\s+([a-z0-9]{6,20})$/i.exec(text.trim());
  if (mm) {
    const rid = await env.LIC.get("tgc:" + mm[1].toLowerCase());
    if (!rid) { await say("Ссылка устарела. Нажмите «Подключить Telegram» в боте ещё раз."); return new Response("ok"); }
    await env.LIC.put("tg:" + rid, chat); await env.LIC.delete("tgc:" + mm[1].toLowerCase());
    let rl = []; try { rl = JSON.parse((await env.LIC.get("tgr:" + chat)) || "[]"); } catch (e) {}
    if (rl.indexOf(rid) < 0) { rl.push(rid); await env.LIC.put("tgr:" + chat, JSON.stringify(rl)); }
    await sayApp(env, chat, "✅ Готово: сюда будут приходить уведомления о капче из бота WOLFICH. Кнопка «Пульт» — отправить марши удалённо.");
    return new Response("ok");
  }
  if (!ownerChat) await say("Этот бот только присылает уведомления о капче из WOLFICH. Подключение — кнопкой «Подключить Telegram» в настройках бота.");   // владельцу на прочие сообщения не отвечаем
  return new Response("ok");
}

/* ---------- пульт: мини-приложение в Telegram → команда в очередь → программа забирает (опрос раз в 30 с) ---------- */
const appUrl = (env) => String(env.APP_URL || "https://storage.yandexcloud.net/wolfich-mirror/tg.html");
const RESK = ["mana", "ore", "wood", "gold", "gems"];
const SHOT_URL = /^https:\/\/storage\.yandexcloud\.net\/[a-z0-9-]+\/shots\/[a-z0-9-]+\.(jpg|png|webp)$/;
async function sayApp(env, chat, text, img) {   // сообщение (или снимок с подписью) с кнопкой «Открыть пульт»
  const kb = JSON.stringify({ inline_keyboard: [[{ text: "🐺 Открыть пульт", web_app: { url: appUrl(env) } }]] });
  if (img && SHOT_URL.test(img)) {   // снимок, переданный зеркалом ссылкой на хранилище Yandex — Telegram скачает сам
    const f = new FormData(); f.append("chat_id", chat); f.append("caption", text.slice(0, 1000)); f.append("reply_markup", kb); f.append("photo", img);
    const r = await tgCall(env, "sendPhoto", f); if (r && r.ok) return r;
  }
  if (img && /^data:image\/(jpeg|png);base64,/.test(img) && img.length < 4000000) {
    const bin = Uint8Array.from(atob(img.split(",")[1]), (c) => c.charCodeAt(0));
    const f = new FormData(); f.append("chat_id", chat); f.append("caption", text.slice(0, 1000)); f.append("reply_markup", kb); f.append("photo", new Blob([bin], { type: "image/jpeg" }), "game.jpg");
    const r = await tgCall(env, "sendPhoto", f); if (r && r.ok) return r;
  }
  const f = new FormData(); f.append("chat_id", chat); f.append("text", text); f.append("reply_markup", kb);
  return tgCall(env, "sendMessage", f);
}
async function sayAlbum(env, chat, text, shots) {   // несколько снимков одним альбомом (подписи у каждого), затем текст с кнопкой пульта
  const ok = (shots || []).filter((x) => x && ((/^data:image\/(jpeg|png);base64,/.test(x.img || "") && x.img.length < 4000000) || SHOT_URL.test(x.img || ""))).slice(0, 10);
  if (ok.length === 1) return sayApp(env, chat, (ok[0].cap ? ok[0].cap + "\n" : "") + text, ok[0].img);
  if (ok.length > 1) {
    const f = new FormData(); f.append("chat_id", chat);
    f.append("media", JSON.stringify(ok.map((x, i) => ({ type: "photo", media: SHOT_URL.test(x.img) ? x.img : "attach://p" + i, caption: String(x.cap || "").slice(0, 200) }))));
    ok.forEach((x, i) => { if (SHOT_URL.test(x.img)) return; const bin = Uint8Array.from(atob(x.img.split(",")[1]), (c) => c.charCodeAt(0)); f.append("p" + i, new Blob([bin], { type: "image/jpeg" }), "p" + i + ".jpg"); });
    await tgCall(env, "sendMediaGroup", f);
  }
  return sayApp(env, chat, text);
}
async function hmacRaw(key, data) { const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); return new Uint8Array(await crypto.subtle.sign("HMAC", k, data)); }
const hexb = (u) => Array.from(u).map((b) => b.toString(16).padStart(2, "0")).join("");
async function tgUser(initData, env) {   // проверка подписи данных мини-приложения (правила Telegram)
  const p = new URLSearchParams(String(initData || "")), hash = p.get("hash"); if (!hash) return null;
  p.delete("hash");
  const dcs = Array.from(p.entries()).sort((a, b) => (a[0] < b[0] ? -1 : 1)).map((x) => x[0] + "=" + x[1]).join("\n");
  const secret = await hmacRaw(new TextEncoder().encode("WebAppData"), new TextEncoder().encode(String(env.TG_TOKEN).trim()));
  if (hexb(await hmacRaw(secret, new TextEncoder().encode(dcs))) !== hash) return null;
  if (Date.now() / 1000 - (+p.get("auth_date") || 0) > 86400) return null;
  try { return JSON.parse(p.get("user") || "null"); } catch (e) { return null; }
}
async function ridsOf(chat, env) {   // какие ключи привязаны к этому Telegram
  let rl = []; try { rl = JSON.parse((await env.LIC.get("tgr:" + chat)) || "[]"); } catch (e) {}
  if (!rl.length) {   // привязки, сделанные до появления пульта, — находим перебором
    let cur;
    do { const r = await env.LIC.list({ prefix: "tg:", cursor: cur }); for (const k of r.keys) { if (k.name === "tg:botname") continue; if ((await env.LIC.get(k.name)) === chat) rl.push(k.name.slice(3)); } cur = r.list_complete ? null : r.cursor; } while (cur);
    if (rl.length) await env.LIC.put("tgr:" + chat, JSON.stringify(rl));
  }
  if (env.TG_CHAT && chat === String(env.TG_CHAT) && rl.indexOf("owner") < 0) rl.unshift("owner");
  return rl;
}
async function chatOf(rid, env) { return rid === "owner" ? env.TG_CHAT : await env.LIC.get("tg:" + rid); }
const qK = (rid, inst) => "q:" + rid + ":" + (inst || "");   // все ждущие команды вкладки — одним ключом (один запрос KV на опрос)
/* Команды пишет только пульт (ключ q:…). Программа ничего в q не переписывает — отметки «взял» лежат отдельно в qa:… {поле: ts команды}.
   Раньше подтверждение перечитывало q и записывало его обратно: если KV отдавал устаревшую копию, только что отправленная команда стиралась. */
const qaK = (rid, inst) => "qa:" + rid + ":" + (inst || "");
async function rawQ(env, rid, inst) { try { return JSON.parse((await env.LIC.get(qK(rid, inst), { cacheTtl: 30 })) || "null") || {}; } catch (e) { return {}; } }
async function getQA(env, rid, inst) { try { return JSON.parse((await env.LIC.get(qaK(rid, inst), { cacheTtl: 30 })) || "null") || {}; } catch (e) { return {}; } }
async function getQ(env, rid, inst) {   // ждущие команды = q без тех, что программа уже взяла
  const [q, qa] = await Promise.all([rawQ(env, rid, inst), getQA(env, rid, inst)]);
  for (const f of Object.keys(q)) { const v = q[f]; if (!v || (qa[f] && (+v.ts || 0) <= qa[f])) delete q[f]; }
  return q;
}
async function ackQ(env, rid, inst, field, ts) {   // программа взяла команду field (ts — метка самой команды; старые версии ts не шлют)
  const qa = await getQA(env, rid, inst); const t = +ts || Date.now();
  if ((qa[field] || 0) >= t) return;
  qa[field] = t; await env.LIC.put(qaK(rid, inst), JSON.stringify(qa), { expirationTtl: 1800 });
}
async function putQ(env, rid, inst, q) {
  const k = qK(rid, inst);
  if (!Object.keys(q).some((x) => q[x])) return env.LIC.delete(k);
  return env.LIC.put(k, JSON.stringify(q), { expirationTtl: 1800 });
}
async function setQ(env, rid, inst, field, val) { const q = await getQ(env, rid, inst); q[field] = val; await putQ(env, rid, inst, q); }   // пишет только пульт
async function appApi(req, env) {
  if (!env.TG_TOKEN || !env.LIC) return json({ ok: false, err: "сервер не настроен" });
  let b = {}; try { b = await req.json(); } catch (e) { return json({ ok: false, err: "неверный запрос" }); }
  const u = await tgUser(b.initData, env); if (!u || !u.id) return json({ ok: false, err: "откройте пульт из Telegram" });
  const chat = String(u.id), rids = await ridsOf(chat, env);
  if (!rids.length) return json({ ok: false, err: "Telegram не привязан ни к одному ключу. В боте: ⚙ Настройки → Капча → «Подключить Telegram»." });
  if (b.op === "list") {
    const bots = [], now = Date.now();
    for (const rid of rids) {
      // пульт открыт — программа опрашивает чаще (метка раз в минуту, чтобы не тратить записи KV)
      const hot = +(await env.LIC.get("hot:" + rid)) || 0; if (now - hot > 300000) { try { await env.LIC.put("hot:" + rid, String(now), { expirationTtl: 900 }); } catch (e) {} }
      let tabs = {}, st = null, ld = null;
      try { tabs = JSON.parse((await env.LIC.get("rt:" + rid)) || "{}"); } catch (e) {}
      try { st = JSON.parse((await env.LIC.get("rs:" + rid)) || "null"); } catch (e) {}
      try { ld = JSON.parse((await env.LIC.get("rld:" + rid)) || "null"); } catch (e) {}
      const pending = {}, shotWait = {}, allyWait = {}, restartWait = {}, closeWait = {}, ldWait = {}, stopWait = {}, trainWait = {}, titleWait = {}, atrainWait = {}, atminWait = {}, lastTab = {}, state = {}, shotTs = {}, ins = Object.keys(tabs).length ? Object.keys(tabs) : [""];
      await Promise.all(ins.map(async (i) => {
        const q = await getQ(env, rid, i);
        if (q.cmd) pending[i] = true; if (q.shot) shotWait[i] = true; if (q.ally) allyWait[i] = true;
        if (q.restart) restartWait[i] = true; if (q.stop) stopWait[i] = true; if (q.train) trainWait[i] = true; if (q.title) titleWait[i] = true; if (q.close) closeWait[i] = true; if (q.ldc) ldWait[i] = true; if (q.atrain) { atrainWait[i] = q.atrain.on ? 1 : 0; if (q.atrain.min) atminWait[i] = q.atrain.min; }
        const t = await env.LIC.get("sht:" + rid + ":" + i); if (t) shotTs[i] = +t;
        try { const lt = JSON.parse((await env.LIC.get("rs:" + rid + ":" + i)) || "null"); if (lt) lastTab[i] = lt; } catch (e) {}
        try { const sv = JSON.parse((await env.LIC.get("rst:" + rid + ":" + i)) || "null"); if (sv) state[i] = sv; } catch (e) {}
      }));
      bots.push({ rid, name: rid === "owner" ? "Владелец" : rid.indexOf("own") === 0 ? "Владелец (доп. ключ)" : "Ключ " + rid, tabs, last: st, pending, shotWait, allyWait, restartWait, closeWait, ldWait, stopWait, trainWait, titleWait, atrainWait, atminWait, shotTs, ld, lastTab, state });
    }
    return json({ ok: true, bots });
  }
  const rid = String(b.rid || ""), inst = String(b.inst || "");
  if (rids.indexOf(rid) < 0) return json({ ok: false, err: "нет доступа к этому боту" });
  if (b.op === "send") {
    const plan = {}; let n = 0; RESK.forEach((k) => { plan[k] = Math.max(0, Math.min(5, Math.floor(+((b.plan || {})[k]) || 0))); n += plan[k]; });
    if (!n) return json({ ok: false, err: "укажите хотя бы один марш" });
    const cmd = { id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), inst, plan, ts: Date.now(),
      farm: Math.max(0, Math.min(1440, Math.floor(+b.farm || 0))), rest: Math.max(1, Math.min(720, Math.floor(+b.rest || 10))),   // фарм на время и проверка (мин)
      brk: Math.max(0, Math.min(1440, Math.floor(+b.brk || 0))), brkLen: Math.max(0, Math.min(720, Math.floor(+b.brkLen || 0))) };   // перерыв: каждые brk мин на brkLen мин
    await setQ(env, rid, inst, "cmd", cmd);
    return json({ ok: true, id: cmd.id });
  }
  if (b.op === "cancel") {   // отменить все ждущие команды вкладки или одну (what: stop / cmd / ally / …)
    if (b.what) { const q = await getQ(env, rid, inst); delete q[String(b.what)]; await putQ(env, rid, inst, q); }
    else await env.LIC.delete(qK(rid, inst));
    return json({ ok: true });
  }
  if (b.op === "ld") {   // LDMultiPlayer: открыть менеджер, запустить эмулятор, открыть для него вкладку бота
    const act = ["multi", "launch", "tab"].indexOf(b.act) >= 0 ? b.act : "launch";
    await setQ(env, rid, inst, "ldc", { act, index: Math.max(0, Math.floor(+b.index || 0)), name: String(b.name || "").slice(0, 40), ts: Date.now() });
    return json({ ok: true });
  }
  if (b.op === "train") {   // обучить войска; tr — тиры из пульта {inf,mag,mrk,cav,fly: 0..5}, чего нет — из настроек бота
    const t = { ts: Date.now() }, tr = {};
    if (b.tr && typeof b.tr === "object") for (const k of ["inf", "mag", "mrk", "cav", "fly"]) { const v = +b.tr[k]; if (Number.isInteger(v) && v >= 0 && v <= 5) tr[k] = v; }
    if (Object.keys(tr).length) t.tr = tr;
    if (b.title) t.title = 1;   // сначала титул «Старший надзиратель», обучение — после его получения
    await setQ(env, rid, inst, "train", t); return json({ ok: true });
  }
  if (b.op === "title") {   // заявка на титул советника: t — 0 Старший шпион, 1 Старший надзиратель, 2 Архимаг, 3 Верховный учёный
    const t = Math.floor(+b.t); if (!(t >= 0 && t <= 3)) return json({ ok: false, err: "выберите титул" });
    await setQ(env, rid, inst, "title", { t, ts: Date.now() }); return json({ ok: true });
  }
  if (b.op === "stop") { await setQ(env, rid, inst, "stop", { ts: Date.now() }); return json({ ok: true }); }
  if (b.op === "atrain") { const mn = +b.min; await setQ(env, rid, inst, "atrain", { on: !!b.on, min: mn > 0 ? Math.max(5, Math.min(1440, Math.round(mn))) : null, ts: Date.now() }); return json({ ok: true }); }   // переключатель «Автоматическое обучение» в боте   // остановить бота на этом эмуляторе
  if (b.op === "close") { await setQ(env, rid, inst, "close", { ts: Date.now() }); return json({ ok: true }); }   // закрыть игру → рабочий стол LDPlayer
  if (b.op === "restart") { await setQ(env, rid, inst, "restart", { ts: Date.now() }); return json({ ok: true }); }   // перезапуск игры
  if (b.op === "ally") {   // обход альянса: подарки / технологии / территория (без «Помощи»)
    const a = { gifts: !!b.gifts, tech: !!b.tech, terr: !!b.terr, ts: Date.now() };
    if (!a.gifts && !a.tech && !a.terr) return json({ ok: false, err: "выберите хотя бы одно действие" });
    await setQ(env, rid, inst, "ally", a); return json({ ok: true });
  }
  if (b.op === "shot") { await setQ(env, rid, inst, "shot", { ts: Date.now() }); return json({ ok: true }); }   // снимок экрана вкладки (до 30 с)
  if (b.op === "forget") {   // убрать вкладку из пульта (закрытую в программе)
    if (!inst) return json({ ok: false, err: "основную вкладку убрать нельзя" });
    let tabs = {}; try { tabs = JSON.parse((await env.LIC.get("rt:" + rid)) || "{}"); } catch (e) {}
    delete tabs[inst]; await env.LIC.put("rt:" + rid, JSON.stringify(tabs));
    for (const k of [qK(rid, inst), qaK(rid, inst), "rs:" + rid + ":" + inst, "rst:" + rid + ":" + inst, "sht:" + rid + ":" + inst, "shi:" + rid + ":" + inst]) await env.LIC.delete(k);
    return json({ ok: true });
  }
  if (b.op === "delshot") {   // удалить запрошенный снимок: из пульта и из чата
    const mid = await env.LIC.get("shm:" + rid + ":" + inst);
    const dc = (await chatOf(rid, env)) || chat;
    if (mid) await tgCall(env, "deleteMessage", (() => { const f = new FormData(); f.append("chat_id", dc); f.append("message_id", mid); return f; })());
    await env.LIC.delete("shi:" + rid + ":" + inst); await env.LIC.delete("sht:" + rid + ":" + inst); await env.LIC.delete("shm:" + rid + ":" + inst);
    return json({ ok: true });
  }
  if (b.op === "shotimg") {   // последний снимок вкладки (хранится час)
    let sh = null; try { sh = JSON.parse((await env.LIC.get("shi:" + rid + ":" + inst)) || "null"); } catch (e) {}
    return json({ ok: true, shot: sh });
  }
  return json({ ok: false, err: "неизвестная команда" });
}
function safeKV(lic) {   // запись в KV не должна ронять ответ: при исчерпании суточного лимита записей сообщение в Telegram всё равно уйдёт
  return { get: (...a) => lic.get(...a), list: (...a) => lic.list(...a),
    put: (...a) => lic.put(...a).catch((e) => { console.log("KV put: " + (e && e.message || e)); }),
    delete: (...a) => lic.delete(...a).catch((e) => { console.log("KV delete: " + (e && e.message || e)); }) };
}
async function rcApi(url, req, env) {
  if (!env.LIC) return json({ ok: false });
  env = Object.assign({}, env, { LIC: safeKV(env.LIC) });
  let b = {}; try { b = await req.json(); } catch (e) { return json({ ok: false }); }
  const w = await who(String(b.key || ""), env); if (w.err) return json({ ok: false, err: w.err });
  const p = url.pathname, inst = String(b.inst || "");
  if (p === "/rchello") {   // вкладки бота: список для пульта (пишется при запуске вкладки)
    let tabs = {}; try { tabs = JSON.parse((await env.LIC.get("rt:" + w.rid)) || "{}"); } catch (e) {}
    const name = String(b.name || (inst ? inst : "Основная")).slice(0, 40);
    if (tabs[inst] !== name) { tabs[inst] = name; await env.LIC.put("rt:" + w.rid, JSON.stringify(tabs)); }
    return json({ ok: true });
  }
  if (p === "/rcpoll") {
    const q = await getQ(env, w.rid, inst);
    if (b.st) await env.LIC.put("rst:" + w.rid + ":" + inst, JSON.stringify({ st: String(b.st).slice(0, 12), dev: String(b.dev || "").slice(0, 40), at: b.at == null ? null : !!b.at, tm: +b.tm > 0 ? Math.round(+b.tm) : null, ts: Date.now() }), { expirationTtl: 86400 * 2 });   // состояние вкладки: при смене и раз в 30 мин
    if (Array.isArray(b.ld)) await env.LIC.put("rld:" + w.rid, JSON.stringify({ list: b.ld.slice(0, 40).map((x) => ({ i: Math.floor(+x.i || 0), n: String(x.n || "").slice(0, 40), on: !!x.on })), ts: Date.now() }), { expirationTtl: 86400 * 2 });
    const hot = Object.keys(q).length > 0 || Date.now() - (+(await env.LIC.get("hot:" + w.rid)) || 0) < 420000;   // пульт открыт в последние 7 мин (метка пишется раз в 5 мин) или есть команды
    return json({ ok: true, hot, cmd: q.cmd || null, shot: q.shot || null, ally: q.ally || null, restart: q.restart || null, close: q.close || null, ldc: q.ldc || null, stop: q.stop || null, train: q.train || null, title: q.title || null, atrain: q.atrain || null });
  }
  const chat = await chatOf(w.rid, env);
  if (p === "/rcack") {   // программа взяла команду
    const msg = String(b.msg || "").slice(0, 500);
    await ackQ(env, w.rid, inst, b.atrain ? "atrain" : b.title ? "title" : b.train ? "train" : b.stop ? "stop" : b.ldc ? "ldc" : b.close ? "close" : b.restart ? "restart" : b.ally ? "ally" : "cmd", b.ts);
    await env.LIC.put("rs:" + w.rid + ":" + inst, JSON.stringify({ msg, ts: Date.now(), inst }), { expirationTtl: 86400 * 3 });
    if (chat && env.TG_TOKEN) await sayApp(env, chat, msg);
    return json({ ok: true });
  }
  if (p === "/rcnote") {   // ход удалённой отправки: марши ушли, все вернулись, не нашёл ресурс
    const msg = String(b.msg || "").slice(0, 800);
    if (b.shot) {   // ответ на «Запросить скриншот»: в чат и в пульт, «последнее событие» не трогаем
      await ackQ(env, w.rid, inst, "shot", b.ts);
      const img = String(b.img || ""), ts = Date.now();
      if (img) await env.LIC.put("shi:" + w.rid + ":" + inst, JSON.stringify({ img, ts, msg }), { expirationTtl: 3600 });
      await env.LIC.put("sht:" + w.rid + ":" + inst, String(ts), { expirationTtl: 3600 });
      if (chat && env.TG_TOKEN) { const r = await sayApp(env, chat, msg, img); if (r && r.ok && r.result) await env.LIC.put("shm:" + w.rid + ":" + inst, String(r.result.message_id), { expirationTtl: 86400 * 2 }); }
      return json({ ok: true });
    }
    await env.LIC.put("rs:" + w.rid + ":" + inst, JSON.stringify({ msg, ts: Date.now(), inst }), { expirationTtl: 86400 * 3 });
    if (Array.isArray(b.imgs) && b.imgs.length) {   // отчёт обхода альянса: снимок после каждой операции
      if (chat && env.TG_TOKEN) await sayAlbum(env, chat, msg, b.imgs.slice(0, 3).map((x) => ({ img: String(x && x.img || ""), cap: String(x && x.cap || "") })));
      return json({ ok: true });
    }
    if (chat && env.TG_TOKEN) await sayApp(env, chat, msg, String(b.img || ""));
    return json({ ok: true });
  }
  return json({ ok: false }, 404);
}

/* ---------- Альянсы на сайте: сбор данных участников ----------
   KV al:<id> = { id, name, ts, own, inv, off, m: { <mid>: { nick, k (секрет участника), role, power, merit, rank (4|5), troops, heroes, marches, ts } } }
   Ссылки: #ally=<id>.<inv> — участник (смотреть + свои данные), #ally=<id>.<off> — офицер (всё, кроме удаления альянса).
   Владелец (создатель) держит токен own у себя в браузере. */
const alRnd = (n) => { const a = new Uint8Array(n); crypto.getRandomValues(a); return Array.from(a, (b) => "abcdefghijkmnpqrstuvwxyz23456789"[b & 31]).join(""); };
const alKey = (id) => "al:" + String(id).replace(/[^a-z0-9]/g, "").slice(0, 16);
const alStr = (v, n) => String(v == null ? "" : v).replace(/[\u0000-\u001f]/g, " ").trim().slice(0, n || 40);
function alClean(d) {   // данные участника: только известные поля, с ограничениями размера
  const o = {};
  if (d.nick != null) o.nick = alStr(d.nick, 32);
  if (d.power != null) o.power = Math.max(0, Math.min(9e12, Math.floor(+d.power || 0)));
  if (d.merit != null) o.merit = Math.max(0, Math.min(9e12, Math.floor(+d.merit || 0)));
  if (Array.isArray(d.troops)) o.troops = d.troops.slice(0, 8).map((t) => ({ type: alStr(t.type, 16), fly: !!t.fly, tier: Math.max(0, Math.min(9, Math.floor(+t.tier || 0))), n: Math.max(0, Math.min(1e9, Math.floor(+t.n || 0))) }));
  if (Array.isArray(d.heroes)) o.heroes = d.heroes.slice(0, 2).map((h) => ({ name: alStr(h.name, 32), lvl: Math.max(0, Math.min(99, Math.floor(+h.lvl || 0))), skills: alStr(h.skills, 24).replace(/[^0-5/]/g, "") }));
  if (d.note != null) o.note = alStr(d.note, 300);
  if (d.pt !== undefined) {   // прайм-тайм в UTC: минуты от полуночи (a — начало, b — конец; через полночь b < a)
    const a0 = Math.floor(+(d.pt && d.pt.a)), b0 = Math.floor(+(d.pt && d.pt.b));
    o.pt = d.pt && a0 >= 0 && a0 < 1440 && b0 >= 0 && b0 < 1440 && a0 !== b0 ? { a: a0, b: b0 } : null;
  }
  if (d.hrs != null) o.hrs = Math.max(0, Math.min(24, Math.round((+d.hrs || 0) * 2) / 2));   // часов в игре в день
  if (d.rank != null) o.rank = [4, 5].includes(+d.rank) ? +d.rank : 0;   // R4/R5 — подтверждён скриншотом вкладки «Участники»
  if (Array.isArray(d.marches)) o.marches = d.marches.slice(0, 5).map((x) => { const c = alClean({ heroes: (x && x.heroes) || [], troops: (x && x.troops) || [] }); return { heroes: c.heroes, troops: c.troops }; });   // до 5 маршей
  return o;
}
const rowT = (t) => Math.max(1, Math.min(3, Math.floor(+t || 1)));
const rowOf = (a) => { const o = {}; Object.keys(a.row || {}).forEach((t) => { o[t] = { open: !!a.row[t].open, ts: a.row[t].ts || 0 }; }); return o; };

/* ---------- Планер RoW: личные планеры (не привязанные к альянсу) ----------
   KV rp:<id> = { id, name, ts, view, edit, data }. Ссылки: #row=p.<id>.<view> — наблюдать, #row=p.<id>.<edit> — редактировать.
   Командные планеры альянса — в /al (op rowget/rowmk/rowopen/rowdel), карта команды в KV rw:<альянс>:<1..3>. */
function rowEntry(e) {   // здание планера: участники (снимок марша) и заметка
  const o = {}; e = e && typeof e === "object" ? e : {};
  if (Array.isArray(e.a)) o.a = e.a.slice(0, 30).map((x) => {
    x = x && typeof x === "object" ? x : {};
    const r = { nick: alStr(x.nick, 32) };
    if (x.mid) r.mid = alStr(x.mid, 12).replace(/[^a-z0-9]/g, "");
    if (x.m != null) r.m = Math.max(0, Math.min(4, Math.floor(+x.m || 0)));
    if (Array.isArray(x.h)) r.h = alClean({ heroes: x.h.map((n) => (typeof n === "string" ? { name: n } : n || {})) }).heroes.filter((h) => h.name);   // герои: имя, уровень, навыки
    if (Array.isArray(x.tr)) r.tr = alClean({ troops: x.tr }).troops;
    if (x.ty) r.ty = alStr(x.ty, 16);
    if (x.fly) r.fly = true;
    return r;
  }).filter((r) => r.nick);
  if (!o.a || !o.a.length) delete o.a;
  const n = alStr(e.note, 500); if (n) o.note = n;
  return o;
}
function rowPut(data, b, e) {   // data.b[<0..63>] = запись здания (пустая — удалить)
  data = data && typeof data === "object" ? data : {}; data.b = data.b && typeof data.b === "object" ? data.b : {};
  const i = Math.max(0, Math.min(63, Math.floor(+b || 0))), c = rowEntry(e);
  if (Object.keys(c).length) { c.ts = Date.now(); data.b[i] = c; } else delete data.b[i];
  data.ts = Date.now(); return data;
}
function rowMark(data, kind, id, v) {   // тактика: data.k — метки { t, x, y, note }, data.r — стрелки { x1, y1, x2, y2, c, bend }; v = null — удалить
  data = data && typeof data === "object" ? data : {};
  const K = kind === "r" ? "r" : "k"; data[K] = data[K] && typeof data[K] === "object" ? data[K] : {};
  id = alStr(id, 12).replace(/[^a-z0-9]/gi, ""); if (!id) return data;
  const pc = (n) => Math.round(Math.max(-5, Math.min(105, +n || 0)) * 100) / 100;
  if (!v || typeof v !== "object") delete data[K][id];
  else if (Object.keys(data[K]).length < 150 || data[K][id]) {
    if (K === "k") { const o = { t: ["warn", "mana", "rally", "note"].includes(v.t) ? v.t : "warn", x: pc(v.x), y: pc(v.y) }, ce = rowEntry({ a: v.a, note: v.note }); if (ce.a) o.a = ce.a; if (ce.note) o.note = ce.note; const sz = Math.round(Math.max(0.5, Math.min(3, +v.s || 1)) * 10) / 10; if (sz !== 1) o.s = sz; const nm = alStr(v.n, 40); if (nm) o.n = nm; data.k[id] = o; }   // s — размер метки (0.5–3)   // метка: участники с маршами и заметка
    else data.r[id] = { x1: pc(v.x1), y1: pc(v.y1), x2: pc(v.x2), y2: pc(v.y2), c: ["r", "b", "g"].includes(v.c) ? v.c : "r", bend: Math.round(Math.max(-0.5, Math.min(0.5, +v.bend || 0)) * 100) / 100 };
  }
  data.ts = Date.now(); return data;
}
const rowPl = (v) => (v === "B" || v === "C" ? v : "A");   // План А (прежние данные) / Б / В
const rwKey = (id, t, pl) => "rw:" + id + ":" + t + (rowPl(pl) === "A" ? "" : ":" + rowPl(pl));
const rowHas = (d) => !!(d && (Object.keys(d.b || {}).length || Object.keys(d.k || {}).length || Object.keys(d.r || {}).length));
function rowAll(src) {   // весь план целиком (очистка карты и её отмена): данные заново проходят проверку
  src = src && typeof src === "object" ? src : {}; let d = {};
  Object.keys(src.b || {}).slice(0, 64).forEach((i) => { d = rowPut(d, i, src.b[i]); });
  Object.keys(src.k || {}).slice(0, 150).forEach((id) => { d = rowMark(d, "k", id, src.k[id]); });
  Object.keys(src.r || {}).slice(0, 150).forEach((id) => { d = rowMark(d, "r", id, src.r[id]); });
  d.ts = Date.now(); return d;
}
/* ---------- аккаунт сайта (вход через Telegram или Google, сервер wolfich-notify) ----------
   токен: <uid>.<срок>.<HMAC(SECRET, uid.срок)>; ACC_SECRET здесь = SECRET у wolfich-notify */
async function accOf(env, token) {
  const m = /^(\d{1,20}|g\d{1,40})\.(\d+)\.([0-9a-f]{64})$/.exec(String(token || "")); if (!m || !env.ACC_SECRET || +m[2] < Date.now()) return "";
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.ACC_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const h = Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(m[1] + "." + m[2]))), (x) => x.toString(16).padStart(2, "0")).join("");
  let d = 0; for (let i = 0; i < 64; i++) d |= h.charCodeAt(i) ^ m[3].charCodeAt(i);
  return d === 0 ? m[1] : "";
}
async function accIdx(env, acc, kind, id, name) {   // «мои альянсы / планеры» аккаунта: KV acc:<uid> = { al: {id: имя}, rp: {id: имя} }; name = null — убрать
  let o = {}; try { o = JSON.parse((await env.LIC.get("acc:" + acc)) || "{}"); } catch (e) {}
  o[kind] = o[kind] || {}; const was = o[kind][id];
  if (name == null) { if (was === undefined) return; delete o[kind][id]; } else { if (was === name) return; o[kind][id] = name; }
  await env.LIC.put("acc:" + acc, JSON.stringify(o));
}
async function roomTk(env, room, acc, ed) {   // билет комнаты планера для wolfich-notify (кто на карте, чат): <срок>.<ред>.<HMAC(ACC_SECRET, room|acc|срок|ред)>, ред=1 — может очищать чат
  const exp = Date.now() + 43200000 + "." + (ed ? 1 : 0);
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.ACC_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return exp + "." + Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(room + "|" + acc + "|" + exp.replace(".", "|")))), (x) => x.toString(16).padStart(2, "0")).join("");
}
function ackView(ack, acc, ver, full, nickOf) {   // «Ознакомлен»: моя отметка; полный список — офицерам / редакторам
  ack = ack && typeof ack === "object" ? ack : {};
  const o = { ackMe: ack[acc] ? { ts: ack[acc].ts, cur: (ack[acc].v || 0) >= (ver || 0) } : null };
  if (full) o.acks = Object.keys(ack).map((k) => ({ nick: (nickOf && nickOf(k)) || ack[k].nick || "—", ts: ack[k].ts, cur: (ack[k].v || 0) >= (ver || 0), acc: k === acc })).sort((x, y) => x.ts - y.ts);
  return o;
}
async function isAdm(env, acc) {   // владелец сайта: аккаунты из KV adm (JSON-массив uid) — видит все альянсы и управляет ими
  try { const l = JSON.parse((await env.LIC.get("adm")) || "[]"); return !!acc && Array.isArray(l) && l.includes(acc); } catch (e) { return false; }
}
const NOACC = () => json({ ok: false, err: "нужно войти на сайт через Telegram или Google", auth: true });
const rpKey = (id) => "rp:" + String(id).replace(/[^a-z0-9]/g, "").slice(0, 16);
async function rowApi(req, env) {
  if (!env.LIC) return json({ ok: false, err: "сервер не настроен" });
  let b = {}; try { b = await req.json(); } catch (e) { return json({ ok: false, err: "неверный запрос" }); }
  const op = String(b.op || ""), acc = await accOf(env, b.acc);
  if (!acc) return NOACC();
  if (op === "create") {
    const name = alStr(b.name, 40); if (!name) return json({ ok: false, err: "укажите название планера" });
    const lim = "rpc:" + acc, n = +(await env.LIC.get(lim)) || 0;
    if (n >= 5) return json({ ok: false, err: "слишком много новых планеров за день — попробуйте завтра" });
    await env.LIC.put(lim, String(n + 1), { expirationTtl: 86400 });
    const p = { id: alRnd(10), name, ts: Date.now(), own: acc, view: alRnd(12), edit: alRnd(16), data: {} };
    await env.LIC.put(rpKey(p.id), JSON.stringify(p)); await accIdx(env, acc, "rp", p.id, name);
    return json({ ok: true, id: p.id, name, view: p.view, edit: p.edit, role: "edit", data: {}, pl: "A", plans: {} });
  }
  const raw = await env.LIC.get(rpKey(alStr(b.id, 16)));
  if (!raw) { await accIdx(env, acc, "rp", alStr(b.id, 16), null); return json({ ok: false, err: "планер не найден — возможно, его удалили", gone: true }); }
  const p = JSON.parse(raw), tok = String(b.tok || "");
  if (!p.own) return json({ ok: false, err: "это планер старого образца — создайте новый", gone: true });   // до входа через аккаунты
  p.ed = p.ed || {}; p.vw = p.vw || {};   // кто открыл ссылку офицера / участника — помнится за аккаунтом
  if (tok && tok === p.edit && !p.ed[acc]) { p.ed[acc] = 1; delete p.vw[acc]; await env.LIC.put(rpKey(p.id), JSON.stringify(p)); }
  else if (tok && tok === p.view && !p.ed[acc] && !p.vw[acc] && acc !== p.own) { p.vw[acc] = 1; await env.LIC.put(rpKey(p.id), JSON.stringify(p)); }
  const role = acc === p.own || p.ed[acc] ? "edit" : p.vw[acc] ? "view" : "";
  if (!role) return json({ ok: false, err: "нет доступа к планеру — попросите ссылку у его офицеров", gone: true });
  await accIdx(env, acc, "rp", p.id, p.name);
  const pl = rowPl(b.pl), pk = pl === "A" ? "data" : "data" + pl;   // данные плана: data (А), dataB, dataC
  const rt = await roomTk(env, "p:" + p.id, acc, role === "edit");
  p.ack = p.ack && typeof p.ack === "object" ? p.ack : {};
  const out = () => { const o = { ok: true, id: p.id, name: p.name, role, pl, rt, data: p[pk] || {}, plans: { A: rowHas(p.data), B: rowHas(p.dataB), C: rowHas(p.dataC) } }; if (role === "edit") { o.view = p.view; o.edit = p.edit; } Object.assign(o, ackView(p.ack[pl], acc, (p[pk] || {}).ts, role === "edit")); return json(o); };
  if (op === "get") return out();
  if (op === "ack") {   // «Ознакомлен» с планом (своя отметка за аккаунтом; версия — время сохранения плана)
    const m = p.ack[pl] = p.ack[pl] && typeof p.ack[pl] === "object" ? p.ack[pl] : {};
    if (b.off) delete m[acc]; else m[acc] = { nick: alStr(b.nick, 32) || "—", ts: Date.now(), v: (p[pk] || {}).ts || 0 };
    const ks = Object.keys(m); if (ks.length > 300) delete m[ks[0]];
    await env.LIC.put(rpKey(p.id), JSON.stringify(p)); return out();
  }
  if (role !== "edit") return json({ ok: false, err: "нужна офицерская ссылка планера" });
  if (op === "all") { p[pk] = rowAll(b.data); await env.LIC.put(rpKey(p.id), JSON.stringify(p)); return out(); }   // очистить план / вернуть целиком
  if (op === "mark") { p[pk] = rowMark(p[pk], b.kind, b.mid2, b.v); await env.LIC.put(rpKey(p.id), JSON.stringify(p)); return out(); }   // метка или стрелка
  if (op === "save") { p[pk] = rowPut(p[pk], b.b, b.e); await env.LIC.put(rpKey(p.id), JSON.stringify(p)); return out(); }   // здание: участники (ник + вид войск) и заметка
  if (op === "rename") { const nm = alStr(b.name, 40); if (!nm) return json({ ok: false, err: "пустое название" }); p.name = nm; await env.LIC.put(rpKey(p.id), JSON.stringify(p)); return out(); }
  if (op === "relink") { if (b.which === "edit") p.edit = alRnd(16); else p.view = alRnd(12); await env.LIC.put(rpKey(p.id), JSON.stringify(p)); return out(); }
  if (op === "relink2") { delete p.ed; delete p.vw; p.edit = alRnd(16); p.view = alRnd(12); await env.LIC.put(rpKey(p.id), JSON.stringify(p)); return out(); }   // сбросить все доступы
  if (op === "delete") { if (acc !== p.own) return json({ ok: false, err: "удалить планер может только его создатель" }); await env.LIC.delete(rpKey(p.id)); await accIdx(env, acc, "rp", p.id, null); return json({ ok: true, deleted: true }); }
  return json({ ok: false, err: "неизвестная команда" });
}

async function alApi(req, env) {
  if (!env.LIC) return json({ ok: false, err: "сервер не настроен" });
  let b = {}; try { b = await req.json(); } catch (e) { return json({ ok: false, err: "неверный запрос" }); }
  const op = String(b.op || ""), acc = await accOf(env, b.acc);
  if (!acc) return NOACC();
  if (op === "mine") {   // мои альянсы и планеры (с любого устройства)
    let o = {}; try { o = JSON.parse((await env.LIC.get("acc:" + acc)) || "{}"); } catch (e) {}
    const al = {};   // { id: { name, role } } — роль из самого альянса (own / off / inv)
    for (const id of Object.keys(o.al || {}).slice(0, 30)) {
      let x = null; try { x = JSON.parse((await env.LIC.get(alKey(id))) || "null"); } catch (e) {}
      const me = x && x.v === 2 ? Object.values(x.m || {}).find((m) => m.acc === acc) : null;
      if (me) al[id] = { name: x.name, role: me.role === "own" ? "own" : me.role === "off" ? "off" : "inv" };
    }
    return json({ ok: true, al, rp: o.rp || {} });
  }
  if (op === "all") {   // витрина «Альянсы, которые пользуются нашими услугами»: название и число участников; владельцу сайта — с id для входа
    const adm = await isAdm(env, acc);
    if (!adm) return json({ ok: true, adm: false, list: [] });   // список альянсов видит только владелец сайта
    let list = null; if (!(adm && b.fresh)) { try { list = JSON.parse((await env.LIC.get("alls")) || "null"); } catch (e) {} }
    if (!Array.isArray(list)) {
      list = []; let cur;
      do {
        const r = await env.LIC.list({ prefix: "al:", cursor: cur });
        for (const k of r.keys) { let x = null; try { x = JSON.parse((await env.LIC.get(k.name)) || "null"); } catch (e) {} if (x && x.v === 2 && x.name) list.push({ id: x.id, name: x.name, n: Object.keys(x.m || {}).length, ts: x.ts || 0 }); }
        cur = r.list_complete ? null : r.cursor;
      } while (cur && list.length < 500);
      list.sort((p, q) => q.n - p.n || p.ts - q.ts);
      await env.LIC.put("alls", JSON.stringify(list), { expirationTtl: 600 });   // 10 минут — не перечитывать все альянсы на каждый заход
    }
    return json({ ok: true, adm, list: list.map((x) => (adm ? x : { name: x.name, n: x.n, ts: x.ts })) });
  }
  if (op === "create") {
    const name = alStr(b.name, 40), nick = alStr(b.nick, 32);
    if (!name || !nick) return json({ ok: false, err: "укажите название альянса и свой ник" });
    const lim = "alc:" + acc, n = +(await env.LIC.get(lim)) || 0;
    if (n >= 5) return json({ ok: false, err: "слишком много новых альянсов за день — попробуйте завтра" });
    await env.LIC.put(lim, String(n + 1), { expirationTtl: 86400 });
    const id = alRnd(10), mid = alRnd(8);
    const a = { id, name, v: 2, ts: Date.now(), inv: alRnd(12), off: alRnd(16), m: {} };
    a.m[mid] = { nick, acc, role: "own", ts: Date.now() };
    await env.LIC.put(alKey(id), JSON.stringify(a)); await accIdx(env, acc, "al", id, name);
    await env.LIC.delete("alls");   // витрина пересоберётся с новым альянсом
    return json({ ok: true, id, inv: a.inv, off: a.off, mid });
  }
  const id = alStr(b.id, 16), raw = await env.LIC.get(alKey(id));
  if (!raw) { await accIdx(env, acc, "al", id, null); return json({ ok: false, err: "альянс не найден — возможно, его удалили", gone: true }); }
  const a = JSON.parse(raw), tok = String(b.tok || "");
  if (a.v !== 2) return json({ ok: false, err: "это альянс старого образца — создайте альянс заново", gone: true });   // до входа через аккаунты
  const save = () => env.LIC.put(alKey(id), JSON.stringify(a));
  a.nt = a.nt || {};   // пометки офицеров — по аккаунту участника: не пропадают при изменении данных, удалении карточки и повторном вступлении
  for (const x of Object.keys(a.m)) { const mm = a.m[x]; if (mm.note && mm.acc && !a.nt[mm.acc]) a.nt[mm.acc] = { t: mm.note, ts: mm.nts || Date.now() }; delete mm.note; delete mm.nts; }
  let me = Object.keys(a.m).find((x) => a.m[x].acc === acc) || "";
  const adm = await isAdm(env, acc);   // владелец сайта: просмотр и управление без вступления, может завести свою карточку
  const lr = tok && tok === a.off ? "off" : tok && tok === a.inv ? "inv" : "";   // роль по ссылке (для вступления)
  if (me && lr === "off" && a.m[me].role === "mem") { a.m[me].role = "off"; await save(); }   // участник открыл офицерскую ссылку — становится офицером
  if (!me && (op === "join" || !adm)) {
    if (!lr && !adm) { await accIdx(env, acc, "al", id, null); return json({ ok: false, err: "вы не состоите в этом альянсе — вступите по пригласительной ссылке", gone: true }); }
    if (op === "view") return json({ ok: true, join: true, id: a.id, name: a.name, role: lr });
    if (op !== "join") return json({ ok: false, err: "сначала вступите в альянс" });
    const nick = alStr(b.nick, 32); if (!nick) return json({ ok: false, err: "укажите ник" });
    if (Object.keys(a.m).length >= 200) return json({ ok: false, err: "в альянсе уже 200 участников" });
    me = alRnd(8); a.m[me] = { nick, acc, role: lr === "off" ? "off" : "mem", ts: Date.now() };
    await save(); await accIdx(env, acc, "al", id, a.name);
  }
  const mr = me ? a.m[me].role : "", role = mr === "own" ? "own" : mr === "off" || adm ? "off" : "inv";
  const boss = role === "own" || role === "off";
  a.red = a.red || {};   // редакторы планера RoW (вручную, по аккаунту) — не офицеры альянса, но правят карты команд
  const pEd = boss || !!a.red[acc];
  if (me) await accIdx(env, acc, "al", id, a.name);   // владелец сайта без членства — альянс не попадает в «Мои альянсы»
  const view = () => {
    const ms = Object.keys(a.m).map((mid) => { const x = Object.assign({ mid }, a.m[mid]), n = a.nt[a.m[mid].acc]; if (n) { x.note = n.t; x.nts = n.ts; } if (a.red[a.m[mid].acc]) x.red = true; delete x.k; delete x.acc; return x; });
    const o = { ok: true, id: a.id, name: a.name, role, me, members: ms };
    if (adm) o.adm = true;
    if (boss) { o.inv = a.inv; o.off = a.off; }
    o.row = rowOf(a);
    return json(o);
  };
  if (op === "view" || op === "join") return view();
  if (op === "leave") {   // выйти из альянса (создатель — нельзя)
    if (!me) return json({ ok: false, err: "вы не состоите в этом альянсе" });
    if (mr === "own") return json({ ok: false, err: "создатель не может выйти — удалите альянс" });
    delete a.m[me]; await save(); await accIdx(env, acc, "al", id, null); return json({ ok: true, left: true });
  }
  if (op === "save") {   // свои данные (участник) или любого участника (офицер, владелец)
    const mid = String(b.mid || ""); if (!a.m[mid]) return json({ ok: false, err: "участник не найден" });
    if (!(boss || mid === me)) return json({ ok: false, err: "можно менять только свои данные" });
    const cd = alClean(b.data || {}); delete cd.note;   // пометку ставят и снимают только офицеры (op note)
    Object.assign(a.m[mid], cd, { ts: Date.now() });
    await save(); return view();
  }
  if (op === "clear") {   // удалить данные карточки (ник и место в альянсе остаются): свою — любой участник, любую — офицер и создатель
    const mid = String(b.mid || ""); if (!a.m[mid]) return json({ ok: false, err: "участник не найден" });
    if (!(boss || mid === me)) return json({ ok: false, err: "можно очистить только свою карточку" });
    ["power", "merit", "troops", "heroes", "marches", "rank", "pt", "hrs"].forEach((k) => { delete a.m[mid][k]; }); a.m[mid].ts = Date.now();   // пометка остаётся (она за аккаунтом)
    await save(); return view();
  }
  if (op === "rwteam") {   // команда RoW в карточке участника (1–3, 0 — без команды): только офицеры и создатель
    const mid = String(b.mid || ""); if (!a.m[mid]) return json({ ok: false, err: "участник не найден" });
    if (!boss) return json({ ok: false, err: "команду RoW назначают офицеры и создатель" });
    const t = Math.floor(+b.t || 0); if (t >= 1 && t <= 3) a.m[mid].rt = t; else delete a.m[mid].rt;
    await save(); return view();
  }
  if (op === "rowack") {   // «Ознакомлен» с планом команды: любой, кому карта открыта; список видят офицеры и создатель
    const t = rowT(b.t), r = a.row && a.row[t], pl = rowPl(b.pl);
    if (!r) return json({ ok: false, err: "команда RoW " + t + " ещё не создана" });
    if (!pEd && !r.open) return json({ ok: false, err: "доступ к команде закрыт" });
    let d = {}; try { d = JSON.parse((await env.LIC.get(rwKey(a.id, t, pl))) || "{}"); } catch (e) {}
    a.ack = a.ack || {}; const k = t + ":" + pl, m = a.ack[k] = a.ack[k] || {};
    if (b.off) delete m[acc]; else m[acc] = { nick: (me && a.m[me] && a.m[me].nick) || "—", ts: Date.now(), v: d.ts || 0 };
    await save();
    const ak = ackView(m, acc, d.ts, boss, (x) => { const y = Object.values(a.m).find((z) => z.acc === x); return y && y.nick; });
    return json(Object.assign({ ok: true }, ak));
  }
  if (op === "rowget") {   // карта команды RoW: офицеры и создатель — всегда (редактирование), участники — только если команда открыта (просмотр)
    const t = rowT(b.t), r = a.row && a.row[t];
    if (!r) return json({ ok: false, err: "команда RoW " + t + " ещё не создана", nort: true });
    if (!pEd && !r.open) return json({ ok: false, err: "доступ к команде закрыт — его откроет офицер или создатель альянса", closed: true, name: a.name, role });
    const ms = Object.keys(a.m).map((mid) => {
      const m = a.m[mid], o = { mid, nick: m.nick, role: m.role, rank: m.rank || 0, power: m.power || 0, merit: m.merit || 0 };
      if (a.red[m.acc]) o.red = true;
      if (m.rt) o.rt = m.rt;   // команда RoW из карточки
      if (pEd) o.marches = Array.isArray(m.marches) && m.marches.length ? m.marches : ((m.heroes || []).length || (m.troops || []).length ? [{ heroes: m.heroes || [], troops: m.troops || [] }] : []);   // офицерам — для выбора марша
      return o;
    });
    const pl = rowPl(b.pl), plans = {}; let data = {};
    for (const x of ["A", "B", "C"]) { let d = {}; try { d = JSON.parse((await env.LIC.get(rwKey(a.id, t, x))) || "{}"); } catch (e) {} plans[x] = rowHas(d); if (x === pl) data = d; }
    a.ack = a.ack || {}; const ak = ackView(a.ack[t + ":" + pl], acc, data.ts, boss, (k) => { const x = Object.values(a.m).find((y) => y.acc === k); return x && x.nick; });
    return json({ ok: true, ackMe: ak.ackMe, acks: ak.acks, id: a.id, name: a.name, role, edit: pEd, boss, t, pl, plans, open: !!r.open, me, members: ms, data, row: rowOf(a), rt: await roomTk(env, "a:" + a.id + ":" + t, acc, pEd) });
  }
  if (["rowall", "rowmark", "rowsave"].includes(op) && !pEd) return json({ ok: false, err: "нужны права на редактирование планера" });
  if (!["rowall", "rowmark", "rowsave"].includes(op) && !boss) return json({ ok: false, err: "нужен офицерский доступ" });
  if (op === "setrole") {   // участник ⇄ офицер вручную: повышать — офицеры и создатель, понижать офицеров — только создатель
    const mid = String(b.mid || ""), mm = a.m[mid]; if (!mm) return json({ ok: false, err: "участник не найден" });
    if (mm.role === "own") return json({ ok: false, err: "роль создателя не меняется" });
    const to = b.role === "off" ? "off" : "mem";
    if (to === "mem" && role !== "own" && !adm) return json({ ok: false, err: "снять офицера может только создатель альянса" });
    mm.role = to; await save(); return view();
  }
  if (op === "red") {   // права на планер вручную: участнику — редактирование карт команд RoW (без офицерских прав в альянсе)
    const mid = String(b.mid || ""), mm = a.m[mid]; if (!mm || !mm.acc) return json({ ok: false, err: "участник не найден" });
    if (mm.role === "own" || mm.role === "off") return json({ ok: false, err: "офицеры и создатель и так редактируют планер" });
    if (b.on) a.red[mm.acc] = 1; else delete a.red[mm.acc];
    await save(); return view();
  }
  if (op === "rowall") {   // план команды целиком: очистить карту или вернуть после очистки
    const t = rowT(b.t); if (!a.row || !a.row[t]) return json({ ok: false, err: "команда RoW " + t + " ещё не создана" });
    const data = rowAll(b.data); await env.LIC.put(rwKey(a.id, t, b.pl), JSON.stringify(data));
    return json({ ok: true, data });
  }
  if (op === "rowmark") {   // метка или стрелка на карте команды
    const t = rowT(b.t); if (!a.row || !a.row[t]) return json({ ok: false, err: "команда RoW " + t + " ещё не создана" });
    let data = {}; try { data = JSON.parse((await env.LIC.get(rwKey(a.id, t, b.pl))) || "{}"); } catch (e) {}
    data = rowMark(data, b.kind, b.mid2, b.v); await env.LIC.put(rwKey(a.id, t, b.pl), JSON.stringify(data));
    return json({ ok: true, data });
  }
  if (op === "rowsave") {   // здание на карте команды: участники с маршами и заметка
    const t = rowT(b.t); if (!a.row || !a.row[t]) return json({ ok: false, err: "команда RoW " + t + " ещё не создана" });
    let data = {}; try { data = JSON.parse((await env.LIC.get(rwKey(a.id, t, b.pl))) || "{}"); } catch (e) {}
    data = rowPut(data, b.b, b.e); await env.LIC.put(rwKey(a.id, t, b.pl), JSON.stringify(data));
    return json({ ok: true, data });
  }
  if (op === "rowmk") {   // создать команду RoW 1–3 (закрыта для участников, пока её не откроют)
    const t = rowT(b.t); a.row = a.row || {};
    if (!a.row[t]) { a.row[t] = { open: false, ts: Date.now() }; await save(); }
    return view();
  }
  if (op === "rowopen") {   // открыть / закрыть команду для участников альянса
    const t = rowT(b.t); if (!a.row || !a.row[t]) return json({ ok: false, err: "команда RoW " + t + " ещё не создана" });
    a.row[t].open = !!b.open; a.row[t].ots = Date.now(); await save(); return view();
  }
  if (op === "rowdel") {   // удалить команду вместе с её картой
    const t = rowT(b.t); if (a.row && a.row[t]) { delete a.row[t]; for (const x of ["A", "B", "C"]) await env.LIC.delete(rwKey(a.id, t, x)); await save(); }
    return view();
  }
  if (op === "kick") {
    const mid = String(b.mid || ""); if (!a.m[mid]) return json({ ok: false, err: "участник не найден" });
    if (a.m[mid].role === "own") return json({ ok: false, err: "создателя альянса исключить нельзя" });
    delete a.m[mid]; await save(); return view();
  }
  if (op === "note") {   // пометка офицера/создателя на карточке (что исправить); пустая — снять
    const mid = String(b.mid || ""); if (!a.m[mid]) return json({ ok: false, err: "участник не найден" });
    const t = alStr(b.note, 300), ac = a.m[mid].acc; if (!ac) return json({ ok: false, err: "участник не найден" });
    if (t) a.nt[ac] = { t, ts: Date.now() }; else delete a.nt[ac];
    await save(); return view();
  }
  if (op === "ranks") {   // ранги R4/R5 сразу нескольким участникам (по скриншоту альянса): { ranks: { <mid>: 4|5|0 } }
    const rs = b.ranks && typeof b.ranks === "object" ? b.ranks : {}; let n = 0;
    Object.keys(rs).slice(0, 200).forEach((mid) => { if (a.m[mid]) { a.m[mid].rank = [4, 5].includes(+rs[mid]) ? +rs[mid] : 0; n++; } });
    if (n) await save(); return view();
  }
  if (op === "rename") { const nm = alStr(b.name, 40); if (!nm) return json({ ok: false, err: "пустое название" }); a.name = nm; await save(); return view(); }
  if (op === "relink") {   // новая ссылка — старая перестаёт работать
    if (b.which === "off") { if (role !== "own") return json({ ok: false, err: "офицерскую ссылку меняет только создатель альянса" }); a.off = alRnd(16); }
    else a.inv = alRnd(12);
    await save(); return view();
  }
  if (op === "delete") {
    if (role !== "own") return json({ ok: false, err: "удалить альянс может только его создатель" });
    for (const t of Object.keys(a.row || {})) for (const x of ["A", "B", "C"]) await env.LIC.delete(rwKey(a.id, t, x));
    await env.LIC.delete(alKey(id)); await env.LIC.delete("alls"); return json({ ok: true, deleted: true });
  }
  return json({ ok: false, err: "неизвестная команда" });
}
