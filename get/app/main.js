/* WOLFICH · Автопоход — программа для Windows (Electron).
   Окно настроек + окно бота поверх игры. Помощник (мышь/колесо/Esc) запускается сам с правами администратора. */
const { app, BrowserWindow, ipcMain, session, desktopCapturer, Menu, shell, net } = require("electron");
const path = require("path");
const fs = require("fs");
const http = require("http");
const { spawn, execFile } = require("child_process");

const PORT = 47321;
// не выводить в консоль служебные ошибки Chromium (например, обрывы соединения с Cloudflare из России)
app.commandLine.appendSwitch("log-level", "3");
let win = null;

if (!app.requestSingleInstanceLock()) { app.quit(); }
app.on("second-instance", () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });

/* запрос к помощнику: без заголовка Origin, с таймаутом */
function helper(cmd, q, timeout) {
  return new Promise((resolve, reject) => {
    const qs = Object.keys(q || {}).map((k) => k + "=" + encodeURIComponent(q[k])).join("&");
    // помощник слушает http://localhost:47321/ — заголовок Host должен быть именно «localhost», иначе Windows отвечает 400
    const req = http.get({ host: "127.0.0.1", port: PORT, path: "/" + cmd + (qs ? "?" + qs : ""), headers: { Host: "localhost:" + PORT }, timeout: timeout || 20000 }, (res) => {
      let d = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (d += c));
      res.on("end", () => { try { resolve(JSON.parse(d.replace(/^﻿/, ""))); } catch (e) { reject(new Error("bad answer")); } });
    });
    req.on("timeout", () => { req.destroy(new Error("timeout")); });
    req.on("error", (e) => reject(e));
  });
}

/* запуск помощника: скрипт из модуля бота → файл .ps1 → PowerShell с правами администратора, скрытое окно */
async function startHelper(text) {
  const want = +((/v = (\d+); stopped/.exec(String(text)) || [])[1] || 0);
  try {
    const j = await helper("ping", {}, 2500);
    if (j && j.ok && (j.v || 0) >= want) return { ok: true, already: true, v: j.v };
    if (j && j.ok) { await helper("quit", {}, 2000).catch(() => {}); await new Promise((r) => setTimeout(r, 1500)); }   // старый помощник — заменяем новым
  } catch (e) {}
  // тот же WOLFICH-Helper.bat, что и на сайте: он сам просит права администратора (видимое окно Windows)
  const file = path.join(app.getPath("userData"), "WOLFICH-Helper.bat");
  const bat = String(text).replace(/\r?\n/g, "\n").replace(/\npause\n/, "\n").replace(/\n/g, "\r\n");   // без «Нажмите любую клавишу» после выхода
  fs.writeFileSync(file, bat, "utf8");
  const err = await shell.openPath(file);
  if (err) return { ok: false, err: "не удалось открыть помощник: " + err };
  // ждём, пока помощник поднимется (пользователь подтверждает запрос администратора)
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    try { const j = await helper("ping", {}, 1500); if (j && j.ok) return { ok: true, v: j.v }; } catch (e) {}
  }
  return { ok: false, err: "помощник не ответил за минуту — подтвердите запрос администратора или перезапустите программу" };
}

ipcMain.handle("helper", (e, cmd, q) => helper(cmd, q));
ipcMain.handle("start-helper", (e, text) => startHelper(text));
ipcMain.handle("app-version", () => app.getVersion());

ipcMain.handle("minimize", () => { if (win) win.minimize(); });

/* ---------- эмулятор LDPlayer: управление через ADB (без мыши, работает и при свёрнутом окне) ---------- */
function run(file, args, opts) {
  return new Promise((resolve) => {
    execFile(file, args, Object.assign({ windowsHide: true, timeout: 20000, maxBuffer: 64 * 1024 * 1024, encoding: "buffer" }, opts || {}), (err, out, errOut) => {
      resolve({ code: err ? (err.code || 1) : 0, out: out || Buffer.alloc(0), err: (errOut ? errOut.toString() : "") + (err && !errOut ? String(err.message || err) : "") });
    });
  });
}
async function findAdb(hint) {
  const cand = [];
  if (hint) cand.push(hint.replace(/[\\/]+$/, "") + (/adb\.exe$/i.test(hint) ? "" : "\\adb.exe"));
  // путь установки LDPlayer из реестра
  for (const key of ["HKCU\\Software\\XuanZhi\\LDPlayer9", "HKCU\\Software\\XuanZhi\\LDPlayer", "HKLM\\SOFTWARE\\XuanZhi\\LDPlayer9", "HKLM\\SOFTWARE\\WOW6432Node\\XuanZhi\\LDPlayer9"]) {
    const r = await run("reg.exe", ["query", key, "/v", "InstallDir"], { encoding: "utf8", timeout: 5000 });
    const m = /InstallDir\s+REG_\w+\s+(.+)/i.exec(String(r.out || ""));
    if (m) cand.push(m[1].trim().replace(/[\\/]+$/, "") + "\\adb.exe");
  }
  for (const d of ["C:", "D:", "E:", "F:"]) for (const sub of ["\\LDPlayer\\LDPlayer9", "\\LDPlayer\\LDPlayer4.0", "\\Program Files\\LDPlayer\\LDPlayer9", "\\LDPlayer9"]) cand.push(d + sub + "\\adb.exe");
  for (const c of cand) { try { if (fs.existsSync(c)) return c; } catch (e) {} }
  return "";
}
ipcMain.handle("adb-find", (e, hint) => findAdb(hint));
ipcMain.handle("adb", async (e, adbPath, args, bin) => {
  const r = await run(adbPath, args || [], bin ? {} : { encoding: "utf8" });
  return { code: r.code, out: bin ? Buffer.from(r.out) : String(r.out || ""), err: r.err };
});

/* модуль бота: свежий с сайта (Cloudflare); если не отдаётся (из России Cloudflare обрывает загрузку) —
   с зеркала в Yandex Cloud; без сети — копия из программы. Что сработало в прошлый раз — пробуем первым. */
const MODULE_URL = "https://wolfich-bot.pages.dev/owner.bin";   // с 1.14 — отдельный хостинг бота (ветка bot)
const MIRROR_URL = "https://storage.yandexcloud.net/wolfich-mirror/owner.bin";
async function fetchBin(url, ms) {
  const ac = new AbortController(), tm = setTimeout(() => ac.abort(), ms);
  try {
    const r = await net.fetch(url + "?t=" + Date.now(), { cache: "no-store", signal: ac.signal });
    if (!r.ok) return null;
    const b = Buffer.from(await r.arrayBuffer());
    return b.length > 64 && b.slice(0, 4).toString() === "WOL1" ? b : null;
  } catch (e) { return null; } finally { clearTimeout(tm); }
}
ipcMain.handle("get-module", async () => {
  const flag = path.join(app.getPath("userData"), "prefer-mirror");
  let mirrorFirst = false; try { mirrorFirst = fs.existsSync(flag); } catch (e) {}
  const order = mirrorFirst ? [["mirror", MIRROR_URL], ["site", MODULE_URL]] : [["site", MODULE_URL], ["mirror", MIRROR_URL]];
  for (const [from, url] of order) {
    const b = await fetchBin(url, from === "site" ? 12000 : 20000);
    if (b) {
      try { if (from === "mirror") fs.writeFileSync(flag, "1"); else if (mirrorFirst) fs.unlinkSync(flag); } catch (e) {}
      return { data: b, from };
    }
  }
  return { data: fs.readFileSync(path.join(__dirname, "owner.bin")), from: "local" };
});

/* окно программы: главное (inst = "") или окно бота для отдельного эмулятора (inst = серийный номер ADB) */
const instWins = {};
function makeWindow(inst) {
  const w = new BrowserWindow({
    width: 520, height: 780, minWidth: 420, minHeight: 520,
    title: inst ? "WOLFICH · " + inst : "WOLFICH · Автопоход",
    backgroundColor: "#0b0a14",
    autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, nodeIntegration: false, nodeIntegrationInSubFrames: true, backgroundThrottling: false },
  });
  w.loadFile(path.join(__dirname, "index.html"), inst ? { query: { inst } } : undefined);
  // «Окно поверх игры» — отдельное окно всегда сверху
  w.webContents.setWindowOpenHandler(({ url }) => {
    if (url && /^https?:/i.test(url)) { shell.openExternal(url); return { action: "deny" }; }
    return {
      action: "allow",
      overrideBrowserWindowOptions: {
        width: 300, height: 440, minWidth: 240, minHeight: 300,
        alwaysOnTop: true, autoHideMenuBar: true, backgroundColor: "#14111f", title: inst ? "Бот · " + inst : "WOLFICH · Автопоход",
        webPreferences: { backgroundThrottling: false },
      },
    };
  });
  w.webContents.on("did-create-window", (child) => {
    child.setAlwaysOnTop(true, "screen-saver");   // поверх игры даже в полноэкранном окне
    child.setMenu(null);
  });
  return w;
}
function createWindow() {
  win = makeWindow("");
  win.on("close", () => { BrowserWindow.getAllWindows().forEach((w) => { if (w !== win) w.destroy(); }); });
  win.on("closed", () => { win = null; });
}
ipcMain.handle("open-instance", (e, inst) => {
  inst = String(inst || "").trim();
  if (!inst) return false;
  const old = instWins[inst];
  if (old && !old.isDestroyed()) { if (old.isMinimized()) old.restore(); old.focus(); return true; }
  const w = makeWindow(inst);
  instWins[inst] = w;
  w.on("closed", () => { delete instWins[inst]; });
  return true;
});

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  // захват экрана: сразу весь основной экран, без окна выбора
  session.defaultSession.setDisplayMediaRequestHandler((request, callback) => {
    desktopCapturer.getSources({ types: ["screen"] }).then((src) => callback(src.length ? { video: src[0] } : {})).catch(() => callback({}));
  });
  createWindow();
});

app.on("window-all-closed", () => {
  helper("quit", {}, 1500).catch(() => {}).finally(() => app.quit());
});
