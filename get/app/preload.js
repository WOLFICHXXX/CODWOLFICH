const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("wolfApp", {
  build: 5,
  helper: (cmd, q) => ipcRenderer.invoke("helper", cmd, q || {}),
  startHelper: (text) => ipcRenderer.invoke("start-helper", text),
  version: () => ipcRenderer.invoke("app-version"),
  getModule: () => ipcRenderer.invoke("get-module"),
  minimize: () => ipcRenderer.invoke("minimize"),
  adbFind: (hint) => ipcRenderer.invoke("adb-find", hint),
  adb: (path, args, bin) => ipcRenderer.invoke("adb", path, args, bin),
  openInstance: (inst) => ipcRenderer.invoke("open-instance", inst),
});
