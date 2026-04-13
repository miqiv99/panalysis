const { contextBridge, ipcRenderer } = require("electron");

const IPC_CHANNELS = {
  GET_BOOTSTRAP_DATA: "app:get-bootstrap-data",
  OPEN_CAPTURE_FILE: "capture:open-file"
} as const;

const desktopApi = {
  getBootstrapData() {
    return ipcRenderer.invoke(IPC_CHANNELS.GET_BOOTSTRAP_DATA);
  },
  openCaptureFile() {
    return ipcRenderer.invoke(IPC_CHANNELS.OPEN_CAPTURE_FILE);
  }
};

contextBridge.exposeInMainWorld("panalysis", desktopApi);
