import { contextBridge, ipcRenderer } from "electron";
import { IPC_CHANNELS } from "../shared/channels.js";
import type { AnalysisResult, AppBootstrapData } from "../shared/types.js";

const desktopApi = {
  getBootstrapData(): Promise<AppBootstrapData> {
    return ipcRenderer.invoke(IPC_CHANNELS.GET_BOOTSTRAP_DATA);
  },
  openCaptureFile(): Promise<AnalysisResult | null> {
    return ipcRenderer.invoke(IPC_CHANNELS.OPEN_CAPTURE_FILE);
  }
};

contextBridge.exposeInMainWorld("panalysis", desktopApi);

