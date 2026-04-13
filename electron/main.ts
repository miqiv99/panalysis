import { app, BrowserWindow, dialog, ipcMain, session } from "electron";
import { join } from "node:path";
import { analyzeCaptureFile } from "../core/analyzer/AnalysisEngine.js";
import { IPC_CHANNELS } from "../shared/channels.js";
import type { AppBootstrapData } from "../shared/types.js";

const isDev = !app.isPackaged;

function buildContentSecurityPolicy(): string {
  if (isDev) {
    return [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' http://localhost:5173",
      "style-src 'self' 'unsafe-inline' http://localhost:5173",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      "connect-src 'self' http://localhost:5173 ws://localhost:5173",
      "worker-src 'self' blob:",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'"
    ].join("; ");
  }

  return [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "worker-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join("; ");
}

function registerContentSecurityPolicy(): void {
  const policy = buildContentSecurityPolicy();

  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        "Content-Security-Policy": [policy]
      }
    });
  });
}

function getRendererEntry(): string {
  if (isDev) {
    return "http://localhost:5173";
  }

  return join(app.getAppPath(), "dist", "index.html");
}

async function createMainWindow(): Promise<void> {
  const window = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1180,
    minHeight: 760,
    backgroundColor: "#0f172a",
    autoHideMenuBar: true,
    webPreferences: {
      preload: join(app.getAppPath(), "dist-electron", "electron", "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  if (isDev) {
    await window.loadURL(getRendererEntry());
    window.webContents.openDevTools({ mode: "detach" });
    return;
  }

  await window.loadFile(getRendererEntry());
}

function registerIpc(): void {
  ipcMain.handle(IPC_CHANNELS.GET_BOOTSTRAP_DATA, async (): Promise<AppBootstrapData> => {
      return {
        appName: "PAnalysis",
        version: app.getVersion(),
        supportedProtocols: ["SIP"],
        supportedFormats: [".pcap", ".pcapng"]
      };
    });

  ipcMain.handle(IPC_CHANNELS.OPEN_CAPTURE_FILE, async () => {
    const result = await dialog.showOpenDialog({
      title: "选择抓包文件",
      filters: [
        { name: "Capture Files", extensions: ["pcap", "pcapng"] },
        { name: "All Files", extensions: ["*"] }
      ],
      properties: ["openFile"]
    });

    if (result.canceled || result.filePaths.length === 0) {
      return null;
    }

    const [filePath] = result.filePaths;
    return analyzeCaptureFile(filePath);
  });
}

app.whenReady().then(async () => {
  registerContentSecurityPolicy();
  registerIpc();
  await createMainWindow();

  app.on("activate", async () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      await createMainWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
