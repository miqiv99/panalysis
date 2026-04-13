import { useEffect, useState } from "react";
import type { AnalysisResult, AppBootstrapData } from "../../shared/types";

const fallbackBootstrap: AppBootstrapData = {
  appName: "PAnalysis",
  version: "0.1.0",
  supportedProtocols: ["SIP"],
  supportedFormats: [".pcap", ".pcapng"]
};

export function App() {
  const [bootstrap, setBootstrap] = useState<AppBootstrapData>(fallbackBootstrap);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [isOpening, setIsOpening] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isElectronRuntime, setIsElectronRuntime] = useState(false);

  useEffect(() => {
    if (!window.panalysis) {
      setBootstrap(fallbackBootstrap);
      setIsElectronRuntime(false);
      return;
    }

    setIsElectronRuntime(true);
    window.panalysis.getBootstrapData().then(setBootstrap).catch(() => setBootstrap(fallbackBootstrap));
  }, []);

  async function handleOpenFile() {
    if (!window.panalysis) {
      setErrorMessage("当前是浏览器预览模式。请使用 Electron 窗口，或继续执行 `pnpm dev` 后在弹出的桌面窗口中操作。");
      return;
    }

    setIsOpening(true);
    setErrorMessage(null);

    try {
      const nextAnalysis = await window.panalysis.openCaptureFile();
      if (nextAnalysis) {
        setAnalysis(nextAnalysis);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "抓包文件解析失败。";
      setErrorMessage(message);
    } finally {
      setIsOpening(false);
    }
  }

  return (
    <main className="app-shell">
      <section className="hero">
        <div>
          <p className="eyebrow">Offline Packet Analysis Studio</p>
          <h1>{bootstrap.appName}</h1>
          <p className="hero-copy">
            当前聚焦 SIP 呼叫定位与媒体质量分析，支持离线导入 pcap/pcapng，
            输出呼叫状态、失败原因、RTP 流跟踪和异常提示。
          </p>
          {!isElectronRuntime ? (
            <p className="runtime-banner">
              当前是浏览器预览模式，只显示界面骨架。要打开抓包并执行真实分析，请在 `pnpm dev` 启动后使用 Electron 桌面窗口。
            </p>
          ) : null}
        </div>
        <button className="primary-button" onClick={handleOpenFile} disabled={isOpening}>
          {isOpening ? "正在打开..." : "打开抓包文件"}
        </button>
      </section>

      {errorMessage ? <section className="error-banner">{errorMessage}</section> : null}

      <section className="overview-grid">
        <article className="panel">
          <span className="panel-label">协议范围</span>
          <div className="protocol-chip-row">
            {bootstrap.supportedProtocols.map((protocol) => (
              <span className="protocol-chip" key={protocol}>
                {protocol}
              </span>
            ))}
          </div>
          <p className="muted">支持格式：{bootstrap.supportedFormats.join(" / ")}</p>
        </article>

        <article className="panel">
          <span className="panel-label">当前阶段</span>
          <h2>SIP Focus</h2>
          <p className="muted">
            SIP 解析、错误归因和 RTP 跟踪已经接入，OMCI 与 CTC OAM 先不在界面展示。
          </p>
        </article>
      </section>

      <section className="content-grid">
        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">分析摘要</span>
              <h2>{analysis?.capture.name ?? "尚未导入抓包文件"}</h2>
            </div>
            <span className="version-tag">v{bootstrap.version}</span>
          </div>
          {analysis ? (
            <div className="summary-stack">
              <p className="muted">
                路径：<code>{analysis.capture.path}</code>
              </p>
              <p className="muted">
                格式：<strong>{analysis.capture.format}</strong>，大小：
                <strong>{analysis.capture.sizeInBytes.toLocaleString()}</strong> bytes
              </p>
              {analysis.sip ? (
                <div className="stats-row">
                  <div className="stat-card">
                    <strong>{analysis.sip.callCount}</strong>
                    <span>Calls</span>
                  </div>
                  <div className="stat-card">
                    <strong>{analysis.sip.totalMessages}</strong>
                    <span>SIP Messages</span>
                  </div>
                  <div className="stat-card">
                    <strong>{analysis.sip.rtpStreams.length}</strong>
                    <span>RTP Streams</span>
                  </div>
                  <div className="stat-card">
                    <strong>{analysis.sip.rtcpReports.length}</strong>
                    <span>RTCP Reports</span>
                  </div>
                </div>
              ) : null}
              <div className="warning-list">
                {analysis.warnings.map((warning) => (
                  <p key={warning}>{warning}</p>
                ))}
              </div>
            </div>
          ) : (
            <p className="empty-state">
              先导入一个抓包文件，后续这里会展示协议统计、异常摘要和分析建议。
            </p>
          )}
        </article>

        <article className="panel">
          <span className="panel-label">SIP 状态</span>
          {analysis?.summaries.map((summary) => (
            <div className="protocol-card" key={summary.protocol}>
              <div className="protocol-card-header">
                <h3>{summary.protocol}</h3>
                <span data-status={summary.status}>{summary.status}</span>
              </div>
              <p>{summary.note}</p>
              <small>报文数：{summary.packets}</small>
            </div>
          )) ?? <p className="empty-state">导入 SIP 抓包后，这里会显示协议状态。</p>}
        </article>
      </section>

      <section className="content-grid">
        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">错误归因</span>
              <h2>SIP Issues</h2>
            </div>
          </div>
          <div className="issue-list">
            {(analysis?.sip?.issues ?? []).slice(0, 8).map((issue, index) => (
              <div className="issue-card" key={`${issue.title}-${index}`} data-severity={issue.severity}>
                <strong>{issue.title}</strong>
                <p>{issue.detail}</p>
                {issue.callId ? <small>Call-ID: {issue.callId}</small> : null}
              </div>
            ))}
            {!analysis?.sip?.issues.length ? <p className="empty-state">暂未发现明显 SIP 异常。</p> : null}
          </div>
        </article>

        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">媒体跟踪</span>
              <h2>RTP Streams</h2>
            </div>
          </div>
          <div className="issue-list">
              {(analysis?.sip?.rtpStreams ?? []).slice(0, 8).map((stream) => (
                <div className="issue-card" key={stream.id} data-severity={stream.status === "error" ? "error" : stream.status === "warning" ? "warning" : "info"}>
                  <strong>{stream.source} {"->"} {stream.destination}</strong>
                  <p>{stream.note}</p>
                  <small>
                    packets {stream.packetCount} / lost {stream.estimatedLostPackets} / out-of-order {stream.outOfOrderPackets} / jitter {stream.jitterMs ?? 0} ms
                  </small>
                </div>
            ))}
            {!analysis?.sip?.rtpStreams.length ? <p className="empty-state">暂未识别到 RTP 流。</p> : null}
          </div>
        </article>
      </section>

      <section className="content-grid">
        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">SDP 变化</span>
              <h2>SDP Diff</h2>
            </div>
          </div>
          <div className="issue-list">
            {(analysis?.sip?.sdpDiffs ?? []).slice(0, 8).map((diff) => (
              <div className="issue-card" key={`${diff.callId}-${diff.offerPacketIndex ?? 0}`} data-severity={diff.result === "incompatible" ? "error" : diff.result === "changed" ? "warning" : "info"}>
                <strong>{diff.callId}</strong>
                <p>{diff.summary}</p>
                <small>
                  added [{diff.addedCodecs.join(", ") || "-"}] / removed [{diff.removedCodecs.join(", ") || "-"}]
                </small>
              </div>
            ))}
            {!analysis?.sip?.sdpDiffs.length ? <p className="empty-state">暂未识别到可比较的 SDP Offer/Answer。</p> : null}
          </div>
        </article>

        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">RTCP 观测</span>
              <h2>RTCP Reports</h2>
            </div>
          </div>
          <div className="issue-list">
            {(analysis?.sip?.rtcpReports ?? []).slice(0, 8).map((report) => (
              <div className="issue-card" key={report.id} data-severity={(report.fractionLost ?? 0) > 25 ? "error" : (report.fractionLost ?? 0) > 0 ? "warning" : "info"}>
                <strong>{report.packetType} {report.source} {"->"} {report.destination}</strong>
                <p>{report.note}</p>
                <small>
                  lost {report.fractionLost ?? "-"} / cumulative {report.cumulativeLost ?? "-"} / jitter {report.interarrivalJitter ?? "-"}
                </small>
              </div>
            ))}
            {!analysis?.sip?.rtcpReports.length ? <p className="empty-state">暂未识别到 RTCP 报告。</p> : null}
          </div>
        </article>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <span className="panel-label">事务诊断</span>
            <h2>SIP Transactions</h2>
          </div>
        </div>
        <div className="table-shell">
          <table>
            <thead>
              <tr>
                <th>Method</th>
                <th>Call-ID</th>
                <th>Status</th>
                <th>Final Code</th>
                <th>Latency</th>
                <th>Diagnosis</th>
              </tr>
            </thead>
            <tbody>
              {(analysis?.sip?.transactions ?? []).slice(0, 20).map((transaction) => (
                <tr key={transaction.id}>
                  <td>{transaction.method}</td>
                  <td>{transaction.callId}</td>
                  <td>{transaction.finalStatus}</td>
                  <td>{transaction.finalCode ?? "-"}</td>
                  <td>{transaction.latencyMs ?? "-"}</td>
                  <td>{transaction.diagnosis}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!analysis?.sip?.transactions.length ? <p className="empty-state">导入抓包后，这里会出现事务级诊断。</p> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <span className="panel-label">时序图</span>
            <h2>Call-ID Sequence</h2>
          </div>
        </div>
        <div className="sequence-list">
          {(analysis?.sip?.sequenceDiagrams ?? []).slice(0, 3).map((diagram) => (
            <div className="sequence-card" key={diagram.callId}>
              <strong>{diagram.callId}</strong>
              <div className="sequence-steps">
                {diagram.steps.slice(0, 16).map((step, index) => (
                  <div className="sequence-step" key={`${diagram.callId}-${index}`}>
                    <span>{step.timestamp}</span>
                    <span>{step.source}</span>
                    <span>{"->"}</span>
                    <span>{step.destination}</span>
                    <span>{step.label}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
          {!analysis?.sip?.sequenceDiagrams.length ? <p className="empty-state">导入抓包后，这里会出现 Call-ID 级时序图。</p> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <span className="panel-label">呼叫汇总</span>
            <h2>SIP Dialogs</h2>
          </div>
        </div>
        <div className="table-shell">
          <table>
            <thead>
              <tr>
                <th>Call-ID</th>
                <th>Method</th>
                <th>Status</th>
                <th>Messages</th>
                <th>Failure Reason</th>
              </tr>
            </thead>
            <tbody>
              {(analysis?.sip?.dialogs ?? []).map((dialog) => (
                <tr key={dialog.callId}>
                  <td>{dialog.callId}</td>
                  <td>{dialog.method ?? "-"}</td>
                  <td>{dialog.status}</td>
                  <td>{dialog.messageCount}</td>
                  <td>{dialog.failureReason ?? (dialog.diagnostics.join(" ; ") || "-")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!analysis?.sip?.dialogs.length ? <p className="empty-state">导入抓包后，这里会出现呼叫级汇总。</p> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <span className="panel-label">报文列表</span>
            <h2>Packet Timeline</h2>
          </div>
        </div>
        <div className="table-shell">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Time</th>
                <th>Protocol</th>
                <th>Summary</th>
                <th>Length</th>
              </tr>
            </thead>
            <tbody>
              {(analysis?.packets ?? []).map((packet) => (
                <tr key={`${packet.index}-${packet.timestamp}`}>
                  <td>{packet.index}</td>
                  <td>{packet.timestamp}</td>
                  <td>{packet.protocol}</td>
                  <td>{packet.summary}</td>
                  <td>{packet.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!analysis && <p className="empty-state">导入抓包后，这里会出现逐包时间线。</p>}
        </div>
      </section>
    </main>
  );
}
