import { useEffect, useState } from "react";
import type { AnalysisResult, AppBootstrapData } from "../../shared/types";
import { LANGUAGE_STORAGE_KEY, type AppLanguage, uiCopy } from "./i18n";

const fallbackBootstrap: AppBootstrapData = {
  appName: "PAnalysis",
  version: "0.1.0",
  supportedProtocols: ["SIP"],
  supportedFormats: [".pcap", ".pcapng"]
};

export function App() {
  const [language, setLanguage] = useState<AppLanguage>("zh-CN");
  const [bootstrap, setBootstrap] = useState<AppBootstrapData>(fallbackBootstrap);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [isOpening, setIsOpening] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isElectronRuntime, setIsElectronRuntime] = useState(false);
  const copy = uiCopy[language];

  useEffect(() => {
    const savedLanguage = window.localStorage.getItem(LANGUAGE_STORAGE_KEY);
    if (savedLanguage === "zh-CN" || savedLanguage === "en") {
      setLanguage(savedLanguage);
    }
  }, []);

  useEffect(() => {
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
  }, [language]);

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
      setErrorMessage(copy.browserPreviewError);
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
          <p className="eyebrow">{copy.heroEyebrow}</p>
          <h1>{bootstrap.appName}</h1>
          <p className="hero-copy">{copy.heroCopy}</p>
          {!isElectronRuntime ? (
            <p className="runtime-banner">{copy.runtimeBanner}</p>
          ) : null}
        </div>
        <div className="hero-actions">
          <div className="language-switch" aria-label={copy.languageLabel}>
            <button
              className="language-button"
              data-active={language === "zh-CN"}
              onClick={() => setLanguage("zh-CN")}
              type="button"
            >
              中文
            </button>
            <button
              className="language-button"
              data-active={language === "en"}
              onClick={() => setLanguage("en")}
              type="button"
            >
              English
            </button>
          </div>
          <button className="primary-button" onClick={handleOpenFile} disabled={isOpening}>
            {isOpening ? copy.openingCaptureFile : copy.openCaptureFile}
          </button>
        </div>
      </section>

      {errorMessage ? <section className="error-banner">{errorMessage}</section> : null}

      <section className="overview-grid">
        <article className="panel">
          <span className="panel-label">{copy.protocolScope}</span>
          <div className="protocol-chip-row">
            {bootstrap.supportedProtocols.map((protocol) => (
              <span className="protocol-chip" key={protocol}>
                {protocol}
              </span>
            ))}
          </div>
          <p className="muted">{copy.supportedFormats}: {bootstrap.supportedFormats.join(" / ")}</p>
        </article>

        <article className="panel">
          <span className="panel-label">{copy.currentStage}</span>
          <h2>{copy.stageTitle}</h2>
          <p className="muted">{copy.stageDescription}</p>
        </article>
      </section>

      <section className="content-grid">
        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">{copy.analysisSummary}</span>
              <h2>{analysis?.capture.name ?? copy.noCaptureImported}</h2>
            </div>
            <span className="version-tag">v{bootstrap.version}</span>
          </div>
          {analysis ? (
            <div className="summary-stack">
              <p className="muted">
                {copy.pathLabel}: <code>{analysis.capture.path}</code>
              </p>
              <p className="muted">
                {copy.formatLabel}: <strong>{analysis.capture.format}</strong>，{copy.sizeLabel}：
                <strong>{analysis.capture.sizeInBytes.toLocaleString()}</strong> {copy.bytes}
              </p>
              {analysis.sip ? (
                <div className="stats-row">
                  <div className="stat-card">
                    <strong>{analysis.sip.callCount}</strong>
                    <span>{copy.calls}</span>
                  </div>
                  <div className="stat-card">
                    <strong>{analysis.sip.totalMessages}</strong>
                    <span>{copy.sipMessages}</span>
                  </div>
                  <div className="stat-card">
                    <strong>{analysis.sip.rtpStreams.length}</strong>
                    <span>{copy.rtpStreams}</span>
                  </div>
                  <div className="stat-card">
                    <strong>{analysis.sip.rtcpReports.length}</strong>
                    <span>{copy.rtcpReports}</span>
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
            <p className="empty-state">{copy.summaryEmpty}</p>
          )}
        </article>

        <article className="panel">
          <span className="panel-label">{copy.sipStatus}</span>
          {analysis?.summaries.map((summary) => (
            <div className="protocol-card" key={summary.protocol}>
              <div className="protocol-card-header">
                <h3>{summary.protocol}</h3>
                <span data-status={summary.status}>{summary.status === "ready" ? copy.ready : copy.planned}</span>
              </div>
              <p>{summary.protocol === "SIP" ? copy.protocolStatusNote : summary.note}</p>
              <small>{copy.packetCount}: {summary.packets}</small>
            </div>
          )) ?? <p className="empty-state">{copy.protocolStatusEmpty}</p>}
        </article>
      </section>

      <section className="content-grid">
        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">{copy.issueAttribution}</span>
              <h2>{copy.sipIssues}</h2>
            </div>
          </div>
          <div className="issue-list">
            {(analysis?.sip?.issues ?? []).slice(0, 8).map((issue, index) => (
              <div className="issue-card" key={`${issue.title}-${index}`} data-severity={issue.severity}>
                <strong>{issue.title}</strong>
                <p>{issue.detail}</p>
                {issue.callId ? <small>{copy.callId}: {issue.callId}</small> : null}
              </div>
            ))}
            {!analysis?.sip?.issues.length ? <p className="empty-state">{copy.noSipIssues}</p> : null}
          </div>
        </article>

        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">{copy.mediaTracking}</span>
              <h2>{copy.rtpStreams}</h2>
            </div>
          </div>
          <div className="issue-list">
              {(analysis?.sip?.rtpStreams ?? []).slice(0, 8).map((stream) => (
                <div className="issue-card" key={stream.id} data-severity={stream.status === "error" ? "error" : stream.status === "warning" ? "warning" : "info"}>
                  <strong>{stream.source} {"->"} {stream.destination}</strong>
                  <p>{stream.note}</p>
                  <small>
                    {copy.packets} {stream.packetCount} / {copy.lost} {stream.estimatedLostPackets} / {copy.outOfOrder} {stream.outOfOrderPackets} / {copy.jitter} {stream.jitterMs ?? 0} ms
                  </small>
                </div>
            ))}
            {!analysis?.sip?.rtpStreams.length ? <p className="empty-state">{copy.noRtpStreams}</p> : null}
          </div>
        </article>
      </section>

      <section className="content-grid">
        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">{copy.sdpChanges}</span>
              <h2>{copy.sdpDiff}</h2>
            </div>
          </div>
          <div className="issue-list">
            {(analysis?.sip?.sdpDiffs ?? []).slice(0, 8).map((diff) => (
              <div className="issue-card" key={`${diff.callId}-${diff.offerPacketIndex ?? 0}`} data-severity={diff.result === "incompatible" ? "error" : diff.result === "changed" ? "warning" : "info"}>
                <strong>{diff.callId}</strong>
                <p>{diff.summary}</p>
                <small>
                  {copy.added} [{diff.addedCodecs.join(", ") || copy.unknown}] / {copy.removed} [{diff.removedCodecs.join(", ") || copy.unknown}]
                </small>
              </div>
            ))}
            {!analysis?.sip?.sdpDiffs.length ? <p className="empty-state">{copy.noSdpDiffs}</p> : null}
          </div>
        </article>

        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">{copy.rtcpObservation}</span>
              <h2>{copy.rtcpReports}</h2>
            </div>
          </div>
          <div className="issue-list">
            {(analysis?.sip?.rtcpReports ?? []).slice(0, 8).map((report) => (
              <div className="issue-card" key={report.id} data-severity={(report.fractionLost ?? 0) > 25 ? "error" : (report.fractionLost ?? 0) > 0 ? "warning" : "info"}>
                <strong>{report.packetType} {report.source} {"->"} {report.destination}</strong>
                <p>{report.note}</p>
                <small>
                  {copy.lost} {report.fractionLost ?? copy.unknown} / {copy.cumulative} {report.cumulativeLost ?? copy.unknown} / {copy.jitter} {report.interarrivalJitter ?? copy.unknown}
                </small>
              </div>
            ))}
            {!analysis?.sip?.rtcpReports.length ? <p className="empty-state">{copy.noRtcpReports}</p> : null}
          </div>
        </article>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <span className="panel-label">{copy.transactionDiagnostics}</span>
            <h2>SIP Transactions</h2>
          </div>
        </div>
        <div className="table-shell">
          <table>
            <thead>
              <tr>
                <th>{copy.methods}</th>
                <th>{copy.callId}</th>
                <th>{copy.status}</th>
                <th>{copy.finalCode}</th>
                <th>{copy.latency}</th>
                <th>{copy.diagnosis}</th>
              </tr>
            </thead>
            <tbody>
              {(analysis?.sip?.transactions ?? []).slice(0, 20).map((transaction) => (
                <tr key={transaction.id}>
                  <td>{transaction.method}</td>
                  <td>{transaction.callId}</td>
                  <td>{transaction.finalStatus}</td>
                  <td>{transaction.finalCode ?? copy.unknown}</td>
                  <td>{transaction.latencyMs ?? copy.unknown}</td>
                  <td>{transaction.diagnosis}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!analysis?.sip?.transactions.length ? <p className="empty-state">{copy.noTransactions}</p> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <span className="panel-label">{copy.sequenceDiagram}</span>
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
          {!analysis?.sip?.sequenceDiagrams.length ? <p className="empty-state">{copy.noSequences}</p> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <span className="panel-label">{copy.dialogSummary}</span>
            <h2>SIP Dialogs</h2>
          </div>
        </div>
        <div className="table-shell">
          <table>
            <thead>
              <tr>
                <th>{copy.callId}</th>
                <th>{copy.methods}</th>
                <th>{copy.status}</th>
                <th>{copy.messages}</th>
                <th>{copy.failureReason}</th>
              </tr>
            </thead>
            <tbody>
              {(analysis?.sip?.dialogs ?? []).map((dialog) => (
                <tr key={dialog.callId}>
                  <td>{dialog.callId}</td>
                  <td>{dialog.method ?? copy.unknown}</td>
                  <td>{dialog.status}</td>
                  <td>{dialog.messageCount}</td>
                  <td>{dialog.failureReason ?? (dialog.diagnostics.join(" ; ") || copy.unknown)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!analysis?.sip?.dialogs.length ? <p className="empty-state">{copy.noDialogs}</p> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <span className="panel-label">{copy.packetTimeline}</span>
            <h2>Packet Timeline</h2>
          </div>
        </div>
        <div className="table-shell">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>{copy.time}</th>
                <th>{copy.protocol}</th>
                <th>{copy.summary}</th>
                <th>{copy.length}</th>
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
          {!analysis && <p className="empty-state">{copy.noPackets}</p>}
        </div>
      </section>
    </main>
  );
}
