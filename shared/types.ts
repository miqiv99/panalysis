export type SupportedProtocol = "OMCI" | "CTC OAM" | "SIP";

export interface AppBootstrapData {
  appName: string;
  version: string;
  supportedProtocols: SupportedProtocol[];
  supportedFormats: string[];
}

export interface CaptureFileSummary {
  path: string;
  name: string;
  sizeInBytes: number;
  format: "pcap" | "pcapng" | "unknown";
}

export interface PacketRecord {
  index: number;
  timestamp: string;
  protocol: string;
  summary: string;
  length: number;
}

export interface ProtocolSummary {
  protocol: SupportedProtocol;
  packets: number;
  status: "ready" | "planned";
  note: string;
}

export interface SipMessageRecord {
  packetIndex: number;
  timestamp: string;
  transport: "UDP" | "TCP";
  direction: "request" | "response";
  source: string;
  destination: string;
  callId: string;
  method?: string;
  requestUri?: string;
  statusCode?: number;
  reasonPhrase?: string;
  cseq?: string;
  hasSdp: boolean;
  isRetransmission: boolean;
  summary: string;
}

export interface SipIssue {
  severity: "error" | "warning" | "info";
  title: string;
  detail: string;
  callId?: string;
  packetIndex?: number;
}

export interface SipDialogSummary {
  callId: string;
  startTime: string;
  endTime: string;
  from: string;
  to: string;
  requestUri?: string;
  method?: string;
  messageCount: number;
  status: "established" | "failed" | "incomplete" | "cancelled";
  failureReason?: string;
  diagnostics: string[];
  mediaCount: number;
}

export interface SipTransactionSummary {
  id: string;
  callId: string;
  method: string;
  cseqNumber?: number;
  branch?: string;
  requestPacketIndex: number;
  startTime: string;
  endTime?: string;
  source: string;
  destination: string;
  requestCount: number;
  responseCount: number;
  provisionalCount: number;
  finalStatus: "success" | "failed" | "timeout" | "challenged" | "cancelled" | "incomplete";
  finalCode?: number;
  diagnosis: string;
  latencyMs?: number;
  relatedPackets: number[];
}

export interface SipSequenceStep {
  packetIndex?: number;
  timestamp: string;
  source: string;
  destination: string;
  kind: "sip" | "rtp" | "rtcp" | "note";
  label: string;
}

export interface SipSequenceDiagram {
  callId: string;
  participants: string[];
  steps: SipSequenceStep[];
}

export interface SdpDiffSummary {
  callId: string;
  offerPacketIndex?: number;
  answerPacketIndex?: number;
  result: "unchanged" | "changed" | "incompatible" | "missing-answer";
  summary: string;
  addedCodecs: string[];
  removedCodecs: string[];
  changedConnections: string[];
  changedDirections: string[];
}

export interface RtcpSummary {
  id: string;
  callId?: string;
  packetIndex: number;
  timestamp: string;
  source: string;
  destination: string;
  packetType: "SR" | "RR" | "XR" | "SDES" | "BYE" | "APP" | "UNKNOWN";
  ssrc?: string;
  reportCount: number;
  fractionLost?: number;
  cumulativeLost?: number;
  interarrivalJitter?: number;
  note: string;
}

export interface RtpStreamSummary {
  id: string;
  callId?: string;
  source: string;
  destination: string;
  ssrc: string;
  payloadType: number;
  packetCount: number;
  firstSeen: string;
  lastSeen: string;
  estimatedLostPackets: number;
  longGapCount?: number;
  outOfOrderPackets: number;
  markerPackets: number;
  jitterMs?: number;
  maxJitterMs?: number;
  clockRate?: number;
  status: "healthy" | "warning" | "error" | "idle";
  note: string;
}

export interface SipOverview {
  totalMessages: number;
  requestCount: number;
  responseCount: number;
  callCount: number;
  issues: SipIssue[];
  dialogs: SipDialogSummary[];
  transactions: SipTransactionSummary[];
  messages: SipMessageRecord[];
  sequenceDiagrams: SipSequenceDiagram[];
  sdpDiffs: SdpDiffSummary[];
  rtcpReports: RtcpSummary[];
  rtpStreams: RtpStreamSummary[];
}

export interface AnalysisResult {
  capture: CaptureFileSummary;
  packets: PacketRecord[];
  summaries: ProtocolSummary[];
  warnings: string[];
  sip?: SipOverview;
}

declare global {
  interface Window {
    panalysis?: {
      getBootstrapData: () => Promise<AppBootstrapData>;
      openCaptureFile: () => Promise<AnalysisResult | null>;
    };
  }
}

export {};
