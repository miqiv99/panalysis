import type {
  RtcpSummary,
  RtpStreamSummary,
  SipDialogSummary,
  SipSequenceDiagram,
  SipSequenceStep,
  SdpDiffSummary,
  SipIssue,
  SipMessageRecord,
  SipOverview,
  SipTransactionSummary
} from "../../../shared/types.js";
import type { DecodedNetworkPacket } from "../../decoder/PacketDecoder.js";
import {
  extractSipMessagesFromTcpBuffer,
  getSipHeader,
  getSipTag,
  isSipPayload,
  parseSdp,
  parseSipMessage,
  summarizeSipMessage,
  type ParsedSipMessage
} from "./SipDecoder.js";

interface SipMessageEnvelope {
  packetIndex: number;
  timestamp: string;
  transport: "UDP" | "TCP";
  source: string;
  destination: string;
  sourceAddress: string;
  destinationAddress: string;
  sourcePort: number;
  destinationPort: number;
  callId: string;
  cseq?: string;
  cseqNumber?: number;
  cseqMethod?: string;
  viaBranch?: string;
  hasAuthorization: boolean;
  fromTag?: string;
  toTag?: string;
  message: ParsedSipMessage;
}

interface ExpectedMedia {
  callId: string;
  address: string;
  port: number;
  type: string;
  direction?: "sendrecv" | "sendonly" | "recvonly" | "inactive";
  clockRates: Record<number, number>;
}

interface RtpInspectionResult {
  streams: RtpStreamSummary[];
  rtcpReports: RtcpSummary[];
  issues: SipIssue[];
}

interface TransactionAnalysis {
  transactions: SipTransactionSummary[];
  issues: SipIssue[];
}

interface TcpChunkMeta {
  start: number;
  end: number;
  packetIndex: number;
  timestamp: string;
}

interface TcpSegment {
  sequenceNumber: number;
  payload: Buffer;
  packetIndex: number;
  timestamp: string;
}

interface TcpReassemblyState {
  sourceAddress: string;
  destinationAddress: string;
  sourcePort: number;
  destinationPort: number;
  buffer: Buffer;
  chunks: TcpChunkMeta[];
  nextSequenceNumber?: number;
  pending: TcpSegment[];
}

const STATIC_RTP_CLOCK_RATES: Record<number, number> = {
  0: 8000,
  3: 8000,
  4: 8000,
  8: 8000,
  9: 8000,
  18: 8000,
  26: 90000,
  31: 90000,
  32: 90000,
  34: 90000
};

function parseTimestamp(value: string): number {
  return Date.parse(value);
}

function parseCseq(cseq: string | undefined): { number?: number; method?: string } {
  if (!cseq) {
    return {};
  }

  const match = /^(\d+)\s+([A-Z]+)$/i.exec(cseq.trim());
  if (!match) {
    return {};
  }

  return {
    number: Number.parseInt(match[1], 10),
    method: match[2].toUpperCase()
  };
}

function getViaBranch(message: ParsedSipMessage): string | undefined {
  const via = getSipHeader(message, "via");
  if (!via) {
    return undefined;
  }

  const firstVia = via.split(",")[0]?.trim() ?? via;
  const match = /(?:^|;)\s*branch=([^;,\s]+)/i.exec(firstVia);
  return match?.[1]?.trim();
}

function createEnvelope(
  packetIndex: number,
  timestamp: string,
  transport: "UDP" | "TCP",
  sourceAddress: string,
  destinationAddress: string,
  sourcePort: number,
  destinationPort: number,
  message: ParsedSipMessage
): SipMessageEnvelope {
  const callId = getSipHeader(message, "call-id") ?? "no-call-id";
  const cseq = getSipHeader(message, "cseq");
  const parsedCseq = parseCseq(cseq);

  return {
    packetIndex,
    timestamp,
    transport,
    source: `${sourceAddress}:${sourcePort}`,
    destination: `${destinationAddress}:${destinationPort}`,
    sourceAddress,
    destinationAddress,
    sourcePort,
    destinationPort,
    callId,
    cseq,
    cseqNumber: parsedCseq.number,
    cseqMethod: parsedCseq.method,
    viaBranch: getViaBranch(message),
    hasAuthorization: Boolean(getSipHeader(message, "authorization") || getSipHeader(message, "proxy-authorization")),
    fromTag: getSipTag(getSipHeader(message, "from")),
    toTag: getSipTag(getSipHeader(message, "to")),
    message
  };
}

function createMessageRecord(envelope: SipMessageEnvelope, isRetransmission: boolean): SipMessageRecord {
  return {
    packetIndex: envelope.packetIndex,
    timestamp: envelope.timestamp,
    transport: envelope.transport,
    direction: envelope.message.kind,
    source: envelope.source,
    destination: envelope.destination,
    callId: envelope.callId,
    method: envelope.message.method,
    requestUri: envelope.message.requestUri,
    statusCode: envelope.message.statusCode,
    reasonPhrase: envelope.message.reasonPhrase,
    cseq: envelope.cseq,
    hasSdp: (getSipHeader(envelope.message, "content-type") ?? "").toLowerCase().includes("sdp"),
    isRetransmission,
    summary: summarizeSipMessage(envelope.message, envelope.source, envelope.destination)
  };
}

function parseUdpSipMessages(decodedPackets: DecodedNetworkPacket[]): SipMessageEnvelope[] {
  const messages: SipMessageEnvelope[] = [];

  for (const packet of decodedPackets) {
    if (packet.transportProtocol !== "UDP" || !packet.payload || packet.payload.length === 0) {
      continue;
    }

    if (!packet.sourceAddress || !packet.destinationAddress || packet.sourcePort === undefined || packet.destinationPort === undefined) {
      continue;
    }

    if (!isSipPayload(packet.payload, packet.sourcePort, packet.destinationPort)) {
      continue;
    }

    const message = parseSipMessage(packet.payload);
    if (!message) {
      continue;
    }

    messages.push(
      createEnvelope(
        packet.packetIndex,
        packet.timestamp,
        "UDP",
        packet.sourceAddress,
        packet.destinationAddress,
        packet.sourcePort,
        packet.destinationPort,
        message
      )
    );
  }

  return messages;
}

function appendTcpPayload(state: TcpReassemblyState, payload: Buffer, packetIndex: number, timestamp: string): void {
  if (payload.length === 0) {
    return;
  }

  const start = state.buffer.length;
  state.buffer = Buffer.concat([state.buffer, payload]);
  state.chunks.push({
    start,
    end: start + payload.length - 1,
    packetIndex,
    timestamp
  });
}

function consumeTcpMessages(state: TcpReassemblyState, target: SipMessageEnvelope[]): void {
  const extracted = extractSipMessagesFromTcpBuffer(state.buffer);
  let consumed = 0;

  for (const messageBuffer of extracted.messages) {
    consumed += messageBuffer.length;
    const message = parseSipMessage(messageBuffer);
    if (!message) {
      continue;
    }

    const endOffset = consumed - 1;
    const ownerChunk = [...state.chunks].reverse().find((chunk) => chunk.end >= endOffset);
    target.push(
      createEnvelope(
        ownerChunk?.packetIndex ?? state.chunks.at(-1)?.packetIndex ?? 0,
        ownerChunk?.timestamp ?? state.chunks.at(-1)?.timestamp ?? new Date().toISOString(),
        "TCP",
        state.sourceAddress,
        state.destinationAddress,
        state.sourcePort,
        state.destinationPort,
        message
      )
    );
  }

  if (consumed === 0) {
    return;
  }

  state.buffer = state.buffer.subarray(consumed);
  state.chunks = state.chunks
    .filter((chunk) => chunk.end >= consumed)
    .map((chunk) => ({
      ...chunk,
      start: chunk.start - consumed,
      end: chunk.end - consumed
    }));
}

function flushPendingTcpSegments(state: TcpReassemblyState, target: SipMessageEnvelope[]): void {
  let advanced = true;

  while (advanced) {
    advanced = false;
    state.pending.sort((left, right) => left.sequenceNumber - right.sequenceNumber);

    for (let index = 0; index < state.pending.length; index += 1) {
      const segment = state.pending[index];
      if (state.nextSequenceNumber === undefined) {
        appendTcpPayload(state, segment.payload, segment.packetIndex, segment.timestamp);
        state.nextSequenceNumber = segment.sequenceNumber + segment.payload.length;
        state.pending.splice(index, 1);
        consumeTcpMessages(state, target);
        advanced = true;
        break;
      }

      if (segment.sequenceNumber > state.nextSequenceNumber) {
        continue;
      }

      const overlap = Math.max(0, state.nextSequenceNumber - segment.sequenceNumber);
      const tail = segment.payload.subarray(overlap);
      if (tail.length > 0) {
        appendTcpPayload(state, tail, segment.packetIndex, segment.timestamp);
        state.nextSequenceNumber += tail.length;
        consumeTcpMessages(state, target);
      }

      state.pending.splice(index, 1);
      advanced = true;
      break;
    }
  }
}

function insertPendingSegment(state: TcpReassemblyState, segment: TcpSegment): void {
  const exists = state.pending.some(
    (item) => item.sequenceNumber === segment.sequenceNumber && item.payload.length === segment.payload.length
  );
  if (!exists) {
    state.pending.push(segment);
  }
}

function acceptTcpSegment(state: TcpReassemblyState, segment: TcpSegment, target: SipMessageEnvelope[]): void {
  if (state.nextSequenceNumber === undefined) {
    appendTcpPayload(state, segment.payload, segment.packetIndex, segment.timestamp);
    state.nextSequenceNumber = segment.sequenceNumber + segment.payload.length;
    consumeTcpMessages(state, target);
    flushPendingTcpSegments(state, target);
    return;
  }

  if (segment.sequenceNumber > state.nextSequenceNumber) {
    insertPendingSegment(state, segment);
    return;
  }

  const overlap = Math.max(0, state.nextSequenceNumber - segment.sequenceNumber);
  const tail = segment.payload.subarray(overlap);
  if (tail.length > 0) {
    appendTcpPayload(state, tail, segment.packetIndex, segment.timestamp);
    state.nextSequenceNumber += tail.length;
    consumeTcpMessages(state, target);
  }

  flushPendingTcpSegments(state, target);
}

function parseTcpSipMessages(decodedPackets: DecodedNetworkPacket[]): SipMessageEnvelope[] {
  const messages: SipMessageEnvelope[] = [];
  const states = new Map<string, TcpReassemblyState>();

  for (const packet of decodedPackets) {
    if (
      packet.transportProtocol !== "TCP" ||
      !packet.payload ||
      packet.payload.length === 0 ||
      !packet.sourceAddress ||
      !packet.destinationAddress ||
      packet.sourcePort === undefined ||
      packet.destinationPort === undefined ||
      packet.tcpSequenceNumber === undefined
    ) {
      continue;
    }

    const key = `${packet.sourceAddress}:${packet.sourcePort}->${packet.destinationAddress}:${packet.destinationPort}`;
    const state =
      states.get(key) ??
      {
        sourceAddress: packet.sourceAddress,
        destinationAddress: packet.destinationAddress,
        sourcePort: packet.sourcePort,
        destinationPort: packet.destinationPort,
        buffer: Buffer.alloc(0),
        chunks: [],
        pending: []
      };

    states.set(key, state);
    acceptTcpSegment(
      state,
      {
        sequenceNumber: packet.tcpSequenceNumber,
        payload: packet.payload,
        packetIndex: packet.packetIndex,
        timestamp: packet.timestamp
      },
      messages
    );
  }

  return messages;
}

function buildFailureReason(statusCode: number, reasonPhrase: string | undefined): string {
  const normalizedReason = reasonPhrase?.trim() || "Unknown";
  const mapped: Record<number, string> = {
    400: "请求格式不合法",
    401: "需要认证，通常是鉴权未通过或缺少 Authorization",
    403: "服务器拒绝该请求，常见于权限或策略限制",
    404: "目标用户或路由不存在",
    407: "代理要求认证，通常需要 Proxy-Authorization",
    408: "请求超时，可能是对端无响应或网络丢包",
    480: "被叫暂时不可达",
    481: "事务或对话不存在，通常是对话状态不一致",
    486: "被叫忙",
    487: "请求被终止，常见于 CANCEL 或上层主动中断",
    488: "媒体协商失败，SDP 或编解码能力不匹配",
    500: "服务器内部错误",
    503: "服务器不可用或过载",
    603: "被叫明确拒绝"
  };

  return mapped[statusCode] ? `${mapped[statusCode]} (${normalizedReason})` : normalizedReason;
}

function analyzeRetransmissions(messages: SipMessageEnvelope[]): Set<number> {
  const retransmissions = new Set<number>();
  const seen = new Map<string, number>();

  for (const envelope of messages) {
    const key =
      envelope.message.kind === "request"
        ? `req|${envelope.callId}|${envelope.cseqNumber ?? "na"}|${envelope.cseqMethod ?? envelope.message.method ?? "UNKNOWN"}|${envelope.source}|${envelope.destination}`
        : `res|${envelope.callId}|${envelope.cseqNumber ?? "na"}|${envelope.message.statusCode ?? 0}|${envelope.source}|${envelope.destination}`;
    const currentTime = parseTimestamp(envelope.timestamp);
    const previousTime = seen.get(key);

    if (previousTime !== undefined && currentTime - previousTime <= 2_000) {
      retransmissions.add(envelope.packetIndex);
    } else {
      seen.set(key, currentTime);
    }
  }

  return retransmissions;
}

function collectExpectedMedia(messages: SipMessageEnvelope[]): ExpectedMedia[] {
  const expectedMedia: ExpectedMedia[] = [];

  for (const envelope of messages) {
    const contentType = (getSipHeader(envelope.message, "content-type") ?? "").toLowerCase();
    if (!contentType.includes("sdp") || !envelope.message.body) {
      continue;
    }

    const sdp = parseSdp(envelope.message.body);
    expectedMedia.push(
      ...sdp.media
        .filter((media) => media.port > 0 && media.type.toLowerCase() === "audio")
        .map((media) => ({
          callId: envelope.callId,
          address: media.connectionAddress ?? sdp.sessionConnectionAddress ?? envelope.sourceAddress,
          port: media.port,
          type: media.type,
          direction: media.direction,
          clockRates: Object.fromEntries(
            Object.entries(media.rtpMap).map(([payloadType, value]) => [Number(payloadType), value.clockRate])
          )
        }))
    );
  }

  return expectedMedia;
}

function buildTransactionKey(envelope: SipMessageEnvelope): string {
  const method = envelope.message.kind === "request" ? envelope.message.method ?? envelope.cseqMethod ?? "UNKNOWN" : envelope.cseqMethod ?? "UNKNOWN";
  return `${envelope.callId}|${method}|${envelope.cseqNumber ?? "na"}|${envelope.viaBranch ?? `${envelope.source}|${envelope.destination}`}`;
}

function analyzeTransactions(messages: SipMessageEnvelope[]): TransactionAnalysis {
  const issues: SipIssue[] = [];
  const states = new Map<
    string,
    {
      key: string;
      callId: string;
      method: string;
      cseqNumber?: number;
      branch?: string;
      source: string;
      destination: string;
      request?: SipMessageEnvelope;
      requests: SipMessageEnvelope[];
      responses: SipMessageEnvelope[];
    }
  >();

  for (const envelope of messages) {
    const key = buildTransactionKey(envelope);
    const method = envelope.message.kind === "request" ? envelope.message.method ?? envelope.cseqMethod ?? "UNKNOWN" : envelope.cseqMethod ?? "UNKNOWN";
    const state =
      states.get(key) ??
      {
        key,
        callId: envelope.callId,
        method,
        cseqNumber: envelope.cseqNumber,
        branch: envelope.viaBranch,
        source: envelope.source,
        destination: envelope.destination,
        requests: [],
        responses: []
      };

    if (envelope.message.kind === "request") {
      state.requests.push(envelope);
      state.request ??= envelope;
    } else {
      state.responses.push(envelope);
    }

    states.set(key, state);
  }

  const transactions: SipTransactionSummary[] = [];

  for (const state of states.values()) {
    const request = state.request ?? state.requests[0];
    if (!request) {
      continue;
    }

    const provisionalResponses = state.responses.filter((item) => {
      const code = item.message.statusCode ?? 0;
      return code >= 100 && code < 200;
    });
    const finalResponse = state.responses.filter((item) => (item.message.statusCode ?? 0) >= 200).at(-1);
    const requestTime = parseTimestamp(request.timestamp);
    const lastResponseTime = parseTimestamp(finalResponse?.timestamp ?? provisionalResponses.at(-1)?.timestamp ?? request.timestamp);

    let finalStatus: SipTransactionSummary["finalStatus"];
    let diagnosis: string;

    if (state.method === "ACK") {
      finalStatus = "success";
      diagnosis = "ACK 事务不期望响应。";
    } else if (state.method === "CANCEL") {
      finalStatus = (finalResponse?.message.statusCode ?? 0) === 200 ? "cancelled" : "incomplete";
      diagnosis = finalStatus === "cancelled" ? "CANCEL 已被 200 OK 确认。" : "看到了 CANCEL，但没有看到对应的 200 OK。";
    } else if (!finalResponse) {
      finalStatus = provisionalResponses.length > 0 ? "timeout" : "incomplete";
      diagnosis = provisionalResponses.length > 0 ? "仅收到临时响应，未看到最终响应。" : "未看到任何响应，可能超时或抓包不完整。";
    } else if ((finalResponse.message.statusCode ?? 0) === 401 || (finalResponse.message.statusCode ?? 0) === 407) {
      const retry = Array.from(states.values()).find(
        (candidate) =>
          candidate.callId === state.callId &&
          candidate.method === state.method &&
          (candidate.cseqNumber ?? 0) > (state.cseqNumber ?? 0) &&
          candidate.requests.some((item) => item.hasAuthorization)
      );

      finalStatus = "challenged";
      diagnosis = retry
        ? "收到鉴权挑战后看到了后续重试请求。"
        : "收到鉴权挑战，但未看到携带认证信息的后续重试请求。";
    } else if ((finalResponse.message.statusCode ?? 0) === 487) {
      finalStatus = "cancelled";
      diagnosis = "请求被终止，通常对应 CANCEL 或上层主动取消。";
    } else if ((finalResponse.message.statusCode ?? 0) < 300) {
      finalStatus = "success";
      diagnosis = `${state.method} 最终成功，状态码 ${finalResponse.message.statusCode}。`;
    } else {
      finalStatus = "failed";
      diagnosis = buildFailureReason(finalResponse.message.statusCode ?? 0, finalResponse.message.reasonPhrase);
    }

    const summary: SipTransactionSummary = {
      id: state.key,
      callId: state.callId,
      method: state.method,
      cseqNumber: state.cseqNumber,
      branch: state.branch,
      requestPacketIndex: request.packetIndex,
      startTime: request.timestamp,
      endTime: finalResponse?.timestamp,
      source: state.source,
      destination: state.destination,
      requestCount: state.requests.length,
      responseCount: state.responses.length,
      provisionalCount: provisionalResponses.length,
      finalStatus,
      finalCode: finalResponse?.message.statusCode,
      diagnosis,
      latencyMs: lastResponseTime > requestTime ? lastResponseTime - requestTime : undefined,
      relatedPackets: [...state.requests, ...state.responses].map((item) => item.packetIndex).sort((left, right) => left - right)
    };

    transactions.push(summary);

    if (finalStatus === "failed" || finalStatus === "challenged" || finalStatus === "timeout" || finalStatus === "incomplete") {
      issues.push({
        severity: finalStatus === "failed" && (summary.finalCode ?? 0) >= 500 ? "error" : "warning",
        title: `${summary.method} 事务${finalStatus === "failed" ? "失败" : "异常"}`,
        detail: `Call-ID ${summary.callId} 的 ${summary.method} 事务诊断：${summary.diagnosis}`,
        callId: summary.callId,
        packetIndex: summary.requestPacketIndex
      });
    }
  }

  transactions.sort((left, right) => parseTimestamp(right.startTime) - parseTimestamp(left.startTime));
  return { transactions, issues };
}

function analyzeDialogs(messages: SipMessageEnvelope[], retransmissions: Set<number>, expectedMedia: ExpectedMedia[]): {
  dialogs: SipDialogSummary[];
  issues: SipIssue[];
  records: SipMessageRecord[];
  expectedMedia: ExpectedMedia[];
} {
  const issues: SipIssue[] = [];
  const records: SipMessageRecord[] = [];
  const byCallId = new Map<string, SipMessageEnvelope[]>();

  for (const envelope of messages) {
    const record = createMessageRecord(envelope, retransmissions.has(envelope.packetIndex));
    records.push(record);

    const current = byCallId.get(envelope.callId);
    if (current) {
      current.push(envelope);
    } else {
      byCallId.set(envelope.callId, [envelope]);
    }
  }

  const dialogs: SipDialogSummary[] = [];

  for (const [callId, envelopes] of byCallId) {
    const sorted = [...envelopes].sort((left, right) => parseTimestamp(left.timestamp) - parseTimestamp(right.timestamp));
    const firstRequest = sorted.find((item) => item.message.kind === "request");
    const finalResponses = sorted.filter((item) => item.message.kind === "response" && (item.message.statusCode ?? 0) >= 200);
    const errorResponse = finalResponses.find((item) => (item.message.statusCode ?? 0) >= 300);
    const inviteOk = finalResponses.find((item) => item.message.statusCode === 200 && (item.cseqMethod ?? "").includes("INVITE"));
    const hasAck = sorted.some((item) => item.message.kind === "request" && item.message.method === "ACK");
    const hasCancel = sorted.some((item) => item.message.kind === "request" && item.message.method === "CANCEL");
    const retransmissionCount = sorted.filter((item) => retransmissions.has(item.packetIndex)).length;
    const diagnostics: string[] = [];
    const fromHeader = getSipHeader(sorted[0]?.message, "from") ?? "";
    const toHeader = getSipHeader(sorted[0]?.message, "to") ?? "";

    let status: SipDialogSummary["status"] = "incomplete";
    let failureReason: string | undefined;

    if (hasCancel || errorResponse?.message.statusCode === 487) {
      status = "cancelled";
      failureReason = "呼叫被取消或请求被终止。";
    } else if (errorResponse?.message.statusCode) {
      status = "failed";
      failureReason = buildFailureReason(errorResponse.message.statusCode, errorResponse.message.reasonPhrase);
    } else if (inviteOk && hasAck) {
      status = "established";
    } else if (finalResponses.some((item) => item.message.statusCode === 200 && ((item.message.method ?? item.cseqMethod) === "REGISTER"))) {
      status = "established";
      diagnostics.push("REGISTER 已获得 200 OK。");
    }

    if (retransmissionCount > 0) {
      diagnostics.push(`发现 ${retransmissionCount} 次重复 SIP 报文，疑似重传。`);
      issues.push({
        severity: retransmissionCount >= 3 ? "warning" : "info",
        title: "发现 SIP 重传",
        detail: `Call-ID ${callId} 中检测到 ${retransmissionCount} 次近时间窗口内的重复 SIP 报文。`,
        callId
      });
    }

    if (inviteOk && !hasAck) {
      diagnostics.push("INVITE 已收到 200 OK，但未看到 ACK。");
      issues.push({
        severity: "warning",
        title: "缺少 ACK",
        detail: `Call-ID ${callId} 的 INVITE 已收到 200 OK，但当前抓包中未看到 ACK，请确认抓包范围或链路质量。`,
        callId
      });
    }

    if (errorResponse?.message.statusCode) {
      issues.push({
        severity: errorResponse.message.statusCode >= 500 ? "error" : "warning",
        title: `SIP ${errorResponse.message.statusCode} ${errorResponse.message.reasonPhrase ?? ""}`.trim(),
        detail: `Call-ID ${callId} 失败原因：${buildFailureReason(errorResponse.message.statusCode, errorResponse.message.reasonPhrase)}。`,
        callId,
        packetIndex: errorResponse.packetIndex
      });
      diagnostics.push(`失败原因：${buildFailureReason(errorResponse.message.statusCode, errorResponse.message.reasonPhrase)}`);
    }

    if (status === "incomplete" && firstRequest) {
      issues.push({
        severity: "warning",
        title: "呼叫流程不完整",
        detail: `Call-ID ${callId} 缺少最终响应，可能是抓包不完整、对端未响应，或网络中途丢包。`,
        callId,
        packetIndex: firstRequest.packetIndex
      });
      diagnostics.push("未看到最终响应。");
    }

    dialogs.push({
      callId,
      startTime: sorted[0]?.timestamp ?? "",
      endTime: sorted[sorted.length - 1]?.timestamp ?? "",
      from: fromHeader,
      to: toHeader,
      requestUri: firstRequest?.message.requestUri,
      method: firstRequest?.message.method,
      messageCount: sorted.length,
      status,
      failureReason,
      diagnostics,
      mediaCount: expectedMedia.filter((item) => item.callId === callId).length
    });
  }

  dialogs.sort((left, right) => parseTimestamp(right.startTime) - parseTimestamp(left.startTime));
  records.sort((left, right) => parseTimestamp(left.timestamp) - parseTimestamp(right.timestamp));

  return { dialogs, issues, records, expectedMedia };
}

function isLikelyRtpPayload(payload: Buffer): boolean {
  if (payload.length < 12) {
    return false;
  }

  const version = payload[0] >> 6;
  if (version !== 2) {
    return false;
  }

  const payloadType = payload[1] & 0x7f;
  return payloadType <= 127;
}

function resolveClockRate(payloadType: number, media: ExpectedMedia | undefined): number | undefined {
  return media?.clockRates[payloadType] ?? STATIC_RTP_CLOCK_RATES[payloadType];
}

function isLikelyRtcpPayload(payload: Buffer): boolean {
  if (payload.length < 8) {
    return false;
  }

  const version = payload[0] >> 6;
  if (version !== 2) {
    return false;
  }

  const packetType = payload[1];
  return packetType >= 192 && packetType <= 223;
}

function parseRtcpType(packetType: number): RtcpSummary["packetType"] {
  switch (packetType) {
    case 200:
      return "SR";
    case 201:
      return "RR";
    case 202:
      return "SDES";
    case 203:
      return "BYE";
    case 204:
      return "APP";
    case 207:
      return "XR";
    default:
      return "UNKNOWN";
  }
}

function inspectRtpStreams(decodedPackets: DecodedNetworkPacket[], expectedMedia: ExpectedMedia[]): RtpInspectionResult {
  const issues: SipIssue[] = [];
  const expectedMediaByPort = new Map<number, ExpectedMedia[]>();
  for (const media of expectedMedia) {
    const current = expectedMediaByPort.get(media.port);
    if (current) {
      current.push(media);
    } else {
      expectedMediaByPort.set(media.port, [media]);
    }
  }

  const rtcpReports: RtcpSummary[] = [];
  const streamMap = new Map<
    string,
    {
      summary: RtpStreamSummary;
      lastSequence?: number;
      lastTransit?: number;
      jitter?: number;
      payloadTypes: Set<number>;
    }
  >();
  const seenSsrcByCallAndDirection = new Map<string, Set<string>>();

  for (const packet of decodedPackets) {
    if (
      packet.transportProtocol !== "UDP" ||
      !packet.payload ||
      !packet.sourceAddress ||
      !packet.destinationAddress ||
      packet.sourcePort === undefined ||
      packet.destinationPort === undefined
    ) {
      continue;
    }

    if (isSipPayload(packet.payload, packet.sourcePort, packet.destinationPort)) {
      continue;
    }

    const relatedMedia =
      expectedMediaByPort.get(packet.sourcePort)?.[0] ??
      expectedMediaByPort.get(packet.destinationPort)?.[0];
    const callId = relatedMedia?.callId;

    if (isLikelyRtcpPayload(packet.payload)) {
      const packetType = packet.payload[1];
      const reportCount = packet.payload[0] & 0x1f;
      const ssrc = packet.payload.length >= 8 ? packet.payload.readUInt32BE(4).toString(16).padStart(8, "0") : undefined;
      let fractionLost: number | undefined;
      let cumulativeLost: number | undefined;
      let interarrivalJitter: number | undefined;
      const type = parseRtcpType(packetType);

      if ((type === "SR" || type === "RR") && packet.payload.length >= (type === "SR" ? 32 : 20)) {
        const reportOffset = type === "SR" ? 28 : 8;
        if (reportCount > 0 && packet.payload.length >= reportOffset + 24) {
          fractionLost = packet.payload[reportOffset + 4];
          cumulativeLost =
            ((packet.payload[reportOffset + 5] << 16) |
              (packet.payload[reportOffset + 6] << 8) |
              packet.payload[reportOffset + 7]) >>>
            0;
          interarrivalJitter = packet.payload.readUInt32BE(reportOffset + 12);
        }
      }

      rtcpReports.push({
        id: `${packet.packetIndex}-${type}-${ssrc ?? "na"}`,
        callId,
        packetIndex: packet.packetIndex,
        timestamp: packet.timestamp,
        source: `${packet.sourceAddress}:${packet.sourcePort}`,
        destination: `${packet.destinationAddress}:${packet.destinationPort}`,
        packetType: type,
        ssrc,
        reportCount,
        fractionLost,
        cumulativeLost,
        interarrivalJitter,
        note:
          type === "XR"
            ? "检测到 RTCP XR，可用于后续更细的质量诊断。"
            : type === "SR" || type === "RR"
              ? "检测到 RTCP 统计报告。"
              : "检测到 RTCP 控制报文。"
      });
      continue;
    }

    if (!callId && !isLikelyRtpPayload(packet.payload)) {
      continue;
    }

    if (!isLikelyRtpPayload(packet.payload)) {
      continue;
    }

    const marker = (packet.payload[1] & 0x80) !== 0;
    const payloadType = packet.payload[1] & 0x7f;
    const sequence = packet.payload.readUInt16BE(2);
    const rtpTimestamp = packet.payload.readUInt32BE(4);
    const ssrc = packet.payload.readUInt32BE(8).toString(16).padStart(8, "0");
    const clockRate = resolveClockRate(payloadType, relatedMedia);
    const directionKey = `${callId ?? "unbound"}|${packet.sourceAddress}:${packet.sourcePort}->${packet.destinationAddress}:${packet.destinationPort}`;
    const knownSsrcSet = seenSsrcByCallAndDirection.get(directionKey) ?? new Set<string>();
    if (!knownSsrcSet.has(ssrc) && knownSsrcSet.size > 0) {
      issues.push({
        severity: "warning",
        title: "检测到 SSRC 切换",
        detail: `流 ${packet.sourceAddress}:${packet.sourcePort} -> ${packet.destinationAddress}:${packet.destinationPort} 出现新的 SSRC ${ssrc}。`,
        callId
      });
    }
    knownSsrcSet.add(ssrc);
    seenSsrcByCallAndDirection.set(directionKey, knownSsrcSet);
    const streamId = `${callId ?? "unbound"}|${packet.sourceAddress}:${packet.sourcePort}->${packet.destinationAddress}:${packet.destinationPort}|${ssrc}`;
    const existing = streamMap.get(streamId);

    if (!existing) {
      streamMap.set(streamId, {
        summary: {
          id: streamId,
          callId,
          source: `${packet.sourceAddress}:${packet.sourcePort}`,
          destination: `${packet.destinationAddress}:${packet.destinationPort}`,
          ssrc,
          payloadType,
          packetCount: 1,
          firstSeen: packet.timestamp,
          lastSeen: packet.timestamp,
          estimatedLostPackets: 0,
          longGapCount: 0,
          outOfOrderPackets: 0,
          markerPackets: marker ? 1 : 0,
          jitterMs: 0,
          maxJitterMs: 0,
          clockRate,
          status: "healthy",
          note: callId ? "RTP 流已与 SIP/SDP 端口关联。" : "RTP 流通过报文特征推断得到。"
        },
        lastSequence: sequence,
        lastTransit: clockRate ? (parseTimestamp(packet.timestamp) * clockRate) / 1000 - rtpTimestamp : undefined,
        jitter: 0,
        payloadTypes: new Set([payloadType])
      });
      continue;
    }

    existing.summary.packetCount += 1;
    existing.summary.lastSeen = packet.timestamp;
    existing.summary.markerPackets += marker ? 1 : 0;
    existing.payloadTypes.add(payloadType);

    if (existing.lastSequence !== undefined) {
      const diff = (sequence - existing.lastSequence + 65_536) % 65_536;
      if (diff === 0) {
        existing.summary.outOfOrderPackets += 1;
      } else if (diff > 1 && diff < 30_000) {
        existing.summary.estimatedLostPackets += diff - 1;
      } else if (diff > 30_000) {
        existing.summary.outOfOrderPackets += 1;
      }
    }

    if (clockRate) {
      const transit = (parseTimestamp(packet.timestamp) * clockRate) / 1000 - rtpTimestamp;
      if (existing.lastTransit !== undefined) {
        const difference = Math.abs(transit - existing.lastTransit);
        existing.jitter = existing.jitter !== undefined ? existing.jitter + (difference - existing.jitter) / 16 : difference / 16;
        existing.summary.jitterMs = Number((((existing.jitter ?? 0) / clockRate) * 1000).toFixed(2));
        existing.summary.maxJitterMs = Math.max(existing.summary.maxJitterMs ?? 0, existing.summary.jitterMs ?? 0);
      }
      existing.lastTransit = transit;
    }

    const previousSeenTime = parseTimestamp(existing.summary.lastSeen);
    const currentSeenTime = parseTimestamp(packet.timestamp);
    if (currentSeenTime - previousSeenTime >= 3_000) {
      existing.summary.longGapCount = (existing.summary.longGapCount ?? 0) + 1;
    }

    existing.lastSequence = sequence;
    existing.summary.lastSeen = packet.timestamp;
  }

  const streams = Array.from(streamMap.values()).map((item) => {
    const payloadTypeChanged = item.payloadTypes.size > 1;
    const jitterMs = item.summary.jitterMs ?? 0;
    const longGapCount = item.summary.longGapCount ?? 0;

    if (item.summary.packetCount < 5) {
      item.summary.status = "idle";
      item.summary.note = "RTP 报文数量很少，可能只抓到建立阶段或媒体未真正打通。";
    } else if (item.summary.estimatedLostPackets > 10 || item.summary.outOfOrderPackets > 5 || jitterMs >= 100 || longGapCount >= 3) {
      item.summary.status = "error";
      item.summary.note = "RTP 丢包、乱序、抖动或时间间隙偏大，媒体质量风险较高。";
    } else if (item.summary.estimatedLostPackets > 0 || item.summary.outOfOrderPackets > 0 || payloadTypeChanged || jitterMs >= 30 || longGapCount > 0) {
      item.summary.status = "warning";
      item.summary.note = payloadTypeChanged
        ? "RTP 流中出现 payload type 变化，请确认是否发生编解码协商切换。"
        : "RTP 流存在少量丢包、乱序、抖动或异常间隙。";
    }

    if (item.summary.status !== "healthy") {
      issues.push({
        severity: item.summary.status === "error" ? "error" : "warning",
        title: "RTP 流异常",
        detail: `${item.summary.source} -> ${item.summary.destination} 丢包估计 ${item.summary.estimatedLostPackets}，乱序 ${item.summary.outOfOrderPackets}，抖动 ${item.summary.jitterMs ?? 0}ms，长间隙 ${item.summary.longGapCount ?? 0} 次。`,
        callId: item.summary.callId
      });
    }

    return item.summary;
  });

  for (const media of expectedMedia) {
    const matched = streams.some(
      (stream) =>
        stream.callId === media.callId &&
        (stream.source.endsWith(`:${media.port}`) || stream.destination.endsWith(`:${media.port}`))
    );

    if (!matched) {
      issues.push({
        severity: "warning",
        title: "未发现预期 RTP 流",
        detail: `Call-ID ${media.callId} 在 SDP 中声明了音频端口 ${media.address}:${media.port}，但抓包中未看到对应 RTP 流。`,
        callId: media.callId
      });
    }
  }

  const streamsByCall = new Map<string, RtpStreamSummary[]>();
  for (const stream of streams) {
    if (!stream.callId) {
      continue;
    }

    const current = streamsByCall.get(stream.callId);
    if (current) {
      current.push(stream);
    } else {
      streamsByCall.set(stream.callId, [stream]);
    }
  }

  for (const [callId, callStreams] of streamsByCall) {
    const expectedPorts = new Set(expectedMedia.filter((item) => item.callId === callId).map((item) => item.port));
    const observedPorts = new Set<number>();

    for (const stream of callStreams) {
      const sourcePort = Number.parseInt(stream.source.split(":").at(-1) ?? "", 10);
      const destinationPort = Number.parseInt(stream.destination.split(":").at(-1) ?? "", 10);
      if (!Number.isNaN(sourcePort)) {
        observedPorts.add(sourcePort);
      }
      if (!Number.isNaN(destinationPort)) {
        observedPorts.add(destinationPort);
      }
    }

    if (expectedPorts.size >= 2 && observedPorts.size < expectedPorts.size) {
      issues.push({
        severity: "warning",
        title: "疑似单向媒体",
        detail: `Call-ID ${callId} 的 SDP 声明了 ${expectedPorts.size} 个媒体端口，但当前仅观测到 ${observedPorts.size} 个相关端口参与 RTP。`,
        callId
      });
    }
  }

  streams.sort((left, right) => parseTimestamp(right.lastSeen) - parseTimestamp(left.lastSeen));
  rtcpReports.sort((left, right) => parseTimestamp(right.timestamp) - parseTimestamp(left.timestamp));

  for (const report of rtcpReports) {
    if ((report.packetType === "SR" || report.packetType === "RR") && ((report.fractionLost ?? 0) > 10 || (report.cumulativeLost ?? 0) > 50)) {
      issues.push({
        severity: (report.fractionLost ?? 0) > 25 ? "error" : "warning",
        title: "RTCP 报告存在明显丢包",
        detail: `${report.source} -> ${report.destination} 的 ${report.packetType} 报告 fraction lost=${report.fractionLost ?? 0}，cumulative lost=${report.cumulativeLost ?? 0}。`,
        callId: report.callId,
        packetIndex: report.packetIndex
      });
    }
  }

  return { streams, rtcpReports, issues };
}

function codecNamesFromMedia(media: ReturnType<typeof parseSdp>["media"][number] | undefined): string[] {
  if (!media) {
    return [];
  }

  return media.payloadTypes.map((payloadType) => {
    const mapped = media.rtpMap[payloadType];
    return mapped ? `${mapped.encoding}/${mapped.clockRate}` : `PT${payloadType}`;
  });
}

function buildSdpDiffs(messages: SipMessageEnvelope[]): SdpDiffSummary[] {
  const byCallId = new Map<string, SipMessageEnvelope[]>();

  for (const message of messages) {
    if (!(getSipHeader(message.message, "content-type") ?? "").toLowerCase().includes("sdp")) {
      continue;
    }

    const current = byCallId.get(message.callId);
    if (current) {
      current.push(message);
    } else {
      byCallId.set(message.callId, [message]);
    }
  }

  const diffs: SdpDiffSummary[] = [];

  for (const [callId, envelopes] of byCallId) {
    const offer = envelopes.find((item) => item.message.kind === "request" && item.message.body);
    const answer = envelopes.find((item) => item.message.kind === "response" && (item.message.statusCode ?? 0) >= 180 && item.message.body);

    if (!offer) {
      continue;
    }

    const offerSdp = parseSdp(offer.message.body);
    const offerAudio = offerSdp.media.find((item) => item.type.toLowerCase() === "audio");

    if (!answer) {
      diffs.push({
        callId,
        offerPacketIndex: offer.packetIndex,
        result: "missing-answer",
        summary: "发现 Offer，但未在抓包中看到带 SDP 的 Answer。",
        addedCodecs: [],
        removedCodecs: codecNamesFromMedia(offerAudio),
        changedConnections: [],
        changedDirections: []
      });
      continue;
    }

    const answerSdp = parseSdp(answer.message.body);
    const answerAudio = answerSdp.media.find((item) => item.type.toLowerCase() === "audio");
    const offerCodecs = codecNamesFromMedia(offerAudio);
    const answerCodecs = codecNamesFromMedia(answerAudio);
    const addedCodecs = answerCodecs.filter((item) => !offerCodecs.includes(item));
    const removedCodecs = offerCodecs.filter((item) => !answerCodecs.includes(item));
    const changedConnections: string[] = [];
    const changedDirections: string[] = [];

    const offerAddress = offerAudio?.connectionAddress ?? offerSdp.sessionConnectionAddress;
    const answerAddress = answerAudio?.connectionAddress ?? answerSdp.sessionConnectionAddress;
    if (offerAddress !== answerAddress) {
      changedConnections.push(`${offerAddress ?? "unknown"} -> ${answerAddress ?? "unknown"}`);
    }

    if ((offerAudio?.direction ?? "sendrecv") !== (answerAudio?.direction ?? "sendrecv")) {
      changedDirections.push(`${offerAudio?.direction ?? "sendrecv"} -> ${answerAudio?.direction ?? "sendrecv"}`);
    }

    const result =
      removedCodecs.length > 0 && answerCodecs.length === 0
        ? "incompatible"
        : addedCodecs.length === 0 && removedCodecs.length === 0 && changedConnections.length === 0 && changedDirections.length === 0
          ? "unchanged"
          : "changed";

    diffs.push({
      callId,
      offerPacketIndex: offer.packetIndex,
      answerPacketIndex: answer.packetIndex,
      result,
      summary:
        result === "incompatible"
          ? "Offer/Answer 中未找到共同音频能力，疑似编解码不兼容。"
          : result === "unchanged"
            ? "Offer/Answer 的音频能力基本一致。"
            : "Offer/Answer 的媒体能力或地址发生了变化。",
      addedCodecs,
      removedCodecs,
      changedConnections,
      changedDirections
    });
  }

  return diffs.sort((left, right) => (right.offerPacketIndex ?? 0) - (left.offerPacketIndex ?? 0));
}

function buildSequenceDiagrams(
  dialogs: SipDialogSummary[],
  messages: SipMessageEnvelope[],
  rtpStreams: RtpStreamSummary[],
  rtcpReports: RtcpSummary[]
): SipSequenceDiagram[] {
  return dialogs.map((dialog) => {
    const relatedSipSteps: SipSequenceStep[] = messages
      .filter((message) => message.callId === dialog.callId)
      .map((message) => ({
        packetIndex: message.packetIndex,
        timestamp: message.timestamp,
        source: message.source,
        destination: message.destination,
        kind: "sip",
        label:
          message.message.kind === "request"
            ? `${message.message.method} ${message.message.requestUri ?? ""}`.trim()
            : `${message.message.statusCode ?? 0} ${message.message.reasonPhrase ?? ""}`.trim()
      }));

    const relatedRtpSteps: SipSequenceStep[] = rtpStreams
      .filter((stream) => stream.callId === dialog.callId)
      .flatMap((stream) => [
        {
          timestamp: stream.firstSeen,
          source: stream.source,
          destination: stream.destination,
          kind: "rtp" as const,
          label: `RTP start PT=${stream.payloadType} SSRC=${stream.ssrc}`
        },
        {
          timestamp: stream.lastSeen,
          source: stream.source,
          destination: stream.destination,
          kind: "rtp" as const,
          label: `RTP end packets=${stream.packetCount} loss=${stream.estimatedLostPackets}`
        }
      ]);

    const relatedRtcpSteps: SipSequenceStep[] = rtcpReports
      .filter((report) => report.callId === dialog.callId)
      .map((report) => ({
        packetIndex: report.packetIndex,
        timestamp: report.timestamp,
        source: report.source,
        destination: report.destination,
        kind: "rtcp",
        label: `RTCP ${report.packetType}${report.fractionLost !== undefined ? ` lost=${report.fractionLost}` : ""}`
      }));

    const steps = [...relatedSipSteps, ...relatedRtpSteps, ...relatedRtcpSteps].sort(
      (left, right) => parseTimestamp(left.timestamp) - parseTimestamp(right.timestamp)
    );
    const participants = Array.from(new Set(steps.flatMap((step) => [step.source, step.destination])));

    return {
      callId: dialog.callId,
      participants,
      steps
    };
  });
}

function buildAdditionalIssues(messages: SipMessageEnvelope[], dialogs: SipDialogSummary[], sdpDiffs: SdpDiffSummary[]): SipIssue[] {
  const issues: SipIssue[] = [];
  const registerWindows = new Map<string, number[]>();

  for (const message of messages) {
    if (message.message.kind === "request" && message.message.method === "REGISTER") {
      const key = `${message.source}|${message.destination}`;
      const list = registerWindows.get(key) ?? [];
      list.push(parseTimestamp(message.timestamp));
      registerWindows.set(key, list);
    }
  }

  for (const [key, timestamps] of registerWindows) {
    timestamps.sort((left, right) => left - right);
    let windowStart = 0;
    for (let index = 0; index < timestamps.length; index += 1) {
      while (timestamps[index] - timestamps[windowStart] > 60_000) {
        windowStart += 1;
      }

      const count = index - windowStart + 1;
      if (count >= 6) {
        issues.push({
          severity: "warning",
          title: "疑似重注册风暴",
          detail: `${key} 在 60 秒内出现了 ${count} 次 REGISTER，请检查终端重试、鉴权失败或注册周期配置。`
        });
        break;
      }
    }
  }

  for (const dialog of dialogs) {
    const relatedMessages = messages.filter((message) => message.callId === dialog.callId);
    const hasByeRequest = relatedMessages.some((message) => message.message.kind === "request" && message.message.method === "BYE");
    const hasByeOk = relatedMessages.some(
      (message) =>
        message.message.kind === "response" &&
        (message.message.statusCode ?? 0) === 200 &&
        (message.cseqMethod ?? "").toUpperCase() === "BYE"
    );

    if (hasByeRequest && !hasByeOk) {
      issues.push({
        severity: "warning",
        title: "单边 BYE 或 BYE 未闭合",
        detail: `Call-ID ${dialog.callId} 看到了 BYE 请求，但没有看到对应的 200 OK。`,
        callId: dialog.callId
      });
    }
  }

  for (const diff of sdpDiffs) {
    if (diff.result === "incompatible") {
      issues.push({
        severity: "error",
        title: "SDP 能力不兼容",
        detail: `Call-ID ${diff.callId} 的 Offer/Answer 未找到共同音频能力，疑似 codec 不匹配。`,
        callId: diff.callId,
        packetIndex: diff.offerPacketIndex
      });
    } else if (diff.result === "changed" && diff.changedConnections.length > 0) {
      issues.push({
        severity: "info",
        title: "检测到媒体地址变化",
        detail: `Call-ID ${diff.callId} 的 SDP 媒体地址发生变化：${diff.changedConnections.join(", ")}。`,
        callId: diff.callId,
        packetIndex: diff.offerPacketIndex
      });
    }
  }

  return issues;
}

export function analyzeSip(decodedPackets: DecodedNetworkPacket[]): SipOverview {
  const messages = [...parseUdpSipMessages(decodedPackets), ...parseTcpSipMessages(decodedPackets)].sort(
    (left, right) => parseTimestamp(left.timestamp) - parseTimestamp(right.timestamp)
  );
  const retransmissions = analyzeRetransmissions(messages);
  const expectedMedia = collectExpectedMedia(messages);
  const transactionAnalysis = analyzeTransactions(messages);
  const dialogAnalysis = analyzeDialogs(messages, retransmissions, expectedMedia);
  const rtpInspection = inspectRtpStreams(decodedPackets, expectedMedia);
  const sdpDiffs = buildSdpDiffs(messages);
  const sequenceDiagrams = buildSequenceDiagrams(dialogAnalysis.dialogs, messages, rtpInspection.streams, rtpInspection.rtcpReports);
  const issues = [...transactionAnalysis.issues, ...dialogAnalysis.issues, ...rtpInspection.issues, ...buildAdditionalIssues(messages, dialogAnalysis.dialogs, sdpDiffs)].filter(
    (issue, index, list) =>
      list.findIndex(
        (candidate) =>
          candidate.severity === issue.severity &&
          candidate.title === issue.title &&
          candidate.detail === issue.detail &&
          candidate.callId === issue.callId &&
          candidate.packetIndex === issue.packetIndex
      ) === index
  );

  return {
    totalMessages: dialogAnalysis.records.length,
    requestCount: dialogAnalysis.records.filter((item) => item.direction === "request").length,
    responseCount: dialogAnalysis.records.filter((item) => item.direction === "response").length,
    callCount: dialogAnalysis.dialogs.length,
    issues: issues.sort((left, right) => {
      const weight = { error: 0, warning: 1, info: 2 };
      return weight[left.severity] - weight[right.severity];
    }),
    dialogs: dialogAnalysis.dialogs,
    transactions: transactionAnalysis.transactions,
    messages: dialogAnalysis.records,
    sequenceDiagrams,
    sdpDiffs,
    rtcpReports: rtpInspection.rtcpReports,
    rtpStreams: rtpInspection.streams
  };
}
