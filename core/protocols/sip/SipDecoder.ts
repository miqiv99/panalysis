import type { ProtocolSummary } from "../../../shared/types.js";

const SIP_METHODS = new Set([
  "ACK",
  "BYE",
  "CANCEL",
  "INFO",
  "INVITE",
  "MESSAGE",
  "NOTIFY",
  "OPTIONS",
  "PRACK",
  "PUBLISH",
  "REFER",
  "REGISTER",
  "SUBSCRIBE",
  "UPDATE"
]);

export interface ParsedSipMessage {
  startLine: string;
  kind: "request" | "response";
  method?: string;
  requestUri?: string;
  statusCode?: number;
  reasonPhrase?: string;
  headers: Record<string, string>;
  body: string;
  contentLength: number;
}

export function buildSipSummary(packetCount: number): ProtocolSummary {
  return {
    protocol: "SIP",
    packets: packetCount,
    status: "ready",
    note: "已支持 SIP 会话分析、错误原因归因和 RTP 流异常摘要。"
  };
}

function normalizeSipText(payload: Buffer): string {
  return payload.toString("utf8").replace(/\0/g, "");
}

function findHeaderBoundary(text: string): { headerEnd: number; separatorLength: number } | null {
  const crlfIndex = text.indexOf("\r\n\r\n");
  if (crlfIndex >= 0) {
    return { headerEnd: crlfIndex, separatorLength: 4 };
  }

  const lfIndex = text.indexOf("\n\n");
  if (lfIndex >= 0) {
    return { headerEnd: lfIndex, separatorLength: 2 };
  }

  return null;
}

function looksLikeSipStartLine(startLine: string): boolean {
  if (startLine.startsWith("SIP/2.0 ")) {
    return true;
  }

  const [method, requestUri, version] = startLine.split(" ", 3);
  return SIP_METHODS.has(method) && typeof requestUri === "string" && version === "SIP/2.0";
}

export function isSipPayload(payload: Buffer, sourcePort: number, destinationPort: number): boolean {
  if (payload.length === 0) {
    return false;
  }

  if (sourcePort === 5060 || destinationPort === 5060) {
    return true;
  }

  if (sourcePort === 5061 || destinationPort === 5061) {
    return false;
  }

  const startLine = normalizeSipText(payload).split(/\r?\n/, 1)[0]?.trim() ?? "";
  return looksLikeSipStartLine(startLine);
}

export function parseSipMessage(payload: Buffer): ParsedSipMessage | null {
  const text = normalizeSipText(payload);
  const headerBoundary = findHeaderBoundary(text);
  const headersOnly = headerBoundary ? text.slice(0, headerBoundary.headerEnd) : text;
  const body = headerBoundary ? text.slice(headerBoundary.headerEnd + headerBoundary.separatorLength) : "";
  const lines = headersOnly.split(/\r?\n/).map((line) => line.trimEnd());

  const startLine = lines[0]?.trim();
  if (!startLine || !looksLikeSipStartLine(startLine)) {
    return null;
  }

  const headers: Record<string, string> = {};
  for (const rawLine of lines.slice(1)) {
    if (!rawLine) {
      continue;
    }

    const separatorIndex = rawLine.indexOf(":");
    if (separatorIndex <= 0) {
      continue;
    }

    const name = rawLine.slice(0, separatorIndex).trim().toLowerCase();
    const value = rawLine.slice(separatorIndex + 1).trim();
    if (!(name in headers)) {
      headers[name] = value;
    }
  }

  const contentLength = Number.parseInt(headers["content-length"] ?? `${Buffer.byteLength(body, "utf8")}`, 10);

  if (startLine.startsWith("SIP/2.0 ")) {
    const [, statusCodeText, ...reasonParts] = startLine.split(" ");
    return {
      startLine,
      kind: "response",
      statusCode: Number.parseInt(statusCodeText, 10),
      reasonPhrase: reasonParts.join(" "),
      headers,
      body,
      contentLength: Number.isNaN(contentLength) ? 0 : contentLength
    };
  }

  const [method, requestUri] = startLine.split(" ", 3);
  return {
    startLine,
    kind: "request",
    method,
    requestUri,
    headers,
    body,
    contentLength: Number.isNaN(contentLength) ? 0 : contentLength
  };
}

export function summarizeSipMessage(message: ParsedSipMessage, source: string, destination: string): string {
  const callId = message.headers["call-id"] ?? "no-call-id";

  if (message.kind === "request") {
    const requestTarget = message.requestUri ?? "";
    return `${source} -> ${destination} ${message.method} ${requestTarget} [${callId}]`;
  }

  const cseq = message.headers.cseq ?? "unknown-cseq";
  return `${source} -> ${destination} SIP/2.0 ${message.statusCode ?? 0} ${message.reasonPhrase ?? ""} [${cseq}] [${callId}]`.trim();
}

export function extractSipMessagesFromTcpBuffer(buffer: Buffer): { messages: Buffer[]; remainder: Buffer } {
  const messages: Buffer[] = [];
  let offset = 0;

  while (offset < buffer.length) {
    const text = normalizeSipText(buffer.subarray(offset));
    const boundary = findHeaderBoundary(text);
    if (!boundary) {
      break;
    }

    const headerText = text.slice(0, boundary.headerEnd);
    const startLine = headerText.split(/\r?\n/, 1)[0]?.trim() ?? "";
    if (!looksLikeSipStartLine(startLine)) {
      break;
    }

    let contentLength = 0;
    for (const line of headerText.split(/\r?\n/).slice(1)) {
      const separatorIndex = line.indexOf(":");
      if (separatorIndex <= 0) {
        continue;
      }

      const name = line.slice(0, separatorIndex).trim().toLowerCase();
      if (name === "content-length") {
        contentLength = Number.parseInt(line.slice(separatorIndex + 1).trim(), 10);
        if (Number.isNaN(contentLength)) {
          contentLength = 0;
        }
      }
    }

    const headerByteLength = Buffer.byteLength(text.slice(0, boundary.headerEnd + boundary.separatorLength), "utf8");
    const totalByteLength = headerByteLength + contentLength;
    if (buffer.length - offset < totalByteLength) {
      break;
    }

    messages.push(buffer.subarray(offset, offset + totalByteLength));
    offset += totalByteLength;
  }

  return {
    messages,
    remainder: buffer.subarray(offset)
  };
}

export function getSipHeader(message: ParsedSipMessage, name: string): string | undefined {
  return message.headers[name.toLowerCase()];
}

export function getSipTag(headerValue: string | undefined): string | undefined {
  if (!headerValue) {
    return undefined;
  }

  const match = /(?:^|;)\s*tag=([^;]+)/i.exec(headerValue);
  return match?.[1]?.trim();
}

export interface SdpMediaDescription {
  type: string;
  port: number;
  protocol: string;
  payloadTypes: number[];
  connectionAddress?: string;
  direction?: "sendrecv" | "sendonly" | "recvonly" | "inactive";
  rtpMap: Record<number, { encoding: string; clockRate: number }>;
}

export interface ParsedSdp {
  sessionConnectionAddress?: string;
  media: SdpMediaDescription[];
}

export function parseSdp(body: string): ParsedSdp {
  const result: ParsedSdp = { media: [] };
  let currentMedia: SdpMediaDescription | null = null;
  let sessionDirection: SdpMediaDescription["direction"];

  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }

    if (line.startsWith("c=")) {
      const match = /^c=IN IP[46] ([^\s]+)/i.exec(line);
      if (match) {
        if (currentMedia) {
          currentMedia.connectionAddress = match[1];
        } else {
          result.sessionConnectionAddress = match[1];
        }
      }
      continue;
    }

    if (/^a=(sendrecv|sendonly|recvonly|inactive)$/i.test(line)) {
      const direction = line.slice(2).toLowerCase() as SdpMediaDescription["direction"];
      if (currentMedia) {
        currentMedia.direction = direction;
      } else {
        sessionDirection = direction;
      }
      continue;
    }

    if (line.startsWith("a=rtpmap:")) {
      if (!currentMedia) {
        continue;
      }

      const match = /^a=rtpmap:(\d+)\s+([^/]+)\/(\d+)/i.exec(line);
      if (match) {
        currentMedia.rtpMap[Number.parseInt(match[1], 10)] = {
          encoding: match[2],
          clockRate: Number.parseInt(match[3], 10)
        };
      }
      continue;
    }

    if (line.startsWith("m=")) {
      const parts = line.slice(2).trim().split(/\s+/);
      if (parts.length >= 3) {
        currentMedia = {
          type: parts[0],
          port: Number.parseInt(parts[1], 10),
          protocol: parts[2],
          payloadTypes: parts.slice(3).map((value) => Number.parseInt(value, 10)).filter((value) => !Number.isNaN(value)),
          direction: sessionDirection,
          rtpMap: {}
        };
        result.media.push(currentMedia);
      }
    }
  }

  return result;
}
