import type { RawCapturePacket } from "../capture/pcap/PcapReader.js";
import type { PacketRecord } from "../../shared/types.js";
import { extractSipMessagesFromTcpBuffer, isSipPayload, parseSipMessage, summarizeSipMessage } from "../protocols/sip/SipDecoder.js";

const LINKTYPE_ETHERNET = 1;
const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;
const ETHERTYPE_VLAN = 0x8100;
const ETHERTYPE_QINQ = 0x88a8;
const ETHERTYPE_QINQ_LEGACY = 0x9100;
const ETHERTYPE_SLOW_PROTOCOLS = 0x8809;

const TRANSPORT_TCP = 6;
const TRANSPORT_UDP = 17;

export interface DecodedNetworkPacket {
  packetIndex: number;
  timestamp: string;
  length: number;
  protocolLabel: string;
  summary: string;
  linkType: number;
  networkProtocol?: "IPv4" | "IPv6";
  transportProtocol?: "TCP" | "UDP";
  sourceAddress?: string;
  destinationAddress?: string;
  sourcePort?: number;
  destinationPort?: number;
  tcpSequenceNumber?: number;
  tcpAckNumber?: number;
  tcpFlags?: number;
  payload?: Buffer;
}

export interface DecodeResult {
  packets: PacketRecord[];
  decodedPackets: DecodedNetworkPacket[];
  warnings: string[];
}

interface TransportDecodeBase {
  sourceAddress: string;
  destinationAddress: string;
  payloadOffset: number;
  packet: RawCapturePacket;
}

function formatMac(buffer: Buffer, offset: number): string {
  return Array.from(buffer.subarray(offset, offset + 6), (byte) => byte.toString(16).padStart(2, "0")).join(":");
}

function formatIpv4(buffer: Buffer, offset: number): string {
  return Array.from(buffer.subarray(offset, offset + 4)).join(".");
}

function formatIpv6(buffer: Buffer, offset: number): string {
  const groups: string[] = [];
  for (let cursor = offset; cursor < offset + 16; cursor += 2) {
    groups.push(buffer.readUInt16BE(cursor).toString(16));
  }

  return groups.join(":");
}

function isVlanType(etherType: number): boolean {
  return etherType === ETHERTYPE_VLAN || etherType === ETHERTYPE_QINQ || etherType === ETHERTYPE_QINQ_LEGACY;
}

function toPacketRecord(decodedPacket: DecodedNetworkPacket): PacketRecord {
  return {
    index: decodedPacket.packetIndex,
    timestamp: decodedPacket.timestamp,
    protocol: decodedPacket.protocolLabel,
    summary: decodedPacket.summary,
    length: decodedPacket.length
  };
}

function decodeSlowProtocols(packet: RawCapturePacket, payloadOffset: number): DecodedNetworkPacket {
  const payload = packet.data.subarray(payloadOffset);
  const subtype = payload[0];

  if (subtype === 0x03) {
    return {
      packetIndex: packet.index,
      timestamp: packet.timestamp,
      length: packet.originalLength,
      protocolLabel: "CTRL",
      summary: "非 SIP 控制帧",
      linkType: packet.linkType,
      payload
    };
  }

  return {
    packetIndex: packet.index,
    timestamp: packet.timestamp,
    length: packet.originalLength,
    protocolLabel: "SLOW",
    summary: `Slow Protocols subtype 0x${(subtype ?? 0).toString(16).padStart(2, "0")}`,
    linkType: packet.linkType,
    payload
  };
}

function decodeUdp(base: TransportDecodeBase): DecodedNetworkPacket {
  const { packet, payloadOffset, sourceAddress, destinationAddress } = base;
  if (payloadOffset + 8 > packet.data.length) {
    return {
      packetIndex: packet.index,
      timestamp: packet.timestamp,
      length: packet.originalLength,
      protocolLabel: "UDP",
      summary: "UDP header truncated",
      linkType: packet.linkType,
      sourceAddress,
      destinationAddress,
      transportProtocol: "UDP"
    };
  }

  const sourcePort = packet.data.readUInt16BE(payloadOffset);
  const destinationPort = packet.data.readUInt16BE(payloadOffset + 2);
  const udpLength = packet.data.readUInt16BE(payloadOffset + 4);
  const payload = packet.data.subarray(payloadOffset + 8);

  if (isSipPayload(payload, sourcePort, destinationPort)) {
    const sipMessage = parseSipMessage(payload);
    if (sipMessage) {
      return {
        packetIndex: packet.index,
        timestamp: packet.timestamp,
        length: packet.originalLength,
        protocolLabel: "SIP",
        summary: summarizeSipMessage(sipMessage, `${sourceAddress}:${sourcePort}`, `${destinationAddress}:${destinationPort}`),
        linkType: packet.linkType,
        transportProtocol: "UDP",
        sourceAddress,
        destinationAddress,
        sourcePort,
        destinationPort,
        payload
      };
    }
  }

  return {
    packetIndex: packet.index,
    timestamp: packet.timestamp,
    length: packet.originalLength,
    protocolLabel: "UDP",
    summary: `${sourceAddress}:${sourcePort} -> ${destinationAddress}:${destinationPort} (len ${udpLength})`,
    linkType: packet.linkType,
    transportProtocol: "UDP",
    sourceAddress,
    destinationAddress,
    sourcePort,
    destinationPort,
    payload
  };
}

function decodeTcp(base: TransportDecodeBase): DecodedNetworkPacket {
  const { packet, payloadOffset, sourceAddress, destinationAddress } = base;
  if (payloadOffset + 20 > packet.data.length) {
    return {
      packetIndex: packet.index,
      timestamp: packet.timestamp,
      length: packet.originalLength,
      protocolLabel: "TCP",
      summary: "TCP header truncated",
      linkType: packet.linkType,
      sourceAddress,
      destinationAddress,
      transportProtocol: "TCP"
    };
  }

  const sourcePort = packet.data.readUInt16BE(payloadOffset);
  const destinationPort = packet.data.readUInt16BE(payloadOffset + 2);
  const sequenceNumber = packet.data.readUInt32BE(payloadOffset + 4);
  const ackNumber = packet.data.readUInt32BE(payloadOffset + 8);
  const dataOffset = (packet.data[payloadOffset + 12] >> 4) * 4;
  const flags = packet.data[payloadOffset + 13];
  const segmentPayloadOffset = payloadOffset + dataOffset;

  if (segmentPayloadOffset > packet.data.length) {
    return {
      packetIndex: packet.index,
      timestamp: packet.timestamp,
      length: packet.originalLength,
      protocolLabel: "TCP",
      summary: `${sourceAddress}:${sourcePort} -> ${destinationAddress}:${destinationPort} (invalid header length)`,
      linkType: packet.linkType,
      transportProtocol: "TCP",
      sourceAddress,
      destinationAddress,
      sourcePort,
      destinationPort,
      tcpSequenceNumber: sequenceNumber,
      tcpAckNumber: ackNumber,
      tcpFlags: flags
    };
  }

  const payload = packet.data.subarray(segmentPayloadOffset);

  return {
    packetIndex: packet.index,
    timestamp: packet.timestamp,
    length: packet.originalLength,
    protocolLabel: "TCP",
    summary: `${sourceAddress}:${sourcePort} -> ${destinationAddress}:${destinationPort}${payload.length > 0 ? ` payload ${payload.length}` : ""}`,
    linkType: packet.linkType,
    transportProtocol: "TCP",
    sourceAddress,
    destinationAddress,
    sourcePort,
    destinationPort,
    tcpSequenceNumber: sequenceNumber,
    tcpAckNumber: ackNumber,
    tcpFlags: flags,
    payload
  };
}

function decodeTransport(base: TransportDecodeBase, protocol: number): DecodedNetworkPacket {
  if (protocol === TRANSPORT_UDP) {
    return decodeUdp(base);
  }

  if (protocol === TRANSPORT_TCP) {
    return decodeTcp(base);
  }

  return {
    packetIndex: base.packet.index,
    timestamp: base.packet.timestamp,
    length: base.packet.originalLength,
    protocolLabel: base.packet.data[12] === 0x08 ? "IPv4" : "IPv6",
    summary: `${base.sourceAddress} -> ${base.destinationAddress} next header ${protocol}`,
    linkType: base.packet.linkType,
    sourceAddress: base.sourceAddress,
    destinationAddress: base.destinationAddress
  };
}

function decodeEthernetPacket(packet: RawCapturePacket): DecodedNetworkPacket {
  if (packet.data.length < 14) {
    return {
      packetIndex: packet.index,
      timestamp: packet.timestamp,
      length: packet.originalLength,
      protocolLabel: "ETH",
      summary: "Ethernet header truncated",
      linkType: packet.linkType
    };
  }

  const destinationMac = formatMac(packet.data, 0);
  const sourceMac = formatMac(packet.data, 6);

  let etherType = packet.data.readUInt16BE(12);
  let payloadOffset = 14;

  while (isVlanType(etherType) && payloadOffset + 4 <= packet.data.length) {
    etherType = packet.data.readUInt16BE(payloadOffset + 2);
    payloadOffset += 4;
  }

  if (etherType === ETHERTYPE_SLOW_PROTOCOLS) {
    return decodeSlowProtocols(packet, payloadOffset);
  }

  if (etherType === ETHERTYPE_IPV4) {
    if (payloadOffset + 20 > packet.data.length) {
      return {
        packetIndex: packet.index,
        timestamp: packet.timestamp,
        length: packet.originalLength,
        protocolLabel: "IPv4",
        summary: "IPv4 header truncated",
        linkType: packet.linkType,
        networkProtocol: "IPv4"
      };
    }

    const ihl = (packet.data[payloadOffset] & 0x0f) * 4;
    const protocol = packet.data[payloadOffset + 9];
    const sourceAddress = formatIpv4(packet.data, payloadOffset + 12);
    const destinationAddress = formatIpv4(packet.data, payloadOffset + 16);
    return {
      ...decodeTransport(
        {
          packet,
          payloadOffset: payloadOffset + ihl,
          sourceAddress,
          destinationAddress
        },
        protocol
      ),
      networkProtocol: "IPv4"
    };
  }

  if (etherType === ETHERTYPE_IPV6) {
    if (payloadOffset + 40 > packet.data.length) {
      return {
        packetIndex: packet.index,
        timestamp: packet.timestamp,
        length: packet.originalLength,
        protocolLabel: "IPv6",
        summary: "IPv6 header truncated",
        linkType: packet.linkType,
        networkProtocol: "IPv6"
      };
    }

    const nextHeader = packet.data[payloadOffset + 6];
    const sourceAddress = formatIpv6(packet.data, payloadOffset + 8);
    const destinationAddress = formatIpv6(packet.data, payloadOffset + 24);
    return {
      ...decodeTransport(
        {
          packet,
          payloadOffset: payloadOffset + 40,
          sourceAddress,
          destinationAddress
        },
        nextHeader
      ),
      networkProtocol: "IPv6"
    };
  }

  return {
    packetIndex: packet.index,
    timestamp: packet.timestamp,
    length: packet.originalLength,
    protocolLabel: "ETH",
    summary: `${sourceMac} -> ${destinationMac} ethertype 0x${etherType.toString(16).padStart(4, "0")}`,
    linkType: packet.linkType
  };
}

function buildTcpSipRecordMap(decodedPackets: DecodedNetworkPacket[]): Map<number, PacketRecord> {
  const result = new Map<number, PacketRecord>();
  const buffers = new Map<string, Buffer>();

  for (const packet of decodedPackets) {
    if (packet.transportProtocol !== "TCP" || !packet.payload || packet.payload.length === 0) {
      continue;
    }

    const source = packet.sourceAddress ? `${packet.sourceAddress}:${packet.sourcePort ?? 0}` : "unknown";
    const destination = packet.destinationAddress ? `${packet.destinationAddress}:${packet.destinationPort ?? 0}` : "unknown";
    const key = `${source}->${destination}`;
    const merged = Buffer.concat([buffers.get(key) ?? Buffer.alloc(0), packet.payload]);
    const extracted = extractSipMessagesFromTcpBuffer(merged);
    buffers.set(key, extracted.remainder);

    for (const messageBuffer of extracted.messages) {
      const sipMessage = parseSipMessage(messageBuffer);
      if (!sipMessage) {
        continue;
      }

      result.set(packet.packetIndex, {
        index: packet.packetIndex,
        timestamp: packet.timestamp,
        protocol: "SIP",
        summary: summarizeSipMessage(sipMessage, source, destination),
        length: packet.length
      });
    }
  }

  return result;
}

export function decodePackets(rawPackets: RawCapturePacket[]): DecodeResult {
  const decodedPackets: DecodedNetworkPacket[] = [];
  const warnings: string[] = [];
  const unsupportedLinkTypes = new Set<number>();

  for (const rawPacket of rawPackets) {
    if (rawPacket.linkType !== LINKTYPE_ETHERNET) {
      unsupportedLinkTypes.add(rawPacket.linkType);
      decodedPackets.push({
        packetIndex: rawPacket.index,
        timestamp: rawPacket.timestamp,
        length: rawPacket.originalLength,
        protocolLabel: `LINKTYPE_${rawPacket.linkType}`,
        summary: `暂未支持的链路层类型 ${rawPacket.linkType}`,
        linkType: rawPacket.linkType,
        payload: rawPacket.data
      });
      continue;
    }

    decodedPackets.push(decodeEthernetPacket(rawPacket));
  }

  if (unsupportedLinkTypes.size > 0) {
    warnings.push(`发现未支持的链路层类型：${Array.from(unsupportedLinkTypes).join(", ")}。`);
  }

  const tcpSipRecordMap = buildTcpSipRecordMap(decodedPackets);
  const packets = decodedPackets.map((decodedPacket) => tcpSipRecordMap.get(decodedPacket.packetIndex) ?? toPacketRecord(decodedPacket));

  return {
    packets,
    decodedPackets,
    warnings
  };
}
