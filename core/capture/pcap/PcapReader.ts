import { readFile, stat } from "node:fs/promises";
import { basename, extname } from "node:path";
import type { CaptureFileSummary } from "../../../shared/types.js";

type Endianness = "little" | "big";

interface CaptureInterface {
  linkType: number;
  snapLength: number;
  timestampDivisor: number;
}

export interface RawCapturePacket {
  index: number;
  timestamp: string;
  capturedLength: number;
  originalLength: number;
  linkType: number;
  data: Buffer;
}

export interface ParsedCaptureFile {
  capture: CaptureFileSummary;
  packets: RawCapturePacket[];
  warnings: string[];
}

interface ParsedCaptureData {
  packets: RawCapturePacket[];
  warnings: string[];
}

const PCAP_MAGIC_MICROSECONDS_LE = "d4c3b2a1";
const PCAP_MAGIC_MICROSECONDS_BE = "a1b2c3d4";
const PCAP_MAGIC_NANOSECONDS_LE = "4d3cb2a1";
const PCAP_MAGIC_NANOSECONDS_BE = "a1b23c4d";

const PCAPNG_BLOCK_SECTION_HEADER = 0x0a0d0d0a;
const PCAPNG_BLOCK_INTERFACE_DESCRIPTION = 0x00000001;
const PCAPNG_BLOCK_SIMPLE_PACKET = 0x00000003;
const PCAPNG_BLOCK_ENHANCED_PACKET = 0x00000006;
const PCAPNG_BYTE_ORDER_MAGIC_LE = "4d3c2b1a";
const PCAPNG_BYTE_ORDER_MAGIC_BE = "1a2b3c4d";
const PCAPNG_OPTION_IF_TSRESOL = 9;
const DEFAULT_TIMESTAMP_DIVISOR = 1_000_000;

function readUInt16(buffer: Buffer, offset: number, endianness: Endianness): number {
  return endianness === "little" ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
}

function readUInt32(buffer: Buffer, offset: number, endianness: Endianness): number {
  return endianness === "little" ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
}

function toIsoFromTimestamp(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

function getCaptureFormat(filePath: string): CaptureFileSummary["format"] {
  const extension = extname(filePath).toLowerCase();

  if (extension === ".pcap") {
    return "pcap";
  }

  if (extension === ".pcapng") {
    return "pcapng";
  }

  return "unknown";
}

async function buildCaptureSummary(filePath: string): Promise<CaptureFileSummary> {
  const fileStat = await stat(filePath);

  return {
    path: filePath,
    name: basename(filePath),
    sizeInBytes: fileStat.size,
    format: getCaptureFormat(filePath)
  };
}

function parsePcap(buffer: Buffer): ParsedCaptureData {
  const warnings: string[] = [];
  if (buffer.length < 24) {
    throw new Error("pcap 文件头长度不足。");
  }

  const magic = buffer.subarray(0, 4).toString("hex");
  let endianness: Endianness;
  let timestampScale = 1_000_000;

  switch (magic) {
    case PCAP_MAGIC_MICROSECONDS_LE:
      endianness = "little";
      break;
    case PCAP_MAGIC_MICROSECONDS_BE:
      endianness = "big";
      break;
    case PCAP_MAGIC_NANOSECONDS_LE:
      endianness = "little";
      timestampScale = 1_000_000_000;
      break;
    case PCAP_MAGIC_NANOSECONDS_BE:
      endianness = "big";
      timestampScale = 1_000_000_000;
      break;
    default:
      throw new Error("无法识别 pcap 文件魔数。");
  }

  const network = readUInt32(buffer, 20, endianness);
  const packets: RawCapturePacket[] = [];

  let offset = 24;
  let index = 1;

  while (offset + 16 <= buffer.length) {
    const timestampSeconds = readUInt32(buffer, offset, endianness);
    const timestampFraction = readUInt32(buffer, offset + 4, endianness);
    const capturedLength = readUInt32(buffer, offset + 8, endianness);
    const originalLength = readUInt32(buffer, offset + 12, endianness);
    const dataOffset = offset + 16;
    const dataEnd = dataOffset + capturedLength;

    if (dataEnd > buffer.length) {
      warnings.push(`第 ${index} 个 pcap 包长度超出文件边界，已停止解析。`);
      break;
    }

    packets.push({
      index,
      timestamp: toIsoFromTimestamp(timestampSeconds + timestampFraction / timestampScale),
      capturedLength,
      originalLength,
      linkType: network,
      data: buffer.subarray(dataOffset, dataEnd)
    });

    offset = dataEnd;
    index += 1;
  }

  return { packets, warnings };
}

function parseTimestampResolution(optionValue: Buffer): number {
  if (optionValue.length === 0) {
    return DEFAULT_TIMESTAMP_DIVISOR;
  }

  const raw = optionValue[0];
  if ((raw & 0x80) === 0x80) {
    return 2 ** (raw & 0x7f);
  }

  return 10 ** raw;
}

function parseInterfaceOptions(
  buffer: Buffer,
  optionsOffset: number,
  optionsEnd: number,
  endianness: Endianness
): CaptureInterface["timestampDivisor"] {
  let offset = optionsOffset;
  let timestampDivisor = DEFAULT_TIMESTAMP_DIVISOR;

  while (offset + 4 <= optionsEnd) {
    const code = readUInt16(buffer, offset, endianness);
    const length = readUInt16(buffer, offset + 2, endianness);

    if (code === 0) {
      break;
    }

    const valueOffset = offset + 4;
    const valueEnd = valueOffset + length;
    if (valueEnd > optionsEnd) {
      break;
    }

    if (code === PCAPNG_OPTION_IF_TSRESOL) {
      timestampDivisor = parseTimestampResolution(buffer.subarray(valueOffset, valueEnd));
    }

    offset = valueOffset + Math.ceil(length / 4) * 4;
  }

  return timestampDivisor;
}

function parsePcapng(buffer: Buffer): ParsedCaptureData {
  const warnings: string[] = [];
  const packets: RawCapturePacket[] = [];
  const interfaces: CaptureInterface[] = [];

  let currentEndianness: Endianness | null = null;
  let offset = 0;
  let index = 1;

  while (offset + 12 <= buffer.length) {
    const blockType = buffer.readUInt32LE(offset);

    if (blockType === PCAPNG_BLOCK_SECTION_HEADER) {
      if (offset + 16 > buffer.length) {
        warnings.push("pcapng Section Header Block 不完整，已停止解析。");
        break;
      }

      const byteOrderMagic = buffer.subarray(offset + 8, offset + 12).toString("hex");
      if (byteOrderMagic === PCAPNG_BYTE_ORDER_MAGIC_LE) {
        currentEndianness = "little";
      } else if (byteOrderMagic === PCAPNG_BYTE_ORDER_MAGIC_BE) {
        currentEndianness = "big";
      } else {
        throw new Error("无法识别 pcapng 字节序。");
      }

      const blockTotalLength = readUInt32(buffer, offset + 4, currentEndianness);
      if (blockTotalLength < 12 || offset + blockTotalLength > buffer.length) {
        warnings.push("pcapng Section Header Block 长度异常，已停止解析。");
        break;
      }

      interfaces.length = 0;
      offset += blockTotalLength;
      continue;
    }

    if (!currentEndianness) {
      throw new Error("pcapng 文件在 Section Header Block 之前出现了未知块。");
    }

    const blockTotalLength = readUInt32(buffer, offset + 4, currentEndianness);
    if (blockTotalLength < 12 || offset + blockTotalLength > buffer.length) {
      warnings.push(`pcapng 块在偏移 ${offset} 处长度异常，已停止解析。`);
      break;
    }

    const blockBodyStart = offset + 8;
    const blockEnd = offset + blockTotalLength;

    if (blockType === PCAPNG_BLOCK_INTERFACE_DESCRIPTION) {
      if (blockBodyStart + 8 <= blockEnd - 4) {
        const linkType = readUInt16(buffer, blockBodyStart, currentEndianness);
        const snapLength = readUInt32(buffer, blockBodyStart + 4, currentEndianness);
        const timestampDivisor = parseInterfaceOptions(
          buffer,
          blockBodyStart + 8,
          blockEnd - 4,
          currentEndianness
        );

        interfaces.push({
          linkType,
          snapLength,
          timestampDivisor
        });
      }

      offset += blockTotalLength;
      continue;
    }

    if (blockType === PCAPNG_BLOCK_ENHANCED_PACKET) {
      if (blockBodyStart + 20 > blockEnd - 4) {
        warnings.push(`第 ${index} 个 pcapng Enhanced Packet Block 不完整，已跳过。`);
        offset += blockTotalLength;
        continue;
      }

      const interfaceId = readUInt32(buffer, blockBodyStart, currentEndianness);
      const timestampHigh = readUInt32(buffer, blockBodyStart + 4, currentEndianness);
      const timestampLow = readUInt32(buffer, blockBodyStart + 8, currentEndianness);
      const capturedLength = readUInt32(buffer, blockBodyStart + 12, currentEndianness);
      const originalLength = readUInt32(buffer, blockBodyStart + 16, currentEndianness);
      const packetOffset = blockBodyStart + 20;
      const packetEnd = packetOffset + capturedLength;

      if (packetEnd > blockEnd - 4) {
        warnings.push(`第 ${index} 个 pcapng 包长度超出块边界，已跳过。`);
        offset += blockTotalLength;
        continue;
      }

      const captureInterface = interfaces[interfaceId];
      if (!captureInterface) {
        warnings.push(`第 ${index} 个 pcapng 包引用了未知接口 ${interfaceId}，已跳过。`);
        offset += blockTotalLength;
        continue;
      }

      const timestampRaw = (BigInt(timestampHigh) << 32n) | BigInt(timestampLow);
      const seconds = Number(timestampRaw) / captureInterface.timestampDivisor;

      packets.push({
        index,
        timestamp: toIsoFromTimestamp(seconds),
        capturedLength,
        originalLength,
        linkType: captureInterface.linkType,
        data: buffer.subarray(packetOffset, packetEnd)
      });

      index += 1;
      offset += blockTotalLength;
      continue;
    }

    if (blockType === PCAPNG_BLOCK_SIMPLE_PACKET) {
      if (blockBodyStart + 4 > blockEnd - 4) {
        warnings.push(`第 ${index} 个 pcapng Simple Packet Block 不完整，已跳过。`);
        offset += blockTotalLength;
        continue;
      }

      const captureInterface = interfaces[0];
      if (!captureInterface) {
        warnings.push(`第 ${index} 个 pcapng Simple Packet Block 没有关联接口，已跳过。`);
        offset += blockTotalLength;
        continue;
      }

      const originalLength = readUInt32(buffer, blockBodyStart, currentEndianness);
      const packetOffset = blockBodyStart + 4;
      const packetEnd = blockEnd - 4;

      packets.push({
        index,
        timestamp: new Date(0).toISOString(),
        capturedLength: packetEnd - packetOffset,
        originalLength,
        linkType: captureInterface.linkType,
        data: buffer.subarray(packetOffset, packetEnd)
      });

      index += 1;
      offset += blockTotalLength;
      continue;
    }

    offset += blockTotalLength;
  }

  return { packets, warnings };
}

export async function parseCaptureFile(filePath: string): Promise<ParsedCaptureFile> {
  const [capture, buffer] = await Promise.all([buildCaptureSummary(filePath), readFile(filePath)]);

  let parsed: ParsedCaptureData;
  switch (capture.format) {
    case "pcap":
      parsed = parsePcap(buffer);
      break;
    case "pcapng":
      parsed = parsePcapng(buffer);
      break;
    default:
      throw new Error("暂不支持该抓包格式，请使用 pcap 或 pcapng。");
  }

  return {
    capture,
    packets: parsed.packets,
    warnings: parsed.warnings
  };
}
