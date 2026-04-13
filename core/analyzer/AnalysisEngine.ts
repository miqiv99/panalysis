import type { AnalysisResult } from "../../shared/types.js";
import { parseCaptureFile } from "../capture/pcap/PcapReader.js";
import { decodePackets } from "../decoder/PacketDecoder.js";
import { analyzeSip } from "../protocols/sip/SipAnalyzer.js";
import { buildSipSummary } from "../protocols/sip/SipDecoder.js";

export async function analyzeCaptureFile(filePath: string): Promise<AnalysisResult> {
  const parsedCapture = await parseCaptureFile(filePath);
  const decoded = decodePackets(parsedCapture.packets);
  const sip = analyzeSip(decoded.decodedPackets);
  const packets =
    decoded.packets.length > 0
      ? decoded.packets
      : [
          {
            index: 1,
            timestamp: new Date().toISOString(),
            protocol: "SYSTEM",
            summary: "抓包文件读取成功，但暂未解析出可展示的报文。",
            length: 0
          }
        ];

  return {
    capture: parsedCapture.capture,
    packets,
    summaries: [buildSipSummary(sip.totalMessages)],
    warnings: [
      ...parsedCapture.warnings,
      ...decoded.warnings,
      "RTP 统计基于抓包侧观测推断，若抓包点不在媒体路径上，结果可能偏少。"
    ],
    sip
  };
}
