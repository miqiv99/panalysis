import type { ProtocolSummary } from "../../../shared/types.js";

export function buildCtcOamSummary(packetCount: number): ProtocolSummary {
  return {
    protocol: "CTC OAM",
    packets: packetCount,
    status: "ready",
    note: "已支持首版 CTC OAM 帧识别，后续继续补充 802.3ah 字段和扩展 TLV 解析。"
  };
}
