import type { ProtocolSummary } from "../../../shared/types.js";

export function buildOmciSummary(packetCount: number): ProtocolSummary {
  return {
    protocol: "OMCI",
    packets: packetCount,
    status: "planned",
    note: "预留 ONU 管理消息、Class ID、Entity ID 和操作结果解析入口。"
  };
}
