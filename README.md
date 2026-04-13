# PAnalysis

PAnalysis 是一个独立桌面抓包分析软件，当前阶段重点聚焦 `SIP` 和 `RTP`，用于离线分析 `pcap/pcapng` 抓包文件，不做实时抓包。纯AI制作，莫得感情。

当前版本已经具备：

- Electron 桌面壳
- React + TypeScript 渲染界面
- 抓包文件导入 IPC 通道
- 真实 `pcap/pcapng` 文件读取
- `Ethernet / IPv4 / IPv6 / TCP / UDP` 基础解码
- `SIP` 消息解析、呼叫汇总、失败原因分析
- `SIP` 事务级诊断与基础 TCP 分段重组
- `RTP` 流识别、丢包/乱序/抖动统计、媒体异常提示
- `RTCP SR / RR / XR` 基础识别
- `Call-ID` 级时序图
- `SDP diff` 分析

## 目标

项目不打算复刻 Wireshark 全部能力，而是做“专项协议分析器”：

- 聚焦 SIP 呼叫建立、注册和失败归因
- 跟踪 RTP 流并输出媒体质量风险
- 输出异常诊断和分析报告
- 提供更适合研发/运维的专题视图

## 技术栈

- Electron
- React
- TypeScript
- Vite
- Node.js
- pnpm / npm

## 当前目录结构

```text
panalysis/
├─ core/
│  ├─ analyzer/            # 分析引擎入口
│  ├─ capture/pcap/        # pcap/pcapng 文件读取
│  └─ protocols/
│     ├─ omci/             # OMCI 预留入口
│     └─ sip/              # SIP / RTP 分析
├─ electron/
│  ├─ main.ts              # Electron 主进程
│  └─ preload.ts           # 安全桥接层
├─ shared/                 # 主进程 / 渲染进程共享类型
├─ src/
│  ├─ app/                 # React 页面和样式
│  └─ main.tsx             # 前端入口
├─ index.html
├─ package.json
├─ tsconfig.app.json
├─ tsconfig.electron.json
└─ vite.config.ts
```

## 开发启动

### 1. 安装依赖

```bash
pnpm install
```

### 2. 首次运行时批准 Electron / esbuild 构建脚本

如果这是这台机器第一次跑本项目，执行：

```bash
pnpm approve-builds --all
```

### 3. 启动开发环境

这个命令会同时启动：

- Vite 前端开发服务器
- Electron 主进程 TypeScript 监听编译
- Electron 桌面窗口

命令：

```bash
pnpm dev
```

### 4. 类型检查

```bash
pnpm typecheck
```

### 5. 生产构建

```bash
pnpm build
```

### 6. 你实际使用时推荐这样跑

第一次运行：

```bash
pnpm install
pnpm approve-builds --all
pnpm dev
```

后续日常开发：

```bash
pnpm dev
```

## 当前实现说明

这版已经具备：

- 桌面窗口创建
- 抓包文件选择对话框
- 文件基本信息读取
- 分析结果回传到前端界面
- `pcap` / `pcapng` 容器解析
- `Ethernet / IPv4 / IPv6 / TCP / UDP` 首版解析
- `SIP` 请求/响应行、Header、基础 TCP 重组
- `Call-ID / CSeq / ACK / CANCEL` 级别的呼叫归因
- `SIP` 事务级状态分析，如 `success / failed / challenged / timeout / incomplete`
- 常见失败码分析，如 `401 / 403 / 408 / 486 / 488 / 503`
- `SDP` 提取和 RTP 流跟踪
- `SDP diff`，用于观察 codec、地址、方向变化
- `RTCP` 统计报告识别
- RTP 丢包、乱序、抖动、低报文量、疑似单向流、SSRC 切换、长时间间隙等异常提示
- `REGISTER` 风暴、单边 `BYE` 等专项规则
- SIP 专项界面展示

还未完成：

- 更完整的 SIP TCP 重组和乱序段恢复
- 更准确的 RTP 时延、抖动和静音估计
- 更深入的 `RTCP XR` 字段解释
- `OMCI` 消息头和对象级解析
- 规则引擎和导出报告

## 下一步建议

下一轮建议优先做这几件事：

1. 补强 SIP over TCP 的复杂乱序/跨段恢复
2. 继续细化 `RTCP XR`、MOS 相关指标和媒体质量判分
3. 补充 RTP 静音、长时间间隙、单向流缺失和编解码切换检测
4. 增加导出报告与时序图导出
5. 再回头继续做 OMCI
