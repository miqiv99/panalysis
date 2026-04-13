# PAnalysis

PAnalysis is a standalone desktop packet analysis tool currently focused on `SIP`, `RTP`, and `RTCP` for offline `pcap/pcapng` analysis. No live capture for now. Built entirely with AI. Zero feelings included.

The current feature set has not gone through systematic testing yet. More real-world SIP samples and validation will be added over time.

Current capabilities:

- Electron desktop shell
- React + TypeScript renderer UI
- Chinese / English UI switching
- IPC bridge for importing capture files
- Real `pcap/pcapng` file reading
- Basic `Ethernet / IPv4 / IPv6 / TCP / UDP` decoding
- `SIP` message parsing, call summaries, and failure reason analysis
- `SIP` transaction diagnostics with basic TCP segment reassembly
- `RTP` stream identification, packet loss / reordering / jitter statistics, and media anomaly hints
- Basic `RTCP SR / RR / XR` recognition
- `Call-ID` level sequence views
- `SDP diff` analysis

## Goals

This project is not trying to fully replicate Wireshark. It is meant to be a focused protocol analyzer:

- Focus on SIP call setup, registration, and failure attribution
- Track RTP streams and surface media quality risks
- Output diagnostic findings and analysis summaries
- Provide task-oriented views for development and operations

## Tech Stack

- Electron
- React
- TypeScript
- Vite
- Node.js
- pnpm / npm

## Project Structure

```text
panalysis/
├─ core/
│  ├─ analyzer/            # Analysis engine entry
│  ├─ capture/pcap/        # pcap/pcapng readers
│  └─ protocols/
│     ├─ omci/             # Reserved OMCI entry
│     └─ sip/              # SIP / RTP / RTCP analysis
├─ electron/
│  ├─ main.ts              # Electron main process
│  ├─ preload.cts          # Electron preload (CommonJS)
│  └─ preload.ts           # Legacy preload, no longer used as runtime entry
├─ shared/                 # Shared types for main and renderer
├─ src/
│  ├─ app/                 # React UI and styles
│  └─ main.tsx             # Renderer entry
├─ index.html
├─ package.json
├─ tsconfig.app.json
├─ tsconfig.electron.json
└─ vite.config.ts
```

## Development

### 1. Install dependencies

```bash
pnpm install
```

### 2. Approve Electron / esbuild build scripts on first run

If this is the first time you run the project on this machine, execute:

```bash
pnpm approve-builds --all
```

### 3. Start the development environment

This command starts all of the following:

- Vite renderer dev server
- TypeScript watch build for the Electron main process
- Electron desktop window

Command:

```bash
pnpm dev
```

### 4. Type checking

```bash
pnpm typecheck
```

### 5. Production build

```bash
pnpm build
```

### 6. Recommended daily workflow

First run:

```bash
pnpm install
pnpm approve-builds --all
pnpm dev
```

Daily development:

```bash
pnpm dev
```

Notes:

- After `pnpm dev`, the real app is the Electron desktop window
- `http://localhost:5173` is only the renderer preview page and does not include local file access or IPC features

## Current Implementation Status

This version already includes:

- Desktop window creation
- Capture file picker dialog
- Basic file metadata reading
- Returning analysis results to the renderer
- `pcap` / `pcapng` container parsing
- Initial `Ethernet / IPv4 / IPv6 / TCP / UDP` decoding
- `SIP` request/response line parsing, headers, and basic TCP reassembly
- Call attribution based on `Call-ID / CSeq / ACK / CANCEL`
- `SIP` transaction state analysis such as `success / failed / challenged / timeout / incomplete`
- Common failure code analysis such as `401 / 403 / 408 / 486 / 488 / 503`
- `SDP` extraction and RTP stream tracking
- `SDP diff` for codec, address, and direction changes
- `RTCP` report recognition
- RTP anomaly hints for packet loss, reordering, jitter, low packet volume, suspected one-way media, SSRC switching, and long gaps
- Specialized rules such as `REGISTER` storms and one-sided `BYE`
- SIP-focused UI panels

Not finished yet:

- More complete SIP TCP reassembly and out-of-order recovery
- More accurate RTP delay, jitter, and silence estimation
- Deeper `RTCP XR` field interpretation
- `OMCI` header and entity-level parsing
- Rule engine and export reports

## Suggested Next Steps

Recommended priorities for the next round:

1. Strengthen complex SIP-over-TCP out-of-order and cross-segment recovery
2. Extend `RTCP XR`, MOS-related metrics, and media quality scoring
3. Add richer RTP rules for silence, long gaps, one-way media, and codec switching
4. Add report export and sequence diagram export
5. Return to OMCI afterwards
