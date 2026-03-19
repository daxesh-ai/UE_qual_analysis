# Qualcomm Modem UE Log Analyzer

A Python toolkit for parsing and analyzing Qualcomm diagnostic binary log files (`.dlf`, `.isf`, `.hdf`) from 4G LTE and 5G NR modems. Provides signal quality analysis, RRC/NAS event decoding, throughput statistics, and anomaly detection — all from the command line with zero external dependencies.

## Features

- **Binary log parsing**: Reads Qualcomm DIAG `.dlf`, `.isf`, and `.hdf` log formats
- **LTE analysis**: ML1 serving cell measurements (0xB060 + 0xB193), RRC OTA messages, NAS EMM/ESM events, MAC throughput, PDSCH stats
- **5G NR analysis**: ML1 measurement database, serving cell beam (SSB RSRP/RSRQ per beam), RRC OTA (including v13+ sub-packet format), NAS 5GMM/5GSM events, PDSCH/PUSCH stats, PUSCH power control
- **ASN.1 UPER RRC decoding**: Decodes actual PDU content using UPER (Unaligned PER) bit-level parsing for both LTE and NR RRC messages, with channel-type-aware fallbacks
- **RRC decoding**: Extracts PCI, EARFCN/NR-ARFCN, SFN from packet headers; decodes RRC state transitions, serving cell info, release/reestablishment/reject cause codes
- **NAS decoding**: EMM/ESM for LTE, 5GMM/5GSM for NR, with cause code extraction for reject messages. Distinguishes ciphered (sec_hdr 2/4) from integrity-protected (sec_hdr 1/3) messages
- **RACH decoding**: LTE MAC RACH attempts (0xB061 legacy + 0xB168 new) and NR MAC RACH trigger/attempt/response (0xB883-0xB885) with preamble, timing advance, and result extraction
- **Radio Link Failure**: NR RLF report decoding (0xB825)
- **Anomaly detection**: Flags signal drops, RRC reestablishments, NAS rejects, RACH failures, poor SINR
- **Throughput calculation**: DL/UL throughput from MAC transport block logs with correct multi-subframe/slot duration
- **CSV export**: Export parsed events to CSV for further analysis
- **Timeline plots**: Generate signal quality and event timeline plots (requires matplotlib)
- **Interactive AI agent**: Ask natural-language questions about your logs via Claude API

## Requirements

- Python 3.8+
- No external dependencies for core analysis
- Optional: `matplotlib` for `--plot` support
- Optional: `anthropic` SDK (or just set `ANTHROPIC_API_KEY`) for the interactive agent

## Files

| File | Description |
|------|-------------|
| `qcom_log_analyzer.py` | Core analyzer — parses binary logs, UPER RRC decoding, RACH, NAS |
| `qcom_log_agent.py` | Interactive Q&A agent powered by Claude API (requires API key) |
| `claude-project/UE_log_analysis/ue_signal_analyzer.py` | Signaling analyzer — timelines, ladders, failures, RF dashboard, built-in agent |
| `claude-project/UE_log_analysis/apple_log_parser.py` | Apple sysdiagnose parser for iOS cellular logs |

## Usage

### Log Analyzer

```bash
# Basic analysis with summary report
python3 qcom_log_analyzer.py capture.hdf

# Verbose output (shows every decoded packet)
python3 qcom_log_analyzer.py capture.hdf --verbose

# Export parsed events to CSV
python3 qcom_log_analyzer.py capture.hdf --csv --output-dir ./results

# Generate timeline plots
python3 qcom_log_analyzer.py capture.hdf --plot --output-dir ./results

# Filter to a specific technology
python3 qcom_log_analyzer.py capture.hdf --filter-tech nr

# Filter by time range
python3 qcom_log_analyzer.py capture.hdf --time-range "14:30:00" "15:00:00"

# Combine options
python3 qcom_log_analyzer.py capture.hdf --csv --plot --filter-tech lte --output-dir ./out
```

#### Command-Line Options

| Option | Description |
|--------|-------------|
| `logfile` | Path to `.dlf`, `.isf`, or `.hdf` log file |
| `--output-dir`, `-o` | Directory for CSV/plot output |
| `--csv` | Export parsed events to CSV files |
| `--plot` | Generate timeline plots (requires matplotlib) |
| `--filter-tech {lte,nr}` | Filter output to LTE or NR only |
| `--time-range START END` | Filter by time range (`HH:MM:SS` or `YYYY-MM-DD HH:MM:SS`) |
| `--verbose`, `-v` | Show detailed packet-level output |

### Interactive Agent

Ask natural-language questions about your log data using Claude:

```bash
# Set your API key
export ANTHROPIC_API_KEY=sk-ant-...

# Start interactive session
python3 qcom_log_agent.py capture.hdf

# With verbose mode (shows data summary sent to Claude)
python3 qcom_log_agent.py capture.hdf --verbose

# Use a specific model
python3 qcom_log_agent.py capture.hdf --model claude-sonnet-4-20250514
```

Example questions you can ask:
- "What's the average RSRP and SINR?"
- "Were there any RRC reestablishments or NAS rejects?"
- "Show me the handover events"
- "What PCIs and EARFCNs were seen?"
- "Summarize the signal quality over time"

## Supported Log Codes

### LTE

| Code | Description |
|------|-------------|
| `0xB060` | ML1 Serving Cell Measurement |
| `0xB193` | ML1 Serving Cell Measurement (v2, newer logs) |
| `0xB139` | ML1 PDSCH Stat (MCS/modulation/CA) |
| `0xB0E0` | RRC OTA Messages (UPER-decoded) |
| `0xB0C2` | RRC State |
| `0xB0ED` | RRC Serving Cell Info |
| `0xB0C1` | NAS EMM OTA |
| `0xB0C0` | NAS EMM State (with ciphered message detection) |
| `0xB0E2` | NAS EMM OTA (Security Protected) |
| `0xB0E3` | NAS ESM OTA |
| `0xB063` | MAC DL Transport Block |
| `0xB064` | MAC UL Transport Block |
| `0xB061` | MAC RACH Attempt (legacy) |
| `0xB167` | MAC RACH Config (SIB2 PRACH params) |
| `0xB168` | MAC RACH Attempt (Msg1/Msg2/Msg3) |
| `0xB0A0` | PDCP DL Stats |
| `0xB0A1` | PDCP UL Stats |

### 5G NR

| Code | Description |
|------|-------------|
| `0xB8D2` | ML1 Measurement Database |
| `0xB821` | ML1 Serving Cell Beam (SSB RSRP/RSRQ per beam, SINR) |
| `0xB822` | ML1 PDSCH Status (MCS, Rank/MIMO, BLER) |
| `0xB823` | ML1 PUSCH Power (UL power control) |
| `0xB825` | Radio Link Failure Report |
| `0xB883` | MAC RACH Trigger (cause) |
| `0xB884` | MAC RACH Attempt (Msg1 preamble/power) |
| `0xB885` | MAC RACH Response (Msg2 TA/grant/RNTI) |
| `0xB887` | RRC OTA Messages (UPER-decoded, v13+ with NR-ARFCN) |
| `0xB801` | RRC OTA (SA Registration) |
| `0xB802` | NAS OTA (SA NAS signaling) |
| `0xB808` | RRC State |
| `0xB8D8` | NAS 5GMM State |
| `0xB809` | NAS 5GMM State (Alt) |
| `0xB80A` | NAS 5GSM OTA |
| `0xB80B` | NAS 5GMM OTA Plain |
| `0xB868` | MAC PDSCH Stats |
| `0xB869` | MAC PUSCH Stats |
| `0xB8D0` | ML1 Searcher |
| `0xB814` | PDCP DL Stats |

## Message Decoding

### RRC Messages (UPER Decoding)

The analyzer decodes RRC message types directly from the ASN.1 UPER-encoded PDU content rather than relying on header metadata bytes. This produces accurate message names:

| Channel | LTE Messages | NR Messages |
|---------|-------------|-------------|
| BCCH-BCH | MasterInformationBlock | MIB |
| BCCH-DL-SCH | SystemInformation(SIB2-SIB16), SIB1 | SystemInformation(SIB2-SIB14), SIB1 |
| CCCH-DL | RRCConnectionSetup, Reestablishment, Reject | RRCSetup, RRCReject |
| CCCH-UL | RRCConnectionRequest, ReestablishmentRequest | RRCSetupRequest, RRCResumeRequest |
| DCCH-DL | RRCConnectionReconfiguration, SecurityModeCommand, Release, etc. | RRCReconfiguration, SecurityModeCommand, Release, etc. |
| DCCH-UL | MeasurementReport, SecurityModeComplete, UECapabilityInformation, etc. | MeasurementReport, SecurityModeComplete, etc. |

### NAS Messages (Ciphered Detection)

NAS messages are classified by security header type:
- **sec_hdr 0**: Plain NAS — message type decoded directly
- **sec_hdr 1/3**: Integrity-protected only — inner message type extracted from cleartext PDU
- **sec_hdr 2/4**: Ciphered — labeled as `Ciphered NAS EMM` (inner PDU is encrypted)

### Cause Code Tables

- **EMM Cause Codes**: 3GPP TS 24.301 (Attach Reject, TAU Reject, Service Reject, etc.)
- **5GMM Cause Codes**: 3GPP TS 24.501 (Registration Reject, Service Reject, etc.)
- **RRC Release Causes**: CS fallback, handover cancellation, RRC suspend, DRB integrity failure
- **RRC Reestablishment Causes**: Reconfiguration failure, handover failure, other failure
- **RRC Reject Reasons**: Wait timer, max UE reached, congestion

## Sample Output

```
============================================================
  QUALCOMM UE LOG ANALYSIS REPORT
============================================================
  File: capture.hdf
  Total packets: 624,463
  Parse errors: 0
  Time range: 2025-10-04 22:58:06 to 2025-10-04 23:55:59

--- Packet Distribution ---
  LTE NAS EMM State            (0xB0C0):    613
  LTE NAS EMM OTA              (0xB0C1):     89
  NR NAS 5GMM State            (0xB8D8):    197
  NR RRC OTA                   (0xB887):     52
  LTE MAC RACH Attempt         (0xB061):     22

--- RRC Events ---
  NR RRCSetup                  :     44
  NR RRCReject                 :      8
  LTE RACH Failure             :     22

--- Anomalies ---
  rach_failure                 :     22
  rrc_reject                   :      8
```

## License

Internal use.
