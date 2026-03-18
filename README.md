# Qualcomm Modem UE Log Analyzer

A Python toolkit for parsing and analyzing Qualcomm diagnostic binary log files (`.dlf`, `.isf`, `.hdf`) from 4G LTE and 5G NR modems. Provides signal quality analysis, RRC/NAS event decoding, throughput statistics, and anomaly detection — all from the command line with zero external dependencies.

## Features

- **Binary log parsing**: Reads Qualcomm DIAG `.dlf`, `.isf`, and `.hdf` log formats
- **LTE analysis**: ML1 serving cell measurements, RRC OTA messages, NAS EMM/ESM events, MAC throughput
- **5G NR analysis**: ML1 measurement database, RRC OTA (including v13+ sub-packet format), NAS 5GMM/5GSM events, PDSCH/PUSCH stats
- **RRC decoding**: Extracts PCI, EARFCN/NR-ARFCN, SFN from packet headers; decodes RRC state transitions and serving cell info
- **NAS decoding**: EMM/ESM for LTE, 5GMM/5GSM for NR, with cause code extraction for reject messages
- **Anomaly detection**: Flags signal drops, RRC reestablishments, NAS rejects, poor SINR
- **Throughput calculation**: DL/UL throughput from MAC transport block logs
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
| `qcom_log_analyzer.py` | Core analyzer — parses binary logs and generates reports |
| `qcom_log_agent.py` | Interactive Q&A agent powered by Claude API |

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
| `0xB821` | ML1 Serving Cell Measurement |
| `0xB0E0` | RRC OTA Messages |
| `0xB0C2` | RRC State |
| `0xB0ED` | RRC Serving Cell Info |
| `0xB0C1` | NAS EMM OTA |
| `0xB0C0` | NAS EMM State |
| `0xB0E2` | NAS EMM OTA (Security Protected) |
| `0xB0E3` | NAS ESM OTA |
| `0xB063` | MAC DL Transport Block |
| `0xB064` | MAC UL Transport Block |

### 5G NR
| Code | Description |
|------|-------------|
| `0xB8D2` | ML1 Measurement Database |
| `0xB887` | RRC OTA Messages |
| `0xB808` | RRC State |
| `0xB8D8` | NAS 5GMM State |
| `0xB80A` | NAS 5GSM OTA |
| `0xB80B` | NAS 5GMM OTA Plain |
| `0xB868` | MAC PDSCH Stats |
| `0xB869` | MAC PUSCH Stats |
| `0xB814` | PDCP DL Stats |

## Sample Output

```
============================================================
  QUALCOMM UE LOG ANALYSIS REPORT
============================================================
  File: capture.hdf
  Total packets: 52,341
  Parse errors: 12
  Time range: 2024-03-31 21:19:15 to 2024-03-31 21:24:18
  Duration: 0:05:03

--- Packet Distribution ---
  LTE ML1 Serving Cell Meas        (0xB821):    842
  NR ML1 Meas Database             (0xB8D2):    315
  LTE RRC OTA                      (0xB0E0):     48
  ...

--- LTE Signal Quality ---
  RSRP (dBm): Min=-118.2  Max=-85.3  Avg=-102.4
  RSRQ (dB):  Min=-18.5   Max=-3.2   Avg=-11.7
  SINR (dB):  Min=-5.0    Max=25.3   Avg=12.1

--- RRC Events ---
  NR RRC State: Connected               :   13
  LTE ServingCellInfo                    :   15
  Unique PCIs from RRC: [1, 42, 310]
```

## License

Internal use.
