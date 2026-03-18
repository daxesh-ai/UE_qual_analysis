#!/usr/bin/env python3
"""
Qualcomm Log Agent — Interactive Q&A powered by Claude API.

Parses a Qualcomm modem log file (.hdf/.dlf/.isf) using qcom_log_analyzer,
then lets you ask natural language questions about the data via Claude.

Usage:
    python3 qcom_log_agent.py <logfile> [--verbose] [--model MODEL]

Requires:
    export ANTHROPIC_API_KEY=sk-...
    Optionally: pip install anthropic  (falls back to urllib if not installed)
"""

import argparse
import json
import os
import ssl
import sys
import urllib.request
from collections import defaultdict
from statistics import mean, median

# ---------------------------------------------------------------------------
# Import from the existing analyzer
# ---------------------------------------------------------------------------

try:
    from qcom_log_analyzer import (
        AnalysisResult,
        DLFParser,
        InsightEngine,
        LOG_CODE_NAMES,
        LTEAnalyzer,
        NR5GAnalyzer,
        # Log code constants for dispatch
        LOG_LTE_ML1_SERV_CELL_MEAS,
        LOG_LTE_RRC_OTA,
        LOG_LTE_NAS_EMM_OTA,
        LOG_LTE_NAS_EMM_STATE,
        LOG_LTE_NAS_EMM_SEC_OTA,
        LOG_LTE_NAS_ESM_OTA,
        LOG_LTE_MAC_DL_TB,
        LOG_LTE_MAC_UL_TB,
        LOG_NR_ML1_MEAS_DB,
        LOG_NR_RRC_OTA,
        LOG_NR_RRC_STATE,
        LOG_NR_NAS_MM5G_STATE,
        LOG_NR_NAS_MM5G_STATE_ALT,
        LOG_NR_NAS_SM5G_OTA,
        LOG_NR_NAS_MM5G_OTA_PLAIN,
        LOG_NR_MAC_PDSCH_STATS,
        LOG_NR_MAC_PUSCH_STATS,
        LOG_NR_PDCP_DL_STATS,
    )
except ImportError as e:
    print(f"[ERROR] Cannot import qcom_log_analyzer: {e}")
    print("        Make sure qcom_log_analyzer.py is in the same directory.")
    sys.exit(1)

try:
    import anthropic
    HAS_ANTHROPIC_SDK = True
except ImportError:
    HAS_ANTHROPIC_SDK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "claude-sonnet-4-20250514"
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"

SYSTEM_PROMPT = """\
You are a Qualcomm modem log analyst. You answer questions about parsed \
Qualcomm DIAG log data. Be concise and cite specific values, timestamps, \
and counts from the data provided. If the data doesn't contain information \
to answer a question, say so clearly. When discussing signal quality, \
use standard telecom terminology (RSRP, RSRQ, SINR, PCI, EARFCN, etc.)."""

# ---------------------------------------------------------------------------
# Data Summary Builder
# ---------------------------------------------------------------------------

def build_data_summary(result: AnalysisResult) -> str:
    """Convert an AnalysisResult into a structured text digest for Claude."""
    sections = []

    # --- Overview ---
    lines = ["## Overview"]
    lines.append(f"- Total packets parsed: {result.total_packets}")
    lines.append(f"- Parse errors: {result.parse_errors}")
    if result.first_timestamp and result.last_timestamp:
        lines.append(f"- Time range: {result.first_timestamp} to {result.last_timestamp}")
        lines.append(f"- Duration: {result.file_duration}")
    lines.append(f"- Signal samples: {len(result.signal_samples)}")
    lines.append(f"- RRC events: {len(result.rrc_events)}")
    lines.append(f"- NAS events: {len(result.nas_events)}")
    lines.append(f"- Throughput samples: {len(result.throughput_samples)}")
    lines.append(f"- Anomalies detected: {len(result.anomalies)}")
    sections.append("\n".join(lines))

    # --- Packet Distribution ---
    if result.packet_counts:
        lines = ["## Packet Distribution (top log codes)"]
        sorted_codes = sorted(result.packet_counts.items(), key=lambda x: -x[1])
        for code, count in sorted_codes[:15]:
            name = LOG_CODE_NAMES.get(code, f"0x{code:04X}")
            lines.append(f"- {name} (0x{code:04X}): {count}")
        sections.append("\n".join(lines))

    # --- Signal Stats per tech ---
    for tech in ("LTE", "NR"):
        samples = [s for s in result.signal_samples if s.tech == tech]
        if not samples:
            continue

        label = "SS-" if tech == "NR" else ""
        lines = [f"## {tech} Signal Quality ({len(samples)} samples)"]

        rsrp_vals = [s.rsrp for s in samples if s.rsrp is not None]
        rsrq_vals = [s.rsrq for s in samples if s.rsrq is not None]
        sinr_vals = [s.sinr for s in samples if s.sinr is not None]

        if rsrp_vals:
            lines.append(
                f"- {label}RSRP (dBm): min={min(rsrp_vals):.1f}, max={max(rsrp_vals):.1f}, "
                f"avg={mean(rsrp_vals):.1f}, median={median(rsrp_vals):.1f}"
            )
        if rsrq_vals:
            lines.append(
                f"- {label}RSRQ (dB): min={min(rsrq_vals):.1f}, max={max(rsrq_vals):.1f}, "
                f"avg={mean(rsrq_vals):.1f}, median={median(rsrq_vals):.1f}"
            )
        if sinr_vals:
            lines.append(
                f"- {label}SINR (dB): min={min(sinr_vals):.1f}, max={max(sinr_vals):.1f}, "
                f"avg={mean(sinr_vals):.1f}, median={median(sinr_vals):.1f}"
            )

        pcis = sorted(set(s.pci for s in samples if s.pci is not None))
        if pcis:
            lines.append(f"- Unique PCIs: {pcis}")

        arfcns = sorted(set(s.earfcn for s in samples if s.earfcn is not None))
        if arfcns:
            arfcn_label = "NR-ARFCN" if tech == "NR" else "EARFCN"
            lines.append(f"- Unique {arfcn_label}s: {arfcns}")

        sections.append("\n".join(lines))

    # --- Signal Timeline (sampled) ---
    sig_samples = sorted(result.signal_samples, key=lambda s: s.timestamp)
    if sig_samples:
        # Sample every Nth to keep under ~60 entries
        n = max(1, len(sig_samples) // 60)
        sampled = sig_samples[::n]
        lines = [f"## Signal Timeline ({len(sampled)} sampled points of {len(sig_samples)} total)"]
        for s in sampled:
            ts = s.timestamp.strftime("%H:%M:%S")
            parts = [f"[{ts}] {s.tech}"]
            if s.rsrp is not None:
                parts.append(f"RSRP={s.rsrp}")
            if s.sinr is not None:
                parts.append(f"SINR={s.sinr}")
            if s.pci is not None:
                parts.append(f"PCI={s.pci}")
            lines.append(" ".join(parts))
        sections.append("\n".join(lines))

    # --- RRC Events ---
    rrc = result.rrc_events
    if rrc:
        lines = ["## RRC Events"]
        counts: dict[str, int] = defaultdict(int)
        for e in rrc:
            counts[f"{e.tech} {e.event}"] += 1
        for evt_name, count in sorted(counts.items(), key=lambda x: -x[1]):
            lines.append(f"- {evt_name}: {count}")

        # Unique PCIs / EARFCNs from RRC events
        rrc_pcis = sorted(set(e.pci for e in rrc if e.pci is not None))
        rrc_earfcns = sorted(set(e.earfcn for e in rrc if e.earfcn is not None))
        if rrc_pcis:
            lines.append(f"- Unique PCIs (from RRC): {rrc_pcis}")
        if rrc_earfcns:
            lines.append(f"- Unique EARFCNs (from RRC): {rrc_earfcns}")

        # Last 20 events
        recent = sorted(rrc, key=lambda x: x.timestamp)[-20:]
        lines.append(f"\nLast {len(recent)} RRC events:")
        for e in recent:
            ts = e.timestamp.strftime("%H:%M:%S.%f")[:-3]
            extra = ""
            if e.pci is not None:
                extra += f" PCI={e.pci}"
            if e.earfcn is not None:
                extra += f" EARFCN={e.earfcn}"
            lines.append(f"  [{ts}] {e.tech} {e.direction} {e.event}{extra}")
        sections.append("\n".join(lines))

    # --- NAS Events ---
    nas = result.nas_events
    if nas:
        lines = ["## NAS Events"]
        counts = defaultdict(int)
        for e in nas:
            counts[f"{e.tech} {e.msg_type}"] += 1
        for msg, count in sorted(counts.items(), key=lambda x: -x[1]):
            lines.append(f"- {msg}: {count}")

        # Reject details
        rejects = [e for e in nas if e.cause_code is not None]
        if rejects:
            lines.append("\nNAS Reject/Failure details:")
            for e in rejects:
                ts = e.timestamp.strftime("%H:%M:%S.%f")[:-3]
                lines.append(
                    f"  [{ts}] {e.tech} {e.msg_type}: cause={e.cause_code} ({e.cause_text})"
                )

        # Last 20 events
        recent = sorted(nas, key=lambda x: x.timestamp)[-20:]
        lines.append(f"\nLast {len(recent)} NAS events:")
        for e in recent:
            ts = e.timestamp.strftime("%H:%M:%S.%f")[:-3]
            cause = f" cause={e.cause_code}" if e.cause_code else ""
            lines.append(f"  [{ts}] {e.tech} {e.direction} {e.msg_type}{cause}")
        sections.append("\n".join(lines))

    # --- Throughput ---
    tp = result.throughput_samples
    if tp:
        lines = ["## Throughput"]
        for tech in ("LTE", "NR"):
            for direction in ("DL", "UL"):
                subset = [s for s in tp if s.tech == tech and s.direction == direction]
                if not subset:
                    continue
                total_bytes = sum(s.bytes_count for s in subset)
                total_ms = sum(s.duration_ms for s in subset)
                avg_mbps = (total_bytes * 8) / (total_ms * 1000) if total_ms > 0 else 0
                peak_mbps = max(s.mbps for s in subset)
                lines.append(
                    f"- {tech} {direction}: total={total_bytes / 1e6:.2f} MB, "
                    f"avg={avg_mbps:.2f} Mbps, peak~{peak_mbps:.2f} Mbps, "
                    f"samples={len(subset)}"
                )
        sections.append("\n".join(lines))

    # --- Anomalies ---
    anomalies = result.anomalies
    if anomalies:
        lines = ["## Anomalies"]

        # Summary by category/severity
        cat_counts: dict[tuple, int] = defaultdict(int)
        for a in anomalies:
            cat_counts[(a.tech, a.category, a.severity)] += 1
        for (tech, cat, sev), count in sorted(cat_counts.items(), key=lambda x: -x[1]):
            lines.append(f"- [{sev.upper()}] {tech} {cat}: {count} occurrences")

        # Full detail for critical anomalies, sampled for warnings
        critical = [a for a in anomalies if a.severity == "critical"]
        warnings = [a for a in anomalies if a.severity == "warning"]

        if critical:
            lines.append(f"\nCritical anomalies ({len(critical)}):")
            for a in critical[:30]:
                ts = a.timestamp.strftime("%H:%M:%S.%f")[:-3]
                lines.append(f"  [{ts}] {a.description}")

        if warnings:
            # Sample warnings to keep size down
            sample_n = max(1, len(warnings) // 20)
            sampled_warnings = warnings[::sample_n]
            lines.append(f"\nWarning anomalies ({len(warnings)} total, showing {len(sampled_warnings)}):")
            for a in sampled_warnings[:30]:
                ts = a.timestamp.strftime("%H:%M:%S.%f")[:-3]
                lines.append(f"  [{ts}] {a.description}")

        sections.append("\n".join(lines))
    else:
        sections.append("## Anomalies\nNo anomalies detected.")

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Parse log file
# ---------------------------------------------------------------------------

def parse_log(logfile: str, verbose: bool = False) -> AnalysisResult:
    """Parse a log file and return a fully analyzed AnalysisResult."""
    parser = DLFParser(logfile, verbose=verbose)
    packets = parser.parse()

    if not packets:
        print("[WARN] No DIAG log packets found in file.")
        sys.exit(1)

    result = AnalysisResult()
    lte_analyzer = LTEAnalyzer(verbose=verbose)
    nr_analyzer = NR5GAnalyzer(verbose=verbose)

    lte_codes = {
        LOG_LTE_ML1_SERV_CELL_MEAS, LOG_LTE_RRC_OTA,
        LOG_LTE_NAS_EMM_OTA, LOG_LTE_NAS_EMM_STATE,
        LOG_LTE_NAS_EMM_SEC_OTA, LOG_LTE_NAS_ESM_OTA,
        LOG_LTE_MAC_DL_TB, LOG_LTE_MAC_UL_TB,
    }
    nr_codes = {
        LOG_NR_ML1_MEAS_DB, LOG_NR_RRC_OTA, LOG_NR_RRC_STATE,
        LOG_NR_NAS_MM5G_STATE, LOG_NR_NAS_MM5G_STATE_ALT,
        LOG_NR_NAS_SM5G_OTA, LOG_NR_NAS_MM5G_OTA_PLAIN,
        LOG_NR_MAC_PDSCH_STATS, LOG_NR_MAC_PUSCH_STATS,
        LOG_NR_PDCP_DL_STATS,
    }

    for pkt in packets:
        result.packet_counts[pkt.log_code] += 1
        result.total_packets += 1
        if pkt.log_code in lte_codes:
            lte_analyzer.decode_packet(pkt, result)
        elif pkt.log_code in nr_codes:
            nr_analyzer.decode_packet(pkt, result)

    # Run insight engine
    engine = InsightEngine()
    engine.analyze(result)

    return result


# ---------------------------------------------------------------------------
# Interactive REPL
# ---------------------------------------------------------------------------

def run_agent(logfile: str, verbose: bool = False, model: str = DEFAULT_MODEL) -> None:
    """Parse the log file, then run an interactive Claude Q&A loop."""
    file_size = os.path.getsize(logfile)
    basename = os.path.basename(logfile)
    print(f"Parsing {basename} ({file_size:,} bytes)...")

    result = parse_log(logfile, verbose=verbose)

    print(f"{result.total_packets} packets parsed.")
    if result.parse_errors:
        print(f"({result.parse_errors} parse errors)")

    summary = build_data_summary(result)

    if verbose:
        print(f"\n--- Data summary ({len(summary)} chars) ---")
        print(summary)
        print("--- End summary ---\n")

    # Initialize Claude client
    api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com")

    if HAS_ANTHROPIC_SDK:
        client = anthropic.Anthropic(api_key=api_key, base_url=base_url)
    else:
        client = None  # will use urllib fallback

    # Conversation history: first message is the data context
    messages = [
        {
            "role": "user",
            "content": (
                f"Here is the parsed Qualcomm modem log data from file '{basename}'.\n"
                f"Use this data to answer my questions.\n\n{summary}"
            ),
        },
        {
            "role": "assistant",
            "content": (
                f"I've loaded the parsed log data from {basename}. "
                f"I can see {result.total_packets} packets"
            ) + (
                f" spanning {result.file_duration}" if result.file_duration else ""
            ) + ". Ask me anything about this log.",
        },
    ]

    print(f"\nReady. Ask me anything about this log (type 'quit' to exit).\n")

    while True:
        try:
            user_input = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            print("Goodbye.")
            break

        messages.append({"role": "user", "content": user_input})

        try:
            assistant_text = _call_claude(client, api_key, base_url, model, messages)
        except Exception as e:
            print(f"\n[API Error] {e}\n")
            messages.pop()  # Remove the failed user message
            continue

        messages.append({"role": "assistant", "content": assistant_text})
        print(f"\n{assistant_text}\n")

        # Trim conversation history if it gets too long (keep data context + last 20 turns)
        if len(messages) > 42:
            messages = messages[:2] + messages[-20:]


def _call_claude(client, api_key: str, base_url: str, model: str, messages: list) -> str:
    """Call Claude API using SDK if available, otherwise urllib."""
    if client is not None:
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=messages,
        )
        return response.content[0].text

    # Fallback: raw HTTP via urllib
    url = f"{base_url.rstrip('/')}/v1/messages"

    body = json.dumps({
        "model": model,
        "max_tokens": 1024,
        "system": SYSTEM_PROMPT,
        "messages": messages,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )

    ctx = ssl.create_default_context()
    # macOS Python may lack bundled certs; try loading system cert bundle
    try:
        ctx.load_verify_locations("/etc/ssl/cert.pem")
    except (OSError, ssl.SSLError):
        pass

    with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
        resp_data = json.loads(resp.read().decode("utf-8"))

    if resp_data.get("type") == "error":
        raise RuntimeError(resp_data["error"].get("message", str(resp_data)))

    return resp_data["content"][0]["text"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Qualcomm Log Agent — Ask Claude about your modem logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 qcom_log_agent.py capture.hdf\n"
            "  python3 qcom_log_agent.py capture.hdf --verbose\n"
            "  python3 qcom_log_agent.py capture.hdf --model claude-sonnet-4-20250514\n"
        ),
    )
    parser.add_argument("logfile", help="Path to .hdf/.dlf/.isf log file")
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show packet-level detail during parsing and print the data summary",
    )
    parser.add_argument(
        "--model", "-m", default=DEFAULT_MODEL,
        help=f"Claude model to use (default: {DEFAULT_MODEL})",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.logfile):
        print(f"[ERROR] File not found: {args.logfile}")
        return 1

    api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")
    if not api_key:
        print("[ERROR] No API key found. Set one of:")
        print("        export ANTHROPIC_API_KEY=sk-ant-...")
        print("        export ANTHROPIC_AUTH_TOKEN=...")
        return 1

    try:
        run_agent(args.logfile, verbose=args.verbose, model=args.model)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
