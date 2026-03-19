#!/usr/bin/env python3
"""
Qualcomm Modem UE Log Analyzer
Parses raw Qualcomm diagnostic binary log files (.dlf/.isf/.hdf) and provides
comprehensive insights for 5G NR and LTE: signal quality, call/data events,
NAS/registration issues, and throughput.

No external dependencies beyond the standard library (+ optional matplotlib for plots).
"""

import argparse
import csv
import io
import os
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
from pathlib import Path
from statistics import mean, median
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants — Qualcomm DIAG log codes
# ---------------------------------------------------------------------------

# LTE log codes
LOG_LTE_ML1_SERV_CELL_MEAS = 0xB193
LOG_LTE_RRC_OTA = 0xB0E0
LOG_LTE_NAS_EMM_OTA = 0xB0C1
LOG_LTE_NAS_EMM_STATE = 0xB0C0
LOG_LTE_NAS_EMM_SEC_OTA = 0xB0E2  # NAS EMM OTA (Security Protected)
LOG_LTE_NAS_ESM_OTA = 0xB0E3      # NAS ESM OTA (Session Management)
LOG_LTE_MAC_DL_TB = 0xB063
LOG_LTE_MAC_UL_TB = 0xB064
LOG_LTE_MAC_RACH = 0xB061
LOG_LTE_RRC_STATE = 0xB0C2
LOG_LTE_PDCP_DL_STATS = 0xB0A0
LOG_LTE_PDCP_UL_STATS = 0xB0A1
LOG_LTE_RRC_SERV_CELL_INFO = 0xB0ED

# 5G NR log codes
LOG_NR_ML1_MEAS_DB = 0xB8D2
LOG_NR_RRC_OTA = 0xB887
LOG_NR_RRC_STATE = 0xB808         # NR RRC State
LOG_NR_NAS_MM5G_STATE = 0xB8D8
LOG_NR_NAS_MM5G_STATE_ALT = 0xB809  # NR NAS 5GMM State (alternative)
LOG_NR_NAS_SM5G_OTA = 0xB80A
LOG_NR_NAS_MM5G_OTA_PLAIN = 0xB80B  # NR NAS 5GMM OTA Plain
LOG_NR_MAC_PDSCH_STATS = 0xB868
LOG_NR_MAC_PUSCH_STATS = 0xB869
LOG_NR_ML1_SEARCHER = 0xB8D0
LOG_NR_PDCP_DL_STATS = 0xB814     # NR PDCP DL Stats

# DIAG command codes
DIAG_LOG_F = 0x10  # Log packet
DIAG_EVENT_F = 0x60  # Event
DIAG_EXT_MSG_F = 0x79  # Extended message

# QXDM DLF file magic / marker
DLF_HEADER_MAGIC = b"\x1A\x00"  # Common DLF preamble tag
ISF_HEADER_MAGIC = b"\x01\x00"

LOG_CODE_NAMES = {
    LOG_LTE_ML1_SERV_CELL_MEAS: "LTE ML1 Serving Cell Meas",
    LOG_LTE_RRC_OTA: "LTE RRC OTA",
    LOG_LTE_RRC_STATE: "LTE RRC State",
    LOG_LTE_NAS_EMM_OTA: "LTE NAS EMM OTA",
    LOG_LTE_NAS_EMM_STATE: "LTE NAS EMM State",
    LOG_LTE_NAS_EMM_SEC_OTA: "LTE NAS EMM OTA (Sec Protected)",
    LOG_LTE_NAS_ESM_OTA: "LTE NAS ESM OTA",
    LOG_LTE_MAC_DL_TB: "LTE MAC DL Transport Block",
    LOG_LTE_MAC_UL_TB: "LTE MAC UL Transport Block",
    LOG_LTE_MAC_RACH: "LTE MAC RACH Attempt",
    LOG_LTE_PDCP_DL_STATS: "LTE PDCP DL Stats",
    LOG_LTE_PDCP_UL_STATS: "LTE PDCP UL Stats",
    LOG_LTE_RRC_SERV_CELL_INFO: "LTE RRC Serving Cell Info",
    LOG_NR_ML1_MEAS_DB: "NR ML1 Meas Database",
    LOG_NR_RRC_OTA: "NR RRC OTA",
    LOG_NR_RRC_STATE: "NR RRC State",
    LOG_NR_NAS_MM5G_STATE: "NR NAS 5GMM State",
    LOG_NR_NAS_MM5G_STATE_ALT: "NR NAS 5GMM State (Alt)",
    LOG_NR_NAS_SM5G_OTA: "NR NAS 5GSM OTA",
    LOG_NR_NAS_MM5G_OTA_PLAIN: "NR NAS 5GMM OTA Plain",
    LOG_NR_MAC_PDSCH_STATS: "NR MAC PDSCH Stats",
    LOG_NR_MAC_PUSCH_STATS: "NR MAC PUSCH Stats",
    LOG_NR_ML1_SEARCHER: "NR ML1 Searcher",
    LOG_NR_PDCP_DL_STATS: "NR PDCP DL Stats",
}

# NAS EMM cause codes (3GPP TS 24.301 §9.9.3.9)
EMM_CAUSE_CODES = {
    2: "IMSI unknown in HSS",
    3: "Illegal UE",
    5: "IMEI not accepted",
    6: "Illegal ME",
    7: "EPS services not allowed",
    8: "EPS and non-EPS services not allowed",
    9: "UE identity cannot be derived",
    10: "Implicitly detached",
    11: "PLMN not allowed",
    12: "Tracking area not allowed",
    13: "Roaming not allowed in this TA",
    14: "EPS services not allowed in this PLMN",
    15: "No suitable cells in TA",
    16: "MSC temporarily not reachable",
    17: "Network failure",
    18: "CS domain not available",
    19: "ESM failure",
    20: "MAC failure",
    21: "Synch failure",
    22: "Congestion",
    25: "Not authorized for this CSG",
    35: "Requested service option not authorized",
    39: "CS service temporarily not available",
    40: "No EPS bearer context activated",
    42: "Severe network failure",
}

# 5GMM cause codes (3GPP TS 24.501 §9.11.3.2)
MM5G_CAUSE_CODES = {
    3: "Illegal UE",
    5: "PEI not accepted",
    6: "Illegal ME",
    7: "5GS services not allowed",
    9: "UE identity cannot be derived",
    10: "Implicitly de-registered",
    11: "PLMN not allowed",
    12: "Tracking area not allowed",
    13: "Roaming not allowed in this TA",
    15: "No suitable cells in TA",
    20: "MAC failure",
    21: "Synch failure",
    22: "Congestion",
    27: "N1 mode not allowed",
    28: "Restricted service area",
    31: "Redirection to EPC required",
    62: "No network slices available",
    65: "Maximum number of PDU sessions reached",
    67: "Insufficient resources for specific slice and DNN",
    69: "Insufficient resources for specific slice",
    71: "ngKSI already in use",
    72: "Non-3GPP access to 5GCN not allowed",
    73: "Serving network not authorized",
    74: "Temporarily not authorized for this SNPN",
    76: "Not authorized for this CAG or authorized for CAG cells only",
    90: "Payload was not forwarded",
    95: "Semantically incorrect message",
    96: "Invalid mandatory information",
    97: "Message type non-existent or not implemented",
    99: "Message type not compatible with protocol state",
    100: "Information element non-existent or not implemented",
    101: "Conditional IE error",
    111: "Protocol error, unspecified",
}

# LTE RRC states
LTE_RRC_STATES = {0: "Idle", 1: "Connected", 2: "Inactive"}

# NR RRC states
NR_RRC_STATES = {0: "Idle", 1: "Connected", 2: "Inactive"}

# RRC message type names (subset)
LTE_RRC_MSG_TYPES = {
    0: "MasterInformationBlock",
    1: "SystemInformationBlockType1",
    2: "SystemInformation",
    3: "RRCConnectionRequest",
    4: "RRCConnectionSetup",
    5: "RRCConnectionSetupComplete",
    6: "RRCConnectionReconfiguration",
    7: "RRCConnectionReconfigurationComplete",
    8: "RRCConnectionRelease",
    9: "RRCConnectionReestablishmentRequest",
    10: "RRCConnectionReestablishment",
    11: "RRCConnectionReestablishmentComplete",
    12: "RRCConnectionReestablishmentReject",
    13: "SecurityModeCommand",
    14: "SecurityModeComplete",
    15: "SecurityModeFailure",
    16: "UECapabilityEnquiry",
    17: "UECapabilityInformation",
    18: "DLInformationTransfer",
    19: "ULInformationTransfer",
    20: "MeasurementReport",
    21: "Paging",
    22: "CounterCheck",
    23: "CounterCheckResponse",
    24: "UEInformationRequest",
    25: "UEInformationResponse",
    26: "ProximityIndication",
    27: "RNReconfiguration",
    28: "RNReconfigurationComplete",
    29: "MBMSCountingRequest",
    30: "MBMSCountingResponse",
}

NR_RRC_MSG_TYPES = {
    0: "MIB",
    1: "SIB1",
    2: "RRCSetupRequest",
    3: "RRCSetup",
    4: "RRCSetupComplete",
    5: "RRCReconfiguration",
    6: "RRCReconfigurationComplete",
    7: "RRCRelease",
    8: "RRCReestablishmentRequest",
    9: "RRCReestablishment",
    10: "RRCReestablishmentComplete",
    11: "SecurityModeCommand",
    12: "SecurityModeComplete",
    13: "DLInformationTransfer",
    14: "ULInformationTransfer",
    15: "MeasurementReport",
    16: "RRCReject",
    17: "RRCResume",
    18: "RRCResumeRequest",
    19: "RRCResumeComplete",
    20: "RRCSystemInfoRequest",
    21: "UEAssistanceInformation",
    22: "FailureInformation",
    23: "ULDedicatedMessageSegment",
    24: "DedicatedSIBRequest",
}

# ---------------------------------------------------------------------------
# UPER (ASN.1 Unaligned PER) message-type lookup tables
# These map the c1 CHOICE index in the first PDU byte to message names,
# keyed by channel type ID.  Format: channel_type -> (num_c1_bits, [msg_names])
# ---------------------------------------------------------------------------

_LTE_UPER_CHANNEL_C1 = {
    # BCCH-BCH (chan 0): single message, no c1 bits needed
    0: (0, ["MasterInformationBlock"]),
    # BCCH-DL-SCH (chan 1): c1 = 2 bits (4 choices)
    1: (2, ["SystemInformation", "SystemInformationBlockType1", None, None]),
    # CCCH-DL (chan 2): c1 = 2 bits
    2: (2, ["RRCConnectionReestablishment", "RRCConnectionReestablishmentReject",
            "RRCConnectionSetup", None]),
    # CCCH-UL (chan 3): c1 = 1 bit
    3: (1, ["RRCConnectionReestablishmentRequest", "RRCConnectionRequest"]),
    # DCCH-DL (chan 4): c1 = 4 bits (16 choices)
    4: (4, [
        "CSFBParametersResponseCDMA2000", "DLInformationTransfer",
        "HandoverFromEUTRAPreparationRequest", "MobilityFromEUTRACommand",
        "RRCConnectionReconfiguration", "RRCConnectionRelease",
        "SecurityModeCommand", "UECapabilityEnquiry",
        "CounterCheck", "UEInformationRequest",
        "LoggedMeasurementConfiguration", "RNReconfiguration",
        None, None, None, None,
    ]),
    # DCCH-UL (chan 5): c1 = 4 bits (16 choices)
    5: (4, [
        "CSFBParametersRequestCDMA2000", "MeasurementReport",
        "RRCConnectionReconfigurationComplete", "RRCConnectionReestablishmentComplete",
        "RRCConnectionSetupComplete", "SecurityModeComplete",
        "SecurityModeFailure", "UECapabilityInformation",
        "ULHandoverPreparationTransfer", "ULInformationTransfer",
        "CounterCheckResponse", "UEInformationResponse",
        "ProximityIndication", "RNReconfigurationComplete",
        None, None,
    ]),
    # PCCH (chan 6): c1 = 1 bit
    6: (1, ["Paging", None]),
}

_NR_UPER_CHANNEL_C1 = {
    # BCCH-BCH (chan 0): single message
    0: (0, ["MIB"]),
    # BCCH-DL-SCH (chan 1): c1 = 2 bits
    1: (2, ["SystemInformation", "SIB1", None, None]),
    # CCCH-DL (chan 2): c1 = 2 bits (4 choices in NR DL-CCCH)
    2: (2, ["RRCReject", "RRCSetup", None, None]),
    # CCCH-UL (chan 3): c1 = 2 bits
    3: (2, ["RRCSetupRequest", "RRCResumeRequest", "RRCReestablishmentRequest",
            "RRCSystemInfoRequest"]),
    # DCCH-DL (chan 4): c1 = 4 bits (16 choices)
    4: (4, [
        "RRCReconfiguration", "RRCResume", "RRCRelease",
        "RRCReestablishment", "SecurityModeCommand",
        "DLInformationTransfer", "UECapabilityEnquiry",
        "CounterCheck", "MobilityFromNRCommand",
        "DLDedicatedMessageSegment", "UEInformationRequest",
        None, None, None, None, None,
    ]),
    # DCCH-UL (chan 5): c1 = 4 bits
    5: (4, [
        "MeasurementReport", "RRCReconfigurationComplete",
        "RRCSetupComplete", "RRCReestablishmentComplete",
        "RRCResumeComplete", "SecurityModeComplete",
        "SecurityModeFailure", "ULInformationTransfer",
        "LocationMeasurementIndication", "UECapabilityInformation",
        "CounterCheckResponse", "UEAssistanceInformation",
        "FailureInformation", "ULInformationTransferMRDC",
        None, None,
    ]),
    # PCCH (chan 6): c1 = 1 bit
    6: (1, ["Paging", None]),
}

# SIB type maps: CHOICE index inside SystemInformation → SIB name
_LTE_SIB_TYPES = {
    0: "SIB2", 1: "SIB3", 2: "SIB4", 3: "SIB5", 4: "SIB6",
    5: "SIB7", 6: "SIB8", 7: "SIB9", 8: "SIB10", 9: "SIB11",
    10: "SIB12", 11: "SIB13", 12: "SIB14", 13: "SIB15", 14: "SIB16",
}

_NR_SIB_TYPES = {
    0: "SIB2", 1: "SIB3", 2: "SIB4", 3: "SIB5", 4: "SIB6",
    5: "SIB7", 6: "SIB8", 7: "SIB9", 8: "SIB10", 9: "SIB11",
    10: "SIB12", 11: "SIB13", 12: "SIB14",
}


def _decode_rrc_msg_from_pdu(pdu: bytes, chan_type: int, tech: str) -> Optional[str]:
    """
    Extract message type name from UPER-encoded RRC PDU bytes.

    The first byte of an ASN.1 UPER RRC PDU contains:
      bit 7 = outer CHOICE (0 = c1, 1 = messageClassExtension)
      next N bits = c1 index (N depends on channel type)

    For SystemInformation messages, also attempts to identify which SIB
    from the second byte.

    Returns message name string or None if decoding fails.
    """
    if not pdu:
        return None

    channel_table = _NR_UPER_CHANNEL_C1 if tech == "NR" else _LTE_UPER_CHANNEL_C1
    sib_table = _NR_SIB_TYPES if tech == "NR" else _LTE_SIB_TYPES

    entry = channel_table.get(chan_type)
    if entry is None:
        return None

    num_c1_bits, msg_list = entry

    # Special case: no c1 bits needed (e.g., BCCH-BCH = always MIB)
    if num_c1_bits == 0:
        return msg_list[0] if msg_list else None

    first_byte = pdu[0]

    # Bit 7 = outer CHOICE: 0 = c1, 1 = messageClassExtension
    outer_choice = (first_byte >> 7) & 1
    if outer_choice != 0:
        # messageClassExtension — can't decode further
        return None

    # Extract c1 index from the next N bits (bits 6 down to 6-N+1)
    shift = 7 - num_c1_bits
    mask = (1 << num_c1_bits) - 1
    c1_index = (first_byte >> shift) & mask

    if c1_index >= len(msg_list):
        return None

    msg_name = msg_list[c1_index]
    if msg_name is None:
        return None

    # For SystemInformation, try to identify which SIB
    if msg_name == "SystemInformation" and len(pdu) >= 2:
        # The SIB type CHOICE index is typically in the upper bits of byte 2
        # (after remaining bits from the message header)
        second_byte = pdu[1]
        sib_index = (second_byte >> 4) & 0x0F
        sib_name = sib_table.get(sib_index)
        if sib_name:
            msg_name = f"SystemInformation({sib_name})"

    return msg_name


NAS_EMM_MSG_TYPES = {
    0x41: "Attach Request",
    0x42: "Attach Accept",
    0x43: "Attach Complete",
    0x44: "Attach Reject",
    0x45: "Detach Request",
    0x46: "Detach Accept",
    0x48: "Tracking Area Update Request",
    0x49: "Tracking Area Update Accept",
    0x4B: "Tracking Area Update Reject",
    0x4C: "Extended Service Request",
    0x4E: "Service Reject",
    0x50: "GUTI Reallocation Command",
    0x51: "GUTI Reallocation Complete",
    0x52: "Authentication Request",
    0x53: "Authentication Response",
    0x54: "Authentication Reject",
    0x55: "Authentication Failure",
    0x56: "Identity Request",
    0x57: "Identity Response",
    0x5C: "Security Mode Command",
    0x5D: "Security Mode Complete",
    0x5E: "Security Mode Reject",
    0x60: "EMM Status",
    0x61: "EMM Information",
    0x62: "Downlink NAS Transport",
    0x63: "Uplink NAS Transport",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DiagPacket:
    """Represents a single DIAG protocol packet extracted from a log file."""
    cmd_code: int
    log_code: int
    timestamp: datetime
    length: int
    payload: bytes
    file_offset: int = 0

    @property
    def log_name(self) -> str:
        return LOG_CODE_NAMES.get(self.log_code, f"0x{self.log_code:04X}")

    @property
    def tech(self) -> str:
        if 0xB000 <= self.log_code <= 0xB0FF:
            return "LTE"
        if 0xB100 <= self.log_code <= 0xB1FF:
            return "LTE"  # LTE ML1 (Layer 1 measurements)
        if 0xB800 <= self.log_code <= 0xB8FF:
            return "NR"
        if 0xB060 <= self.log_code <= 0xB06F:
            return "LTE"
        return "Unknown"


@dataclass
class SignalSample:
    timestamp: datetime
    tech: str  # "LTE" or "NR"
    rsrp: Optional[float] = None
    rsrq: Optional[float] = None
    rssi: Optional[float] = None
    sinr: Optional[float] = None
    pci: Optional[int] = None
    earfcn: Optional[int] = None  # or NR-ARFCN
    band: Optional[int] = None


@dataclass
class RRCEvent:
    timestamp: datetime
    tech: str
    event: str  # e.g. "RRCConnectionSetup", "RRCRelease"
    direction: str = ""  # "UL" or "DL"
    details: str = ""
    pci: Optional[int] = None
    earfcn: Optional[int] = None  # EARFCN or NR-ARFCN
    sfn: Optional[int] = None  # System Frame Number


@dataclass
class NASEvent:
    timestamp: datetime
    tech: str
    msg_type: str
    direction: str = ""
    cause_code: Optional[int] = None
    cause_text: str = ""
    details: str = ""


@dataclass
class ThroughputSample:
    timestamp: datetime
    tech: str
    direction: str  # "DL" or "UL"
    bytes_count: int = 0
    tb_count: int = 0
    duration_ms: float = 0.0

    @property
    def mbps(self) -> float:
        if self.duration_ms > 0:
            return (self.bytes_count * 8) / (self.duration_ms * 1000)
        return 0.0


@dataclass
class Anomaly:
    timestamp: datetime
    tech: str
    category: str  # "signal_drop", "nas_reject", "rrc_reestablish", "poor_sinr"
    severity: str  # "warning", "critical"
    description: str
    value: Optional[float] = None


@dataclass
class AnalysisResult:
    signal_samples: List[SignalSample] = field(default_factory=list)
    rrc_events: List[RRCEvent] = field(default_factory=list)
    nas_events: List[NASEvent] = field(default_factory=list)
    throughput_samples: List[ThroughputSample] = field(default_factory=list)
    anomalies: List[Anomaly] = field(default_factory=list)
    packet_counts: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    total_packets: int = 0
    parse_errors: int = 0
    file_duration: Optional[timedelta] = None
    first_timestamp: Optional[datetime] = None
    last_timestamp: Optional[datetime] = None


# ---------------------------------------------------------------------------
# DLF / ISF Binary Parser
# ---------------------------------------------------------------------------

class DLFParser:
    """
    Parse Qualcomm DIAG binary log files (.dlf, .isf, .hdf).

    DLF format:
    - File may start with a file-level header (variable).
    - Packets follow HDLC-like framing with 0x7E delimiters, or are stored
      as length-prefixed records depending on the tool version.
    - Each log packet: [cmd_code(1)][more(1)][len(2)][log_code(2)][ts(8)][payload]

    We support two common layouts:
      A) HDLC-framed (0x7E delimited) — classic DIAG serial capture
      B) Length-prefixed record stream — QXDM DLF export format
    """

    # Qualcomm DIAG timestamp epoch: Jan 6, 1980 00:00:00 UTC
    DIAG_EPOCH = datetime(1980, 1, 6)
    # DIAG time unit: 1/52428800 seconds per tick.
    # The 8-byte timestamp is a 64-bit count of ticks since the DIAG epoch,
    # stored as two 32-bit LE words.
    DIAG_TS_RESOLUTION = 1.0 / 52428800.0  # seconds per tick

    def __init__(self, filepath: str, verbose: bool = False):
        self.filepath = filepath
        self.verbose = verbose
        self.packets: List[DiagPacket] = []

    # HDF file magic: ASCII ".hdf" at offset 0
    HDF_MAGIC = b".hdf"
    # HDF record delimiter
    HDF_DELIMITER = b"\xff\xff\xff\xff"

    def parse(self) -> List[DiagPacket]:
        filepath = self.filepath
        with open(filepath, "rb") as f:
            data = f.read()

        if len(data) < 16:
            print(f"[WARN] File too small ({len(data)} bytes), may be empty.")
            return []

        # Detect HDF container format (magic ".hdf" at offset 0, or .hdf extension
        # with 0xFFFFFFFF delimiters present)
        is_hdf = data[:4] == self.HDF_MAGIC
        if not is_hdf and filepath.lower().endswith(".hdf"):
            # Also detect by delimiter density — real HDF files have many 0xFFFFFFFF
            delim_count = data.count(self.HDF_DELIMITER)
            if delim_count > 5:
                is_hdf = True

        if is_hdf:
            self._parse_hdf(data)
        elif data.count(b"\x7e") > 10:
            # Try HDLC-framed parsing (0x7E delimiters)
            self._parse_hdlc(data)
        else:
            # Try length-prefixed record stream
            self._parse_length_prefixed(data)

        # If no approach found packets, try a brute-force scan for log headers
        if not self.packets:
            self._parse_bruteforce(data)

        if self.verbose and self.packets:
            print(f"[INFO] Parsed {len(self.packets)} packets from {filepath}")

        return self.packets

    def _parse_hdlc(self, data: bytes) -> None:
        """Parse HDLC-framed DIAG packets (0x7E delimited)."""
        frames = []
        i = 0
        n = len(data)

        # Find frame boundaries
        while i < n:
            # Skip to next 0x7E
            start = data.find(b"\x7e", i)
            if start == -1:
                break
            # Find end delimiter
            end = data.find(b"\x7e", start + 1)
            if end == -1:
                break
            # Skip empty frames (consecutive 0x7E bytes)
            if end == start + 1:
                i = end
                continue
            frame_data = data[start + 1 : end]
            if len(frame_data) >= 12:
                frames.append((start, frame_data))
            i = end

        for offset, frame in frames:
            # Unescape HDLC: 0x7D 0x5E -> 0x7E, 0x7D 0x5D -> 0x7D
            unescaped = self._hdlc_unescape(frame)
            # Strip CRC (last 2 bytes)
            if len(unescaped) > 2:
                unescaped = unescaped[:-2]
            pkt = self._decode_log_packet(unescaped, offset)
            if pkt:
                self.packets.append(pkt)

    def _hdlc_unescape(self, data: bytes) -> bytes:
        result = bytearray()
        i = 0
        while i < len(data):
            if data[i] == 0x7D and i + 1 < len(data):
                result.append(data[i + 1] ^ 0x20)
                i += 2
            else:
                result.append(data[i])
                i += 1
        return bytes(result)

    def _parse_hdf(self, data: bytes) -> None:
        """
        Parse HDF container format used by QXDM.
        HDF files use 0xFFFFFFFF as record delimiters. Each DIAG packet sits
        between consecutive delimiters. Records where byte[0] == 0x10 are
        DIAG_LOG_F log packets.
        """
        delimiter = self.HDF_DELIMITER
        delim_len = len(delimiter)
        n = len(data)
        parsed = 0
        skipped = 0
        ext_msg_count = 0
        event_count = 0

        # Find all delimiter positions
        positions = []
        pos = data.find(delimiter)
        while pos != -1:
            positions.append(pos)
            pos = data.find(delimiter, pos + delim_len)

        if self.verbose:
            print(f"[INFO] HDF format: found {len(positions)} delimiters")

        # Extract records between consecutive delimiters
        for i in range(len(positions) - 1):
            rec_start = positions[i] + delim_len
            rec_end = positions[i + 1]

            if rec_end <= rec_start:
                continue

            record = data[rec_start:rec_end]
            if len(record) < 16:
                skipped += 1
                continue

            cmd_code = record[0]

            if cmd_code == DIAG_LOG_F:
                pkt = self._decode_log_packet(record, rec_start)
                if pkt:
                    self.packets.append(pkt)
                    parsed += 1
                else:
                    skipped += 1
            elif cmd_code == DIAG_EXT_MSG_F:
                ext_msg_count += 1
            elif cmd_code == DIAG_EVENT_F:
                event_count += 1
            else:
                skipped += 1

        if self.verbose:
            print(
                f"[INFO] HDF: {parsed} log packets, "
                f"{ext_msg_count} ext_msg, {event_count} events, "
                f"{skipped} skipped"
            )

    def _parse_length_prefixed(self, data: bytes) -> None:
        """
        Parse length-prefixed record format.
        Common DLF layout: each record starts with a 2-byte little-endian length,
        followed by the record payload of that length. Some files have a file
        header we need to skip.
        """
        offset = 0
        n = len(data)

        # Try to detect and skip file-level header
        # Common pattern: first few bytes might be a header; look for the first
        # valid DIAG_LOG_F command code
        offset = self._find_first_log_record(data)

        while offset + 4 < n:
            # Read record length (2 bytes LE)
            rec_len = struct.unpack_from("<H", data, offset)[0]

            if rec_len < 12 or rec_len > 65535 or offset + 2 + rec_len > n:
                offset += 1  # skip and try next byte
                continue

            record = data[offset + 2 : offset + 2 + rec_len]
            pkt = self._decode_log_packet(record, offset)
            if pkt:
                self.packets.append(pkt)
                offset += 2 + rec_len
            else:
                offset += 1

    def _find_first_log_record(self, data: bytes) -> int:
        """Scan for the first valid DIAG log record header."""
        n = len(data)
        for i in range(min(n - 16, 4096)):
            if data[i] == DIAG_LOG_F:
                # Check if this looks like a valid log packet header
                if i + 16 <= n:
                    try:
                        # cmd(1) + rsvd(1) + outer_len(2) + inner_len(2)
                        # + log_code(2) + ts(8)
                        outer_len = struct.unpack_from("<H", data, i + 2)[0]
                        inner_len = struct.unpack_from("<H", data, i + 4)[0]
                        log_code = struct.unpack_from("<H", data, i + 6)[0]
                        if (10 < outer_len < 65535
                                and inner_len == outer_len
                                and log_code > 0):
                            return max(0, i - 2)  # back up for length prefix
                    except struct.error:
                        continue
        return 0

    def _parse_bruteforce(self, data: bytes) -> None:
        """
        Brute-force scan for known log codes in the binary data.
        Looks for the DIAG_LOG_F command code followed by known log code patterns.
        """
        n = len(data)
        known_codes = set(LOG_CODE_NAMES.keys())

        i = 0
        while i < n - 16:
            if data[i] == DIAG_LOG_F:
                pkt = self._try_decode_at_offset(data, i, known_codes)
                if pkt:
                    self.packets.append(pkt)
                    i += max(pkt.length, 12)
                    continue
            i += 1

    def _try_decode_at_offset(
        self, data: bytes, offset: int, known_codes: set
    ) -> Optional[DiagPacket]:
        """Try to decode a DIAG log packet at a specific offset."""
        n = len(data)
        if offset + 16 > n:
            return None

        cmd_code = data[offset]
        if cmd_code != DIAG_LOG_F:
            return None

        # Real DIAG layout: cmd(1) + rsvd(1) + outer_len(2) + inner_len(2)
        #                    + log_code(2) + ts(8) + payload
        try:
            outer_len = struct.unpack_from("<H", data, offset + 2)[0]
            inner_len = struct.unpack_from("<H", data, offset + 4)[0]
            log_code = struct.unpack_from("<H", data, offset + 6)[0]
        except struct.error:
            return None

        # Validate inner_len == outer_len
        if inner_len != outer_len:
            return None

        if log_code not in known_codes:
            return None

        ts_offset = offset + 8
        payload_offset = offset + 16

        if payload_offset > n:
            return None

        timestamp = self._decode_timestamp(data, ts_offset)
        total_len = max(outer_len, 16)

        end = min(offset + total_len, n)
        payload = data[payload_offset:end]

        return DiagPacket(
            cmd_code=cmd_code,
            log_code=log_code,
            timestamp=timestamp,
            length=total_len,
            payload=payload,
            file_offset=offset,
        )

    def _decode_log_packet(
        self, record: bytes, file_offset: int
    ) -> Optional[DiagPacket]:
        """
        Decode a DIAG log packet from raw record bytes.
        Real HDF/DIAG layout:
          [0]    cmd_code (0x10 for log)
          [1]    reserved (0x00)
          [2:4]  outer_len (uint16 LE) — total log item length
          [4:6]  inner_len (uint16 LE) — repeated length (must equal outer_len)
          [6:8]  log_code (uint16 LE)
          [8:16] timestamp (8 bytes, uint64 LE)
          [16:]  payload
        """
        if len(record) < 16:
            return None

        cmd_code = record[0]

        # We're interested in log packets
        if cmd_code != DIAG_LOG_F:
            return None

        outer_len = struct.unpack_from("<H", record, 2)[0]
        inner_len = struct.unpack_from("<H", record, 4)[0]

        # Validate: inner_len should equal outer_len
        if inner_len != outer_len:
            return None

        log_code = struct.unpack_from("<H", record, 6)[0]
        timestamp = self._decode_timestamp(record, 8)
        payload = record[16:]
        return DiagPacket(
            cmd_code=cmd_code,
            log_code=log_code,
            timestamp=timestamp,
            length=outer_len,
            payload=payload,
            file_offset=file_offset,
        )

    def _decode_timestamp(self, data: bytes, offset: int) -> datetime:
        """
        Decode DIAG 8-byte timestamp.
        The timestamp is a 64-bit value representing the number of
        1/52428800-second ticks since the DIAG epoch (Jan 6, 1980).
        Stored as two 32-bit LE words.
        """
        if offset + 8 > len(data):
            return self.DIAG_EPOCH

        try:
            ts_lo = struct.unpack_from("<I", data, offset)[0]
            ts_hi = struct.unpack_from("<I", data, offset + 4)[0]
            ts_val = (ts_hi << 32) | ts_lo
            seconds = ts_val * self.DIAG_TS_RESOLUTION
            return self.DIAG_EPOCH + timedelta(seconds=seconds)
        except (struct.error, OverflowError, OSError):
            return self.DIAG_EPOCH


# ---------------------------------------------------------------------------
# LTE Analyzer — decodes LTE-specific log packets
# ---------------------------------------------------------------------------

class LTEAnalyzer:
    """Decode and analyze LTE-layer log packets."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def decode_packet(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        code = pkt.log_code
        if code == LOG_LTE_ML1_SERV_CELL_MEAS:
            self._decode_ml1_serving_cell(pkt, result)
        elif code == LOG_LTE_RRC_OTA:
            self._decode_rrc_ota(pkt, result)
        elif code == LOG_LTE_NAS_EMM_OTA:
            self._decode_nas_emm_ota(pkt, result)
        elif code == LOG_LTE_NAS_EMM_STATE:
            self._decode_nas_emm_state(pkt, result)
        elif code == LOG_LTE_NAS_EMM_SEC_OTA:
            self._decode_nas_emm_sec_ota(pkt, result)
        elif code == LOG_LTE_NAS_ESM_OTA:
            self._decode_nas_esm_ota(pkt, result)
        elif code == LOG_LTE_RRC_STATE:
            self._decode_rrc_state(pkt, result)
        elif code == LOG_LTE_RRC_SERV_CELL_INFO:
            self._decode_rrc_serv_cell_info(pkt, result)
        elif code == LOG_LTE_MAC_DL_TB:
            self._decode_mac_tb(pkt, result, "DL")
        elif code == LOG_LTE_MAC_UL_TB:
            self._decode_mac_tb(pkt, result, "UL")
        elif code == LOG_LTE_MAC_RACH:
            self._decode_mac_rach(pkt, result)

    def _decode_ml1_serving_cell(
        self, pkt: DiagPacket, result: AnalysisResult
    ) -> None:
        """
        Decode 0xB821 LTE ML1 Serving Cell Measurement.
        Payload layout (version-dependent, common fields):
          [0]    version
          [1:3]  num_cells (or sub-packet count)
          Followed by per-cell records with EARFCN, PCI, RSRP, RSRQ, RSSI, SINR.
        RSRP/RSRQ are typically stored as (value * 64 + offset) or similar scaled int.
        """
        payload = pkt.payload
        if len(payload) < 4:
            return

        version = payload[0]

        # Version-dependent decode
        if version >= 5:
            # v5+ uses sub-packet structure with bitfield-packed measurements
            self._decode_ml1_v5_plus(pkt, payload, version, result)
        elif version in (1, 2, 3, 4):
            self._decode_ml1_v1_v5(pkt, payload, version, result)
        else:
            # Attempt generic decode for unknown versions
            self._decode_ml1_generic(pkt, payload, result)

    def _decode_ml1_v1_v5(
        self,
        pkt: DiagPacket,
        payload: bytes,
        version: int,
        result: AnalysisResult,
    ) -> None:
        """Decode ML1 serving cell meas for versions 1-5."""
        if len(payload) < 16:
            return

        try:
            # Common layout for many versions:
            # [0] version, [1] reserved, [2:4] EARFCN, [4:6] PCI
            # [6:8] RSRP (int16 * 0.0625 or similar), [8:10] RSRQ, [10:12] RSSI
            # [12:14] SINR
            earfcn = struct.unpack_from("<H", payload, 2)[0]
            pci = struct.unpack_from("<H", payload, 4)[0]

            # RSRP is stored as int16 in units of -0.0625 dBm offset by some base
            rsrp_raw = struct.unpack_from("<h", payload, 6)[0]
            rsrq_raw = struct.unpack_from("<h", payload, 8)[0]
            rssi_raw = struct.unpack_from("<h", payload, 10)[0]
            sinr_raw = struct.unpack_from("<h", payload, 12)[0]

            # Scaling: different versions use different scales.
            # Common: RSRP = raw / 64 (for older) or raw * 0.0625 - 180
            # We use a commonly seen conversion.
            rsrp = rsrp_raw / 64.0 if abs(rsrp_raw) > 200 else rsrp_raw / 10.0
            rsrq = rsrq_raw / 64.0 if abs(rsrq_raw) > 200 else rsrq_raw / 10.0
            rssi = rssi_raw / 64.0 if abs(rssi_raw) > 200 else rssi_raw / 10.0
            sinr = sinr_raw / 64.0 if abs(sinr_raw) > 200 else sinr_raw / 10.0

            # Sanity check ranges: RSRP [-150, -30], RSRQ [-30, 0], SINR [-30, 50]
            if not (-180 < rsrp < 0):
                rsrp = rsrp_raw * 0.0625 - 180
            if not (-40 < rsrq < 10):
                rsrq = rsrq_raw * 0.0625 - 30
            if not (-30 < sinr < 60):
                sinr = sinr_raw * 0.0625 - 20

            sample = SignalSample(
                timestamp=pkt.timestamp,
                tech="LTE",
                rsrp=round(rsrp, 2),
                rsrq=round(rsrq, 2),
                rssi=round(rssi, 2) if -120 < rssi < 0 else None,
                sinr=round(sinr, 2),
                pci=pci,
                earfcn=earfcn,
            )
            result.signal_samples.append(sample)

            if self.verbose:
                print(
                    f"  [LTE Signal] PCI={pci} EARFCN={earfcn} "
                    f"RSRP={sample.rsrp} RSRQ={sample.rsrq} SINR={sample.sinr}"
                )
        except struct.error:
            result.parse_errors += 1

    def _decode_ml1_v5_plus(
        self,
        pkt: DiagPacket,
        payload: bytes,
        version: int,
        result: AnalysisResult,
    ) -> None:
        """
        Decode ML1 serving cell meas for version >= 5 (including v19+).
        Uses sub-packet structure with bitfield-packed measurements.
        Layout:
          [0:4]  version word (version in lower byte)
          [4:8]  sub-packet header: sub_id(8) | sub_ver(8) | sub_size(16)
          [8+]   sub-packet payload with EARFCN, PCI, and packed signal fields
        For the signal scanning approach: scan from offset 20+ for uint32 words
        where lower 11 bits decode to a plausible RSRP.
        """
        if len(payload) < 8:
            return

        try:
            earfcn = None
            pci = None
            rsrp = None
            rsrq = None
            sinr = None

            # Try sub-packet parsing if payload is long enough
            if len(payload) >= 12:
                # Sub-packet header at offset 4
                sub_id = payload[4]
                sub_ver = payload[5]
                sub_size = struct.unpack_from("<H", payload, 6)[0]

                # Try to extract EARFCN from first uint32 in sub-packet payload
                if len(payload) >= 12:
                    earfcn_word = struct.unpack_from("<I", payload, 8)[0]
                    earfcn_candidate = earfcn_word & 0x3FFFF  # lower 18 bits
                    if 0 < earfcn_candidate < 1000000:
                        earfcn = earfcn_candidate

                # Try to extract PCI
                if len(payload) >= 16:
                    pci_word = struct.unpack_from("<I", payload, 12)[0]
                    pci_candidate = pci_word & 0x1FF  # lower 9 bits
                    if 0 <= pci_candidate < 504:
                        pci = pci_candidate

            # Scan variable-length portion (offset 20+) for bitfield-packed
            # signal measurements
            scan_start = min(20, len(payload) - 4)
            best_rsrp = None
            best_offset = None

            for off in range(scan_start, min(len(payload) - 4, 200), 4):
                word = struct.unpack_from("<I", payload, off)[0]

                # RSRP: lower 11 bits, scale = raw * 0.0625 - 180
                rsrp_raw = word & 0x7FF  # 11 bits
                rsrp_val = rsrp_raw * 0.0625 - 180.0

                if -150 < rsrp_val < -40:
                    # Found a plausible RSRP — also try to extract RSRQ and SINR
                    # from adjacent bits in the same or next word
                    rsrq_raw = (word >> 11) & 0x3FF  # 10 bits
                    rsrq_val = rsrq_raw * 0.0625 - 30.0

                    sinr_raw = (word >> 21) & 0x1FF  # 9 bits
                    sinr_val = sinr_raw * 0.0625 - 20.0

                    # Pick the first plausible hit
                    if best_rsrp is None or abs(rsrp_val + 100) < abs(best_rsrp + 100):
                        best_rsrp = rsrp_val
                        best_offset = off
                        rsrp = round(rsrp_val, 2)
                        if -30 < rsrq_val < 10:
                            rsrq = round(rsrq_val, 2)
                        if -30 < sinr_val < 60:
                            sinr = round(sinr_val, 2)

            if rsrp is not None:
                sample = SignalSample(
                    timestamp=pkt.timestamp,
                    tech="LTE",
                    rsrp=rsrp,
                    rsrq=rsrq,
                    sinr=sinr,
                    pci=pci,
                    earfcn=earfcn,
                )
                result.signal_samples.append(sample)

                if self.verbose:
                    print(
                        f"  [LTE Signal v{version}] PCI={pci} EARFCN={earfcn} "
                        f"RSRP={rsrp} RSRQ={rsrq} SINR={sinr}"
                    )
        except struct.error:
            result.parse_errors += 1

    def _decode_ml1_generic(
        self, pkt: DiagPacket, payload: bytes, result: AnalysisResult
    ) -> None:
        """Attempt a best-effort decode of ML1 serving cell for unknown versions."""
        if len(payload) < 12:
            return
        try:
            # Scan for int16 values that look like RSRP (range -150 to -30 when scaled)
            for offset in range(0, min(len(payload) - 8, 64), 2):
                val = struct.unpack_from("<h", payload, offset)[0]
                scaled = val / 64.0
                if -150 < scaled < -30:
                    rsrp = scaled
                    # Grab next values as RSRQ, SINR
                    rsrq_raw = struct.unpack_from("<h", payload, offset + 2)[0]
                    sinr_raw = struct.unpack_from("<h", payload, offset + 4)[0]
                    sample = SignalSample(
                        timestamp=pkt.timestamp,
                        tech="LTE",
                        rsrp=round(rsrp, 2),
                        rsrq=round(rsrq_raw / 64.0, 2),
                        sinr=round(sinr_raw / 64.0, 2),
                    )
                    result.signal_samples.append(sample)
                    break
        except struct.error:
            result.parse_errors += 1

    # LTE RRC channel type mapping: id -> (channel_name, direction)
    LTE_RRC_CHAN_MAP = {
        0: ("BCCH-BCH", "DL"),
        1: ("BCCH-DL-SCH", "DL"),
        2: ("CCCH-DL", "DL"),
        3: ("CCCH-UL", "UL"),
        4: ("DCCH-DL", "DL"),
        5: ("DCCH-UL", "UL"),
        6: ("PCCH", "DL"),
    }

    def _decode_rrc_ota(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """
        Decode 0xB0E0 LTE RRC OTA packet.
        Payload layout is version-dependent:
          v6+:  [0] ver, [1] rel, [2] rb, [3:5] PCI, [5:7] EARFCN,
                [7:9] SFN, [9] chan_type, [10:12] pdu_len, [12:] PDU
          v1-5: [0] ver, [1] rel, [2] rb, [3:5] PCI, [4:6] EARFCN,
                [6:8] SFN, [8] chan_type, [9:11] pdu_len, [11:] PDU
        """
        payload = pkt.payload
        if len(payload) < 10:
            return

        try:
            version = payload[0]

            # Version-dependent header offsets
            if version >= 6:
                pci = struct.unpack_from("<H", payload, 3)[0] if len(payload) > 4 else None
                earfcn = struct.unpack_from("<H", payload, 5)[0] if len(payload) > 6 else None
                sfn_raw = struct.unpack_from("<H", payload, 7)[0] if len(payload) > 8 else None
                chan_type_off, pdu_len_off, pdu_off = 9, 10, 12
            else:
                pci = struct.unpack_from("<H", payload, 3)[0] if len(payload) > 4 else None
                earfcn = struct.unpack_from("<H", payload, 4)[0] if len(payload) > 5 else None
                sfn_raw = struct.unpack_from("<H", payload, 6)[0] if len(payload) > 7 else None
                chan_type_off, pdu_len_off, pdu_off = 8, 9, 11

            sfn = (sfn_raw & 0x03FF) if sfn_raw is not None else None

            # Channel type with lookup dict for direction
            chan_type = payload[chan_type_off] if len(payload) > chan_type_off else 0
            chan_info = self.LTE_RRC_CHAN_MAP.get(chan_type)
            if chan_info:
                chan_name, direction = chan_info
            else:
                chan_name = f"Chan_{chan_type}"
                direction = "DL" if (chan_type % 2 == 0) else "UL"

            # Decode message type from actual PDU bytes via UPER
            msg_name = None
            if len(payload) > pdu_off:
                pdu_len = struct.unpack_from("<H", payload, pdu_len_off)[0] if len(payload) > pdu_len_off + 1 else 0
                pdu_bytes = payload[pdu_off:pdu_off + pdu_len] if pdu_len else payload[pdu_off:]
                msg_name = _decode_rrc_msg_from_pdu(pdu_bytes, chan_type, "LTE")

            if msg_name is None:
                # Fallback: channel-type defaults, then old lookup table
                _LTE_CHAN_DEFAULTS = {
                    0: "MasterInformationBlock",
                    2: "RRCConnectionSetup",    # CCCH-DL: setup or reestablishment
                    3: "RRCConnectionRequest",  # CCCH-UL
                    6: "Paging",
                }
                msg_name = _LTE_CHAN_DEFAULTS.get(chan_type)
                if msg_name is None:
                    fallback_id = payload[chan_type_off + 1] if len(payload) > chan_type_off + 1 else -1
                    msg_name = LTE_RRC_MSG_TYPES.get(fallback_id, f"MsgType_{fallback_id}")

            event = RRCEvent(
                timestamp=pkt.timestamp,
                tech="LTE",
                event=msg_name,
                direction=direction,
                details=f"chan={chan_name}",
                pci=pci,
                earfcn=earfcn,
                sfn=sfn,
            )
            result.rrc_events.append(event)

            # Detect specific interesting events
            self._check_rrc_anomalies(event, result)

            if self.verbose:
                pci_str = f" PCI={pci}" if pci is not None else ""
                earfcn_str = f" EARFCN={earfcn}" if earfcn is not None else ""
                print(f"  [LTE RRC] {direction} {msg_name} ({chan_name}{pci_str}{earfcn_str})")
        except (struct.error, IndexError):
            result.parse_errors += 1

    def _check_rrc_anomalies(self, event: RRCEvent, result: AnalysisResult) -> None:
        """Flag anomalies based on RRC events."""
        if "Reestablishment" in event.event and "Reject" not in event.event:
            result.anomalies.append(
                Anomaly(
                    timestamp=event.timestamp,
                    tech="LTE",
                    category="rrc_reestablish",
                    severity="warning",
                    description=f"LTE RRC Reestablishment: {event.event}",
                )
            )
        if event.event == "RRCConnectionReestablishmentReject":
            result.anomalies.append(
                Anomaly(
                    timestamp=event.timestamp,
                    tech="LTE",
                    category="rrc_reestablish_reject",
                    severity="critical",
                    description="LTE RRC Reestablishment Rejected — possible call drop",
                )
            )

    def _decode_rrc_state(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """Decode 0xB0C2 LTE RRC State."""
        payload = pkt.payload
        if len(payload) < 1:
            return
        try:
            rrc_state = payload[0]
            state_name = LTE_RRC_STATES.get(rrc_state, f"LTE_RRC_State_{rrc_state}")
            event = RRCEvent(
                timestamp=pkt.timestamp,
                tech="LTE",
                event=f"RRC State: {state_name}",
                details=f"state_id={rrc_state}",
            )
            result.rrc_events.append(event)
            if self.verbose:
                print(f"  [LTE RRC State] {state_name}")
        except (struct.error, IndexError):
            result.parse_errors += 1

    def _decode_rrc_serv_cell_info(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """Decode 0xB0ED LTE RRC Serving Cell Info (basic — log the event)."""
        payload = pkt.payload
        try:
            event = RRCEvent(
                timestamp=pkt.timestamp,
                tech="LTE",
                event="ServingCellInfo",
                details=f"payload_len={len(payload)}",
            )
            result.rrc_events.append(event)
            if self.verbose:
                print(f"  [LTE RRC ServCellInfo] payload={len(payload)} bytes")
        except (struct.error, IndexError):
            result.parse_errors += 1

    def _decode_nas_emm_ota(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """
        Decode 0xB0C1 NAS EMM OTA messages.
        Payload:
          [0]    version
          [1]    direction (0=UL, 1=DL)
          [2:4]  message length
          [4:]   NAS PDU
        The NAS PDU first byte (after security header) contains the message type.
        """
        payload = pkt.payload
        if len(payload) < 5:
            return

        try:
            direction = "UL" if payload[1] == 0 else "DL"
            msg_len = struct.unpack_from("<H", payload, 2)[0]
            nas_pdu = payload[4:]

            # Parse NAS message type
            # Security header type is in first byte high nibble
            # If security-protected, the actual NAS message is deeper
            msg_type_byte = None
            cause_code = None

            if len(nas_pdu) >= 2:
                sec_header = (nas_pdu[0] >> 4) & 0x0F
                if sec_header == 0:
                    # Plain NAS message: byte[0]=sec_hdr+proto_disc, byte[1]=msg_type
                    candidate = nas_pdu[1]
                    if candidate in NAS_EMM_MSG_TYPES:
                        msg_type_byte = candidate
                        if len(nas_pdu) >= 3:
                            if msg_type_byte in (0x44, 0x4B, 0x4E):  # Reject messages
                                cause_code = nas_pdu[2]
                elif sec_header in (1, 3):
                    # Integrity-protected only (not ciphered): cleartext inner PDU
                    # [0]=hdr, [1:5]=MAC, [5]=seq, [6]=inner_proto_disc, [7]=msg_type
                    if len(nas_pdu) >= 8:
                        msg_type_byte = nas_pdu[7]
                        if msg_type_byte not in NAS_EMM_MSG_TYPES:
                            msg_type_byte = None  # likely wrong offset
                        elif msg_type_byte in (0x44, 0x4B, 0x4E) and len(nas_pdu) >= 9:
                            cause_code = nas_pdu[8]
                # sec_header 2 or 4: ciphered — can't decode msg type

            if msg_type_byte is not None:
                msg_name = NAS_EMM_MSG_TYPES.get(
                    msg_type_byte, f"EMM_0x{msg_type_byte:02X}"
                )
                cause_text = ""
                if cause_code is not None:
                    cause_text = EMM_CAUSE_CODES.get(
                        cause_code, f"Cause #{cause_code}"
                    )

                event = NASEvent(
                    timestamp=pkt.timestamp,
                    tech="LTE",
                    msg_type=msg_name,
                    direction=direction,
                    cause_code=cause_code,
                    cause_text=cause_text,
                )
                result.nas_events.append(event)

                # Flag NAS rejects
                if "Reject" in msg_name:
                    result.anomalies.append(
                        Anomaly(
                            timestamp=pkt.timestamp,
                            tech="LTE",
                            category="nas_reject",
                            severity="critical",
                            description=f"LTE {msg_name}: {cause_text}",
                            value=cause_code,
                        )
                    )

                if self.verbose:
                    extra = f" cause={cause_code} ({cause_text})" if cause_code else ""
                    print(f"  [LTE NAS] {direction} {msg_name}{extra}")
            else:
                # Couldn't decode — likely ciphered NAS
                sec_header = (nas_pdu[0] >> 4) & 0x0F if len(nas_pdu) >= 1 else 0
                if sec_header in (1, 2, 3, 4):
                    event = NASEvent(
                        timestamp=pkt.timestamp,
                        tech="LTE",
                        msg_type="Ciphered NAS EMM",
                        direction=direction,
                    )
                    result.nas_events.append(event)
        except (struct.error, IndexError):
            result.parse_errors += 1

    def _decode_nas_emm_state(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """
        Decode 0xB0C0 NAS EMM state change.
        For version >= 20 (e.g. v27), this contains full NAS PDUs with
        variable lengths (23 to 1155+ bytes), not just a 2-byte state.
        """
        payload = pkt.payload
        if len(payload) < 2:
            return

        try:
            version = payload[0]

            if version >= 20 and len(payload) >= 6:
                # v20+: full NAS PDU container
                # Direction is at byte 5 (0x00=UL, 0x01=DL)
                direction = "UL" if payload[5] == 0x00 else "DL"
                nas_region = payload[6:]  # NAS data starts after header

                # Scan for NAS security header pattern
                msg_type_byte = None
                sec_protected = False

                for scan_off in range(min(len(nas_region), 32)):
                    b = nas_region[scan_off]
                    # NAS EMM protocol discriminator = 0x07
                    if (b & 0x0F) == 0x07:
                        sec_hdr = (b >> 4) & 0x0F
                        if sec_hdr in (1, 2, 3, 4):
                            # Security-protected EMM message
                            sec_protected = True
                            if sec_hdr in (1, 3):
                                # Integrity-protected only (not ciphered) —
                                # inner PDU is cleartext, msg type at +7
                                inner_off = scan_off + 7
                                if inner_off < len(nas_region):
                                    candidate = nas_region[inner_off]
                                    if candidate in NAS_EMM_MSG_TYPES:
                                        msg_type_byte = candidate
                                    else:
                                        # Try +6 as fallback (proto disc byte)
                                        fb = scan_off + 6
                                        if fb < len(nas_region) and nas_region[fb] in NAS_EMM_MSG_TYPES:
                                            msg_type_byte = nas_region[fb]
                            # sec_hdr 2 or 4: ciphered — can't decode msg type
                            # msg_type_byte stays None, handled below
                            break
                        elif sec_hdr == 0:
                            # Plain NAS: msg_type at next byte
                            if scan_off + 1 < len(nas_region):
                                candidate = nas_region[scan_off + 1]
                                # Validate: must be a known EMM msg type
                                if candidate in NAS_EMM_MSG_TYPES:
                                    msg_type_byte = candidate
                            break

                if msg_type_byte is not None:
                    msg_name = NAS_EMM_MSG_TYPES.get(
                        msg_type_byte, f"EMM_0x{msg_type_byte:02X}"
                    )
                    prot_label = " (SecProt)" if sec_protected else ""
                    event = NASEvent(
                        timestamp=pkt.timestamp,
                        tech="LTE",
                        msg_type=f"{msg_name}{prot_label}",
                        direction=direction,
                        details=f"v{version} len={len(payload)}",
                    )
                    result.nas_events.append(event)

                    if "Reject" in msg_name:
                        result.anomalies.append(
                            Anomaly(
                                timestamp=pkt.timestamp,
                                tech="LTE",
                                category="nas_reject",
                                severity="critical",
                                description=f"LTE {msg_name}",
                            )
                        )

                    if self.verbose:
                        print(
                            f"  [LTE NAS B0C0 v{version}] {direction} "
                            f"{msg_name}{prot_label} ({len(payload)}B)"
                        )
                else:
                    # Couldn't decode NAS message type — likely ciphered
                    label = "Ciphered NAS EMM" if sec_protected else f"NAS PDU (v{version})"
                    event = NASEvent(
                        timestamp=pkt.timestamp,
                        tech="LTE",
                        msg_type=label,
                        direction=direction,
                        details=f"len={len(payload)}",
                    )
                    result.nas_events.append(event)

                    if self.verbose:
                        print(
                            f"  [LTE NAS B0C0 v{version}] {direction} "
                            f"NAS PDU ({len(payload)}B)"
                        )
            else:
                # Legacy v1-v19: simple 2-byte state
                emm_state = payload[0]
                emm_substate = payload[1] if len(payload) > 1 else 0
                state_names = {
                    0: "Deregistered",
                    1: "Registered-Initiated",
                    2: "Registered",
                    3: "Deregistered-Initiated",
                    4: "TAU-Initiated",
                    5: "Service-Request-Initiated",
                }
                state_name = state_names.get(emm_state, f"State_{emm_state}")
                event = NASEvent(
                    timestamp=pkt.timestamp,
                    tech="LTE",
                    msg_type=f"EMM State: {state_name}",
                    details=f"substate={emm_substate}",
                )
                result.nas_events.append(event)

                if self.verbose:
                    print(f"  [LTE EMM State] {state_name} (sub={emm_substate})")
        except (struct.error, IndexError):
            result.parse_errors += 1

    def _decode_nas_emm_sec_ota(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """
        Decode 0xB0E2 LTE NAS EMM OTA (Security Protected).
        Similar to B0C1 but specifically for security-protected NAS messages.
        """
        payload = pkt.payload
        if len(payload) < 5:
            return

        try:
            direction = "UL" if payload[1] == 0 else "DL"
            msg_len = struct.unpack_from("<H", payload, 2)[0]
            nas_pdu = payload[4:]

            msg_type_byte = None
            cause_code = None

            if len(nas_pdu) >= 2:
                sec_header = (nas_pdu[0] >> 4) & 0x0F
                if sec_header == 0 and len(nas_pdu) >= 2:
                    msg_type_byte = nas_pdu[1]
                    if len(nas_pdu) >= 3 and msg_type_byte in (0x44, 0x4B, 0x4E):
                        cause_code = nas_pdu[2]
                elif sec_header in (1, 2, 3, 4) and len(nas_pdu) >= 8:
                    msg_type_byte = nas_pdu[7]
                    if msg_type_byte in (0x44, 0x4B, 0x4E) and len(nas_pdu) >= 9:
                        cause_code = nas_pdu[8]

            if msg_type_byte is not None:
                msg_name = NAS_EMM_MSG_TYPES.get(
                    msg_type_byte, f"EMM_0x{msg_type_byte:02X}"
                )
                cause_text = ""
                if cause_code is not None:
                    cause_text = EMM_CAUSE_CODES.get(cause_code, f"Cause #{cause_code}")

                event = NASEvent(
                    timestamp=pkt.timestamp,
                    tech="LTE",
                    msg_type=msg_name,
                    direction=direction,
                    cause_code=cause_code,
                    cause_text=cause_text,
                    details="security_protected",
                )
                result.nas_events.append(event)

                if "Reject" in msg_name:
                    result.anomalies.append(
                        Anomaly(
                            timestamp=pkt.timestamp,
                            tech="LTE",
                            category="nas_reject",
                            severity="critical",
                            description=f"LTE {msg_name}: {cause_text}",
                            value=cause_code,
                        )
                    )

                if self.verbose:
                    extra = f" cause={cause_code} ({cause_text})" if cause_code else ""
                    print(f"  [LTE NAS SecProt] {direction} {msg_name}{extra}")
        except (struct.error, IndexError):
            result.parse_errors += 1

    def _decode_nas_esm_ota(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """Decode 0xB0E3 LTE NAS ESM OTA (Session Management)."""
        payload = pkt.payload
        if len(payload) < 5:
            return

        try:
            direction = "UL" if payload[1] == 0 else "DL"
            nas_pdu = payload[4:]

            esm_msg_types = {
                0xC1: "Activate Default EPS Bearer Request",
                0xC2: "Activate Default EPS Bearer Accept",
                0xC3: "Activate Default EPS Bearer Reject",
                0xC5: "Activate Dedicated EPS Bearer Request",
                0xC6: "Activate Dedicated EPS Bearer Accept",
                0xC7: "Activate Dedicated EPS Bearer Reject",
                0xC9: "Modify EPS Bearer Request",
                0xCA: "Modify EPS Bearer Accept",
                0xCB: "Modify EPS Bearer Reject",
                0xCD: "Deactivate EPS Bearer Request",
                0xCE: "Deactivate EPS Bearer Accept",
                0xD1: "PDN Connectivity Request",
                0xD2: "PDN Connectivity Reject",
                0xD3: "PDN Disconnect Request",
                0xD4: "PDN Disconnect Reject",
                0xD9: "ESM Information Request",
                0xDA: "ESM Information Response",
                0xE8: "ESM Status",
            }

            msg_type_byte = None
            if len(nas_pdu) >= 4:
                # ESM: [0]=proto_disc, [1]=ebi+pti, [2]=pti, [3]=msg_type
                msg_type_byte = nas_pdu[3] if len(nas_pdu) > 3 else None

            if msg_type_byte is not None:
                msg_name = esm_msg_types.get(
                    msg_type_byte, f"ESM_0x{msg_type_byte:02X}"
                )
                event = NASEvent(
                    timestamp=pkt.timestamp,
                    tech="LTE",
                    msg_type=msg_name,
                    direction=direction,
                )
                result.nas_events.append(event)

                if self.verbose:
                    print(f"  [LTE ESM] {direction} {msg_name}")
        except (struct.error, IndexError):
            result.parse_errors += 1

    def _decode_mac_tb(
        self, pkt: DiagPacket, result: AnalysisResult, direction: str
    ) -> None:
        """
        Decode 0xB063/0xB064 LTE MAC DL/UL Transport Block.
        Payload contains aggregate TB size across num_samples subframes.
        """
        payload = pkt.payload
        if len(payload) < 8:
            return

        try:
            version = payload[0]
            # Number of subframes covered by this log packet
            num_samples = payload[1] if len(payload) > 1 else 1
            num_samples = max(num_samples, 1)

            # TB size (total bytes across all subframes) at offset 2
            total_bytes = 0
            if len(payload) >= 6:
                tb_size = struct.unpack_from("<I", payload, 2)[0]
                if tb_size < 10_000_000:  # sanity: less than 10MB per packet
                    total_bytes = tb_size

            if total_bytes > 0:
                sample = ThroughputSample(
                    timestamp=pkt.timestamp,
                    tech="LTE",
                    direction=direction,
                    bytes_count=total_bytes,
                    tb_count=num_samples,
                    duration_ms=float(num_samples),  # num_samples subframes × 1ms each
                )
                result.throughput_samples.append(sample)
        except struct.error:
            result.parse_errors += 1

    def _decode_mac_rach(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """
        Decode 0xB061 LTE MAC RACH Attempt.
        Supports multiple payload layouts across log versions:
          v1-2: fixed layout with record at offset 4
          v3+:  sub-packet structure with header (version, num_subpkts, reserved,
                sub_id, sub_ver, sub_size) then per-record data
        """
        payload = pkt.payload
        if len(payload) < 10:
            return

        try:
            version = payload[0]
            num_samples = payload[1] if len(payload) > 1 else 1

            # Determine record start offset based on version
            if version <= 2:
                # v1-2: record starts at offset 4 (after version, num_samples, reserved)
                record_offset = 4
            else:
                # v3+: sub-packet header at offset 2-7
                # [2] sub_id, [3] sub_ver, [4:6] sub_size, record at offset 6 or 8
                if len(payload) >= 14:
                    record_offset = 8  # skip version(1)+num(1)+sub_id(1)+sub_ver(1)+sub_size(2)+pad(2)
                else:
                    record_offset = 4  # fallback

            if record_offset + 6 > len(payload):
                return

            preamble = payload[record_offset + 1] if record_offset + 1 < len(payload) else None
            timing_advance = None
            if record_offset + 4 <= len(payload):
                timing_advance = struct.unpack_from("<H", payload, record_offset + 2)[0]

            rach_result_byte = payload[record_offset + 4] if record_offset + 4 < len(payload) else 255
            contention_type = payload[record_offset + 5] if record_offset + 5 < len(payload) else 0

            # Validate result byte — if out of range, try scanning for it
            if rach_result_byte > 2:
                rach_result_byte, contention_type, preamble, timing_advance = (
                    self._scan_rach_fields(payload)
                )

            rach_results = {0: "Success", 1: "Failure", 2: "Aborted"}
            rach_result = rach_results.get(rach_result_byte, f"Unknown({rach_result_byte})")
            contention = "Contention-Free" if contention_type == 1 else "Contention-Based"

            event_name = f"RACH {rach_result}"
            details_parts = [contention]
            if preamble is not None:
                details_parts.append(f"preamble={preamble}")
            if timing_advance is not None:
                details_parts.append(f"TA={timing_advance}")

            event = RRCEvent(
                timestamp=pkt.timestamp,
                tech="LTE",
                event=event_name,
                direction="UL",
                details=", ".join(details_parts),
            )
            result.rrc_events.append(event)

            # Flag RACH failures as anomalies
            if rach_result_byte != 0:
                result.anomalies.append(
                    Anomaly(
                        timestamp=pkt.timestamp,
                        tech="LTE",
                        category="rach_failure",
                        severity="warning",
                        description=f"LTE RACH {rach_result} ({contention}, preamble={preamble})",
                    )
                )

            if self.verbose:
                print(f"  [LTE RACH v{version}] {event_name} {', '.join(details_parts)}")
        except (struct.error, IndexError):
            result.parse_errors += 1

    @staticmethod
    def _scan_rach_fields(payload: bytes) -> Tuple[int, int, Optional[int], Optional[int]]:
        """
        Fallback scanner: find RACH result (0-2) and preamble (0-63) in payload.
        Returns (result_byte, contention_type, preamble, timing_advance).
        """
        # Scan for a byte sequence: preamble(0-63), TA(2 bytes), result(0-2), contention(0-1)
        for off in range(2, min(len(payload) - 5, 32)):
            preamble_candidate = payload[off]
            result_candidate = payload[off + 3] if off + 3 < len(payload) else 255
            contention_candidate = payload[off + 4] if off + 4 < len(payload) else 255

            if (0 <= preamble_candidate <= 63
                    and result_candidate <= 2
                    and contention_candidate <= 1):
                ta = struct.unpack_from("<H", payload, off + 1)[0] if off + 3 <= len(payload) else None
                return result_candidate, contention_candidate, preamble_candidate, ta

        # Couldn't find a valid pattern — return unknown
        return 255, 0, None, None


# ---------------------------------------------------------------------------
# 5G NR Analyzer — decodes NR-specific log packets
# ---------------------------------------------------------------------------

class NR5GAnalyzer:
    """Decode and analyze 5G NR layer log packets."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def decode_packet(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        code = pkt.log_code
        if code == LOG_NR_ML1_MEAS_DB:
            self._decode_ml1_meas_db(pkt, result)
        elif code == LOG_NR_RRC_OTA:
            self._decode_rrc_ota(pkt, result)
        elif code == LOG_NR_RRC_STATE:
            self._decode_rrc_state(pkt, result)
        elif code in (LOG_NR_NAS_MM5G_STATE, LOG_NR_NAS_MM5G_STATE_ALT):
            self._decode_nas_mm5g_state(pkt, result)
        elif code == LOG_NR_NAS_SM5G_OTA:
            self._decode_nas_sm5g_ota(pkt, result)
        elif code == LOG_NR_NAS_MM5G_OTA_PLAIN:
            self._decode_nas_mm5g_ota_plain(pkt, result)
        elif code == LOG_NR_MAC_PDSCH_STATS:
            self._decode_mac_pdsch(pkt, result)
        elif code == LOG_NR_MAC_PUSCH_STATS:
            self._decode_mac_pusch(pkt, result)
        elif code == LOG_NR_PDCP_DL_STATS:
            self._decode_pdcp_dl_stats(pkt, result)

    def _decode_ml1_meas_db(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """
        Decode 0xB8D2 NR ML1 Measurement Database.
        Contains SS-RSRP, SS-RSRQ, SS-SINR for NR serving/neighbor cells.
        """
        payload = pkt.payload
        if len(payload) < 8:
            return

        try:
            version = payload[0]
            # NR measurement DB layout (version-dependent):
            # Typically: version(1), num_layers(1), rsvd(2),
            # then per-cell: NR-ARFCN(4), PCI(2), SS-RSRP(2), SS-RSRQ(2), SS-SINR(2)

            if len(payload) >= 16:
                nr_arfcn = struct.unpack_from("<I", payload, 4)[0]
                pci = struct.unpack_from("<H", payload, 8)[0]
                ssrsrp_raw = struct.unpack_from("<h", payload, 10)[0]
                ssrsrq_raw = struct.unpack_from("<h", payload, 12)[0]
                sssinr_raw = struct.unpack_from("<h", payload, 14)[0]

                # Scale: commonly stored as value * 64 or value * 128
                ssrsrp = ssrsrp_raw / 64.0 if abs(ssrsrp_raw) > 200 else ssrsrp_raw / 10.0
                ssrsrq = ssrsrq_raw / 64.0 if abs(ssrsrq_raw) > 200 else ssrsrq_raw / 10.0
                sssinr = sssinr_raw / 64.0 if abs(sssinr_raw) > 200 else sssinr_raw / 10.0

                # Sanity bounds
                if not (-180 < ssrsrp < 0):
                    ssrsrp = ssrsrp_raw * 0.0625 - 156.0
                if not (-40 < ssrsrq < 10):
                    ssrsrq = ssrsrq_raw * 0.0625 - 43.0
                if not (-30 < sssinr < 60):
                    sssinr = sssinr_raw * 0.5 - 23.0

                sample = SignalSample(
                    timestamp=pkt.timestamp,
                    tech="NR",
                    rsrp=round(ssrsrp, 2),
                    rsrq=round(ssrsrq, 2),
                    sinr=round(sssinr, 2),
                    pci=pci,
                    earfcn=nr_arfcn,
                )
                result.signal_samples.append(sample)

                if self.verbose:
                    print(
                        f"  [NR Signal] PCI={pci} ARFCN={nr_arfcn} "
                        f"SS-RSRP={sample.rsrp} SS-RSRQ={sample.rsrq} "
                        f"SS-SINR={sample.sinr}"
                    )
        except struct.error:
            result.parse_errors += 1

    # NR RRC channel type mapping for v13+ sub-packet format
    NR_RRC_CHAN_MAP = {
        0: ("BCCH-BCH", "DL"),
        1: ("BCCH-DL-SCH", "DL"),
        2: ("CCCH-DL", "DL"),
        3: ("CCCH-UL", "UL"),
        4: ("DCCH-DL", "DL"),
        5: ("DCCH-UL", "UL"),
        6: ("PCCH", "DL"),
    }

    def _decode_rrc_ota(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """
        Decode 0xB887 NR RRC OTA.
        Supports legacy (v1-v5) and sub-packet (v13+) formats.
        """
        payload = pkt.payload
        if len(payload) < 6:
            return

        try:
            version = payload[0]
            pci = None
            sfn = None
            chan_name = None
            nr_arfcn = None

            if version >= 13 and len(payload) >= 18:
                # v13+ sub-packet format:
                # [0:4] header, [4:8] sub-packet header
                # [8] channel_type, [9] direction_byte, [10:12] SFN
                # [12:14] PCI (uint16 LE), [14:18] NR-ARFCN (uint32 LE)
                # [18:20] PDU length, [20:] PDU bytes
                chan_type = payload[8]
                direction_byte = payload[9]
                sfn = struct.unpack_from("<H", payload, 10)[0] & 0x03FF
                pci = struct.unpack_from("<H", payload, 12)[0]
                _raw_arfcn = struct.unpack_from("<I", payload, 14)[0] if len(payload) >= 18 else 0
                # Validate: NR-ARFCN max is ~2300000 (FR2). Discard bogus values.
                nr_arfcn = _raw_arfcn if 0 < _raw_arfcn <= 2300000 else None
                chan_info = self.NR_RRC_CHAN_MAP.get(chan_type)
                if chan_info:
                    chan_name, direction = chan_info
                else:
                    chan_name = f"Chan_{chan_type}"
                    direction = "UL" if (direction_byte & 1) else "DL"

                # Decode message type from actual PDU bytes via UPER
                msg_name = None
                if len(payload) >= 20:
                    pdu_len = struct.unpack_from("<H", payload, 18)[0]
                    pdu_start = 20
                    pdu_bytes = payload[pdu_start:pdu_start + pdu_len] if pdu_len else payload[pdu_start:]
                    msg_name = _decode_rrc_msg_from_pdu(pdu_bytes, chan_type, "NR")

                if msg_name is None:
                    # Fallback: infer from channel type
                    # For channels with few possible messages, use informed defaults
                    _NR_CHAN_DEFAULTS = {
                        0: "MIB",
                        1: "SystemInformation",
                        2: "RRCSetup",          # CCCH-DL: RRCSetup or RRCReject (Reject caught by UPER)
                        3: "RRCSetupRequest",    # CCCH-UL: most common UL CCCH msg
                        6: "Paging",
                    }
                    msg_name = _NR_CHAN_DEFAULTS.get(chan_type)
                    if msg_name is None:
                        # DCCH or unknown channel — can't infer message type
                        msg_type_id = payload[18] if len(payload) > 18 else -1
                        msg_name = NR_RRC_MSG_TYPES.get(msg_type_id, f"NR_RRC_{msg_type_id}")
            else:
                # Legacy v1-v5 format
                chan_type = payload[4] if len(payload) > 4 else 0
                direction = "DL" if (chan_type % 2 == 0) else "UL"
                msg_type_id = payload[5] if len(payload) > 5 else -1
                msg_name = NR_RRC_MSG_TYPES.get(msg_type_id, f"NR_RRC_{msg_type_id}")

            details = f"chan={chan_name}" if chan_name else f"chan_type={chan_type}"
            # Use NR-ARFCN when available (v13+ format)
            earfcn = nr_arfcn
            event = RRCEvent(
                timestamp=pkt.timestamp,
                tech="NR",
                event=msg_name,
                direction=direction,
                details=details,
                pci=pci,
                earfcn=earfcn,
                sfn=sfn,
            )
            result.rrc_events.append(event)

            # Flag reestablishments
            if "Reestablishment" in msg_name:
                sev = "critical" if "Reject" in event.event else "warning"
                result.anomalies.append(
                    Anomaly(
                        timestamp=event.timestamp,
                        tech="NR",
                        category="rrc_reestablish",
                        severity=sev,
                        description=f"NR {msg_name}",
                    )
                )
            if msg_name == "RRCReject":
                result.anomalies.append(
                    Anomaly(
                        timestamp=event.timestamp,
                        tech="NR",
                        category="rrc_reject",
                        severity="critical",
                        description="NR RRC Setup Rejected",
                    )
                )

            if self.verbose:
                pci_str = f" PCI={pci}" if pci is not None else ""
                sfn_str = f" SFN={sfn}" if sfn is not None else ""
                print(f"  [NR RRC] {direction} {msg_name}{pci_str}{sfn_str}")
        except (struct.error, IndexError):
            result.parse_errors += 1

    def _decode_nas_mm5g_state(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """Decode 0xB8D8 NR NAS 5GMM State."""
        payload = pkt.payload
        if len(payload) < 2:
            return

        try:
            mm5g_state = payload[0]
            mm5g_substate = payload[1] if len(payload) > 1 else 0
            state_names = {
                0: "5GMM-Deregistered",
                1: "5GMM-Registered-Initiated",
                2: "5GMM-Registered",
                3: "5GMM-Deregistered-Initiated",
                4: "5GMM-Service-Request-Initiated",
            }
            state_name = state_names.get(mm5g_state, f"5GMM_State_{mm5g_state}")

            event = NASEvent(
                timestamp=pkt.timestamp,
                tech="NR",
                msg_type=f"5GMM State: {state_name}",
                details=f"substate={mm5g_substate}",
            )
            result.nas_events.append(event)

            if self.verbose:
                print(f"  [NR 5GMM State] {state_name} (sub={mm5g_substate})")
        except (struct.error, IndexError):
            result.parse_errors += 1

    def _decode_nas_sm5g_ota(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """Decode 0xB80A NR NAS 5GSM OTA messages (PDU session management)."""
        payload = pkt.payload
        if len(payload) < 5:
            return

        try:
            direction = "UL" if payload[1] == 0 else "DL"
            msg_len = struct.unpack_from("<H", payload, 2)[0]
            nas_pdu = payload[4:]

            msg_type_byte = None
            cause_code = None

            if len(nas_pdu) >= 2:
                sec_header = (nas_pdu[0] >> 4) & 0x0F
                if sec_header == 0 and len(nas_pdu) >= 4:
                    # 5GS NAS: [0]=ext_proto_disc, [1]=pdu_session_id, [2]=pti, [3]=msg_type
                    msg_type_byte = nas_pdu[3]
                elif len(nas_pdu) >= 10:
                    msg_type_byte = nas_pdu[9]

            if msg_type_byte is not None:
                sm5g_msg_types = {
                    0xC1: "PDU Session Establishment Request",
                    0xC2: "PDU Session Establishment Accept",
                    0xC3: "PDU Session Establishment Reject",
                    0xC5: "PDU Session Authentication Command",
                    0xC9: "PDU Session Modification Request",
                    0xCA: "PDU Session Modification Accept",
                    0xCB: "PDU Session Modification Reject",
                    0xCD: "PDU Session Modification Command",
                    0xD1: "PDU Session Release Request",
                    0xD2: "PDU Session Release Reject",
                    0xD3: "PDU Session Release Command",
                    0xD4: "PDU Session Release Complete",
                }
                msg_name = sm5g_msg_types.get(
                    msg_type_byte, f"5GSM_0x{msg_type_byte:02X}"
                )

                event = NASEvent(
                    timestamp=pkt.timestamp,
                    tech="NR",
                    msg_type=msg_name,
                    direction=direction,
                    cause_code=cause_code,
                )
                result.nas_events.append(event)

                if "Reject" in msg_name:
                    result.anomalies.append(
                        Anomaly(
                            timestamp=pkt.timestamp,
                            tech="NR",
                            category="nas_reject",
                            severity="critical",
                            description=f"NR {msg_name}",
                            value=cause_code,
                        )
                    )

                if self.verbose:
                    print(f"  [NR 5GSM] {direction} {msg_name}")
        except (struct.error, IndexError):
            result.parse_errors += 1

    def _decode_rrc_state(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """Decode 0xB808 NR RRC State."""
        payload = pkt.payload
        if len(payload) < 1:
            return
        try:
            rrc_state = payload[0]
            state_name = NR_RRC_STATES.get(rrc_state, f"NR_RRC_State_{rrc_state}")
            event = RRCEvent(
                timestamp=pkt.timestamp,
                tech="NR",
                event=f"RRC State: {state_name}",
                details=f"state_id={rrc_state} payload_len={len(payload)}",
            )
            result.rrc_events.append(event)
            if self.verbose:
                print(f"  [NR RRC State] {state_name} ({len(payload)} bytes)")
        except (struct.error, IndexError):
            result.parse_errors += 1

    def _decode_nas_mm5g_ota_plain(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """Decode 0xB80B NR NAS 5GMM OTA Plain messages."""
        payload = pkt.payload
        if len(payload) < 5:
            return
        try:
            direction = "UL" if payload[1] == 0 else "DL"
            msg_len = struct.unpack_from("<H", payload, 2)[0]
            nas_pdu = payload[4:]

            msg_type_byte = None
            if len(nas_pdu) >= 2:
                sec_header = (nas_pdu[0] >> 4) & 0x0F
                if sec_header == 0 and len(nas_pdu) >= 2:
                    msg_type_byte = nas_pdu[1]

            if msg_type_byte is not None:
                mm5g_msg_types = {
                    0x41: "Registration Request",
                    0x42: "Registration Accept",
                    0x43: "Registration Complete",
                    0x44: "Registration Reject",
                    0x45: "Deregistration Request (UE)",
                    0x46: "Deregistration Accept (UE)",
                    0x47: "Deregistration Request (NW)",
                    0x48: "Deregistration Accept (NW)",
                    0x4C: "Service Request",
                    0x4D: "Service Reject",
                    0x4E: "Service Accept",
                    0x54: "Configuration Update Command",
                    0x55: "Configuration Update Complete",
                    0x56: "Authentication Request",
                    0x57: "Authentication Response",
                    0x58: "Authentication Reject",
                    0x59: "Authentication Failure",
                    0x5C: "Security Mode Command",
                    0x5D: "Security Mode Complete",
                    0x5E: "Security Mode Reject",
                    0x64: "5GMM Status",
                    0x68: "DL NAS Transport",
                    0x67: "UL NAS Transport",
                }
                msg_name = mm5g_msg_types.get(
                    msg_type_byte, f"5GMM_0x{msg_type_byte:02X}"
                )

                event = NASEvent(
                    timestamp=pkt.timestamp,
                    tech="NR",
                    msg_type=msg_name,
                    direction=direction,
                )
                result.nas_events.append(event)

                if "Reject" in msg_name:
                    cause_code = nas_pdu[2] if len(nas_pdu) >= 3 else None
                    cause_text = MM5G_CAUSE_CODES.get(cause_code, f"Cause #{cause_code}") if cause_code else ""
                    result.anomalies.append(
                        Anomaly(
                            timestamp=pkt.timestamp,
                            tech="NR",
                            category="nas_reject",
                            severity="critical",
                            description=f"NR {msg_name}: {cause_text}",
                            value=cause_code,
                        )
                    )

                if self.verbose:
                    print(f"  [NR 5GMM Plain] {direction} {msg_name}")
        except (struct.error, IndexError):
            result.parse_errors += 1

    def _decode_pdcp_dl_stats(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """Decode 0xB814 NR PDCP DL Stats for throughput estimation."""
        payload = pkt.payload
        if len(payload) < 8:
            return
        try:
            if len(payload) >= 8:
                dl_bytes = struct.unpack_from("<I", payload, 4)[0]
                if 0 < dl_bytes < 100_000_000:
                    sample = ThroughputSample(
                        timestamp=pkt.timestamp,
                        tech="NR",
                        direction="DL",
                        bytes_count=dl_bytes,
                        tb_count=1,
                        duration_ms=1.0,
                    )
                    result.throughput_samples.append(sample)
        except struct.error:
            result.parse_errors += 1

    def _decode_mac_pdsch(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """Decode 0xB868 NR MAC PDSCH statistics for DL throughput."""
        payload = pkt.payload
        if len(payload) < 8:
            return

        try:
            version = payload[0]
            num_slots = payload[1] if len(payload) > 1 else 1
            num_slots = max(num_slots, 1)

            if len(payload) >= 8:
                tb_bytes = struct.unpack_from("<I", payload, 4)[0]
                if 0 < tb_bytes < 100_000_000:
                    sample = ThroughputSample(
                        timestamp=pkt.timestamp,
                        tech="NR",
                        direction="DL",
                        bytes_count=tb_bytes,
                        tb_count=num_slots,
                        duration_ms=num_slots * 0.5,  # NR slot = 0.5ms
                    )
                    result.throughput_samples.append(sample)
        except struct.error:
            result.parse_errors += 1

    def _decode_mac_pusch(self, pkt: DiagPacket, result: AnalysisResult) -> None:
        """Decode 0xB869 NR MAC PUSCH statistics for UL throughput."""
        payload = pkt.payload
        if len(payload) < 8:
            return

        try:
            num_slots = payload[1] if len(payload) > 1 else 1
            num_slots = max(num_slots, 1)

            if len(payload) >= 8:
                tb_bytes = struct.unpack_from("<I", payload, 4)[0]
                if 0 < tb_bytes < 100_000_000:
                    sample = ThroughputSample(
                        timestamp=pkt.timestamp,
                        tech="NR",
                        direction="UL",
                        bytes_count=tb_bytes,
                        tb_count=num_slots,
                        duration_ms=num_slots * 0.5,
                    )
                    result.throughput_samples.append(sample)
        except struct.error:
            result.parse_errors += 1


# ---------------------------------------------------------------------------
# Insight Engine — cross-layer analysis and anomaly detection
# ---------------------------------------------------------------------------

class InsightEngine:
    """Analyzes parsed results to generate higher-level insights."""

    # Thresholds
    RSRP_POOR_LTE = -110  # dBm
    RSRP_CRITICAL_LTE = -120
    SINR_POOR_LTE = 0  # dB
    RSRP_POOR_NR = -110
    RSRP_CRITICAL_NR = -120
    SINR_POOR_NR = 0
    RSRP_DROP_THRESHOLD = 10  # dB drop in consecutive samples

    def analyze(self, result: AnalysisResult) -> AnalysisResult:
        """Run all insight analyses on the parsed result."""
        self._detect_signal_anomalies(result)
        self._detect_handovers(result)
        self._detect_call_drops(result)
        self._compute_file_duration(result)
        return result

    def _compute_file_duration(self, result: AnalysisResult) -> None:
        """Compute time span of the log file."""
        all_times = []
        for s in result.signal_samples:
            all_times.append(s.timestamp)
        for e in result.rrc_events:
            all_times.append(e.timestamp)
        for e in result.nas_events:
            all_times.append(e.timestamp)
        for t in result.throughput_samples:
            all_times.append(t.timestamp)

        # Filter out epoch timestamps (unparsed)
        epoch = datetime(1980, 1, 6)
        all_times = [t for t in all_times if t > epoch + timedelta(days=365)]

        if all_times:
            result.first_timestamp = min(all_times)
            result.last_timestamp = max(all_times)
            result.file_duration = result.last_timestamp - result.first_timestamp

    def _detect_signal_anomalies(self, result: AnalysisResult) -> None:
        """Detect sudden signal drops and poor signal periods."""
        samples_by_tech: Dict[str, List[SignalSample]] = defaultdict(list)
        for s in result.signal_samples:
            samples_by_tech[s.tech].append(s)

        for tech, samples in samples_by_tech.items():
            samples.sort(key=lambda x: x.timestamp)
            poor_thresh = (
                self.RSRP_POOR_LTE if tech == "LTE" else self.RSRP_POOR_NR
            )
            crit_thresh = (
                self.RSRP_CRITICAL_LTE if tech == "LTE" else self.RSRP_CRITICAL_NR
            )
            sinr_thresh = (
                self.SINR_POOR_LTE if tech == "LTE" else self.SINR_POOR_NR
            )

            prev_rsrp = None
            for s in samples:
                if s.rsrp is not None:
                    # Sudden drop detection
                    if prev_rsrp is not None:
                        drop = prev_rsrp - s.rsrp
                        if drop > self.RSRP_DROP_THRESHOLD:
                            result.anomalies.append(
                                Anomaly(
                                    timestamp=s.timestamp,
                                    tech=tech,
                                    category="signal_drop",
                                    severity="warning",
                                    description=(
                                        f"{tech} RSRP sudden drop: "
                                        f"{prev_rsrp:.1f} -> {s.rsrp:.1f} dBm "
                                        f"({drop:.1f} dB drop)"
                                    ),
                                    value=drop,
                                )
                            )

                    # Poor signal detection
                    if s.rsrp < crit_thresh:
                        result.anomalies.append(
                            Anomaly(
                                timestamp=s.timestamp,
                                tech=tech,
                                category="signal_critical",
                                severity="critical",
                                description=(
                                    f"{tech} critically weak signal: "
                                    f"RSRP={s.rsrp:.1f} dBm"
                                ),
                                value=s.rsrp,
                            )
                        )
                    elif s.rsrp < poor_thresh:
                        result.anomalies.append(
                            Anomaly(
                                timestamp=s.timestamp,
                                tech=tech,
                                category="signal_poor",
                                severity="warning",
                                description=(
                                    f"{tech} poor signal: RSRP={s.rsrp:.1f} dBm"
                                ),
                                value=s.rsrp,
                            )
                        )

                    prev_rsrp = s.rsrp

                # Poor SINR detection
                if s.sinr is not None and s.sinr < sinr_thresh:
                    result.anomalies.append(
                        Anomaly(
                            timestamp=s.timestamp,
                            tech=tech,
                            category="poor_sinr",
                            severity="warning",
                            description=(
                                f"{tech} poor SINR: {s.sinr:.1f} dB"
                            ),
                            value=s.sinr,
                        )
                    )

    def _detect_handovers(self, result: AnalysisResult) -> None:
        """Detect technology handovers from RRC reconfiguration events."""
        rrc_sorted = sorted(result.rrc_events, key=lambda x: x.timestamp)
        for i, evt in enumerate(rrc_sorted):
            if "Reconfiguration" in evt.event and evt.direction == "DL":
                # Check if there's a tech change nearby
                if i + 1 < len(rrc_sorted):
                    next_evt = rrc_sorted[i + 1]
                    if next_evt.tech != evt.tech:
                        result.anomalies.append(
                            Anomaly(
                                timestamp=evt.timestamp,
                                tech=evt.tech,
                                category="handover",
                                severity="warning",
                                description=(
                                    f"Possible inter-RAT handover: "
                                    f"{evt.tech} -> {next_evt.tech}"
                                ),
                            )
                        )

    def _detect_call_drops(self, result: AnalysisResult) -> None:
        """Detect potential call drops from RRC release patterns."""
        rrc_sorted = sorted(result.rrc_events, key=lambda x: x.timestamp)
        for i, evt in enumerate(rrc_sorted):
            # A release shortly after reestablishment rejection = call drop
            if "Release" in evt.event:
                # Look back for a recent reestablishment reject
                for j in range(max(0, i - 5), i):
                    prev = rrc_sorted[j]
                    if "Reject" in prev.event or "Reestablishment" in prev.event:
                        dt = (evt.timestamp - prev.timestamp).total_seconds()
                        if 0 < dt < 5:
                            result.anomalies.append(
                                Anomaly(
                                    timestamp=evt.timestamp,
                                    tech=evt.tech,
                                    category="call_drop",
                                    severity="critical",
                                    description=(
                                        f"{evt.tech} probable call drop: "
                                        f"Release after {prev.event} "
                                        f"({dt:.1f}s apart)"
                                    ),
                                )
                            )
                            break


# ---------------------------------------------------------------------------
# Report Generator — console, CSV, and plot output
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generate human-readable reports and optional CSV/plot exports."""

    def __init__(
        self,
        result: AnalysisResult,
        output_dir: Optional[str] = None,
        export_csv: bool = False,
        export_plot: bool = False,
        filter_tech: Optional[str] = None,
    ):
        self.result = result
        self.output_dir = output_dir
        self.export_csv = export_csv
        self.export_plot = export_plot
        self.filter_tech = filter_tech.upper() if filter_tech else None

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

    def generate(self) -> None:
        self._print_console_report()
        if self.export_csv:
            self._write_csv()
        if self.export_plot:
            self._generate_plots()

    # ------------- Console Report ----------------

    def _print_console_report(self) -> None:
        r = self.result
        sep = "=" * 72
        thin = "-" * 72

        print(f"\n{sep}")
        print("  QUALCOMM MODEM UE LOG ANALYSIS REPORT")
        print(sep)

        # Overview
        print(f"\n{'--- Overview ---':^72}")
        print(f"  Total packets parsed : {r.total_packets}")
        print(f"  Parse errors         : {r.parse_errors}")
        if r.first_timestamp and r.last_timestamp:
            print(f"  Time range           : {r.first_timestamp} to {r.last_timestamp}")
            print(f"  Duration             : {r.file_duration}")
        print()

        # Packet distribution
        print(f"{'--- Packet Distribution ---':^72}")
        sorted_codes = sorted(r.packet_counts.items(), key=lambda x: -x[1])
        for code, count in sorted_codes[:20]:
            name = LOG_CODE_NAMES.get(code, f"0x{code:04X}")
            print(f"  {name:40s} (0x{code:04X}): {count:>6d}")
        if len(sorted_codes) > 20:
            others = sum(c for _, c in sorted_codes[20:])
            print(f"  {'(other log codes)':40s}         : {others:>6d}")
        print()

        # Signal Quality
        self._print_signal_summary("LTE")
        self._print_signal_summary("NR")

        # RRC Events
        self._print_rrc_summary()

        # NAS Events
        self._print_nas_summary()

        # Throughput
        self._print_throughput_summary()

        # Anomalies
        self._print_anomaly_summary()

        print(sep)
        print("  END OF REPORT")
        print(sep)

    def _print_signal_summary(self, tech: str) -> None:
        if self.filter_tech and self.filter_tech != tech:
            return

        samples = [s for s in self.result.signal_samples if s.tech == tech]
        if not samples:
            return

        label = "SS-" if tech == "NR" else ""
        print(f"{'--- ' + tech + ' Signal Quality ---':^72}")

        rsrp_vals = [s.rsrp for s in samples if s.rsrp is not None]
        rsrq_vals = [s.rsrq for s in samples if s.rsrq is not None]
        sinr_vals = [s.sinr for s in samples if s.sinr is not None]

        if rsrp_vals:
            rsrp_sorted = sorted(rsrp_vals)
            p5 = rsrp_sorted[max(0, len(rsrp_sorted) * 5 // 100)]
            p50 = rsrp_sorted[len(rsrp_sorted) * 50 // 100]
            p95 = rsrp_sorted[min(len(rsrp_sorted) - 1, len(rsrp_sorted) * 95 // 100)]
            print(f"  {label}RSRP (dBm):")
            print(
                f"    Min={min(rsrp_vals):.1f}  Max={max(rsrp_vals):.1f}  "
                f"Avg={mean(rsrp_vals):.1f}  Median={median(rsrp_vals):.1f}"
            )
            print(f"    5th%={p5:.1f}  50th%={p50:.1f}  95th%={p95:.1f}")

        if rsrq_vals:
            print(f"  {label}RSRQ (dB):")
            print(
                f"    Min={min(rsrq_vals):.1f}  Max={max(rsrq_vals):.1f}  "
                f"Avg={mean(rsrq_vals):.1f}  Median={median(rsrq_vals):.1f}"
            )

        if sinr_vals:
            print(f"  {label}SINR (dB):")
            print(
                f"    Min={min(sinr_vals):.1f}  Max={max(sinr_vals):.1f}  "
                f"Avg={mean(sinr_vals):.1f}  Median={median(sinr_vals):.1f}"
            )

        # Unique PCIs
        pcis = set(s.pci for s in samples if s.pci is not None)
        if pcis:
            print(f"  Unique PCIs: {sorted(pcis)}")

        # Unique EARFCNs/ARFCNs
        arfcns = set(s.earfcn for s in samples if s.earfcn is not None)
        if arfcns:
            label2 = "NR-ARFCN" if tech == "NR" else "EARFCN"
            print(f"  Unique {label2}s: {sorted(arfcns)}")

        print(f"  Samples: {len(samples)}")
        print()

    def _print_rrc_summary(self) -> None:
        events = self.result.rrc_events
        if self.filter_tech:
            events = [e for e in events if e.tech == self.filter_tech]
        if not events:
            return

        print(f"{'--- RRC Events ---':^72}")
        # Count by event type
        counts: Dict[str, int] = defaultdict(int)
        for e in events:
            counts[f"{e.tech} {e.event}"] += 1

        for evt_name, count in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"  {evt_name:50s}: {count:>4d}")

        # Show unique PCIs and EARFCNs seen in RRC events
        pcis = sorted(set(e.pci for e in events if e.pci is not None))
        earfcns = sorted(set(e.earfcn for e in events if e.earfcn is not None))
        if pcis:
            print(f"  Unique PCIs from RRC: {pcis}")
        if earfcns:
            print(f"  Unique EARFCNs from RRC: {earfcns}")

        # Show last N events
        recent = sorted(events, key=lambda x: x.timestamp)[-10:]
        if recent:
            print(f"\n  Last {len(recent)} RRC events:")
            for e in recent:
                ts = e.timestamp.strftime("%H:%M:%S.%f")[:-3]
                extra = ""
                if e.pci is not None:
                    extra += f" PCI={e.pci}"
                if e.earfcn is not None:
                    extra += f" EARFCN={e.earfcn}"
                print(f"    [{ts}] {e.tech} {e.direction:2s} {e.event}{extra}")
        print()

    def _print_nas_summary(self) -> None:
        events = self.result.nas_events
        if self.filter_tech:
            events = [e for e in events if e.tech == self.filter_tech]
        if not events:
            return

        print(f"{'--- NAS Events ---':^72}")
        counts: Dict[str, int] = defaultdict(int)
        for e in events:
            counts[f"{e.tech} {e.msg_type}"] += 1

        for msg, count in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"  {msg:50s}: {count:>4d}")

        # Show NAS rejects separately
        rejects = [e for e in events if e.cause_code is not None]
        if rejects:
            print(f"\n  NAS Reject/Failure details:")
            for e in rejects:
                ts = e.timestamp.strftime("%H:%M:%S.%f")[:-3]
                print(
                    f"    [{ts}] {e.tech} {e.msg_type}: "
                    f"cause={e.cause_code} ({e.cause_text})"
                )

        # Timeline of recent NAS events
        recent = sorted(events, key=lambda x: x.timestamp)[-10:]
        if recent:
            print(f"\n  Last {len(recent)} NAS events:")
            for e in recent:
                ts = e.timestamp.strftime("%H:%M:%S.%f")[:-3]
                extra = f" cause={e.cause_code}" if e.cause_code else ""
                print(f"    [{ts}] {e.tech} {e.direction:2s} {e.msg_type}{extra}")
        print()

    def _print_throughput_summary(self) -> None:
        samples = self.result.throughput_samples
        if self.filter_tech:
            samples = [s for s in samples if s.tech == self.filter_tech]
        if not samples:
            return

        print(f"{'--- Throughput Estimation ---':^72}")

        for tech in ("LTE", "NR"):
            for direction in ("DL", "UL"):
                subset = [
                    s for s in samples if s.tech == tech and s.direction == direction
                ]
                if not subset:
                    continue

                total_bytes = sum(s.bytes_count for s in subset)
                total_time_ms = sum(s.duration_ms for s in subset)

                # Aggregate throughput over 1-second windows
                if total_time_ms > 0:
                    avg_mbps = (total_bytes * 8) / (total_time_ms * 1000)
                else:
                    avg_mbps = 0

                # Peak: max single-sample throughput
                peak_mbps = max(s.mbps for s in subset) if subset else 0

                print(
                    f"  {tech} {direction}: "
                    f"Total={total_bytes / 1e6:.2f} MB, "
                    f"Avg={avg_mbps:.2f} Mbps, "
                    f"Peak~{peak_mbps:.2f} Mbps, "
                    f"Samples={len(subset)}"
                )
        print()

    def _print_anomaly_summary(self) -> None:
        anomalies = self.result.anomalies
        if self.filter_tech:
            anomalies = [a for a in anomalies if a.tech == self.filter_tech]
        if not anomalies:
            print(f"{'--- Anomalies ---':^72}")
            print("  No anomalies detected.")
            print()
            return

        # Deduplicate: keep unique by (category, severity) with counts
        cat_counts: Dict[Tuple[str, str, str], int] = defaultdict(int)
        for a in anomalies:
            cat_counts[(a.tech, a.category, a.severity)] += 1

        critical = [a for a in anomalies if a.severity == "critical"]
        warnings = [a for a in anomalies if a.severity == "warning"]

        print(f"{'--- Anomalies ---':^72}")
        print(f"  Total: {len(anomalies)} ({len(critical)} critical, {len(warnings)} warnings)")
        print()

        print("  Summary by category:")
        for (tech, cat, sev), count in sorted(
            cat_counts.items(), key=lambda x: (-1 if x[0][2] == "critical" else 0, -x[1])
        ):
            marker = "!!" if sev == "critical" else " *"
            print(f"  {marker} {tech} {cat:25s} [{sev:8s}]: {count:>4d}")
        print()

        # Show first/last critical anomalies
        if critical:
            critical_sorted = sorted(critical, key=lambda x: x.timestamp)
            print("  Critical anomaly details (first 10):")
            for a in critical_sorted[:10]:
                ts = a.timestamp.strftime("%H:%M:%S.%f")[:-3]
                print(f"    [{ts}] {a.description}")
            if len(critical_sorted) > 10:
                print(f"    ... and {len(critical_sorted) - 10} more")
        print()

    # ------------- CSV Export ----------------

    def _write_csv(self) -> None:
        if not self.output_dir:
            print("[WARN] --output-dir required for CSV export.")
            return

        self._write_signal_csv()
        self._write_rrc_csv()
        self._write_nas_csv()
        self._write_throughput_csv()
        self._write_anomaly_csv()
        print(f"[INFO] CSV files written to {self.output_dir}/")

    def _write_signal_csv(self) -> None:
        samples = self.result.signal_samples
        if self.filter_tech:
            samples = [s for s in samples if s.tech == self.filter_tech]
        if not samples:
            return

        path = os.path.join(self.output_dir, "signal_quality.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                ["timestamp", "tech", "rsrp", "rsrq", "rssi", "sinr", "pci", "earfcn"]
            )
            for s in sorted(samples, key=lambda x: x.timestamp):
                w.writerow(
                    [
                        s.timestamp.isoformat(),
                        s.tech,
                        s.rsrp,
                        s.rsrq,
                        s.rssi,
                        s.sinr,
                        s.pci,
                        s.earfcn,
                    ]
                )

    def _write_rrc_csv(self) -> None:
        events = self.result.rrc_events
        if self.filter_tech:
            events = [e for e in events if e.tech == self.filter_tech]
        if not events:
            return

        path = os.path.join(self.output_dir, "rrc_events.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "tech", "direction", "event", "details"])
            for e in sorted(events, key=lambda x: x.timestamp):
                w.writerow(
                    [e.timestamp.isoformat(), e.tech, e.direction, e.event, e.details]
                )

    def _write_nas_csv(self) -> None:
        events = self.result.nas_events
        if self.filter_tech:
            events = [e for e in events if e.tech == self.filter_tech]
        if not events:
            return

        path = os.path.join(self.output_dir, "nas_events.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "timestamp", "tech", "direction", "msg_type",
                    "cause_code", "cause_text", "details",
                ]
            )
            for e in sorted(events, key=lambda x: x.timestamp):
                w.writerow(
                    [
                        e.timestamp.isoformat(), e.tech, e.direction, e.msg_type,
                        e.cause_code, e.cause_text, e.details,
                    ]
                )

    def _write_throughput_csv(self) -> None:
        samples = self.result.throughput_samples
        if self.filter_tech:
            samples = [s for s in samples if s.tech == self.filter_tech]
        if not samples:
            return

        path = os.path.join(self.output_dir, "throughput.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                ["timestamp", "tech", "direction", "bytes", "tb_count", "duration_ms", "mbps"]
            )
            for s in sorted(samples, key=lambda x: x.timestamp):
                w.writerow(
                    [
                        s.timestamp.isoformat(), s.tech, s.direction,
                        s.bytes_count, s.tb_count, s.duration_ms,
                        round(s.mbps, 2),
                    ]
                )

    def _write_anomaly_csv(self) -> None:
        anomalies = self.result.anomalies
        if self.filter_tech:
            anomalies = [a for a in anomalies if a.tech == self.filter_tech]
        if not anomalies:
            return

        path = os.path.join(self.output_dir, "anomalies.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                ["timestamp", "tech", "category", "severity", "description", "value"]
            )
            for a in sorted(anomalies, key=lambda x: x.timestamp):
                w.writerow(
                    [
                        a.timestamp.isoformat(), a.tech, a.category,
                        a.severity, a.description, a.value,
                    ]
                )

    # ------------- Plot Generation ----------------

    def _generate_plots(self) -> None:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import matplotlib.dates as mdates
        except ImportError:
            print("[WARN] matplotlib not installed. Skipping plot generation.")
            print("       Install with: pip install matplotlib")
            return

        if not self.output_dir:
            print("[WARN] --output-dir required for plot export.")
            return

        self._plot_signal(plt, mdates)
        self._plot_throughput(plt, mdates)
        self._plot_events_timeline(plt, mdates)
        print(f"[INFO] Plots written to {self.output_dir}/")

    def _plot_signal(self, plt, mdates) -> None:
        for tech in ("LTE", "NR"):
            if self.filter_tech and self.filter_tech != tech:
                continue

            samples = [
                s for s in self.result.signal_samples if s.tech == tech
            ]
            if not samples:
                continue

            samples.sort(key=lambda x: x.timestamp)
            times = [s.timestamp for s in samples]

            fig, axes = plt.subplots(3, 1, figsize=(14, 10), sharex=True)
            fig.suptitle(f"{tech} Signal Quality Over Time", fontsize=14)

            # RSRP
            rsrp_vals = [s.rsrp for s in samples]
            axes[0].plot(times, rsrp_vals, "b-", linewidth=0.8, alpha=0.8)
            axes[0].axhline(y=-110, color="orange", linestyle="--", alpha=0.5, label="Poor (-110)")
            axes[0].axhline(y=-120, color="red", linestyle="--", alpha=0.5, label="Critical (-120)")
            axes[0].set_ylabel("RSRP (dBm)")
            axes[0].legend(loc="upper right", fontsize=8)
            axes[0].grid(True, alpha=0.3)

            # RSRQ
            rsrq_vals = [s.rsrq for s in samples]
            axes[1].plot(times, rsrq_vals, "g-", linewidth=0.8, alpha=0.8)
            axes[1].set_ylabel("RSRQ (dB)")
            axes[1].grid(True, alpha=0.3)

            # SINR
            sinr_vals = [s.sinr for s in samples]
            axes[2].plot(times, sinr_vals, "m-", linewidth=0.8, alpha=0.8)
            axes[2].axhline(y=0, color="red", linestyle="--", alpha=0.5, label="Poor (0 dB)")
            axes[2].set_ylabel("SINR (dB)")
            axes[2].set_xlabel("Time")
            axes[2].legend(loc="upper right", fontsize=8)
            axes[2].grid(True, alpha=0.3)

            axes[2].xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
            fig.autofmt_xdate()

            path = os.path.join(self.output_dir, f"{tech.lower()}_signal.png")
            fig.savefig(path, dpi=150, bbox_inches="tight")
            plt.close(fig)

    def _plot_throughput(self, plt, mdates) -> None:
        samples = self.result.throughput_samples
        if self.filter_tech:
            samples = [s for s in samples if s.tech == self.filter_tech]
        if not samples:
            return

        # Aggregate into 1-second bins
        bins: Dict[Tuple[str, str, int], int] = defaultdict(int)
        for s in samples:
            epoch_sec = int(s.timestamp.timestamp())
            bins[(s.tech, s.direction, epoch_sec)] += s.bytes_count

        fig, axes = plt.subplots(2, 1, figsize=(14, 8), sharex=True)
        fig.suptitle("Throughput Over Time", fontsize=14)

        for idx, direction in enumerate(("DL", "UL")):
            for tech in ("LTE", "NR"):
                if self.filter_tech and self.filter_tech != tech:
                    continue
                points = [
                    (datetime.fromtimestamp(ts), (bcount * 8) / 1e6)
                    for (t, d, ts), bcount in sorted(bins.items())
                    if t == tech and d == direction
                ]
                if points:
                    times, mbps = zip(*points)
                    color = "blue" if tech == "LTE" else "red"
                    axes[idx].plot(
                        times, mbps, color=color, linewidth=0.8,
                        alpha=0.8, label=tech
                    )

            axes[idx].set_ylabel(f"{direction} (Mbps)")
            axes[idx].legend(loc="upper right", fontsize=8)
            axes[idx].grid(True, alpha=0.3)

        axes[1].set_xlabel("Time")
        axes[1].xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
        fig.autofmt_xdate()

        path = os.path.join(self.output_dir, "throughput.png")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)

    def _plot_events_timeline(self, plt, mdates) -> None:
        """Plot RRC and NAS events on a timeline."""
        rrc = self.result.rrc_events
        nas = self.result.nas_events
        if self.filter_tech:
            rrc = [e for e in rrc if e.tech == self.filter_tech]
            nas = [e for e in nas if e.tech == self.filter_tech]

        if not rrc and not nas:
            return

        fig, axes = plt.subplots(2, 1, figsize=(14, 6), sharex=True)
        fig.suptitle("Event Timeline", fontsize=14)

        # RRC events
        if rrc:
            rrc_sorted = sorted(rrc, key=lambda x: x.timestamp)
            times = [e.timestamp for e in rrc_sorted]
            labels = [f"{e.tech} {e.event[:20]}" for e in rrc_sorted]
            colors = ["blue" if e.tech == "LTE" else "red" for e in rrc_sorted]
            axes[0].scatter(times, range(len(times)), c=colors, s=8, alpha=0.6)
            axes[0].set_ylabel("RRC Event #")
            axes[0].set_title("RRC Events")
            axes[0].grid(True, alpha=0.3)

        # NAS events
        if nas:
            nas_sorted = sorted(nas, key=lambda x: x.timestamp)
            times = [e.timestamp for e in nas_sorted]
            colors = []
            for e in nas_sorted:
                if e.cause_code:
                    colors.append("red")
                elif e.tech == "NR":
                    colors.append("orange")
                else:
                    colors.append("green")
            axes[1].scatter(times, range(len(times)), c=colors, s=8, alpha=0.6)
            axes[1].set_ylabel("NAS Event #")
            axes[1].set_title("NAS Events (red = reject/failure)")
            axes[1].grid(True, alpha=0.3)

        axes[1].set_xlabel("Time")
        axes[1].xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
        fig.autofmt_xdate()

        path = os.path.join(self.output_dir, "events_timeline.png")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def parse_time_arg(s: str) -> Optional[datetime]:
    """Parse a time string in various formats."""
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Qualcomm Modem UE Log Analyzer — "
            "Parse .dlf/.isf/.hdf binary logs for LTE/5G NR insights"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python qcom_log_analyzer.py capture.dlf\n"
            "  python qcom_log_analyzer.py capture.dlf --verbose\n"
            "  python qcom_log_analyzer.py capture.dlf --csv --output-dir ./results\n"
            "  python qcom_log_analyzer.py capture.dlf --plot --output-dir ./results\n"
            "  python qcom_log_analyzer.py capture.dlf --filter-tech nr --csv --plot --output-dir ./out\n"
        ),
    )
    parser.add_argument("logfile", help="Path to .dlf/.isf/.hdf log file")
    parser.add_argument(
        "--output-dir", "-o", help="Directory for CSV/plot output"
    )
    parser.add_argument(
        "--csv", action="store_true", help="Export parsed events to CSV files"
    )
    parser.add_argument(
        "--plot", action="store_true", help="Generate timeline plots (requires matplotlib)"
    )
    parser.add_argument(
        "--filter-tech",
        choices=["lte", "nr"],
        help="Filter output to specific technology",
    )
    parser.add_argument(
        "--time-range",
        nargs=2,
        metavar=("START", "END"),
        help="Filter by time range (format: HH:MM:SS or YYYY-MM-DD HH:MM:SS)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed packet-level output"
    )

    args = parser.parse_args()

    # Validate input file
    if not os.path.isfile(args.logfile):
        print(f"[ERROR] File not found: {args.logfile}")
        return 1

    if (args.csv or args.plot) and not args.output_dir:
        args.output_dir = os.path.splitext(args.logfile)[0] + "_analysis"
        print(f"[INFO] Using output directory: {args.output_dir}")

    file_size = os.path.getsize(args.logfile)
    print(f"[INFO] Parsing {args.logfile} ({file_size:,} bytes)...")

    # Parse
    dlf_parser = DLFParser(args.logfile, verbose=args.verbose)
    packets = dlf_parser.parse()

    if not packets:
        print("[WARN] No DIAG log packets found in file.")
        print("       Ensure this is a valid Qualcomm .dlf/.isf/.hdf binary log file.")
        return 1

    print(f"[INFO] Found {len(packets)} DIAG packets.")

    # Time range filter
    time_start = None
    time_end = None
    if args.time_range:
        time_start = parse_time_arg(args.time_range[0])
        time_end = parse_time_arg(args.time_range[1])
        if time_start and time_end:
            packets = [
                p for p in packets
                if time_start <= p.timestamp <= time_end
            ]
            print(f"[INFO] {len(packets)} packets in time range.")

    # Analyze
    result = AnalysisResult()
    lte_analyzer = LTEAnalyzer(verbose=args.verbose)
    nr_analyzer = NR5GAnalyzer(verbose=args.verbose)

    lte_codes = {
        LOG_LTE_ML1_SERV_CELL_MEAS,
        LOG_LTE_RRC_OTA,
        LOG_LTE_RRC_STATE,
        LOG_LTE_RRC_SERV_CELL_INFO,
        LOG_LTE_NAS_EMM_OTA,
        LOG_LTE_NAS_EMM_STATE,
        LOG_LTE_NAS_EMM_SEC_OTA,
        LOG_LTE_NAS_ESM_OTA,
        LOG_LTE_MAC_DL_TB,
        LOG_LTE_MAC_UL_TB,
    }
    nr_codes = {
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

    # Generate report
    reporter = ReportGenerator(
        result=result,
        output_dir=args.output_dir,
        export_csv=args.csv,
        export_plot=args.plot,
        filter_tech=args.filter_tech,
    )
    reporter.generate()

    return 0


if __name__ == "__main__":
    sys.exit(main())
