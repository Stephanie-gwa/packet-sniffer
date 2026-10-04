"""
packetanalyzer — offline (and optional live) packet capture analysis.

Public API:
    read_pcap(path) -> Iterator[RawPacket]
    parse_ethernet_frame(data, timestamp) -> Packet
    summarize(packets) -> CaptureSummary
    apply_filters(packets, ...) -> list[Packet]
    run_all_detectors(packets, ...) -> list[Alert]
"""
from .pcap_io import read_pcap, write_pcap, PcapFormatError
from .parser import parse_ethernet_frame, Packet
from .analyzer import summarize, CaptureSummary
from .filters import apply_filters
from .detectors import run_all_detectors, detect_port_scans, detect_icmp_floods, detect_cleartext_credentials, Alert

__all__ = [
    "read_pcap", "write_pcap", "PcapFormatError",
    "parse_ethernet_frame", "Packet",
    "summarize", "CaptureSummary",
    "apply_filters",
    "run_all_detectors", "detect_port_scans", "detect_icmp_floods", "detect_cleartext_credentials", "Alert",
]

__version__ = "1.0.0"
