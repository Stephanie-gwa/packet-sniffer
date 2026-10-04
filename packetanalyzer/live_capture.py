"""
live_capture.py — OPTIONAL live packet capture on an interface you
control. This module only ever *receives* packets; nothing in this
project sends or injects traffic onto a network.

Two backends:
  1. Linux, stdlib only: a raw AF_PACKET/SOCK_RAW socket. This needs
     root (or CAP_NET_RAW/CAP_NET_ADMIN via setcap) and only exists on
     Linux, but requires no third-party packages.
  2. Other platforms (or if you prefer it on Linux too): the optional
     `scapy` package, which wraps libpcap/Npcap. Install it with
     `pip install -r requirements-live.txt`.

See README.md "Live capture" for full setup instructions and the
authorization requirements — only capture on interfaces/networks you
own or are explicitly authorized to monitor.
"""
from __future__ import annotations
import socket
import time
from typing import Callable, Optional

from .pcap_io import write_pcap

OnPacket = Callable[[float, bytes], None]


class LiveCaptureError(Exception):
    """Raised for any live-capture setup or permission problem, with a
    message that explains what to do about it."""


def _has_af_packet() -> bool:
    return hasattr(socket, "AF_PACKET")


def list_interfaces() -> list[str]:
    """Best-effort list of network interface names on this machine."""
    try:
        return sorted(name for _, name in socket.if_nameindex())
    except (AttributeError, OSError):
        pass
    try:
        import scapy.all as scapy_all  # optional dependency
        return list(scapy_all.get_if_list())
    except ImportError as e:
        raise LiveCaptureError(
            "Could not list interfaces: socket.if_nameindex() is not available on "
            "this platform, and the optional 'scapy' package is not installed. "
            "Run: pip install -r requirements-live.txt"
        ) from e


def capture_packets(
    iface: str,
    count: Optional[int] = None,
    duration: Optional[float] = None,
    on_packet: Optional[OnPacket] = None,
    snaplen: int = 65535,
) -> list[tuple[float, bytes]]:
    """Capture raw Ethernet frames from `iface`. Stops after `count`
    packets and/or `duration` seconds (at least one must be given).
    Returns a list of (timestamp, raw_bytes) tuples in capture order.
    `on_packet(timestamp, raw_bytes)`, if given, is called as each
    packet arrives (useful for live progress output)."""
    if count is None and duration is None:
        raise LiveCaptureError("Specify at least one of count or duration to bound the capture.")

    if _has_af_packet():
        return _capture_af_packet(iface, count, duration, on_packet, snaplen)

    try:
        return _capture_scapy(iface, count, duration, on_packet)
    except ImportError as e:
        raise LiveCaptureError(
            "Raw AF_PACKET sockets are only available on Linux via the standard "
            "library, and this platform doesn't have them. Install the optional "
            "'scapy' package to capture here:\n"
            "    pip install -r requirements-live.txt\n"
            "Windows also needs Npcap (https://npcap.com) installed first; "
            "macOS needs to be run with sudo."
        ) from e


def _capture_af_packet(
    iface: str, count: Optional[int], duration: Optional[float],
    on_packet: Optional[OnPacket], snaplen: int,
) -> list[tuple[float, bytes]]:
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except PermissionError as e:
        raise LiveCaptureError(
            "Permission denied creating a raw socket. Live capture needs elevated "
            "privileges. Either run with sudo, e.g.:\n"
            "    sudo python -m packetanalyzer capture --iface eth0 --count 100\n"
            "or grant the interpreter the capability once instead of using sudo "
            "every time:\n"
            "    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))\n"
            f"Original error: {e}"
        ) from e

    try:
        sock.bind((iface, 0))
    except OSError as e:
        sock.close()
        raise LiveCaptureError(
            f"Could not bind to interface '{iface}': {e}. "
            "Run with --list-interfaces to see available interface names."
        ) from e

    packets: list[tuple[float, bytes]] = []
    start = time.monotonic()
    try:
        while True:
            if count is not None and len(packets) >= count:
                break
            if duration is not None and (time.monotonic() - start) >= duration:
                break
            if duration is not None:
                remaining = duration - (time.monotonic() - start)
                sock.settimeout(max(0.01, remaining))
            else:
                sock.settimeout(1.0)
            try:
                data, _addr = sock.recvfrom(snaplen)
            except socket.timeout:
                continue
            ts = time.time()
            packets.append((ts, data))
            if on_packet:
                on_packet(ts, data)
    finally:
        sock.close()

    return packets


def _capture_scapy(
    iface: str, count: Optional[int], duration: Optional[float], on_packet: Optional[OnPacket],
) -> list[tuple[float, bytes]]:
    from scapy.all import sniff, raw  # optional dependency; raises ImportError if absent

    collected: list[tuple[float, bytes]] = []

    def _callback(pkt):
        ts = float(pkt.time)
        data = bytes(raw(pkt))
        collected.append((ts, data))
        if on_packet:
            on_packet(ts, data)

    kwargs = {"iface": iface, "prn": _callback, "store": False}
    if count is not None:
        kwargs["count"] = count
    if duration is not None:
        kwargs["timeout"] = duration
    sniff(**kwargs)
    return collected


def capture_to_pcap(
    iface: str, path: str, count: Optional[int] = None, duration: Optional[float] = None,
    on_packet: Optional[OnPacket] = None,
) -> int:
    """Capture and write straight to a pcap file. Returns the packet count."""
    return write_pcap(path, iter(capture_packets(iface, count=count, duration=duration, on_packet=on_packet)))
