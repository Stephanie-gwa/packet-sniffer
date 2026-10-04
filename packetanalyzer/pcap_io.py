"""
pcap_io.py — read and write the classic libpcap file format (the format
Wireshark calls "pcap", as opposed to the newer "pcapng"). This is a
from-scratch implementation using only `struct` — no dependency on
scapy, dpkt, or libpcap itself.

File layout (see https://wiki.wireshark.org/Development/LibpcapFileFormat):
    global header (24 bytes)
    repeated: [record header (16 bytes)] [packet data (incl_len bytes)]
"""
from __future__ import annotations
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator, Union

MAGIC_USEC = 0xA1B2C3D4
MAGIC_NSEC = 0xA1B23C4D
# Kept as aliases for readability at call sites / in tests: the magic number
# is a fixed logical value (MAGIC_USEC / MAGIC_NSEC); what varies is only
# which byte order it's *encoded* in on disk, which _detect_header figures
# out by trying both interpretations of the same 4 bytes.
MAGIC_USEC_LE = MAGIC_USEC
MAGIC_NSEC_LE = MAGIC_NSEC

LINKTYPE_ETHERNET = 1


class PcapFormatError(Exception):
    """Raised when a file is not a recognizable pcap capture."""


@dataclass
class RawPacket:
    timestamp: float   # seconds since the epoch, as a float
    orig_len: int       # length of the packet as it appeared on the wire
    data: bytes          # captured bytes (may be shorter than orig_len if snaplen truncated it)


def _detect_header(magic_bytes: bytes) -> tuple[str, str]:
    """Return (byte_order_char, unit) for the 4-byte magic number, or raise.

    The magic number is always logically MAGIC_USEC or MAGIC_NSEC; a file
    written on a big-endian system stores those same bytes in big-endian
    order. So we try reading the 4 bytes both ways and see which
    interpretation lands on a known magic value — that tells us the file's
    byte order, which we then use for every other field in the file."""
    (as_little_endian,) = struct.unpack("<I", magic_bytes)
    (as_big_endian,) = struct.unpack(">I", magic_bytes)
    if as_little_endian == MAGIC_USEC:
        return "<", "usec"
    if as_little_endian == MAGIC_NSEC:
        return "<", "nsec"
    if as_big_endian == MAGIC_USEC:
        return ">", "usec"
    if as_big_endian == MAGIC_NSEC:
        return ">", "nsec"
    raise PcapFormatError(
        f"Not a recognized pcap file (unexpected magic bytes {magic_bytes.hex()}). "
        "Note: pcapng (.pcapng) files are a different, newer format and are not "
        "supported by this reader — re-save as classic pcap in Wireshark "
        "(File -> Export Specified Packets -> .pcap) if needed."
    )


def read_pcap(path: Union[str, Path]) -> Iterator[RawPacket]:
    """Yield RawPacket records from a classic pcap file, in file order."""
    with open(path, "rb") as f:
        yield from _read_pcap_stream(f)


def _read_pcap_stream(f: BinaryIO) -> Iterator[RawPacket]:
    global_header = f.read(24)
    if len(global_header) < 24:
        raise PcapFormatError("File is too short to contain a valid pcap global header.")
    order, unit = _detect_header(global_header[:4])
    # magic(4) version_major(2) version_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
    _, _, _, _, _, _, network = struct.unpack(order + "IHHiIII", global_header)
    if network != LINKTYPE_ETHERNET:
        raise PcapFormatError(
            f"Unsupported link-layer type {network} (this reader only supports "
            f"Ethernet, LINKTYPE_ETHERNET=1)."
        )

    record_header_fmt = order + "IIII"
    record_header_size = struct.calcsize(record_header_fmt)

    while True:
        rec_header = f.read(record_header_size)
        if len(rec_header) == 0:
            break
        if len(rec_header) < record_header_size:
            raise PcapFormatError("Truncated packet record header at end of file.")
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(record_header_fmt, rec_header)
        data = f.read(incl_len)
        if len(data) < incl_len:
            raise PcapFormatError("Truncated packet data at end of file.")
        frac_seconds = ts_frac / 1_000_000_000 if unit == "nsec" else ts_frac / 1_000_000
        yield RawPacket(timestamp=ts_sec + frac_seconds, orig_len=orig_len, data=data)


class PcapWriter:
    """Writes a classic, little-endian, microsecond-resolution pcap file —
    the most broadly compatible variant, readable by any current version
    of Wireshark, tcpdump, or tshark."""

    def __init__(self, path: Union[str, Path], snaplen: int = 65535):
        self._f = open(path, "wb")
        self._f.write(struct.pack(
            "<IHHiIII", MAGIC_USEC_LE, 2, 4, 0, 0, snaplen, LINKTYPE_ETHERNET,
        ))

    def write_packet(self, timestamp: float, data: bytes) -> None:
        ts_sec = int(timestamp)
        ts_usec = int(round((timestamp - ts_sec) * 1_000_000))
        incl_len = len(data)
        self._f.write(struct.pack("<IIII", ts_sec, ts_usec, incl_len, incl_len))
        self._f.write(data)

    def close(self) -> None:
        self._f.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def write_pcap(path: Union[str, Path], packets: Iterator[tuple[float, bytes]]) -> int:
    """Convenience one-shot writer. `packets` is an iterable of (timestamp, raw_bytes).
    Returns the number of packets written."""
    count = 0
    with PcapWriter(path) as writer:
        for ts, data in packets:
            writer.write_packet(ts, data)
            count += 1
    return count
