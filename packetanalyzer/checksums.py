"""
checksums.py — the standard Internet checksum (RFC 1071), used to build
sample packets with headers that validate correctly if opened in
Wireshark or any other real packet tool.

The parser in this project does NOT validate checksums on read (see
README limitations) — this module is only used by the packet builders
to produce realistic, correctly-checksummed sample data.
"""
import struct


def checksum16(data: bytes) -> int:
    """Standard Internet checksum: ones'-complement sum of 16-bit words,
    with any final odd byte padded, carries folded back in, then
    complemented."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_pseudo_header(src_ip: bytes, dst_ip: bytes, protocol: int, length: int) -> bytes:
    return struct.pack("!4s4sBBH", src_ip, dst_ip, 0, protocol, length)
