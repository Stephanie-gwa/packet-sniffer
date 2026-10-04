import struct

import pytest

from packetanalyzer.pcap_io import (
    read_pcap, write_pcap, PcapWriter, PcapFormatError,
    MAGIC_USEC, MAGIC_NSEC, LINKTYPE_ETHERNET,
)


def test_write_then_read_round_trip(tmp_path):
    path = tmp_path / "test.pcap"
    packets = [(1000.5, b"A" * 20), (1000.75, b"B" * 40), (1001.0, b"C" * 14)]
    count = write_pcap(path, iter(packets))
    assert count == 3

    read_back = list(read_pcap(path))
    assert len(read_back) == 3
    for (ts, data), rp in zip(packets, read_back):
        assert rp.data == data
        assert rp.orig_len == len(data)
        assert abs(rp.timestamp - ts) < 1e-6


def test_write_preserves_microsecond_precision(tmp_path):
    path = tmp_path / "test.pcap"
    write_pcap(path, iter([(1234567890.123456, b"hello")]))
    (rp,) = list(read_pcap(path))
    assert abs(rp.timestamp - 1234567890.123456) < 1e-6


def test_empty_capture_round_trip(tmp_path):
    path = tmp_path / "empty.pcap"
    count = write_pcap(path, iter([]))
    assert count == 0
    assert list(read_pcap(path)) == []


def test_pcap_writer_context_manager(tmp_path):
    path = tmp_path / "ctx.pcap"
    with PcapWriter(path) as w:
        w.write_packet(100.0, b"\x00" * 14)
    packets = list(read_pcap(path))
    assert len(packets) == 1
    assert packets[0].data == b"\x00" * 14


def test_reject_too_short_file(tmp_path):
    path = tmp_path / "short.pcap"
    path.write_bytes(b"\x00\x01\x02")
    with pytest.raises(PcapFormatError):
        list(read_pcap(path))


def test_reject_bad_magic(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"NOTA" + b"\x00" * 20)
    with pytest.raises(PcapFormatError, match="(?i)not a recognized pcap"):
        list(read_pcap(path))


def test_reject_unsupported_linktype(tmp_path):
    path = tmp_path / "wrongtype.pcap"
    header = struct.pack("<IHHiIII", MAGIC_USEC, 2, 4, 0, 0, 65535, 105)  # 105 = LINKTYPE_IEEE802_11
    path.write_bytes(header)
    with pytest.raises(PcapFormatError, match="Ethernet"):
        list(read_pcap(path))


def test_reject_truncated_packet_data(tmp_path):
    path = tmp_path / "trunc.pcap"
    header = struct.pack("<IHHiIII", MAGIC_USEC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
    # claims 100 bytes of packet data but only provides 5
    record_header = struct.pack("<IIII", 0, 0, 100, 100)
    path.write_bytes(header + record_header + b"\x00" * 5)
    with pytest.raises(PcapFormatError, match="Truncated"):
        list(read_pcap(path))


def test_reads_nanosecond_variant(tmp_path):
    path = tmp_path / "nsec.pcap"
    header = struct.pack("<IHHiIII", MAGIC_NSEC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
    data = b"X" * 10
    record_header = struct.pack("<IIII", 500, 250_000_000, len(data), len(data))
    path.write_bytes(header + record_header + data)
    (rp,) = list(read_pcap(path))
    assert rp.timestamp == pytest.approx(500.25, abs=1e-9)


def test_reads_big_endian_variant(tmp_path):
    """A file written on a big-endian system stores the same logical magic
    number (MAGIC_USEC), just encoded big-endian — i.e. its on-disk bytes
    are the ">"-packed form of MAGIC_USEC, not some other constant."""
    path = tmp_path / "be.pcap"
    header = struct.pack(">IHHiIII", MAGIC_USEC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
    data = b"Y" * 10
    record_header = struct.pack(">IIII", 42, 500000, len(data), len(data))
    path.write_bytes(header + record_header + data)
    (rp,) = list(read_pcap(path))
    assert rp.timestamp == pytest.approx(42.5, abs=1e-6)
    assert rp.data == data


def test_snaplen_truncation_preserves_orig_len(tmp_path):
    """incl_len (captured) can be shorter than orig_len (on the wire)."""
    path = tmp_path / "snap.pcap"
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", MAGIC_USEC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        data = b"Z" * 10
        f.write(struct.pack("<IIII", 1, 0, len(data), 1500))  # orig_len 1500, only 10 captured
        f.write(data)
    (rp,) = list(read_pcap(path))
    assert rp.orig_len == 1500
    assert len(rp.data) == 10
