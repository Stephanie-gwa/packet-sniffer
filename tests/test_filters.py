from packetanalyzer.parser import Packet
from packetanalyzer.filters import apply_filters


def make_packet(**kw):
    defaults = dict(timestamp=1.0, length=60, protocol="TCP")
    defaults.update(kw)
    return Packet(**defaults)


PACKETS = [
    make_packet(protocol="TCP", src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=5000, dst_port=443),
    make_packet(protocol="UDP", src_ip="1.1.1.1", dst_ip="9.9.9.9", src_port=6000, dst_port=53),
    make_packet(protocol="ICMP", src_ip="3.3.3.3", dst_ip="2.2.2.2"),
    make_packet(protocol="ARP", src_ip="1.1.1.1", dst_ip="1.1.1.254"),
]


def test_filter_by_protocol():
    result = apply_filters(PACKETS, protocol="TCP")
    assert len(result) == 1
    assert result[0].protocol == "TCP"


def test_filter_by_protocol_case_insensitive():
    result = apply_filters(PACKETS, protocol="udp")
    assert len(result) == 1
    assert result[0].protocol == "UDP"


def test_filter_by_src_ip():
    result = apply_filters(PACKETS, src_ip="1.1.1.1")
    assert len(result) == 3


def test_filter_by_dst_ip():
    result = apply_filters(PACKETS, dst_ip="2.2.2.2")
    assert len(result) == 2


def test_filter_by_ip_matches_either_direction():
    result = apply_filters(PACKETS, ip="2.2.2.2")
    assert len(result) == 2
    assert all(p.src_ip == "2.2.2.2" or p.dst_ip == "2.2.2.2" for p in result)


def test_filter_by_port():
    result = apply_filters(PACKETS, port=443)
    assert len(result) == 1
    assert result[0].dst_port == 443


def test_filter_by_port_matches_src_or_dst():
    result = apply_filters(PACKETS, port=6000)
    assert len(result) == 1


def test_combined_filters():
    result = apply_filters(PACKETS, protocol="TCP", src_ip="1.1.1.1")
    assert len(result) == 1


def test_no_filters_returns_all():
    result = apply_filters(PACKETS)
    assert len(result) == len(PACKETS)


def test_filter_matching_nothing():
    result = apply_filters(PACKETS, protocol="TCP", port=9999)
    assert result == []
