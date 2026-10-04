"""
generate_sample_capture.py — builds sample_capture.pcap: a synthetic
capture for demoing and testing this project without capturing anyone's
real traffic.

Every address is either RFC 1918 private space (the "local network") or
RFC 5737 documentation space (203.0.113.0/24, 198.51.100.0/24) reserved
specifically for examples like this one — none of it corresponds to a
real, reachable host. MAC addresses use the locally-administered range
(02:...) rather than a real vendor OUI.

The capture contains a mix of ordinary traffic and three intentionally
embedded suspicious patterns, one for each detector in detectors.py:

  1. A simulated port scan: 198.51.100.66 -> 192.168.1.10, SYN packets
     across 25 distinct ports.
  2. A simulated ICMP flood: 198.51.100.66 -> 192.168.1.10, 30 echo
     requests in quick succession.
  3. Cleartext credentials: an FTP login (USER/PASS) and an HTTP POST
     with a "password=" field — both using the well-known placeholder
     password "hunter2".

Run directly to regenerate sample_capture.pcap:
    python sample_data/generate_sample_capture.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packetanalyzer.pcap_io import PcapWriter
from packetanalyzer.builders import (
    build_arp_packet, build_tcp_packet, build_udp_packet, build_icmp_echo_packet,
    TCP_SYN, TCP_ACK, TCP_FIN, TCP_PSH,
)

HOST_MAC = "02:00:00:00:00:01"
ROUTER_MAC = "02:00:00:00:00:02"
ATTACKER_MAC = "02:00:00:00:00:99"

LOCAL_IP = "192.168.1.10"      # "our" host — the machine being analyzed
ROUTER_IP = "192.168.1.1"
WEB_SERVER_IP = "203.0.113.10"     # RFC 5737 TEST-NET-3 (documentation-only)
FTP_SERVER_IP = "203.0.113.20"     # RFC 5737 TEST-NET-3 (documentation-only)
HTTP_SERVER_IP = "203.0.113.11"    # RFC 5737 TEST-NET-3 (documentation-only)
ATTACKER_IP = "198.51.100.66"      # RFC 5737 TEST-NET-2 (documentation-only)

BASE_TS = 1735689600.0  # 2025-01-01 00:00:00 UTC — arbitrary, deterministic


def main():
    out_path = Path(__file__).resolve().parent / "sample_capture.pcap"
    t = BASE_TS

    with PcapWriter(out_path) as w:
        def emit(raw: bytes, dt: float = 0.02):
            nonlocal t
            t += dt
            w.write_packet(t, raw)

        # 1) ARP: LOCAL_IP resolves the router's MAC
        emit(build_arp_packet(HOST_MAC, LOCAL_IP, "00:00:00:00:00:00", ROUTER_IP))
        emit(build_arp_packet(ROUTER_MAC, ROUTER_IP, HOST_MAC, LOCAL_IP, is_reply=True))

        # 2) A DNS-like UDP query/response to the router (port 53)
        emit(build_udp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=ROUTER_IP,
                               src_port=51000, dst_port=53, payload=b"\x12\x34\x01\x00query:example.com"))
        emit(build_udp_packet(src_mac=ROUTER_MAC, dst_mac=HOST_MAC, src_ip=ROUTER_IP, dst_ip=LOCAL_IP,
                               src_port=53, dst_port=51000, payload=b"\x12\x34\x81\x80reply:203.0.113.10"))

        # 3) Normal-looking HTTPS session (TCP handshake + a little data + teardown), port 443
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=WEB_SERVER_IP,
                               src_port=52000, dst_port=443, seq=1000, flags=TCP_SYN))
        emit(build_tcp_packet(src_mac=ROUTER_MAC, dst_mac=HOST_MAC, src_ip=WEB_SERVER_IP, dst_ip=LOCAL_IP,
                               src_port=443, dst_port=52000, seq=5000, ack=1001, flags=TCP_SYN | TCP_ACK))
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=WEB_SERVER_IP,
                               src_port=52000, dst_port=443, seq=1001, ack=5001, flags=TCP_ACK))
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=WEB_SERVER_IP,
                               src_port=52000, dst_port=443, seq=1001, ack=5001, flags=TCP_PSH | TCP_ACK,
                               payload=b"\x16\x03\x03TLS-ClientHello-bytes-would-go-here"))
        emit(build_tcp_packet(src_mac=ROUTER_MAC, dst_mac=HOST_MAC, src_ip=WEB_SERVER_IP, dst_ip=LOCAL_IP,
                               src_port=443, dst_port=52000, seq=5001, ack=1030, flags=TCP_PSH | TCP_ACK,
                               payload=b"\x16\x03\x03TLS-ServerHello-bytes-would-go-here"))
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=WEB_SERVER_IP,
                               src_port=52000, dst_port=443, seq=1030, ack=5030, flags=TCP_FIN | TCP_ACK))
        emit(build_tcp_packet(src_mac=ROUTER_MAC, dst_mac=HOST_MAC, src_ip=WEB_SERVER_IP, dst_ip=LOCAL_IP,
                               src_port=443, dst_port=52000, seq=5030, ack=1031, flags=TCP_FIN | TCP_ACK))

        # 4) Cleartext FTP login — deliberately insecure, deliberately flagged.
        #    "hunter2" is the well-known placeholder password (a long-running InfoSec
        #    in-joke), used here purely as an obvious, harmless stand-in.
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=FTP_SERVER_IP,
                               src_port=52050, dst_port=21, seq=2000, flags=TCP_SYN))
        emit(build_tcp_packet(src_mac=ROUTER_MAC, dst_mac=HOST_MAC, src_ip=FTP_SERVER_IP, dst_ip=LOCAL_IP,
                               src_port=21, dst_port=52050, seq=6000, ack=2001, flags=TCP_SYN | TCP_ACK))
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=FTP_SERVER_IP,
                               src_port=52050, dst_port=21, seq=2001, ack=6001, flags=TCP_ACK))
        emit(build_tcp_packet(src_mac=ROUTER_MAC, dst_mac=HOST_MAC, src_ip=FTP_SERVER_IP, dst_ip=LOCAL_IP,
                               src_port=21, dst_port=52050, seq=6001, ack=2001, flags=TCP_PSH | TCP_ACK,
                               payload=b"220 sample-ftp ready\r\n"))
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=FTP_SERVER_IP,
                               src_port=52050, dst_port=21, seq=2001, ack=6023, flags=TCP_PSH | TCP_ACK,
                               payload=b"USER alice\r\n"))
        emit(build_tcp_packet(src_mac=ROUTER_MAC, dst_mac=HOST_MAC, src_ip=FTP_SERVER_IP, dst_ip=LOCAL_IP,
                               src_port=21, dst_port=52050, seq=6023, ack=2013, flags=TCP_PSH | TCP_ACK,
                               payload=b"331 password required\r\n"))
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=FTP_SERVER_IP,
                               src_port=52050, dst_port=21, seq=2013, ack=6047, flags=TCP_PSH | TCP_ACK,
                               payload=b"PASS hunter2\r\n"))
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=FTP_SERVER_IP,
                               src_port=52050, dst_port=21, seq=2027, ack=6047, flags=TCP_FIN | TCP_ACK))

        # 5) HTTP form POST with a plaintext password field — the HTTP-specific
        #    credential-marker path in detect_cleartext_credentials().
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=HTTP_SERVER_IP,
                               src_port=52100, dst_port=80, seq=3000, flags=TCP_SYN))
        emit(build_tcp_packet(src_mac=ROUTER_MAC, dst_mac=HOST_MAC, src_ip=HTTP_SERVER_IP, dst_ip=LOCAL_IP,
                               src_port=80, dst_port=52100, seq=7000, ack=3001, flags=TCP_SYN | TCP_ACK))
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=HTTP_SERVER_IP,
                               src_port=52100, dst_port=80, seq=3001, ack=7001, flags=TCP_ACK))
        http_body = b"username=alice&password=hunter2"
        http_req = (
            b"POST /login HTTP/1.1\r\nHost: example-app.test\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: " + str(len(http_body)).encode() + b"\r\n\r\n" + http_body
        )
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=HTTP_SERVER_IP,
                               src_port=52100, dst_port=80, seq=3001, ack=7001, flags=TCP_PSH | TCP_ACK,
                               payload=http_req))
        emit(build_tcp_packet(src_mac=ROUTER_MAC, dst_mac=HOST_MAC, src_ip=HTTP_SERVER_IP, dst_ip=LOCAL_IP,
                               src_port=80, dst_port=52100, seq=7001, ack=3001 + len(http_req), flags=TCP_FIN | TCP_ACK,
                               payload=b"HTTP/1.1 302 Found\r\nLocation: /dashboard\r\n\r\n"))
        emit(build_tcp_packet(src_mac=HOST_MAC, dst_mac=ROUTER_MAC, src_ip=LOCAL_IP, dst_ip=HTTP_SERVER_IP,
                               src_port=52100, dst_port=80, seq=3001 + len(http_req), ack=7002, flags=TCP_FIN | TCP_ACK))

        # 6) Simulated port scan: ATTACKER_IP -> LOCAL_IP, SYN to 25 distinct ports, rapid-fire.
        scan_ports = list(range(20, 45))  # 25 ports
        for port in scan_ports:
            emit(build_tcp_packet(src_mac=ATTACKER_MAC, dst_mac=HOST_MAC, src_ip=ATTACKER_IP, dst_ip=LOCAL_IP,
                                   src_port=40000 + port, dst_port=port, seq=1, flags=TCP_SYN), dt=0.01)

        # 7) Simulated ICMP flood: ATTACKER_IP -> LOCAL_IP, 30 echo requests, rapid-fire.
        for i in range(30):
            emit(build_icmp_echo_packet(src_mac=ATTACKER_MAC, dst_mac=HOST_MAC, src_ip=ATTACKER_IP, dst_ip=LOCAL_IP,
                                         ident=1337, seq=i), dt=0.005)

    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
