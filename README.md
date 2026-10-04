# packetanalyzer

An offline (and optionally live) packet capture analysis tool, built from
scratch in Python with no third-party dependencies for the core features.
It parses raw `.pcap` files, summarizes protocols and conversations,
supports filtering, and flags a small number of clearly defined
suspicious patterns.

Ships with a synthetic **sample capture** (`sample_data/sample_capture.pcap`)
so you can run and demo everything immediately without capturing anyone's
real traffic.

## ⚠️ Authorization & ethics

- **Offline analysis** (`analyze`) only ever reads a `.pcap` file you
  already have. It performs no network activity at all.
- **Live capture** (`capture`) reads every packet that reaches the
  interface you point it at — including traffic from other people or
  devices on a shared network segment, not just "your own" traffic.
  **Only capture on an interface and network you own or are explicitly
  authorized to monitor.** Capturing others' traffic without consent can
  be illegal where you live (e.g. wiretapping statutes) and typically
  violates employer/ISP acceptable-use policies. The `capture` command
  always prints this reminder and requires explicit confirmation
  (`--yes`, or typing `yes` interactively) before it opens a socket —
  there's no default target the way `analyze` has none needed.
- This project never sends or injects packets onto a network. The
  `builders.py` module used to construct the sample capture only ever
  returns `bytes` for writing to a `.pcap` file.

## Features

- **From-scratch pcap reader/writer** (`pcap_io.py`) — classic libpcap
  format, no `scapy`/`dpkt`/libpcap binding required to read a capture.
  Handles both byte orders and micro/nanosecond timestamp variants.
- **From-scratch protocol parser** (`parser.py`) — Ethernet II, ARP,
  IPv4 with TCP/UDP/ICMP. Malformed frames are reported, not silently
  dropped.
- **Summary statistics** (`analyzer.py`) — protocol breakdown, top
  talkers, top conversations, most active ports, byte/packet counts,
  capture duration.
- **Filters** (`filters.py`) — by protocol, source IP, destination IP,
  either-direction IP, either-direction port.
- **Three suspicious-pattern detectors** (`detectors.py`), each with a
  precise, documented definition — see [Detectors](#detectors-what-exactly-they-flag) below.
- **JSON export** and a human-readable table report.
- **Optional live capture** (`live_capture.py`) — raw `AF_PACKET`
  sockets on Linux (stdlib only), with an optional `scapy` fallback for
  other platforms.
- 83 automated tests, including one that performs a **real** capture of
  a real UDP packet over the loopback interface.

## Project layout

```
packetanalyzer/
  pcap_io.py         Classic .pcap file reader + writer
  builders.py          Raw Ethernet/ARP/IP/TCP/UDP/ICMP frame construction (used for sample data + tests; never sends anything)
  checksums.py          Internet checksum (RFC 1071) helper for the builders
  parser.py             Decodes a raw frame into a Packet
  analyzer.py            Packet list -> CaptureSummary
  filters.py               Protocol/IP/port filters
  detectors.py              Port scan / ICMP flood / cleartext-credential detectors
  reporter.py                Text table + JSON rendering
  live_capture.py             Optional live capture (AF_PACKET or scapy)
  cli.py                        analyze / list-interfaces / capture subcommands
sample_data/
  generate_sample_capture.py    Regenerates sample_capture.pcap
  sample_capture.pcap            The 80-packet synthetic sample capture
tests/
  test_pcap_io.py, test_parser.py, test_analyzer.py, test_filters.py,
  test_detectors.py, test_cli.py, test_live_capture.py
examples/
  sample_output.json              JSON export of the sample capture
  sample_table_output.txt          Table/report view of the sample capture
```

## Setup

Requires Python 3.9+. No third-party dependencies for offline analysis.

```bash
git clone <this-repo>
cd packet-analyzer
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .                 # installs the `packetanalyzer` command
pip install -r requirements-dev.txt   # only needed to run the tests
```

For live capture on **non-Linux** platforms, also install the optional
extra:

```bash
pip install -r requirements-live.txt   # installs scapy
```

## Usage

```bash
# Analyze the bundled sample capture
packetanalyzer analyze --pcap sample_data/sample_capture.pcap

# Filter to one protocol
packetanalyzer analyze --pcap sample_data/sample_capture.pcap --protocol ICMP

# Filter by address or port (matches source OR destination)
packetanalyzer analyze --pcap sample_data/sample_capture.pcap --ip 203.0.113.20
packetanalyzer analyze --pcap sample_data/sample_capture.pcap --port 21

# Export full results as JSON
packetanalyzer analyze --pcap sample_data/sample_capture.pcap --output results.json

# Machine-readable output straight to stdout (e.g. for piping to jq)
packetanalyzer analyze --pcap sample_data/sample_capture.pcap --json-stdout --quiet

# Tune the detector thresholds
packetanalyzer analyze --pcap sample_data/sample_capture.pcap \
    --port-scan-threshold 10 --icmp-flood-threshold 15

# Analyze your own capture (e.g. exported from Wireshark as classic .pcap)
packetanalyzer analyze --pcap /path/to/your.pcap
```

**Note on filters and alerts:** protocol/IP/port filters only change what
the *summary table* shows. The suspicious-pattern detectors always run
over the **full, unfiltered** capture — so filtering down to `UDP` won't
hide a TCP-based port scan. The tool prints a note when this applies.

### Optional live capture

```bash
# See available interfaces
packetanalyzer list-interfaces

# Capture 50 packets on your own loopback interface, then analyze them
sudo packetanalyzer capture --iface lo --count 50 --analyze

# Capture for 30 seconds and save to a .pcap for later analysis
sudo packetanalyzer capture --iface eth0 --duration 30 --save mycapture.pcap
packetanalyzer analyze --pcap mycapture.pcap
```

Live capture needs elevated privileges:

- **Linux** (stdlib backend, no extra install): run with `sudo`, or grant
  the interpreter the capability once instead of using `sudo` every time:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
  ```
- **macOS / Windows**: install the optional `scapy` extra
  (`pip install -r requirements-live.txt`). macOS also needs `sudo`;
  Windows also needs [Npcap](https://npcap.com) installed first.

If a live capture fails, the error message tells you exactly which of
the above to do — it doesn't just say "permission denied".

### Library usage

```python
from packetanalyzer import read_pcap, parse_ethernet_frame, summarize, run_all_detectors

packets = [parse_ethernet_frame(rp.data, rp.timestamp, orig_len=rp.orig_len)
           for rp in read_pcap("sample_data/sample_capture.pcap")]

summary = summarize(packets)
alerts = run_all_detectors(packets)
```

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

**83/83 tests pass** on a clean checkout. Notably,
`tests/test_live_capture.py::test_real_capture_on_loopback_sees_a_udp_packet`
performs a genuine capture: it sends a real UDP datagram over the
loopback interface while capturing on it, and asserts the tool actually
observed and correctly parsed it. It needs root/`CAP_NET_RAW` to run for
real — if that's not available in your environment it **skips**
(doesn't fail), and the message explains why.

## Detectors: what exactly they flag

Each detector is a small, deterministic heuristic over the packets
present in the capture — not a signature database or ML model. Exact
definitions (see `detectors.py` docstrings for the full rationale):

| Detector | Default threshold | Flags when... | Will NOT catch |
|---|---|---|---|
| `port_scan` | 15 distinct ports | One source IP sends TCP SYN (no ACK) to ≥15 distinct destination ports on one destination IP, within the capture | A slow scan spread across a longer window than your capture covers |
| `icmp_flood` | 20 requests | One source IP sends ≥20 ICMP echo *requests* to one destination within the capture | A flood using a different ICMP type, or spread across multiple source IPs |
| `cleartext_credentials` | n/a | Any FTP (port 21) or Telnet (port 23) payload; or an HTTP (port 80) payload containing `password=` or `Authorization: Basic` | Credentials split across multiple TCP segments; any encrypted protocol (HTTPS, SSH, etc.) by design |

Run against the bundled sample capture, all three fire exactly once:

```
[HIGH  ] port_scan: 198.51.100.66 sent SYN packets to 25 distinct ports on 192.168.1.10 in 0.240s
[HIGH  ] cleartext_credentials: Possible credentials sent in cleartext over HTTP between 192.168.1.10 and 203.0.113.11
[MEDIUM] icmp_flood: 198.51.100.66 sent 30 ICMP echo requests to 192.168.1.10 in 0.145s
[MEDIUM] cleartext_credentials: FTP traffic between 203.0.113.20 and 192.168.1.10 is unencrypted by design
```

## Comparing a result with Wireshark

Every number below was independently verified by loading
`sample_data/sample_capture.pcap` in **tshark 4.2.2** (Wireshark's
command-line sibling — the GUI reads the same output). You can follow
along with either tshark or the Wireshark GUI.

**1. Protocol Hierarchy vs. our protocol breakdown**

```
$ tshark -r sample_data/sample_capture.pcap -q -z io,phs
eth                     frames:80 bytes:4534
  arp                   frames:2  bytes:84
  ip                    frames:78 bytes:4450
    udp                 frames:2  bytes:127
      dns               frames:2  bytes:127
        _ws.malformed   frames:2  bytes:127
    tcp                 frames:46 bytes:2823
    icmp                frames:30 bytes:1500
```
Matches our tool's summary exactly: 80 total packets, 4534 bytes,
46 TCP / 30 ICMP / 2 ARP / 2 UDP.
(*In Wireshark: Statistics -> Protocol Hierarchy.*)

The `_ws.malformed` under `dns` is expected and informative: our sample
capture's "DNS" packets are just placeholder UDP payloads on port 53,
not real DNS wire format — Wireshark tries to dissect them as DNS and
correctly reports that they aren't valid. Our tool doesn't attempt DNS
parsing at all (see Limitations), so it just reports them as `UDP`.

**2. Conversations vs. our top_conversations / top_talkers**

```
$ tshark -r sample_data/sample_capture.pcap -q -z conv,ip
198.51.100.66  <-> 192.168.1.10    55 frames  2850 bytes
192.168.1.10   <-> 203.0.113.20     8 frames   503 bytes
192.168.1.10   <-> 203.0.113.10     7 frames   454 bytes
192.168.1.10   <-> 203.0.113.11     6 frames   516 bytes
192.168.1.10   <-> 192.168.1.1      2 frames   127 bytes
```
Matches our per-pair totals exactly (e.g. our tool reports the
203.0.113.20 pair as 5 + 3 = 8 across both directions).
(*In Wireshark: Statistics -> Conversations -> IPv4 tab.*)

One deliberate difference: `tshark -z endpoints,ip` reports
`192.168.1.10` with **78** total packets, while our `top_talkers` reports
**80**. That's not a bug — Wireshark's IPv4 endpoint stats only count IP
traffic, while our `top_talkers` also credits the 2 ARP packets (which
carry IP addresses in their payload but aren't IP packets). Worth
knowing before you assume the two numbers should always match exactly.

**3. Port scan vs. our `port_scan` alert**

```
$ tshark -r sample_data/sample_capture.pcap \
    -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==198.51.100.66"
```
returns 25 packets — exactly the `distinct_ports: 25` our detector
reports. (*In Wireshark: apply the same string in the display filter bar.*)

**4. ICMP flood vs. our `icmp_flood` alert**

```
$ tshark -r sample_data/sample_capture.pcap -Y "icmp.type==8 && ip.src==198.51.100.66"
```
returns 30 packets, matching `count: 30` in our alert.

**5. Cleartext credentials vs. our `cleartext_credentials` alerts**

```
$ tshark -r sample_data/sample_capture.pcap -Y ftp \
    -T fields -e frame.number -e ftp.request.command -e ftp.request.arg
16   USER   alice
18   PASS   hunter2
```
In the Wireshark GUI: right-click any FTP packet -> **Follow -> TCP
Stream** shows the same `USER alice` / `PASS hunter2` exchange in
plaintext — a good visual for why this detector exists.

```
$ tshark -r sample_data/sample_capture.pcap -Y "http.request.method==POST" \
    -T fields -e http.file_data
757365726e616d653d616c6963652670617373776f72643d68756e74657232
```
That hex decodes to `username=alice&password=hunter2` — the same
payload our HTTP credential detector flagged. In Wireshark:
right-click the POST packet -> **Follow -> HTTP Stream** shows it as
plain text directly.

## Limitations

Being upfront about what this tool does *not* do, so results aren't
over-trusted:

- **No checksum validation.** The parser extracts header fields but
  never verifies IP/TCP/UDP/ICMP checksums. (For what it's worth,
  Wireshark disables checksum validation by default too, since modern
  NICs offload checksum calculation and captured packets often show
  "unverified" checksums even for perfectly good traffic.)
- **No deep protocol dissection.** DNS, HTTP, TLS, etc. are recognized
  only by port number and treated as opaque TCP/UDP payloads — there's
  no DNS name parsing, no TLS handshake parsing, no HTTP header
  parsing beyond the literal byte search the credential detector does.
  Wireshark's hundreds of protocol dissectors are far more thorough.
- **IPv6 is recognized but not deeply parsed.** Source/destination
  addresses are extracted; nothing past the fixed 40-byte header is.
- **Classic pcap only, not pcapng.** Wireshark defaults to pcapng for
  new captures. If your `.pcap` won't load, re-export it in Wireshark
  as classic pcap: *File -> Export Specified Packets -> .pcap*.
- **Detectors are heuristics, not proof.** See the table above for
  exactly what each one does and doesn't catch. A capture with no
  alerts is not a certification that nothing suspicious happened — it
  means these three specific patterns, at these specific thresholds,
  weren't observed in this specific capture.
- **`live_capture`'s stdlib backend is Linux-only.** `AF_PACKET` sockets
  don't exist on macOS or Windows; those platforms need the optional
  `scapy` extra.
- **No fragmentation reassembly.** Each captured frame is parsed
  independently; a payload split across IP fragments or TCP segments
  won't be reassembled before the credential detector looks at it.

## Portfolio description

> **packetanalyzer** — A Python packet capture analysis tool built to
> demonstrate protocol/network fundamentals from first principles: it
> parses the classic pcap file format and Ethernet/ARP/IPv4/TCP/UDP/ICMP
> headers using only `struct` (no scapy/dpkt for the core path),
> summarizes traffic, supports filtering, and flags port scans, ICMP
> floods, and cleartext credential exposure with precisely documented
> heuristics. Includes an from-scratch synthetic sample capture (built
> with its own frame-construction module and correct checksums) so it's
> fully runnable without capturing real traffic, an optional live-capture
> mode using raw sockets, and 83 automated tests — including one that
> performs a real loopback packet capture. Every reported number in the
> README was independently cross-checked against `tshark`.

**Technologies used:** Python 3, `struct`, `socket` (`AF_PACKET` raw
sockets), `argparse`, `dataclasses`, `json`; `pytest` for testing;
`scapy` as an optional live-capture dependency on non-Linux platforms;
`pyproject.toml`/`setuptools` for packaging. Verified against Wireshark
4.2 / tshark.

**Screenshot/demo ideas:**
- Terminal recording: `packetanalyzer analyze --pcap sample_data/sample_capture.pcap`
  showing the full table with all four alerts, followed by
  `--json-stdout | jq` to show the structured export.
- Side-by-side screenshot: our table output on one side, the same
  capture open in Wireshark's Protocol Hierarchy / Conversations views
  on the other — this README's "Comparing with Wireshark" section gives
  you the exact filters to reproduce.
- A Wireshark "Follow TCP Stream" screenshot of the FTP session showing
  `PASS hunter2` in plaintext, next to our tool's
  `cleartext_credentials` alert for the same conversation — a strong
  before/after for an interview walkthrough.
- A terminal screenshot of `sudo packetanalyzer capture --iface lo --count 20 --analyze`
  actually running, to show the live-capture path isn't just theoretical.
- `python -m pytest -v` passing, especially the real loopback-capture
  test, as a "this is genuinely tested" signal.

## License

MIT — see `LICENSE`.
