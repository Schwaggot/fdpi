# fdpi Comparison Tools

Validates fdpi's packet decoding correctness by comparing its output field-by-field against tshark (Wireshark's CLI) as
ground truth.

## Architecture

```
tracefiles/*.pcap
      |
      +---> tshark -T fields -e ... --> reference TSV (per PCAP)
      |                                        |
      +---> fdpi_compare (C++ tool)  --> fdpi TSV (per PCAP)
                                               |
                        compare_with_tshark.py <+
                                |
                          Comparison report
                     (match rates, mismatches)
```

**Components:**

- `compare_output.cpp` -- C++ tool that reads PCAPs via fpcap, decodes each packet with fdpi, and outputs one TSV line
  per packet using tshark-compatible field names
- `compare_with_tshark.py` -- Python script that orchestrates tshark baseline generation, runs fdpi_compare, compares
  results field-by-field with normalization, and produces a detailed report

## Prerequisites

- **tshark** (Wireshark CLI):
    - macOS: `brew install wireshark`
    - Ubuntu: `sudo apt install tshark`
    - Fedora: `sudo dnf install wireshark-cli`
- **Python 3** (stdlib only, no pip packages needed)
- **fdpi built with tools enabled** (see below)

## Building

```bash
cmake -B build -DFDPI_BUILD_TOOLS=ON
cmake --build build
```

This builds the `fdpi_compare` executable at `build/tools/fdpi_compare`.

## Usage

### Quick start (generate baselines + compare)

```bash
python3 tools/compare_with_tshark.py full
```

### Step by step

```bash
# 1. Generate tshark reference baselines for all PCAPs
python3 tools/compare_with_tshark.py generate

# 2. Run comparison against baselines
python3 tools/compare_with_tshark.py compare
```

### Single PCAP

```bash
python3 tools/compare_with_tshark.py full --pcap tracefiles/protocol-pcap/dns.pcap --verbose
```

### Options

| Flag               | Description                                          |
|--------------------|------------------------------------------------------|
| `--pcap FILE`      | Process a single PCAP instead of all tracefiles      |
| `--verbose` / `-v` | Show every individual field mismatch                 |
| `--include-large`  | Include PCAPs larger than 10 MB (skipped by default) |

### fdpi_compare standalone

```bash
# Outputs TSV to stdout (header + one row per packet)
./build/tools/fdpi_compare tracefiles/protocol-pcap/dns.pcap
```

## Compared Fields (116 total)

The tool compares fields across all protocol layers fdpi supports:

| Layer    | Fields                                                                                                                                                                    |
|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Frame    | `frame.number`, `frame.len`, `frame.cap_len`                                                                                                                              |
| Ethernet | `eth.src`, `eth.dst`, `eth.type`                                                                                                                                          |
| IPv4     | `ip.version`, `ip.hdr_len`, `ip.dsfield.dscp`, `ip.dsfield.ecn`, `ip.len`, `ip.id`, `ip.flags`, `ip.frag_offset`, `ip.ttl`, `ip.proto`, `ip.checksum`, `ip.src`, `ip.dst` |
| IPv6     | `ipv6.version`, `ipv6.tclass`, `ipv6.flow`, `ipv6.plen`, `ipv6.nxt`, `ipv6.hlim`, `ipv6.src`, `ipv6.dst`                                                                  |
| ARP      | `arp.hw.type`, `arp.proto.type`, `arp.hw.size`, `arp.proto.size`, `arp.opcode`, `arp.src.hw_mac`, `arp.src.proto_ipv4`, `arp.dst.hw_mac`, `arp.dst.proto_ipv4`            |
| TCP      | `tcp.srcport`, `tcp.dstport`, `tcp.seq_raw`, `tcp.ack_raw`, `tcp.hdr_len`, `tcp.flags`, `tcp.window_size_value`, `tcp.checksum`, `tcp.urgent_pointer`                     |
| UDP      | `udp.srcport`, `udp.dstport`, `udp.length`, `udp.checksum`                                                                                                                |
| ICMP     | `icmp.type`, `icmp.code`, `icmp.checksum`                                                                                                                                 |
| ICMPv6   | `icmpv6.type`, `icmpv6.code`, `icmpv6.checksum`                                                                                                                           |
| DNS      | `dns.id`, `dns.flags.*` (7 flags), `dns.count.queries`, `dns.count.answers`, `dns.qry.name`, `dns.qry.type`                                                               |
| HTTP     | `http.request.method`, `http.request.uri`, `http.response.code`, `http.request.version`                                                                                   |
| TLS      | `tls.record.content_type`, `tls.record.version`, `tls.handshake.extensions_server_name`                                                                                   |
| QUIC     | `quic.long.packet_type`, `quic.version`, `quic.dcid`, `quic.scid`                                                                                                         |
| FTP      | `ftp.request.command`, `ftp.request.arg`, `ftp.response.code`, `ftp.response.arg`                                                                                         |
| SSH      | `ssh.protocol`                                                                                                                                                            |
| DHCP     | `dhcp.type`, `dhcp.hw.type`, `dhcp.hw.len`, `dhcp.hops`, `dhcp.id`, `dhcp.secs`, `dhcp.flags`, `dhcp.ip.*` (4 fields), `dhcp.hw.mac_addr`, `dhcp.option.dhcp`             |
| DHCPv6   | `dhcpv6.msgtype`, `dhcpv6.xid`                                                                                                                                            |
| SMTP     | `smtp.req.command`, `smtp.req.parameter`, `smtp.response.code`                                                                                                            |
| POP3     | `pop.request.command`, `pop.request.parameter`, `pop.response.indicator`                                                                                                  |
| IMAP     | `imap.request_tag`, `imap.request.command`                                                                                                                                |
| SNMP     | `snmp.version`, `snmp.community`                                                                                                                                          |
| NTP      | `ntp.flags.li`, `ntp.flags.vn`, `ntp.flags.mode`, `ntp.stratum`                                                                                                           |
| BGP      | `bgp.type`                                                                                                                                                                |
| LDAP     | `ldap.messageID`                                                                                                                                                          |
| TPKT/RDP | `tpkt.version`, `tpkt.length`                                                                                                                                             |

## Normalization

The comparison script normalizes values before comparing to account for known format differences between fdpi and
tshark:

| Category                   | Example                               | Normalization                          |
|----------------------------|---------------------------------------|----------------------------------------|
| Hex values                 | `0x0800` vs `0x00000800`              | Strip leading zeros, case-insensitive  |
| Booleans                   | `True`/`False` vs `1`/`0`             | Normalize to `1`/`0`                   |
| DNS names                  | `example.com.` vs `example.com`       | Strip trailing dots                    |
| MAC addresses              | `AA:BB:CC:DD:EE:FF`                   | Lowercase                              |
| IPv6 addresses             | mixed case                            | Lowercase                              |
| Empty response-only fields | tshark leaves empty, fdpi outputs `0` | Treat empty as `0` for DNS flag fields |
| DHCP hw.type               | `0x01` vs `1`                         | Compare as integer                     |

## Extending with New Protocols

To add a new protocol to the comparison:

### 1. Find the tshark field names

```bash
# List all tshark fields for a protocol
tshark -G fields | grep -i "^F.*your_protocol"
```

### 2. Add columns to the C++ tool (`compare_output.cpp`)

Add the tshark field names to the `COLUMNS` vector:

```cpp
const std::vector<std::string> COLUMNS = {
    // ... existing columns ...
    // YourProtocol
    "yourproto.field1", "yourproto.field2",
};
```

Add a setter function and wire it into `setLayer7()`:

```cpp
void setYourProto(Row& row, const fdpi::YourProto& proto) {
    row[colIndex("yourproto.field1")] = decStr(proto.field1);
    row[colIndex("yourproto.field2")] = proto.field2;
}

// In setLayer7():
} else if constexpr (std::is_same_v<T, fdpi::YourProto>) {
    setYourProto(row, v);
}
```

### 3. Mirror in the Python script (`compare_with_tshark.py`)

Add the same field names to the `COLUMNS` list in the Python script (must be in the same order):

```python
COLUMNS = [
    # ... existing columns ...
    # YourProtocol
    "yourproto.field1", "yourproto.field2",
]
```

Add normalization rules if needed (hex fields, booleans, etc.).

### 4. Rebuild and test

```bash
cmake --build build --target fdpi_compare
python3 tools/compare_with_tshark.py full --pcap tracefiles/protocol-pcap/yourproto.pcap --verbose
```

## Current Results

Tested against 94 PCAPs in `tracefiles/` (88 compared, 6 skipped as 802.11 wireless).

### 100% match (34 PCAPs)

These PCAPs match tshark field-for-field on every packet:

arp_gratuitous, arp_resolution, dhcp_inlease_renewal, dhcp_nolease_initialization,
dns (chrissanders), dns_lab, dns_query_nonexistent, dns_query_response,
dns_recursivequery_client, dns_recursivequery_server, dns_reverse_lookup, dns (protocol-pcap),
ftp-cmd-data, ftp-data, icmp_echo, inconsistent_printer, ip_ttl_dest, ip_ttl_source,
nowebaccess1, nowebaccess2, nowebaccess3, passiveosfingerprinting, ratinfected,
rtmp_live_flow, stranded_branchdns, stranded_clientside, synscan, tcp_dupack,
tcp_handshake, tcp_refuseconnection, tcp_retransmissions, tcp_teardown,
tcp_zerowindowdead, tcp_zerowindowrecovery, tickedoffdeveloper, udp_dnsrequest,
wrongdissector

### 95-99% match (30+ PCAPs)

High match rates with minor differences, typically in L7 protocol detection timing (fdpi and tshark may detect
HTTP/TLS/FTP on different packets within the same flow):

activeosfingerprinting (99.9%), aurora (99.4%), cryptowall4_c2 (99.5%),
dns_isp_hijack (99.6%), http_dvwa_* (98-99%), http_google (99.1%),
mail_sender_* (98-99%), tcp_ports (99.2%), ipv6-some (96.7%)

### Lower match rates

Primarily caused by **packet count differences** between tshark and fdpi, which cause cascading mismatches when
comparing line-by-line:

| PCAP                     | Match Rate | Cause                                          |
|--------------------------|------------|------------------------------------------------|
| lotsofweb.pcapng         | 58.5%      | tshark: 12899 packets, fdpi: 13236 (337 extra) |
| ipv6-http.pcap           | 62.1%      | Packet count mismatch in large trace           |
| http_espn.pcapng         | 67.4%      | Packet count mismatch                          |
| ek_to_cryptowall4.pcapng | 73.6%      | Mixed HTTP/TLS traffic, detection differences  |
| IPv4_Vxlan_12pkts.pcap   | 35.9%      | VxLAN encapsulation (fdpi decodes outer only)  |

### Skipped (6 PCAPs)

802.11 wireless PCAPs (non-Ethernet link layer): 3e80211_wepauth, 3e80211_wepauthfail,
3e80211_wpaauth, 3e80211_wpaauthfail, 80211beacon, iquery-dns

## Limitations

- **Ethernet only.** fdpi only supports Ethernet (link layer type 1). 802.11, raw IP, and other link types are detected
  and skipped with exit code 2.
- **Packet count mismatches cause cascading errors.** The comparison is strictly line-by-line. If tshark and fdpi
  disagree on how many packets a PCAP contains, all subsequent fields are misaligned.
- **No TCP reassembly comparison.** Both fdpi and tshark have defragmentation and TCP reassembly disabled for this
  comparison, so only per-packet decoding is validated.
- **L7 detection differences.** fdpi and tshark may detect application protocols on different packets. For example,
  tshark may label a packet as HTTP while fdpi classifies it as plain TCP, or vice versa. This is expected due to
  different heuristics.
- **Encapsulated protocols.** VxLAN, GRE, and other tunneling protocols are decoded by tshark as inner protocols, while
  fdpi may only decode the outer layer, causing field mismatches.
- **QUIC version field.** fdpi stores the QUIC version as `uint8_t` while tshark uses a 32-bit value. These will always
  differ for QUIC packets.
- **tshark baselines are not committed.** Generated baselines are in `.gitignore` and must be regenerated locally (
  requires tshark). This ensures results always reflect the local tshark version.
