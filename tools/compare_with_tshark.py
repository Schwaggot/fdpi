#!/usr/bin/env python3
"""Compare fdpi packet decoding output against tshark (Wireshark CLI) as ground truth.

Usage:
    python3 tools/compare_with_tshark.py generate               # Generate tshark baselines
    python3 tools/compare_with_tshark.py compare                 # Compare fdpi vs tshark
    python3 tools/compare_with_tshark.py full                    # Generate + compare
    python3 tools/compare_with_tshark.py compare --pcap FILE     # Single PCAP
    python3 tools/compare_with_tshark.py compare --verbose       # Show every mismatch
    python3 tools/compare_with_tshark.py compare --include-large # Include large PCAPs
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
TRACEFILES_DIR = REPO_ROOT / "tracefiles"
BASELINES_DIR = SCRIPT_DIR / "tshark-baselines"
FDPI_COMPARE = REPO_ROOT / "build" / "tools" / "fdpi_compare"

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# Column names matching the C++ tool and tshark -e fields (same order)
COLUMNS = [
    # Frame
    "frame.number", "frame.len", "frame.cap_len",
    # Ethernet
    "eth.src", "eth.dst", "eth.type",
    # IPv4
    "ip.version", "ip.hdr_len", "ip.dsfield.dscp", "ip.dsfield.ecn",
    "ip.len", "ip.id", "ip.flags", "ip.frag_offset", "ip.ttl",
    "ip.proto", "ip.checksum", "ip.src", "ip.dst",
    # IPv6
    "ipv6.version", "ipv6.tclass", "ipv6.flow", "ipv6.plen",
    "ipv6.nxt", "ipv6.hlim", "ipv6.src", "ipv6.dst",
    # ARP
    "arp.hw.type", "arp.proto.type", "arp.hw.size", "arp.proto.size",
    "arp.opcode", "arp.src.hw_mac", "arp.src.proto_ipv4",
    "arp.dst.hw_mac", "arp.dst.proto_ipv4",
    # TCP
    "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw",
    "tcp.hdr_len", "tcp.flags", "tcp.window_size_value",
    "tcp.checksum", "tcp.urgent_pointer",
    # UDP
    "udp.srcport", "udp.dstport", "udp.length", "udp.checksum",
    # ICMP
    "icmp.type", "icmp.code", "icmp.checksum",
    # ICMPv6
    "icmpv6.type", "icmpv6.code", "icmpv6.checksum",
    # DNS
    "dns.id", "dns.flags.response", "dns.flags.opcode",
    "dns.flags.rcode", "dns.flags.authoritative",
    "dns.flags.truncated", "dns.flags.recdesired",
    "dns.flags.recavail", "dns.count.queries", "dns.count.answers",
    "dns.qry.name", "dns.qry.type",
    # HTTP
    "http.request.method", "http.request.uri", "http.response.code",
    "http.request.version",
    # TLS
    "tls.record.content_type", "tls.record.version",
    "tls.handshake.extensions_server_name",
    # QUIC
    "quic.long.packet_type", "quic.version", "quic.dcid", "quic.scid",
    # FTP
    "ftp.request.command", "ftp.request.arg", "ftp.response.code",
    "ftp.response.arg",
    # SSH
    "ssh.protocol",
    # DHCP
    "dhcp.type", "dhcp.hw.type", "dhcp.hw.len", "dhcp.hops",
    "dhcp.id", "dhcp.secs", "dhcp.flags", "dhcp.ip.client",
    "dhcp.ip.your", "dhcp.ip.server", "dhcp.ip.relay",
    "dhcp.hw.mac_addr", "dhcp.option.dhcp",
    # DHCPv6
    "dhcpv6.msgtype", "dhcpv6.xid",
    # SMTP
    "smtp.req.command", "smtp.req.parameter", "smtp.response.code",
    # POP
    "pop.request.command", "pop.request.parameter",
    "pop.response.indicator",
    # IMAP
    "imap.request_tag", "imap.request.command",
    # SNMP
    "snmp.version", "snmp.msgVersion", "snmp.community",
    # NTP
    "ntp.flags.li", "ntp.flags.vn", "ntp.flags.mode", "ntp.stratum",
    # BGP
    "bgp.type",
    # LDAP
    "ldap.messageID",
    # RDP/TPKT
    "tpkt.version", "tpkt.length",
    # Telnet
    "telnet.cmd", "telnet.data",
    # TFTP
    "tftp.opcode", "tftp.source_file", "tftp.destination_file",
    "tftp.type", "tftp.block", "tftp.error.code", "tftp.error.message",
    # STUN
    "stun.type", "stun.length", "stun.cookie",
    # DTLS
    "dtls.record.content_type", "dtls.record.version",
    "dtls.record.epoch", "dtls.record.length",
    # RTCP
    "rtcp.pt", "rtcp.length", "rtcp.senderssrc",
    # LLDP
    "lldp.chassis.id.mac", "lldp.port.id.mac", "lldp.time_to_live",
    # HomePlug-AV
    "homeplug_av.mmhdr.mmtype.qualcomm",
]


def check_tshark():
    """Check if tshark is available."""
    if shutil.which("tshark") is None:
        print("Error: tshark not found in PATH.", file=sys.stderr)
        print("Install Wireshark/tshark:", file=sys.stderr)
        print("  macOS:  brew install wireshark", file=sys.stderr)
        print("  Ubuntu: sudo apt install tshark", file=sys.stderr)
        print("  Fedora: sudo dnf install wireshark-cli", file=sys.stderr)
        sys.exit(1)


def check_fdpi_compare():
    """Check if fdpi_compare is built."""
    if not FDPI_COMPARE.exists():
        print(f"Error: fdpi_compare not found at {FDPI_COMPARE}",
              file=sys.stderr)
        print("Build it with:", file=sys.stderr)
        print("  cmake -B build -DFDPI_BUILD_TOOLS=ON && "
              "cmake --build build", file=sys.stderr)
        sys.exit(1)


def scan_pcaps(include_large=False):
    """Find all PCAP files in tracefiles/."""
    pcaps = []
    for root, _, files in os.walk(TRACEFILES_DIR):
        for f in files:
            if not (f.endswith(".pcap") or f.endswith(".pcapng")):
                continue
            path = Path(root) / f
            if not include_large and path.stat().st_size > MAX_FILE_SIZE:
                continue
            pcaps.append(path)
    pcaps.sort()
    return pcaps


def baseline_path(pcap_path):
    """Derive tshark baseline path from PCAP path."""
    rel = pcap_path.relative_to(TRACEFILES_DIR)
    return BASELINES_DIR / (str(rel) + ".tsv")


def build_tshark_cmd(pcap_path):
    """Build the tshark command to extract fields."""
    cmd = ["tshark", "-r", str(pcap_path), "-T", "fields"]
    # Disable TCP reassembly / desegmentation so tshark reports per-packet
    # L7 fields (matching fdpi's per-packet mode).
    cmd.extend(["-o", "tcp.desegment_tcp_streams:FALSE"])
    # Disable tshark's rtcp_udp heuristic dissector — it aggressively
    # pattern-matches on 2 bytes of random UDP payloads and produces false
    # positives (every match is flagged [Malformed Packet]).
    cmd.extend(["--disable-heuristic", "rtcp_udp"])
    for col in COLUMNS:
        cmd.extend(["-e", col])
    # Use tab separator (default), disable quoting
    cmd.extend(["-E", "separator=\t", "-E", "quote=n", "-E", "header=y"])
    return cmd


def generate_baseline(pcap_path):
    """Run tshark on a PCAP and save the TSV output."""
    out_path = baseline_path(pcap_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = build_tshark_cmd(pcap_path)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=120, errors="replace")
    except subprocess.TimeoutExpired:
        print(f"  TIMEOUT: {pcap_path.name}", file=sys.stderr)
        return False

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "unsupported" in stderr.lower() or "can't open" in stderr.lower():
            print(f"  SKIP (tshark error): {pcap_path.name}: {stderr}")
            return False
        print(f"  WARN: tshark returned {result.returncode} for "
              f"{pcap_path.name}: {stderr}", file=sys.stderr)

    with open(out_path, "w") as f:
        f.write(result.stdout)
    return True


def run_fdpi_compare(pcap_path):
    """Run fdpi_compare on a PCAP and return the TSV output lines."""
    cmd = [str(FDPI_COMPARE), str(pcap_path)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=120, errors="replace")
    except subprocess.TimeoutExpired:
        print(f"  TIMEOUT: fdpi_compare on {pcap_path.name}",
              file=sys.stderr)
        return None

    if result.returncode == 2:
        # Unsupported link layer (e.g., 802.11)
        return "UNSUPPORTED_LINK_LAYER"

    if result.returncode != 0:
        stderr = result.stderr.strip()
        print(f"  WARN: fdpi_compare returned {result.returncode} for "
              f"{pcap_path.name}: {stderr}", file=sys.stderr)
        return None

    return result.stdout


def normalize_hex(val):
    """Normalize hex values: strip 0x prefix, leading zeros, lowercase."""
    val = val.strip().lower()
    if val.startswith("0x"):
        val = val[2:]
    # Strip leading zeros but keep at least one digit
    val = val.lstrip("0") or "0"
    return val


def normalize_dns_name(val):
    """Strip trailing dots from DNS names."""
    return val.rstrip(".")


def normalize_bool(val):
    """Normalize boolean values: True/False/1/0 → '1'/'0'."""
    v = val.strip().lower()
    if v in ("true", "1"):
        return "1"
    if v in ("false", "0"):
        return "0"
    return val.strip()


# Fields where tshark may leave empty but fdpi outputs "0"
# (e.g., response-only DNS flags on query packets)
ZERO_IF_EMPTY_FIELDS = {
    "dns.flags.response", "dns.flags.opcode", "dns.flags.rcode",
    "dns.flags.authoritative", "dns.flags.truncated",
    "dns.flags.recdesired", "dns.flags.recavail",
}

# Boolean fields that tshark outputs as True/False
BOOLEAN_FIELDS = {
    "dns.flags.response", "dns.flags.authoritative",
    "dns.flags.truncated", "dns.flags.recdesired",
    "dns.flags.recavail",
}


def normalize_value(field, val):
    """Normalize a field value for comparison."""
    val = val.strip()
    if not val:
        # For certain fields, treat empty as "0"
        if field in ZERO_IF_EMPTY_FIELDS:
            return "0"
        return ""

    # Boolean fields: True/False → 1/0
    if field in BOOLEAN_FIELDS:
        return normalize_bool(val)

    # Hex fields: compare as integer
    hex_fields = {
        "eth.type", "ip.id", "ip.flags", "ip.checksum",
        "tcp.flags", "tcp.checksum", "udp.checksum",
        "icmp.checksum", "icmpv6.checksum",
        "tls.record.version", "ipv6.tclass", "ipv6.flow",
        "arp.proto.type", "dhcp.id", "dhcp.flags",
        "dhcp.hw.type", "dhcpv6.xid",
        "stun.type", "stun.cookie",
        "dtls.record.version",
        "rtcp.senderssrc",
        "homeplug_av.mmhdr.mmtype.qualcomm",
    }
    if field in hex_fields:
        return normalize_hex(val)

    # Telnet data: tshark includes \r\n and splits lines with commas;
    # fdpi strips control chars and concatenates. Normalize by removing
    # \r\n escape sequences and commas used as line separators.
    if field == "telnet.data":
        # tshark outputs literal backslash-r backslash-n sequences
        normalized = val.replace("\\r\\n", "").replace("\\r", "")
        # tshark separates multiple data segments with commas
        normalized = normalized.replace(",", "")
        return normalized

    # DNS names: strip trailing dots
    if field in ("dns.qry.name",):
        return normalize_dns_name(val)

    # MAC addresses: lowercase
    if field in ("eth.src", "eth.dst", "arp.src.hw_mac", "arp.dst.hw_mac",
                 "dhcp.hw.mac_addr", "lldp.chassis.id.mac",
                 "lldp.port.id.mac"):
        return val.lower()

    # IPv6 addresses: lowercase
    if field in ("ipv6.src", "ipv6.dst"):
        return val.lower()

    # Connection IDs: lowercase hex comparison
    if field in ("quic.dcid", "quic.scid"):
        return val.lower().replace(":", "")

    return val


def parse_tsv(text):
    """Parse TSV text into list of dicts (field -> value)."""
    lines = text.strip().split("\n")
    if not lines:
        return []

    header = lines[0].split("\t")
    rows = []
    for line in lines[1:]:
        if not line.strip():
            continue
        values = line.split("\t")
        row = {}
        for i, col in enumerate(header):
            row[col] = values[i] if i < len(values) else ""
        rows.append(row)
    return rows


def compare_pcap(pcap_path, verbose=False):
    """Compare fdpi output against tshark baseline for a single PCAP."""
    bl_path = baseline_path(pcap_path)
    if not bl_path.exists():
        return {"status": "no_baseline", "file": pcap_path.name}

    # Read tshark baseline
    with open(bl_path) as f:
        tshark_text = f.read()
    tshark_rows = parse_tsv(tshark_text)

    if not tshark_rows:
        return {"status": "empty_baseline", "file": pcap_path.name}

    # Run fdpi_compare
    fdpi_text = run_fdpi_compare(pcap_path)
    if fdpi_text is None:
        return {"status": "fdpi_error", "file": pcap_path.name}
    if fdpi_text == "UNSUPPORTED_LINK_LAYER":
        return {"status": "unsupported_link_layer", "file": pcap_path.name}

    fdpi_rows = parse_tsv(fdpi_text)

    # Build frame.number → row dicts for alignment
    tshark_by_frame = {}
    for row in tshark_rows:
        fn = row.get("frame.number", "").strip()
        if fn:
            tshark_by_frame[fn] = row

    fdpi_by_frame = {}
    for row in fdpi_rows:
        fn = row.get("frame.number", "").strip()
        if fn:
            fdpi_by_frame[fn] = row

    # Find shared frame numbers (preserve order from tshark)
    shared_frames = [fn for fn in tshark_by_frame if fn in fdpi_by_frame]
    fdpi_only = set(fdpi_by_frame) - set(tshark_by_frame)
    tshark_only = set(tshark_by_frame) - set(fdpi_by_frame)

    # Compare only shared frames
    total_fields = 0
    matches = 0
    mismatches = []
    field_stats = defaultdict(lambda: {"match": 0, "mismatch": 0, "total": 0})

    for fn in shared_frames:
        trow = tshark_by_frame[fn]
        frow = fdpi_by_frame[fn]

        for col in COLUMNS:
            tval = trow.get(col, "")
            fval = frow.get(col, "")

            tnorm = normalize_value(col, tval)
            fnorm = normalize_value(col, fval)

            # Skip comparison if both are empty (absent layer)
            if not tnorm and not fnorm:
                continue

            # tshark reports ip.version=6 on IPv6 packets; fdpi correctly
            # leaves ip.version empty and uses ipv6.version instead. Skip
            # ip.version when ipv6.version is present on either side.
            if col == "ip.version":
                tv6 = normalize_value("ipv6.version",
                                      trow.get("ipv6.version", ""))
                fv6 = normalize_value("ipv6.version",
                                      frow.get("ipv6.version", ""))
                if tv6 or fv6:
                    continue

            total_fields += 1
            field_stats[col]["total"] += 1

            # Multi-value normalization: tshark may report comma-separated
            # values for encapsulated protocols (e.g., "17,6" for outer UDP +
            # inner TCP). fdpi only reports the outer value. Compare against
            # the first comma-delimited element from tshark.
            if tnorm != fnorm and ',' in tval and ',' not in fval:
                tnorm = normalize_value(col, tval.split(',')[0].strip())

            if tnorm == fnorm:
                matches += 1
                field_stats[col]["match"] += 1
            else:
                field_stats[col]["mismatch"] += 1
                mismatches.append({
                    "packet": int(fn),
                    "field": col,
                    "fdpi": fval.strip(),
                    "tshark": tval.strip(),
                })

    return {
        "status": "compared",
        "file": pcap_path.name,
        "packets_matched": len(shared_frames),
        "fdpi_only_packets": len(fdpi_only),
        "tshark_only_packets": len(tshark_only),
        "total_fields": total_fields,
        "matches": matches,
        "mismatches": mismatches,
        "field_stats": dict(field_stats),
    }


def cmd_generate(args):
    """Generate tshark baselines."""
    check_tshark()

    if args.pcap:
        pcaps = [Path(args.pcap).resolve()]
    else:
        pcaps = scan_pcaps(include_large=args.include_large)

    print(f"Generating tshark baselines for {len(pcaps)} PCAPs...")
    success = 0
    for pcap in pcaps:
        print(f"  {pcap.name}...", end=" ", flush=True)
        if generate_baseline(pcap):
            print("OK")
            success += 1
        else:
            print("SKIPPED")

    print(f"\nGenerated {success}/{len(pcaps)} baselines in {BASELINES_DIR}")


def cmd_compare(args):
    """Run comparison."""
    check_fdpi_compare()

    if args.pcap:
        pcaps = [Path(args.pcap).resolve()]
    else:
        pcaps = scan_pcaps(include_large=args.include_large)

    results = []
    for pcap in pcaps:
        result = compare_pcap(pcap, verbose=args.verbose)
        results.append(result)

    # Per-file report
    overall_fields = 0
    overall_matches = 0
    overall_field_stats = defaultdict(
        lambda: {"match": 0, "mismatch": 0, "total": 0})
    files_compared = 0
    files_skipped = 0

    for r in results:
        if r["status"] != "compared":
            files_skipped += 1
            print(f"\n=== {r['file']} === [{r['status']}]")
            continue

        files_compared += 1
        overall_fields += r["total_fields"]
        overall_matches += r["matches"]

        for col, stats in r["field_stats"].items():
            overall_field_stats[col]["match"] += stats["match"]
            overall_field_stats[col]["mismatch"] += stats["mismatch"]
            overall_field_stats[col]["total"] += stats["total"]

        pct = (r["matches"] / r["total_fields"] * 100
               if r["total_fields"] > 0 else 100.0)
        n_mismatch = len(r["mismatches"])

        print(f"\n=== {r['file']} ===")
        print(f"Packets: {r['packets_matched']} matched"
              f", {r['fdpi_only_packets']} fdpi-only"
              f", {r['tshark_only_packets']} tshark-only")
        print(f"Fields compared: {r['total_fields']}")
        print(f"Matches: {r['matches']} ({pct:.1f}%)")
        print(f"Mismatches: {n_mismatch}")

        if args.verbose and r["mismatches"]:
            for m in r["mismatches"]:
                print(f"  Packet {m['packet']}, {m['field']}: "
                      f"fdpi=\"{m['fdpi']}\" tshark=\"{m['tshark']}\"")

    # Summary
    print("\n" + "=" * 60)
    print("=== SUMMARY ===")
    print(f"Files: {len(results)} total, {files_compared} compared, "
          f"{files_skipped} skipped")

    if overall_fields > 0:
        overall_pct = overall_matches / overall_fields * 100
        print(f"Overall match rate: {overall_pct:.1f}% "
              f"({overall_matches}/{overall_fields})")

        # Per-field match rates (sorted by match rate ascending)
        print("\nPer-field match rates:")
        field_rates = []
        for col in COLUMNS:
            stats = overall_field_stats.get(col)
            if stats and stats["total"] > 0:
                rate = stats["match"] / stats["total"] * 100
                field_rates.append((col, rate, stats["total"],
                                    stats["mismatch"]))

        field_rates.sort(key=lambda x: x[1])
        for col, rate, total, mismatches in field_rates:
            marker = " *" if mismatches > 0 else ""
            print(f"  {col:45s} {rate:6.1f}%  "
                  f"({total} compared, {mismatches} mismatches){marker}")
    else:
        print("No fields compared.")


def cmd_full(args):
    """Generate baselines then compare."""
    cmd_generate(args)
    print("\n" + "=" * 60)
    print("Running comparison...\n")
    cmd_compare(args)


def main():
    parser = argparse.ArgumentParser(
        description="Compare fdpi output against tshark")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate
    gen_parser = subparsers.add_parser(
        "generate", help="Generate tshark baselines")
    gen_parser.add_argument("--pcap", help="Single PCAP file")
    gen_parser.add_argument("--include-large", action="store_true",
                            help="Include PCAPs > 10MB")

    # compare
    cmp_parser = subparsers.add_parser(
        "compare", help="Compare fdpi vs tshark")
    cmp_parser.add_argument("--pcap", help="Single PCAP file")
    cmp_parser.add_argument("--verbose", "-v", action="store_true",
                            help="Show every mismatch")
    cmp_parser.add_argument("--include-large", action="store_true",
                            help="Include PCAPs > 10MB")

    # full
    full_parser = subparsers.add_parser(
        "full", help="Generate baselines then compare")
    full_parser.add_argument("--pcap", help="Single PCAP file")
    full_parser.add_argument("--verbose", "-v", action="store_true",
                             help="Show every mismatch")
    full_parser.add_argument("--include-large", action="store_true",
                             help="Include PCAPs > 10MB")

    args = parser.parse_args()

    if args.command == "generate":
        cmd_generate(args)
    elif args.command == "compare":
        cmd_compare(args)
    elif args.command == "full":
        cmd_full(args)


if __name__ == "__main__":
    main()
