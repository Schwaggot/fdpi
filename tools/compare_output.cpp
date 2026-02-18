#include <fdpi/fdpi.hpp>
#include <fpcap/fpcap.hpp>

#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {

// Column names matching tshark -e field names
const std::vector<std::string> COLUMNS = {
    // Frame
    "frame.number",
    "frame.len",
    "frame.cap_len",
    // Ethernet
    "eth.src",
    "eth.dst",
    "eth.type",
    // IPv4
    "ip.version",
    "ip.hdr_len",
    "ip.dsfield.dscp",
    "ip.dsfield.ecn",
    "ip.len",
    "ip.id",
    "ip.flags",
    "ip.frag_offset",
    "ip.ttl",
    "ip.proto",
    "ip.checksum",
    "ip.src",
    "ip.dst",
    // IPv6
    "ipv6.version",
    "ipv6.tclass",
    "ipv6.flow",
    "ipv6.plen",
    "ipv6.nxt",
    "ipv6.hlim",
    "ipv6.src",
    "ipv6.dst",
    // ARP
    "arp.hw.type",
    "arp.proto.type",
    "arp.hw.size",
    "arp.proto.size",
    "arp.opcode",
    "arp.src.hw_mac",
    "arp.src.proto_ipv4",
    "arp.dst.hw_mac",
    "arp.dst.proto_ipv4",
    // TCP
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.hdr_len",
    "tcp.flags",
    "tcp.window_size_value",
    "tcp.checksum",
    "tcp.urgent_pointer",
    // UDP
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "udp.checksum",
    // ICMP
    "icmp.type",
    "icmp.code",
    "icmp.checksum",
    // ICMPv6
    "icmpv6.type",
    "icmpv6.code",
    "icmpv6.checksum",
    // DNS
    "dns.id",
    "dns.flags.response",
    "dns.flags.opcode",
    "dns.flags.rcode",
    "dns.flags.authoritative",
    "dns.flags.truncated",
    "dns.flags.recdesired",
    "dns.flags.recavail",
    "dns.count.queries",
    "dns.count.answers",
    "dns.qry.name",
    "dns.qry.type",
    // HTTP
    "http.request.method",
    "http.request.uri",
    "http.response.code",
    "http.request.version",
    // TLS
    "tls.record.content_type",
    "tls.record.version",
    "tls.handshake.extensions_server_name",
    // QUIC
    "quic.long.packet_type",
    "quic.version",
    "quic.dcid",
    "quic.scid",
    // FTP
    "ftp.request.command",
    "ftp.request.arg",
    "ftp.response.code",
    "ftp.response.arg",
    // SSH
    "ssh.protocol",
    // DHCP
    "dhcp.type",
    "dhcp.hw.type",
    "dhcp.hw.len",
    "dhcp.hops",
    "dhcp.id",
    "dhcp.secs",
    "dhcp.flags",
    "dhcp.ip.client",
    "dhcp.ip.your",
    "dhcp.ip.server",
    "dhcp.ip.relay",
    "dhcp.hw.mac_addr",
    "dhcp.option.dhcp",
    // DHCPv6
    "dhcpv6.msgtype",
    "dhcpv6.xid",
    // SMTP
    "smtp.req.command",
    "smtp.req.parameter",
    "smtp.response.code",
    // POP
    "pop.request.command",
    "pop.request.parameter",
    "pop.response.indicator",
    // IMAP
    "imap.request_tag",
    "imap.request.command",
    // SNMP
    "snmp.version",
    "snmp.msgVersion",
    "snmp.community",
    // NTP
    "ntp.flags.li",
    "ntp.flags.vn",
    "ntp.flags.mode",
    "ntp.stratum",
    // BGP
    "bgp.type",
    // LDAP
    "ldap.messageID",
    // RDP/TPKT
    "tpkt.version",
    "tpkt.length",
    // Telnet
    "telnet.cmd",
    "telnet.data",
    // TFTP
    "tftp.opcode",
    "tftp.source_file",
    "tftp.destination_file",
    "tftp.type",
    "tftp.block",
    "tftp.error.code",
    "tftp.error.message",
    // STUN
    "stun.type",
    "stun.length",
    "stun.cookie",
    // DTLS
    "dtls.record.content_type",
    "dtls.record.version",
    "dtls.record.epoch",
    "dtls.record.length",
    // RTCP
    "rtcp.pt",
    "rtcp.length",
    "rtcp.senderssrc",
    // LLDP
    "lldp.chassis.id.mac",
    "lldp.port.id.mac",
    "lldp.time_to_live",
    // HomePlug-AV
    "homeplug_av.mmhdr.mmtype.qualcomm",
};

// Column index lookup helpers
size_t colIndex(const std::string& name) {
    for (size_t i = 0; i < COLUMNS.size(); ++i) {
        if (COLUMNS[i] == name)
            return i;
    }
    return COLUMNS.size(); // should never happen
}

// Formatting helpers
std::string hex8(uint8_t val) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%02x", val);
    return buf;
}

std::string hex16(uint16_t val) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%04x", val);
    return buf;
}

std::string hex32(uint32_t val) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%08x", val);
    return buf;
}

std::string hexBytes(const std::vector<uint8_t>& data) {
    std::string result;
    for (auto b : data) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02x", b);
        result += buf;
    }
    return result;
}

std::string decStr(auto val) {
    return std::to_string(val);
}

using Row = std::vector<std::string>;

void setFrame(Row& row, uint32_t number, uint32_t wireLen, uint32_t capLen) {
    row[colIndex("frame.number")] = decStr(number);
    row[colIndex("frame.len")] = decStr(wireLen);
    row[colIndex("frame.cap_len")] = decStr(capLen);
}

void setEthernet(Row& row, const fdpi::Ethernet& eth) {
    row[colIndex("eth.src")] = eth.src.toString();
    row[colIndex("eth.dst")] = eth.dst.toString();
    row[colIndex("eth.type")] = hex16(eth.etherType);
}

void setIPv4(Row& row, const fdpi::IPv4& ip) {
    row[colIndex("ip.version")] = decStr(ip.version);
    row[colIndex("ip.hdr_len")] = decStr(static_cast<int>(ip.ihl) * 4);
    row[colIndex("ip.dsfield.dscp")] = decStr(ip.dscp);
    row[colIndex("ip.dsfield.ecn")] = decStr(ip.ecn);
    row[colIndex("ip.len")] = decStr(ip.totalLength);
    row[colIndex("ip.id")] = hex16(ip.identification);
    row[colIndex("ip.flags")] = hex8(ip.flags);
    row[colIndex("ip.frag_offset")] = decStr(ip.fragmentOffset);
    row[colIndex("ip.ttl")] = decStr(ip.ttl);
    row[colIndex("ip.proto")] = decStr(ip.protocol);
    row[colIndex("ip.checksum")] = hex16(ip.checksum);
    row[colIndex("ip.src")] = ip.srcIp.toString();
    row[colIndex("ip.dst")] = ip.dstIp.toString();
}

void setIPv6(Row& row, const fdpi::IPv6& ip) {
    row[colIndex("ipv6.version")] = decStr(ip.version);
    row[colIndex("ipv6.tclass")] = hex8(ip.trafficClass);
    row[colIndex("ipv6.flow")] = hex32(ip.flowLabel);
    row[colIndex("ipv6.plen")] = decStr(ip.payloadLength);
    row[colIndex("ipv6.nxt")] = decStr(ip.nextHeader);
    row[colIndex("ipv6.hlim")] = decStr(ip.hopLimit);
    row[colIndex("ipv6.src")] = ip.srcIp.toString();
    row[colIndex("ipv6.dst")] = ip.dstIp.toString();
}

void setARP(Row& row, const fdpi::ARP& arp) {
    row[colIndex("arp.hw.type")] = decStr(arp.hardwareType);
    row[colIndex("arp.proto.type")] = hex16(arp.protocolType);
    row[colIndex("arp.hw.size")] = decStr(arp.hardwareSize);
    row[colIndex("arp.proto.size")] = decStr(arp.protocolSize);
    row[colIndex("arp.opcode")] = decStr(arp.opcode);
    row[colIndex("arp.src.hw_mac")] = arp.senderMac.toString();
    row[colIndex("arp.src.proto_ipv4")] = arp.senderIp.toString();
    row[colIndex("arp.dst.hw_mac")] = arp.targetMac.toString();
    row[colIndex("arp.dst.proto_ipv4")] = arp.targetIp.toString();
}

void setTCP(Row& row, const fdpi::TCP& tcp) {
    row[colIndex("tcp.srcport")] = decStr(tcp.srcPort);
    row[colIndex("tcp.dstport")] = decStr(tcp.dstPort);
    row[colIndex("tcp.seq_raw")] = decStr(tcp.seqNum);
    row[colIndex("tcp.ack_raw")] = decStr(tcp.ackNum);
    row[colIndex("tcp.hdr_len")] = decStr(static_cast<int>(tcp.dataOffset) * 4);
    row[colIndex("tcp.flags")] = hex16(static_cast<uint16_t>(tcp.flags));
    row[colIndex("tcp.window_size_value")] = decStr(tcp.window);
    row[colIndex("tcp.checksum")] = hex16(tcp.checksum);
    row[colIndex("tcp.urgent_pointer")] = decStr(tcp.urgentPointer);
}

void setUDP(Row& row, const fdpi::UDP& udp) {
    row[colIndex("udp.srcport")] = decStr(udp.srcPort);
    row[colIndex("udp.dstport")] = decStr(udp.dstPort);
    row[colIndex("udp.length")] = decStr(udp.length);
    row[colIndex("udp.checksum")] = hex16(udp.checksum);
}

void setICMP(Row& row, const fdpi::ICMP& icmp) {
    row[colIndex("icmp.type")] = decStr(icmp.type);
    row[colIndex("icmp.code")] = decStr(icmp.code);
    row[colIndex("icmp.checksum")] = hex16(icmp.checksum);
    if (icmp.embedded && icmp.embedded->protocol == 17) {
        row[colIndex("udp.srcport")] = decStr(icmp.embedded->srcPort);
        row[colIndex("udp.dstport")] = decStr(icmp.embedded->dstPort);
        row[colIndex("udp.length")] = decStr(icmp.embedded->udpLength);
        row[colIndex("udp.checksum")] = hex16(icmp.embedded->udpChecksum);
    }
}

void setICMPv6(Row& row, const fdpi::ICMPv6& icmp) {
    row[colIndex("icmpv6.type")] = decStr(icmp.type);
    row[colIndex("icmpv6.code")] = decStr(icmp.code);
    row[colIndex("icmpv6.checksum")] = hex16(icmp.checksum);
    if (icmp.embedded && icmp.embedded->nextHeader == 17) {
        row[colIndex("udp.srcport")] = decStr(icmp.embedded->srcPort);
        row[colIndex("udp.dstport")] = decStr(icmp.embedded->dstPort);
        row[colIndex("udp.length")] = decStr(icmp.embedded->udpLength);
        row[colIndex("udp.checksum")] = hex16(icmp.embedded->udpChecksum);
    }
}

void setDNS(Row& row, const fdpi::DNS& dns) {
    row[colIndex("dns.id")] = hex16(dns.id);
    row[colIndex("dns.flags.response")] = dns.isResponse ? "1" : "0";
    row[colIndex("dns.flags.opcode")] = decStr(dns.opcode);
    row[colIndex("dns.flags.rcode")] = decStr(dns.rcode);
    row[colIndex("dns.flags.authoritative")] = dns.authoritative ? "1" : "0";
    row[colIndex("dns.flags.truncated")] = dns.truncated ? "1" : "0";
    row[colIndex("dns.flags.recdesired")] = dns.recursionDesired ? "1" : "0";
    row[colIndex("dns.flags.recavail")] = dns.recursionAvailable ? "1" : "0";
    row[colIndex("dns.count.queries")] = decStr(dns.questions.size());
    row[colIndex("dns.count.answers")] = decStr(dns.answers.size());
    // Join multiple query names/types with comma
    std::string names, types;
    for (size_t i = 0; i < dns.questions.size(); ++i) {
        if (i > 0) {
            names += ",";
            types += ",";
        }
        names += dns.questions[i].name;
        types += decStr(dns.questions[i].type);
    }
    row[colIndex("dns.qry.name")] = names;
    row[colIndex("dns.qry.type")] = types;
}

void setHTTP(Row& row, const fdpi::HTTP& http) {
    // tshark formats version as "HTTP/1.1", fdpi stores just "1.1"
    std::string ver = http.version;
    if (!ver.empty() && ver.find("HTTP/") == std::string::npos) {
        ver = "HTTP/" + ver;
    }
    if (http.isRequest) {
        row[colIndex("http.request.method")] = http.method;
        row[colIndex("http.request.uri")] = http.uri;
        row[colIndex("http.request.version")] = ver;
    } else {
        row[colIndex("http.response.code")] = decStr(http.statusCode);
        row[colIndex("http.request.version")] = ver;
    }
}

void setTLS(Row& row, const fdpi::TLS& tls) {
    row[colIndex("tls.record.content_type")] = decStr(tls.contentType);
    row[colIndex("tls.record.version")] = hex16(tls.version);
    if (tls.sni) {
        row[colIndex("tls.handshake.extensions_server_name")] = *tls.sni;
    }
}

void setQUIC(Row& row, const fdpi::QUIC& quic) {
    row[colIndex("quic.long.packet_type")] = decStr(quic.packetType);
    row[colIndex("quic.version")] = decStr(quic.version);
    row[colIndex("quic.dcid")] = hexBytes(quic.dcid);
    row[colIndex("quic.scid")] = hexBytes(quic.scid);
}

void setFTP(Row& row, const fdpi::FTP& ftp) {
    if (!ftp.isResponse) {
        row[colIndex("ftp.request.command")] = ftp.command;
        row[colIndex("ftp.request.arg")] = ftp.argument;
    } else {
        row[colIndex("ftp.response.code")] = decStr(ftp.replyCode);
        row[colIndex("ftp.response.arg")] = ftp.replyText;
    }
}

void setSSH(Row& row, const fdpi::SSH& ssh) {
    row[colIndex("ssh.protocol")] = ssh.protocolVersion;
}

void setDHCP(Row& row, const fdpi::DHCP& dhcp) {
    row[colIndex("dhcp.type")] = decStr(dhcp.op);
    row[colIndex("dhcp.hw.type")] = decStr(dhcp.htype);
    row[colIndex("dhcp.hw.len")] = decStr(dhcp.hlen);
    row[colIndex("dhcp.hops")] = decStr(dhcp.hops);
    row[colIndex("dhcp.id")] = hex32(dhcp.xid);
    row[colIndex("dhcp.secs")] = decStr(dhcp.secs);
    row[colIndex("dhcp.flags")] = hex16(dhcp.flags);
    row[colIndex("dhcp.ip.client")] = dhcp.ciaddr.toString();
    row[colIndex("dhcp.ip.your")] = dhcp.yiaddr.toString();
    row[colIndex("dhcp.ip.server")] = dhcp.siaddr.toString();
    row[colIndex("dhcp.ip.relay")] = dhcp.giaddr.toString();
    row[colIndex("dhcp.hw.mac_addr")] = dhcp.chaddr.toString();
    if (dhcp.messageType) {
        row[colIndex("dhcp.option.dhcp")] = decStr(*dhcp.messageType);
    }
}

void setDHCPv6(Row& row, const fdpi::DHCPv6& dhcp) {
    row[colIndex("dhcpv6.msgtype")] = decStr(dhcp.messageType);
    row[colIndex("dhcpv6.xid")] = decStr(dhcp.transactionId);
}

void setSMTP(Row& row, const fdpi::SMTP& smtp) {
    if (!smtp.isResponse) {
        row[colIndex("smtp.req.command")] = smtp.command;
        row[colIndex("smtp.req.parameter")] = smtp.argument;
    } else {
        row[colIndex("smtp.response.code")] = decStr(smtp.replyCode);
    }
}

void setPOP3(Row& row, const fdpi::POP3& pop3) {
    if (!pop3.isResponse) {
        row[colIndex("pop.request.command")] = pop3.command;
        row[colIndex("pop.request.parameter")] = pop3.argument;
    } else {
        row[colIndex("pop.response.indicator")] = pop3.success ? "+OK" : "-ERR";
    }
}

void setIMAP(Row& row, const fdpi::IMAP& imap) {
    if (!imap.isResponse) {
        row[colIndex("imap.request_tag")] = imap.tag;
        row[colIndex("imap.request.command")] = imap.command;
    }
}

void setSNMP(Row& row, const fdpi::SNMP& snmp) {
    // tshark uses snmp.version for v1/v2c but snmp.msgVersion for v3
    if (snmp.version <= 1) {
        row[colIndex("snmp.version")] = decStr(snmp.version);
    } else {
        row[colIndex("snmp.msgVersion")] = decStr(snmp.version);
    }
    if (snmp.community) {
        row[colIndex("snmp.community")] = *snmp.community;
    }
}

void setNTP(Row& row, const fdpi::NTP& ntp) {
    row[colIndex("ntp.flags.li")] = decStr(ntp.leapIndicator);
    row[colIndex("ntp.flags.vn")] = decStr(ntp.version);
    row[colIndex("ntp.flags.mode")] = decStr(ntp.mode);
    row[colIndex("ntp.stratum")] = decStr(ntp.stratum);
}

void setBGP(Row& row, const fdpi::BGP& bgp) {
    row[colIndex("bgp.type")] = decStr(bgp.type);
}

void setLDAP(Row& row, const fdpi::LDAP& ldap) {
    row[colIndex("ldap.messageID")] = decStr(ldap.messageId);
}

void setRDP(Row& row, const fdpi::RDP& rdp) {
    row[colIndex("tpkt.version")] = decStr(rdp.tpktVersion);
    row[colIndex("tpkt.length")] = decStr(rdp.tpktLength);
}

void setSTUN(Row& row, const fdpi::STUN& stun) {
    row[colIndex("stun.type")] = hex16(stun.type);
    row[colIndex("stun.length")] = decStr(stun.length);
    row[colIndex("stun.cookie")] = hex32(stun.magicCookie);
}

void setTelnet(Row& row, const fdpi::Telnet& telnet) {
    if (!telnet.commands.empty()) {
        // Report first command byte (matches tshark telnet.cmd)
        row[colIndex("telnet.cmd")] = decStr(telnet.commands[0].command);
    }
    if (!telnet.data.empty()) {
        row[colIndex("telnet.data")] = telnet.data;
    }
}

void setTFTP(Row& row, const fdpi::TFTP& tftp) {
    row[colIndex("tftp.opcode")] = decStr(tftp.opcode);
    // tshark uses tftp.type for the opcode text, we output the numeric opcode
    row[colIndex("tftp.type")] = decStr(tftp.opcode);
    if (tftp.opcode == 1) { // RRQ
        row[colIndex("tftp.source_file")] = tftp.filename;
    } else if (tftp.opcode == 2) { // WRQ
        row[colIndex("tftp.destination_file")] = tftp.filename;
    } else if (tftp.opcode == 3 || tftp.opcode == 4) { // DATA or ACK
        row[colIndex("tftp.block")] = decStr(tftp.blockNumber);
    } else if (tftp.opcode == 5) { // ERROR
        row[colIndex("tftp.error.code")] = decStr(tftp.errorCode);
        row[colIndex("tftp.error.message")] = tftp.errorMessage;
    }
}

void setDTLS(Row& row, const fdpi::DTLS& dtls) {
    row[colIndex("dtls.record.content_type")] = decStr(dtls.contentType);
    row[colIndex("dtls.record.version")] = hex16(dtls.version);
    row[colIndex("dtls.record.epoch")] = decStr(dtls.epoch);
    row[colIndex("dtls.record.length")] = decStr(dtls.length);
}

void setRTCP(Row& row, const fdpi::RTCP& rtcp) {
    row[colIndex("rtcp.pt")] = decStr(rtcp.packetType);
    row[colIndex("rtcp.length")] = decStr(rtcp.length);
    row[colIndex("rtcp.senderssrc")] = hex32(rtcp.ssrc);
}

void setLLDP(Row& row, const fdpi::LLDP& lldp) {
    row[colIndex("lldp.chassis.id.mac")] = lldp.chassisId;
    row[colIndex("lldp.port.id.mac")] = lldp.portId;
    row[colIndex("lldp.time_to_live")] = decStr(lldp.ttl);
}

void setHomePlug(Row& row, const fdpi::HomePlug& hp) {
    row[colIndex("homeplug_av.mmhdr.mmtype.qualcomm")] = hex16(hp.type);
}

void setLayer3(Row& row, const decltype(fdpi::Packet::layer3)& l3) {
    std::visit(
        [&row](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, fdpi::IPv4>) {
                setIPv4(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::IPv6>) {
                setIPv6(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::ARP>) {
                setARP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::LLDP>) {
                setLLDP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::HomePlug>) {
                setHomePlug(row, v);
            }
            // RARP, EAPOL: no tshark fields defined, skip
        },
        l3);
}

void setLayer4(Row& row, const decltype(fdpi::Packet::layer4)& l4) {
    std::visit(
        [&row](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, fdpi::TCP>) {
                setTCP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::UDP>) {
                setUDP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::ICMP>) {
                setICMP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::ICMPv6>) {
                setICMPv6(row, v);
            }
        },
        l4);
}

void setLayer7(Row& row, const decltype(fdpi::Packet::layer7)& l7) {
    std::visit(
        [&row](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, fdpi::DNS>) {
                setDNS(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::HTTP>) {
                setHTTP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::TLS>) {
                setTLS(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::QUIC>) {
                setQUIC(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::FTP>) {
                setFTP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::SSH>) {
                setSSH(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::DHCP>) {
                setDHCP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::DHCPv6>) {
                setDHCPv6(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::SMTP>) {
                setSMTP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::POP3>) {
                setPOP3(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::IMAP>) {
                setIMAP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::SNMP>) {
                setSNMP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::RDP>) {
                setRDP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::BGP>) {
                setBGP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::NTP>) {
                setNTP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::LDAP>) {
                setLDAP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::STUN>) {
                setSTUN(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::Telnet>) {
                setTelnet(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::TFTP>) {
                setTFTP(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::DTLS>) {
                setDTLS(row, v);
            } else if constexpr (std::is_same_v<T, fdpi::RTCP>) {
                setRTCP(row, v);
            }
        },
        l7);
}

std::string sanitize(const std::string& val) {
    std::string result;
    result.reserve(val.size());
    for (const char c : val) {
        if (c == '\t' || c == '\n' || c == '\r') {
            result += ' ';
        } else {
            result += c;
        }
    }
    return result;
}

void printRow(const Row& row) {
    for (size_t i = 0; i < row.size(); ++i) {
        if (i > 0)
            std::cout << '\t';
        std::cout << sanitize(row[i]);
    }
    std::cout << '\n';
}

void printHeader() {
    for (size_t i = 0; i < COLUMNS.size(); ++i) {
        if (i > 0)
            std::cout << '\t';
        std::cout << COLUMNS[i];
    }
    std::cout << '\n';
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: fdpi_compare <pcap_file>\n";
        return 1;
    }

    std::string pcapPath = argv[1];
    if (!std::filesystem::exists(pcapPath)) {
        std::cerr << "Error: file not found: " << pcapPath << "\n";
        return 1;
    }

    fdpi::PacketDecoderConfig config;
    config.enableDefragmentation = false;
    config.enableTcpReassembly = false;
    config.enableProtocolDetection = true;
    fdpi::PacketDecoder decoder(config);

    printHeader();

    uint32_t frameNum = 0;
    fpcap::PacketReader reader(pcapPath);
    for (const auto& fpkt : reader) {
        ++frameNum;

        auto result = decoder.decode(fpkt);
        if (!result) {
            // Output a row with just frame info and an error marker
            Row row(COLUMNS.size());
            setFrame(row, frameNum, fpkt.length, fpkt.captureLength);
            printRow(row);
            continue;
        }

        const auto& pkt = result.value();
        Row row(COLUMNS.size());

        setFrame(row, frameNum, pkt.wireLength, pkt.captureLength);

        if (pkt.ethernet) {
            setEthernet(row, *pkt.ethernet);
        }

        setLayer3(row, pkt.layer3);
        setLayer4(row, pkt.layer4);
        setLayer7(row, pkt.layer7);

        printRow(row);
    }

    return 0;
}
