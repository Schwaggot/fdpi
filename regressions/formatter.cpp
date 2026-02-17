#include "formatter.hpp"

#include <cstdio>
#include <sstream>
#include <variant>

namespace regression {

namespace {

std::string hex8(const uint8_t val) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%02x", val);
    return buf;
}

std::string hex16(const uint16_t val) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%04x", val);
    return buf;
}

std::string hex32(const uint32_t val) {
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

std::string ipStr(const fdpi::IpAddress& addr) {
    return std::visit([](const auto& a) { return a.toString(); }, addr);
}

// --- Link layer ---

void formatEthernet(std::ostringstream& ss, const fdpi::Ethernet& eth) {
    ss << "ethernet.src=" << eth.src.toString() << "\n";
    ss << "ethernet.dst=" << eth.dst.toString() << "\n";
    ss << "ethernet.etherType=" << hex16(eth.etherType) << "\n";
}

void formatWifi(std::ostringstream& ss, const fdpi::WiFi& wifi) {
    ss << "wifi.type=" << static_cast<int>(wifi.type) << "\n";
    ss << "wifi.subtype=" << static_cast<int>(wifi.subtype) << "\n";
    ss << "wifi.toDS=" << (wifi.toDS ? "true" : "false") << "\n";
    ss << "wifi.fromDS=" << (wifi.fromDS ? "true" : "false") << "\n";
    ss << "wifi.protectedFrame=" << (wifi.protectedFrame ? "true" : "false") << "\n";
    ss << "wifi.retry=" << (wifi.retry ? "true" : "false") << "\n";
    ss << "wifi.durationId=" << wifi.durationId << "\n";
    ss << "wifi.addr1=" << wifi.addr1.toString() << "\n";
    if (wifi.addr2) {
        ss << "wifi.addr2=" << wifi.addr2->toString() << "\n";
    }
    if (wifi.addr3) {
        ss << "wifi.addr3=" << wifi.addr3->toString() << "\n";
    }
    if (wifi.addr4) {
        ss << "wifi.addr4=" << wifi.addr4->toString() << "\n";
    }
    ss << "wifi.sequenceControl=" << wifi.sequenceControl << "\n";
}

void formatVlan(std::ostringstream& ss, const fdpi::VlanTag& vlan) {
    ss << "vlan.id=" << vlan.vlanId() << "\n";
    ss << "vlan.priority=" << static_cast<int>(vlan.priority()) << "\n";
    ss << "vlan.etherType=" << hex16(vlan.etherType) << "\n";
}

// --- Layer 3 ---

void formatIPv4(std::ostringstream& ss, const fdpi::IPv4& ip) {
    ss << "layer3=IPv4\n";
    ss << "ipv4.version=" << static_cast<int>(ip.version) << "\n";
    ss << "ipv4.ihl=" << static_cast<int>(ip.ihl) << "\n";
    ss << "ipv4.dscp=" << static_cast<int>(ip.dscp) << "\n";
    ss << "ipv4.ecn=" << static_cast<int>(ip.ecn) << "\n";
    ss << "ipv4.totalLength=" << ip.totalLength << "\n";
    ss << "ipv4.id=" << ip.identification << "\n";
    ss << "ipv4.flags=" << hex8(ip.flags) << "\n";
    ss << "ipv4.fragmentOffset=" << ip.fragmentOffset << "\n";
    ss << "ipv4.ttl=" << static_cast<int>(ip.ttl) << "\n";
    ss << "ipv4.protocol=" << static_cast<int>(ip.protocol) << "\n";
    ss << "ipv4.checksum=" << hex16(ip.checksum) << "\n";
    ss << "ipv4.src=" << ip.srcIp.toString() << "\n";
    ss << "ipv4.dst=" << ip.dstIp.toString() << "\n";
}

void formatIPv6(std::ostringstream& ss, const fdpi::IPv6& ip) {
    ss << "layer3=IPv6\n";
    ss << "ipv6.version=" << static_cast<int>(ip.version) << "\n";
    ss << "ipv6.trafficClass=" << static_cast<int>(ip.trafficClass) << "\n";
    ss << "ipv6.flowLabel=" << ip.flowLabel << "\n";
    ss << "ipv6.payloadLength=" << ip.payloadLength << "\n";
    ss << "ipv6.nextHeader=" << static_cast<int>(ip.nextHeader) << "\n";
    ss << "ipv6.hopLimit=" << static_cast<int>(ip.hopLimit) << "\n";
    ss << "ipv6.src=" << ip.srcIp.toString() << "\n";
    ss << "ipv6.dst=" << ip.dstIp.toString() << "\n";
}

void formatARP(std::ostringstream& ss, const fdpi::ARP& arp) {
    ss << "layer3=ARP\n";
    ss << "arp.hardwareType=" << arp.hardwareType << "\n";
    ss << "arp.protocolType=" << hex16(arp.protocolType) << "\n";
    ss << "arp.hardwareSize=" << static_cast<int>(arp.hardwareSize) << "\n";
    ss << "arp.protocolSize=" << static_cast<int>(arp.protocolSize) << "\n";
    ss << "arp.opcode=" << arp.opcode << "\n";
    ss << "arp.senderMac=" << arp.senderMac.toString() << "\n";
    ss << "arp.senderIp=" << arp.senderIp.toString() << "\n";
    ss << "arp.targetMac=" << arp.targetMac.toString() << "\n";
    ss << "arp.targetIp=" << arp.targetIp.toString() << "\n";
}

void formatEAPOL(std::ostringstream& ss, const fdpi::EAPOL& eapol) {
    ss << "layer3=EAPOL\n";
    ss << "eapol.version=" << static_cast<int>(eapol.version) << "\n";
    ss << "eapol.type=" << static_cast<int>(eapol.type) << "\n";
    ss << "eapol.bodyLength=" << eapol.bodyLength << "\n";
    ss << "eapol.bodySize=" << eapol.body.size() << "\n";
}

void formatRARP(std::ostringstream& ss, const fdpi::RARP& rarp) {
    ss << "layer3=RARP\n";
    ss << "rarp.hardwareType=" << rarp.hardwareType << "\n";
    ss << "rarp.protocolType=" << hex16(rarp.protocolType) << "\n";
    ss << "rarp.hardwareSize=" << static_cast<int>(rarp.hardwareSize) << "\n";
    ss << "rarp.protocolSize=" << static_cast<int>(rarp.protocolSize) << "\n";
    ss << "rarp.opcode=" << rarp.opcode << "\n";
    ss << "rarp.senderMac=" << rarp.senderMac.toString() << "\n";
    ss << "rarp.senderIp=" << rarp.senderIp.toString() << "\n";
    ss << "rarp.targetMac=" << rarp.targetMac.toString() << "\n";
    ss << "rarp.targetIp=" << rarp.targetIp.toString() << "\n";
}

// --- Layer 4 ---

void formatTCP(std::ostringstream& ss, const fdpi::TCP& tcp) {
    ss << "layer4=TCP\n";
    ss << "tcp.srcPort=" << tcp.srcPort << "\n";
    ss << "tcp.dstPort=" << tcp.dstPort << "\n";
    ss << "tcp.seq=" << tcp.seqNum << "\n";
    ss << "tcp.ack=" << tcp.ackNum << "\n";
    ss << "tcp.dataOffset=" << static_cast<int>(tcp.dataOffset) << "\n";
    ss << "tcp.flags=" << hex8(tcp.flags) << "\n";
    ss << "tcp.window=" << tcp.window << "\n";
    ss << "tcp.checksum=" << hex16(tcp.checksum) << "\n";
    ss << "tcp.urgentPointer=" << tcp.urgentPointer << "\n";
}

void formatUDP(std::ostringstream& ss, const fdpi::UDP& udp) {
    ss << "layer4=UDP\n";
    ss << "udp.srcPort=" << udp.srcPort << "\n";
    ss << "udp.dstPort=" << udp.dstPort << "\n";
    ss << "udp.length=" << udp.length << "\n";
    ss << "udp.checksum=" << hex16(udp.checksum) << "\n";
}

void formatICMP(std::ostringstream& ss, const fdpi::ICMP& icmp) {
    ss << "layer4=ICMP\n";
    ss << "icmp.type=" << static_cast<int>(icmp.type) << "\n";
    ss << "icmp.code=" << static_cast<int>(icmp.code) << "\n";
    ss << "icmp.checksum=" << hex16(icmp.checksum) << "\n";
    ss << "icmp.restOfHeader=" << hex32(icmp.restOfHeader) << "\n";
}

void formatICMPv6(std::ostringstream& ss, const fdpi::ICMPv6& icmp) {
    ss << "layer4=ICMPv6\n";
    ss << "icmpv6.type=" << static_cast<int>(icmp.type) << "\n";
    ss << "icmpv6.code=" << static_cast<int>(icmp.code) << "\n";
    ss << "icmpv6.checksum=" << hex16(icmp.checksum) << "\n";
    ss << "icmpv6.restOfHeader=" << hex32(icmp.restOfHeader) << "\n";
}

void formatIGMP(std::ostringstream& ss, const fdpi::IGMP& igmp) {
    ss << "layer4=IGMP\n";
    ss << "igmp.type=" << hex8(igmp.type) << "\n";
    ss << "igmp.maxRespTime=" << static_cast<int>(igmp.maxRespTime) << "\n";
    ss << "igmp.checksum=" << hex16(igmp.checksum) << "\n";
    ss << "igmp.groupAddress=" << igmp.groupAddress.toString() << "\n";
}

void formatESP(std::ostringstream& ss, const fdpi::ESP& esp) {
    ss << "layer4=ESP\n";
    ss << "esp.spi=" << hex32(esp.spi) << "\n";
    ss << "esp.sequenceNumber=" << esp.sequenceNumber << "\n";
}

// --- Layer 7 ---

void formatDNS(std::ostringstream& ss, const fdpi::DNS& dns) {
    ss << "layer7=DNS\n";
    ss << "dns.id=" << hex16(dns.id) << "\n";
    ss << "dns.isResponse=" << (dns.isResponse ? "true" : "false") << "\n";
    ss << "dns.opcode=" << static_cast<int>(dns.opcode) << "\n";
    ss << "dns.rcode=" << static_cast<int>(dns.rcode) << "\n";
    ss << "dns.authoritative=" << (dns.authoritative ? "true" : "false") << "\n";
    ss << "dns.truncated=" << (dns.truncated ? "true" : "false") << "\n";
    ss << "dns.recursionDesired=" << (dns.recursionDesired ? "true" : "false") << "\n";
    ss << "dns.recursionAvailable=" << (dns.recursionAvailable ? "true" : "false")
       << "\n";
    ss << "dns.questions.count=" << dns.questions.size() << "\n";
    for (size_t i = 0; i < dns.questions.size(); ++i) {
        ss << "dns.questions[" << i << "].name=" << dns.questions[i].name << "\n";
        ss << "dns.questions[" << i << "].type=" << dns.questions[i].type << "\n";
        ss << "dns.questions[" << i << "].class=" << dns.questions[i].qclass << "\n";
    }
    ss << "dns.answers.count=" << dns.answers.size() << "\n";
    for (size_t i = 0; i < dns.answers.size(); ++i) {
        ss << "dns.answers[" << i << "].name=" << dns.answers[i].name << "\n";
        ss << "dns.answers[" << i << "].type=" << dns.answers[i].type << "\n";
        ss << "dns.answers[" << i << "].class=" << dns.answers[i].rclass << "\n";
        ss << "dns.answers[" << i << "].ttl=" << dns.answers[i].ttl << "\n";
        ss << "dns.answers[" << i << "].rdataSize=" << dns.answers[i].rdata.size()
           << "\n";
    }
    ss << "dns.authorities.count=" << dns.authorities.size() << "\n";
    for (size_t i = 0; i < dns.authorities.size(); ++i) {
        ss << "dns.authorities[" << i << "].name=" << dns.authorities[i].name << "\n";
        ss << "dns.authorities[" << i << "].type=" << dns.authorities[i].type << "\n";
        ss << "dns.authorities[" << i << "].class=" << dns.authorities[i].rclass << "\n";
        ss << "dns.authorities[" << i << "].ttl=" << dns.authorities[i].ttl << "\n";
        ss << "dns.authorities[" << i << "].rdataSize=" << dns.authorities[i].rdata.size()
           << "\n";
    }
    ss << "dns.additionals.count=" << dns.additionals.size() << "\n";
    for (size_t i = 0; i < dns.additionals.size(); ++i) {
        ss << "dns.additionals[" << i << "].name=" << dns.additionals[i].name << "\n";
        ss << "dns.additionals[" << i << "].type=" << dns.additionals[i].type << "\n";
        ss << "dns.additionals[" << i << "].class=" << dns.additionals[i].rclass << "\n";
        ss << "dns.additionals[" << i << "].ttl=" << dns.additionals[i].ttl << "\n";
        ss << "dns.additionals[" << i << "].rdataSize=" << dns.additionals[i].rdata.size()
           << "\n";
    }
}

void formatHTTP(std::ostringstream& ss, const fdpi::HTTP& http) {
    ss << "layer7=HTTP\n";
    ss << "http.isRequest=" << (http.isRequest ? "true" : "false") << "\n";
    ss << "http.method=" << http.method << "\n";
    ss << "http.uri=" << http.uri << "\n";
    ss << "http.statusCode=" << http.statusCode << "\n";
    ss << "http.version=" << http.version << "\n";
    ss << "http.headers.count=" << http.headers.size() << "\n";
    for (size_t i = 0; i < http.headers.size(); ++i) {
        ss << "http.headers[" << i << "].name=" << http.headers[i].first << "\n";
        ss << "http.headers[" << i << "].value=" << http.headers[i].second << "\n";
    }
}

void formatTLS(std::ostringstream& ss, const fdpi::TLS& tls) {
    ss << "layer7=TLS\n";
    ss << "tls.contentType=" << static_cast<int>(tls.contentType) << "\n";
    ss << "tls.version=" << hex16(tls.version) << "\n";
    if (tls.sni) {
        ss << "tls.sni=" << *tls.sni << "\n";
    }
    if (tls.alpn) {
        ss << "tls.alpn.count=" << tls.alpn->size() << "\n";
        for (size_t i = 0; i < tls.alpn->size(); ++i) {
            ss << "tls.alpn[" << i << "]=" << (*tls.alpn)[i] << "\n";
        }
    }
    if (tls.tlsVersion) {
        ss << "tls.tlsVersion=" << hex16(*tls.tlsVersion) << "\n";
    }
    ss << "tls.cipherSuites.count=" << tls.cipherSuites.size() << "\n";
    for (size_t i = 0; i < tls.cipherSuites.size(); ++i) {
        ss << "tls.cipherSuites[" << i << "]=" << hex16(tls.cipherSuites[i]) << "\n";
    }
}

void formatQUIC(std::ostringstream& ss, const fdpi::QUIC& quic) {
    ss << "layer7=QUIC\n";
    ss << "quic.isLongHeader=" << (quic.isLongHeader ? "true" : "false") << "\n";
    ss << "quic.version=" << static_cast<int>(quic.version) << "\n";
    ss << "quic.dcid=" << hexBytes(quic.dcid) << "\n";
    ss << "quic.scid=" << hexBytes(quic.scid) << "\n";
    ss << "quic.packetType=" << static_cast<int>(quic.packetType) << "\n";
}

void formatFTP(std::ostringstream& ss, const fdpi::FTP& ftp) {
    ss << "layer7=FTP\n";
    ss << "ftp.isResponse=" << (ftp.isResponse ? "true" : "false") << "\n";
    ss << "ftp.command=" << ftp.command << "\n";
    ss << "ftp.argument=" << ftp.argument << "\n";
    ss << "ftp.replyCode=" << ftp.replyCode << "\n";
    ss << "ftp.replyText=" << ftp.replyText << "\n";
}

void formatSSH(std::ostringstream& ss, const fdpi::SSH& ssh) {
    ss << "layer7=SSH\n";
    ss << "ssh.protocolVersion=" << ssh.protocolVersion << "\n";
    ss << "ssh.softwareVersion=" << ssh.softwareVersion << "\n";
    if (ssh.comments) {
        ss << "ssh.comments=" << *ssh.comments << "\n";
    }
}

void formatDHCP(std::ostringstream& ss, const fdpi::DHCP& dhcp) {
    ss << "layer7=DHCP\n";
    ss << "dhcp.op=" << static_cast<int>(dhcp.op) << "\n";
    ss << "dhcp.htype=" << static_cast<int>(dhcp.htype) << "\n";
    ss << "dhcp.hlen=" << static_cast<int>(dhcp.hlen) << "\n";
    ss << "dhcp.hops=" << static_cast<int>(dhcp.hops) << "\n";
    ss << "dhcp.xid=" << hex32(dhcp.xid) << "\n";
    ss << "dhcp.secs=" << dhcp.secs << "\n";
    ss << "dhcp.flags=" << hex16(dhcp.flags) << "\n";
    ss << "dhcp.ciaddr=" << dhcp.ciaddr.toString() << "\n";
    ss << "dhcp.yiaddr=" << dhcp.yiaddr.toString() << "\n";
    ss << "dhcp.siaddr=" << dhcp.siaddr.toString() << "\n";
    ss << "dhcp.giaddr=" << dhcp.giaddr.toString() << "\n";
    ss << "dhcp.chaddr=" << dhcp.chaddr.toString() << "\n";
    if (dhcp.messageType) {
        ss << "dhcp.messageType=" << static_cast<int>(*dhcp.messageType) << "\n";
    }
    if (dhcp.hostname) {
        ss << "dhcp.hostname=" << *dhcp.hostname << "\n";
    }
    ss << "dhcp.options.count=" << dhcp.options.size() << "\n";
}

void formatDHCPv6(std::ostringstream& ss, const fdpi::DHCPv6& dhcp) {
    ss << "layer7=DHCPv6\n";
    ss << "dhcpv6.messageType=" << static_cast<int>(dhcp.messageType) << "\n";
    ss << "dhcpv6.transactionId=" << dhcp.transactionId << "\n";
    if (dhcp.clientFqdn) {
        ss << "dhcpv6.clientFqdn=" << *dhcp.clientFqdn << "\n";
    }
    ss << "dhcpv6.options.count=" << dhcp.options.size() << "\n";
}

void formatSMTP(std::ostringstream& ss, const fdpi::SMTP& smtp) {
    ss << "layer7=SMTP\n";
    ss << "smtp.isResponse=" << (smtp.isResponse ? "true" : "false") << "\n";
    ss << "smtp.command=" << smtp.command << "\n";
    ss << "smtp.argument=" << smtp.argument << "\n";
    ss << "smtp.replyCode=" << smtp.replyCode << "\n";
    ss << "smtp.replyText=" << smtp.replyText << "\n";
}

void formatPOP3(std::ostringstream& ss, const fdpi::POP3& pop3) {
    ss << "layer7=POP3\n";
    ss << "pop3.isResponse=" << (pop3.isResponse ? "true" : "false") << "\n";
    ss << "pop3.command=" << pop3.command << "\n";
    ss << "pop3.argument=" << pop3.argument << "\n";
    ss << "pop3.success=" << (pop3.success ? "true" : "false") << "\n";
    ss << "pop3.responseText=" << pop3.responseText << "\n";
}

void formatIMAP(std::ostringstream& ss, const fdpi::IMAP& imap) {
    ss << "layer7=IMAP\n";
    ss << "imap.isResponse=" << (imap.isResponse ? "true" : "false") << "\n";
    ss << "imap.tag=" << imap.tag << "\n";
    ss << "imap.command=" << imap.command << "\n";
    ss << "imap.argument=" << imap.argument << "\n";
    ss << "imap.statusCode=" << imap.statusCode << "\n";
    ss << "imap.responseText=" << imap.responseText << "\n";
}

void formatSNMP(std::ostringstream& ss, const fdpi::SNMP& snmp) {
    ss << "layer7=SNMP\n";
    ss << "snmp.version=" << static_cast<int>(snmp.version) << "\n";
    if (snmp.community) {
        ss << "snmp.community=" << *snmp.community << "\n";
    }
    if (snmp.pduType) {
        ss << "snmp.pduType=" << hex8(static_cast<uint8_t>(*snmp.pduType)) << "\n";
    }
    if (snmp.requestId) {
        ss << "snmp.requestId=" << *snmp.requestId << "\n";
    }
}

void formatRDP(std::ostringstream& ss, const fdpi::RDP& rdp) {
    ss << "layer7=RDP\n";
    ss << "rdp.tpktVersion=" << static_cast<int>(rdp.tpktVersion) << "\n";
    ss << "rdp.tpktLength=" << rdp.tpktLength << "\n";
    ss << "rdp.x224Type=" << hex8(rdp.x224Type) << "\n";
    ss << "rdp.dstRef=" << rdp.dstRef << "\n";
    ss << "rdp.srcRef=" << rdp.srcRef << "\n";
    ss << "rdp.classOption=" << static_cast<int>(rdp.classOption) << "\n";
    if (rdp.requestedProtocols) {
        ss << "rdp.requestedProtocols=" << *rdp.requestedProtocols << "\n";
    }
    if (rdp.selectedProtocol) {
        ss << "rdp.selectedProtocol=" << *rdp.selectedProtocol << "\n";
    }
    if (rdp.cookie) {
        ss << "rdp.cookie=" << *rdp.cookie << "\n";
    }
}

void formatBGP(std::ostringstream& ss, const fdpi::BGP& bgp) {
    ss << "layer7=BGP\n";
    ss << "bgp.length=" << bgp.length << "\n";
    ss << "bgp.type=" << static_cast<int>(bgp.type) << "\n";
    if (bgp.version) {
        ss << "bgp.version=" << static_cast<int>(*bgp.version) << "\n";
    }
    if (bgp.myAs) {
        ss << "bgp.myAs=" << *bgp.myAs << "\n";
    }
    if (bgp.holdTime) {
        ss << "bgp.holdTime=" << *bgp.holdTime << "\n";
    }
    if (bgp.bgpId) {
        ss << "bgp.bgpId=" << bgp.bgpId->toString() << "\n";
    }
}

void formatNTP(std::ostringstream& ss, const fdpi::NTP& ntp) {
    ss << "layer7=NTP\n";
    ss << "ntp.leapIndicator=" << static_cast<int>(ntp.leapIndicator) << "\n";
    ss << "ntp.version=" << static_cast<int>(ntp.version) << "\n";
    ss << "ntp.mode=" << static_cast<int>(ntp.mode) << "\n";
    ss << "ntp.stratum=" << static_cast<int>(ntp.stratum) << "\n";
    ss << "ntp.poll=" << static_cast<int>(ntp.poll) << "\n";
    ss << "ntp.precision=" << static_cast<int>(ntp.precision) << "\n";
    ss << "ntp.rootDelay=" << ntp.rootDelay << "\n";
    ss << "ntp.rootDispersion=" << ntp.rootDispersion << "\n";
    ss << "ntp.referenceId=" << hex32(ntp.referenceId) << "\n";
    ss << "ntp.referenceTimestamp=" << ntp.referenceTimestamp << "\n";
    ss << "ntp.originTimestamp=" << ntp.originTimestamp << "\n";
    ss << "ntp.receiveTimestamp=" << ntp.receiveTimestamp << "\n";
    ss << "ntp.transmitTimestamp=" << ntp.transmitTimestamp << "\n";
}

void formatLDAP(std::ostringstream& ss, const fdpi::LDAP& ldap) {
    ss << "layer7=LDAP\n";
    ss << "ldap.messageId=" << ldap.messageId << "\n";
    ss << "ldap.operation=" << hex8(static_cast<uint8_t>(ldap.operation)) << "\n";
    if (ldap.ldapVersion) {
        ss << "ldap.ldapVersion=" << static_cast<int>(*ldap.ldapVersion) << "\n";
    }
    if (ldap.bindDn) {
        ss << "ldap.bindDn=" << *ldap.bindDn << "\n";
    }
}

void formatSSDP(std::ostringstream& ss, const fdpi::SSDP& ssdp) {
    ss << "layer7=SSDP\n";
    ss << "ssdp.isRequest=" << (ssdp.isRequest ? "true" : "false") << "\n";
    ss << "ssdp.method=" << ssdp.method << "\n";
    ss << "ssdp.uri=" << ssdp.uri << "\n";
    ss << "ssdp.statusCode=" << ssdp.statusCode << "\n";
    ss << "ssdp.headers.count=" << ssdp.headers.size() << "\n";
    for (size_t i = 0; i < ssdp.headers.size(); ++i) {
        ss << "ssdp.headers[" << i << "].name=" << ssdp.headers[i].first << "\n";
        ss << "ssdp.headers[" << i << "].value=" << ssdp.headers[i].second << "\n";
    }
}

void formatSrvLoc(std::ostringstream& ss, const fdpi::SrvLoc& slp) {
    ss << "layer7=SrvLoc\n";
    ss << "srvloc.version=" << static_cast<int>(slp.version) << "\n";
    ss << "srvloc.functionId=" << static_cast<int>(slp.functionId) << "\n";
    ss << "srvloc.length=" << slp.length << "\n";
    ss << "srvloc.xid=" << slp.xid << "\n";
    if (!slp.languageTag.empty()) {
        ss << "srvloc.languageTag=" << slp.languageTag << "\n";
    }
}

void formatNBNS(std::ostringstream& ss, const fdpi::NBNS& nbns) {
    ss << "layer7=NBNS\n";
    ss << "nbns.id=" << hex16(nbns.id) << "\n";
    ss << "nbns.isResponse=" << (nbns.isResponse ? "true" : "false") << "\n";
    ss << "nbns.opcode=" << static_cast<int>(nbns.opcode) << "\n";
    ss << "nbns.rcode=" << static_cast<int>(nbns.rcode) << "\n";
    ss << "nbns.questions.count=" << nbns.questions.size() << "\n";
    for (size_t i = 0; i < nbns.questions.size(); ++i) {
        ss << "nbns.questions[" << i << "].name=" << nbns.questions[i].name << "\n";
        ss << "nbns.questions[" << i << "].type=" << nbns.questions[i].type << "\n";
        ss << "nbns.questions[" << i << "].class=" << nbns.questions[i].qclass << "\n";
    }
    ss << "nbns.answers.count=" << nbns.answers.size() << "\n";
    for (size_t i = 0; i < nbns.answers.size(); ++i) {
        ss << "nbns.answers[" << i << "].name=" << nbns.answers[i].name << "\n";
        ss << "nbns.answers[" << i << "].type=" << nbns.answers[i].type << "\n";
        ss << "nbns.answers[" << i << "].ttl=" << nbns.answers[i].ttl << "\n";
        ss << "nbns.answers[" << i << "].rdataSize=" << nbns.answers[i].rdata.size()
           << "\n";
    }
}

void formatNBDGM(std::ostringstream& ss, const fdpi::NBDGM& nbdgm) {
    ss << "layer7=NBDGM\n";
    ss << "nbdgm.messageType=" << hex8(nbdgm.messageType) << "\n";
    ss << "nbdgm.flags=" << hex8(nbdgm.flags) << "\n";
    ss << "nbdgm.dgmId=" << nbdgm.dgmId << "\n";
    ss << "nbdgm.sourceIp=" << nbdgm.sourceIp.toString() << "\n";
    ss << "nbdgm.sourcePort=" << nbdgm.sourcePort << "\n";
    if (nbdgm.messageType >= 0x10 && nbdgm.messageType <= 0x12) {
        ss << "nbdgm.dgmLength=" << nbdgm.dgmLength << "\n";
        ss << "nbdgm.packetOffset=" << nbdgm.packetOffset << "\n";
        ss << "nbdgm.sourceName=" << nbdgm.sourceName << "\n";
        ss << "nbdgm.destinationName=" << nbdgm.destinationName << "\n";
    }
}

void formatSMB(std::ostringstream& ss, const fdpi::SMB& smb) {
    ss << "layer7=SMB\n";
    ss << "smb.version=" << static_cast<int>(smb.version) << "\n";
    ss << "smb.command=" << hex8(smb.command) << "\n";
    ss << "smb.status=" << hex32(smb.status) << "\n";
    ss << "smb.tid=" << smb.tid << "\n";
    ss << "smb.uid=" << smb.uid << "\n";
    ss << "smb.mid=" << smb.mid << "\n";
    ss << "smb.flags=" << hex8(smb.flags) << "\n";
    if (smb.version == 1) {
        ss << "smb.flags2=" << hex16(smb.flags2) << "\n";
    }
}

void formatRTMP(std::ostringstream& ss, const fdpi::RTMP& rtmp) {
    ss << "layer7=RTMP\n";
    ss << "rtmp.isHandshake=" << (rtmp.isHandshake ? "true" : "false") << "\n";
    if (rtmp.isHandshake) {
        ss << "rtmp.handshakeType=" << static_cast<int>(rtmp.handshakeType) << "\n";
    } else {
        ss << "rtmp.chunkType=" << static_cast<int>(rtmp.chunkType) << "\n";
        ss << "rtmp.chunkStreamId=" << rtmp.chunkStreamId << "\n";
        ss << "rtmp.timestamp=" << rtmp.timestamp << "\n";
        ss << "rtmp.messageLength=" << rtmp.messageLength << "\n";
        ss << "rtmp.messageTypeId=" << static_cast<int>(rtmp.messageTypeId) << "\n";
        ss << "rtmp.messageStreamId=" << rtmp.messageStreamId << "\n";
    }
}

void formatIMF(std::ostringstream& ss, const fdpi::IMF& imf) {
    ss << "layer7=IMF\n";
    if (!imf.from.empty()) {
        ss << "imf.from=" << imf.from << "\n";
    }
    if (!imf.to.empty()) {
        ss << "imf.to=" << imf.to << "\n";
    }
    if (!imf.subject.empty()) {
        ss << "imf.subject=" << imf.subject << "\n";
    }
    if (!imf.date.empty()) {
        ss << "imf.date=" << imf.date << "\n";
    }
    if (!imf.messageId.empty()) {
        ss << "imf.messageId=" << imf.messageId << "\n";
    }
    if (!imf.contentType.empty()) {
        ss << "imf.contentType=" << imf.contentType << "\n";
    }
    ss << "imf.headers.count=" << imf.headers.size() << "\n";
}

// --- Variant dispatchers ---

void formatLayer3(std::ostringstream& ss,
                  const std::variant<std::monostate,
                                     fdpi::IPv4,
                                     fdpi::IPv6,
                                     fdpi::ARP,
                                     fdpi::RARP,
                                     fdpi::EAPOL,
                                     fdpi::LLDP,
                                     fdpi::HomePlug>& layer3) {
    std::visit(
        [&ss](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, fdpi::IPv4>) {
                formatIPv4(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::IPv6>) {
                formatIPv6(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::ARP>) {
                formatARP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::RARP>) {
                formatRARP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::EAPOL>) {
                formatEAPOL(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::LLDP>) {
                ss << "layer3=LLDP\n";
                ss << "lldp.chassisId=" << v.chassisId << "\n";
                ss << "lldp.portId=" << v.portId << "\n";
                ss << "lldp.ttl=" << v.ttl << "\n";
            } else if constexpr (std::is_same_v<T, fdpi::HomePlug>) {
                ss << "layer3=HomePlug\n";
                ss << "homeplug.version=" << static_cast<int>(v.version) << "\n";
                ss << "homeplug.type=" << v.type << "\n";
            }
        },
        layer3);
}

void formatLayer4(std::ostringstream& ss,
                  const std::variant<std::monostate,
                                     fdpi::TCP,
                                     fdpi::UDP,
                                     fdpi::ICMP,
                                     fdpi::ICMPv6,
                                     fdpi::IGMP,
                                     fdpi::ESP>& layer4) {
    std::visit(
        [&ss](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, fdpi::TCP>) {
                formatTCP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::UDP>) {
                formatUDP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::ICMP>) {
                formatICMP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::ICMPv6>) {
                formatICMPv6(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::IGMP>) {
                formatIGMP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::ESP>) {
                formatESP(ss, v);
            }
        },
        layer4);
}

void formatLayer7(std::ostringstream& ss,
                  const std::variant<std::monostate,
                                     fdpi::DNS,
                                     fdpi::HTTP,
                                     fdpi::TLS,
                                     fdpi::QUIC,
                                     fdpi::FTP,
                                     fdpi::SSH,
                                     fdpi::DHCP,
                                     fdpi::DHCPv6,
                                     fdpi::SMTP,
                                     fdpi::POP3,
                                     fdpi::IMAP,
                                     fdpi::SNMP,
                                     fdpi::RDP,
                                     fdpi::BGP,
                                     fdpi::NTP,
                                     fdpi::LDAP,
                                     fdpi::SSDP,
                                     fdpi::SrvLoc,
                                     fdpi::NBNS,
                                     fdpi::NBDGM,
                                     fdpi::SMB,
                                     fdpi::RTMP,
                                     fdpi::IMF,
                                     fdpi::STUN,
                                     fdpi::DTLS,
                                     fdpi::RTCP,
                                     fdpi::DbLanSyncDisc>& layer7) {
    std::visit(
        [&ss](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, fdpi::DNS>) {
                formatDNS(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::HTTP>) {
                formatHTTP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::TLS>) {
                formatTLS(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::QUIC>) {
                formatQUIC(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::FTP>) {
                formatFTP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::SSH>) {
                formatSSH(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::DHCP>) {
                formatDHCP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::DHCPv6>) {
                formatDHCPv6(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::SMTP>) {
                formatSMTP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::POP3>) {
                formatPOP3(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::IMAP>) {
                formatIMAP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::SNMP>) {
                formatSNMP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::RDP>) {
                formatRDP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::BGP>) {
                formatBGP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::NTP>) {
                formatNTP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::LDAP>) {
                formatLDAP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::SSDP>) {
                formatSSDP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::SrvLoc>) {
                formatSrvLoc(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::NBNS>) {
                formatNBNS(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::NBDGM>) {
                formatNBDGM(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::SMB>) {
                formatSMB(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::RTMP>) {
                formatRTMP(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::IMF>) {
                formatIMF(ss, v);
            } else if constexpr (std::is_same_v<T, fdpi::STUN>) {
                ss << "layer7=STUN\n";
                ss << "stun.type=" << v.type << "\n";
                ss << "stun.isRequest=" << v.isRequest << "\n";
            } else if constexpr (std::is_same_v<T, fdpi::DTLS>) {
                ss << "layer7=DTLS\n";
                ss << "dtls.contentType=" << static_cast<int>(v.contentType) << "\n";
                ss << "dtls.version=0x" << std::hex << v.version << std::dec << "\n";
            } else if constexpr (std::is_same_v<T, fdpi::RTCP>) {
                ss << "layer7=RTCP\n";
                ss << "rtcp.packetType=" << static_cast<int>(v.packetType) << "\n";
                ss << "rtcp.ssrc=" << v.ssrc << "\n";
            } else if constexpr (std::is_same_v<T, fdpi::DbLanSyncDisc>) {
                ss << "layer7=DbLanSyncDisc\n";
            }
        },
        layer7);
}

void formatFlow(std::ostringstream& ss, const fdpi::FlowId& flow) {
    ss << "flow.srcIp=" << ipStr(flow.srcIp) << "\n";
    ss << "flow.dstIp=" << ipStr(flow.dstIp) << "\n";
    ss << "flow.srcPort=" << flow.srcPort << "\n";
    ss << "flow.dstPort=" << flow.dstPort << "\n";
    ss << "flow.protocol=" << static_cast<int>(flow.protocol) << "\n";
}

} // anonymous namespace

std::string formatPacket(uint32_t index, const fdpi::Packet& pkt) {
    std::ostringstream ss;
    ss << "--- packet " << index << " ---\n";
    ss << "timestamp=" << pkt.timestamp.time_since_epoch().count() << "\n";
    ss << "captureLength=" << pkt.captureLength << "\n";
    ss << "wireLength=" << pkt.wireLength << "\n";

    if (pkt.ethernet) {
        formatEthernet(ss, *pkt.ethernet);
    }
    if (pkt.wifi) {
        formatWifi(ss, *pkt.wifi);
    }
    if (pkt.vlan) {
        formatVlan(ss, *pkt.vlan);
    }

    formatLayer3(ss, pkt.layer3);
    formatLayer4(ss, pkt.layer4);
    formatLayer7(ss, pkt.layer7);
    formatFlow(ss, pkt.flowId);

    ss << "payloadSize=" << pkt.payload.size() << "\n";

    return ss.str();
}

std::string formatError(uint32_t index, fdpi::Error error) {
    std::ostringstream ss;
    ss << "--- packet " << index << " ---\n";
    ss << "error=" << fdpi::toString(error) << "\n";
    return ss.str();
}

} // namespace regression
