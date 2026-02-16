#ifndef FDPI_PACKET_HPP
#define FDPI_PACKET_HPP

#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

#include <fdpi/flow_id.hpp>
#include <fdpi/protocol/arp.hpp>
#include <fdpi/protocol/bgp.hpp>
#include <fdpi/protocol/dhcp.hpp>
#include <fdpi/protocol/dhcpv6.hpp>
#include <fdpi/protocol/dns.hpp>
#include <fdpi/protocol/ethernet.hpp>
#include <fdpi/protocol/ftp.hpp>
#include <fdpi/protocol/gre.hpp>
#include <fdpi/protocol/http.hpp>
#include <fdpi/protocol/icmp.hpp>
#include <fdpi/protocol/imap.hpp>
#include <fdpi/protocol/ipv4.hpp>
#include <fdpi/protocol/ipv6.hpp>
#include <fdpi/protocol/ldap.hpp>
#include <fdpi/protocol/mpls.hpp>
#include <fdpi/protocol/ntp.hpp>
#include <fdpi/protocol/pop3.hpp>
#include <fdpi/protocol/quic.hpp>
#include <fdpi/protocol/rarp.hpp>
#include <fdpi/protocol/rdp.hpp>
#include <fdpi/protocol/smtp.hpp>
#include <fdpi/protocol/snmp.hpp>
#include <fdpi/protocol/ssh.hpp>
#include <fdpi/protocol/tcp.hpp>
#include <fdpi/protocol/tls.hpp>
#include <fdpi/protocol/udp.hpp>

namespace fdpi {

struct Packet {
    // Link layer
    std::optional<Ethernet> ethernet;
    std::optional<VlanTag> vlan;

    // Network layer
    std::variant<std::monostate, IPv4, IPv6, ARP, RARP> layer3;

    // Transport layer
    std::variant<std::monostate, TCP, UDP, ICMP, ICMPv6> layer4;

    // Application layer
    std::variant<std::monostate,
                 DNS,
                 HTTP,
                 TLS,
                 QUIC,
                 FTP,
                 SSH,
                 DHCP,
                 DHCPv6,
                 SMTP,
                 POP3,
                 IMAP,
                 SNMP,
                 RDP,
                 BGP,
                 NTP,
                 LDAP>
        layer7;

    // Unparsed payload beyond the last decoded layer
    std::vector<uint8_t> payload;

    // Metadata
    FlowId flowId;
    uint64_t timestamp{0};
    uint32_t captureLength{0};
    uint32_t wireLength{0};
};

} // namespace fdpi

#endif // FDPI_PACKET_HPP
