#ifndef FDPI_FLOW_HPP
#define FDPI_FLOW_HPP

#include <cstddef>
#include <cstdint>

#include <fdpi/address.hpp>

namespace fdpi {

enum class AppProtocol : uint8_t {
    Unknown = 0,
    BGP,
    DbLanSyncDisc,
    DHCP,
    DHCPv6,
    DNS,
    DTLS,
    FTP,
    HTTP,
    IMAP,
    IMF,
    LDAP,
    LLMNR,
    MDNS,
    NBDGM,
    NBNS,
    NTP,
    POP3,
    QUIC,
    RDP,
    RTCP,
    RTMP,
    SMB,
    SMTP,
    SNMP,
    SSDP,
    SSH,
    SrvLoc,
    STUN,
    TLS,
};

struct FlowId {
    IpAddress srcIp;
    IpAddress dstIp;
    uint16_t  srcPort{0};
    uint16_t  dstPort{0};
    uint8_t   protocol{0};

    bool operator==(const FlowId&) const = default;
};

struct FlowIdHash {
    std::size_t operator()(const FlowId& id) const noexcept;
};

} // namespace fdpi

#endif // FDPI_FLOW_HPP
