#ifndef FDPI_PROTOCOL_DHCP_HPP
#define FDPI_PROTOCOL_DHCP_HPP

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <fdpi/address.hpp>
#include <fdpi/error.hpp>

namespace fdpi {

struct DhcpOption {
    uint8_t code;
    std::vector<uint8_t> data;
};

struct DHCP {
    uint8_t op; // 1=Request, 2=Reply
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    IPv4Address ciaddr;
    IPv4Address yiaddr;
    IPv4Address siaddr;
    IPv4Address giaddr;
    MacAddress chaddr;
    std::optional<uint8_t> messageType;  // option 53
    std::optional<std::string> hostname; // option 12
    std::vector<DhcpOption> options;
};

std::expected<DHCP, Error> decodeDhcp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_DHCP_HPP
