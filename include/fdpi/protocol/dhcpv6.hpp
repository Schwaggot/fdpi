#ifndef FDPI_PROTOCOL_DHCPV6_HPP
#define FDPI_PROTOCOL_DHCPV6_HPP

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <fdpi/error.hpp>

namespace fdpi {

struct Dhcpv6Option {
    uint16_t code;
    std::vector<uint8_t> data;
};

struct DHCPv6 {
    uint8_t messageType;                   // 1=Solicit..13=RelayReply
    uint32_t transactionId;                // 24 bits
    std::optional<std::string> clientFqdn; // option 39
    std::vector<Dhcpv6Option> options;
};

std::expected<DHCPv6, Error> decodeDhcpv6(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_DHCPV6_HPP
