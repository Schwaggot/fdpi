#ifndef FDPI_PROTOCOL_STUN_HPP
#define FDPI_PROTOCOL_STUN_HPP

#include <fdpi/address.hpp>
#include <fdpi/error.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace fdpi {

struct STUN {
    uint16_t type{0};        // Binding Request=0x0001, Response=0x0101, etc.
    uint16_t length{0};      // Message length (excl 20-byte header)
    uint32_t magicCookie{0}; // Always 0x2112A442
    std::array<uint8_t, 12> transactionId{};
    bool isRequest{false};
    bool isIndication{false};
    std::optional<IpAddress> mappedAddress;
    std::optional<uint16_t> mappedPort;
};

std::expected<STUN, Error> decodeStun(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_STUN_HPP
