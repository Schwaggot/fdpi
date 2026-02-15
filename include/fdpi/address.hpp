#ifndef FDPI_ADDRESS_HPP
#define FDPI_ADDRESS_HPP

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>

namespace fdpi {

struct IPv4Address {
    std::array<uint8_t, 4> bytes{};

    IPv4Address() = default;

    constexpr explicit IPv4Address(const uint32_t ip)
        : bytes{{static_cast<uint8_t>((ip >> 24) & 0xFF),
                 static_cast<uint8_t>((ip >> 16) & 0xFF),
                 static_cast<uint8_t>((ip >> 8) & 0xFF),
                 static_cast<uint8_t>(ip & 0xFF)}} {}

    explicit IPv4Address(std::string_view str);

    constexpr explicit IPv4Address(const std::array<uint8_t, 4> bytes) : bytes(bytes) {}

    [[nodiscard]] constexpr uint32_t toUint32() const {
        return (static_cast<uint32_t>(bytes[0]) << 24) |
               (static_cast<uint32_t>(bytes[1]) << 16) |
               (static_cast<uint32_t>(bytes[2]) << 8) |
                static_cast<uint32_t>(bytes[3]);
    }

    [[nodiscard]] std::string toString() const;

    bool operator==(const IPv4Address&) const = default;
    auto operator<=>(const IPv4Address&) const = default;
};

struct IPv6Address {
    std::array<uint8_t, 16> bytes{};

    IPv6Address() = default;

    constexpr explicit IPv6Address(const uint64_t hi, const uint64_t lo)
        : bytes{{static_cast<uint8_t>((hi >> 56) & 0xFF),
                 static_cast<uint8_t>((hi >> 48) & 0xFF),
                 static_cast<uint8_t>((hi >> 40) & 0xFF),
                 static_cast<uint8_t>((hi >> 32) & 0xFF),
                 static_cast<uint8_t>((hi >> 24) & 0xFF),
                 static_cast<uint8_t>((hi >> 16) & 0xFF),
                 static_cast<uint8_t>((hi >> 8) & 0xFF),
                 static_cast<uint8_t>(hi & 0xFF),
                 static_cast<uint8_t>((lo >> 56) & 0xFF),
                 static_cast<uint8_t>((lo >> 48) & 0xFF),
                 static_cast<uint8_t>((lo >> 40) & 0xFF),
                 static_cast<uint8_t>((lo >> 32) & 0xFF),
                 static_cast<uint8_t>((lo >> 24) & 0xFF),
                 static_cast<uint8_t>((lo >> 16) & 0xFF),
                 static_cast<uint8_t>((lo >> 8) & 0xFF),
                 static_cast<uint8_t>(lo & 0xFF)}} {}

    explicit IPv6Address(std::string_view str);

    constexpr explicit IPv6Address(const std::array<uint8_t, 16> bytes) : bytes(bytes) {}

    [[nodiscard]] constexpr uint64_t hi() const {
        return (static_cast<uint64_t>(bytes[0]) << 56) |
               (static_cast<uint64_t>(bytes[1]) << 48) |
               (static_cast<uint64_t>(bytes[2]) << 40) |
               (static_cast<uint64_t>(bytes[3]) << 32) |
               (static_cast<uint64_t>(bytes[4]) << 24) |
               (static_cast<uint64_t>(bytes[5]) << 16) |
               (static_cast<uint64_t>(bytes[6]) << 8) |
                static_cast<uint64_t>(bytes[7]);
    }

    [[nodiscard]] constexpr uint64_t lo() const {
        return (static_cast<uint64_t>(bytes[8]) << 56) |
               (static_cast<uint64_t>(bytes[9]) << 48) |
               (static_cast<uint64_t>(bytes[10]) << 40) |
               (static_cast<uint64_t>(bytes[11]) << 32) |
               (static_cast<uint64_t>(bytes[12]) << 24) |
               (static_cast<uint64_t>(bytes[13]) << 16) |
               (static_cast<uint64_t>(bytes[14]) << 8) |
                static_cast<uint64_t>(bytes[15]);
    }

    [[nodiscard]] std::string toString() const;

    bool operator==(const IPv6Address&) const = default;
    auto operator<=>(const IPv6Address&) const = default;
};

struct MacAddress {
    std::array<uint8_t, 6> bytes{};

    MacAddress() = default;

    explicit MacAddress(std::string_view str);

    constexpr explicit MacAddress(const std::array<uint8_t, 6> bytes) : bytes(bytes) {}

    [[nodiscard]] std::string toString() const;

    bool operator==(const MacAddress&) const = default;
    auto operator<=>(const MacAddress&) const = default;
};

using IpAddress = std::variant<IPv4Address, IPv6Address>;

} // namespace fdpi

#endif // FDPI_ADDRESS_HPP
