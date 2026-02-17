#ifndef FDPI_DATALINK_HPP
#define FDPI_DATALINK_HPP

#include <fdpi/address.hpp>
#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

namespace fdpi {

enum class DataLinkType : uint16_t {
    DLT_NULL = 0,         // BSD loopback (4-byte AF family)
    DLT_EN10MB = 1,       // Ethernet (14-byte header)
    DLT_IEEE802_5 = 6,    // Token Ring
    DLT_PPP = 9,          // Point-to-Point Protocol
    DLT_FDDI = 10,        // FDDI
    DLT_RAW = 101,        // Raw IP (no L2 header)
    DLT_IEEE802_11 = 105,         // 802.11 WiFi
    DLT_LINUX_SLL = 113,          // Linux cooked capture v1
    DLT_IEEE802_11_RADIOTAP = 127, // 802.11 WiFi + radiotap header
    DLT_LINUX_SLL2 = 276,         // Linux cooked capture v2
};

struct LinkLayerResult {
    uint16_t etherType{0};
    bool hasMacs{false};
    MacAddress srcMac;
    MacAddress dstMac;
};

std::expected<LinkLayerResult, Error>
resolveDataLink(DataLinkType dlt, std::span<const uint8_t> data, size_t& offset);

constexpr std::string_view toString(const DataLinkType dlt) {
    switch (dlt) {
    case DataLinkType::DLT_NULL:
        return "DLT_NULL";
    case DataLinkType::DLT_EN10MB:
        return "DLT_EN10MB";
    case DataLinkType::DLT_IEEE802_5:
        return "DLT_IEEE802_5";
    case DataLinkType::DLT_PPP:
        return "DLT_PPP";
    case DataLinkType::DLT_FDDI:
        return "DLT_FDDI";
    case DataLinkType::DLT_RAW:
        return "DLT_RAW";
    case DataLinkType::DLT_IEEE802_11:
        return "DLT_IEEE802_11";
    case DataLinkType::DLT_IEEE802_11_RADIOTAP:
        return "DLT_IEEE802_11_RADIOTAP";
    case DataLinkType::DLT_LINUX_SLL:
        return "DLT_LINUX_SLL";
    case DataLinkType::DLT_LINUX_SLL2:
        return "DLT_LINUX_SLL2";
    }
    return "Unknown";
}

} // namespace fdpi

#endif // FDPI_DATALINK_HPP
