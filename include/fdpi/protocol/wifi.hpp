#ifndef FDPI_PROTOCOL_WIFI_HPP
#define FDPI_PROTOCOL_WIFI_HPP

#include <fdpi/address.hpp>

#include <cstdint>
#include <optional>

namespace fdpi {

struct WiFi {
    uint8_t type{0}; // 0=Management, 1=Control, 2=Data
    uint8_t subtype{0};
    bool toDS{false};
    bool fromDS{false};
    bool protectedFrame{false};
    bool retry{false};
    uint16_t durationId{0};
    MacAddress addr1;                // Always present (receiver)
    std::optional<MacAddress> addr2; // Most frames (transmitter)
    std::optional<MacAddress> addr3; // 3+ address frames
    std::optional<MacAddress> addr4; // WDS only (toDS=1, fromDS=1)
    uint16_t sequenceControl{0};
};

} // namespace fdpi

#endif // FDPI_PROTOCOL_WIFI_HPP
