#ifndef FDPI_PROTOCOL_LLDP_HPP
#define FDPI_PROTOCOL_LLDP_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace fdpi {

struct LldpTlv {
    uint16_t type;
    std::vector<uint8_t> value;
};

struct LLDP {
    std::string chassisId;
    std::string portId;
    uint16_t ttl{0};
    std::optional<std::string> systemName;
    std::optional<std::string> systemDescription;
    std::vector<LldpTlv> tlvs;
};

std::expected<LLDP, Error> decodeLldp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_LLDP_HPP
