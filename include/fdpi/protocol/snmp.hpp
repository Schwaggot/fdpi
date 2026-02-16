#ifndef FDPI_PROTOCOL_SNMP_HPP
#define FDPI_PROTOCOL_SNMP_HPP

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>

#include <fdpi/error.hpp>

namespace fdpi {

enum class SnmpPduType : uint8_t {
    GetRequest = 0xA0,
    GetNextRequest = 0xA1,
    GetResponse = 0xA2,
    SetRequest = 0xA3,
    Trap = 0xA4,
    GetBulkRequest = 0xA5,
    InformRequest = 0xA6,
    TrapV2 = 0xA7,
    Report = 0xA8,
};

struct SNMP {
    uint8_t version;                      // 0=v1, 1=v2c, 3=v3
    std::optional<std::string> community; // v1/v2c only
    std::optional<SnmpPduType> pduType;
    std::optional<uint32_t> requestId;
};

std::expected<SNMP, Error> decodeSnmp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_SNMP_HPP
