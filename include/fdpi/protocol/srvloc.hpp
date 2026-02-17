#ifndef FDPI_PROTOCOL_SRVLOC_HPP
#define FDPI_PROTOCOL_SRVLOC_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace fdpi {

struct SrvLoc {
    uint8_t version;    // 1 or 2
    uint8_t functionId; // 1=SrvRqst, 2=SrvRply, 6=SrvTypeRqst, etc.
    uint16_t length;
    uint16_t xid; // Transaction ID
    std::string languageTag;
};

std::expected<SrvLoc, Error> decodeSrvloc(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_SRVLOC_HPP
