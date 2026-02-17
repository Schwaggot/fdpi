#ifndef FDPI_PROTOCOL_OCSP_HPP
#define FDPI_PROTOCOL_OCSP_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace fdpi {

struct OCSP {
    bool isRequest{true};
    uint8_t responseStatus{0};         // 0=successful, 1=malformedRequest, etc.
    std::optional<uint8_t> certStatus; // 0=good, 1=revoked, 2=unknown
};

std::expected<OCSP, Error> decodeOcsp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_OCSP_HPP
