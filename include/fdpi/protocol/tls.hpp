#ifndef FDPI_PROTOCOL_TLS_HPP
#define FDPI_PROTOCOL_TLS_HPP

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <fdpi/error.hpp>

namespace fdpi {

struct TLS {
    uint8_t  contentType;
    uint16_t version;
    std::optional<std::string> sni;
    std::optional<std::vector<std::string>> alpn;
    std::optional<uint16_t> tlsVersion;
    std::vector<uint16_t> cipherSuites;
};

std::expected<TLS, Error> decodeTls(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_TLS_HPP
