#ifndef FDPI_PROTOCOL_HTTP_HPP
#define FDPI_PROTOCOL_HTTP_HPP

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <fdpi/error.hpp>

namespace fdpi {

struct HTTP {
    bool        isRequest;
    std::string method;
    std::string uri;
    uint16_t    statusCode;
    std::string version;
    std::vector<std::pair<std::string, std::string>> headers;
};

std::expected<HTTP, Error> decodeHttp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_HTTP_HPP
