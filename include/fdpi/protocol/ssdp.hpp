#ifndef FDPI_PROTOCOL_SSDP_HPP
#define FDPI_PROTOCOL_SSDP_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace fdpi {

struct SSDP {
    bool isRequest{true};
    std::string method;     // M-SEARCH, NOTIFY
    std::string uri;        // "*" for M-SEARCH
    uint16_t statusCode{0}; // for responses (200)
    std::vector<std::pair<std::string, std::string>> headers;
};

std::expected<SSDP, Error> decodeSsdp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_SSDP_HPP
