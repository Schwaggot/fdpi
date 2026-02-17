#ifndef FDPI_PROTOCOL_IMF_HPP
#define FDPI_PROTOCOL_IMF_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace fdpi {

struct IMF {
    std::string from;
    std::string to;
    std::string subject;
    std::string date;
    std::string messageId;
    std::string contentType;
    std::vector<std::pair<std::string, std::string>> headers;
};

std::expected<IMF, Error> decodeImf(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_IMF_HPP
