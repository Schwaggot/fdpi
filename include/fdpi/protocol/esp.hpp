#ifndef FDPI_PROTOCOL_ESP_HPP
#define FDPI_PROTOCOL_ESP_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>

namespace fdpi {

struct ESP {
    uint32_t spi; // Security Parameters Index
    uint32_t sequenceNumber;
};

std::expected<ESP, Error> decodeEsp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_ESP_HPP
