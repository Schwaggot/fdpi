#ifndef FDPI_PROTOCOL_HOMEPLUG_HPP
#define FDPI_PROTOCOL_HOMEPLUG_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>

namespace fdpi {

struct HomePlug {
    uint8_t version{0};
    uint16_t type{0}; // Management Message Type (MMType)
};

std::expected<HomePlug, Error> decodeHomeplug(std::span<const uint8_t> data,
                                              size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_HOMEPLUG_HPP
