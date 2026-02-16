#ifndef FDPI_PROTOCOL_SSH_HPP
#define FDPI_PROTOCOL_SSH_HPP

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>

#include <fdpi/error.hpp>

namespace fdpi {

struct SSH {
    std::string protocolVersion; // "2.0"
    std::string softwareVersion; // "OpenSSH_9.0"
    std::optional<std::string> comments;
};

std::expected<SSH, Error> decodeSsh(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_SSH_HPP
