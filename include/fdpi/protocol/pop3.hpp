#ifndef FDPI_PROTOCOL_POP3_HPP
#define FDPI_PROTOCOL_POP3_HPP

#include <cstdint>
#include <expected>
#include <span>
#include <string>

#include <fdpi/error.hpp>

namespace fdpi {

struct POP3 {
    bool isResponse;
    std::string command; // "USER", "PASS", "STAT", "RETR", etc.
    std::string argument;
    bool success; // +OK -> true, -ERR -> false
    std::string responseText;
};

std::expected<POP3, Error> decodePop3(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_POP3_HPP
