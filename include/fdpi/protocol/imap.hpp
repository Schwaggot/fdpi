#ifndef FDPI_PROTOCOL_IMAP_HPP
#define FDPI_PROTOCOL_IMAP_HPP

#include <cstdint>
#include <expected>
#include <span>
#include <string>

#include <fdpi/error.hpp>

namespace fdpi {

struct IMAP {
    bool isResponse;
    std::string tag;     // "*" for untagged, or command tag like "A001"
    std::string command; // "LOGIN", "SELECT", "OK", etc.
    std::string argument;
    std::string statusCode; // "OK", "NO", "BAD" for tagged responses
    std::string responseText;
};

std::expected<IMAP, Error> decodeImap(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_IMAP_HPP
