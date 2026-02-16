#ifndef FDPI_PROTOCOL_FTP_HPP
#define FDPI_PROTOCOL_FTP_HPP

#include <cstdint>
#include <expected>
#include <span>
#include <string>

#include <fdpi/error.hpp>

namespace fdpi {

struct FTP {
    bool isResponse;
    std::string command; // "USER", "PASS", "RETR", etc.
    std::string argument;
    uint16_t replyCode; // 0 for commands
    std::string replyText;
};

std::expected<FTP, Error> decodeFtp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_FTP_HPP
