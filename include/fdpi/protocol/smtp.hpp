#ifndef FDPI_PROTOCOL_SMTP_HPP
#define FDPI_PROTOCOL_SMTP_HPP

#include <cstdint>
#include <expected>
#include <span>
#include <string>

#include <fdpi/error.hpp>

namespace fdpi {

struct SMTP {
    bool isResponse;
    std::string command; // "EHLO", "MAIL FROM", "RCPT TO", etc.
    std::string argument;
    uint16_t replyCode; // 0 for commands
    std::string replyText;
};

std::expected<SMTP, Error> decodeSmtp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_SMTP_HPP
