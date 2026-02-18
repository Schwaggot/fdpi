#ifndef FDPI_PROTOCOL_TFTP_HPP
#define FDPI_PROTOCOL_TFTP_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace fdpi {

struct TFTP {
    uint16_t opcode{0};             // 1=RRQ, 2=WRQ, 3=DATA, 4=ACK, 5=ERROR
    std::string filename;           // RRQ/WRQ only
    std::string mode;               // RRQ/WRQ only ("octet", "netascii", "mail")
    uint16_t blockNumber{0};        // DATA/ACK: block #
    std::vector<uint8_t> blockData; // DATA: the data bytes
    uint16_t errorCode{0};          // ERROR: error code
    std::string errorMessage;       // ERROR: human-readable message
    std::vector<std::pair<std::string, std::string>> options; // RFC 2347
};

std::expected<TFTP, Error> decodeTftp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_TFTP_HPP
