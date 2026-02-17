#ifndef FDPI_PROTOCOL_SMB_HPP
#define FDPI_PROTOCOL_SMB_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>

namespace fdpi {

struct SMB {
    uint8_t version; // 1 for SMB1, 2/3 for SMB2/3
    uint8_t command; // SMB1: negotiate=0x72, session_setup=0x73
    uint32_t status; // NT status code
    uint16_t tid;    // Tree ID
    uint16_t uid;    // User ID (SMB1) / lower Session ID (SMB2)
    uint16_t mid;    // Multiplex ID (SMB1) / lower Message ID (SMB2)
    uint8_t flags;
    uint16_t flags2; // SMB1 only
};

std::expected<SMB, Error> decodeSmb(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_SMB_HPP
