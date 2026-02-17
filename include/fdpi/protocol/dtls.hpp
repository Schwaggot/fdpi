#ifndef FDPI_PROTOCOL_DTLS_HPP
#define FDPI_PROTOCOL_DTLS_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace fdpi {

struct DTLS {
    uint8_t contentType{0}; // 20=ChangeCipherSpec, 22=Handshake, 23=AppData
    uint16_t version{0};    // 0xFEFD=DTLS 1.2, 0xFEFF=DTLS 1.0
    uint16_t epoch{0};
    uint64_t sequenceNumber{0}; // 48-bit
    uint16_t length{0};
    std::optional<uint8_t> handshakeType; // 1=ClientHello, 2=ServerHello
};

std::expected<DTLS, Error> decodeDtls(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_DTLS_HPP
