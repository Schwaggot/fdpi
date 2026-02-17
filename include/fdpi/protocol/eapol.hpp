#ifndef FDPI_PROTOCOL_EAPOL_HPP
#define FDPI_PROTOCOL_EAPOL_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>
#include <vector>

namespace fdpi {

struct EAPOL {
    uint8_t version{0};
    uint8_t type{0}; // 0=EAP-Packet, 1=Start, 2=Logoff, 3=Key
    uint16_t bodyLength{0};
    std::vector<uint8_t> body;
};

std::expected<EAPOL, Error> decodeEapol(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_EAPOL_HPP
