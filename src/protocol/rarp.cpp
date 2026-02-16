#include <fdpi/protocol/rarp.hpp>

#include <cstring>

namespace fdpi {

std::expected<RARP, Error> decodeRarp(const std::span<const uint8_t> data,
                                      size_t& offset) {
    constexpr size_t kRarpSize = 28; // standard Ethernet/IPv4 RARP

    if (data.size() < offset + kRarpSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    RARP hdr{};
    hdr.hardwareType = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);
    hdr.protocolType = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.hardwareSize = ptr[4];
    hdr.protocolSize = ptr[5];
    hdr.opcode = static_cast<uint16_t>((ptr[6] << 8) | ptr[7]);

    std::memcpy(hdr.senderMac.bytes.data(), ptr + 8, 6);
    hdr.senderIp =
        IPv4Address(std::array<uint8_t, 4>{ptr[14], ptr[15], ptr[16], ptr[17]});
    std::memcpy(hdr.targetMac.bytes.data(), ptr + 18, 6);
    hdr.targetIp =
        IPv4Address(std::array<uint8_t, 4>{ptr[24], ptr[25], ptr[26], ptr[27]});

    offset += kRarpSize;
    return hdr;
}

} // namespace fdpi
