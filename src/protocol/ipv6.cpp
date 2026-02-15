#include <cstring>
#include <fdpi/protocol/ipv6.hpp>

namespace fdpi {

std::expected<IPv6, Error> decodeIPv6(const std::span<const uint8_t> data,
                                      size_t& offset) {
    constexpr size_t kIPv6Size = 40;

    if (data.size() < offset + kIPv6Size) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    IPv6 hdr{};
    hdr.version = (ptr[0] >> 4) & 0x0F;

    if (hdr.version != 6) {
        return std::unexpected(Error::MalformedPacket);
    }

    hdr.trafficClass =
        static_cast<uint8_t>(((ptr[0] & 0x0F) << 4) | ((ptr[1] >> 4) & 0x0F));
    hdr.flowLabel =
        static_cast<uint32_t>(((ptr[1] & 0x0F) << 16) | (ptr[2] << 8) | ptr[3]);
    hdr.payloadLength = static_cast<uint16_t>((ptr[4] << 8) | ptr[5]);
    hdr.nextHeader = ptr[6];
    hdr.hopLimit = ptr[7];

    std::memcpy(hdr.srcIp.bytes.data(), ptr + 8, 16);
    std::memcpy(hdr.dstIp.bytes.data(), ptr + 24, 16);

    offset += kIPv6Size;
    return hdr;
}

} // namespace fdpi
