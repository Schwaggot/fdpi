#include <fdpi/protocol/udp.hpp>

namespace fdpi {

std::expected<UDP, Error> decodeUdp(const std::span<const uint8_t> data, size_t& offset) {
    constexpr size_t kUdpSize = 8;

    if (data.size() < offset + kUdpSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    UDP hdr{};
    hdr.srcPort = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);
    hdr.dstPort = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.length = static_cast<uint16_t>((ptr[4] << 8) | ptr[5]);
    hdr.checksum = static_cast<uint16_t>((ptr[6] << 8) | ptr[7]);

    offset += kUdpSize;
    return hdr;
}

} // namespace fdpi
