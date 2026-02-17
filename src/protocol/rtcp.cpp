#include <fdpi/protocol/rtcp.hpp>

namespace fdpi {

std::expected<RTCP, Error> decodeRtcp(const std::span<const uint8_t> data,
                                      size_t& offset) {
    constexpr size_t kRtcpMinSize = 8;

    if (data.size() < offset + kRtcpMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    RTCP hdr{};
    hdr.version = (ptr[0] >> 6) & 0x03;
    hdr.padding = ((ptr[0] >> 5) & 0x01) != 0;
    hdr.receptionReportCount = ptr[0] & 0x1F;
    hdr.packetType = ptr[1];
    hdr.length = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.ssrc = (static_cast<uint32_t>(ptr[4]) << 24) |
               (static_cast<uint32_t>(ptr[5]) << 16) |
               (static_cast<uint32_t>(ptr[6]) << 8) | static_cast<uint32_t>(ptr[7]);

    // Advance past the full RTCP packet (header word + length words)
    const size_t totalSize = (static_cast<size_t>(hdr.length) + 1) * 4;
    offset += totalSize;
    if (offset > data.size()) {
        offset = data.size();
    }

    return hdr;
}

} // namespace fdpi
