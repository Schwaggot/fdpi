#include <fdpi/protocol/gtp.hpp>

namespace fdpi {

std::expected<GTP, Error> decodeGtp(const std::span<const uint8_t> data, size_t& offset) {
    constexpr size_t kGtpMinSize = 8;

    if (data.size() < offset + kGtpMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    GTP hdr{};
    hdr.version = (ptr[0] >> 5) & 0x07;
    hdr.protocolType = (ptr[0] >> 4) & 0x01;
    hdr.messageType = ptr[1];
    hdr.length = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.teid = (static_cast<uint32_t>(ptr[4]) << 24) |
               (static_cast<uint32_t>(ptr[5]) << 16) |
               (static_cast<uint32_t>(ptr[6]) << 8) | static_cast<uint32_t>(ptr[7]);

    offset += kGtpMinSize;

    // If extension, sequence number, or N-PDU flags are set, skip 4 more bytes
    bool hasExtension = (ptr[0] >> 2) & 0x01;
    bool hasSeqNum = (ptr[0] >> 1) & 0x01;
    bool hasNPdu = ptr[0] & 0x01;

    if (hasExtension || hasSeqNum || hasNPdu) {
        if (data.size() < offset + 4) {
            return std::unexpected(Error::TruncatedHeader);
        }
        offset += 4;
    }

    return hdr;
}

} // namespace fdpi
