#include <cstring>
#include <fdpi/protocol/tcp.hpp>

namespace fdpi {

std::expected<TCP, Error> decodeTcp(const std::span<const uint8_t> data, size_t& offset) {
    constexpr size_t kTcpMinSize = 20;

    if (data.size() < offset + kTcpMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    TCP hdr{};
    hdr.srcPort = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);
    hdr.dstPort = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.seqNum = (static_cast<uint32_t>(ptr[4]) << 24) |
                 (static_cast<uint32_t>(ptr[5]) << 16) |
                 (static_cast<uint32_t>(ptr[6]) << 8) | static_cast<uint32_t>(ptr[7]);
    hdr.ackNum = (static_cast<uint32_t>(ptr[8]) << 24) |
                 (static_cast<uint32_t>(ptr[9]) << 16) |
                 (static_cast<uint32_t>(ptr[10]) << 8) | static_cast<uint32_t>(ptr[11]);
    hdr.dataOffset = (ptr[12] >> 4) & 0x0F;
    hdr.flags = ptr[13];
    hdr.window = static_cast<uint16_t>((ptr[14] << 8) | ptr[15]);
    hdr.checksum = static_cast<uint16_t>((ptr[16] << 8) | ptr[17]);
    hdr.urgentPointer = static_cast<uint16_t>((ptr[18] << 8) | ptr[19]);

    if (hdr.dataOffset < 5) {
        return std::unexpected(Error::InvalidHeaderLength);
    }

    const size_t headerLen = static_cast<size_t>(hdr.dataOffset) * 4;
    if (data.size() < offset + headerLen) {
        return std::unexpected(Error::TruncatedHeader);
    }

    if (hdr.dataOffset > 5) {
        const size_t optLen = headerLen - 20;
        hdr.options.assign(ptr + 20, ptr + 20 + optLen);
    }

    offset += headerLen;
    return hdr;
}

} // namespace fdpi
