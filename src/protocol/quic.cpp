#include <fdpi/protocol/quic.hpp>

namespace fdpi {

std::expected<QUIC, Error> decodeQuic(const std::span<const uint8_t> data,
                                      size_t& offset) {
    if (data.size() <= offset) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;
    QUIC hdr{};

    const uint8_t firstByte = ptr[0];
    hdr.isLongHeader = (firstByte & 0x80) != 0;

    if (hdr.isLongHeader) {
        // Long header: first byte + version(4) + DCID len(1) + DCID + SCID len(1) + SCID
        constexpr size_t kLongHeaderMinSize = 7; // 1 + 4 + 1 + 0 + 1
        if (data.size() < offset + kLongHeaderMinSize) {
            return std::unexpected(Error::TruncatedHeader);
        }

        hdr.packetType = static_cast<uint8_t>((firstByte >> 4) & 0x03);

        // Version is 4 bytes
        uint32_t ver = (static_cast<uint32_t>(ptr[1]) << 24) |
                       (static_cast<uint32_t>(ptr[2]) << 16) |
                       (static_cast<uint32_t>(ptr[3]) << 8) |
                       static_cast<uint32_t>(ptr[4]);
        hdr.version = static_cast<uint8_t>(ver & 0xFF);

        size_t pos = offset + 5;

        // DCID
        if (pos >= data.size())
            return std::unexpected(Error::TruncatedHeader);
        uint8_t dcidLen = data[pos];
        pos++;
        if (pos + dcidLen > data.size())
            return std::unexpected(Error::TruncatedHeader);
        hdr.dcid.assign(data.data() + pos, data.data() + pos + dcidLen);
        pos += dcidLen;

        // SCID
        if (pos >= data.size())
            return std::unexpected(Error::TruncatedHeader);
        uint8_t scidLen = data[pos];
        pos++;
        if (pos + scidLen > data.size())
            return std::unexpected(Error::TruncatedHeader);
        hdr.scid.assign(data.data() + pos, data.data() + pos + scidLen);
        pos += scidLen;

        offset = pos;
    } else {
        // Short header: we can only read the first byte for basic detection
        hdr.packetType = 0;
        hdr.version = 0;
        offset += 1;
    }

    return hdr;
}

} // namespace fdpi
