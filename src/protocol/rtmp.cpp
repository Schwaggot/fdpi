#include <fdpi/protocol/rtmp.hpp>

namespace fdpi {

std::expected<RTMP, Error> decodeRtmp(const std::span<const uint8_t> data,
                                      size_t& offset) {
    if (data.size() <= offset) {
        return std::unexpected(Error::TruncatedHeader);
    }

    RTMP hdr{};
    const uint8_t firstByte = data[offset];

    // Check for RTMP handshake: version byte 0x03
    if (firstByte == 0x03 && offset == 0) {
        hdr.isHandshake = true;
        hdr.handshakeType = 0; // C0/S0
        offset++;
        return hdr;
    }

    // Parse RTMP chunk header
    // Basic header: fmt (2 bits) + cs id (6 bits)
    hdr.chunkType = (firstByte >> 6) & 0x03;
    uint32_t csId = firstByte & 0x3F;
    offset++;

    if (csId == 0) {
        // 2-byte form: cs id = 64 + next byte
        if (data.size() <= offset) {
            return std::unexpected(Error::TruncatedHeader);
        }
        csId = 64 + data[offset];
        offset++;
    } else if (csId == 1) {
        // 3-byte form: cs id = 64 + next byte + 256 * byte after
        if (data.size() < offset + 2) {
            return std::unexpected(Error::TruncatedHeader);
        }
        csId = 64 + data[offset] + 256u * data[offset + 1];
        offset += 2;
    }
    hdr.chunkStreamId = csId;

    // Message header depends on chunk type (fmt)
    if (hdr.chunkType == 0) {
        // Type 0: 11 bytes
        if (data.size() < offset + 11) {
            return std::unexpected(Error::TruncatedHeader);
        }
        const uint8_t* p = data.data() + offset;
        hdr.timestamp = (static_cast<uint32_t>(p[0]) << 16) |
                        (static_cast<uint32_t>(p[1]) << 8) | static_cast<uint32_t>(p[2]);
        hdr.messageLength = (static_cast<uint32_t>(p[3]) << 16) |
                            (static_cast<uint32_t>(p[4]) << 8) |
                            static_cast<uint32_t>(p[5]);
        hdr.messageTypeId = p[6];
        hdr.messageStreamId =
            static_cast<uint32_t>(p[7]) | (static_cast<uint32_t>(p[8]) << 8) |
            (static_cast<uint32_t>(p[9]) << 16) | (static_cast<uint32_t>(p[10]) << 24);
        offset += 11;
    } else if (hdr.chunkType == 1) {
        // Type 1: 7 bytes
        if (data.size() < offset + 7) {
            return std::unexpected(Error::TruncatedHeader);
        }
        const uint8_t* p = data.data() + offset;
        hdr.timestamp = (static_cast<uint32_t>(p[0]) << 16) |
                        (static_cast<uint32_t>(p[1]) << 8) | static_cast<uint32_t>(p[2]);
        hdr.messageLength = (static_cast<uint32_t>(p[3]) << 16) |
                            (static_cast<uint32_t>(p[4]) << 8) |
                            static_cast<uint32_t>(p[5]);
        hdr.messageTypeId = p[6];
        offset += 7;
    } else if (hdr.chunkType == 2) {
        // Type 2: 3 bytes (timestamp delta only)
        if (data.size() < offset + 3) {
            return std::unexpected(Error::TruncatedHeader);
        }
        const uint8_t* p = data.data() + offset;
        hdr.timestamp = (static_cast<uint32_t>(p[0]) << 16) |
                        (static_cast<uint32_t>(p[1]) << 8) | static_cast<uint32_t>(p[2]);
        offset += 3;
    }
    // Type 3: 0 bytes - nothing to parse

    return hdr;
}

} // namespace fdpi
