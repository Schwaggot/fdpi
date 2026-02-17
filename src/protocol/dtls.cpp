#include <fdpi/protocol/dtls.hpp>

namespace fdpi {

std::expected<DTLS, Error> decodeDtls(const std::span<const uint8_t> data,
                                      size_t& offset) {
    constexpr size_t kDtlsRecordHeaderSize = 13;

    if (data.size() < offset + kDtlsRecordHeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    DTLS hdr{};
    hdr.contentType = ptr[0];
    hdr.version = static_cast<uint16_t>((ptr[1] << 8) | ptr[2]);
    hdr.epoch = static_cast<uint16_t>((ptr[3] << 8) | ptr[4]);
    // 48-bit sequence number (6 bytes)
    hdr.sequenceNumber =
        (static_cast<uint64_t>(ptr[5]) << 40) | (static_cast<uint64_t>(ptr[6]) << 32) |
        (static_cast<uint64_t>(ptr[7]) << 24) | (static_cast<uint64_t>(ptr[8]) << 16) |
        (static_cast<uint64_t>(ptr[9]) << 8) | static_cast<uint64_t>(ptr[10]);
    hdr.length = static_cast<uint16_t>((ptr[11] << 8) | ptr[12]);

    offset += kDtlsRecordHeaderSize;

    // Parse handshake type if content type is Handshake (22)
    if (hdr.contentType == 22 && offset < data.size()) {
        hdr.handshakeType = data[offset];
    }

    // Advance past the record body
    size_t bodyEnd = offset + hdr.length;
    if (bodyEnd > data.size()) {
        bodyEnd = data.size();
    }
    offset = bodyEnd;

    return hdr;
}

} // namespace fdpi
