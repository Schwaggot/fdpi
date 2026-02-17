#include <fdpi/protocol/eapol.hpp>

namespace fdpi {

std::expected<EAPOL, Error> decodeEapol(const std::span<const uint8_t> data,
                                        size_t& offset) {
    constexpr size_t kMinHeaderSize = 4;

    if (data.size() < offset + kMinHeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* p = data.data() + offset;

    EAPOL hdr{};
    hdr.version = p[0];
    hdr.type = p[1];
    hdr.bodyLength = static_cast<uint16_t>((p[2] << 8) | p[3]);
    offset += kMinHeaderSize;

    // Copy body bytes (up to bodyLength, clamped to available data)
    size_t available = data.size() - offset;
    size_t bodyBytes = std::min(static_cast<size_t>(hdr.bodyLength), available);
    if (bodyBytes > 0) {
        hdr.body.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                        data.begin() + static_cast<ptrdiff_t>(offset + bodyBytes));
        offset += bodyBytes;
    }

    return hdr;
}

} // namespace fdpi
