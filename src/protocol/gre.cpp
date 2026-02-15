#include <fdpi/protocol/gre.hpp>

namespace fdpi {

std::expected<GRE, Error> decodeGre(const std::span<const uint8_t> data, size_t& offset) {
    constexpr size_t kGreMinSize = 4;

    if (data.size() < offset + kGreMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    GRE hdr{};
    uint16_t flags = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);
    hdr.checksumPresent = (flags & 0x8000) != 0;
    hdr.keyPresent = (flags & 0x2000) != 0;
    hdr.seqPresent = (flags & 0x1000) != 0;
    hdr.protocolType = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);

    size_t pos = offset + kGreMinSize;

    if (hdr.checksumPresent) {
        if (data.size() < pos + 4) {
            return std::unexpected(Error::TruncatedHeader);
        }
        // Checksum (2 bytes) + Reserved1 (2 bytes)
        hdr.checksum = static_cast<uint32_t>((data[pos] << 8) | data[pos + 1]);
        pos += 4;
    }

    if (hdr.keyPresent) {
        if (data.size() < pos + 4) {
            return std::unexpected(Error::TruncatedHeader);
        }
        hdr.key = (static_cast<uint32_t>(data[pos]) << 24) |
                  (static_cast<uint32_t>(data[pos + 1]) << 16) |
                  (static_cast<uint32_t>(data[pos + 2]) << 8) |
                  static_cast<uint32_t>(data[pos + 3]);
        pos += 4;
    }

    if (hdr.seqPresent) {
        if (data.size() < pos + 4) {
            return std::unexpected(Error::TruncatedHeader);
        }
        hdr.sequenceNumber = (static_cast<uint32_t>(data[pos]) << 24) |
                             (static_cast<uint32_t>(data[pos + 1]) << 16) |
                             (static_cast<uint32_t>(data[pos + 2]) << 8) |
                             static_cast<uint32_t>(data[pos + 3]);
        pos += 4;
    }

    offset = pos;
    return hdr;
}

} // namespace fdpi
