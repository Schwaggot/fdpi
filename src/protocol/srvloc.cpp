#include <fdpi/protocol/srvloc.hpp>

namespace fdpi {

std::expected<SrvLoc, Error> decodeSrvloc(const std::span<const uint8_t> data,
                                          size_t& offset) {
    if (data.size() < offset + 5) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    SrvLoc hdr{};
    hdr.version = ptr[0];

    if (hdr.version == 1) {
        // SLPv1: 12-byte minimum header
        constexpr size_t kV1MinSize = 12;
        if (data.size() < offset + kV1MinSize) {
            return std::unexpected(Error::TruncatedHeader);
        }

        hdr.functionId = ptr[1];
        hdr.length = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
        // XID at offset 10-11
        hdr.xid = static_cast<uint16_t>((ptr[10] << 8) | ptr[11]);

        offset += kV1MinSize;
    } else if (hdr.version == 2) {
        // SLPv2: 14-byte minimum header
        constexpr size_t kV2MinSize = 14;
        if (data.size() < offset + kV2MinSize) {
            return std::unexpected(Error::TruncatedHeader);
        }

        hdr.functionId = ptr[1];
        // Length is 3 bytes in v2 (bytes 2-4)
        hdr.length = static_cast<uint16_t>((ptr[3] << 8) | ptr[4]);
        // XID at offset 10-11
        hdr.xid = static_cast<uint16_t>((ptr[10] << 8) | ptr[11]);

        // Language tag length at offset 12-13
        uint16_t langLen = static_cast<uint16_t>((ptr[12] << 8) | ptr[13]);
        offset += kV2MinSize;

        if (langLen > 0 && data.size() >= offset + langLen) {
            hdr.languageTag =
                std::string(reinterpret_cast<const char*>(data.data() + offset), langLen);
            offset += langLen;
        }
    } else {
        return std::unexpected(Error::MalformedPacket);
    }

    return hdr;
}

} // namespace fdpi
