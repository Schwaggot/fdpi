#include <fdpi/protocol/icmp.hpp>

namespace fdpi {

std::expected<ICMP, Error> decodeIcmp(const std::span<const uint8_t> data,
                                      size_t& offset) {
    constexpr size_t kIcmpMinSize = 8;

    if (data.size() < offset + kIcmpMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    ICMP hdr{};
    hdr.type = ptr[0];
    hdr.code = ptr[1];
    hdr.checksum = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.restOfHeader =
        (static_cast<uint32_t>(ptr[4]) << 24) | (static_cast<uint32_t>(ptr[5]) << 16) |
        (static_cast<uint32_t>(ptr[6]) << 8) | static_cast<uint32_t>(ptr[7]);

    offset += kIcmpMinSize;
    return hdr;
}

std::expected<ICMPv6, Error> decodeIcmpv6(const std::span<const uint8_t> data,
                                          size_t& offset) {
    constexpr size_t kIcmpv6MinSize = 8;

    if (data.size() < offset + kIcmpv6MinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    ICMPv6 hdr{};
    hdr.type = ptr[0];
    hdr.code = ptr[1];
    hdr.checksum = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.restOfHeader =
        (static_cast<uint32_t>(ptr[4]) << 24) | (static_cast<uint32_t>(ptr[5]) << 16) |
        (static_cast<uint32_t>(ptr[6]) << 8) | static_cast<uint32_t>(ptr[7]);

    offset += kIcmpv6MinSize;
    return hdr;
}

} // namespace fdpi
