#include <cstring>
#include <fdpi/protocol/ipv4.hpp>

namespace fdpi {

std::expected<IPv4, Error> decodeIPv4(const std::span<const uint8_t> data,
                                      size_t& offset) {
    constexpr size_t kIPv4MinSize = 20;

    if (data.size() < offset + kIPv4MinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    IPv4 hdr{};
    hdr.version = (ptr[0] >> 4) & 0x0F;
    hdr.ihl = ptr[0] & 0x0F;

    if (hdr.version != 4) {
        return std::unexpected(Error::MalformedPacket);
    }

    if (hdr.ihl < 5) {
        return std::unexpected(Error::InvalidHeaderLength);
    }

    const size_t headerLen = static_cast<size_t>(hdr.ihl) * 4;
    if (data.size() < offset + headerLen) {
        return std::unexpected(Error::TruncatedHeader);
    }

    hdr.dscp = (ptr[1] >> 2) & 0x3F;
    hdr.ecn = ptr[1] & 0x03;
    hdr.totalLength = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.identification = static_cast<uint16_t>((ptr[4] << 8) | ptr[5]);

    const uint16_t flagsFrag = static_cast<uint16_t>((ptr[6] << 8) | ptr[7]);
    hdr.flags = static_cast<uint8_t>((flagsFrag >> 13) & 0x07);
    hdr.fragmentOffset = flagsFrag & 0x1FFF;

    hdr.ttl = ptr[8];
    hdr.protocol = ptr[9];
    hdr.checksum = static_cast<uint16_t>((ptr[10] << 8) | ptr[11]);

    hdr.srcIp = IPv4Address(std::array{ptr[12], ptr[13], ptr[14], ptr[15]});
    hdr.dstIp = IPv4Address(std::array{ptr[16], ptr[17], ptr[18], ptr[19]});

    if (hdr.ihl > 5) {
        const size_t optLen = headerLen - 20;
        hdr.options.assign(ptr + 20, ptr + 20 + optLen);
    }

    offset += headerLen;
    return hdr;
}

} // namespace fdpi
