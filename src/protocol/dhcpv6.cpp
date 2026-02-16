#include <fdpi/protocol/dhcpv6.hpp>

#include <string>

namespace fdpi {

std::expected<DHCPv6, Error> decodeDhcpv6(const std::span<const uint8_t> data,
                                          size_t& offset) {
    constexpr size_t kHeaderSize = 4; // 1 byte msgType + 3 bytes txnId

    if (data.size() < offset + kHeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    DHCPv6 hdr{};
    hdr.messageType = ptr[0];

    // Message type 0 is invalid (valid range: 1-13)
    if (hdr.messageType == 0) {
        return std::unexpected(Error::MalformedPacket);
    }

    hdr.transactionId = (static_cast<uint32_t>(ptr[1]) << 16) |
                        (static_cast<uint32_t>(ptr[2]) << 8) |
                        static_cast<uint32_t>(ptr[3]);

    // Parse TLV options
    size_t remaining = data.size() - offset;
    size_t optOffset = kHeaderSize;
    while (optOffset + 4 <= remaining) {
        uint16_t optType =
            static_cast<uint16_t>((ptr[optOffset] << 8) | ptr[optOffset + 1]);
        uint16_t optLen =
            static_cast<uint16_t>((ptr[optOffset + 2] << 8) | ptr[optOffset + 3]);

        if (optOffset + 4 + optLen > remaining) {
            break;
        }

        Dhcpv6Option opt;
        opt.code = optType;
        opt.data.assign(ptr + optOffset + 4, ptr + optOffset + 4 + optLen);
        hdr.options.push_back(std::move(opt));

        // Option 39: Client FQDN
        if (optType == 39 && optLen > 1) {
            // First byte is flags, rest is the FQDN string
            hdr.clientFqdn = std::string(
                reinterpret_cast<const char*>(ptr + optOffset + 4 + 1), optLen - 1);
        }

        optOffset += 4 + optLen;
    }

    offset += optOffset;
    return hdr;
}

} // namespace fdpi
