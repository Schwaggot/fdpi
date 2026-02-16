#include <fdpi/protocol/dhcp.hpp>

#include <cstring>

namespace fdpi {

std::expected<DHCP, Error> decodeDhcp(const std::span<const uint8_t> data,
                                      size_t& offset) {
    constexpr size_t kHeaderSize = 236;
    constexpr size_t kMagicCookieSize = 4;
    constexpr size_t kMinSize = kHeaderSize + kMagicCookieSize;

    if (data.size() < offset + kMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    // Verify magic cookie at offset 236
    if (ptr[236] != 0x63 || ptr[237] != 0x82 || ptr[238] != 0x53 || ptr[239] != 0x63) {
        return std::unexpected(Error::MalformedPacket);
    }

    DHCP hdr{};
    hdr.op = ptr[0];
    hdr.htype = ptr[1];
    hdr.hlen = ptr[2];
    hdr.hops = ptr[3];

    hdr.xid = (static_cast<uint32_t>(ptr[4]) << 24) |
              (static_cast<uint32_t>(ptr[5]) << 16) |
              (static_cast<uint32_t>(ptr[6]) << 8) | static_cast<uint32_t>(ptr[7]);

    hdr.secs = static_cast<uint16_t>((ptr[8] << 8) | ptr[9]);
    hdr.flags = static_cast<uint16_t>((ptr[10] << 8) | ptr[11]);

    hdr.ciaddr = IPv4Address(std::array<uint8_t, 4>{ptr[12], ptr[13], ptr[14], ptr[15]});
    hdr.yiaddr = IPv4Address(std::array<uint8_t, 4>{ptr[16], ptr[17], ptr[18], ptr[19]});
    hdr.siaddr = IPv4Address(std::array<uint8_t, 4>{ptr[20], ptr[21], ptr[22], ptr[23]});
    hdr.giaddr = IPv4Address(std::array<uint8_t, 4>{ptr[24], ptr[25], ptr[26], ptr[27]});

    std::memcpy(hdr.chaddr.bytes.data(), ptr + 28, 6);

    // Parse options starting after magic cookie
    size_t optOffset = 240;
    while (optOffset < data.size() - offset) {
        uint8_t code = ptr[optOffset];
        if (code == 255) { // End option
            break;
        }
        if (code == 0) { // Pad option
            ++optOffset;
            continue;
        }
        if (optOffset + 1 >= data.size() - offset) {
            break;
        }
        uint8_t len = ptr[optOffset + 1];
        if (optOffset + 2 + len > data.size() - offset) {
            break;
        }

        DhcpOption opt;
        opt.code = code;
        opt.data.assign(ptr + optOffset + 2, ptr + optOffset + 2 + len);
        hdr.options.push_back(std::move(opt));

        if (code == 53 && len >= 1) {
            hdr.messageType = ptr[optOffset + 2];
        } else if (code == 12 && len > 0) {
            hdr.hostname =
                std::string(reinterpret_cast<const char*>(ptr + optOffset + 2), len);
        }

        optOffset += 2 + len;
    }

    offset += data.size() - (data.data() + offset - ptr);
    // Advance offset past all consumed data
    offset = data.size();

    return hdr;
}

} // namespace fdpi
