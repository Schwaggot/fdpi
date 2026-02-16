#include <fdpi/protocol/rdp.hpp>

#include <algorithm>
#include <cstring>
#include <string_view>

namespace fdpi {

std::expected<RDP, Error> decodeRdp(const std::span<const uint8_t> data, size_t& offset) {
    constexpr size_t kTpktSize = 4;
    constexpr size_t kX224Min = 7; // LI(1) + type/credit(1) + dstRef(2)
                                   // + srcRef(2) + classOption(1)
    constexpr size_t kMinSize = kTpktSize + kX224Min;

    if (data.size() < offset + kMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    // TPKT header
    const uint8_t tpktVersion = ptr[0];
    if (tpktVersion != 3) {
        return std::unexpected(Error::MalformedPacket);
    }

    RDP rdp{};
    rdp.tpktVersion = tpktVersion;
    // reserved byte at ptr[1]
    rdp.tpktLength = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);

    if (data.size() < offset + rdp.tpktLength) {
        return std::unexpected(Error::TruncatedHeader);
    }

    // X.224 COTP Connection
    // ptr[4] = length indicator
    const uint8_t typeByte = ptr[5];
    rdp.x224Type = typeByte & 0xF0; // upper nibble
    rdp.dstRef = static_cast<uint16_t>((ptr[6] << 8) | ptr[7]);
    rdp.srcRef = static_cast<uint16_t>((ptr[8] << 8) | ptr[9]);
    rdp.classOption = ptr[10];

    const uint8_t* payload = ptr + kMinSize;
    const size_t remaining = static_cast<size_t>(rdp.tpktLength) - kMinSize;

    if (rdp.x224Type == 0xE0) {
        // Connection Request - scan for cookie and negotiation
        std::string_view sv(reinterpret_cast<const char*>(payload), remaining);

        // Look for cookie
        constexpr std::string_view kCookiePrefix = "Cookie:";
        const auto cookiePos = sv.find(kCookiePrefix);
        if (cookiePos != std::string_view::npos) {
            const auto crlfPos = sv.find("\r\n", cookiePos);
            if (crlfPos != std::string_view::npos) {
                rdp.cookie = std::string(sv.substr(cookiePos, crlfPos - cookiePos + 2));
            }
        }

        // Look for RDP Negotiation Request (type 0x01)
        for (size_t i = 0; i + 8 <= remaining; ++i) {
            if (payload[i] == 0x01 && payload[i + 1] == 0x00 && payload[i + 2] == 0x08 &&
                payload[i + 3] == 0x00) {
                rdp.requestedProtocols = static_cast<uint32_t>(payload[i + 4]) |
                                         (static_cast<uint32_t>(payload[i + 5]) << 8) |
                                         (static_cast<uint32_t>(payload[i + 6]) << 16) |
                                         (static_cast<uint32_t>(payload[i + 7]) << 24);
                break;
            }
        }
    } else if (rdp.x224Type == 0xD0) {
        // Connection Confirm - look for negotiation response
        for (size_t i = 0; i + 8 <= remaining; ++i) {
            if (payload[i] == 0x02 && payload[i + 1] == 0x00 && payload[i + 2] == 0x08 &&
                payload[i + 3] == 0x00) {
                rdp.selectedProtocol = static_cast<uint32_t>(payload[i + 4]) |
                                       (static_cast<uint32_t>(payload[i + 5]) << 8) |
                                       (static_cast<uint32_t>(payload[i + 6]) << 16) |
                                       (static_cast<uint32_t>(payload[i + 7]) << 24);
                break;
            }
        }
    }

    offset += rdp.tpktLength;
    return rdp;
}

} // namespace fdpi
