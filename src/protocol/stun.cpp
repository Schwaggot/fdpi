#include <cstring>
#include <fdpi/protocol/stun.hpp>

namespace fdpi {

std::expected<STUN, Error> decodeStun(const std::span<const uint8_t> data,
                                      size_t& offset) {
    constexpr size_t kStunHeaderSize = 20;

    if (data.size() < offset + kStunHeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    STUN hdr{};
    hdr.type = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);
    hdr.length = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.magicCookie =
        (static_cast<uint32_t>(ptr[4]) << 24) | (static_cast<uint32_t>(ptr[5]) << 16) |
        (static_cast<uint32_t>(ptr[6]) << 8) | static_cast<uint32_t>(ptr[7]);
    std::memcpy(hdr.transactionId.data(), ptr + 8, 12);

    // Classify message class from type field (RFC 5389 §6)
    // Bits C0 and C1 encode the class:
    //   C1C0 = 00 → Request, 01 → Indication, 10 → Success, 11 → Error
    const uint8_t c0 = (hdr.type >> 4) & 0x01;
    const uint8_t c1 = (hdr.type >> 8) & 0x01;
    const uint8_t msgClass = static_cast<uint8_t>((c1 << 1) | c0);
    hdr.isRequest = (msgClass == 0x00);
    hdr.isIndication = (msgClass == 0x01);

    offset += kStunHeaderSize;

    // Parse attributes within the message body
    size_t attrEnd = offset + hdr.length;
    if (attrEnd > data.size()) {
        attrEnd = data.size();
    }

    while (offset + 4 <= attrEnd) {
        const uint8_t* ap = data.data() + offset;
        const uint16_t attrType = static_cast<uint16_t>((ap[0] << 8) | ap[1]);
        const uint16_t attrLength = static_cast<uint16_t>((ap[2] << 8) | ap[3]);
        offset += 4;

        if (offset + attrLength > attrEnd) {
            break;
        }

        const uint8_t* av = data.data() + offset;

        if (attrType == 0x0020 && attrLength >= 8) {
            // XOR-MAPPED-ADDRESS
            const uint8_t family = av[1];
            const uint16_t xport = static_cast<uint16_t>((av[2] << 8) | av[3]);
            hdr.mappedPort = xport ^ 0x2112;
            if (family == 0x01 && attrLength >= 8) {
                // IPv4
                const uint32_t xaddr = (static_cast<uint32_t>(av[4]) << 24) |
                                       (static_cast<uint32_t>(av[5]) << 16) |
                                       (static_cast<uint32_t>(av[6]) << 8) |
                                       static_cast<uint32_t>(av[7]);
                const uint32_t addr = xaddr ^ 0x2112A442;
                hdr.mappedAddress = IPv4Address(
                    std::array<uint8_t, 4>{static_cast<uint8_t>((addr >> 24) & 0xFF),
                                           static_cast<uint8_t>((addr >> 16) & 0xFF),
                                           static_cast<uint8_t>((addr >> 8) & 0xFF),
                                           static_cast<uint8_t>(addr & 0xFF)});
            } else if (family == 0x02 && attrLength >= 20) {
                // IPv6
                std::array<uint8_t, 16> addr{};
                // XOR with magic cookie (4 bytes) + transaction ID (12 bytes)
                uint8_t xorKey[16];
                xorKey[0] = 0x21;
                xorKey[1] = 0x12;
                xorKey[2] = 0xA4;
                xorKey[3] = 0x42;
                std::memcpy(xorKey + 4, hdr.transactionId.data(), 12);
                for (size_t i = 0; i < 16; ++i) {
                    addr[i] = av[4 + i] ^ xorKey[i];
                }
                hdr.mappedAddress = IPv6Address(addr);
            }
        } else if (attrType == 0x0001 && attrLength >= 8) {
            // MAPPED-ADDRESS (non-XOR, fallback)
            if (!hdr.mappedAddress) {
                const uint8_t family = av[1];
                hdr.mappedPort = static_cast<uint16_t>((av[2] << 8) | av[3]);
                if (family == 0x01 && attrLength >= 8) {
                    hdr.mappedAddress =
                        IPv4Address(std::array<uint8_t, 4>{av[4], av[5], av[6], av[7]});
                }
            }
        }

        // Advance past attribute value (padded to 4-byte boundary)
        const size_t padded = (attrLength + 3) & ~static_cast<size_t>(3);
        offset += padded;
    }

    // Ensure offset covers the full message
    offset = attrEnd;
    return hdr;
}

} // namespace fdpi
