#include <fdpi/protocol/nbdgm.hpp>
#include <fdpi/protocol/nbns.hpp>

namespace fdpi {

std::expected<NBDGM, Error> decodeNbdgm(const std::span<const uint8_t> data,
                                        size_t& offset) {
    constexpr size_t kMinSize = 10;

    if (data.size() < offset + kMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    NBDGM hdr{};
    hdr.messageType = ptr[0];
    hdr.flags = ptr[1];
    hdr.dgmId = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.sourceIp = IPv4Address(std::array<uint8_t, 4>{ptr[4], ptr[5], ptr[6], ptr[7]});
    hdr.sourcePort = static_cast<uint16_t>((ptr[8] << 8) | ptr[9]);

    offset += kMinSize;

    // For direct/broadcast datagrams (0x10-0x12), parse additional fields
    if (hdr.messageType >= 0x10 && hdr.messageType <= 0x12) {
        if (data.size() < offset + 4) {
            return std::unexpected(Error::TruncatedHeader);
        }

        hdr.dgmLength = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
        hdr.packetOffset =
            static_cast<uint16_t>((data[offset + 2] << 8) | data[offset + 3]);
        offset += 4;

        // Decode source and destination NetBIOS names
        hdr.sourceName = decodeNetbiosName(data, offset);
        hdr.destinationName = decodeNetbiosName(data, offset);
    }

    return hdr;
}

} // namespace fdpi
