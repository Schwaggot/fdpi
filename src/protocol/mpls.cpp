#include <fdpi/protocol/mpls.hpp>

#include <cstring>

namespace fdpi {

std::expected<MPLS, Error> decodeMpls(const std::span<const uint8_t> data,
                                      size_t& offset) {
    constexpr size_t kMplsLabelSize = 4;

    MPLS hdr{};

    while (true) {
        if (data.size() < offset + kMplsLabelSize) {
            return std::unexpected(Error::TruncatedHeader);
        }

        const uint8_t* ptr = data.data() + offset;

        // MPLS label entry: 20-bit label | 3-bit TC | 1-bit S | 8-bit TTL
        uint32_t raw = (static_cast<uint32_t>(ptr[0]) << 24) |
                       (static_cast<uint32_t>(ptr[1]) << 16) |
                       (static_cast<uint32_t>(ptr[2]) << 8) |
                       static_cast<uint32_t>(ptr[3]);

        MplsLabel label{};
        label.label = (raw >> 12) & 0xFFFFF;
        label.tc = static_cast<uint8_t>((raw >> 9) & 0x07);
        label.bottomOfStack = (raw >> 8) & 0x01;
        label.ttl = static_cast<uint8_t>(raw & 0xFF);

        hdr.labelStack.push_back(label);
        offset += kMplsLabelSize;

        if (label.bottomOfStack) {
            break;
        }
    }

    return hdr;
}

} // namespace fdpi
