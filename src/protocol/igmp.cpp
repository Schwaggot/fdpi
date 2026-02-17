#include <fdpi/protocol/igmp.hpp>

namespace fdpi {

std::expected<IGMP, Error> decodeIgmp(const std::span<const uint8_t> data,
                                      size_t& offset) {
    constexpr size_t kIgmpMinSize = 8;

    if (data.size() < offset + kIgmpMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    IGMP hdr{};
    hdr.type = ptr[0];
    hdr.maxRespTime = ptr[1];
    hdr.checksum = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.groupAddress =
        IPv4Address(std::array<uint8_t, 4>{ptr[4], ptr[5], ptr[6], ptr[7]});

    offset += kIgmpMinSize;

    return hdr;
}

} // namespace fdpi
