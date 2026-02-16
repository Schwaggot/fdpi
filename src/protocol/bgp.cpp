#include <fdpi/protocol/bgp.hpp>

#include <cstring>

namespace fdpi {

std::expected<BGP, Error> decodeBgp(const std::span<const uint8_t> data, size_t& offset) {
    constexpr size_t kMarkerSize = 16;
    constexpr size_t kMinHeader = 19; // marker(16) + length(2) + type(1)

    if (data.size() < offset + kMinHeader) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    // Verify 16-byte marker (all 0xFF)
    for (size_t i = 0; i < kMarkerSize; ++i) {
        if (ptr[i] != 0xFF) {
            return std::unexpected(Error::MalformedPacket);
        }
    }

    BGP bgp{};
    bgp.length = static_cast<uint16_t>((ptr[16] << 8) | ptr[17]);
    bgp.type = ptr[18];

    // Validate that the full message fits
    if (data.size() < offset + bgp.length) {
        return std::unexpected(Error::TruncatedHeader);
    }

    // For OPEN messages (type 1), parse additional fields
    if (bgp.type == 1) {
        constexpr size_t kOpenMin = 29; // 19 header + 10 open fields
        if (bgp.length < kOpenMin) {
            return std::unexpected(Error::TruncatedHeader);
        }
        bgp.version = ptr[19];
        bgp.myAs = static_cast<uint16_t>((ptr[20] << 8) | ptr[21]);
        bgp.holdTime = static_cast<uint16_t>((ptr[22] << 8) | ptr[23]);
        bgp.bgpId =
            IPv4Address(std::array<uint8_t, 4>{ptr[24], ptr[25], ptr[26], ptr[27]});
    }

    offset += bgp.length;
    return bgp;
}

} // namespace fdpi
