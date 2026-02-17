#include <fdpi/protocol/esp.hpp>

namespace fdpi {

std::expected<ESP, Error> decodeEsp(const std::span<const uint8_t> data, size_t& offset) {
    constexpr size_t kEspMinSize = 8;

    if (data.size() < offset + kEspMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    ESP hdr{};
    hdr.spi = (static_cast<uint32_t>(ptr[0]) << 24) |
              (static_cast<uint32_t>(ptr[1]) << 16) |
              (static_cast<uint32_t>(ptr[2]) << 8) | static_cast<uint32_t>(ptr[3]);
    hdr.sequenceNumber =
        (static_cast<uint32_t>(ptr[4]) << 24) | (static_cast<uint32_t>(ptr[5]) << 16) |
        (static_cast<uint32_t>(ptr[6]) << 8) | static_cast<uint32_t>(ptr[7]);

    offset += kEspMinSize;

    return hdr;
}

} // namespace fdpi
