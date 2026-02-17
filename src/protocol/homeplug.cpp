#include <fdpi/protocol/homeplug.hpp>

namespace fdpi {

std::expected<HomePlug, Error> decodeHomeplug(const std::span<const uint8_t> data,
                                              size_t& offset) {
    constexpr size_t kMinSize = 5; // 1B version + 2B MMType + 2B frag info

    if (data.size() < offset + kMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    HomePlug hdr{};
    hdr.version = ptr[0];
    hdr.type = static_cast<uint16_t>(ptr[1] | (ptr[2] << 8)); // little-endian

    offset += kMinSize;
    return hdr;
}

} // namespace fdpi
