#include <fdpi/protocol/ntp.hpp>

namespace fdpi {

std::expected<NTP, Error> decodeNtp(const std::span<const uint8_t> data, size_t& offset) {
    constexpr size_t kNtpSize = 48;

    if (data.size() < offset + kNtpSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    NTP hdr{};
    hdr.leapIndicator = (ptr[0] >> 6) & 0x03;
    hdr.version = (ptr[0] >> 3) & 0x07;
    hdr.mode = ptr[0] & 0x07;
    hdr.stratum = ptr[1];
    hdr.poll = static_cast<int8_t>(ptr[2]);
    hdr.precision = static_cast<int8_t>(ptr[3]);

    auto read32 = [](const uint8_t* p) -> uint32_t {
        return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
    };

    auto read64 = [](const uint8_t* p) -> uint64_t {
        return (static_cast<uint64_t>(p[0]) << 56) | (static_cast<uint64_t>(p[1]) << 48) |
               (static_cast<uint64_t>(p[2]) << 40) | (static_cast<uint64_t>(p[3]) << 32) |
               (static_cast<uint64_t>(p[4]) << 24) | (static_cast<uint64_t>(p[5]) << 16) |
               (static_cast<uint64_t>(p[6]) << 8) | static_cast<uint64_t>(p[7]);
    };

    hdr.rootDelay = read32(ptr + 4);
    hdr.rootDispersion = read32(ptr + 8);
    hdr.referenceId = read32(ptr + 12);
    hdr.referenceTimestamp = read64(ptr + 16);
    hdr.originTimestamp = read64(ptr + 24);
    hdr.receiveTimestamp = read64(ptr + 32);
    hdr.transmitTimestamp = read64(ptr + 40);

    offset += kNtpSize;
    return hdr;
}

} // namespace fdpi
