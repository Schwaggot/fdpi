#include <cstring>
#include <fdpi/protocol/ethernet.hpp>

namespace fdpi {

std::expected<Ethernet, Error> decodeEthernet(const std::span<const uint8_t> data,
                                              size_t& offset) {
    constexpr size_t kEthernetMinSize = 14; // 6 + 6 + 2

    if (data.size() < offset + kEthernetMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    Ethernet hdr{};
    const uint8_t* ptr = data.data() + offset;

    std::memcpy(hdr.dst.bytes.data(), ptr, 6); // MacAddress is in fdpi namespace
    ptr += 6;
    std::memcpy(hdr.src.bytes.data(), ptr, 6);
    ptr += 6;

    hdr.etherType = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);
    offset += kEthernetMinSize;

    return hdr;
}

std::expected<VlanTag, Error> decodeVlan(const std::span<const uint8_t> data,
                                         size_t& offset) {
    constexpr size_t kVlanSize = 4; // TCI (2) + inner EtherType (2)

    if (data.size() < offset + kVlanSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    VlanTag tag{};
    const uint8_t* ptr = data.data() + offset;

    tag.tci = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);
    ptr += 2;
    tag.etherType = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);
    offset += kVlanSize;

    return tag;
}

} // namespace fdpi
