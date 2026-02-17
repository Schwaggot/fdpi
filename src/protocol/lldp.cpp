#include <fdpi/protocol/lldp.hpp>

#include <cstdio>

namespace fdpi {

namespace {

std::string formatMac(const uint8_t* data, size_t len) {
    if (len != 6) {
        return std::string(reinterpret_cast<const char*>(data), len);
    }
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", data[0], data[1],
                  data[2], data[3], data[4], data[5]);
    return buf;
}

} // anonymous namespace

std::expected<LLDP, Error> decodeLldp(const std::span<const uint8_t> data,
                                      size_t& offset) {
    // Minimum: at least one TLV (2 bytes for End-of-LLDPDU)
    if (data.size() < offset + 2) {
        return std::unexpected(Error::TruncatedHeader);
    }

    LLDP hdr{};

    while (offset + 2 <= data.size()) {
        const uint8_t* p = data.data() + offset;
        // TLV header: 7-bit type + 9-bit length
        const uint16_t tlvHeader = static_cast<uint16_t>((p[0] << 8) | p[1]);
        const uint16_t tlvType = (tlvHeader >> 9) & 0x7F;
        const uint16_t tlvLength = tlvHeader & 0x01FF;
        offset += 2;

        if (tlvType == 0) {
            // End of LLDPDU
            break;
        }

        if (data.size() < offset + tlvLength) {
            return std::unexpected(Error::TruncatedHeader);
        }

        const uint8_t* val = data.data() + offset;

        LldpTlv tlv;
        tlv.type = tlvType;
        tlv.value.assign(val, val + tlvLength);
        hdr.tlvs.push_back(std::move(tlv));

        switch (tlvType) {
        case 1: // Chassis ID — first byte is subtype
            if (tlvLength > 1) {
                const uint8_t subtype = val[0];
                if (subtype == 4 && tlvLength == 7) { // MAC address
                    hdr.chassisId = formatMac(val + 1, 6);
                } else {
                    hdr.chassisId.assign(reinterpret_cast<const char*>(val + 1),
                                         tlvLength - 1);
                }
            }
            break;
        case 2: // Port ID — first byte is subtype
            if (tlvLength > 1) {
                const uint8_t subtype = val[0];
                if (subtype == 3 && tlvLength == 7) { // MAC address
                    hdr.portId = formatMac(val + 1, 6);
                } else {
                    hdr.portId.assign(reinterpret_cast<const char*>(val + 1),
                                      tlvLength - 1);
                }
            }
            break;
        case 3: // TTL
            if (tlvLength >= 2) {
                hdr.ttl = static_cast<uint16_t>((val[0] << 8) | val[1]);
            }
            break;
        case 5: // System Name
            hdr.systemName = std::string(reinterpret_cast<const char*>(val), tlvLength);
            break;
        case 6: // System Description
            hdr.systemDescription =
                std::string(reinterpret_cast<const char*>(val), tlvLength);
            break;
        default:
            break;
        }

        offset += tlvLength;
    }

    return hdr;
}

} // namespace fdpi
