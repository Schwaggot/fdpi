#include <fdpi/protocol/snmp.hpp>

#include "asn1.hpp"

namespace fdpi {

std::expected<SNMP, Error> decodeSnmp(const std::span<const uint8_t> data,
                                      size_t& offset) {
    size_t pos = offset;

    // Outer SEQUENCE tag
    auto seqTag = detail::readAsn1Tag(data, pos);
    if (!seqTag) {
        return std::unexpected(seqTag.error());
    }
    if (*seqTag != 0x30) {
        return std::unexpected(Error::MalformedPacket);
    }

    auto seqLen = detail::readAsn1Length(data, pos);
    if (!seqLen) {
        return std::unexpected(seqLen.error());
    }
    if (pos + *seqLen > data.size()) {
        return std::unexpected(Error::TruncatedHeader);
    }

    size_t seqEnd = pos + *seqLen;

    // Version INTEGER
    auto version = detail::readAsn1Integer(data, pos);
    if (!version) {
        return std::unexpected(version.error());
    }

    SNMP snmp{};
    snmp.version = static_cast<uint8_t>(*version);

    if (snmp.version <= 1) {
        // v1 or v2c: read community string
        auto community = detail::readAsn1OctetString(data, pos);
        if (!community) {
            return std::unexpected(community.error());
        }
        snmp.community = std::move(*community);

        // PDU tag (context-specific constructed: 0xA0-0xA8)
        auto pduTag = detail::readAsn1Tag(data, pos);
        if (!pduTag) {
            return std::unexpected(pduTag.error());
        }
        if (*pduTag < 0xA0 || *pduTag > 0xA8) {
            return std::unexpected(Error::MalformedPacket);
        }
        snmp.pduType = static_cast<SnmpPduType>(*pduTag);

        auto pduLen = detail::readAsn1Length(data, pos);
        if (!pduLen) {
            return std::unexpected(pduLen.error());
        }
        if (pos + *pduLen > data.size()) {
            return std::unexpected(Error::TruncatedHeader);
        }

        // First field inside PDU is requestId
        auto reqId = detail::readAsn1Integer(data, pos);
        if (!reqId) {
            return std::unexpected(reqId.error());
        }
        snmp.requestId = static_cast<uint32_t>(*reqId);
    }
    // v3: just store version, skip rest

    offset = seqEnd;
    return snmp;
}

} // namespace fdpi
