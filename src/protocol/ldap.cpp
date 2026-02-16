#include "asn1.hpp"
#include <fdpi/protocol/ldap.hpp>

namespace fdpi {

std::expected<LDAP, Error> decodeLdap(const std::span<const uint8_t> data,
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

    // messageId INTEGER
    auto msgId = detail::readAsn1Integer(data, pos);
    if (!msgId) {
        return std::unexpected(msgId.error());
    }

    // Application tag byte (operation)
    auto opTag = detail::readAsn1Tag(data, pos);
    if (!opTag) {
        return std::unexpected(opTag.error());
    }

    auto opLen = detail::readAsn1Length(data, pos);
    if (!opLen) {
        return std::unexpected(opLen.error());
    }
    if (pos + *opLen > data.size()) {
        return std::unexpected(Error::TruncatedHeader);
    }

    LDAP ldap{};
    ldap.messageId = static_cast<uint32_t>(*msgId);
    ldap.operation = static_cast<LdapOperation>(*opTag);

    // For BindRequest (0x60), extract version and DN
    if (*opTag == 0x60) {
        auto ver = detail::readAsn1Integer(data, pos);
        if (!ver) {
            return std::unexpected(ver.error());
        }
        ldap.ldapVersion = static_cast<uint8_t>(*ver);

        auto dn = detail::readAsn1OctetString(data, pos);
        if (!dn) {
            return std::unexpected(dn.error());
        }
        ldap.bindDn = std::move(*dn);
    }

    offset = seqEnd;
    return ldap;
}

} // namespace fdpi
