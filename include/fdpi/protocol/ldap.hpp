#ifndef FDPI_PROTOCOL_LDAP_HPP
#define FDPI_PROTOCOL_LDAP_HPP

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>

#include <fdpi/error.hpp>

namespace fdpi {

enum class LdapOperation : uint8_t {
    BindRequest = 0x60,
    BindResponse = 0x61,
    UnbindRequest = 0x42,
    SearchRequest = 0x63,
    SearchResultEntry = 0x64,
    SearchResultDone = 0x65,
    ModifyRequest = 0x66,
    ModifyResponse = 0x67,
    AddRequest = 0x68,
    AddResponse = 0x69,
    DeleteRequest = 0x4A,
    DeleteResponse = 0x6B,
};

struct LDAP {
    uint32_t messageId;
    LdapOperation operation;
    std::optional<uint8_t> ldapVersion; // for BindRequest
    std::optional<std::string> bindDn;  // for BindRequest
};

std::expected<LDAP, Error> decodeLdap(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_LDAP_HPP
