#ifndef FDPI_PROTOCOL_ASN1_HPP
#define FDPI_PROTOCOL_ASN1_HPP

#include <cstdint>
#include <expected>
#include <span>
#include <string>

#include <fdpi/error.hpp>

namespace fdpi::detail {

// Read BER tag byte. Returns the tag value and advances pos.
std::expected<uint8_t, Error> readAsn1Tag(std::span<const uint8_t> data, size_t& pos);

// Read BER length. Returns the length value and advances pos.
std::expected<size_t, Error> readAsn1Length(std::span<const uint8_t> data, size_t& pos);

// Read a BER INTEGER. Verifies tag 0x02, reads length and value.
std::expected<int64_t, Error> readAsn1Integer(std::span<const uint8_t> data, size_t& pos);

// Read a BER OCTET STRING. Verifies tag 0x04, reads length and value.
std::expected<std::string, Error> readAsn1OctetString(std::span<const uint8_t> data,
                                                      size_t& pos);

// Skip over one complete TLV. Reads tag + length and advances pos past value.
std::expected<size_t, Error> skipAsn1Value(std::span<const uint8_t> data, size_t& pos);

} // namespace fdpi::detail

#endif // FDPI_PROTOCOL_ASN1_HPP
