#ifndef FDPI_PROTOCOL_MPLS_HPP
#define FDPI_PROTOCOL_MPLS_HPP

#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include <fdpi/error.hpp>

namespace fdpi {

struct MplsLabel {
    uint32_t label;
    uint8_t  tc;
    bool     bottomOfStack;
    uint8_t  ttl;
};

struct MPLS {
    std::vector<MplsLabel> labelStack;
};

std::expected<MPLS, Error> decodeMpls(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_MPLS_HPP
