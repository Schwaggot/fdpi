#ifndef FDPI_PROTOCOL_NBNS_HPP
#define FDPI_PROTOCOL_NBNS_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace fdpi {

struct NbnsQuestion {
    std::string name;
    uint16_t type;
    uint16_t qclass;
};

struct NbnsRecord {
    std::string name;
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    std::vector<uint8_t> rdata;
};

struct NBNS {
    uint16_t id;
    bool isResponse;
    uint8_t opcode;
    uint8_t rcode;
    std::vector<NbnsQuestion> questions;
    std::vector<NbnsRecord> answers;
    std::vector<NbnsRecord> authorities;
    std::vector<NbnsRecord> additionals;
};

// Decode a NetBIOS first-level encoded name from raw data
std::string decodeNetbiosName(std::span<const uint8_t> data, size_t& offset);

std::expected<NBNS, Error> decodeNbns(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_NBNS_HPP
