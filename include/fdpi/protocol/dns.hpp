#ifndef FDPI_PROTOCOL_DNS_HPP
#define FDPI_PROTOCOL_DNS_HPP

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

#include <fdpi/error.hpp>

namespace fdpi {

struct DnsQuestion {
    std::string name;
    uint16_t    type;
    uint16_t    qclass;
};

struct DnsRecord {
    std::string name;
    uint16_t    type;
    uint16_t    rclass;
    uint32_t    ttl;
    std::vector<uint8_t> rdata;
};

struct DNS {
    uint16_t id;
    bool     isResponse;
    uint8_t  opcode;
    uint8_t  rcode;
    bool     authoritative;
    bool     truncated;
    bool     recursionDesired;
    bool     recursionAvailable;
    std::vector<DnsQuestion> questions;
    std::vector<DnsRecord>   answers;
    std::vector<DnsRecord>   authorities;
    std::vector<DnsRecord>   additionals;
};

std::expected<DNS, Error> decodeDns(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_DNS_HPP
