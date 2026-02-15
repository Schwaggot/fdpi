#ifndef FDPI_PROTOCOL_TCP_HPP
#define FDPI_PROTOCOL_TCP_HPP

#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include <fdpi/error.hpp>

namespace fdpi {

struct TCP {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t  dataOffset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentPointer;
    std::vector<uint8_t> options;

    bool fin() const { return flags & 0x01; }
    bool syn() const { return flags & 0x02; }
    bool rst() const { return flags & 0x04; }
    bool psh() const { return flags & 0x08; }
    bool ack() const { return flags & 0x10; }
    bool urg() const { return flags & 0x20; }
    bool ece() const { return flags & 0x40; }
    bool cwr() const { return flags & 0x80; }
};

std::expected<TCP, Error> decodeTcp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_TCP_HPP
