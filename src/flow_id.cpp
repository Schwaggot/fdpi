#include <fdpi/flow_id.hpp>

namespace fdpi {

namespace {

// Boost-style hash combine
size_t hashCombine(const size_t seed, const size_t value) {
    return seed ^ (value + 0x9e3779b9 + (seed << 6) + (seed >> 2));
}

size_t hashIpAddress(size_t seed, const IpAddress& addr) {
    return std::visit(
        [seed](const auto& a) {
            size_t h = seed;
            for (auto b : a.bytes) {
                h = hashCombine(h, std::hash<uint8_t>{}(b));
            }
            return h;
        },
        addr);
}

} // anonymous namespace

std::size_t FlowIdHash::operator()(const FlowId& id) const noexcept {
    size_t h = 0;
    h = hashIpAddress(h, id.srcIp);
    h = hashIpAddress(h, id.dstIp);
    h = hashCombine(h, std::hash<uint16_t>{}(id.srcPort));
    h = hashCombine(h, std::hash<uint16_t>{}(id.dstPort));
    h = hashCombine(h, std::hash<uint8_t>{}(id.protocol));
    return h;
}

} // namespace fdpi
