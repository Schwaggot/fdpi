#include <fdpi/decoder.hpp>
#include <map>
#include <unordered_map>

namespace fdpi {

struct TcpReassembler::Impl {
    struct StreamBuffer {
        std::map<uint32_t, std::vector<uint8_t>> segments; // seq -> data
        uint32_t nextExpectedSeq{0};
        bool synSeen{false};
        uint64_t lastSeen{0};
        size_t totalBytes{0};
    };

    TcpReassembler::Config config;
    std::unordered_map<FlowId, StreamBuffer, FlowIdHash> streams;
};

TcpReassembler::TcpReassembler(const Config& config) : mImpl(std::make_unique<Impl>()) {
    mImpl->config = config;
}

TcpReassembler::~TcpReassembler() = default;

std::optional<std::vector<uint8_t>> TcpReassembler::process(
    const FlowId& flowId, const TCP& header, std::span<const uint8_t> payload) const {
    if (payload.empty()) {
        return std::nullopt;
    }

    auto& stream = mImpl->streams[flowId];

    if (header.syn()) {
        stream.synSeen = true;
        stream.nextExpectedSeq = header.seqNum + 1;
        return std::nullopt;
    }

    if (!stream.synSeen) {
        stream.synSeen = true;
        stream.nextExpectedSeq = header.seqNum;
    }

    // Check stream size limit
    if (stream.totalBytes + payload.size() > mImpl->config.maxStreamBytes) {
        return std::nullopt;
    }

    // Store the segment
    stream.segments[header.seqNum] = std::vector(payload.begin(), payload.end());
    stream.totalBytes += payload.size();

    // Try to assemble in-order data
    std::vector<uint8_t> result;
    while (true) {
        auto it = stream.segments.find(stream.nextExpectedSeq);
        if (it == stream.segments.end()) {
            break;
        }

        result.insert(result.end(), it->second.begin(), it->second.end());
        stream.nextExpectedSeq += static_cast<uint32_t>(it->second.size());
        stream.totalBytes -= it->second.size();
        stream.segments.erase(it);
    }

    if (result.empty()) {
        return std::nullopt;
    }

    return result;
}

size_t TcpReassembler::cleanupExpired(Timestamp /*now*/) {
    return 0;
}

} // namespace fdpi
