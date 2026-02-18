#include <fdpi/decoder.hpp>
#include <map>
#include <unordered_map>

namespace fdpi {

namespace {

inline bool seqBeforeOrEqual(const uint32_t a, const uint32_t b) {
    return static_cast<int32_t>(a - b) <= 0;
}

} // anonymous namespace

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

ReassemblyResult TcpReassembler::process(const FlowId& flowId,
                                         const TCP& header,
                                         std::span<const uint8_t> payload) const {
    auto& stream = mImpl->streams[flowId];

    // Handle SYN
    if (header.syn()) {
        bool retransmission = stream.synSeen;
        stream.synSeen = true;
        stream.nextExpectedSeq = header.seqNum + 1;
        return ReassemblyResult{{}, retransmission};
    }

    if (payload.empty()) {
        return ReassemblyResult{};
    }

    if (!stream.synSeen) {
        stream.synSeen = true;
        stream.nextExpectedSeq = header.seqNum;
    }

    // Check stream size limit
    if (stream.totalBytes + payload.size() > mImpl->config.maxStreamBytes) {
        return ReassemblyResult{};
    }

    // Retransmission detection
    bool retransmission = false;
    uint32_t seqEnd = header.seqNum + static_cast<uint32_t>(payload.size());

    // Case 1: Entire segment already delivered
    if (seqBeforeOrEqual(seqEnd, stream.nextExpectedSeq)) {
        retransmission = true;
    }
    // Case 2: Duplicate of buffered out-of-order segment
    else if (auto it = stream.segments.find(header.seqNum);
             it != stream.segments.end() && it->second.size() == payload.size()) {
        retransmission = true;
    }

    // Skip insertion for retransmissions
    if (retransmission) {
        return ReassemblyResult{{}, true};
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

    return ReassemblyResult{
        result.empty() ? std::nullopt : std::optional(std::move(result)), false};
}

size_t TcpReassembler::cleanupExpired(Timestamp /*now*/) {
    return 0;
}

} // namespace fdpi
