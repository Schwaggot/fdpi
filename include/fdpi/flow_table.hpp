#ifndef FDPI_FLOW_TABLE_HPP
#define FDPI_FLOW_TABLE_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <unordered_map>

#include <fdpi/flow_id.hpp>
#include <fdpi/timestamp.hpp>

namespace fdpi {

// Forward declaration
struct Packet;

struct FlowMetadata {
    FlowId flowId;
    Timestamp firstSeen{};
    Timestamp lastSeen{};
    uint64_t packetCount{0};
    uint64_t byteCount{0};
    std::optional<AppProtocol> detectedProtocol;
};

struct FlowTableConfig {
    std::chrono::seconds flowTimeout{60};
    std::chrono::seconds reassemblyTimeout{30};
    size_t maxFlows{1'000'000};
};

class FlowTable {
public:
    using Config = FlowTableConfig;

    explicit FlowTable(const Config& config = {});

    FlowMetadata& update(const Packet& packet);
    std::optional<FlowMetadata> lookup(const FlowId& id) const;
    size_t cleanupExpired(Timestamp now);
    void forEach(const std::function<void(const FlowMetadata&)>& visitor) const;
    size_t size() const;

private:
    Config mConfig;
    mutable std::mutex mMutex;
    std::unordered_map<FlowId, FlowMetadata, FlowIdHash> mFlows;
};

} // namespace fdpi

#endif // FDPI_FLOW_TABLE_HPP
