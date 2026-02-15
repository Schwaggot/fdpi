#include <algorithm>
#include <fdpi/flow_table.hpp>
#include <fdpi/packet.hpp>
#include <ranges>

namespace fdpi {

FlowTable::FlowTable(const Config& config) : mConfig(config) {}

FlowMetadata& FlowTable::update(const Packet& packet) {
    std::lock_guard<std::mutex> lock(mMutex);

    // Normalize the flow ID for bidirectional matching
    FlowId normalizedId = packet.flowId;

    // Normalize: ensure the "smaller" IP/port combo is always src
    bool shouldSwap = false;
    if (normalizedId.srcIp > normalizedId.dstIp ||
        (normalizedId.srcIp == normalizedId.dstIp &&
         normalizedId.srcPort > normalizedId.dstPort)) {
        shouldSwap = true;
    }

    if (shouldSwap) {
        std::swap(normalizedId.srcIp, normalizedId.dstIp);
        std::swap(normalizedId.srcPort, normalizedId.dstPort);
    }

    auto it = mFlows.find(normalizedId);
    if (it == mFlows.end()) {
        if (mFlows.size() >= mConfig.maxFlows) {
            // Evict oldest flow
            auto oldest = mFlows.begin();
            for (auto check = mFlows.begin(); check != mFlows.end(); ++check) {
                if (check->second.lastSeen < oldest->second.lastSeen) {
                    oldest = check;
                }
            }
            mFlows.erase(oldest);
        }

        FlowMetadata meta{};
        meta.flowId = normalizedId;
        meta.firstSeen = packet.timestamp;
        meta.lastSeen = packet.timestamp;
        meta.packetCount = 1;
        meta.byteCount = packet.captureLength;

        auto [inserted, _] = mFlows.emplace(normalizedId, meta);
        return inserted->second;
    }

    it->second.lastSeen = packet.timestamp;
    it->second.packetCount++;
    it->second.byteCount += packet.captureLength;
    return it->second;
}

std::optional<FlowMetadata> FlowTable::lookup(const FlowId& id) const {
    std::lock_guard lock(mMutex);
    const auto it = mFlows.find(id);
    if (it != mFlows.end()) {
        return it->second;
    }
    return std::nullopt;
}

size_t FlowTable::cleanupExpired(const uint64_t nowTimestamp) {
    std::lock_guard lock(mMutex);
    size_t removed = 0;

    const uint64_t timeoutNs =
        static_cast<uint64_t>(mConfig.flowTimeout.count()) * 1'000'000'000ULL;

    for (auto it = mFlows.begin(); it != mFlows.end();) {
        if (nowTimestamp > it->second.lastSeen &&
            (nowTimestamp - it->second.lastSeen) > timeoutNs) {
            it = mFlows.erase(it);
            removed++;
        } else {
            ++it;
        }
    }

    return removed;
}

void FlowTable::forEach(const std::function<void(const FlowMetadata&)>& visitor) const {
    std::lock_guard lock(mMutex);
    for (const auto& meta : mFlows | std::views::values) {
        visitor(meta);
    }
}

size_t FlowTable::size() const {
    std::lock_guard lock(mMutex);
    return mFlows.size();
}

} // namespace fdpi
