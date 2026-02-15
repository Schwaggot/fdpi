#include <fdpi/decoder.hpp>
#include <map>
#include <ranges>
#include <unordered_map>

namespace fdpi {

struct IpDefragmenter::Impl {
    struct FragmentGroup {
        uint16_t identification;
        IPv4Address srcIp;
        IPv4Address dstIp;
        bool operator==(const FragmentGroup&) const = default;
    };

    struct FragmentGroupHash {
        size_t operator()(const FragmentGroup& g) const noexcept {
            size_t h = std::hash<uint16_t>{}(g.identification);
            h ^= std::hash<uint32_t>{}(g.srcIp.toUint32()) + 0x9e3779b9 + (h << 6) +
                 (h >> 2);
            h ^= std::hash<uint32_t>{}(g.dstIp.toUint32()) + 0x9e3779b9 + (h << 6) +
                 (h >> 2);
            return h;
        }
    };

    struct FragmentBuffer {
        std::map<uint16_t, std::vector<uint8_t>> fragments; // offset -> data
        bool lastFragmentReceived{false};
        uint64_t firstSeen{0};
        size_t totalExpectedSize{0};
    };

    IpDefragmenter::Config config;
    std::unordered_map<FragmentGroup, FragmentBuffer, FragmentGroupHash> groups;
};

IpDefragmenter::IpDefragmenter(const Config config) : mImpl(std::make_unique<Impl>()) {
    mImpl->config = config;
}

IpDefragmenter::~IpDefragmenter() = default;

std::optional<std::vector<uint8_t>>
IpDefragmenter::process(const std::span<const uint8_t> fragment,
                        const IPv4& header) const {
    // Not a fragment
    if (header.fragmentOffset == 0 && (header.flags & 0x01) == 0) {
        return std::nullopt;
    }

    const Impl::FragmentGroup key{header.identification, header.srcIp, header.dstIp};

    auto& buf = mImpl->groups[key];
    if (buf.fragments.empty()) {
        buf.firstSeen = 0; // would use timestamp in real impl
    }

    const size_t headerLen = static_cast<size_t>(header.ihl) * 4;
    const size_t fragDataLen = header.totalLength - headerLen;
    const uint16_t fragOffset = header.fragmentOffset * 8;

    // Store fragment data (payload after IP header)
    if (fragment.size() >= headerLen) {
        buf.fragments[fragOffset] = std::vector<uint8_t>(
            fragment.data() + headerLen, fragment.data() + headerLen + fragDataLen);
    }

    // Check if this is the last fragment (MF=0 and offset>0)
    if ((header.flags & 0x01) == 0 && header.fragmentOffset > 0) {
        buf.lastFragmentReceived = true;
        buf.totalExpectedSize = fragOffset + fragDataLen;
    }

    // Check if reassembly is complete
    if (!buf.lastFragmentReceived) {
        return std::nullopt;
    }

    // Verify all fragments are present
    size_t assembled = 0;
    for (const auto& [off, data] : buf.fragments) {
        if (off != assembled) {
            return std::nullopt; // gap found
        }
        assembled += data.size();
    }

    if (assembled != buf.totalExpectedSize) {
        return std::nullopt;
    }

    // Assemble
    std::vector<uint8_t> result;
    result.reserve(assembled);
    for (const auto& data : buf.fragments | std::views::values) {
        result.insert(result.end(), data.begin(), data.end());
    }

    mImpl->groups.erase(key);
    return result;
}

size_t IpDefragmenter::cleanupExpired(uint64_t /*nowTimestamp*/) {
    // Simplified: in production would check timestamps
    return 0;
}

} // namespace fdpi
