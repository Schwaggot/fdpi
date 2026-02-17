#ifndef FDPI_PROCESSOR_HPP
#define FDPI_PROCESSOR_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <thread>
#include <utility>
#include <vector>

#include <fdpi/decoder.hpp>

namespace fdpi {

enum class DistributionStrategy {
    FlowPinned,
    RoundRobin,
};

struct PacketProcessorConfig {
    size_t numThreads{std::thread::hardware_concurrency()};
    DistributionStrategy strategy{DistributionStrategy::FlowPinned};
    PacketDecoderConfig decoderConfig{};
};

class PacketProcessor {
public:
    using Config = PacketProcessorConfig;

    explicit PacketProcessor(Config config = {});
    ~PacketProcessor();

    void setHandler(std::shared_ptr<PacketHandler> handler) const;

    void submit(std::span<const uint8_t> data,
                Timestamp timestamp = {},
                DataLinkType dlt = DataLinkType::DLT_EN10MB) const;
    void submit(std::vector<uint8_t>&& data,
                Timestamp timestamp = {},
                DataLinkType dlt = DataLinkType::DLT_EN10MB) const;
    void submitBatch(
        std::span<const std::pair<std::span<const uint8_t>, Timestamp>> packets) const;

    template <PacketSource P>
    void submit(const P& source) const {
        Timestamp ts{};
        if constexpr (requires {
                          { source.timestampSeconds } -> std::convertible_to<uint64_t>;
                      }) {
            ts = Timestamp{std::chrono::seconds{source.timestampSeconds}};
            if constexpr (requires {
                              {
                                  source.timestampMicroseconds
                              } -> std::convertible_to<uint64_t>;
                          })
                ts += std::chrono::microseconds{source.timestampMicroseconds};
        }

        DataLinkType dlt = DataLinkType::DLT_EN10MB;
        if constexpr (requires {
                          { source.dataLinkType } -> std::convertible_to<uint16_t>;
                      })
            dlt = static_cast<DataLinkType>(source.dataLinkType);

        submit({source.data, static_cast<std::size_t>(source.captureLength)}, ts, dlt);
    }

    void start() const;
    void stop() const;
    void flush() const;

    [[nodiscard]] size_t packetsProcessed() const;
    [[nodiscard]] size_t packetsDropped() const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};

} // namespace fdpi

#endif // FDPI_PROCESSOR_HPP
