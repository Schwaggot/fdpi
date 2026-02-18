#ifndef FDPI_DECODER_HPP
#define FDPI_DECODER_HPP

#include <chrono>
#include <concepts>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>

#include <fdpi/error.hpp>
#include <fdpi/flow_table.hpp>
#include <fdpi/packet.hpp>

namespace fdpi {

struct IpDefragmenterConfig {
    std::chrono::seconds timeout{30};
    size_t maxFragments{10'000};
};

class IpDefragmenter {
public:
    using Config = IpDefragmenterConfig;

    explicit IpDefragmenter(Config config = {});
    ~IpDefragmenter();

    std::optional<std::vector<uint8_t>> process(std::span<const uint8_t> fragment,
                                                const IPv4& header) const;
    static size_t cleanupExpired(Timestamp now);

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};

struct TcpReassemblerConfig {
    std::chrono::seconds streamTimeout{60};
    size_t maxStreams{100'000};
    size_t maxStreamBytes{10 * 1024 * 1024};
};

struct ReassemblyResult {
    std::optional<std::vector<uint8_t>> data;
    bool retransmission{false};
};

class TcpReassembler {
public:
    using Config = TcpReassemblerConfig;

    explicit TcpReassembler(const Config& config = {});
    ~TcpReassembler();

    ReassemblyResult process(const FlowId& flowId,
                             const TCP& header,
                             std::span<const uint8_t> payload) const;
    static size_t cleanupExpired(Timestamp now);

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};

class ProtocolDetectionEngine {
public:
    ProtocolDetectionEngine();
    ~ProtocolDetectionEngine();

    [[nodiscard]] AppProtocol detect(const Packet& packet,
                                     std::span<const uint8_t> payload) const;
    [[nodiscard]] AppProtocol detectFlow(const FlowId& flowId,
                                         const Packet& packet,
                                         std::span<const uint8_t> payload,
                                         size_t maxPackets = 10);

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};

struct PacketDecoderConfig {
    bool enableDefragmentation{true};
    bool enableTcpReassembly{true};
    bool enableProtocolDetection{true};
    size_t maxL7StreamBytes{1 * 1024 * 1024}; // 1MB per-flow L7 buffer limit
    FlowTableConfig flowTableConfig{};
    IpDefragmenterConfig defragConfig{};
    TcpReassemblerConfig reassemblyConfig{};
};

template <typename T>
concept PacketSource = requires(const T& p) {
    { p.data } -> std::convertible_to<const uint8_t*>;
    { p.captureLength } -> std::convertible_to<std::size_t>;
};

class PacketDecoder {
public:
    using Config = PacketDecoderConfig;

    explicit PacketDecoder(Config config = {});
    ~PacketDecoder();

    std::expected<Packet, Error>
    decode(std::span<const uint8_t> data,
           Timestamp timestamp = {},
           DataLinkType dlt = DataLinkType::DLT_EN10MB) const;

    template <PacketSource P>
    std::expected<Packet, Error> decode(const P& source) const {
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

        return decode({source.data, static_cast<std::size_t>(source.captureLength)}, ts,
                      dlt);
    }

    const FlowTable& flows() const;
    FlowTable& flows();

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};

class PacketHandler {
public:
    virtual ~PacketHandler() = default;
    virtual void onPacket(const Packet& packet) = 0;
    virtual void onError(const Error error, const std::span<const uint8_t> rawData) {
        (void)error;
        (void)rawData;
    }
    virtual void onFlowExpired(const FlowMetadata& flow) { (void)flow; }
};

} // namespace fdpi

#endif // FDPI_DECODER_HPP
