#ifndef FDPI_DECODER_HPP
#define FDPI_DECODER_HPP

#include <chrono>
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
    static size_t cleanupExpired(uint64_t nowTimestamp);

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};

struct TcpReassemblerConfig {
    std::chrono::seconds streamTimeout{60};
    size_t maxStreams{100'000};
    size_t maxStreamBytes{10 * 1024 * 1024};
};

class TcpReassembler {
public:
    using Config = TcpReassemblerConfig;

    explicit TcpReassembler(const Config& config = {});
    ~TcpReassembler();

    std::optional<std::vector<uint8_t>> process(const FlowId& flowId,
                                                const TCP& header,
                                                std::span<const uint8_t> payload) const;
    static size_t cleanupExpired(uint64_t nowTimestamp);

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
    FlowTableConfig flowTableConfig{};
    IpDefragmenterConfig defragConfig{};
    TcpReassemblerConfig reassemblyConfig{};
};

class PacketDecoder {
public:
    using Config = PacketDecoderConfig;

    explicit PacketDecoder(Config config = {});
    ~PacketDecoder();

    std::expected<Packet, Error>
    decode(std::span<const uint8_t> data,
           uint64_t timestamp = 0,
           DataLinkType dlt = DataLinkType::DLT_EN10MB) const;

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
