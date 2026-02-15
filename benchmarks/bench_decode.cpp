#include <fdpi/fdpi.hpp>
#include <benchmark/benchmark.h>
#include <vector>

namespace {

// Synthetic Ethernet+IPv4+TCP packet (54 bytes)
const std::vector<uint8_t> kTcpPacket = {
    // Ethernet header (14 bytes)
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
    0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // src MAC
    0x08, 0x00,                           // EtherType: IPv4
    // IPv4 header (20 bytes)
    0x45, 0x00, 0x00, 0x28, // version, IHL, DSCP, ECN, total length
    0x00, 0x01, 0x00, 0x00, // identification, flags, fragment offset
    0x40, 0x06, 0x00, 0x00, // TTL, protocol (TCP), checksum
    0xC0, 0xA8, 0x01, 0x01, // src IP: 192.168.1.1
    0xC0, 0xA8, 0x01, 0x02, // dst IP: 192.168.1.2
    // TCP header (20 bytes)
    0x00, 0x50, 0x1F, 0x90, // src port: 80, dst port: 8080
    0x00, 0x00, 0x00, 0x01, // seq num
    0x00, 0x00, 0x00, 0x00, // ack num
    0x50, 0x02, 0xFF, 0xFF, // data offset, flags, window
    0x00, 0x00, 0x00, 0x00, // checksum, urgent pointer
};

} // anonymous namespace

static void BM_DecodeEthIPv4TCP(benchmark::State& state) {
    fdpi::PacketDecoder decoder;
    for (auto _ : state) {
        auto result = decoder.decode(kTcpPacket);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_DecodeEthIPv4TCP);
