# FDPI - A fast deep packet inspection library

[![license](https://img.shields.io/github/license/fpcap/fdpi)](https://github.com/fpcap/fdpi/blob/main/LICENSE)

FDPI is a modern, high-performance C++23 library for deep packet inspection. It takes raw network packet bytes as input,
decodes protocol layers (L2–L7), tracks flows, performs application-layer protocol detection, and provides structured
access to decoded fields. It is designed as a fast, zero-dependency alternative to libraries such as libtins and nDPI.

FDPI operates purely on byte buffers — it does not capture packets itself. The companion library
[fpcap](https://github.com/fpcap/fpcap) is a natural fit for reading PCAP files but is not a dependency.

## Features

- Layered protocol decoding (L2 -> L3 -> L4 -> L7)
- Supported protocols:
    - L2: Ethernet, VLAN 802.1Q, MPLS
    - L3: IPv4, IPv6, ARP, RARP
    - L4: TCP, UDP, ICMP, ICMPv6, IGMP, ESP
    - Tunnel: GRE, VxLAN, GTP
    - L7: BGP, DHCP, DHCPv6, DNS, FTP, HTTP/1.x, IMAP, IMF, LDAP, LLMNR, mDNS, NBDGM, NBNS, NTP, POP3, QUIC,
      RDP, RTMP, SMB (v1/v2/v3), SMTP, SNMP (v1/v2c/v3), SSDP, SrvLoc, SSH, TLS (SNI/ALPN extraction)
- IP defragmentation and TCP stream reassembly
- Bidirectional flow tracking with timeout-based cleanup
- Application-layer protocol detection (port hints + payload DPI)
- Multi-threaded packet processing pipeline
- No exceptions — uses `std::expected` and `std::optional`
- Zero external dependencies (core library)
- Cross-platform: Linux, macOS, Windows

## Usage

### CMake Integration

```cmake
include(FetchContent)
FetchContent_Declare(
        fdpi
        GIT_REPOSITORY https://github.com/fpcap/fdpi.git
        GIT_TAG v0.1.0
)
FetchContent_MakeAvailable(fdpi)

target_link_libraries(your_target PRIVATE fdpi::fdpi)
```

### Basic Decoding

```cpp
#include <fdpi/fdpi.hpp>

fdpi::PacketDecoder decoder;

// raw packet bytes from any source (fpcap, libpcap, AF_PACKET, ...)
auto result = decoder.decode({data, length});
if (result) {
    const auto& pkt = result.value();

    if (auto* ipv4 = std::get_if<fdpi::IPv4>(&pkt.layer3)) {
        // ipv4->srcIp, ipv4->dstIp, ipv4->ttl, ...
    }

    if (auto* tcp = std::get_if<fdpi::TCP>(&pkt.layer4)) {
        // tcp->srcPort, tcp->dstPort, tcp->syn(), ...
    }

    if (auto* dns = std::get_if<fdpi::DNS>(&pkt.layer7)) {
        // dns->questions, dns->answers, ...
    }
}
```

### With fpcap

Any struct with `data` and `captureLength` members satisfies the `PacketSource` concept and can be
passed directly to `decode()`. [fpcap](https://github.com/fpcap/fpcap) packets work out of the box — no
manual field extraction needed. Optional members like `timestampSeconds`, `timestampMicroseconds`,
and `dataLinkType` are picked up automatically via `if constexpr`.

```cpp
#include <fdpi/fdpi.hpp>
#include <fpcap/fpcap.hpp>

fdpi::PacketDecoder decoder;

fpcap::PacketReader reader("capture.pcap");
for (const auto& fpkt : reader) {
    auto result = decoder.decode(fpkt);
    if (!result) continue;

    const auto& pkt = result.value();
    // process decoded packet...
}

// access flow statistics
std::cout << "Total flows: " << decoder.flows().size() << "\n";
```

### With libpcap

For libpcap, construct a `Timestamp` from the `pcap_pkthdr` timeval and pass the raw buffer directly:

```cpp
#include <fdpi/fdpi.hpp>
#include <pcap/pcap.h>

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t* handle = pcap_open_offline("capture.pcap", errbuf);
auto dlt = static_cast<fdpi::DataLinkType>(pcap_datalink(handle));

fdpi::PacketDecoder decoder;

struct pcap_pkthdr* header;
const u_char* data;
while (pcap_next_ex(handle, &header, &data) == 1) {
    auto ts = fdpi::Timestamp{std::chrono::seconds{header->ts.tv_sec}} +
              std::chrono::microseconds{header->ts.tv_usec};

    auto result = decoder.decode({data, header->caplen}, ts, dlt);
    if (!result) continue;

    const auto& pkt = result.value();
    // process decoded packet...
}

pcap_close(handle);
```

See `examples/` for complete working examples using both fpcap and libpcap.

### Multi-Threaded Processing

```cpp
#include <fdpi/fdpi.hpp>

class MyHandler : public fdpi::PacketHandler {
public:
    void onPacket(const fdpi::Packet& pkt) override {
        // called from worker threads
    }
};

fdpi::PacketProcessor::Config config;
config.numThreads = 4;
config.strategy = fdpi::DistributionStrategy::FlowPinned;

fdpi::PacketProcessor processor(config);
processor.setHandler(std::make_shared<MyHandler>());
processor.start();

// submit packets from any source
processor.submit({data, length});

processor.flush();
processor.stop();
```

## Build

### Requirements

- C++23 compatible compiler:
    - GCC 13+
    - Clang 17+
    - MSVC (Visual Studio 2022 17.10+)
- CMake 3.20 or newer
- Linux, macOS or Windows

### Library only

```shell
cmake -B build .
cmake --build build --target fdpi
```

### Tests

```shell
cmake -B build .
cmake --build build
ctest --test-dir build --output-on-failure
```

### Examples

```shell
cmake -DFDPI_BUILD_EXAMPLES=ON -B build .
cmake --build build
```

### Benchmarks

```shell
cmake -DFDPI_BUILD_BENCHMARKS=ON -B build .
cmake --build build
./build/benchmarks/fdpi_benchmarks
```

When building standalone (fdpi is the top-level project), tests, examples, and benchmarks are enabled by default.

## Contributing

Contributions and feedback are welcome! Feel free to open an issue or a pull request.

## License

This project is licensed under the [MIT License](LICENSE).
