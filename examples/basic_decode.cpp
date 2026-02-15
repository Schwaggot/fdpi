#include <fdpi/fdpi.hpp>
#include <fpcap/fpcap.hpp>
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>\n";
        return 1;
    }

    fdpi::PacketDecoder decoder;

    fpcap::PacketReader reader(argv[1]);
    for (const auto& fpkt : reader) {
        auto result = decoder.decode({fpkt.data, fpkt.captureLength}, fpkt.timestampSeconds);
        if (!result) {
            std::cerr << "Decode error: " << fdpi::toString(result.error()) << "\n";
            continue;
        }

        const auto& pkt = result.value();
        if (auto* ipv4 = std::get_if<fdpi::IPv4>(&pkt.layer3)) {
            std::cout << "IPv4 " << ipv4->srcIp.toString()
                      << " -> " << ipv4->dstIp.toString() << "\n";
        }
    }

    return 0;
}
