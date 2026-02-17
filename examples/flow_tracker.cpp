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
        decoder.decode(fpkt);
    }

    std::cout << "Total flows: " << decoder.flows().size() << "\n";
    decoder.flows().forEach([](const fdpi::FlowMetadata& flow) {
        std::cout << "  Flow: " << flow.packetCount << " packets, " << flow.byteCount
                  << " bytes\n";
    });

    return 0;
}
