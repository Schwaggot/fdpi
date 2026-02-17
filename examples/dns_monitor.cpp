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
        auto result =
            decoder.decode({fpkt.data, fpkt.captureLength}, fpkt.timestampSeconds,
                           static_cast<fdpi::DataLinkType>(fpkt.dataLinkType));
        if (!result)
            continue;

        const auto& pkt = result.value();
        if (auto* dns = std::get_if<fdpi::DNS>(&pkt.layer7)) {
            for (const auto& q : dns->questions) {
                std::cout << "DNS query: " << q.name << " (type " << q.type << ")\n";
            }
            for (const auto& a : dns->answers) {
                std::cout << "DNS answer: " << a.name << " (type " << a.type << ")\n";
            }
        }
    }

    return 0;
}
