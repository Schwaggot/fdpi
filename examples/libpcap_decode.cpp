#include <fdpi/fdpi.hpp>
#include <iostream>
#include <pcap/pcap.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>\n";
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        std::cerr << "pcap_open_offline: " << errbuf << "\n";
        return 1;
    }

    const auto dlt = static_cast<fdpi::DataLinkType>(pcap_datalink(handle));
    fdpi::PacketDecoder decoder;

    struct pcap_pkthdr* header;
    const u_char* data;
    while (pcap_next_ex(handle, &header, &data) == 1) {
        const auto ts = fdpi::Timestamp{std::chrono::seconds{header->ts.tv_sec}} +
                        std::chrono::microseconds{header->ts.tv_usec};

        auto result = decoder.decode({data, header->caplen}, ts, dlt);
        if (!result) {
            std::cerr << "Decode error: " << fdpi::toString(result.error()) << "\n";
            continue;
        }

        const auto& pkt = result.value();
        if (auto* ipv4 = std::get_if<fdpi::IPv4>(&pkt.layer3)) {
            std::cout << "IPv4 " << ipv4->srcIp.toString() << " -> "
                      << ipv4->dstIp.toString() << "\n";
        }
    }

    pcap_close(handle);
    return 0;
}
