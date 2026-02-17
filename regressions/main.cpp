#include "formatter.hpp"

#include <fdpi/fdpi.hpp>
#include <fpcap/fpcap.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// Mutable globals so --tracefiles-dir / --baselines-dir can override.
// regression_test.cpp uses the compile-time defaults directly.
static std::string sTracefilesDir = FDPI_TRACEFILES_DIR;
static std::string sBaselinesDir = FDPI_BASELINES_DIR;

static std::string generateOutput(const fs::path& pcapPath) {
    fdpi::PacketDecoderConfig config;
    config.enableDefragmentation = false;
    config.enableTcpReassembly = false;
    config.enableProtocolDetection = true;
    fdpi::PacketDecoder decoder(config);

    std::string output;
    uint32_t index = 0;

    fpcap::PacketReader reader(pcapPath.string());
    for (const auto& fpkt : reader) {
        ++index;
        auto result =
            decoder.decode({fpkt.data, fpkt.captureLength}, fpkt.timestampSeconds,
                           static_cast<fdpi::DataLinkType>(fpkt.dataLinkType));
        if (result) {
            output += regression::formatPacket(index, result.value());
        } else {
            output += regression::formatError(index, result.error());
        }
    }

    return output;
}

static fs::path deriveBaselinePath(const fs::path& pcapPath) {
    const auto rel = fs::relative(pcapPath, sTracefilesDir);
    return fs::path(sBaselinesDir) / (rel.string() + ".txt");
}

static std::vector<fs::path> scanTracefiles() {
    std::vector<fs::path> result;
    for (const auto& entry : fs::recursive_directory_iterator(sTracefilesDir)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        auto ext = entry.path().extension().string();
        if (ext != ".pcap" && ext != ".pcapng") {
            continue;
        }
        if (entry.file_size() > 1024 * 1024) {
            std::cout << "Skipping (>1MB): " << entry.path() << "\n";
            continue;
        }
        result.push_back(entry.path());
    }
    std::ranges::sort(result);
    return result;
}

static void createBaseline(const fs::path& pcapPath) {
    std::cout << "Creating baseline for: " << pcapPath << "\n";
    const auto output = generateOutput(pcapPath);
    const auto baselinePath = deriveBaselinePath(pcapPath);
    fs::create_directories(baselinePath.parent_path());

    std::ofstream ofs(baselinePath, std::ios::binary);
    ofs << output;
    std::cout << "  -> " << baselinePath << "\n";
}

int main(int argc, char* argv[]) {
    bool createMode = false;
    bool allPcaps = false;
    std::string singlePcap;

    // Separate our flags from GTest flags.
    std::vector<char*> gtestArgs;
    gtestArgs.push_back(argv[0]);

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--create") {
            createMode = true;
        } else if (arg == "--all") {
            allPcaps = true;
        } else if (arg == "--pcap" && i + 1 < argc) {
            singlePcap = argv[++i];
        } else if (arg == "--baselines-dir" && i + 1 < argc) {
            sBaselinesDir = argv[++i];
        } else if (arg == "--tracefiles-dir" && i + 1 < argc) {
            sTracefilesDir = argv[++i];
        } else {
            gtestArgs.push_back(argv[i]);
        }
    }

    if (createMode) {
        if (allPcaps) {
            const auto pcaps = scanTracefiles();
            std::cout << "Found " << pcaps.size() << " PCAP files\n";
            for (const auto& pcap : pcaps) {
                createBaseline(pcap);
            }
        } else if (!singlePcap.empty()) {
            createBaseline(singlePcap);
        } else {
            std::cerr << "Usage: --create --all  OR  --create --pcap <file>\n";
            return 1;
        }
        return 0;
    }

    // Default: run GTest
    int gtestArgc = static_cast<int>(gtestArgs.size());
    ::testing::InitGoogleTest(&gtestArgc, gtestArgs.data());
    return RUN_ALL_TESTS();
}
