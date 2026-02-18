#include "formatter.hpp"

#include <fdpi/fdpi.hpp>
#include <fpcap/fpcap.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

fs::path deriveTracefilePath(const fs::path& baselinePath) {
    const fs::path baselinesDir{FDPI_BASELINES_DIR};
    const fs::path tracefilesDir{FDPI_TRACEFILES_DIR};

    const auto rel = fs::relative(baselinePath, baselinesDir);
    auto relStr = rel.string();
    // Strip trailing ".txt" to recover the original PCAP filename.
    if (relStr.size() > 4 && relStr.substr(relStr.size() - 4) == ".txt") {
        relStr = relStr.substr(0, relStr.size() - 4);
    }
    return tracefilesDir / relStr;
}

std::vector<fs::path> discoverBaselines() {
    const fs::path baselinesDir{FDPI_BASELINES_DIR};
    std::vector<fs::path> result;
    if (!fs::exists(baselinesDir)) {
        return result;
    }
    for (const auto& entry : fs::recursive_directory_iterator(baselinesDir)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        if (entry.path().extension() != ".txt") {
            continue;
        }
        result.push_back(entry.path());
    }
    std::ranges::sort(result);
    return result;
}

std::string sanitizeTestName(const fs::path& path) {
    const fs::path baselinesDir{FDPI_BASELINES_DIR};
    auto rel = fs::relative(path, baselinesDir);
    std::string name = rel.string();
    for (auto& c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c))) {
            c = '_';
        }
    }
    return name;
}

} // anonymous namespace

class RegressionTest : public ::testing::TestWithParam<fs::path> {};

TEST_P(RegressionTest, MatchesBaseline) {
    const auto baselinePath = GetParam();
    const auto pcapPath = deriveTracefilePath(baselinePath);

    ASSERT_TRUE(fs::exists(pcapPath)) << "PCAP not found: " << pcapPath;

    std::ifstream baseline(baselinePath);
    ASSERT_TRUE(baseline.is_open()) << "Cannot open baseline: " << baselinePath;

    fdpi::PacketDecoderConfig config;
    config.enableDefragmentation = false;
    config.enableTcpReassembly = false;
    config.enableProtocolDetection = true;
    fdpi::PacketDecoder decoder(config);

    uint32_t index = 0;
    size_t lineNum = 0;
    std::string expectedLine;

    fpcap::PacketReader reader(pcapPath.string());
    for (const auto& fpkt : reader) {
        ++index;
        auto result = decoder.decode(fpkt);
        std::string pktOutput;
        if (result) {
            pktOutput = regression::formatPacket(index, result.value());
        } else {
            pktOutput = regression::formatError(index, result.error());
        }

        // Compare the packet output line by line against the baseline
        size_t pos = 0;
        while (pos < pktOutput.size()) {
            size_t nl = pktOutput.find('\n', pos);
            std::string currentLine;
            if (nl != std::string::npos) {
                currentLine = pktOutput.substr(pos, nl - pos);
                pos = nl + 1;
            } else {
                currentLine = pktOutput.substr(pos);
                pos = pktOutput.size();
            }
            ++lineNum;

            if (!std::getline(baseline, expectedLine)) {
                ADD_FAILURE() << pcapPath.filename() << ": packet " << index << ", line "
                              << lineNum << ": unexpected extra output: " << currentLine;
                return;
            }

            if (currentLine != expectedLine) {
                EXPECT_EQ(currentLine, expectedLine)
                    << pcapPath.filename() << ": mismatch at line " << lineNum
                    << " (packet " << index << ")";
                return;
            }
        }
    }

    // Check for trailing lines in the baseline
    if (std::getline(baseline, expectedLine)) {
        ADD_FAILURE() << pcapPath.filename() << ": baseline has extra lines after line "
                      << lineNum << ": " << expectedLine;
    }
}

INSTANTIATE_TEST_SUITE_P(Regression,
                         RegressionTest,
                         ::testing::ValuesIn(discoverBaselines()),
                         [](const ::testing::TestParamInfo<fs::path>& info) {
                             return sanitizeTestName(info.param);
                         });
