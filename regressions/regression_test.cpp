#include "formatter.hpp"

#include <fdpi/fdpi.hpp>
#include <fpcap/fpcap.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::string readFile(const fs::path& path) {
    std::ifstream ifs(path, std::ios::binary);
    std::ostringstream ss;
    ss << ifs.rdbuf();
    return ss.str();
}

std::string generateOutput(const fs::path& pcapPath) {
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
        auto result = decoder.decode(fpkt);
        if (result) {
            output += regression::formatPacket(index, result.value());
        } else {
            output += regression::formatError(index, result.error());
        }
    }

    return output;
}

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

    const std::string current = generateOutput(pcapPath);
    const std::string expected = readFile(baselinePath);

    EXPECT_EQ(current, expected) << "Regression detected for: " << pcapPath.filename();
}

INSTANTIATE_TEST_SUITE_P(Regression,
                         RegressionTest,
                         ::testing::ValuesIn(discoverBaselines()),
                         [](const ::testing::TestParamInfo<fs::path>& info) {
                             return sanitizeTestName(info.param);
                         });
