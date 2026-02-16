#include <fdpi/protocol/ssh.hpp>

#include <algorithm>
#include <cstring>
#include <string_view>

namespace fdpi {

std::expected<SSH, Error> decodeSsh(const std::span<const uint8_t> data, size_t& offset) {
    constexpr std::string_view kPrefix = "SSH-";
    constexpr size_t kMinBanner = 8; // "SSH-x-y\n"

    if (data.size() < offset + kMinBanner) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const auto* begin = data.data() + offset;
    const auto* end = data.data() + data.size();

    // Find the line terminator (\r\n or \n)
    const auto* pos = begin;
    const uint8_t* lineEnd = nullptr;
    size_t consumed = 0;
    while (pos < end) {
        if (*pos == '\n') {
            lineEnd = pos;
            consumed = static_cast<size_t>(pos - begin) + 1;
            break;
        }
        ++pos;
    }
    if (lineEnd == nullptr) {
        return std::unexpected(Error::TruncatedHeader);
    }

    // Strip optional \r before \n
    const auto* contentEnd = lineEnd;
    if (contentEnd > begin && *(contentEnd - 1) == '\r') {
        --contentEnd;
    }

    std::string_view line(reinterpret_cast<const char*>(begin),
                          static_cast<size_t>(contentEnd - begin));

    // Verify "SSH-" prefix
    if (!line.starts_with(kPrefix)) {
        return std::unexpected(Error::MalformedPacket);
    }
    line.remove_prefix(kPrefix.size());

    // Find protocol version (up to next '-')
    auto dash = line.find('-');
    if (dash == std::string_view::npos) {
        return std::unexpected(Error::MalformedPacket);
    }

    SSH ssh{};
    ssh.protocolVersion = std::string(line.substr(0, dash));
    line.remove_prefix(dash + 1);

    // Software version is up to first space (or end of line)
    auto space = line.find(' ');
    if (space == std::string_view::npos) {
        ssh.softwareVersion = std::string(line);
    } else {
        ssh.softwareVersion = std::string(line.substr(0, space));
        auto rest = line.substr(space + 1);
        if (!rest.empty()) {
            ssh.comments = std::string(rest);
        }
    }

    offset += consumed;
    return ssh;
}

} // namespace fdpi
