#include <charconv>
#include <fdpi/address.hpp>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fdpi {

IPv4Address::IPv4Address(const std::string_view str) {
    size_t pos = 0;
    for (int i = 0; i < 4; ++i) {
        if (pos >= str.size()) {
            throw std::invalid_argument("Invalid IPv4 address: " + std::string(str));
        }

        auto dot = str.find('.', pos);
        if (i < 3 && dot == std::string_view::npos) {
            throw std::invalid_argument("Invalid IPv4 address: " + std::string(str));
        }
        if (i == 3) {
            dot = str.size();
        }

        uint32_t octet = 0;
        auto [ptr, ec] = std::from_chars(str.data() + pos, str.data() + dot, octet);
        if (ec != std::errc{} || ptr != str.data() + dot || octet > 255) {
            throw std::invalid_argument("Invalid IPv4 address: " + std::string(str));
        }

        bytes[static_cast<size_t>(i)] = static_cast<uint8_t>(octet);
        pos = dot + 1;
    }
}

namespace {

uint16_t parseHexGroup(const std::string_view s) {
    uint16_t val = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), val, 16);
    if (ec != std::errc{} || ptr != s.data() + s.size()) {
        throw std::invalid_argument("Invalid IPv6 hex group: " + std::string(s));
    }
    return val;
}

} // anonymous namespace

IPv6Address::IPv6Address(std::string_view str) {
    // Split on "::" first
    const auto dcolon = str.find("::");
    const bool hasDcolon = (dcolon != std::string_view::npos);

    auto parseGroups = [](const std::string_view part) {
        std::vector<uint16_t> groups;
        if (part.empty())
            return groups;
        size_t pos = 0;
        while (pos <= part.size()) {
            auto colon = part.find(':', pos);
            if (colon == std::string_view::npos)
                colon = part.size();
            groups.push_back(parseHexGroup(part.substr(pos, colon - pos)));
            pos = colon + 1;
        }
        return groups;
    };

    std::vector<uint16_t> left, right;

    if (hasDcolon) {
        left = parseGroups(str.substr(0, dcolon));
        right = parseGroups(str.substr(dcolon + 2));
    } else {
        left = parseGroups(str);
    }

    const size_t totalGroups = left.size() + right.size();
    if (hasDcolon) {
        if (totalGroups > 8) {
            throw std::invalid_argument("Invalid IPv6 address: " + std::string(str));
        }
    } else {
        if (totalGroups != 8) {
            throw std::invalid_argument("Invalid IPv6 address: " + std::string(str));
        }
    }

    const size_t zeroFill = 8 - totalGroups;

    // Write left groups
    size_t idx = 0;
    for (const auto g : left) {
        bytes[idx * 2] = static_cast<uint8_t>((g >> 8) & 0xFF);
        bytes[idx * 2 + 1] = static_cast<uint8_t>(g & 0xFF);
        ++idx;
    }

    // Skip zero-filled groups
    idx += zeroFill;

    // Write right groups
    for (const auto g : right) {
        bytes[idx * 2] = static_cast<uint8_t>((g >> 8) & 0xFF);
        bytes[idx * 2 + 1] = static_cast<uint8_t>(g & 0xFF);
        ++idx;
    }
}

MacAddress::MacAddress(const std::string_view str) {
    // Accept "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF"
    if (str.size() != 17) {
        throw std::invalid_argument("Invalid MAC address: " + std::string(str));
    }

    const char sep = str[2];
    if (sep != ':' && sep != '-') {
        throw std::invalid_argument("Invalid MAC address: " + std::string(str));
    }

    for (int i = 0; i < 6; ++i) {
        const size_t offset = static_cast<size_t>(i) * 3;
        if (i > 0 && str[offset - 1] != sep) {
            throw std::invalid_argument("Invalid MAC address: " + std::string(str));
        }

        uint8_t val = 0;
        auto [ptr, ec] =
            std::from_chars(str.data() + offset, str.data() + offset + 2, val, 16);
        if (ec != std::errc{} || ptr != str.data() + offset + 2) {
            throw std::invalid_argument("Invalid MAC address: " + std::string(str));
        }

        bytes[static_cast<size_t>(i)] = val;
    }
}

std::string IPv4Address::toString() const {
    return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "." +
           std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);
}

std::string IPv6Address::toString() const {
    // Build 8 groups
    uint16_t groups[8];
    for (int i = 0; i < 8; ++i) {
        groups[i] = static_cast<uint16_t>((bytes[i * 2] << 8) | bytes[i * 2 + 1]);
    }

    // Find the longest run of consecutive zero groups for :: compression
    int bestStart = -1, bestLen = 0;
    int curStart = -1, curLen = 0;
    for (int i = 0; i < 8; ++i) {
        if (groups[i] == 0) {
            if (curStart < 0)
                curStart = i;
            ++curLen;
            if (curLen > bestLen) {
                bestStart = curStart;
                bestLen = curLen;
            }
        } else {
            curStart = -1;
            curLen = 0;
        }
    }

    // Only compress runs of 2+ zeros
    if (bestLen < 2)
        bestStart = -1;

    std::ostringstream oss;
    oss << std::hex;
    for (int i = 0; i < 8; ++i) {
        if (bestStart >= 0 && i == bestStart) {
            oss << "::";
            i += bestLen - 1;
            continue;
        }
        if (i > 0 && !(bestStart >= 0 && i == bestStart + bestLen)) {
            oss << ':';
        }
        oss << groups[i];
    }

    return oss.str();
}

std::string MacAddress::toString() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) {
            oss << ':';
        }
        oss << std::setw(2) << static_cast<unsigned>(bytes[i]);
    }
    return oss.str();
}

} // namespace fdpi
