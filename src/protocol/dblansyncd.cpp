#include <fdpi/protocol/dblansyncd.hpp>

#include <string_view>

namespace fdpi {

namespace {

// Simple JSON value extractor — finds "key": value or "key": "value"
std::optional<std::string_view> extractJsonValue(std::string_view json,
                                                 const std::string_view key) {
    // Search for "key":
    const std::string needle = "\"" + std::string(key) + "\"";
    auto pos = json.find(needle);
    if (pos == std::string_view::npos) {
        return std::nullopt;
    }
    pos += needle.size();
    // Skip whitespace and colon
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) {
        ++pos;
    }
    if (pos >= json.size()) {
        return std::nullopt;
    }

    if (json[pos] == '"') {
        // String value
        ++pos;
        const auto end = json.find('"', pos);
        if (end == std::string_view::npos) {
            return std::nullopt;
        }
        return json.substr(pos, end - pos);
    }
    // Numeric value — read until comma, brace, or whitespace
    auto end = json.find_first_of(",} \t\n\r", pos);
    if (end == std::string_view::npos) {
        end = json.size();
    }
    return json.substr(pos, end - pos);
}

} // anonymous namespace

std::expected<DbLanSyncDisc, Error>
decodeDbLanSyncDisc(const std::span<const uint8_t> data, size_t& offset) {

    if (data.size() < offset + 2) {
        return std::unexpected(Error::TruncatedHeader);
    }

    // Verify JSON start
    if (data[offset] != '{') {
        return std::unexpected(Error::MalformedPacket);
    }

    const std::string_view json(reinterpret_cast<const char*>(data.data() + offset),
                                data.size() - offset);

    DbLanSyncDisc hdr{};

    if (const auto val = extractJsonValue(json, "version")) {
        try {
            hdr.version = static_cast<uint32_t>(std::stoul(std::string(*val)));
        } catch (...) {
        }
    }

    if (const auto val = extractJsonValue(json, "host_int")) {
        try {
            hdr.hostInt = static_cast<uint64_t>(std::stoull(std::string(*val)));
        } catch (...) {
        }
    }

    if (const auto val = extractJsonValue(json, "displayname")) {
        hdr.displayName = std::string(*val);
    }

    if (const auto val = extractJsonValue(json, "port")) {
        try {
            hdr.port = static_cast<uint16_t>(std::stoul(std::string(*val)));
        } catch (...) {
        }
    }

    offset = data.size();
    return hdr;
}

} // namespace fdpi
