#include <fdpi/protocol/imap.hpp>

#include <string_view>

namespace fdpi {

namespace {

size_t findCRLF(std::string_view sv, const size_t start = 0) {
    return sv.find("\r\n", start);
}

} // anonymous namespace

std::expected<IMAP, Error> decodeImap(const std::span<const uint8_t> data,
                                       size_t& offset) {
    if (data.size() <= offset) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const std::string_view text(reinterpret_cast<const char*>(data.data() + offset),
                          data.size() - offset);

    const auto lineEnd = findCRLF(text);
    if (lineEnd == std::string_view::npos) {
        return std::unexpected(Error::MalformedPacket);
    }

    std::string_view line = text.substr(0, lineEnd);
    if (line.empty()) {
        return std::unexpected(Error::MalformedPacket);
    }

    IMAP msg{};

    // First token is the tag
    const auto firstSpace = line.find(' ');
    if (firstSpace == std::string_view::npos) {
        // Single token line - treat as tag-only (malformed)
        return std::unexpected(Error::MalformedPacket);
    }

    msg.tag = std::string(line.substr(0, firstSpace));
    std::string_view rest = line.substr(firstSpace + 1);

    if (msg.tag == "*") {
        // Untagged response
        msg.isResponse = true;
        const auto secondSpace = rest.find(' ');
        if (secondSpace == std::string_view::npos) {
            msg.command = std::string(rest);
        } else {
            msg.command = std::string(rest.substr(0, secondSpace));
            msg.argument = std::string(rest.substr(secondSpace + 1));
        }
    } else {
        // Tagged: check if second token is OK/NO/BAD (response)
        const auto secondSpace = rest.find(' ');
        std::string_view secondToken;
        std::string_view remaining;
        if (secondSpace == std::string_view::npos) {
            secondToken = rest;
        } else {
            secondToken = rest.substr(0, secondSpace);
            remaining = rest.substr(secondSpace + 1);
        }

        if (secondToken == "OK" || secondToken == "NO" ||
            secondToken == "BAD") {
            // Tagged response
            msg.isResponse = true;
            msg.statusCode = std::string(secondToken);
            msg.responseText = std::string(remaining);
        } else {
            // Command
            msg.isResponse = false;
            msg.command = std::string(secondToken);
            msg.argument = std::string(remaining);
        }
    }

    offset += lineEnd + 2;
    return msg;
}

} // namespace fdpi
