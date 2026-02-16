#include <fdpi/protocol/ftp.hpp>

#include <string_view>

namespace fdpi {

namespace {

size_t findCRLF(std::string_view sv, const size_t start = 0) {
    return sv.find("\r\n", start);
}

bool isDigit(const char c) {
    return c >= '0' && c <= '9';
}

} // anonymous namespace

std::expected<FTP, Error> decodeFtp(const std::span<const uint8_t> data, size_t& offset) {
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

    FTP msg{};
    msg.replyCode = 0;

    // Response: first 3 chars are digits, char 4 is space or dash
    if (line.size() >= 4 && isDigit(line[0]) && isDigit(line[1]) && isDigit(line[2]) &&
        (line[3] == ' ' || line[3] == '-')) {
        msg.isResponse = true;
        int code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
        msg.replyCode = static_cast<uint16_t>(code);
        if (line.size() > 4) {
            msg.replyText = std::string(line.substr(4));
        }
    } else {
        // Command: split on first space
        msg.isResponse = false;
        auto spacePos = line.find(' ');
        if (spacePos == std::string_view::npos) {
            msg.command = std::string(line);
        } else {
            msg.command = std::string(line.substr(0, spacePos));
            msg.argument = std::string(line.substr(spacePos + 1));
        }
    }

    offset += lineEnd + 2;
    return msg;
}

} // namespace fdpi
