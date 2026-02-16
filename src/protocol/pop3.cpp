#include <fdpi/protocol/pop3.hpp>
#include <string_view>

namespace fdpi {

namespace {

size_t findCRLF(std::string_view sv, const size_t start = 0) {
    return sv.find("\r\n", start);
}

} // anonymous namespace

std::expected<POP3, Error> decodePop3(const std::span<const uint8_t> data,
                                      size_t& offset) {
    if (data.size() <= offset) {
        return std::unexpected(Error::TruncatedHeader);
    }

    std::string_view text(reinterpret_cast<const char*>(data.data() + offset),
                          data.size() - offset);

    auto lineEnd = findCRLF(text);
    if (lineEnd == std::string_view::npos) {
        return std::unexpected(Error::MalformedPacket);
    }

    std::string_view line = text.substr(0, lineEnd);
    if (line.empty()) {
        return std::unexpected(Error::MalformedPacket);
    }

    POP3 msg{};
    msg.success = false;

    if (line.starts_with("+OK")) {
        msg.isResponse = true;
        msg.success = true;
        if (line.size() > 3 && line[3] == ' ') {
            msg.responseText = std::string(line.substr(4));
        } else if (line.size() > 3) {
            msg.responseText = std::string(line.substr(3));
        }
    } else if (line.starts_with("-ERR")) {
        msg.isResponse = true;
        msg.success = false;
        if (line.size() > 4 && line[4] == ' ') {
            msg.responseText = std::string(line.substr(5));
        } else if (line.size() > 4) {
            msg.responseText = std::string(line.substr(4));
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
