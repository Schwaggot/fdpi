#include <fdpi/protocol/http.hpp>
#include <string_view>

namespace fdpi {

namespace {

size_t findCRLF(std::string_view sv, const size_t start = 0) {
    return sv.find("\r\n", start);
}

} // anonymous namespace

std::expected<HTTP, Error> decodeHttp(std::span<const uint8_t> data, size_t& offset) {
    if (data.size() <= offset) {
        return std::unexpected(Error::TruncatedHeader);
    }

    std::string_view text(reinterpret_cast<const char*>(data.data() + offset),
                          data.size() - offset);

    auto firstLineEnd = findCRLF(text);
    if (firstLineEnd == std::string_view::npos) {
        return std::unexpected(Error::MalformedPacket);
    }

    std::string_view firstLine = text.substr(0, firstLineEnd);

    HTTP msg{};
    msg.statusCode = 0;

    if (firstLine.starts_with("HTTP/")) {
        // Response: HTTP/1.1 200 OK
        msg.isRequest = false;

        auto spacePos = firstLine.find(' ');
        if (spacePos == std::string_view::npos) {
            return std::unexpected(Error::MalformedPacket);
        }

        msg.version = std::string(firstLine.substr(5, spacePos - 5));

        auto codeStart = spacePos + 1;
        auto codeEnd = firstLine.find(' ', codeStart);
        if (codeEnd == std::string_view::npos) {
            codeEnd = firstLine.size();
        }

        std::string_view codeStr = firstLine.substr(codeStart, codeEnd - codeStart);
        int code = 0;
        for (char c : codeStr) {
            if (c < '0' || c > '9') {
                return std::unexpected(Error::MalformedPacket);
            }
            code = code * 10 + (c - '0');
        }
        msg.statusCode = static_cast<uint16_t>(code);
    } else {
        // Request: GET /path HTTP/1.1
        msg.isRequest = true;

        auto spacePos = firstLine.find(' ');
        if (spacePos == std::string_view::npos) {
            return std::unexpected(Error::MalformedPacket);
        }
        msg.method = std::string(firstLine.substr(0, spacePos));

        auto uriStart = spacePos + 1;
        auto uriEnd = firstLine.find(' ', uriStart);
        if (uriEnd == std::string_view::npos) {
            return std::unexpected(Error::MalformedPacket);
        }
        msg.uri = std::string(firstLine.substr(uriStart, uriEnd - uriStart));

        auto verStart = uriEnd + 1;
        if (firstLine.size() > verStart && firstLine.substr(verStart).starts_with("HTTP/")) {
            msg.version = std::string(firstLine.substr(verStart + 5));
        }
    }

    // Parse headers
    size_t pos = firstLineEnd + 2;
    while (pos < text.size()) {
        auto lineEnd = findCRLF(text, pos);
        if (lineEnd == std::string_view::npos) {
            break;
        }

        if (lineEnd == pos) {
            pos = lineEnd + 2;
            break;
        }

        std::string_view line = text.substr(pos, lineEnd - pos);
        auto colonPos = line.find(':');
        if (colonPos != std::string_view::npos) {
            std::string_view key = line.substr(0, colonPos);
            std::string_view val = line.substr(colonPos + 1);
            while (!val.empty() && val.front() == ' ') {
                val.remove_prefix(1);
            }
            msg.headers.emplace_back(std::string(key), std::string(val));
        }

        pos = lineEnd + 2;
    }

    offset += pos;
    return msg;
}

} // namespace fdpi
