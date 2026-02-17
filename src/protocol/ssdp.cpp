#include <fdpi/protocol/ssdp.hpp>

#include <string_view>

namespace fdpi {

std::expected<SSDP, Error> decodeSsdp(const std::span<const uint8_t> data,
                                      size_t& offset) {
    if (data.size() <= offset) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const std::string_view sv(reinterpret_cast<const char*>(data.data() + offset),
                              data.size() - offset);

    SSDP hdr{};

    // Find end of first line
    auto lineEnd = sv.find("\r\n");
    if (lineEnd == std::string_view::npos) {
        return std::unexpected(Error::MalformedPacket);
    }

    auto firstLine = sv.substr(0, lineEnd);

    if (firstLine.starts_with("HTTP/")) {
        // Response: HTTP/1.1 200 OK
        hdr.isRequest = false;
        auto spacePos = firstLine.find(' ');
        if (spacePos != std::string_view::npos && spacePos + 3 <= firstLine.size()) {
            auto codeStr = firstLine.substr(spacePos + 1, 3);
            hdr.statusCode = 0;
            for (char c : codeStr) {
                if (c >= '0' && c <= '9') {
                    hdr.statusCode =
                        static_cast<uint16_t>(hdr.statusCode * 10 + (c - '0'));
                }
            }
        }
    } else {
        // Request: M-SEARCH * HTTP/1.1 or NOTIFY * HTTP/1.1
        hdr.isRequest = true;
        auto spacePos = firstLine.find(' ');
        if (spacePos != std::string_view::npos) {
            hdr.method = std::string(firstLine.substr(0, spacePos));
            auto uriStart = spacePos + 1;
            auto uriEnd = firstLine.find(' ', uriStart);
            if (uriEnd != std::string_view::npos) {
                hdr.uri = std::string(firstLine.substr(uriStart, uriEnd - uriStart));
            }
        }
    }

    // Parse headers
    size_t pos = lineEnd + 2;
    while (pos < sv.size()) {
        auto nextEnd = sv.find("\r\n", pos);
        if (nextEnd == std::string_view::npos || nextEnd == pos) {
            break;
        }

        auto headerLine = sv.substr(pos, nextEnd - pos);
        auto colonPos = headerLine.find(':');
        if (colonPos != std::string_view::npos) {
            auto name = headerLine.substr(0, colonPos);
            auto value = headerLine.substr(colonPos + 1);
            // Trim leading whitespace from value
            while (!value.empty() && value[0] == ' ') {
                value = value.substr(1);
            }
            hdr.headers.emplace_back(std::string(name), std::string(value));
        }
        pos = nextEnd + 2;
    }

    offset = data.size();
    return hdr;
}

} // namespace fdpi
