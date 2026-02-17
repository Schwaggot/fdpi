#include <fdpi/protocol/imf.hpp>

#include <algorithm>
#include <string_view>

namespace fdpi {

std::expected<IMF, Error> decodeImf(const std::span<const uint8_t> data, size_t& offset) {
    if (data.size() <= offset) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const std::string_view sv(reinterpret_cast<const char*>(data.data() + offset),
                              data.size() - offset);

    IMF hdr{};

    size_t pos = 0;
    std::string currentName;
    std::string currentValue;

    auto storeHeader = [&]() {
        if (!currentName.empty()) {
            // Store in named fields if applicable
            if (currentName == "From" || currentName == "from") {
                hdr.from = currentValue;
            } else if (currentName == "To" || currentName == "to") {
                hdr.to = currentValue;
            } else if (currentName == "Subject" || currentName == "subject") {
                hdr.subject = currentValue;
            } else if (currentName == "Date" || currentName == "date") {
                hdr.date = currentValue;
            } else if (currentName == "Message-ID" || currentName == "Message-Id" ||
                       currentName == "message-id") {
                hdr.messageId = currentValue;
            } else if (currentName == "Content-Type" || currentName == "content-type") {
                hdr.contentType = currentValue;
            }
            hdr.headers.emplace_back(std::move(currentName), std::move(currentValue));
            currentName.clear();
            currentValue.clear();
        }
    };

    while (pos < sv.size()) {
        auto lineEnd = sv.find("\r\n", pos);
        if (lineEnd == std::string_view::npos) {
            lineEnd = sv.size();
        }

        // Empty line = end of headers
        if (lineEnd == pos) {
            storeHeader();
            break;
        }

        auto line = sv.substr(pos, lineEnd - pos);

        // Continuation line (starts with whitespace)
        if ((line[0] == ' ' || line[0] == '\t') && !currentName.empty()) {
            // Unfold: append to current value
            currentValue += ' ';
            size_t start = line.find_first_not_of(" \t");
            if (start != std::string_view::npos) {
                currentValue += std::string(line.substr(start));
            }
        } else {
            // New header
            storeHeader();

            auto colonPos = line.find(':');
            if (colonPos != std::string_view::npos) {
                currentName = std::string(line.substr(0, colonPos));
                auto valStart = colonPos + 1;
                while (valStart < line.size() && line[valStart] == ' ') {
                    valStart++;
                }
                currentValue = std::string(line.substr(valStart));
            }
        }

        pos = lineEnd + 2;
        if (lineEnd == sv.size()) {
            break;
        }
    }

    storeHeader();

    if (hdr.headers.empty()) {
        return std::unexpected(Error::MalformedPacket);
    }

    offset = data.size();
    return hdr;
}

} // namespace fdpi
