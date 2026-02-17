#include <fdpi/protocol/nbns.hpp>

#include <algorithm>

namespace fdpi {

std::string decodeNetbiosName(const std::span<const uint8_t> data, size_t& offset) {
    std::string result;

    if (offset >= data.size()) {
        return result;
    }

    // First byte is the label length
    uint8_t labelLen = data[offset];
    offset++;

    if (labelLen == 0 || offset + labelLen > data.size()) {
        return result;
    }

    // NetBIOS first-level encoding: pairs of bytes encode each character
    // Each byte pair: ((c1 - 'A') << 4) | (c2 - 'A') = original byte
    for (size_t i = 0; i + 1 < labelLen; i += 2) {
        uint8_t c1 = data[offset + i];
        uint8_t c2 = data[offset + i + 1];
        if (c1 >= 'A' && c1 <= 'P' && c2 >= 'A' && c2 <= 'P') {
            char decoded = static_cast<char>(((c1 - 'A') << 4) | (c2 - 'A'));
            result += decoded;
        }
    }

    offset += labelLen;

    // Skip any remaining labels (scope ID)
    while (offset < data.size() && data[offset] != 0) {
        uint8_t scopeLen = data[offset];
        offset++;
        if (offset + scopeLen <= data.size()) {
            if (!result.empty()) {
                result += '.';
            }
            result += std::string(reinterpret_cast<const char*>(data.data() + offset),
                                  scopeLen);
            offset += scopeLen;
        } else {
            break;
        }
    }

    // Skip null terminator
    if (offset < data.size() && data[offset] == 0) {
        offset++;
    }

    // Trim trailing spaces from the decoded NetBIOS name (first 15 chars)
    auto trimEnd = result.find_last_not_of(' ');
    if (trimEnd != std::string::npos && trimEnd + 1 < result.size()) {
        // Keep any scope portion after the 16th byte
        result = result.substr(0, trimEnd + 1);
    }

    return result;
}

namespace {

std::string decodeName(const std::span<const uint8_t> data, size_t& offset) {
    // Handle compression pointers and regular NetBIOS names
    if (offset >= data.size()) {
        return {};
    }

    // Check for compression pointer
    if ((data[offset] & 0xC0) == 0xC0) {
        if (offset + 1 >= data.size()) {
            return {};
        }
        size_t ptrOffset =
            static_cast<size_t>(((data[offset] & 0x3F) << 8) | data[offset + 1]);
        offset += 2;
        return decodeNetbiosName(data, ptrOffset);
    }

    return decodeNetbiosName(data, offset);
}

} // namespace

std::expected<NBNS, Error> decodeNbns(const std::span<const uint8_t> data,
                                      size_t& offset) {
    constexpr size_t kHeaderSize = 12;

    if (data.size() < offset + kHeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    NBNS hdr{};
    hdr.id = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);

    uint16_t flags = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.isResponse = (flags >> 15) & 1;
    hdr.opcode = (flags >> 11) & 0x0F;
    hdr.rcode = flags & 0x0F;

    uint16_t qdCount = static_cast<uint16_t>((ptr[4] << 8) | ptr[5]);
    uint16_t anCount = static_cast<uint16_t>((ptr[6] << 8) | ptr[7]);
    uint16_t nsCount = static_cast<uint16_t>((ptr[8] << 8) | ptr[9]);
    uint16_t arCount = static_cast<uint16_t>((ptr[10] << 8) | ptr[11]);

    offset += kHeaderSize;

    // Parse questions
    for (uint16_t i = 0; i < qdCount && offset < data.size(); ++i) {
        NbnsQuestion q{};
        q.name = decodeName(data, offset);
        if (offset + 4 > data.size())
            break;
        q.type = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
        q.qclass = static_cast<uint16_t>((data[offset + 2] << 8) | data[offset + 3]);
        offset += 4;
        hdr.questions.push_back(std::move(q));
    }

    // Helper to parse resource records
    auto parseRecords = [&](std::vector<NbnsRecord>& records, uint16_t count) {
        for (uint16_t i = 0; i < count && offset < data.size(); ++i) {
            NbnsRecord r{};
            r.name = decodeName(data, offset);
            if (offset + 10 > data.size())
                break;
            r.type = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
            r.rclass = static_cast<uint16_t>((data[offset + 2] << 8) | data[offset + 3]);
            r.ttl = (static_cast<uint32_t>(data[offset + 4]) << 24) |
                    (static_cast<uint32_t>(data[offset + 5]) << 16) |
                    (static_cast<uint32_t>(data[offset + 6]) << 8) |
                    static_cast<uint32_t>(data[offset + 7]);
            uint16_t rdLength =
                static_cast<uint16_t>((data[offset + 8] << 8) | data[offset + 9]);
            offset += 10;

            if (offset + rdLength <= data.size()) {
                r.rdata.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                               data.begin() + static_cast<ptrdiff_t>(offset + rdLength));
                offset += rdLength;
            }
            records.push_back(std::move(r));
        }
    };

    parseRecords(hdr.answers, anCount);
    parseRecords(hdr.authorities, nsCount);
    parseRecords(hdr.additionals, arCount);

    return hdr;
}

} // namespace fdpi
