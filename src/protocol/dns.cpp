#include <cstring>
#include <fdpi/protocol/dns.hpp>

namespace fdpi {

namespace {

// Decode a DNS name with compression support.
// dnsStart: absolute offset in data where the DNS message begins (for pointer
// resolution). pos: current absolute position in data (advanced past the name on return).
std::expected<std::string, Error> decodeName(const std::span<const uint8_t> data,
                                             const size_t dnsStart,
                                             size_t& pos,
                                             const int depth = 0) {
    if (depth > 16) {
        return std::unexpected(Error::MalformedPacket);
    }

    std::string name;
    bool jumped = false;
    size_t savedPos = 0;

    while (pos < data.size()) {
        const uint8_t len = data[pos];

        if (len == 0) {
            if (!jumped) {
                pos++;
            }
            break;
        }

        // Compression pointer: top 2 bits = 11
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= data.size()) {
                return std::unexpected(Error::TruncatedHeader);
            }
            uint16_t pointer = static_cast<uint16_t>(((len & 0x3F) << 8) | data[pos + 1]);
            if (!jumped) {
                savedPos = pos + 2;
            }
            // Pointer is relative to DNS message start
            const size_t target = dnsStart + pointer;
            if (target >= data.size()) {
                return std::unexpected(Error::MalformedPacket);
            }
            pos = target;
            jumped = true;
            continue;
        }

        // Reserved label types
        if ((len & 0xC0) != 0) {
            return std::unexpected(Error::MalformedPacket);
        }

        pos++;
        if (pos + len > data.size()) {
            return std::unexpected(Error::TruncatedHeader);
        }

        if (!name.empty()) {
            name += '.';
        }
        name.append(reinterpret_cast<const char*>(data.data() + pos), len);
        pos += len;
    }

    if (jumped) {
        pos = savedPos;
    }

    return name;
}

std::expected<DnsQuestion, Error>
decodeQuestion(const std::span<const uint8_t> data, const size_t dnsStart, size_t& pos) {
    DnsQuestion q{};

    auto nameResult = decodeName(data, dnsStart, pos);
    if (!nameResult) {
        return std::unexpected(nameResult.error());
    }
    q.name = std::move(*nameResult);

    if (pos + 4 > data.size()) {
        return std::unexpected(Error::TruncatedHeader);
    }

    q.type = static_cast<uint16_t>((data[pos] << 8) | data[pos + 1]);
    pos += 2;
    q.qclass = static_cast<uint16_t>((data[pos] << 8) | data[pos + 1]);
    pos += 2;

    return q;
}

std::expected<DnsRecord, Error>
decodeRecord(const std::span<const uint8_t> data, const size_t dnsStart, size_t& pos) {
    DnsRecord r{};

    auto nameResult = decodeName(data, dnsStart, pos);
    if (!nameResult) {
        return std::unexpected(nameResult.error());
    }
    r.name = std::move(*nameResult);

    if (pos + 10 > data.size()) {
        return std::unexpected(Error::TruncatedHeader);
    }

    r.type = static_cast<uint16_t>((data[pos] << 8) | data[pos + 1]);
    pos += 2;
    r.rclass = static_cast<uint16_t>((data[pos] << 8) | data[pos + 1]);
    pos += 2;
    r.ttl = (static_cast<uint32_t>(data[pos]) << 24) |
            (static_cast<uint32_t>(data[pos + 1]) << 16) |
            (static_cast<uint32_t>(data[pos + 2]) << 8) |
            static_cast<uint32_t>(data[pos + 3]);
    pos += 4;
    uint16_t rdlen = static_cast<uint16_t>((data[pos] << 8) | data[pos + 1]);
    pos += 2;

    if (pos + rdlen > data.size()) {
        return std::unexpected(Error::TruncatedHeader);
    }

    r.rdata.assign(data.data() + pos, data.data() + pos + rdlen);
    pos += rdlen;

    return r;
}

} // anonymous namespace

std::expected<DNS, Error> decodeDns(std::span<const uint8_t> data, size_t& offset) {
    const size_t dnsStart = offset;
    constexpr size_t kDnsHeaderSize = 12;

    if (data.size() < offset + kDnsHeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    DNS msg{};
    msg.id = static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);

    uint16_t flags = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    msg.isResponse = (flags & 0x8000) != 0;
    msg.opcode = static_cast<uint8_t>((flags >> 11) & 0x0F);
    msg.authoritative = (flags & 0x0400) != 0;
    msg.truncated = (flags & 0x0200) != 0;
    msg.recursionDesired = (flags & 0x0100) != 0;
    msg.recursionAvailable = (flags & 0x0080) != 0;
    msg.rcode = static_cast<uint8_t>(flags & 0x000F);

    uint16_t qdcount = static_cast<uint16_t>((ptr[4] << 8) | ptr[5]);
    uint16_t ancount = static_cast<uint16_t>((ptr[6] << 8) | ptr[7]);
    uint16_t nscount = static_cast<uint16_t>((ptr[8] << 8) | ptr[9]);
    uint16_t arcount = static_cast<uint16_t>((ptr[10] << 8) | ptr[11]);

    size_t pos = offset + kDnsHeaderSize;

    for (uint16_t i = 0; i < qdcount; i++) {
        auto q = decodeQuestion(data, dnsStart, pos);
        if (!q)
            return std::unexpected(q.error());
        msg.questions.push_back(std::move(*q));
    }

    for (uint16_t i = 0; i < ancount; i++) {
        auto r = decodeRecord(data, dnsStart, pos);
        if (!r)
            return std::unexpected(r.error());
        msg.answers.push_back(std::move(*r));
    }

    for (uint16_t i = 0; i < nscount; i++) {
        auto r = decodeRecord(data, dnsStart, pos);
        if (!r)
            return std::unexpected(r.error());
        msg.authorities.push_back(std::move(*r));
    }

    for (uint16_t i = 0; i < arcount; i++) {
        auto r = decodeRecord(data, dnsStart, pos);
        if (!r)
            return std::unexpected(r.error());
        msg.additionals.push_back(std::move(*r));
    }

    offset = pos;
    return msg;
}

} // namespace fdpi
