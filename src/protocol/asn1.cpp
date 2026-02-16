#include "asn1.hpp"

namespace fdpi::detail {

std::expected<uint8_t, Error> readAsn1Tag(const std::span<const uint8_t> data,
                                          size_t& pos) {
    if (pos >= data.size()) {
        return std::unexpected(Error::TruncatedHeader);
    }
    return data[pos++];
}

std::expected<size_t, Error> readAsn1Length(const std::span<const uint8_t> data,
                                            size_t& pos) {
    if (pos >= data.size()) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t first = data[pos++];
    if ((first & 0x80) == 0) {
        return static_cast<size_t>(first);
    }

    const size_t numBytes = first & 0x7F;
    if (numBytes == 0 || numBytes > 4) {
        return std::unexpected(Error::MalformedPacket);
    }
    if (pos + numBytes > data.size()) {
        return std::unexpected(Error::TruncatedHeader);
    }

    size_t length = 0;
    for (size_t i = 0; i < numBytes; ++i) {
        length = (length << 8) | data[pos++];
    }
    return length;
}

std::expected<int64_t, Error> readAsn1Integer(const std::span<const uint8_t> data,
                                              size_t& pos) {
    auto tag = readAsn1Tag(data, pos);
    if (!tag)
        return std::unexpected(tag.error());
    if (*tag != 0x02) {
        return std::unexpected(Error::MalformedPacket);
    }

    auto len = readAsn1Length(data, pos);
    if (!len)
        return std::unexpected(len.error());
    if (pos + *len > data.size() || *len == 0) {
        return std::unexpected(Error::TruncatedHeader);
    }

    int64_t value = 0;
    // Sign-extend the first byte
    if (data[pos] & 0x80) {
        value = -1;
    }
    for (size_t i = 0; i < *len; ++i) {
        value = (value << 8) | data[pos++];
    }
    return value;
}

std::expected<std::string, Error> readAsn1OctetString(const std::span<const uint8_t> data,
                                                      size_t& pos) {
    auto tag = readAsn1Tag(data, pos);
    if (!tag)
        return std::unexpected(tag.error());
    if (*tag != 0x04) {
        return std::unexpected(Error::MalformedPacket);
    }

    auto len = readAsn1Length(data, pos);
    if (!len)
        return std::unexpected(len.error());
    if (pos + *len > data.size()) {
        return std::unexpected(Error::TruncatedHeader);
    }

    std::string result(reinterpret_cast<const char*>(data.data() + pos), *len);
    pos += *len;
    return result;
}

std::expected<size_t, Error> skipAsn1Value(const std::span<const uint8_t> data,
                                           size_t& pos) {
    auto tag = readAsn1Tag(data, pos);
    if (!tag)
        return std::unexpected(tag.error());

    auto len = readAsn1Length(data, pos);
    if (!len)
        return std::unexpected(len.error());
    if (pos + *len > data.size()) {
        return std::unexpected(Error::TruncatedHeader);
    }

    pos += *len;
    return *len;
}

} // namespace fdpi::detail
