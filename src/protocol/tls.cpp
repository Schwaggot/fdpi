#include <fdpi/protocol/tls.hpp>

namespace fdpi {

namespace {

constexpr uint8_t kContentTypeHandshake = 22;
constexpr uint8_t kHandshakeClientHello = 1;
constexpr uint8_t kHandshakeServerHello = 2;
constexpr uint16_t kExtSNI = 0x0000;
constexpr uint16_t kExtALPN = 0x0010;
constexpr uint16_t kExtSupportedVersions = 0x002B;

uint16_t readU16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

} // anonymous namespace

std::expected<TLS, Error> decodeTls(std::span<const uint8_t> data, size_t& offset) {
    constexpr size_t kTlsRecordHeaderSize = 5;

    if (data.size() < offset + kTlsRecordHeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    TLS rec{};
    rec.contentType = ptr[0];
    rec.version = readU16(ptr + 1);
    uint16_t recordLen = readU16(ptr + 3);

    if (data.size() < offset + kTlsRecordHeaderSize + recordLen) {
        return std::unexpected(Error::TruncatedHeader);
    }

    if (rec.contentType != kContentTypeHandshake) {
        offset += kTlsRecordHeaderSize + recordLen;
        return rec;
    }

    size_t hsOffset = offset + kTlsRecordHeaderSize;
    if (data.size() < hsOffset + 4) {
        offset += kTlsRecordHeaderSize + recordLen;
        return rec;
    }

    uint8_t hsType = data[hsOffset];

    if (hsType != kHandshakeClientHello && hsType != kHandshakeServerHello) {
        offset += kTlsRecordHeaderSize + recordLen;
        return rec;
    }

    size_t pos = hsOffset + 4;

    // version(2) + random(32)
    if (data.size() < pos + 34) {
        offset += kTlsRecordHeaderSize + recordLen;
        return rec;
    }
    pos += 2 + 32;

    // Session ID
    if (data.size() < pos + 1) {
        offset += kTlsRecordHeaderSize + recordLen;
        return rec;
    }
    uint8_t sessionIdLen = data[pos];
    pos += 1 + sessionIdLen;

    if (hsType == kHandshakeClientHello) {
        // Cipher suites
        if (data.size() < pos + 2) {
            offset += kTlsRecordHeaderSize + recordLen;
            return rec;
        }
        uint16_t cipherSuitesLen = readU16(data.data() + pos);
        pos += 2;
        if (data.size() < pos + cipherSuitesLen) {
            offset += kTlsRecordHeaderSize + recordLen;
            return rec;
        }
        for (size_t i = 0; i < cipherSuitesLen; i += 2) {
            rec.cipherSuites.push_back(readU16(data.data() + pos + i));
        }
        pos += cipherSuitesLen;

        // Compression methods
        if (data.size() < pos + 1) {
            offset += kTlsRecordHeaderSize + recordLen;
            return rec;
        }
        uint8_t compLen = data[pos];
        pos += 1 + compLen;
    } else {
        // ServerHello: single cipher suite
        if (data.size() < pos + 2) {
            offset += kTlsRecordHeaderSize + recordLen;
            return rec;
        }
        rec.cipherSuites.push_back(readU16(data.data() + pos));
        pos += 2;

        // Compression method
        if (data.size() < pos + 1) {
            offset += kTlsRecordHeaderSize + recordLen;
            return rec;
        }
        pos += 1;
    }

    // Extensions
    size_t recordEnd = offset + kTlsRecordHeaderSize + recordLen;
    if (pos + 2 > recordEnd) {
        offset = recordEnd;
        return rec;
    }
    uint16_t extTotalLen = readU16(data.data() + pos);
    pos += 2;

    size_t extEnd = pos + extTotalLen;
    if (extEnd > recordEnd) {
        extEnd = recordEnd;
    }

    while (pos + 4 <= extEnd) {
        uint16_t extType = readU16(data.data() + pos);
        uint16_t extLen = readU16(data.data() + pos + 2);
        pos += 4;

        if (pos + extLen > extEnd)
            break;

        if (extType == kExtSNI && extLen > 0) {
            if (extLen >= 5) {
                size_t sniPos = pos + 2;
                sniPos += 1; // skip name type
                uint16_t nameLen = readU16(data.data() + sniPos);
                sniPos += 2;
                if (sniPos + nameLen <= pos + extLen) {
                    rec.sni = std::string(
                        reinterpret_cast<const char*>(data.data() + sniPos), nameLen);
                }
            }
        } else if (extType == kExtALPN && extLen > 0) {
            if (extLen >= 2) {
                size_t alpnPos = pos + 2;
                rec.alpn = std::vector<std::string>{};
                while (alpnPos < pos + extLen) {
                    uint8_t protoLen = data[alpnPos];
                    alpnPos++;
                    if (alpnPos + protoLen > pos + extLen)
                        break;
                    rec.alpn->emplace_back(
                        reinterpret_cast<const char*>(data.data() + alpnPos), protoLen);
                    alpnPos += protoLen;
                }
            }
        } else if (extType == kExtSupportedVersions && extLen > 0) {
            if (hsType == kHandshakeClientHello) {
                // ClientHello format: versions_length(1) + version_list
                if (extLen >= 3) {
                    uint8_t versionsLen = data[pos];
                    uint16_t maxVer = 0;
                    for (size_t vi = 1; vi + 1 < 1 + versionsLen && vi + 1 < extLen;
                         vi += 2) {
                        uint16_t ver = readU16(data.data() + pos + vi);
                        if (ver > maxVer) {
                            maxVer = ver;
                        }
                    }
                    if (maxVer > 0) {
                        rec.tlsVersion = maxVer;
                    }
                }
            } else {
                // ServerHello format: just version(2)
                if (extLen >= 2) {
                    rec.tlsVersion = readU16(data.data() + pos);
                }
            }
        }

        pos += extLen;
    }

    offset = recordEnd;
    return rec;
}

} // namespace fdpi
