#include <fdpi/protocol/ocsp.hpp>

namespace fdpi {

std::expected<OCSP, Error> decodeOcsp(const std::span<const uint8_t> data,
                                      size_t& offset) {
    // Minimal OCSP: need at least a SEQUENCE tag + length + some content
    if (data.size() < offset + 3) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    // Both request and response start with ASN.1 SEQUENCE (tag 0x30)
    if (ptr[0] != 0x30) {
        return std::unexpected(Error::MalformedPacket);
    }

    OCSP hdr{};

    // Determine request vs response:
    // OCSPResponse has an ENUMERATED (tag 0x0A) responseStatus early on.
    // OCSPRequest has a SEQUENCE inside (tag 0x30).
    // Parse length to get inner content.
    const size_t lenByte = ptr[1];
    size_t headerLen = 2;
    size_t contentLen = 0;

    if (lenByte < 0x80) {
        contentLen = lenByte;
    } else {
        const size_t numLenBytes = lenByte & 0x7F;
        if (data.size() < offset + 2 + numLenBytes) {
            return std::unexpected(Error::TruncatedHeader);
        }
        for (size_t i = 0; i < numLenBytes; ++i) {
            contentLen = (contentLen << 8) | ptr[2 + i];
        }
        headerLen = 2 + numLenBytes;
    }

    const size_t innerOffset = offset + headerLen;
    if (innerOffset < data.size()) {
        const uint8_t firstInnerTag = data[innerOffset];
        if (firstInnerTag == 0x0A) {
            // OCSPResponse: ENUMERATED tag for responseStatus
            hdr.isRequest = false;
            if (innerOffset + 2 < data.size()) {
                hdr.responseStatus = data[innerOffset + 2];
            }
            // Try to find certStatus in the response body
            // This is deep in the ASN.1 tree — we do a simple scan for
            // context-specific tags [0]=good, [1]=revoked, [2]=unknown
            // within the first 128 bytes of inner content
            const size_t scanEnd = std::min(data.size(), offset + headerLen + contentLen);
            for (size_t i = innerOffset; i + 1 < scanEnd; ++i) {
                // Context-specific tags for certStatus:
                // [0] IMPLICIT NULL = 0x80 + length 0 → good
                // [1] IMPLICIT = 0xA1 → revoked
                // [2] IMPLICIT NULL = 0x82 + length 0 → unknown
                if (data[i] == 0x80 && data[i + 1] == 0x00) {
                    hdr.certStatus = 0; // good
                    break;
                }
                if (data[i] == 0xA1) {
                    hdr.certStatus = 1; // revoked
                    break;
                }
                if (data[i] == 0x82 && data[i + 1] == 0x00) {
                    hdr.certStatus = 2; // unknown
                    break;
                }
            }
        } else {
            // OCSPRequest
            hdr.isRequest = true;
        }
    }

    // Advance past the full ASN.1 structure
    offset += headerLen + contentLen;
    if (offset > data.size()) {
        offset = data.size();
    }

    return hdr;
}

} // namespace fdpi
