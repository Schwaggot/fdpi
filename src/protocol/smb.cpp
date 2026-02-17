#include <fdpi/protocol/smb.hpp>

namespace fdpi {

std::expected<SMB, Error> decodeSmb(const std::span<const uint8_t> data, size_t& offset) {
    if (data.size() < offset + 4) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    SMB hdr{};

    // Check for SMB2/3 magic: \xFE SMB
    if (ptr[0] == 0xFE && ptr[1] == 'S' && ptr[2] == 'M' && ptr[3] == 'B') {
        constexpr size_t kSmb2MinSize = 64;
        if (data.size() < offset + kSmb2MinSize) {
            return std::unexpected(Error::TruncatedHeader);
        }

        hdr.version = 2;
        // Command at offset 12-13
        hdr.command = ptr[12];
        // Status at offset 8-11
        hdr.status = (static_cast<uint32_t>(ptr[8]) << 24) |
                     (static_cast<uint32_t>(ptr[9]) << 16) |
                     (static_cast<uint32_t>(ptr[10]) << 8) |
                     static_cast<uint32_t>(ptr[11]);
        // Flags at offset 16
        hdr.flags = ptr[16];
        hdr.flags2 = 0;
        // Session ID lower 2 bytes at offset 40-41
        hdr.uid = static_cast<uint16_t>((ptr[40] << 8) | ptr[41]);
        // Tree ID at offset 36-39 (lower 2 bytes)
        hdr.tid = static_cast<uint16_t>((ptr[36] << 8) | ptr[37]);
        // Message ID lower 2 bytes at offset 28-29
        hdr.mid = static_cast<uint16_t>((ptr[28] << 8) | ptr[29]);

        offset += kSmb2MinSize;
    }
    // Check for SMB1 magic: \xFF SMB
    else if (ptr[0] == 0xFF && ptr[1] == 'S' && ptr[2] == 'M' && ptr[3] == 'B') {
        constexpr size_t kSmb1MinSize = 32;
        if (data.size() < offset + kSmb1MinSize) {
            return std::unexpected(Error::TruncatedHeader);
        }

        hdr.version = 1;
        hdr.command = ptr[4];
        // Status at offset 5-8
        hdr.status = (static_cast<uint32_t>(ptr[5]) << 24) |
                     (static_cast<uint32_t>(ptr[6]) << 16) |
                     (static_cast<uint32_t>(ptr[7]) << 8) | static_cast<uint32_t>(ptr[8]);
        // Flags at offset 9
        hdr.flags = ptr[9];
        // Flags2 at offset 10-11
        hdr.flags2 = static_cast<uint16_t>((ptr[10] << 8) | ptr[11]);
        // TID at offset 24-25
        hdr.tid = static_cast<uint16_t>((ptr[24] << 8) | ptr[25]);
        // UID at offset 28-29
        hdr.uid = static_cast<uint16_t>((ptr[28] << 8) | ptr[29]);
        // MID at offset 30-31
        hdr.mid = static_cast<uint16_t>((ptr[30] << 8) | ptr[31]);

        offset += kSmb1MinSize;
    } else {
        return std::unexpected(Error::MalformedPacket);
    }

    return hdr;
}

} // namespace fdpi
