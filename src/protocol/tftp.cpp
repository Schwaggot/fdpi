#include <fdpi/protocol/tftp.hpp>

namespace fdpi {

namespace {

std::string readNullTerminated(const std::span<const uint8_t> data, size_t& pos) {
    std::string result;
    while (pos < data.size() && data[pos] != 0) {
        result += static_cast<char>(data[pos]);
        ++pos;
    }
    if (pos < data.size()) {
        ++pos; // skip null terminator
    }
    return result;
}

} // anonymous namespace

std::expected<TFTP, Error> decodeTftp(const std::span<const uint8_t> data,
                                      size_t& offset) {
    // Need at least 2 bytes for the opcode
    if (data.size() < offset + 2) {
        return std::unexpected(Error::TruncatedHeader);
    }

    TFTP msg{};
    size_t pos = offset;

    // Read 2-byte big-endian opcode
    msg.opcode = static_cast<uint16_t>((data[pos] << 8) | data[pos + 1]);
    pos += 2;

    switch (msg.opcode) {
    case 1: // RRQ
    case 2: // WRQ
        msg.filename = readNullTerminated(data, pos);
        msg.mode = readNullTerminated(data, pos);
        // Parse optional RFC 2347 option extensions
        while (pos < data.size()) {
            std::string optName = readNullTerminated(data, pos);
            if (optName.empty())
                break;
            std::string optValue = readNullTerminated(data, pos);
            msg.options.emplace_back(std::move(optName), std::move(optValue));
        }
        break;

    case 3: // DATA
        if (pos + 2 > data.size()) {
            return std::unexpected(Error::TruncatedHeader);
        }
        msg.blockNumber = static_cast<uint16_t>((data[pos] << 8) | data[pos + 1]);
        pos += 2;
        msg.blockData.assign(data.begin() + static_cast<ptrdiff_t>(pos), data.end());
        pos = data.size();
        break;

    case 4: // ACK
        if (pos + 2 > data.size()) {
            return std::unexpected(Error::TruncatedHeader);
        }
        msg.blockNumber = static_cast<uint16_t>((data[pos] << 8) | data[pos + 1]);
        pos += 2;
        break;

    case 5: // ERROR
        if (pos + 2 > data.size()) {
            return std::unexpected(Error::TruncatedHeader);
        }
        msg.errorCode = static_cast<uint16_t>((data[pos] << 8) | data[pos + 1]);
        pos += 2;
        msg.errorMessage = readNullTerminated(data, pos);
        break;

    default:
        return std::unexpected(Error::MalformedPacket);
    }

    offset = pos;
    return msg;
}

} // namespace fdpi
