#include <fdpi/protocol/telnet.hpp>

namespace fdpi {

namespace {

constexpr uint8_t IAC = 0xFF;
constexpr uint8_t SB = 0xFA;
constexpr uint8_t SE = 0xF0;
constexpr uint8_t WILL = 0xFB;
constexpr uint8_t WONT = 0xFC;
constexpr uint8_t DO = 0xFD;
constexpr uint8_t DONT = 0xFE;

} // anonymous namespace

std::expected<Telnet, Error> decodeTelnet(const std::span<const uint8_t> data,
                                          size_t& offset) {
    if (data.size() <= offset) {
        return std::unexpected(Error::TruncatedHeader);
    }

    Telnet msg{};
    size_t i = offset;
    const size_t end = data.size();

    while (i < end) {
        if (data[i] == IAC) {
            // Need at least one more byte for the command
            if (i + 1 >= end) {
                break;
            }

            uint8_t cmd = data[i + 1];

            if (cmd == IAC) {
                // Escaped 0xFF — literal 0xFF in data
                msg.data += static_cast<char>(0xFF);
                i += 2;
            } else if (cmd == SB) {
                // Sub-negotiation: FF FA <option> ... FF F0
                // Skip until we find IAC SE
                size_t j = i + 2;
                while (j + 1 < end) {
                    if (data[j] == IAC && data[j + 1] == SE) {
                        break;
                    }
                    ++j;
                }
                // Advance past IAC SE (or to end if not found)
                if (j + 1 < end) {
                    i = j + 2;
                } else {
                    i = end;
                }
            } else if (cmd >= WILL && cmd <= DONT) {
                // 3-byte command: IAC <WILL|WONT|DO|DONT> <option>
                if (i + 2 >= end) {
                    break;
                }
                TelnetCommand tc{};
                tc.command = cmd;
                tc.option = data[i + 2];
                msg.commands.push_back(tc);
                i += 3;
            } else {
                // 2-byte command (NOP, Data Mark, Break, etc.)
                i += 2;
            }
        } else {
            msg.data += static_cast<char>(data[i]);
            ++i;
        }
    }

    offset = i;
    return msg;
}

} // namespace fdpi
