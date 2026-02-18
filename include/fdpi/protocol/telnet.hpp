#ifndef FDPI_PROTOCOL_TELNET_HPP
#define FDPI_PROTOCOL_TELNET_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace fdpi {

struct TelnetCommand {
    uint8_t command; // WILL=251, WONT=252, DO=253, DONT=254, etc.
    uint8_t option;  // Option code (echo=1, suppress-go-ahead=3, etc.)
};

struct Telnet {
    std::vector<std::string> data;       // Plain text segments between commands
    std::vector<TelnetCommand> commands; // IAC command sequences
};

std::expected<Telnet, Error> decodeTelnet(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_TELNET_HPP
