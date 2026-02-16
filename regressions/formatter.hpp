#ifndef FDPI_REGRESSION_FORMATTER_HPP
#define FDPI_REGRESSION_FORMATTER_HPP

#include <fdpi/fdpi.hpp>
#include <string>

namespace regression {

/// Serialize a decoded packet to deterministic text (multi-line key=value).
std::string formatPacket(uint32_t index, const fdpi::Packet& pkt);

/// Serialize a decode error.
std::string formatError(uint32_t index, fdpi::Error error);

} // namespace regression

#endif // FDPI_REGRESSION_FORMATTER_HPP
