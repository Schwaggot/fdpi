#ifndef FDPI_ERROR_HPP
#define FDPI_ERROR_HPP

#include <cstdint>
#include <string_view>

namespace fdpi {

enum class Error : uint8_t {
    TruncatedHeader,
    InvalidChecksum,
    UnsupportedProtocol,
    ReassemblyTimeout,
    MalformedPacket,
    BufferTooSmall,
    MaxFlowsReached,
    InvalidHeaderLength,
    FragmentOverlap,
    StreamLimitExceeded,
};

constexpr std::string_view toString(const Error error) {
    switch (error) {
        case Error::TruncatedHeader:      return "TruncatedHeader";
        case Error::InvalidChecksum:      return "InvalidChecksum";
        case Error::UnsupportedProtocol:  return "UnsupportedProtocol";
        case Error::ReassemblyTimeout:    return "ReassemblyTimeout";
        case Error::MalformedPacket:      return "MalformedPacket";
        case Error::BufferTooSmall:       return "BufferTooSmall";
        case Error::MaxFlowsReached:      return "MaxFlowsReached";
        case Error::InvalidHeaderLength:  return "InvalidHeaderLength";
        case Error::FragmentOverlap:      return "FragmentOverlap";
        case Error::StreamLimitExceeded:  return "StreamLimitExceeded";
    }
    return "Unknown";
}

} // namespace fdpi

#endif // FDPI_ERROR_HPP
