#ifndef FDPI_TIMESTAMP_HPP
#define FDPI_TIMESTAMP_HPP

#include <chrono>

namespace fdpi {

using Timestamp =
    std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;

} // namespace fdpi

#endif // FDPI_TIMESTAMP_HPP
