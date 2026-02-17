#ifndef FDPI_PROTOCOL_DBLANSYNCD_HPP
#define FDPI_PROTOCOL_DBLANSYNCD_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>

namespace fdpi {

struct DbLanSyncDisc {
    std::optional<uint32_t> version;
    std::optional<uint64_t> hostInt;
    std::optional<std::string> displayName;
    std::optional<uint16_t> port;
};

std::expected<DbLanSyncDisc, Error> decodeDbLanSyncDisc(std::span<const uint8_t> data,
                                                        size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_DBLANSYNCD_HPP
