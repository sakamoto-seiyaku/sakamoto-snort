#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace sucre::protocol {

enum class ApplicationProtocolId : std::uint32_t {
    RESERVED_1000 = 1000,
    DNS = 1001,
    HTTP = 1002,
    TLS = 1003,
    QUIC = 1004,
    SSH = 1005,
};

struct ApplicationProtocolEntry {
    ApplicationProtocolId id;
    std::string_view key;
    std::string_view status;
    std::string_view category;
};

inline constexpr std::uint32_t kApplicationProtocolCatalogVersion = 1;
inline constexpr std::array<ApplicationProtocolEntry, 6> kApplicationProtocolCatalog = {{
    {ApplicationProtocolId::RESERVED_1000, "reserved-1000", "reserved", ""},
    {ApplicationProtocolId::DNS, "dns", "active", "infrastructure"},
    {ApplicationProtocolId::HTTP, "http", "active", "web"},
    {ApplicationProtocolId::TLS, "tls", "active", "web"},
    {ApplicationProtocolId::QUIC, "quic", "active", "web"},
    {ApplicationProtocolId::SSH, "ssh", "active", "remote-access"},
}};

inline constexpr std::string_view applicationProtocolKey(ApplicationProtocolId id) {
    for (const auto& entry : kApplicationProtocolCatalog) {
        if (entry.id == id) {
            return entry.key;
        }
    }
    return {};
}

inline constexpr bool applicationProtocolIsActive(ApplicationProtocolId id) {
    for (const auto& entry : kApplicationProtocolCatalog) {
        if (entry.id == id) {
            return entry.status == std::string_view{"active"};
        }
    }
    return false;
}

} // namespace sucre::protocol
