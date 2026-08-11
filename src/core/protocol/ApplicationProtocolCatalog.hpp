#pragma once

#include <array>
#include <cstdint>
#include <optional>
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

struct ApplicationProtocolProviderAlias {
    std::string_view alias;
    ApplicationProtocolId id;
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

inline constexpr std::array<ApplicationProtocolProviderAlias, 6> kApplicationProtocolProviderAliases = {{
    {"lpi:dns", ApplicationProtocolId::DNS},
    {"lpi:http", ApplicationProtocolId::HTTP},
    {"lpi:ssl", ApplicationProtocolId::TLS},
    {"lpi:tls", ApplicationProtocolId::TLS},
    {"lpi:quic", ApplicationProtocolId::QUIC},
    {"lpi:ssh", ApplicationProtocolId::SSH},
}};

inline constexpr std::string_view applicationProtocolKey(ApplicationProtocolId id) {
    for (const auto& entry : kApplicationProtocolCatalog) {
        if (entry.id == id) {
            return entry.key;
        }
    }
    return {};
}

inline constexpr std::string_view applicationProtocolCategory(ApplicationProtocolId id) {
    for (const auto& entry : kApplicationProtocolCatalog) {
        if (entry.id == id) {
            return entry.category;
        }
    }
    return {};
}

inline constexpr std::optional<ApplicationProtocolId> applicationProtocolIdForProviderAlias(std::string_view alias) {
    for (const auto& entry : kApplicationProtocolProviderAliases) {
        if (entry.alias == alias) {
            return entry.id;
        }
    }
    return std::nullopt;
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
