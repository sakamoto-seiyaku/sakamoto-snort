/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <core/protocol/ApplicationProtocolCatalog.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <string_view>
#include <vector>

namespace {

using sucre::protocol::ApplicationProtocolId;
using sucre::protocol::applicationProtocolIsActive;
using sucre::protocol::applicationProtocolKey;
using sucre::protocol::kApplicationProtocolCatalog;
using sucre::protocol::kApplicationProtocolCatalogVersion;

TEST(ApplicationProtocolCatalogTest, StableIdsDoNotInheritProviderOrdinals) {
    EXPECT_EQ(kApplicationProtocolCatalogVersion, 1U);
    EXPECT_EQ(static_cast<std::uint32_t>(ApplicationProtocolId::DNS), 1001U);
    EXPECT_EQ(static_cast<std::uint32_t>(ApplicationProtocolId::HTTP), 1002U);
    EXPECT_EQ(static_cast<std::uint32_t>(ApplicationProtocolId::TLS), 1003U);
    EXPECT_EQ(static_cast<std::uint32_t>(ApplicationProtocolId::QUIC), 1004U);

    EXPECT_NE(static_cast<std::uint32_t>(ApplicationProtocolId::DNS), 32U);
    EXPECT_NE(static_cast<std::uint32_t>(ApplicationProtocolId::HTTP), 67U);
    EXPECT_NE(static_cast<std::uint32_t>(ApplicationProtocolId::TLS), 199U);
    EXPECT_NE(static_cast<std::uint32_t>(ApplicationProtocolId::QUIC), 2521U);
}

TEST(ApplicationProtocolCatalogTest, TombstonesStayReservedAndCategoriesAreExactIds) {
    EXPECT_EQ(applicationProtocolKey(ApplicationProtocolId::RESERVED_1000), "reserved-1000");
    EXPECT_FALSE(applicationProtocolIsActive(ApplicationProtocolId::RESERVED_1000));
    EXPECT_TRUE(applicationProtocolIsActive(ApplicationProtocolId::HTTP));

    std::vector<ApplicationProtocolId> webIds;
    for (const auto& entry : kApplicationProtocolCatalog) {
        if (entry.status == std::string_view{"active"}
            && entry.category == std::string_view{"web"}) {
            webIds.push_back(entry.id);
        }
    }

    ASSERT_EQ(webIds.size(), 3U);
    EXPECT_EQ(webIds[0], ApplicationProtocolId::HTTP);
    EXPECT_EQ(webIds[1], ApplicationProtocolId::TLS);
    EXPECT_EQ(webIds[2], ApplicationProtocolId::QUIC);
}

} // namespace
