/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextStreamJson.hpp>
#include <ControlVNextStreamManager.hpp>
#include <Settings.hpp>

#include <gtest/gtest.h>

#include <netinet/in.h>

#include <cstdint>
#include <memory>
#include <string>

// Provide the global Settings instance normally defined in src/sucre-snort.cpp.
Settings settings;

TEST(ControlVNextPktEventJson, L4StatusAlwaysPresentAndPortsZeroWhenNotKnownL4) {
    ControlVNextStreamManager::PktEvent ev{};
    ev.timestamp = timespec{.tv_sec = 1710000000, .tv_nsec = 123};
    ev.uid = 12345;
    ev.userId = 0;
    ev.app = std::make_shared<const std::string>("com.example.app");
    ev.ipVersion = 4;
    ev.proto = IPPROTO_TCP;
    ev.length = 100;
    ev.input = true;
    ev.accepted = true;

    ev.l4Status = L4Status::KNOWN_L4;
    ev.srcPort = 1234;
    ev.dstPort = 80;

    {
        const auto doc = ControlVNextStreamJson::makePktEvent(ev);
        ASSERT_TRUE(doc.IsObject());
        ASSERT_TRUE(doc.HasMember("l4Status"));
        ASSERT_TRUE(doc["l4Status"].IsString());
        EXPECT_STREQ(doc["l4Status"].GetString(), "known-l4");

        ASSERT_TRUE(doc.HasMember("srcPort"));
        ASSERT_TRUE(doc.HasMember("dstPort"));
        EXPECT_EQ(doc["srcPort"].GetUint(), 1234u);
        EXPECT_EQ(doc["dstPort"].GetUint(), 80u);
    }

    // When L4 is not known, ports must be forced to 0 in stream output.
    ev.l4Status = L4Status::FRAGMENT;
    ev.srcPort = 5555;
    ev.dstPort = 6666;
    {
        const auto doc = ControlVNextStreamJson::makePktEvent(ev);
        ASSERT_TRUE(doc.IsObject());
        ASSERT_TRUE(doc.HasMember("l4Status"));
        ASSERT_TRUE(doc["l4Status"].IsString());
        EXPECT_STREQ(doc["l4Status"].GetString(), "fragment");

        ASSERT_TRUE(doc.HasMember("srcPort"));
        ASSERT_TRUE(doc.HasMember("dstPort"));
        EXPECT_EQ(doc["srcPort"].GetUint(), 0u);
        EXPECT_EQ(doc["dstPort"].GetUint(), 0u);
    }
}
