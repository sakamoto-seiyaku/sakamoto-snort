/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextCodec.hpp>

#include <rapidjson/document.h>

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::vector<std::byte> asBytes(std::string_view s) {
    std::vector<std::byte> out;
    out.reserve(s.size());
    for (const char ch : s) {
        out.push_back(static_cast<std::byte>(ch));
    }
    return out;
}

} // namespace

TEST(ControlVNextNetstring, EncodesLengthAndTerminators) {
    EXPECT_EQ(ControlVNext::encodeNetstring("{}"), "2:{},");
    EXPECT_EQ(ControlVNext::encodeNetstring(""), "0:,");
    EXPECT_EQ(ControlVNext::encodeNetstring("abc"), "3:abc,");
}

TEST(ControlVNextNetstring, DecodesRoundtripSingleFrame) {
    ControlVNext::NetstringDecoder decoder(/*maxFrameBytes=*/1024);
    const auto bytes = asBytes("3:abc,");
    ASSERT_FALSE(decoder.feed(bytes));
    const auto payload = decoder.pop();
    ASSERT_TRUE(payload.has_value());
    EXPECT_EQ(*payload, "abc");
    EXPECT_FALSE(decoder.pop().has_value());
}

TEST(ControlVNextNetstring, SupportsPartialReads) {
    ControlVNext::NetstringDecoder decoder(/*maxFrameBytes=*/1024);

    ASSERT_FALSE(decoder.feed(asBytes("2:")));
    EXPECT_FALSE(decoder.pop().has_value());

    ASSERT_FALSE(decoder.feed(asBytes("{},")));
    const auto payload = decoder.pop();
    ASSERT_TRUE(payload.has_value());
    EXPECT_EQ(*payload, "{}");
}

TEST(ControlVNextNetstring, SupportsMultipleFramesInOneRead) {
    ControlVNext::NetstringDecoder decoder(/*maxFrameBytes=*/1024);
    ASSERT_FALSE(decoder.feed(asBytes("1:a,1:b,")));

    const auto a = decoder.pop();
    const auto b = decoder.pop();
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(*a, "a");
    EXPECT_EQ(*b, "b");
    EXPECT_FALSE(decoder.pop().has_value());
}

TEST(ControlVNextNetstring, RejectsLeadingZero) {
    ControlVNext::NetstringDecoder decoder(/*maxFrameBytes=*/1024);
    const auto err = decoder.feed(asBytes("01:a,"));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(err->code, ControlVNext::NetstringError::Code::LeadingZero);
}

TEST(ControlVNextNetstring, RejectsNonDigitHeader) {
    ControlVNext::NetstringDecoder decoder(/*maxFrameBytes=*/1024);
    const auto err = decoder.feed(asBytes("x:abc,"));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(err->code, ControlVNext::NetstringError::Code::InvalidHeader);
}

TEST(ControlVNextNetstring, RejectsMissingTerminator) {
    ControlVNext::NetstringDecoder decoder(/*maxFrameBytes=*/1024);
    const auto err = decoder.feed(asBytes("1:a;"));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(err->code, ControlVNext::NetstringError::Code::MissingTerminator);
}

TEST(ControlVNextNetstring, RejectsOversizedFrames) {
    ControlVNext::NetstringDecoder decoder(/*maxFrameBytes=*/2);
    const auto err = decoder.feed(asBytes("3:abc,"));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(err->code, ControlVNext::NetstringError::Code::FrameTooLarge);
}

TEST(ControlVNextJson, ParsesStrictObject) {
    rapidjson::Document doc;
    ControlVNext::JsonError error;
    EXPECT_TRUE(ControlVNext::parseStrictJsonObject(R"({"x":1})", doc, error))
        << error.message;
    EXPECT_TRUE(doc.IsObject());
}

TEST(ControlVNextJson, RejectsTrailingGarbage) {
    rapidjson::Document doc;
    ControlVNext::JsonError error;
    EXPECT_FALSE(ControlVNext::parseStrictJsonObject(R"({"x":1})" " trailing", doc, error));
}

TEST(ControlVNextJson, RejectsNonObjectTopLevel) {
    rapidjson::Document doc;
    ControlVNext::JsonError error;
    EXPECT_FALSE(ControlVNext::parseStrictJsonObject(R"([1,2,3])", doc, error));
}

TEST(ControlVNextJson, StringEscapeRoundtrip) {
    rapidjson::Document in(rapidjson::kObjectType);
    auto &alloc = in.GetAllocator();

    rapidjson::Value value;
    const std::string raw = std::string("quote=\" backslash=\\ newline=\n tab=\t cr=\r");
    value.SetString(raw.data(), static_cast<rapidjson::SizeType>(raw.size()), alloc);
    in.AddMember("s", value, alloc);

    const std::string encoded = ControlVNext::encodeJson(in, ControlVNext::JsonFormat::Compact);

    rapidjson::Document out;
    ControlVNext::JsonError error;
    ASSERT_TRUE(ControlVNext::parseStrictJsonObject(encoded, out, error)) << error.message;
    ASSERT_TRUE(out.HasMember("s"));
    ASSERT_TRUE(out["s"].IsString());
    EXPECT_EQ(std::string(out["s"].GetString(), out["s"].GetStringLength()), raw);
}

TEST(ControlVNextEnvelope, RejectsUnknownKeysInRequest) {
    rapidjson::Document doc;
    doc.Parse(R"({"id":1,"cmd":"HELLO","args":{},"extra":1})");

    ControlVNext::RequestView request;
    const auto err = ControlVNext::parseRequestEnvelope(doc, request);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(err->code, "SYNTAX_ERROR");
}

TEST(ControlVNextEnvelope, ValidatesResponseInvariants) {
    {
        rapidjson::Document doc;
        doc.Parse(R"({"id":1,"ok":true,"error":{"code":"SYNTAX_ERROR","message":"x"}})");
        ControlVNext::ResponseView resp;
        const auto err = ControlVNext::parseResponseEnvelope(doc, resp);
        ASSERT_TRUE(err.has_value());
        EXPECT_EQ(err->code, "SYNTAX_ERROR");
    }
    {
        rapidjson::Document doc;
        doc.Parse(R"({"id":1,"ok":false})");
        ControlVNext::ResponseView resp;
        const auto err = ControlVNext::parseResponseEnvelope(doc, resp);
        ASSERT_TRUE(err.has_value());
        EXPECT_EQ(err->code, "MISSING_ARGUMENT");
    }
}
