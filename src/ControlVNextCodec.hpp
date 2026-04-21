/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <rapidjson/document.h>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace ControlVNext {

enum class JsonFormat {
    Compact,
    Pretty,
};

struct NetstringError {
    enum class Code {
        InvalidHeader,
        LeadingZero,
        FrameTooLarge,
        MissingTerminator,
        InvalidLength,
    };

    Code code;
    std::string message;
};

class NetstringDecoder {
public:
    explicit NetstringDecoder(size_t maxFrameBytes);

    NetstringDecoder(const NetstringDecoder &) = delete;
    NetstringDecoder &operator=(const NetstringDecoder &) = delete;

    [[nodiscard]] std::optional<NetstringError> feed(std::span<const std::byte> bytes);

    [[nodiscard]] std::optional<std::string> pop();

    [[nodiscard]] size_t queued() const { return _frames.size(); }

    [[nodiscard]] size_t bufferedBytes() const { return _buffer.size(); }

private:
    [[nodiscard]] std::optional<NetstringError> parseAvailable();

    size_t _maxFrameBytes = 0;
    std::string _buffer;
    std::deque<std::string> _frames;

    std::optional<size_t> _expectedLen;
    size_t _headerBytes = 0;
};

[[nodiscard]] std::string encodeNetstring(std::string_view payload);

struct JsonError {
    std::string message;
    size_t offset = 0;
};

[[nodiscard]] bool parseStrictJsonObject(std::string_view json, rapidjson::Document &out,
                                        JsonError &error);

[[nodiscard]] std::string encodeJson(const rapidjson::Value &value, JsonFormat format);

[[nodiscard]] std::optional<std::string_view>
findUnknownKey(const rapidjson::Value &object,
               std::initializer_list<std::string_view> allowedKeys);

struct EnvelopeError {
    std::string code;
    std::string message;
};

struct RequestView {
    uint32_t id = 0;
    std::string_view cmd;
    const rapidjson::Value *args = nullptr;
};

struct ResponseView {
    uint32_t id = 0;
    bool ok = false;
    const rapidjson::Value *result = nullptr;
    const rapidjson::Value *error = nullptr;
};

struct EventView {
    std::string_view type;
};

[[nodiscard]] std::optional<EnvelopeError>
parseRequestEnvelope(const rapidjson::Value &root, RequestView &out);

[[nodiscard]] std::optional<EnvelopeError>
parseResponseEnvelope(const rapidjson::Value &root, ResponseView &out);

[[nodiscard]] std::optional<EnvelopeError>
parseEventEnvelope(const rapidjson::Value &root, EventView &out);

[[nodiscard]] rapidjson::Document makeRequest(uint32_t id, std::string_view cmd,
                                              const rapidjson::Value &args);

[[nodiscard]] rapidjson::Document makeOkResponse(uint32_t id, const rapidjson::Value *result);

[[nodiscard]] rapidjson::Document makeErrorResponse(uint32_t id, std::string_view code,
                                                    std::string_view message);

} // namespace ControlVNext
