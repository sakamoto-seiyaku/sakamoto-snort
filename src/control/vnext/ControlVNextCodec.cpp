/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextCodec.hpp>

#include <rapidjson/error/en.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cerrno>
#include <limits>
#include <utility>

namespace ControlVNext {

namespace {

constexpr bool isDigit(const char ch) { return ch >= '0' && ch <= '9'; }

size_t decimalDigits(size_t value) {
    size_t digits = 1;
    while (value >= 10) {
        value /= 10;
        ++digits;
    }
    return digits;
}

std::optional<EnvelopeError> makeSyntaxError(std::string message) {
    return EnvelopeError{.code = "SYNTAX_ERROR", .message = std::move(message)};
}

std::optional<EnvelopeError> makeMissingArg(std::string message) {
    return EnvelopeError{.code = "MISSING_ARGUMENT", .message = std::move(message)};
}

std::optional<EnvelopeError> makeInvalidArg(std::string message) {
    return EnvelopeError{.code = "INVALID_ARGUMENT", .message = std::move(message)};
}

} // namespace

NetstringDecoder::NetstringDecoder(const size_t maxFrameBytes)
    : _maxFrameBytes(maxFrameBytes), _maxHeaderDigits(decimalDigits(maxFrameBytes)) {}

std::optional<NetstringError> NetstringDecoder::feed(const std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return std::nullopt;
    }
    _buffer.append(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    return parseAvailable();
}

std::optional<std::string> NetstringDecoder::pop() {
    if (_frames.empty()) {
        return std::nullopt;
    }
    std::string out = std::move(_frames.front());
    _frames.pop_front();
    return out;
}

std::optional<NetstringError> NetstringDecoder::parseAvailable() {
    for (;;) {
        if (!_expectedLen.has_value()) {
            if (_buffer.empty()) {
                return std::nullopt;
            }

            const size_t colonPos = _buffer.find(':');
            if (colonPos == std::string::npos) {
                // Partial header: ensure all buffered bytes are digits so far.
                if (!std::all_of(_buffer.begin(), _buffer.end(),
                                 [](const char ch) { return isDigit(ch); })) {
                    return NetstringError{.code = NetstringError::Code::InvalidHeader,
                                          .message = "netstring header contains non-digit"};
                }
                if (_buffer.size() > 1 && _buffer.front() == '0') {
                    return NetstringError{.code = NetstringError::Code::LeadingZero,
                                          .message = "netstring header has leading zero"};
                }
                if (_buffer.size() > _maxHeaderDigits) {
                    return NetstringError{.code = NetstringError::Code::FrameTooLarge,
                                          .message = "netstring header exceeds max frame size"};
                }
                // Need more data.
                return std::nullopt;
            }

            if (colonPos == 0) {
                return NetstringError{.code = NetstringError::Code::InvalidHeader,
                                      .message = "netstring header is empty"};
            }

            // Validate digits.
            const std::string_view lenStr(_buffer.data(), colonPos);
            if (!std::all_of(lenStr.begin(), lenStr.end(),
                             [](const char ch) { return isDigit(ch); })) {
                return NetstringError{.code = NetstringError::Code::InvalidHeader,
                                      .message = "netstring header contains non-digit"};
            }
            if (lenStr.size() > 1 && lenStr.front() == '0') {
                return NetstringError{.code = NetstringError::Code::LeadingZero,
                                      .message = "netstring header has leading zero"};
            }

            size_t declaredLen = 0;
            if (const auto [ptr, ec] =
                    std::from_chars(lenStr.data(), lenStr.data() + lenStr.size(), declaredLen);
                ec != std::errc{} || ptr != lenStr.data() + lenStr.size()) {
                return NetstringError{.code = NetstringError::Code::InvalidLength,
                                      .message = "netstring header length parse failed"};
            }

            if (declaredLen > _maxFrameBytes) {
                return NetstringError{.code = NetstringError::Code::FrameTooLarge,
                                      .message = "netstring frame too large"};
            }

            _expectedLen = declaredLen;
            _headerBytes = colonPos + 1;
        }

        const size_t declaredLen = *_expectedLen;
        const size_t needBytes = _headerBytes + declaredLen + 1; // plus ','
        if (_buffer.size() < needBytes) {
            return std::nullopt; // need more
        }

        if (_buffer[_headerBytes + declaredLen] != ',') {
            return NetstringError{.code = NetstringError::Code::MissingTerminator,
                                  .message = "netstring missing ',' terminator"};
        }

        _frames.emplace_back(_buffer.substr(_headerBytes, declaredLen));
        _buffer.erase(0, needBytes);
        _expectedLen.reset();
        _headerBytes = 0;
    }
}

std::string encodeNetstring(const std::string_view payload) {
    std::array<char, 32> lenBuf{};
    const auto payloadLen = static_cast<uint64_t>(payload.size());
    const auto [ptr, ec] = std::to_chars(lenBuf.data(), lenBuf.data() + lenBuf.size(), payloadLen);
    if (ec != std::errc{}) {
        return {};
    }

    std::string out;
    out.reserve(static_cast<size_t>(ptr - lenBuf.data()) + 1 + payload.size() + 1);
    out.append(lenBuf.data(), static_cast<size_t>(ptr - lenBuf.data()));
    out.push_back(':');
    out.append(payload.data(), payload.size());
    out.push_back(',');
    return out;
}

bool parseStrictJsonObject(const std::string_view json, rapidjson::Document &out, JsonError &error) {
    out.Parse(json.data(), json.size());
    if (out.HasParseError()) {
        error.message = rapidjson::GetParseError_En(out.GetParseError());
        error.offset = out.GetErrorOffset();
        return false;
    }
    if (!out.IsObject()) {
        error.message = "top-level JSON value must be an object";
        error.offset = 0;
        return false;
    }
    return true;
}

std::string encodeJson(const rapidjson::Value &value, const JsonFormat format) {
    rapidjson::StringBuffer buffer;

    if (format == JsonFormat::Pretty) {
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
        writer.SetIndent(' ', 2);
        value.Accept(writer);
    } else {
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        value.Accept(writer);
    }

    return std::string(buffer.GetString(), buffer.GetSize());
}

std::optional<std::string_view>
findUnknownKey(const rapidjson::Value &object,
               const std::initializer_list<std::string_view> allowedKeys) {
    if (!object.IsObject()) {
        return std::nullopt;
    }

    for (auto it = object.MemberBegin(); it != object.MemberEnd(); ++it) {
        const std::string_view key(it->name.GetString(), it->name.GetStringLength());
        const bool allowed = std::any_of(
            allowedKeys.begin(), allowedKeys.end(),
            [&](const std::string_view allowedKey) { return allowedKey == key; });
        if (!allowed) {
            return key;
        }
    }
    return std::nullopt;
}

std::optional<EnvelopeError> parseRequestEnvelope(const rapidjson::Value &root, RequestView &out) {
    if (!root.IsObject()) {
        return makeSyntaxError("request must be a JSON object");
    }
    if (const auto unknown = findUnknownKey(root, {"id", "cmd", "args"}); unknown.has_value()) {
        return makeSyntaxError("unknown request key: " + std::string(*unknown));
    }

    const auto idIt = root.FindMember("id");
    if (idIt == root.MemberEnd()) {
        return makeMissingArg("missing request.id");
    }
    if (!idIt->value.IsUint()) {
        return makeInvalidArg("request.id must be u32");
    }

    const auto cmdIt = root.FindMember("cmd");
    if (cmdIt == root.MemberEnd()) {
        return makeMissingArg("missing request.cmd");
    }
    if (!cmdIt->value.IsString()) {
        return makeInvalidArg("request.cmd must be string");
    }

    const auto argsIt = root.FindMember("args");
    if (argsIt == root.MemberEnd()) {
        return makeMissingArg("missing request.args");
    }
    if (!argsIt->value.IsObject()) {
        return makeInvalidArg("request.args must be object");
    }

    out.id = idIt->value.GetUint();
    out.cmd = std::string_view(cmdIt->value.GetString(), cmdIt->value.GetStringLength());
    out.args = &argsIt->value;
    return std::nullopt;
}

std::optional<EnvelopeError> parseResponseEnvelope(const rapidjson::Value &root, ResponseView &out) {
    if (!root.IsObject()) {
        return makeSyntaxError("response must be a JSON object");
    }
    if (const auto unknown = findUnknownKey(root, {"id", "ok", "result", "error"});
        unknown.has_value()) {
        return makeSyntaxError("unknown response key: " + std::string(*unknown));
    }

    const auto idIt = root.FindMember("id");
    if (idIt == root.MemberEnd()) {
        return makeMissingArg("missing response.id");
    }
    if (!idIt->value.IsUint()) {
        return makeInvalidArg("response.id must be u32");
    }

    const auto okIt = root.FindMember("ok");
    if (okIt == root.MemberEnd()) {
        return makeMissingArg("missing response.ok");
    }
    if (!okIt->value.IsBool()) {
        return makeInvalidArg("response.ok must be boolean");
    }

    const auto resultIt = root.FindMember("result");
    const auto errorIt = root.FindMember("error");
    const bool hasResult = resultIt != root.MemberEnd();
    const bool hasError = errorIt != root.MemberEnd();
    const bool ok = okIt->value.GetBool();

    if (ok) {
        if (hasError) {
            return makeSyntaxError("ok=true response must not contain error");
        }
    } else {
        if (!hasError) {
            return makeMissingArg("ok=false response must contain error");
        }
        if (hasResult) {
            return makeSyntaxError("ok=false response must not contain result");
        }
        if (!errorIt->value.IsObject()) {
            return makeInvalidArg("response.error must be object");
        }
    }

    out.id = idIt->value.GetUint();
    out.ok = ok;
    out.result = hasResult ? &resultIt->value : nullptr;
    out.error = hasError ? &errorIt->value : nullptr;
    return std::nullopt;
}

std::optional<EnvelopeError> parseEventEnvelope(const rapidjson::Value &root, EventView &out) {
    if (!root.IsObject()) {
        return makeSyntaxError("event must be a JSON object");
    }

    if (root.HasMember("id") || root.HasMember("ok")) {
        return makeSyntaxError("event must not contain id/ok");
    }

    const auto typeIt = root.FindMember("type");
    if (typeIt == root.MemberEnd()) {
        return makeMissingArg("missing event.type");
    }
    if (!typeIt->value.IsString()) {
        return makeInvalidArg("event.type must be string");
    }

    out.type = std::string_view(typeIt->value.GetString(), typeIt->value.GetStringLength());
    return std::nullopt;
}

rapidjson::Document makeRequest(const uint32_t id, const std::string_view cmd,
                               const rapidjson::Value &args) {
    rapidjson::Document doc(rapidjson::kObjectType);
    auto &alloc = doc.GetAllocator();

    doc.AddMember("id", id, alloc);

    rapidjson::Value cmdValue;
    cmdValue.SetString(cmd.data(), static_cast<rapidjson::SizeType>(cmd.size()), alloc);
    doc.AddMember("cmd", cmdValue, alloc);

    rapidjson::Value argsValue;
    argsValue.CopyFrom(args, alloc);
    doc.AddMember("args", argsValue, alloc);

    return doc;
}

rapidjson::Document makeOkResponse(const uint32_t id, const rapidjson::Value *result) {
    rapidjson::Document doc(rapidjson::kObjectType);
    auto &alloc = doc.GetAllocator();

    doc.AddMember("id", id, alloc);
    doc.AddMember("ok", true, alloc);
    if (result != nullptr) {
        rapidjson::Value resultValue;
        resultValue.CopyFrom(*result, alloc);
        doc.AddMember("result", resultValue, alloc);
    }
    return doc;
}

rapidjson::Document makeErrorResponse(const uint32_t id, const std::string_view code,
                                     const std::string_view message) {
    rapidjson::Document doc(rapidjson::kObjectType);
    auto &alloc = doc.GetAllocator();

    doc.AddMember("id", id, alloc);
    doc.AddMember("ok", false, alloc);

    rapidjson::Value errorValue(rapidjson::kObjectType);
    rapidjson::Value codeValue;
    codeValue.SetString(code.data(), static_cast<rapidjson::SizeType>(code.size()), alloc);
    errorValue.AddMember("code", codeValue, alloc);
    rapidjson::Value messageValue;
    messageValue.SetString(message.data(), static_cast<rapidjson::SizeType>(message.size()), alloc);
    errorValue.AddMember("message", messageValue, alloc);
    doc.AddMember("error", errorValue, alloc);
    return doc;
}

} // namespace ControlVNext
