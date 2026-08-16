#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include "decoded_asset_cache.h"
#include "native_draw_descriptor_builder.h"
#include "native_draw_runtime_v2.h"
#include "native_face_runtime.h"
#include "native_face_plan.h"
#include "native_facepaint_decode.h"
#include "native_geometry.h"
#include "native_material_field_packer.h"
#include "native_material_provider.h"
#include "native_material_schedule.h"
#include "native_noseline12.h"
#include "native_noseline_pipeline_bridge.h"
#include "native_parts_selector.h"
#include "native_png.h"
#include "native_pose.h"
#include "native_postprocess.h"
#include "native_raster_core.h"
#include "native_render_orchestrator.h"
#include "native_render_pipeline.h"
#include "native_runtime_material_adapter.h"
#include "native_scene_assembler.h"
#include "native_scene_cache_adapter.h"
#include "native_scene_math.h"

#include <algorithm>
#include <atomic>
#include <array>
#include <charconv>
#include <cctype>
#include <cmath>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <limits>
#include <locale>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace native_runtime {

constexpr std::string_view kProtocol = "infinimii.ltd-native-runtime";
constexpr std::int64_t kProtocolVersion = 1;
constexpr std::string_view kRuntimeVersion = "0.5.0-native-render-integration-boundary";
constexpr std::string_view kNativePartsCatalogSha256 =
    "d8d56e7ee1e291e2e4cc213ef88521b594093a83952747f1d3c8ab0ca5b00523";
constexpr std::string_view kNativePngBackendSha256 =
    "1a1082400ef0ba899ac6f9264e6c17619d5e967944b99f5ea9ef66eec2f3bc52";
constexpr std::size_t kMaximumRequestBytes = 64 * 1024;
constexpr std::size_t kMaximumLtdBytes = 64 * 1024 * 1024;
constexpr std::uint64_t kMaximumDecodedFrameBytes = 16 * 1024 * 1024;

class RuntimeError final : public std::runtime_error {
public:
    RuntimeError(std::string code, std::string message)
        : std::runtime_error(std::move(message)), code_(std::move(code)) {}

    [[nodiscard]] const std::string& code() const noexcept { return code_; }

private:
    std::string code_;
};

class Json final {
public:
    using Array = std::vector<Json>;
    using Object = std::map<std::string, Json, std::less<>>;
    using Storage =
        std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, Array, Object>;

    Json() : value_(nullptr) {}
    Json(std::nullptr_t) : value_(nullptr) {}
    Json(bool value) : value_(value) {}
    Json(std::int64_t value) : value_(value) {}
    Json(double value) : value_(value) {}
    Json(std::string value) : value_(std::move(value)) {}
    Json(const char* value) : value_(std::string(value)) {}
    Json(Array value) : value_(std::move(value)) {}
    Json(Object value) : value_(std::move(value)) {}

    [[nodiscard]] bool is_null() const { return std::holds_alternative<std::nullptr_t>(value_); }
    [[nodiscard]] bool is_bool() const { return std::holds_alternative<bool>(value_); }
    [[nodiscard]] bool is_integer() const { return std::holds_alternative<std::int64_t>(value_); }
    [[nodiscard]] bool is_double() const { return std::holds_alternative<double>(value_); }
    [[nodiscard]] bool is_string() const { return std::holds_alternative<std::string>(value_); }
    [[nodiscard]] bool is_array() const { return std::holds_alternative<Array>(value_); }
    [[nodiscard]] bool is_object() const { return std::holds_alternative<Object>(value_); }

    [[nodiscard]] bool as_bool() const { return std::get<bool>(value_); }
    [[nodiscard]] std::int64_t as_integer() const { return std::get<std::int64_t>(value_); }
    [[nodiscard]] double as_double() const { return std::get<double>(value_); }
    [[nodiscard]] const std::string& as_string() const { return std::get<std::string>(value_); }
    [[nodiscard]] const Array& as_array() const { return std::get<Array>(value_); }
    [[nodiscard]] const Object& as_object() const { return std::get<Object>(value_); }
    [[nodiscard]] Object& as_object() { return std::get<Object>(value_); }

    [[nodiscard]] std::string dump() const {
        std::string output;
        dump_into(output);
        return output;
    }

    friend bool operator==(const Json& left, const Json& right) {
        return left.value_ == right.value_;
    }

private:
    Storage value_;

    static void dump_string(std::string& output, std::string_view text) {
        static constexpr char hex[] = "0123456789abcdef";
        output.push_back('"');
        for (unsigned char byte : text) {
            switch (byte) {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (byte < 0x20) {
                    output += "\\u00";
                    output.push_back(hex[byte >> 4]);
                    output.push_back(hex[byte & 0x0f]);
                } else {
                    output.push_back(static_cast<char>(byte));
                }
            }
        }
        output.push_back('"');
    }

    void dump_into(std::string& output) const {
        if (is_null()) {
            output += "null";
        } else if (is_bool()) {
            output += as_bool() ? "true" : "false";
        } else if (is_integer()) {
            output += std::to_string(as_integer());
        } else if (is_double()) {
            std::array<char, 64> buffer{};
            const auto converted = std::to_chars(
                buffer.data(), buffer.data() + buffer.size(), as_double(),
                std::chars_format::general, std::numeric_limits<double>::max_digits10);
            if (converted.ec != std::errc{}) {
                throw RuntimeError("JSON_SERIALIZE_FAILURE", "could not serialize finite number");
            }
            output.append(buffer.data(), converted.ptr);
        } else if (is_string()) {
            dump_string(output, as_string());
        } else if (is_array()) {
            output.push_back('[');
            bool first = true;
            for (const Json& item : as_array()) {
                if (!first) output.push_back(',');
                first = false;
                item.dump_into(output);
            }
            output.push_back(']');
        } else {
            output.push_back('{');
            bool first = true;
            for (const auto& [key, item] : as_object()) {
                if (!first) output.push_back(',');
                first = false;
                dump_string(output, key);
                output.push_back(':');
                item.dump_into(output);
            }
            output.push_back('}');
        }
    }
};

void append_utf8(std::string& output, std::uint32_t codepoint) {
    if (codepoint <= 0x7f) {
        output.push_back(static_cast<char>(codepoint));
    } else if (codepoint <= 0x7ff) {
        output.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    } else if (codepoint <= 0xffff) {
        output.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    } else {
        output.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    }
}

bool is_valid_utf8(std::string_view text) {
    std::size_t cursor = 0;
    while (cursor < text.size()) {
        const auto first = static_cast<unsigned char>(text[cursor++]);
        if (first <= 0x7f) continue;
        int continuation_count = 0;
        std::uint32_t codepoint = 0;
        std::uint32_t minimum = 0;
        if ((first & 0xe0) == 0xc0) {
            continuation_count = 1;
            codepoint = first & 0x1f;
            minimum = 0x80;
        } else if ((first & 0xf0) == 0xe0) {
            continuation_count = 2;
            codepoint = first & 0x0f;
            minimum = 0x800;
        } else if ((first & 0xf8) == 0xf0) {
            continuation_count = 3;
            codepoint = first & 0x07;
            minimum = 0x10000;
        } else {
            return false;
        }
        if (cursor + continuation_count > text.size()) return false;
        for (int index = 0; index < continuation_count; ++index) {
            const auto byte = static_cast<unsigned char>(text[cursor++]);
            if ((byte & 0xc0) != 0x80) return false;
            codepoint = (codepoint << 6) | (byte & 0x3f);
        }
        if (codepoint < minimum || codepoint > 0x10ffff ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
            return false;
        }
    }
    return true;
}

class JsonParser final {
public:
    explicit JsonParser(std::string_view input) : input_(input) {}

    Json parse() {
        skip_whitespace();
        Json value = parse_value();
        skip_whitespace();
        if (cursor_ != input_.size()) fail("unexpected trailing data");
        return value;
    }

private:
    std::string_view input_;
    std::size_t cursor_ = 0;

    [[noreturn]] void fail(std::string_view message) const {
        throw RuntimeError(
            "INVALID_JSON",
            std::string(message) + " at byte " + std::to_string(cursor_));
    }

    void skip_whitespace() {
        while (cursor_ < input_.size()) {
            const char byte = input_[cursor_];
            if (byte != ' ' && byte != '\t' && byte != '\r' && byte != '\n') break;
            ++cursor_;
        }
    }

    bool consume(char expected) {
        if (cursor_ < input_.size() && input_[cursor_] == expected) {
            ++cursor_;
            return true;
        }
        return false;
    }

    Json parse_value() {
        if (cursor_ >= input_.size()) fail("expected JSON value");
        switch (input_[cursor_]) {
        case 'n': return parse_literal("null", Json(nullptr));
        case 't': return parse_literal("true", Json(true));
        case 'f': return parse_literal("false", Json(false));
        case '"': return Json(parse_string());
        case '[': return parse_array();
        case '{': return parse_object();
        default:
            if (input_[cursor_] == '-' ||
                (input_[cursor_] >= '0' && input_[cursor_] <= '9')) {
                return parse_number();
            }
            fail("unexpected byte while reading JSON value");
        }
    }

    Json parse_literal(std::string_view literal, Json value) {
        if (input_.substr(cursor_, literal.size()) != literal) fail("invalid JSON literal");
        cursor_ += literal.size();
        return value;
    }

    std::uint32_t parse_hex_quad() {
        if (cursor_ + 4 > input_.size()) fail("truncated Unicode escape");
        std::uint32_t value = 0;
        for (int index = 0; index < 4; ++index) {
            const char byte = input_[cursor_++];
            value <<= 4;
            if (byte >= '0' && byte <= '9') value |= static_cast<std::uint32_t>(byte - '0');
            else if (byte >= 'a' && byte <= 'f') value |= static_cast<std::uint32_t>(byte - 'a' + 10);
            else if (byte >= 'A' && byte <= 'F') value |= static_cast<std::uint32_t>(byte - 'A' + 10);
            else fail("invalid Unicode escape");
        }
        return value;
    }

    std::string parse_string() {
        if (!consume('"')) fail("expected string");
        std::string result;
        while (cursor_ < input_.size()) {
            const auto byte = static_cast<unsigned char>(input_[cursor_++]);
            if (byte == '"') {
                if (!is_valid_utf8(result)) fail("string is not valid UTF-8");
                return result;
            }
            if (byte < 0x20) fail("unescaped control byte in string");
            if (byte != '\\') {
                result.push_back(static_cast<char>(byte));
                continue;
            }
            if (cursor_ >= input_.size()) fail("truncated string escape");
            const char escape = input_[cursor_++];
            switch (escape) {
            case '"': result.push_back('"'); break;
            case '\\': result.push_back('\\'); break;
            case '/': result.push_back('/'); break;
            case 'b': result.push_back('\b'); break;
            case 'f': result.push_back('\f'); break;
            case 'n': result.push_back('\n'); break;
            case 'r': result.push_back('\r'); break;
            case 't': result.push_back('\t'); break;
            case 'u': {
                std::uint32_t codepoint = parse_hex_quad();
                if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
                    if (cursor_ + 2 > input_.size() || input_[cursor_] != '\\' ||
                        input_[cursor_ + 1] != 'u') {
                        fail("high surrogate is not followed by a low surrogate");
                    }
                    cursor_ += 2;
                    const std::uint32_t low = parse_hex_quad();
                    if (low < 0xdc00 || low > 0xdfff) fail("invalid low surrogate");
                    codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (low - 0xdc00);
                } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
                    fail("unpaired low surrogate");
                }
                append_utf8(result, codepoint);
                break;
            }
            default: fail("invalid string escape");
            }
        }
        fail("unterminated string");
    }

    Json parse_number() {
        const std::size_t begin = cursor_;
        consume('-');
        if (cursor_ >= input_.size()) fail("truncated number");
        if (input_[cursor_] == '0') {
            ++cursor_;
            if (cursor_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[cursor_]))) {
                fail("leading zero in number");
            }
        } else {
            if (input_[cursor_] < '1' || input_[cursor_] > '9') fail("invalid number");
            while (cursor_ < input_.size() &&
                   std::isdigit(static_cast<unsigned char>(input_[cursor_]))) ++cursor_;
        }
        bool is_integral = true;
        if (cursor_ < input_.size() && input_[cursor_] == '.') {
            is_integral = false;
            ++cursor_;
            if (cursor_ >= input_.size() ||
                !std::isdigit(static_cast<unsigned char>(input_[cursor_]))) {
                fail("fraction has no digits");
            }
            while (cursor_ < input_.size() &&
                   std::isdigit(static_cast<unsigned char>(input_[cursor_]))) ++cursor_;
        }
        if (cursor_ < input_.size() &&
            (input_[cursor_] == 'e' || input_[cursor_] == 'E')) {
            is_integral = false;
            ++cursor_;
            if (cursor_ < input_.size() &&
                (input_[cursor_] == '+' || input_[cursor_] == '-')) ++cursor_;
            if (cursor_ >= input_.size() ||
                !std::isdigit(static_cast<unsigned char>(input_[cursor_]))) {
                fail("exponent has no digits");
            }
            while (cursor_ < input_.size() &&
                   std::isdigit(static_cast<unsigned char>(input_[cursor_]))) ++cursor_;
        }
        const std::string token(input_.substr(begin, cursor_ - begin));
        if (is_integral) {
            try {
                std::size_t consumed = 0;
                const auto value = std::stoll(token, &consumed, 10);
                if (consumed != token.size()) fail("invalid integer");
                return Json(value);
            } catch (const std::exception&) {
                fail("integer is outside signed 64-bit range");
            }
        }
        char* end = nullptr;
        const double value = std::strtod(token.c_str(), &end);
        if (end != token.c_str() + token.size() || !std::isfinite(value)) {
            fail("number is outside finite double range");
        }
        return Json(value);
    }

    Json parse_array() {
        consume('[');
        Json::Array result;
        skip_whitespace();
        if (consume(']')) return Json(std::move(result));
        while (true) {
            skip_whitespace();
            result.push_back(parse_value());
            skip_whitespace();
            if (consume(']')) return Json(std::move(result));
            if (!consume(',')) fail("expected comma in array");
        }
    }

    Json parse_object() {
        consume('{');
        Json::Object result;
        skip_whitespace();
        if (consume('}')) return Json(std::move(result));
        while (true) {
            skip_whitespace();
            if (cursor_ >= input_.size() || input_[cursor_] != '"') fail("expected object key");
            std::string key = parse_string();
            skip_whitespace();
            if (!consume(':')) fail("expected colon after object key");
            skip_whitespace();
            Json value = parse_value();
            if (!result.emplace(std::move(key), std::move(value)).second) {
                fail("duplicate object key");
            }
            skip_whitespace();
            if (consume('}')) return Json(std::move(result));
            if (!consume(',')) fail("expected comma in object");
        }
    }
};

std::wstring utf8_to_wide(std::string_view input, std::string_view context) {
    if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw RuntimeError("INVALID_REQUEST", std::string(context) + " is too long");
    }
    if (input.empty()) return {};
    const int required = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (required <= 0) {
        throw RuntimeError("INVALID_REQUEST", std::string(context) + " is not valid UTF-8");
    }
    std::wstring output(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                            static_cast<int>(input.size()), output.data(), required) != required) {
        throw RuntimeError("INVALID_REQUEST", "failed to decode " + std::string(context));
    }
    return output;
}

std::string wide_to_utf8(std::wstring_view input) {
    if (input.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()),
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) throw RuntimeError("UTF16_INVALID", "invalid UTF-16 string");
    std::string output(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(),
                            static_cast<int>(input.size()), output.data(), required,
                            nullptr, nullptr) != required) {
        throw RuntimeError("UTF16_INVALID", "failed to encode UTF-16 string");
    }
    return output;
}

std::string decode_utf16le(const std::uint8_t* bytes, std::size_t byte_length,
                           std::string_view section) {
    if ((byte_length & 1U) != 0) {
        throw RuntimeError("LTD_UTF16_INVALID", std::string(section) + " has odd byte length");
    }
    std::wstring value;
    value.reserve(byte_length / 2);
    for (std::size_t offset = 0; offset < byte_length; offset += 2) {
        const auto code_unit = static_cast<wchar_t>(
            static_cast<std::uint16_t>(bytes[offset]) |
            (static_cast<std::uint16_t>(bytes[offset + 1]) << 8));
        if (code_unit == L'\0') break;
        value.push_back(code_unit);
    }
    try {
        return wide_to_utf8(value);
    } catch (const RuntimeError&) {
        throw RuntimeError("LTD_UTF16_INVALID", std::string(section) + " contains invalid UTF-16");
    }
}

std::string sha256_hex(const std::uint8_t* data, std::size_t size) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        throw RuntimeError("HASH_FAILURE", "BCryptOpenAlgorithmProvider(SHA-256) failed");
    }
    std::array<std::uint8_t, 32> digest{};
    const auto close_algorithm = [&]() {
        if (hash) BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
    };
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0) {
        close_algorithm();
        throw RuntimeError("HASH_FAILURE", "BCryptCreateHash(SHA-256) failed");
    }
    constexpr std::size_t chunk_limit = static_cast<std::size_t>(std::numeric_limits<ULONG>::max());
    std::size_t cursor = 0;
    while (cursor < size) {
        const std::size_t chunk = std::min(chunk_limit, size - cursor);
        if (BCryptHashData(hash, const_cast<PUCHAR>(data + cursor),
                           static_cast<ULONG>(chunk), 0) < 0) {
            close_algorithm();
            throw RuntimeError("HASH_FAILURE", "BCryptHashData(SHA-256) failed");
        }
        cursor += chunk;
    }
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) {
        close_algorithm();
        throw RuntimeError("HASH_FAILURE", "BCryptFinishHash(SHA-256) failed");
    }
    close_algorithm();
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(digest.size() * 2);
    for (std::uint8_t byte : digest) {
        output.push_back(hex[byte >> 4]);
        output.push_back(hex[byte & 0x0f]);
    }
    return output;
}

std::string sha256_hex(const std::vector<std::uint8_t>& data) {
    return sha256_hex(data.data(), data.size());
}

std::filesystem::path executable_directory() {
    std::vector<wchar_t> buffer(1024);
    while (true) {
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) throw RuntimeError("RUNTIME_FAILURE", "GetModuleFileNameW failed");
        if (length < buffer.size() - 1) {
            return std::filesystem::path(std::wstring(buffer.data(), length)).parent_path();
        }
        if (buffer.size() >= 32768) {
            throw RuntimeError("RUNTIME_FAILURE", "executable path exceeds Windows path limit");
        }
        buffer.resize(buffer.size() * 2);
    }
}

class PinnedNativePngBackend final {
public:
    explicit PinnedNativePngBackend(std::filesystem::path path)
        : path_(std::move(path)) {
        HANDLE handle = CreateFileW(
            path_.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
                FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            throw RuntimeError(
                "NATIVE_RENDER_PNG_BACKEND",
                "native png sha256 source could not be opened under a read-only pin");
        }
        try {
            FILE_ATTRIBUTE_TAG_INFO tag{};
            if (!GetFileInformationByHandleEx(
                    handle, FileAttributeTagInfo, &tag, sizeof(tag)) ||
                (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                                       FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
                throw RuntimeError(
                    "NATIVE_RENDER_PNG_BACKEND",
                    "native png sha256 source is not a regular sibling file");
            }
            LARGE_INTEGER signed_size{};
            if (!GetFileSizeEx(handle, &signed_size) || signed_size.QuadPart <= 0 ||
                signed_size.QuadPart > 64LL * 1024LL * 1024LL) {
                throw RuntimeError(
                    "NATIVE_RENDER_PNG_BACKEND",
                    "native png sha256 source has an invalid byte length");
            }
            byte_count_ = static_cast<std::size_t>(signed_size.QuadPart);
            std::vector<std::uint8_t> bytes(byte_count_);
            std::size_t offset = 0;
            while (offset != bytes.size()) {
                const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
                    bytes.size() - offset, std::numeric_limits<DWORD>::max()));
                DWORD read = 0;
                if (!ReadFile(handle, bytes.data() + offset, requested, &read, nullptr) ||
                    read != requested) {
                    throw RuntimeError(
                        "NATIVE_RENDER_PNG_BACKEND",
                        "native png sha256 source could not be read completely");
                }
                offset += read;
            }
            sha256_ = sha256_hex(bytes);
            handle_ = handle;
        } catch (...) {
            CloseHandle(handle);
            throw;
        }
    }

    ~PinnedNativePngBackend() {
        if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
    }
    PinnedNativePngBackend(const PinnedNativePngBackend&) = delete;
    PinnedNativePngBackend& operator=(const PinnedNativePngBackend&) = delete;
    PinnedNativePngBackend(PinnedNativePngBackend&&) = delete;
    PinnedNativePngBackend& operator=(PinnedNativePngBackend&&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
    [[nodiscard]] const std::string& sha256() const noexcept { return sha256_; }
    [[nodiscard]] std::size_t byte_count() const noexcept { return byte_count_; }
    [[nodiscard]] bool authenticated() const noexcept {
        return sha256_ == kNativePngBackendSha256;
    }

private:
    std::filesystem::path path_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::string sha256_;
    std::size_t byte_count_ = 0;
};

std::filesystem::path native_png_backend_sibling_path() {
    try {
        return (executable_directory() / L"native_png_zlib1.dll").lexically_normal();
    } catch (const RuntimeError& error) {
        throw RuntimeError(
            "NATIVE_RENDER_PNG_BACKEND",
            std::string("could not resolve the native png sibling path: ") + error.what());
    }
}

class ZstdApi final {
public:
    ZstdApi() { load(); }
    ~ZstdApi() { if (module_) FreeLibrary(module_); }
    ZstdApi(const ZstdApi&) = delete;
    ZstdApi& operator=(const ZstdApi&) = delete;

    [[nodiscard]] bool available() const noexcept { return module_ != nullptr; }
    [[nodiscard]] const std::string& loaded_path() const noexcept { return loaded_path_; }
    [[nodiscard]] const std::string& availability_error() const noexcept { return availability_error_; }
    [[nodiscard]] unsigned version_number() const noexcept {
        return available() ? version_number_() : 0;
    }

    [[nodiscard]] ltd_native_facepaint_zstd_api facepaint_decode_api() const {
        require_available();
        return ltd_native_facepaint_zstd_api{
            LTD_NATIVE_FACEPAINT_ZSTD_ABI_VERSION,
            0,
            find_frame_size_,
            get_content_size_,
            decompress_,
            is_error_,
        };
    }

    std::size_t frame_size(const std::uint8_t* data, std::size_t size,
                           std::string_view section) const {
        require_available();
        const std::size_t result = find_frame_size_(data, size);
        if (is_error_(result)) {
            throw RuntimeError(
                "LTD_ZSTD_INVALID",
                "invalid or truncated Zstandard " + std::string(section) + " frame: " +
                    error_name_(result));
        }
        if (result == 0 || result > size) {
            throw RuntimeError("LTD_ZSTD_INVALID",
                               "invalid Zstandard " + std::string(section) + " frame size");
        }
        return result;
    }

    Json validate_frame(const std::uint8_t* data, std::size_t size,
                        std::string_view section) const {
        require_available();
        const std::size_t encoded_size = frame_size(data, size, section);
        if (encoded_size != size) {
            throw RuntimeError(
                "LTD_ZSTD_TRAILING_DATA",
                "Zstandard " + std::string(section) +
                    " payload contains trailing bytes or more than one frame");
        }
        // Zstandard's public sentinels are intentionally adjacent but ordered as
        // UNKNOWN == UINT64_MAX and ERROR == UINT64_MAX - 1.  Keep these local
        // constants independent of zstd headers because the runtime loads the ABI
        // dynamically.
        constexpr unsigned long long content_size_unknown =
            std::numeric_limits<unsigned long long>::max();
        constexpr unsigned long long content_size_error = content_size_unknown - 1;
        const unsigned long long decoded_size = get_content_size_(data, size);
        if (decoded_size == content_size_error) {
            throw RuntimeError("LTD_ZSTD_INVALID",
                               "invalid Zstandard " + std::string(section) + " content size");
        }
        if (decoded_size == content_size_unknown) {
            throw RuntimeError(
                "LTD_ZSTD_UNKNOWN_SIZE",
                "Zstandard " + std::string(section) + " frame omits its decoded size");
        }
        if (decoded_size > kMaximumDecodedFrameBytes) {
            throw RuntimeError(
                "LTD_ZSTD_TOO_LARGE",
                "Zstandard " + std::string(section) + " expands beyond the " +
                    std::to_string(kMaximumDecodedFrameBytes) + "-byte safety limit");
        }
        std::vector<std::uint8_t> decoded(static_cast<std::size_t>(decoded_size));
        std::uint8_t zero_byte = 0;
        void* destination = decoded.empty() ? static_cast<void*>(&zero_byte) : decoded.data();
        const std::size_t actual = decompress_(destination, decoded.size(), data, size);
        if (is_error_(actual)) {
            throw RuntimeError(
                "LTD_ZSTD_INVALID",
                "failed to decompress Zstandard " + std::string(section) + " frame: " +
                    error_name_(actual));
        }
        if (actual != decoded.size()) {
            throw RuntimeError(
                "LTD_ZSTD_SIZE_MISMATCH",
                "Zstandard " + std::string(section) + " decoded length does not match frame metadata");
        }
        return Json::Object{
            {"decoded_byte_length", Json(static_cast<std::int64_t>(decoded.size()))},
            {"decoded_sha256", Json(sha256_hex(decoded))},
            {"encoded_frame_byte_length", Json(static_cast<std::int64_t>(encoded_size))},
            {"status", Json("validated")},
        };
    }

private:
    using VersionNumberFn = unsigned (*)();
    using FindFrameSizeFn = std::size_t (*)(const void*, std::size_t);
    using GetContentSizeFn = unsigned long long (*)(const void*, std::size_t);
    using DecompressFn = std::size_t (*)(void*, std::size_t, const void*, std::size_t);
    using IsErrorFn = unsigned (*)(std::size_t);
    using ErrorNameFn = const char* (*)(std::size_t);

    HMODULE module_ = nullptr;
    std::string loaded_path_;
    std::string availability_error_;
    VersionNumberFn version_number_ = nullptr;
    FindFrameSizeFn find_frame_size_ = nullptr;
    GetContentSizeFn get_content_size_ = nullptr;
    DecompressFn decompress_ = nullptr;
    IsErrorFn is_error_ = nullptr;
    ErrorNameFn error_name_ = nullptr;

    template <typename Function>
    Function resolve(const char* name) {
        const auto address = GetProcAddress(module_, name);
        if (!address) {
            throw RuntimeError("ZSTD_SYMBOL_MISSING", std::string("libzstd is missing ") + name);
        }
        return reinterpret_cast<Function>(address);
    }

    void load() {
        std::vector<std::filesystem::path> candidates;
        DWORD environment_length = GetEnvironmentVariableW(L"INFINIMII_NATIVE_ZSTD_DLL", nullptr, 0);
        if (environment_length > 1) {
            std::wstring environment_value(environment_length, L'\0');
            const DWORD written = GetEnvironmentVariableW(
                L"INFINIMII_NATIVE_ZSTD_DLL", environment_value.data(), environment_length);
            if (written > 0 && written < environment_length) {
                environment_value.resize(written);
                candidates.emplace_back(environment_value);
            }
        }
        try {
            candidates.push_back(executable_directory() / L"libzstd.dll");
        } catch (const RuntimeError& error) {
            availability_error_ = error.what();
        }
        for (const auto& candidate : candidates) {
            module_ = LoadLibraryExW(
                candidate.c_str(), nullptr,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
            if (module_) {
                loaded_path_ = wide_to_utf8(candidate.wstring());
                break;
            }
        }
        if (!module_) {
            availability_error_ =
                "libzstd.dll was not found beside the executable and "
                "INFINIMII_NATIVE_ZSTD_DLL did not resolve";
            return;
        }
        try {
            version_number_ = resolve<VersionNumberFn>("ZSTD_versionNumber");
            find_frame_size_ = resolve<FindFrameSizeFn>("ZSTD_findFrameCompressedSize");
            get_content_size_ = resolve<GetContentSizeFn>("ZSTD_getFrameContentSize");
            decompress_ = resolve<DecompressFn>("ZSTD_decompress");
            is_error_ = resolve<IsErrorFn>("ZSTD_isError");
            error_name_ = resolve<ErrorNameFn>("ZSTD_getErrorName");
        } catch (const RuntimeError& error) {
            availability_error_ = error.what();
            FreeLibrary(module_);
            module_ = nullptr;
            loaded_path_.clear();
        }
    }

    void require_available() const {
        if (!available()) {
            throw RuntimeError("LTD_ZSTD_UNAVAILABLE", availability_error_);
        }
    }
};

std::uint32_t read_u32le(const std::uint8_t* data) {
    return static_cast<std::uint32_t>(data[0]) |
        (static_cast<std::uint32_t>(data[1]) << 8) |
        (static_cast<std::uint32_t>(data[2]) << 16) |
        (static_cast<std::uint32_t>(data[3]) << 24);
}

std::uint16_t read_u16le(const std::uint8_t* data) {
    return static_cast<std::uint16_t>(data[0]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[1]) << 8);
}

std::string hex_encode(const std::uint8_t* data, std::size_t size) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(size * 2);
    for (std::size_t index = 0; index < size; ++index) {
        output.push_back(hex[data[index] >> 4]);
        output.push_back(hex[data[index] & 0x0f]);
    }
    return output;
}

std::string uuid_text(const std::uint8_t* bytes) {
    const std::string raw = hex_encode(bytes, 16);
    return raw.substr(0, 8) + "-" + raw.substr(8, 4) + "-" + raw.substr(12, 4) +
        "-" + raw.substr(16, 4) + "-" + raw.substr(20, 12);
}

constexpr std::array<std::string_view, 30> kByteFields = {
    "font_region", "gender", "height", "build", "region_move", "face_flags_raw",
    "faceline_type", "faceline_color", "wrinkle_lower_type", "wrinkle_lower_scale",
    "wrinkle_lower_aspect", "wrinkle_lower_x", "wrinkle_lower_y", "wrinkle_upper_type",
    "wrinkle_upper_scale", "wrinkle_upper_aspect", "wrinkle_upper_x", "wrinkle_upper_y",
    "makeup_upper_type", "makeup_upper_color", "makeup_upper_scale", "makeup_upper_aspect",
    "makeup_upper_x", "makeup_upper_y", "makeup_lower_type", "makeup_lower_color",
    "makeup_lower_scale", "makeup_lower_aspect", "makeup_lower_x", "makeup_lower_y",
};

constexpr std::array<std::string_view, 82> kPostHairByteFields = {
    "hair_color_primary", "hair_color_secondary", "hair_front_type", "hair_back_type",
    "hair_style_flags_raw", "ear_type", "ear_scale", "ear_y", "eye_type", "eye_color",
    "eye_scale", "eye_aspect", "eye_rotate", "eye_x", "eye_y", "eye_shadow_color",
    "eye_highlight_type", "eye_highlight_scale", "eye_highlight_aspect", "eye_highlight_rotate",
    "eye_highlight_x", "eye_highlight_y", "eyelash_upper_type", "eyelash_upper_scale",
    "eyelash_upper_aspect", "eyelash_upper_rotate", "eyelash_upper_x", "eyelash_upper_y",
    "eyelash_lower_type", "eyelash_lower_scale", "eyelash_lower_aspect", "eyelash_lower_rotate",
    "eyelash_lower_x", "eyelash_lower_y", "eyelid_upper_type", "eyelid_upper_scale",
    "eyelid_upper_aspect", "eyelid_upper_rotate", "eyelid_upper_x", "eyelid_upper_y",
    "eyelid_lower_type", "eyelid_lower_scale", "eyelid_lower_aspect", "eyelid_lower_rotate",
    "eyelid_lower_x", "eyelid_lower_y", "eyebrow_type", "eyebrow_color", "eyebrow_scale",
    "eyebrow_aspect", "eyebrow_rotate", "eyebrow_x", "eyebrow_y", "nose_type", "nose_scale",
    "nose_y", "mouth_type", "mouth_color", "mouth_scale", "mouth_aspect", "mouth_rotate",
    "mouth_y", "beard_type", "beard_color", "stubble_type", "stubble_color", "mustache_type",
    "mustache_color", "mustache_scale", "mustache_aspect", "mustache_y", "glass_primary_type",
    "glass_primary_color", "glass_scale", "glass_aspect", "glass_y", "glass_lens_material_mode",
    "glass_lens_color", "mole_scale", "mole_x", "mole_y", "schema_version",
};

constexpr std::array<std::string_view, 18> kPersonalityFields = {
    "sociability", "audaciousness", "activeness", "commonsense", "gaiety",
    "voice_formant", "voice_speed", "voice_intonation", "voice_pitch", "voice_tension",
    "voice_preset_type_hash", "face_gender_hash", "pronoun_type_hash", "cloth_style_hash",
    "birthday_year", "birthday_day", "birthday_direct_age", "birthday_month",
};

Json parse_char_info(const std::uint8_t* data) {
    Json::Object result{
        {"name", Json(decode_utf16le(data + 16, 22, "CharInfoEx name"))},
        {"uuid", Json(uuid_text(data))},
        {"uuid_raw", Json(hex_encode(data, 16))},
    };
    std::size_t cursor = 38;
    for (std::string_view field : kByteFields) {
        result.emplace(std::string(field), Json(static_cast<std::int64_t>(data[cursor++])));
    }
    result.emplace("hair_type", Json(static_cast<std::int64_t>(read_u16le(data + cursor))));
    cursor += 2;
    for (std::string_view field : kPostHairByteFields) {
        result.emplace(std::string(field), Json(static_cast<std::int64_t>(data[cursor++])));
    }
    if (cursor != 152) {
        throw RuntimeError("RUNTIME_SCHEMA_ERROR", "native CharInfoEx schema does not consume 152 bytes");
    }
    const std::uint8_t face_flags = data[38 + 5];
    result.emplace("face_flags", Json::Object{
        {"back_dual_color", Json((face_flags & 0x04) != 0)},
        {"bangs_dual_color", Json((face_flags & 0x08) != 0)},
        {"bangs_side", Json((face_flags & 0x02) != 0)},
        {"eye_shadow_enabled", Json((face_flags & 0x10) != 0)},
        {"mole_enabled", Json((face_flags & 0x80) != 0)},
        {"mouth_inverted", Json((face_flags & 0x20) != 0)},
        {"mustache_inverted", Json((face_flags & 0x40) != 0)},
        {"special_mii", Json((face_flags & 0x01) != 0)},
    });
    const std::size_t hair_flags_offset = 38 + kByteFields.size() + 2 + 4;
    const std::uint8_t hair_flags = data[hair_flags_offset];
    result.emplace("hair_style_flags", Json::Object{
        {"left_side", Json((hair_flags & 0x01) != 0)},
        {"reserved", Json(static_cast<std::int64_t>(hair_flags >> 2))},
        {"right_side", Json((hair_flags & 0x02) != 0)},
    });
    return Json(std::move(result));
}

Json section(std::size_t offset, std::size_t byte_length) {
    return Json::Object{
        {"byte_length", Json(static_cast<std::int64_t>(byte_length))},
        {"offset", Json(static_cast<std::int64_t>(offset))},
    };
}

class LtdParser final {
public:
    explicit LtdParser(const ZstdApi& zstd) : zstd_(zstd) {}

    Json parse_file(const std::filesystem::path& path, bool validate_zstd) const {
        std::ifstream stream(path, std::ios::binary | std::ios::ate);
        if (!stream) throw RuntimeError("FILE_IO", "could not open LTD file");
        const std::streamoff length = stream.tellg();
        if (length < 0) throw RuntimeError("FILE_IO", "could not determine LTD file length");
        if (static_cast<std::uint64_t>(length) > kMaximumLtdBytes) {
            throw RuntimeError("FILE_TOO_LARGE", "LTD file exceeds 64 MiB safety limit");
        }
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(length));
        stream.seekg(0, std::ios::beg);
        if (!bytes.empty() &&
            !stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
            throw RuntimeError("FILE_IO", "could not read complete LTD file");
        }
        return parse(bytes, validate_zstd);
    }

    Json parse(const std::vector<std::uint8_t>& data, bool validate_zstd) const {
        constexpr std::size_t char_info_size = 152;
        constexpr std::size_t mii_block_size = 156;
        constexpr std::size_t personality_size = 72;
        constexpr std::size_t display_name_size = 64;
        constexpr std::size_t pronunciation_size = 128;
        if (data.empty()) {
            throw RuntimeError("LTD_EMPTY", "file is too short to contain a ShareMii header");
        }
        const std::uint8_t version = data[0];
        if (version != 2 && version != 3) {
            throw RuntimeError("LTD_UNSUPPORTED_VERSION",
                               "only ShareMii v2 and v3 are supported");
        }
        const std::size_t header_size = version == 2 ? 5 : 4;
        take(data, 0, header_size, version == 2 ? "ShareMii v2 format header" :
                                                 "ShareMii v3 format header");
        const bool has_canvas = data[1] != 0;
        const bool has_ugc = data[2] != 0;
        const std::uint8_t reserved = data[3];
        const std::optional<std::uint8_t> legacy_padding =
            version == 2 ? std::optional<std::uint8_t>(data[4]) : std::nullopt;
        const std::size_t mii_block_offset = header_size;
        take(data, mii_block_offset, mii_block_size, "ShareMii Mii block");
        const std::uint32_t char_info_length = read_u32le(data.data() + mii_block_offset);
        if (char_info_length != char_info_size) {
            throw RuntimeError("LTD_CHARINFO_LENGTH",
                               "expected CharInfoEx length 152, got " +
                                   std::to_string(char_info_length));
        }
        std::size_t cursor = mii_block_offset + 4;
        const std::size_t char_info_offset = cursor;
        const std::uint8_t* char_info = take(data, cursor, char_info_length, "CharInfoEx");
        cursor += char_info_length;
        const std::size_t personality_offset = cursor;
        const std::uint8_t* personality_bytes =
            take(data, cursor, personality_size, "personality and voice block");
        Json::Object personality;
        for (std::size_t index = 0; index < kPersonalityFields.size(); ++index) {
            const std::uint32_t raw = read_u32le(personality_bytes + index * 4);
            const auto signed_value = static_cast<std::int32_t>(raw);
            personality.emplace(std::string(kPersonalityFields[index]),
                                Json(static_cast<std::int64_t>(signed_value)));
        }
        add_hash_enum(personality, "voice_preset_type", personality_bytes + 10 * 4);
        add_hash_enum(personality, "face_gender", personality_bytes + 11 * 4);
        add_hash_enum(personality, "pronoun_type", personality_bytes + 12 * 4);
        add_hash_enum(personality, "cloth_style", personality_bytes + 13 * 4);
        cursor += personality_size;
        const std::size_t display_name_offset = cursor;
        const std::string display_name = decode_utf16le(
            take(data, cursor, display_name_size, "display name"), display_name_size, "display name");
        cursor += display_name_size;
        const std::size_t pronunciation_offset = cursor;
        const std::string pronunciation = decode_utf16le(
            take(data, cursor, pronunciation_size, "pronunciation"), pronunciation_size,
            "pronunciation");
        cursor += pronunciation_size;
        const std::size_t sexuality_size = version == 2 ? 3 : 4;
        const std::size_t sexuality_offset = cursor;
        const std::uint8_t* sexuality = take(data, cursor, sexuality_size, "sexuality block");
        cursor += sexuality_size;
        const std::size_t canvas_marker_offset = cursor;
        const std::size_t marker_size = version == 2 ? 3 : 4;
        const std::uint8_t* canvas_marker = take(
            data, cursor, marker_size, version == 2 ? "v2 canvas marker" : "v3 canvas marker");
        const std::uint8_t expected_canvas_marker = 0xa3;
        if (!std::all_of(canvas_marker, canvas_marker + marker_size,
                         [expected_canvas_marker](std::uint8_t byte) {
                             return byte == expected_canvas_marker;
                         })) {
            throw RuntimeError("LTD_MARKER",
                               "ShareMii canvas marker is missing at expected offset");
        }
        const std::size_t canvas_payload_offset = cursor + marker_size;
        std::size_t ugc_marker_offset = 0;
        std::size_t ugc_marker_size = marker_size;
        if (version == 2) {
            ugc_marker_offset = reverse_find_marker(data, canvas_payload_offset, 3, 0xa3);
            if (ugc_marker_offset == std::numeric_limits<std::size_t>::max()) {
                throw RuntimeError("LTD_MARKER", "ShareMii v2 UGC texture marker is missing");
            }
        } else {
            const std::size_t canvas_payload_size = has_canvas
                ? zstd_.frame_size(data.data() + canvas_payload_offset,
                                   data.size() - canvas_payload_offset, "canvas")
                : 0;
            ugc_marker_offset = canvas_payload_offset + canvas_payload_size;
            const std::uint8_t* ugc_marker = take(data, ugc_marker_offset, 4, "v3 UGC texture marker");
            if (!std::all_of(ugc_marker, ugc_marker + 4,
                             [](std::uint8_t byte) { return byte == 0xa4; })) {
                throw RuntimeError(
                    "LTD_MARKER",
                    "ShareMii v3 UGC marker is not immediately after the canvas frame");
            }
            ugc_marker_size = 4;
        }
        const std::size_t canvas_payload_size = ugc_marker_offset - canvas_payload_offset;
        const std::size_t ugc_payload_offset = ugc_marker_offset + ugc_marker_size;
        take(data, ugc_marker_offset, ugc_marker_size, "UGC texture marker");
        if (ugc_payload_offset > data.size()) {
            throw RuntimeError("LTD_TRUNCATED", "UGC texture payload offset exceeds file length");
        }
        const std::size_t ugc_payload_size = data.size() - ugc_payload_offset;

        Json::Object header{
            {"char_info_length", Json(static_cast<std::int64_t>(char_info_length))},
            {"has_canvas", Json(has_canvas)},
            {"has_ugc_texture", Json(has_ugc)},
            {"reserved", Json(static_cast<std::int64_t>(reserved))},
            {"version", Json(static_cast<std::int64_t>(version))},
        };
        if (legacy_padding.has_value()) {
            header.emplace("legacy_padding", Json(static_cast<std::int64_t>(*legacy_padding)));
        }
        Json::Array love_raw;
        for (std::size_t index = 0; index < sexuality_size; ++index) {
            love_raw.emplace_back(static_cast<std::int64_t>(sexuality[index]));
        }
        Json::Object love_gender{
            {"female", Json(sexuality[1] != 0)},
            {"male", Json(sexuality[0] != 0)},
            {"raw", Json(std::move(love_raw))},
            {"serialized_length", Json(static_cast<std::int64_t>(sexuality_size))},
            {"third", Json(sexuality[2] != 0)},
        };
        if (version == 3) {
            love_gender.emplace("uninterpreted_fourth_byte",
                                Json(static_cast<std::int64_t>(sexuality[3])));
        }

        Json canvas_record = payload_record(
            data.data() + canvas_payload_offset, canvas_payload_size, canvas_payload_offset,
            has_canvas, validate_zstd, "canvas");
        Json ugc_record = payload_record(
            data.data() + ugc_payload_offset, ugc_payload_size, ugc_payload_offset,
            has_ugc, validate_zstd, "UGC texture");

        Json::Object serialized_sections{
            {"canvas_marker", section(canvas_marker_offset, marker_size)},
            {"canvas_texture_payload", section(canvas_payload_offset, canvas_payload_size)},
            {"char_info", section(char_info_offset, char_info_length)},
            {"display_name", section(display_name_offset, display_name_size)},
            {"format_header", section(0, header_size)},
            {"mii_block", section(mii_block_offset, mii_block_size)},
            {"personality_and_voice", section(personality_offset, personality_size)},
            {"pronunciation", section(pronunciation_offset, pronunciation_size)},
            {"sexuality", section(sexuality_offset, sexuality_size)},
            {"ugc_texture_marker", section(ugc_marker_offset, ugc_marker_size)},
            {"ugc_texture_payload", section(ugc_payload_offset, ugc_payload_size)},
        };

        return Json::Object{
            {"byte_length", Json(static_cast<std::int64_t>(data.size()))},
            {"canvas_marker", Json(hex_encode(canvas_marker, marker_size))},
            {"canvas_texture_payload", std::move(canvas_record)},
            {"char_info", parse_char_info(char_info)},
            {"display_name", Json(display_name)},
            {"format", Json("Tomodachi Life: Living the Dream ShareMii")},
            {"header", Json(std::move(header))},
            {"love_gender", Json(std::move(love_gender))},
            {"personality_and_voice", Json(std::move(personality))},
            {"pronunciation", Json(pronunciation)},
            {"serialized_sections", Json(std::move(serialized_sections))},
            {"sha256", Json(sha256_hex(data))},
            {"ugc_texture_marker", Json(hex_encode(data.data() + ugc_marker_offset, ugc_marker_size))},
            {"ugc_texture_payload", std::move(ugc_record)},
        };
    }

private:
    const ZstdApi& zstd_;

    static const std::uint8_t* take(const std::vector<std::uint8_t>& data,
                                    std::size_t offset, std::size_t length,
                                    std::string_view section_name) {
        if (offset > data.size() || length > data.size() - offset) {
            const std::size_t available = offset > data.size() ? 0 : data.size() - offset;
            throw RuntimeError(
                "LTD_TRUNCATED",
                "truncated " + std::string(section_name) + ": expected " +
                    std::to_string(length) + " byte(s), got " + std::to_string(available));
        }
        return data.data() + offset;
    }

    static std::size_t reverse_find_marker(const std::vector<std::uint8_t>& data,
                                           std::size_t begin, std::size_t marker_size,
                                           std::uint8_t marker_byte) {
        if (begin > data.size() || marker_size > data.size() - begin) {
            return std::numeric_limits<std::size_t>::max();
        }
        std::size_t candidate = data.size() - marker_size;
        while (true) {
            if (candidate >= begin &&
                std::all_of(data.begin() + static_cast<std::ptrdiff_t>(candidate),
                            data.begin() + static_cast<std::ptrdiff_t>(candidate + marker_size),
                            [marker_byte](std::uint8_t byte) { return byte == marker_byte; })) {
                return candidate;
            }
            if (candidate == begin) break;
            --candidate;
        }
        return std::numeric_limits<std::size_t>::max();
    }

    static void add_hash_enum(Json::Object& target, std::string_view field,
                              const std::uint8_t* bytes) {
        const std::uint32_t value = read_u32le(bytes);
        const char* label = nullptr;
        switch (value) {
        case 0x0ddcbe76: label = "male"; break;
        case 0x3be5d8d4: label = "he"; break;
        case 0x3b1f8b15: label = "female"; break;
        case 0x25af6ee5: label = "she"; break;
        default: break;
        }
        target.emplace(std::string(field), label ? Json(label) : Json(nullptr));
    }

    Json payload_record(const std::uint8_t* bytes, std::size_t byte_length,
                        std::size_t offset, bool declared_present,
                        bool validate_zstd, std::string_view section_name) const {
        const bool has_magic = byte_length >= 4 && bytes[0] == 0x28 && bytes[1] == 0xb5 &&
            bytes[2] == 0x2f && bytes[3] == 0xfd;
        Json validation;
        if (!validate_zstd) {
            validation = Json::Object{{"status", Json("not_requested")}};
        } else if (!declared_present && byte_length == 0) {
            validation = Json::Object{{"status", Json("not_present")}};
        } else if (!declared_present && byte_length != 0) {
            throw RuntimeError("LTD_PAYLOAD_FLAG_MISMATCH",
                               std::string(section_name) +
                                   " payload is present while its header flag is false");
        } else if (declared_present && byte_length == 0) {
            throw RuntimeError("LTD_PAYLOAD_FLAG_MISMATCH",
                               std::string(section_name) +
                                   " header flag is true but its payload is empty");
        } else if (!has_magic) {
            throw RuntimeError("LTD_ZSTD_INVALID",
                               std::string(section_name) + " payload is not a Zstandard frame");
        } else {
            validation = zstd_.validate_frame(bytes, byte_length, section_name);
        }
        return Json::Object{
            {"byte_length", Json(static_cast<std::int64_t>(byte_length))},
            {"compression", has_magic ? Json("zstandard") : Json(nullptr)},
            {"declared_present", Json(declared_present)},
            {"offset", Json(static_cast<std::int64_t>(offset))},
            {"sha256", Json(sha256_hex(bytes, byte_length))},
            {"validation", std::move(validation)},
        };
    }
};

const Json* find_member(const Json::Object& object, std::string_view key) {
    const auto iterator = object.find(key);
    return iterator == object.end() ? nullptr : &iterator->second;
}

const Json& require_member(const Json::Object& object, std::string_view key) {
    const Json* value = find_member(object, key);
    if (!value) throw RuntimeError("INVALID_REQUEST", "missing required field: " + std::string(key));
    return *value;
}

std::string require_string(const Json::Object& object, std::string_view key) {
    const Json& value = require_member(object, key);
    if (!value.is_string()) {
        throw RuntimeError("INVALID_REQUEST", std::string(key) + " must be a string");
    }
    return value.as_string();
}

std::int64_t require_integer(const Json::Object& object, std::string_view key) {
    const Json& value = require_member(object, key);
    if (!value.is_integer()) {
        throw RuntimeError("INVALID_REQUEST", std::string(key) + " must be an integer");
    }
    return value.as_integer();
}

bool optional_bool(const Json::Object& object, std::string_view key, bool default_value) {
    const Json* value = find_member(object, key);
    if (!value) return default_value;
    if (!value->is_bool()) {
        throw RuntimeError("INVALID_REQUEST", std::string(key) + " must be a boolean");
    }
    return value->as_bool();
}

void reject_unknown_fields(const Json::Object& object,
                           std::initializer_list<std::string_view> allowed) {
    for (const auto& [key, unused] : object) {
        (void)unused;
        if (std::find(allowed.begin(), allowed.end(), key) == allowed.end()) {
            throw RuntimeError("INVALID_REQUEST", "unknown request field: " + key);
        }
    }
}

const Json::Object& require_object(const Json::Object& object, std::string_view key) {
    const Json& value = require_member(object, key);
    if (!value.is_object()) {
        throw RuntimeError("ACTIVE_PARTS_SCHEMA", std::string(key) + " must be an object");
    }
    return value.as_object();
}

const Json::Array& require_array(const Json::Object& object, std::string_view key) {
    const Json& value = require_member(object, key);
    if (!value.is_array()) {
        throw RuntimeError("ACTIVE_PARTS_SCHEMA", std::string(key) + " must be an array");
    }
    return value.as_array();
}

bool require_bool(const Json::Object& object, std::string_view key,
                  std::string_view error_code = "ACTIVE_PARTS_SCHEMA") {
    const Json& value = require_member(object, key);
    if (!value.is_bool()) {
        throw RuntimeError(std::string(error_code), std::string(key) + " must be a boolean");
    }
    return value.as_bool();
}

std::int64_t schema_integer(const Json::Object& object, std::string_view key) {
    const Json& value = require_member(object, key);
    if (!value.is_integer()) {
        throw RuntimeError("ACTIVE_PARTS_SCHEMA", std::string(key) + " must be an integer");
    }
    return value.as_integer();
}

std::string schema_string(const Json::Object& object, std::string_view key) {
    const Json& value = require_member(object, key);
    if (!value.is_string()) {
        throw RuntimeError("ACTIVE_PARTS_SCHEMA", std::string(key) + " must be a string");
    }
    return value.as_string();
}

std::wstring lowercase_path_key(const std::filesystem::path& path) {
    std::wstring key = path.wstring();
    std::transform(key.begin(), key.end(), key.begin(), [](wchar_t value) {
        return static_cast<wchar_t>(std::towlower(value));
    });
    return key;
}

std::filesystem::path canonical_file(const std::filesystem::path& path,
                                     std::string_view label) {
    std::error_code error;
    const std::filesystem::path canonical = std::filesystem::canonical(path, error);
    if (error || !std::filesystem::is_regular_file(canonical, error) || error) {
        throw RuntimeError("ASSET_FILE_MISSING",
                           std::string(label) + " is not an existing regular file");
    }
    return canonical;
}

std::filesystem::path canonical_directory(const std::filesystem::path& path,
                                          std::string_view label) {
    std::error_code error;
    const std::filesystem::path canonical = std::filesystem::canonical(path, error);
    if (error || !std::filesystem::is_directory(canonical, error) || error) {
        throw RuntimeError("ASSET_DIRECTORY_MISSING",
                           std::string(label) + " is not an existing directory");
    }
    return canonical;
}

bool is_within(const std::filesystem::path& root, const std::filesystem::path& candidate) {
    const std::wstring root_key = lowercase_path_key(root);
    const std::wstring candidate_key = lowercase_path_key(candidate);
    if (candidate_key == root_key) return true;
    if (candidate_key.size() <= root_key.size()) return false;
    if (candidate_key.compare(0, root_key.size(), root_key) != 0) return false;
    const wchar_t separator = candidate_key[root_key.size()];
    return separator == L'\\' || separator == L'/';
}

struct StagedOutputFile final {
    std::filesystem::path destination;
    std::filesystem::path temporary;
    std::filesystem::path backup;
    std::string label;
    bool backed_up = false;
    bool published = false;
};

bool delete_file_if_present(const std::filesystem::path& path) noexcept {
    if (path.empty() || DeleteFileW(path.c_str())) return true;
    const DWORD code = GetLastError();
    return code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND;
}

bool inject_second_publish_failure() noexcept {
    std::array<wchar_t, 2> value{};
    const DWORD length = GetEnvironmentVariableW(
        L"INFINIMII_NATIVE_TEST_FAIL_SECOND_PUBLISH", value.data(),
        static_cast<DWORD>(value.size()));
    return length == 1 && value[0] == L'1';
}

std::filesystem::path render_sidecar_path(
    const std::filesystem::path& output_directory,
    const std::filesystem::path& destination,
    std::wstring_view suffix) {
    static std::atomic<std::uint64_t> sequence{0};
    const std::wstring name =
        L".infinimii-native-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(sequence.fetch_add(1, std::memory_order_relaxed)) + L"-" +
        destination.filename().wstring() + std::wstring(suffix);
    return (output_directory / name).lexically_normal();
}

StagedOutputFile stage_output_file(const std::filesystem::path& output_directory,
                                   const std::filesystem::path& destination,
                                   std::span<const std::uint8_t> bytes,
                                   std::string_view label) {
    if (!is_within(output_directory, destination) ||
        lowercase_path_key(destination.parent_path()) != lowercase_path_key(output_directory)) {
        throw RuntimeError("NATIVE_RENDER_OUTPUT_PATH",
                           std::string(label) + " destination escapes output_dir");
    }
    StagedOutputFile staged{
        destination,
        render_sidecar_path(output_directory, destination, L".tmp"),
        render_sidecar_path(output_directory, destination, L".backup"),
        std::string(label)};
    const auto& temporary = staged.temporary;
    if (!is_within(output_directory, temporary) ||
        !is_within(output_directory, staged.backup) ||
        lowercase_path_key(temporary.parent_path()) != lowercase_path_key(output_directory) ||
        lowercase_path_key(staged.backup.parent_path()) != lowercase_path_key(output_directory)) {
        throw RuntimeError("NATIVE_RENDER_OUTPUT_PATH",
                           std::string(label) + " transaction path escapes output_dir");
    }

    HANDLE handle = CreateFileW(
        temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw RuntimeError("NATIVE_RENDER_OUTPUT_IO",
                           "could not create temporary " + std::string(label));
    }
    const auto cleanup = [&]() {
        bool clean = true;
        if (handle != INVALID_HANDLE_VALUE) {
            clean = CloseHandle(handle) != 0 && clean;
            handle = INVALID_HANDLE_VALUE;
        }
        clean = delete_file_if_present(temporary) && clean;
        return clean;
    };
    std::size_t offset = 0;
    while (offset != bytes.size()) {
        const DWORD amount = static_cast<DWORD>(std::min<std::size_t>(
            bytes.size() - offset, std::numeric_limits<DWORD>::max()));
        DWORD written = 0;
        if (!WriteFile(handle, bytes.data() + offset, amount, &written, nullptr) ||
            written != amount) {
            const bool clean = cleanup();
            throw RuntimeError("NATIVE_RENDER_OUTPUT_IO",
                               "could not write complete " + std::string(label) +
                                   (clean ? "" : "; temporary cleanup failed"));
        }
        offset += written;
    }
    const bool flushed = FlushFileBuffers(handle) != 0;
    const bool closed = CloseHandle(handle) != 0;
    if (closed) handle = INVALID_HANDLE_VALUE;
    if (!flushed || !closed) {
        const bool clean = cleanup();
        throw RuntimeError("NATIVE_RENDER_OUTPUT_IO",
                           "could not flush complete " + std::string(label) +
                               (clean ? "" : "; temporary cleanup failed"));
    }
    return staged;
}

bool publish_output_transaction(std::span<StagedOutputFile> files) {
    const auto rollback = [&]() {
        bool restored = true;
        for (auto iterator = files.rbegin(); iterator != files.rend(); ++iterator) {
            if (iterator->backed_up) {
                if (!MoveFileExW(iterator->backup.c_str(), iterator->destination.c_str(),
                                 MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                    restored = false;
                }
            } else if (iterator->published &&
                       !delete_file_if_present(iterator->destination)) {
                restored = false;
            }
            if (!delete_file_if_present(iterator->temporary)) restored = false;
        }
        return restored;
    };
    for (auto& file : files) {
        const DWORD attributes = GetFileAttributesW(file.destination.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
                !MoveFileExW(file.destination.c_str(), file.backup.c_str(),
                             MOVEFILE_WRITE_THROUGH)) {
                const bool restored = rollback();
                throw RuntimeError(
                    "NATIVE_RENDER_OUTPUT_IO",
                    "could not stage previous " + file.label +
                        (restored ? "" : "; rollback was incomplete"));
            }
            file.backed_up = true;
        } else {
            const DWORD code = GetLastError();
            if (code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND) {
                const bool restored = rollback();
                throw RuntimeError(
                    "NATIVE_RENDER_OUTPUT_IO",
                    "could not inspect previous " + file.label +
                        (restored ? "" : "; rollback was incomplete"));
            }
        }
    }
    std::size_t publish_index = 0;
    for (auto& file : files) {
        if (publish_index == 1 && inject_second_publish_failure()) {
            const bool restored = rollback();
            throw RuntimeError(
                "NATIVE_RENDER_OUTPUT_IO",
                "test seam rejected the second transactional publish" +
                    std::string(restored ? "" : "; rollback was incomplete"));
        }
        if (!MoveFileExW(file.temporary.c_str(), file.destination.c_str(),
                         MOVEFILE_WRITE_THROUGH)) {
            const bool restored = rollback();
            throw RuntimeError(
                "NATIVE_RENDER_OUTPUT_IO",
                "could not transactionally publish " + file.label +
                    (restored ? "" : "; rollback was incomplete"));
        }
        file.published = true;
        ++publish_index;
    }
    bool cleanup_complete = true;
    for (auto& file : files) {
        if (file.backed_up) {
            cleanup_complete = delete_file_if_present(file.backup) && cleanup_complete;
        }
    }
    return cleanup_complete;
}

std::string logical_path(const std::filesystem::path& repository_root,
                         const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::path relative = std::filesystem::relative(path, repository_root, error);
    if (!error && !relative.empty()) return wide_to_utf8(relative.generic_wstring());
    return wide_to_utf8(path.generic_wstring());
}

std::filesystem::path request_path(const Json::Object& request, std::string_view key) {
    return std::filesystem::path(utf8_to_wide(require_string(request, key), key));
}

std::filesystem::path declared_path(const std::filesystem::path& repository_root,
                                    std::string_view value, std::string_view label) {
    const std::filesystem::path relative(utf8_to_wide(value, label));
    if (relative.empty() || relative.is_absolute() || relative.has_root_name() ||
        relative.has_root_directory()) {
        throw RuntimeError("ACTIVE_PARTS_PATH", std::string(label) + " must be repository-relative");
    }
    return canonical_file(repository_root / relative, label);
}

bool safe_asset_segment(std::string_view value) {
    if (value.empty() || value == "." || value == "..") return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
        return std::isalnum(byte) || byte == '_' || byte == '-' || byte == '.';
    });
}

bool is_lower_sha256(std::string_view value) {
    return value.size() == 64 &&
        std::all_of(value.begin(), value.end(), [](unsigned char byte) {
            return std::isdigit(byte) != 0 || (byte >= 'a' && byte <= 'f');
        });
}

struct FileIdentity final {
    std::filesystem::path path;
    std::uint64_t byte_length = 0;
    std::string sha256;
    std::vector<std::uint8_t> bytes;
};

struct PinResult final {
    FileIdentity identity;
    bool cache_hit = false;
};

class ImmutableFileCache final {
public:
    PinResult pin(const std::filesystem::path& path, std::size_t maximum_bytes,
                  std::string_view label) {
        const std::filesystem::path canonical = canonical_file(path, label);
        FileIdentity identity = read_stable(canonical, maximum_bytes, label);
        const std::wstring key = lowercase_path_key(canonical);
        const auto cached = entries_.find(key);
        if (cached != entries_.end()) {
            if (cached->second.byte_length != identity.byte_length ||
                cached->second.sha256 != identity.sha256) {
                throw RuntimeError(
                    "IMMUTABLE_ASSET_CHANGED",
                    std::string(label) + " changed after it was pinned by this runtime process");
            }
            return PinResult{std::move(identity), true};
        }
        if (entries_.size() >= kMaximumEntries) {
            throw RuntimeError("ASSET_CACHE_CAPACITY",
                               "immutable file cache reached its 16384-entry limit");
        }
        entries_.emplace(key, CachedIdentity{identity.byte_length, identity.sha256});
        return PinResult{std::move(identity), false};
    }

    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

private:
    static constexpr std::size_t kMaximumEntries = 16384;
    struct CachedIdentity final {
        std::uint64_t byte_length;
        std::string sha256;
    };
    std::map<std::wstring, CachedIdentity> entries_;

    static FileIdentity read_stable(const std::filesystem::path& path,
                                    std::size_t maximum_bytes, std::string_view label) {
        for (int attempt = 0; attempt < 3; ++attempt) {
            std::error_code error;
            const auto before_size = std::filesystem::file_size(path, error);
            if (error) {
                throw RuntimeError("ASSET_IO", "could not stat " + std::string(label));
            }
            if (before_size > maximum_bytes) {
                throw RuntimeError("ASSET_TOO_LARGE",
                                   std::string(label) + " exceeds its byte limit");
            }
            const auto before_time = std::filesystem::last_write_time(path, error);
            if (error) {
                throw RuntimeError("ASSET_IO", "could not timestamp " + std::string(label));
            }
            std::ifstream stream(path, std::ios::binary);
            if (!stream) throw RuntimeError("ASSET_IO", "could not open " + std::string(label));
            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(before_size));
            if (!bytes.empty() &&
                !stream.read(reinterpret_cast<char*>(bytes.data()),
                             static_cast<std::streamsize>(bytes.size()))) {
                throw RuntimeError("ASSET_IO", "could not read complete " + std::string(label));
            }
            char trailing = 0;
            if (stream.read(&trailing, 1)) continue;
            const auto after_size = std::filesystem::file_size(path, error);
            if (error) continue;
            const auto after_time = std::filesystem::last_write_time(path, error);
            if (error) continue;
            if (before_size != after_size || before_time != after_time) continue;
            return FileIdentity{
                path,
                static_cast<std::uint64_t>(bytes.size()),
                sha256_hex(bytes),
                std::move(bytes),
            };
        }
        throw RuntimeError("ASSET_UNSTABLE",
                           std::string(label) + " changed repeatedly while being authenticated");
    }
};

template <typename Value>
std::string native_array_sha256(const Value* values, std::size_t count) {
    if (count == 0) return sha256_hex(nullptr, 0);
    return sha256_hex(reinterpret_cast<const std::uint8_t*>(values),
                      count * sizeof(Value));
}

std::string quantized_f64_sha256(const double* values, std::size_t count) {
    constexpr double scale = 1'000'000.0;
    std::vector<std::int64_t> quantized;
    quantized.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const double value = values[index];
        if (std::isnan(value)) {
            quantized.push_back(std::numeric_limits<std::int64_t>::min());
        } else if (value == std::numeric_limits<double>::infinity()) {
            quantized.push_back(std::numeric_limits<std::int64_t>::max());
        } else if (value == -std::numeric_limits<double>::infinity()) {
            quantized.push_back(std::numeric_limits<std::int64_t>::min() + 1);
        } else {
            constexpr double maximum =
                static_cast<double>(std::numeric_limits<std::int64_t>::max() - 1) / scale;
            if (std::abs(value) > maximum) {
                throw RuntimeError("SCENE_PIPELINE_RANGE",
                                   "scene value exceeds the quantized hash range");
            }
            quantized.push_back(static_cast<std::int64_t>(std::llround(value * scale)));
        }
    }
    return native_array_sha256(quantized.data(), quantized.size());
}

struct AssetDraft final {
    std::string asset_class;
    std::string subtype;
    std::filesystem::path path;
    std::set<std::string> roles;
};

struct ModelDraft final {
    std::string resource_name;
    std::string model_name;
    std::set<std::string> roles;
};

Json linked_render_module_inventory() {
    constexpr std::uint32_t kExpectedFacePlanAbi = 1;
    constexpr std::string_view kExpectedFacePlanContract =
        "1afd8e391d2d7b2f6e50971e8c575a258eb2921e20e39522b000f515854b406d";
    constexpr std::uint32_t kExpectedRuntimeMaterialAdapterAbi = 2;
    constexpr std::string_view kExpectedRuntimeMaterialAdapterContract =
        "225c87ceb0042d45ced4e84d3b1e0af4f12d8a0411f3a3a03a9c12e9ebfd4769";
    constexpr std::uint32_t kExpectedRenderOrchestratorAbi = 4;
    constexpr std::string_view kExpectedRenderOrchestratorContract =
        "3be14b1a393a6cc0f7ecfd72624b106550813319debac4341c3f424a3de7c1fa";
    const auto module = [](std::int64_t actual_abi, std::int64_t expected_abi,
                           const char* actual_contract, const char* expected_contract,
                           bool activation_ready) {
        const bool contract_matches = actual_contract != nullptr && expected_contract != nullptr &&
            std::strcmp(actual_contract, expected_contract) == 0;
        return Json::Object{
            {"abi_matches", Json(actual_abi == expected_abi)},
            {"abi_version", Json(actual_abi)},
            {"activation_ready", Json(activation_ready)},
            {"contract_matches", Json(contract_matches)},
            {"contract_sha256", actual_contract ? Json(actual_contract) : Json(nullptr)},
            {"linked", Json(actual_abi == expected_abi && contract_matches)},
        };
    };
    const auto abi_only = [](std::int64_t actual_abi, std::int64_t expected_abi) {
        return Json::Object{
            {"abi_matches", Json(actual_abi == expected_abi)},
            {"abi_version", Json(actual_abi)},
            {"linked", Json(actual_abi == expected_abi)},
        };
    };

    return Json::Object{
        {"draw_descriptor_builder", module(
            static_cast<std::int64_t>(ltd_native_draw_descriptor_builder_abi_version()),
            LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_ABI_VERSION,
            ltd_native_draw_descriptor_builder_contract_sha256(),
            LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CONTRACT_SHA256, false)},
        {"draw_runtime_v2", module(
            static_cast<std::int64_t>(ltd_draw_runtime_v2_abi_version()),
            LTD_DRAW_RUNTIME_V2_ABI_VERSION,
            ltd_draw_runtime_v2_contract_sha256(), LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256, false)},
        {"face_runtime", module(
            static_cast<std::int64_t>(ltd_face_runtime_abi_version()),
            LTD_FACE_RUNTIME_ABI_VERSION,
            ltd_face_runtime_contract_sha256(), LTD_FACE_RUNTIME_CONTRACT_SHA256, false)},
        {"facepaint_decode", module(
            static_cast<std::int64_t>(ltd_native_facepaint_decode_abi_version()),
            LTD_NATIVE_FACEPAINT_DECODE_ABI_VERSION,
            ltd_native_facepaint_decode_contract_sha256(),
            LTD_NATIVE_FACEPAINT_CONTRACT_SHA256, false)},
        {"material_schedule", module(
            static_cast<std::int64_t>(ltd_native_material_schedule_abi_version()),
            LTD_NATIVE_MATERIAL_SCHEDULE_ABI_VERSION,
            ltd_native_material_schedule_contract_sha256(),
            LTD_NATIVE_MATERIAL_SCHEDULE_CONTRACT_SHA256, false)},
        {"native_png", abi_only(
            static_cast<std::int64_t>(infinimii_native_png_abi_version()),
            INFINIMII_NATIVE_PNG_ABI_VERSION)},
        {"postprocess", abi_only(
            static_cast<std::int64_t>(ltd_native_postprocess_abi_version()), 1)},
        {"render_pipeline", module(
            static_cast<std::int64_t>(ltd_native_render_pipeline_abi_version()),
            LTD_NATIVE_RENDER_PIPELINE_ABI_VERSION,
            ltd_native_render_pipeline_contract_sha256(),
            LTD_NATIVE_RENDER_PIPELINE_CONTRACT_SHA256,
            ltd_native_render_pipeline_activation_ready() != 0)},
        {"scene_assembler", module(
            static_cast<std::int64_t>(ltd_native_scene_assembler_abi_version()),
            LTD_NATIVE_SCENE_ASSEMBLER_ABI_VERSION,
            ltd_native_scene_assembler_contract_sha256(),
            LTD_NATIVE_SCENE_ASSEMBLER_CONTRACT_SHA256,
            ltd_native_scene_assembler_activation_ready() != 0)},
        {"scene_cache_adapter", module(
            static_cast<std::int64_t>(ltd_native_scene_cache_adapter_abi_version()),
            LTD_NATIVE_SCENE_CACHE_ADAPTER_ABI_VERSION,
            ltd_native_scene_cache_adapter_contract_sha256(),
            LTD_NATIVE_SCENE_CACHE_ADAPTER_CONTRACT_SHA256,
            ltd_native_scene_cache_adapter_activation_ready() != 0)},
        {"face_plan", module(
            static_cast<std::int64_t>(infinimii::native_face_plan::kAbiVersion),
            static_cast<std::int64_t>(kExpectedFacePlanAbi),
            infinimii::native_face_plan::kContractSha256.data(),
            kExpectedFacePlanContract.data(), false)},
        {"material_provider", module(
            static_cast<std::int64_t>(ltd_native_material_provider_abi_version()),
            LTD_NATIVE_MATERIAL_PROVIDER_ABI_VERSION,
            ltd_native_material_provider_contract_sha256(),
            LTD_NATIVE_MATERIAL_PROVIDER_CONTRACT_SHA256, false)},
        {"material_field_packer", module(
            static_cast<std::int64_t>(ltd_native_material_field_packer_abi_version()),
            LTD_NATIVE_MATERIAL_FIELD_PACKER_ABI_VERSION,
            ltd_native_material_field_packer_contract_sha256(),
            LTD_NATIVE_MATERIAL_FIELD_PACKER_CONTRACT_SHA256, false)},
        {"runtime_material_adapter", module(
            static_cast<std::int64_t>(
                infinimii::native_runtime_material_adapter::kAbiVersion),
            static_cast<std::int64_t>(kExpectedRuntimeMaterialAdapterAbi),
            infinimii::native_runtime_material_adapter::kContractSha256.data(),
            kExpectedRuntimeMaterialAdapterContract.data(), false)},
        {"noseline12", module(
            static_cast<std::int64_t>(ltd_noseline12_abi_version()),
            LTD_NOSELINE12_ABI_VERSION,
            ltd_noseline12_contract_sha256(), LTD_NOSELINE12_CONTRACT_SHA256, false)},
        {"noseline_pipeline_bridge", module(
            static_cast<std::int64_t>(ltd_native_noseline_pipeline_bridge_abi_version()),
            LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_ABI_VERSION,
            ltd_native_noseline_pipeline_bridge_contract_sha256(),
            LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_CONTRACT_SHA256,
            ltd_native_noseline_pipeline_bridge_activation_ready() != 0)},
        {"render_orchestrator", module(
            static_cast<std::int64_t>(infinimii::native_render_orchestrator::kAbiVersion),
            static_cast<std::int64_t>(kExpectedRenderOrchestratorAbi),
            infinimii::native_render_orchestrator::kContractSha256.data(),
            kExpectedRenderOrchestratorContract.data(),
            infinimii::native_render_orchestrator::ActivationReady())},
    };
}

class ActiveAssetRuntime final {
public:
    ActiveAssetRuntime(const ZstdApi& zstd, ImmutableFileCache& file_cache)
        : zstd_(zstd), ltd_parser_(zstd), file_cache_(file_cache) {}

    Json prepare_native_parts(const Json::Object& request, bool decode_assets = true) {
        return prepare(request, decode_assets, true);
    }

    Json prepare(const Json::Object& request, bool decode_assets = false,
                 bool native_parts = false) {
        const std::filesystem::path repository_root =
            canonical_directory(request_path(request, "repository_root"), "repository_root");
        const std::filesystem::path ltd_path =
            canonical_file(request_path(request, "ltd_path"), "ltd_path");
        std::filesystem::path manifest_path;
        std::filesystem::path parts_catalog_path;
        if (native_parts) {
            parts_catalog_path = canonical_file(
                request_path(request, "catalog_path"), "catalog_path");
        } else {
            manifest_path =
                canonical_file(request_path(request, "active_parts_path"), "active_parts_path");
        }
        const std::filesystem::path model_root =
            canonical_directory(request_path(request, "model_root"), "model_root");
        const std::filesystem::path face_texture_root =
            canonical_directory(request_path(request, "face_texture_root"), "face_texture_root");
        const Json::Array& root_values = require_array(request, "material_texture_roots");
        if (root_values.empty() || root_values.size() > 16) {
            throw RuntimeError("INVALID_REQUEST",
                               "material_texture_roots must contain 1 to 16 directories");
        }
        std::vector<std::filesystem::path> material_texture_roots;
        std::set<std::wstring> material_root_keys;
        for (const Json& value : root_values) {
            if (!value.is_string()) {
                throw RuntimeError("INVALID_REQUEST",
                                   "material_texture_roots entries must be strings");
            }
            const std::filesystem::path root = canonical_directory(
                std::filesystem::path(utf8_to_wide(value.as_string(), "material texture root")),
                "material texture root");
            if (!material_root_keys.insert(lowercase_path_key(root)).second) {
                throw RuntimeError("INVALID_REQUEST", "material_texture_roots contains a duplicate");
            }
            material_texture_roots.push_back(root);
        }

        std::optional<PinResult> native_ltd_pin;
        if (native_parts) {
            native_ltd_pin = file_cache_.pin(ltd_path, kMaximumLtdBytes, "LTD file");
        }
        Json ltd = ltd_parser_.parse_file(ltd_path, true);
        const Json::Object& ltd_document = ltd.as_object();
        if (native_parts &&
            (native_ltd_pin->identity.sha256 != schema_string(ltd_document, "sha256") ||
             native_ltd_pin->identity.byte_length != static_cast<std::uint64_t>(
                 schema_integer(ltd_document, "byte_length")))) {
            throw RuntimeError("ASSET_UNSTABLE", "LTD file changed between pin and parse");
        }
        ManifestResult manifest_result;
        Json manifest_document;
        Json::Object empty_manifest;
        const Json::Object* manifest = &empty_manifest;
        NativePartsResult native_result;
        ValidationResult validated;
        if (native_parts) {
            native_result = select_native_parts(
                repository_root, native_ltd_pin->identity, parts_catalog_path, ltd_document);
            validated = native_result.validated;
        } else {
            manifest_result = load_manifest(manifest_path);
            manifest_document = manifest_result.document;
            manifest = &manifest_document.as_object();
            validated = validate_manifest(
                repository_root, ltd_path, manifest_path, *manifest, ltd_document);
        }

        std::map<std::wstring, PinResult> request_pins;
        auto pin_once = [&](const std::filesystem::path& path, std::size_t maximum_bytes,
                            std::string_view label) -> const PinResult& {
            const std::filesystem::path canonical = canonical_file(path, label);
            const std::wstring key = lowercase_path_key(canonical);
            auto found = request_pins.find(key);
            if (found != request_pins.end()) return found->second;
            auto [inserted, unused] = request_pins.emplace(
                key, file_cache_.pin(canonical, maximum_bytes, label));
            (void)unused;
            return inserted->second;
        };

        std::map<std::wstring, AssetDraft> assets;
        auto add_asset = [&](std::string asset_class, std::string subtype,
                             const std::filesystem::path& path, std::string role) {
            const std::filesystem::path canonical = canonical_file(path, role);
            const std::wstring key = lowercase_path_key(canonical);
            auto found = assets.find(key);
            if (found == assets.end()) {
                AssetDraft draft{std::move(asset_class), std::move(subtype), canonical, {}};
                found = assets.emplace(key, std::move(draft)).first;
            } else if (found->second.asset_class != asset_class ||
                       found->second.subtype != subtype) {
                throw RuntimeError("ASSET_CLASS_CONFLICT",
                                   "one asset path was assigned incompatible classes");
            }
            found->second.roles.insert(std::move(role));
        };

        if (native_parts) {
            add_asset("metadata", "native_parts_catalog", parts_catalog_path,
                      "native_parts:catalog");
        } else {
            add_asset("metadata", "parts_index", validated.parts_metadata_path,
                      "active_parts:parts_metadata");
        }
        for (const auto& config : validated.parts_configs) {
            add_asset("metadata", "parts_config", config.second,
                      "active_part:" + config.first);
        }
        for (const auto& texture : validated.source_textures) {
            add_asset("texture", "parts_source", texture.second,
                      "active_part:" + texture.first);
        }

        std::map<std::string, ModelDraft> models;
        auto add_model = [&](std::string resource, std::string model, std::string role) {
            if (!safe_asset_segment(resource) || !safe_asset_segment(model)) {
                throw RuntimeError("ACTIVE_PARTS_PATH",
                                   "model resource or model name contains unsafe path bytes");
            }
            const std::string key = resource + "\n" + model;
            auto [found, inserted] = models.emplace(
                key, ModelDraft{resource, model, {}});
            (void)inserted;
            found->second.roles.insert(std::move(role));
        };
        add_model("BodyBaseDefault", "BodyBaseDefault", "fixed:body");
        add_model("ClothTopsTshirtLong", "ClothTopsTshirtLong", "fixed:reference_top");
        add_model("ClothShoesStandard", "ClothShoesStandard", "fixed:reference_shoes");
        add_model("ClothBottomsPantsLong", "ClothBottomsPantsLong",
                  "fixed:presentation_bottoms");
        for (const ModelDraft& model : validated.models) {
            for (const std::string& role : model.roles) {
                add_model(model.resource_name, model.model_name, role);
            }
        }

        std::set<std::string> material_texture_refs;
        Json::Array placeholder_refs;
        Json::Array compiled_materials;
        for (const auto& [unused_key, model] : models) {
            (void)unused_key;
            const std::filesystem::path resource_root =
                model_root / utf8_to_wide(model.resource_name, "resource_name");
            const std::filesystem::path obj_path =
                resource_root / utf8_to_wide(model.model_name + ".obj", "model_name");
            const std::filesystem::path catalog_path = resource_root / L"bfres.json";
            for (const std::string& role : model.roles) {
                add_asset("obj", "mesh", obj_path, role);
                add_asset("material", "model_catalog", catalog_path, role);
            }
            const std::filesystem::path sidecar =
                resource_root / utf8_to_wide(model.model_name + ".texcoords.json", "model_name");
            std::error_code sidecar_error;
            if (std::filesystem::is_regular_file(sidecar, sidecar_error) && !sidecar_error) {
                for (const std::string& role : model.roles) {
                    add_asset("obj", "named_uv", sidecar, role);
                }
            }
            const PinResult& catalog_pin = pin_once(catalog_path, 16 * 1024 * 1024,
                                                    "model material catalog");
            Json catalog = parse_json_bytes(catalog_pin.identity.bytes, "model material catalog");
            const Json::Object& catalog_object = catalog.as_object();
            if (schema_string(catalog_object, "ResourceName") != model.resource_name) {
                throw RuntimeError("MATERIAL_CATALOG_MISMATCH",
                                   "bfres.json ResourceName differs from selected model resource");
            }
            const Json::Array& catalog_models = require_array(catalog_object, "Models");
            const Json::Object* selected_model = nullptr;
            for (const Json& candidate : catalog_models) {
                if (!candidate.is_object()) {
                    throw RuntimeError("MATERIAL_CATALOG_SCHEMA",
                                       "bfres.json Models contains a non-object");
                }
                const Json::Object& candidate_object = candidate.as_object();
                if (schema_string(candidate_object, "Name") == model.model_name) {
                    if (selected_model) {
                        throw RuntimeError("MATERIAL_CATALOG_MISMATCH",
                                           "selected model occurs more than once in bfres.json");
                    }
                    selected_model = &candidate_object;
                }
            }
            if (!selected_model) {
                throw RuntimeError("MATERIAL_CATALOG_MISMATCH",
                                   "selected model is absent from bfres.json");
            }
            for (const Json& material_value : require_array(*selected_model, "Materials")) {
                if (!material_value.is_object()) {
                    throw RuntimeError("MATERIAL_CATALOG_SCHEMA",
                                       "bfres.json Materials contains a non-object");
                }
                const Json::Object& material = material_value.as_object();
                const std::string material_name = schema_string(material, "Name");
                Json::Array compiled_texture_refs;
                for (const Json& texture_value : require_array(material, "TextureRefs")) {
                    if (!texture_value.is_string()) {
                        throw RuntimeError("MATERIAL_CATALOG_SCHEMA",
                                           "TextureRefs contains a non-string");
                    }
                    const std::string& texture_name = texture_value.as_string();
                    compiled_texture_refs.emplace_back(texture_name);
                    if (!safe_asset_segment(texture_name)) {
                        throw RuntimeError("MATERIAL_CATALOG_PATH",
                                           "TextureRefs contains an unsafe texture name");
                    }
                    if (texture_name.rfind("Dummy_", 0) == 0) {
                        placeholder_refs.emplace_back(Json::Object{
                            {"material", Json(model.resource_name + "/" + model.model_name +
                                              "/" + material_name)},
                            {"texture", Json(texture_name)},
                        });
                    } else {
                        material_texture_refs.insert(texture_name);
                    }
                }
                Json::Array compiled_samplers;
                for (const Json& sampler : require_array(material, "Samplers")) {
                    if (!sampler.is_string()) {
                        throw RuntimeError("MATERIAL_CATALOG_SCHEMA",
                                           "Samplers contains a non-string");
                    }
                    compiled_samplers.emplace_back(sampler.as_string());
                }
                Json::Array compiled_shader_params;
                for (const Json& parameter : require_array(material, "ShaderParams")) {
                    if (!parameter.is_string()) {
                        throw RuntimeError("MATERIAL_CATALOG_SCHEMA",
                                           "ShaderParams contains a non-string");
                    }
                    compiled_shader_params.emplace_back(parameter.as_string());
                }
                Json::Array compiled_render_infos;
                for (const Json& render_info : require_array(material, "RenderInfos")) {
                    if (!render_info.is_string()) {
                        throw RuntimeError("MATERIAL_CATALOG_SCHEMA",
                                           "RenderInfos contains a non-string");
                    }
                    compiled_render_infos.emplace_back(render_info.as_string());
                }
                compiled_materials.emplace_back(Json::Object{
                    {"material", Json(material_name)},
                    {"model", Json(model.model_name)},
                    {"render_infos", Json(std::move(compiled_render_infos))},
                    {"resource", Json(model.resource_name)},
                    {"samplers", Json(std::move(compiled_samplers))},
                    {"shader_archive", Json(schema_string(material, "ShaderArchive"))},
                    {"shader_params", Json(std::move(compiled_shader_params))},
                    {"shading_model", Json(schema_string(material, "ShadingModel"))},
                    {"texture_refs", Json(std::move(compiled_texture_refs))},
                });
            }
        }

        for (const std::string& texture_name : material_texture_refs) {
            std::vector<std::filesystem::path> matches;
            for (const std::filesystem::path& root : material_texture_roots) {
                const std::filesystem::path candidate =
                    root / utf8_to_wide(texture_name, "material texture name");
                std::error_code error;
                if (std::filesystem::is_directory(candidate, error) && !error) {
                    matches.push_back(canonical_directory(candidate, "material texture directory"));
                }
            }
            if (matches.size() != 1) {
                throw RuntimeError(
                    "MATERIAL_TEXTURE_RESOLUTION",
                    "material texture must resolve in exactly one configured root: " + texture_name);
            }
            add_mip_directory(matches[0], "material:" + texture_name,
                              "material_mip", add_asset);
        }
        for (const auto& texture : validated.texture_names) {
            const std::filesystem::path directory =
                face_texture_root / utf8_to_wide(texture.second, "face texture name");
            add_mip_directory(directory, "face_part:" + texture.first,
                              "face_sprite_mip", add_asset);
        }

        Json::Array asset_records;
        std::map<std::string, std::int64_t> class_counts;
        std::size_t cache_hits = 0;
        std::size_t cache_misses = 0;
        std::size_t decoded_obj_hits = 0;
        std::size_t decoded_obj_misses = 0;
        std::size_t decoded_texture_hits = 0;
        std::size_t decoded_texture_misses = 0;
        Json::Array decoded_objects;
        Json::Array decoded_textures;
        std::vector<const AssetDraft*> ordered_assets;
        ordered_assets.reserve(assets.size());
        for (const auto& [unused_key, asset] : assets) {
            (void)unused_key;
            ordered_assets.push_back(&asset);
        }
        std::sort(ordered_assets.begin(), ordered_assets.end(),
                  [&](const AssetDraft* left, const AssetDraft* right) {
                      return logical_path(repository_root, left->path) <
                          logical_path(repository_root, right->path);
                  });
        for (const AssetDraft* asset : ordered_assets) {
            const PinResult& pinned = pin_once(asset->path, 64 * 1024 * 1024,
                                               asset->asset_class + " asset");
            if (pinned.cache_hit) ++cache_hits;
            else ++cache_misses;
            ++class_counts[asset->asset_class];
            if (decode_assets && asset->asset_class == "obj" && asset->subtype == "mesh") {
                try {
                    const DecodedObjResult decoded = decoded_cache_.decode_obj(
                        lowercase_path_key(asset->path), pinned.identity.sha256,
                        pinned.identity.bytes);
                    if (decoded.cache_hit) ++decoded_obj_hits;
                    else ++decoded_obj_misses;
                    const std::filesystem::path sidecar = asset->path.parent_path() /
                        (asset->path.stem().wstring() + L".texcoords.json");
                    std::error_code sidecar_error;
                    if (std::filesystem::is_regular_file(sidecar, sidecar_error) && !sidecar_error) {
                        const PinResult& sidecar_pin = pin_once(
                            sidecar, 64 * 1024 * 1024, "named-UV sidecar");
                        decoded_cache_.attach_named_uv(
                            lowercase_path_key(asset->path), pinned.identity.sha256,
                            wide_to_utf8(asset->path.stem().wstring()),
                            sidecar_pin.identity.sha256, sidecar_pin.identity.bytes);
                    }
                    const DecodedObjMetadata& metadata = *decoded.metadata;
                    Json::Object groups;
                    for (const auto& [name, count] : metadata.group_triangle_counts) {
                        groups.emplace(name, Json(static_cast<std::int64_t>(count)));
                    }
                    Json::Object named_counts;
                    for (const auto& [name, count] : metadata.named_uv_coverage_counts) {
                        named_counts.emplace(name, Json(static_cast<std::int64_t>(count)));
                    }
                    Json::Object named_hashes;
                    for (const auto& [name, digest] : metadata.named_uv_sha256) {
                        named_hashes.emplace(name, Json(digest));
                    }
                    decoded_objects.emplace_back(Json::Object{
                        {"decoded_sha256", Json(metadata.decoded_sha256)},
                        {"group_triangle_counts", Json(std::move(groups))},
                        {"named_uv_channel_count", Json(static_cast<std::int64_t>(metadata.named_uv_channel_count))},
                        {"named_uv_coverage_counts", Json(std::move(named_counts))},
                        {"named_uv_decoded_sha256", metadata.named_uv_decoded_sha256.empty() ? Json(nullptr) : Json(metadata.named_uv_decoded_sha256)},
                        {"named_uv_sha256", Json(std::move(named_hashes))},
                        {"normal_count", Json(static_cast<std::int64_t>(metadata.normal_count))},
                        {"normals_sha256", Json(metadata.normals_sha256)},
                        {"path", Json(logical_path(repository_root, asset->path))},
                        {"position_count", Json(static_cast<std::int64_t>(metadata.position_count))},
                        {"positions_sha256", Json(metadata.positions_sha256)},
                        {"texcoord_count", Json(static_cast<std::int64_t>(metadata.texcoord_count))},
                        {"texcoords_sha256", Json(metadata.texcoords_sha256)},
                        {"topology_sha256", Json(metadata.topology_sha256)},
                        {"triangle_count", Json(static_cast<std::int64_t>(metadata.triangle_count))},
                    });
                } catch (const DecodedAssetError& error) {
                    throw RuntimeError(error.code(), error.what());
                }
            } else if (decode_assets && asset->asset_class == "texture") {
                try {
                    const DecodedTextureResult decoded = decoded_cache_.decode_png(
                        lowercase_path_key(asset->path), pinned.identity.sha256,
                        pinned.identity.bytes);
                    if (decoded.cache_hit) ++decoded_texture_hits;
                    else ++decoded_texture_misses;
                    const DecodedTextureMetadata& metadata = *decoded.metadata;
                    decoded_textures.emplace_back(Json::Object{
                        {"height", Json(static_cast<std::int64_t>(metadata.height))},
                        {"opaque_pixel_count", Json(static_cast<std::int64_t>(metadata.opaque_pixel_count))},
                        {"path", Json(logical_path(repository_root, asset->path))},
                        {"pixel_count", Json(static_cast<std::int64_t>(metadata.pixel_count))},
                        {"rgba8_byte_length", Json(static_cast<std::int64_t>(metadata.rgba8_byte_length))},
                        {"rgba8_sha256", Json(metadata.rgba8_sha256)},
                        {"transparent_pixel_count", Json(static_cast<std::int64_t>(metadata.transparent_pixel_count))},
                        {"width", Json(static_cast<std::int64_t>(metadata.width))},
                    });
                } catch (const DecodedAssetError& error) {
                    throw RuntimeError(error.code(), error.what());
                }
            }
            Json::Array roles;
            for (const std::string& role : asset->roles) roles.emplace_back(role);
            asset_records.emplace_back(Json::Object{
                {"asset_class", Json(asset->asset_class)},
                {"byte_length", Json(static_cast<std::int64_t>(pinned.identity.byte_length))},
                {"path", Json(logical_path(repository_root, asset->path))},
                {"roles", Json(std::move(roles))},
                {"sha256", Json(pinned.identity.sha256)},
                {"subtype", Json(asset->subtype)},
            });
        }
        Json::Object count_object;
        for (const auto& [name, count] : class_counts) count_object.emplace(name, Json(count));
        const std::string serialized_asset_records = asset_records_dump(asset_records);
        const std::string index_sha256 = sha256_hex(
            reinterpret_cast<const std::uint8_t*>(serialized_asset_records.data()),
            serialized_asset_records.size());
        std::sort(compiled_materials.begin(), compiled_materials.end(), [](const Json& left,
                                                                          const Json& right) {
            const Json::Object& a = left.as_object();
            const Json::Object& b = right.as_object();
            return std::tuple(
                       schema_string(a, "resource"), schema_string(a, "model"),
                       schema_string(a, "material")) <
                std::tuple(
                       schema_string(b, "resource"), schema_string(b, "model"),
                       schema_string(b, "material"));
        });
        const std::string compiled_material_text = Json(compiled_materials).dump();
        const std::string compiled_material_sha256 = sha256_hex(
            reinterpret_cast<const std::uint8_t*>(compiled_material_text.data()),
            compiled_material_text.size());

        Json::Object response{
            {"asset_index", Json::Object{
                {"assets", Json(std::move(asset_records))},
                {"class_counts", Json(std::move(count_object))},
                {"immutable_for_process_lifetime", Json(true)},
                {"index_sha256", Json(index_sha256)},
                {"placeholder_texture_refs", Json(std::move(placeholder_refs))},
                {"schema_version", Json(static_cast<std::int64_t>(1))},
                {"total_asset_count", Json(static_cast<std::int64_t>(assets.size()))},
            }},
            {"cache", Json::Object{
                {"asset_hits", Json(static_cast<std::int64_t>(cache_hits))},
                {"asset_misses", Json(static_cast<std::int64_t>(cache_misses))},
                {"manifest", native_parts ? Json(nullptr) :
                    Json(manifest_result.cache_hit ? "hit" : "miss")},
                {"pinned_file_count", Json(static_cast<std::int64_t>(file_cache_.size()))},
            }},
        };
        if (native_parts) {
            response.emplace("native_parts", Json::Object{
                {"catalog", Json::Object{
                    {"byte_length", Json(static_cast<std::int64_t>(native_result.catalog_identity.byte_length))},
                    {"expected_sha256", Json(std::string(kNativePartsCatalogSha256))},
                    {"path", Json(logical_path(repository_root, parts_catalog_path))},
                    {"sha256", Json(native_result.catalog_identity.sha256)},
                }},
                {"effective_char_info_hex", Json(hex_encode(
                    native_result.selection.effective_char_info.data(),
                    native_result.selection.effective_char_info.size()))},
                {"enabled_record_count", Json(validated.enabled_record_count)},
                {"normalization_action", Json(std::string(
                    infinimii::native_parts::NormalizationActionName(
                        native_result.selection.normalization_action)))},
                {"normalized", Json(native_result.selection.normalized)},
                {"default_index", Json(static_cast<std::int64_t>(
                    native_result.selection.default_index))},
                {"records", std::move(native_result.records_json)},
                {"selector_count", Json(validated.selector_count)},
                {"target_sha256", Json(schema_string(ltd_document, "sha256"))},
                {"unresolved_parts_index_count", Json(validated.unresolved_count)},
                {"active_model_resources", std::move(native_result.active_models_json)},
                {"active_texture_resources", std::move(native_result.active_textures_json)},
            });
        } else {
            response.emplace("manifest", Json::Object{
                {"byte_length", Json(static_cast<std::int64_t>(manifest_result.identity.byte_length))},
                {"enabled_record_count", Json(validated.enabled_record_count)},
                {"path", Json(logical_path(repository_root, manifest_path))},
                {"selector_count", Json(validated.selector_count)},
                {"sha256", Json(manifest_result.identity.sha256)},
                {"target_sha256", Json(schema_string(require_object(*manifest, "target"), "sha256"))},
                {"unresolved_parts_index_count", Json(validated.unresolved_count)},
            });
        }
        if (decode_assets) {
            response.emplace("decoded_cache", Json::Object{
                {"compiled_material_count", Json(static_cast<std::int64_t>(compiled_materials.size()))},
                {"compiled_material_sha256", Json(compiled_material_sha256)},
                {"compiled_materials", Json(std::move(compiled_materials))},
                {"immutable_for_process_lifetime", Json(true)},
                {"obj_cache_hits", Json(static_cast<std::int64_t>(decoded_obj_hits))},
                {"obj_cache_misses", Json(static_cast<std::int64_t>(decoded_obj_misses))},
                {"obj_entry_count", Json(static_cast<std::int64_t>(decoded_cache_.obj_entry_count()))},
                {"objects", Json(std::move(decoded_objects))},
                {"resident_decoded_bytes", Json(static_cast<std::int64_t>(decoded_cache_.resident_decoded_bytes()))},
                {"schema_version", Json(static_cast<std::int64_t>(1))},
                {"texture_cache_hits", Json(static_cast<std::int64_t>(decoded_texture_hits))},
                {"texture_cache_misses", Json(static_cast<std::int64_t>(decoded_texture_misses))},
                {"texture_entry_count", Json(static_cast<std::int64_t>(decoded_cache_.texture_entry_count()))},
                {"textures", Json(std::move(decoded_textures))},
            });
        }
        return Json(std::move(response));
    }

    void render_ltd(const Json::Object& request, Json& response_slot) {
        using Clock = std::chrono::steady_clock;
        const auto started = Clock::now();
        const std::filesystem::path repository_root =
            canonical_directory(request_path(request, "repository_root"), "repository_root");
        const std::filesystem::path model_root =
            canonical_directory(request_path(request, "model_root"), "model_root");
        const std::filesystem::path parts_catalog_path =
            canonical_file(request_path(request, "catalog_path"), "catalog_path");

        const auto require_contract = [](std::uint32_t actual_abi,
                                         std::uint32_t expected_abi,
                                         const char* actual_contract,
                                         const char* expected_contract,
                                         std::string_view module) {
            if (actual_abi != expected_abi || actual_contract == nullptr ||
                std::strcmp(actual_contract, expected_contract) != 0) {
                throw RuntimeError(
                    "NATIVE_RENDER_MODULE_MISMATCH",
                    std::string(module) + " ABI or contract differs from the linked boundary");
            }
        };
        require_contract(
            infinimii::native_face_plan::kAbiVersion, 1,
            infinimii::native_face_plan::kContractSha256.data(),
            "1afd8e391d2d7b2f6e50971e8c575a258eb2921e20e39522b000f515854b406d",
            "face plan");
        require_contract(
            infinimii::native_runtime_material_adapter::kAbiVersion, 2,
            infinimii::native_runtime_material_adapter::kContractSha256.data(),
            "225c87ceb0042d45ced4e84d3b1e0af4f12d8a0411f3a3a03a9c12e9ebfd4769",
            "runtime material adapter");
        require_contract(
            infinimii::native_render_orchestrator::kAbiVersion, 4,
            infinimii::native_render_orchestrator::kContractSha256.data(),
            "3be14b1a393a6cc0f7ecfd72624b106550813319debac4341c3f424a3de7c1fa",
            "render orchestrator");
        require_contract(
            ltd_native_scene_assembler_abi_version(),
            LTD_NATIVE_SCENE_ASSEMBLER_ABI_VERSION,
            ltd_native_scene_assembler_contract_sha256(),
            LTD_NATIVE_SCENE_ASSEMBLER_CONTRACT_SHA256,
            "scene assembler");
        require_contract(
            ltd_native_material_schedule_abi_version(),
            LTD_NATIVE_MATERIAL_SCHEDULE_ABI_VERSION,
            ltd_native_material_schedule_contract_sha256(),
            LTD_NATIVE_MATERIAL_SCHEDULE_CONTRACT_SHA256,
            "material schedule");
        require_contract(
            ltd_native_draw_descriptor_builder_abi_version(),
            LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_ABI_VERSION,
            ltd_native_draw_descriptor_builder_contract_sha256(),
            LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CONTRACT_SHA256,
            "draw descriptor builder");
        require_contract(
            ltd_draw_runtime_v2_abi_version(), LTD_DRAW_RUNTIME_V2_ABI_VERSION,
            ltd_draw_runtime_v2_contract_sha256(), LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256,
            "draw runtime ABI2");
        require_contract(
            ltd_face_runtime_abi_version(), LTD_FACE_RUNTIME_ABI_VERSION,
            ltd_face_runtime_contract_sha256(), LTD_FACE_RUNTIME_CONTRACT_SHA256,
            "face runtime");
        require_contract(
            ltd_native_facepaint_decode_abi_version(),
            LTD_NATIVE_FACEPAINT_DECODE_ABI_VERSION,
            ltd_native_facepaint_decode_contract_sha256(),
            LTD_NATIVE_FACEPAINT_CONTRACT_SHA256,
            "facepaint decoder");
        require_contract(
            ltd_native_render_pipeline_abi_version(),
            LTD_NATIVE_RENDER_PIPELINE_ABI_VERSION,
            ltd_native_render_pipeline_contract_sha256(),
            LTD_NATIVE_RENDER_PIPELINE_CONTRACT_SHA256,
            "render pipeline");
        if (infinimii_native_png_abi_version() != INFINIMII_NATIVE_PNG_ABI_VERSION ||
            ltd_native_postprocess_abi_version() != 1 ||
            ltd_draw_runtime_v2_require(
                LTD_DRAW_RUNTIME_V2_ABI_VERSION,
                LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256) != LTD_DRAW_RUNTIME_OK ||
            ltd_face_runtime_require(
                LTD_FACE_RUNTIME_ABI_VERSION,
                LTD_FACE_RUNTIME_CONTRACT_SHA256) != LTD_FACE_RUNTIME_OK ||
            ltd_native_draw_descriptor_builder_require(
                LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_ABI_VERSION,
                LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CONTRACT_SHA256) !=
                LTD_NATIVE_DRAW_DESCRIPTOR_OK) {
            throw RuntimeError(
                "NATIVE_RENDER_MODULE_MISMATCH",
                "one linked native render module rejected its pinned ABI contract");
        }

        const std::string view = require_string(request, "view");
        if (view != "portrait" && view != "full_body") {
            throw RuntimeError("INVALID_REQUEST", "view must be portrait or full_body");
        }
        const std::int64_t output_size = require_integer(request, "output_size");
        if (output_size != 128 && output_size != 512) {
            throw RuntimeError("INVALID_REQUEST", "output_size must be exactly 128 or 512");
        }
        const Json::Object& supersampling = require_object(request, "supersampling");
        reject_unknown_fields(supersampling, {"profile", "raster_size"});
        if (require_string(supersampling, "profile") != "native-resolution-v1" ||
            require_integer(supersampling, "raster_size") != output_size) {
            throw RuntimeError(
                "INVALID_REQUEST",
                "supersampling must use native-resolution-v1 at the requested output_size");
        }
        const Json::Object& presentation = require_object(request, "presentation_context");
        reject_unknown_fields(presentation, {"kind", "sha256"});
        const std::string presentation_kind = require_string(presentation, "kind");
        const std::string presentation_sha256 = require_string(presentation, "sha256");
        constexpr std::string_view kNonePresentationSha256 =
            "cd70c8439a2ea7f6948a85179a90b1bcad4fe38f07aba5cc737b1b72b08e6a2e";
        if (presentation_kind != "none" || !is_lower_sha256(presentation_sha256) ||
            presentation_sha256 != kNonePresentationSha256) {
            throw RuntimeError(
                "NATIVE_RENDER_PRESENTATION_UNSUPPORTED",
                "render_ltd currently accepts only the canonical kind=none presentation context");
        }

        const std::filesystem::path output_directory = canonical_directory(
            request_path(request, "output_dir"), "output_dir");
        const std::string output_basename =
            view == "portrait" ? "mii.png" : "mii_full_body.png";
        const std::filesystem::path planned_output =
            (output_directory / utf8_to_wide(output_basename, "output basename")).lexically_normal();
        const std::filesystem::path planned_report =
            (output_directory / L"render_report.json").lexically_normal();
        if (!is_within(output_directory, planned_output) ||
            !is_within(output_directory, planned_report)) {
            throw RuntimeError("NATIVE_RENDER_OUTPUT_PATH", "planned output escapes output_dir");
        }

        const std::filesystem::path pose_path =
            canonical_file(request_path(request, "pose_path"), "pose_path");
        const PinResult pose_pin = file_cache_.pin(pose_path, 16 * 1024 * 1024, "IconPose");
        const Json pose_document = parse_json_bytes(pose_pin.identity.bytes, "IconPose");
        const Json::Object& pose_object = pose_document.as_object();
        if (schema_string(pose_object, "Name") != "IconPose" ||
            schema_string(pose_object, "RotationMode") != "EulerXYZ" ||
            schema_integer(pose_object, "FrameCount") != 1) {
            throw RuntimeError(
                "NATIVE_RENDER_POSE_UNSUPPORTED",
                "render_ltd requires the checked one-frame EulerXYZ IconPose source");
        }

        // This executes the source-authenticated native Parts selector and fills the
        // immutable OBJ/named-UV/texture cache.  The request has additional render-only
        // fields, which prepare() intentionally never consumes.
        const Json prepared = prepare(request, true, true);
        const auto prepared_at = Clock::now();
        const Json::Object& prepared_object = prepared.as_object();
        const Json::Object& asset_index = require_object(prepared_object, "asset_index");
        const Json::Object& native_parts = require_object(prepared_object, "native_parts");
        const Json::Object& decoded_cache = require_object(prepared_object, "decoded_cache");
        const std::string input_sha256 = schema_string(native_parts, "target_sha256");
        if (!is_lower_sha256(input_sha256)) {
            throw RuntimeError("NATIVE_RENDER_SOURCE_SEAL", "prepared LTD SHA-256 is invalid");
        }

        const std::filesystem::path ltd_path =
            canonical_file(request_path(request, "ltd_path"), "ltd_path");
        const PinResult ltd_pin = file_cache_.pin(ltd_path, kMaximumLtdBytes, "LTD file");
        if (ltd_pin.identity.sha256 != input_sha256) {
            throw RuntimeError("ASSET_UNSTABLE", "LTD changed after native Parts preparation");
        }
        const Json ltd_document = ltd_parser_.parse(ltd_pin.identity.bytes, true);
        const Json::Object& ltd_object = ltd_document.as_object();
        const Json::Object& header = require_object(ltd_object, "header");
        const Json::Object& serialized = require_object(ltd_object, "serialized_sections");
        const auto payload_span = [&](std::string_view name) {
            const Json::Object& section = require_object(serialized, name);
            const std::int64_t signed_offset = schema_integer(section, "offset");
            const std::int64_t signed_length = schema_integer(section, "byte_length");
            if (signed_offset < 0 || signed_length < 0) {
                throw RuntimeError("NATIVE_RENDER_SOURCE_SEAL", "LTD payload span is negative");
            }
            const std::size_t offset = static_cast<std::size_t>(signed_offset);
            const std::size_t length = static_cast<std::size_t>(signed_length);
            if (offset > ltd_pin.identity.bytes.size() ||
                length > ltd_pin.identity.bytes.size() - offset) {
                throw RuntimeError("NATIVE_RENDER_SOURCE_SEAL", "LTD payload span is truncated");
            }
            return std::pair(offset, length);
        };
        const auto [canvas_offset, canvas_length] = payload_span("canvas_texture_payload");
        const auto [ugc_offset, ugc_length] = payload_span("ugc_texture_payload");
        const auto [char_info_offset, char_info_length] = payload_span("char_info");
        if (char_info_length != infinimii::native_parts::kCharInfoSize) {
            throw RuntimeError(
                "NATIVE_RENDER_SOURCE_SEAL", "LTD CharInfoEx section is not exactly 152 bytes");
        }
        const std::span<const std::uint8_t> raw_char_info(
            ltd_pin.identity.bytes.data() + char_info_offset, char_info_length);
        const bool has_canvas = require_bool(header, "has_canvas", "NATIVE_RENDER_SOURCE_SEAL");
        const bool has_ugc = require_bool(header, "has_ugc_texture", "NATIVE_RENDER_SOURCE_SEAL");
        const std::int64_t container_version = schema_integer(header, "version");
        std::vector<std::uint8_t> canvas_rgba8(256U * 256U * 4U);
        std::vector<std::uint8_t> ugc_rgba8(512U * 512U * 4U);
        const ltd_native_facepaint_zstd_api facepaint_zstd = zstd_.facepaint_decode_api();
        ltd_native_facepaint_decode_request facepaint_request{};
        facepaint_request.container_version = static_cast<std::uint32_t>(container_version);
        facepaint_request.has_canvas = has_canvas ? 1 : 0;
        facepaint_request.has_ugc_texture = has_ugc ? 1 : 0;
        facepaint_request.canvas_encoded = canvas_length == 0 ? nullptr :
            ltd_pin.identity.bytes.data() + canvas_offset;
        facepaint_request.canvas_encoded_byte_count = canvas_length;
        facepaint_request.ugc_encoded = ugc_length == 0 ? nullptr :
            ltd_pin.identity.bytes.data() + ugc_offset;
        facepaint_request.ugc_encoded_byte_count = ugc_length;
        facepaint_request.zstd = &facepaint_zstd;
        facepaint_request.canvas_rgba8 = canvas_rgba8.data();
        facepaint_request.canvas_rgba8_capacity = canvas_rgba8.size();
        facepaint_request.ugc_rgba8 = ugc_rgba8.data();
        facepaint_request.ugc_rgba8_capacity = ugc_rgba8.size();
        ltd_native_facepaint_decode_summary facepaint_summary{};
        std::array<char, 512> facepaint_error{};
        const ltd_native_facepaint_status facepaint_status = ltd_native_facepaint_decode(
            &facepaint_request, &facepaint_summary,
            facepaint_error.data(), facepaint_error.size());
        if (facepaint_status != LTD_NATIVE_FACEPAINT_OK &&
            facepaint_status != LTD_NATIVE_FACEPAINT_ABSENT) {
            throw RuntimeError(
                "NATIVE_RENDER_FACEPAINT_DECODE",
                std::string("native facepaint decode failed: ") +
                    ltd_native_facepaint_status_name(facepaint_status) +
                    (facepaint_error[0] == '\0' ? "" : std::string(": ") + facepaint_error.data()));
        }
        canvas_rgba8.resize(facepaint_summary.canvas_rgba8_byte_count);
        ugc_rgba8.resize(facepaint_summary.ugc_rgba8_byte_count);
        const auto facepaint_at = Clock::now();

        // Build the complete native render transaction from source-authenticated
        // owners.  Every borrowed span below remains live until BuildAndExecute
        // has copied its prepared state and returned the finished output.
        NativePartsResult render_parts = select_native_parts(
            repository_root, ltd_pin.identity, parts_catalog_path, ltd_object);
        for (const auto& asset : infinimii::native_face_plan::RequiredAssets()) {
            const std::filesystem::path asset_path = canonical_file(
                repository_root / utf8_to_wide(asset.canonical_key, "face asset"),
                "native face asset");
            const PinResult pin = file_cache_.pin(asset_path, 32 * 1024 * 1024,
                                                  "native face asset");
            if (pin.identity.sha256 != asset.png_sha256) {
                throw RuntimeError("NATIVE_RENDER_FACE_ASSET_MISMATCH",
                                   "one required face asset differs from its pinned SHA-256");
            }
            const auto decoded = render_decoded_cache_.decode_png(
                utf8_to_wide(asset.canonical_key, "face asset key"),
                std::string(asset.png_sha256), pin.identity.bytes);
            if (decoded.texture == nullptr || decoded.texture->width != asset.width ||
                decoded.texture->height != asset.height) {
                throw RuntimeError("NATIVE_RENDER_FACE_ASSET_MISMATCH",
                                   "one required face asset decoded with different dimensions");
            }
        }

        infinimii::native_face_plan::FacePlan face_plan;
        std::string native_error;
        const auto face_plan_status = infinimii::native_face_plan::Build(
            {render_parts.catalog.get(), kNativePartsCatalogSha256, raw_char_info,
             &render_decoded_cache_},
            &face_plan, &native_error);
        if (face_plan_status != infinimii::native_face_plan::Status::kOk) {
            throw RuntimeError(
                "NATIVE_RENDER_FACE_PLAN",
                "native FacePlan failed: " +
                    std::string(infinimii::native_face_plan::StatusName(face_plan_status)) +
                    (native_error.empty() ? "" : ": " + native_error));
        }

        infinimii::native_runtime_material_adapter::MaterialBundle material_bundle;
        const std::uint32_t view_kind = view == "portrait"
            ? LTD_NATIVE_SCENE_VIEW_PORTRAIT
            : LTD_NATIVE_SCENE_VIEW_FULL_BODY;
        const auto material_status = infinimii::native_runtime_material_adapter::Build(
            {repository_root, ltd_pin.identity.bytes,
             render_parts.selection.effective_char_info, view_kind,
             static_cast<std::uint32_t>(output_size),
             infinimii::native_runtime_material_adapter::CatalogSha256(),
             infinimii::native_runtime_material_adapter::SourceBundleSha256(),
             &render_decoded_cache_, &face_plan, ugc_rgba8},
            &material_bundle, &native_error);
        if (material_status !=
            infinimii::native_runtime_material_adapter::Status::kOk) {
            throw RuntimeError(
                "NATIVE_RENDER_MATERIAL_ADAPTER",
                "native material adapter failed: " +
                    std::string(infinimii::native_runtime_material_adapter::StatusName(
                        material_status)) +
                    (native_error.empty() ? "" : ": " + native_error));
        }

        const std::string model_root_utf8 = wide_to_utf8(model_root.wstring());
        const std::string pose_path_utf8 = wide_to_utf8(pose_path.wstring());
        ltd_native_scene_cache_adapter* raw_scene_adapter = nullptr;
        std::array<char, 512> adapter_error{};
        const ltd_native_scene_cache_adapter_create_request scene_request{
            model_root_utf8.c_str(), pose_path_utf8.c_str()};
        if (ltd_native_scene_cache_adapter_create(
                &scene_request, &raw_scene_adapter, adapter_error.data(),
                adapter_error.size()) != LTD_NATIVE_SCENE_CACHE_ADAPTER_OK ||
            raw_scene_adapter == nullptr) {
            throw RuntimeError(
                "NATIVE_RENDER_SCENE_ADAPTER",
                adapter_error[0] == '\0' ? "native scene adapter creation failed"
                                         : adapter_error.data());
        }
        std::unique_ptr<ltd_native_scene_cache_adapter,
                        decltype(&ltd_native_scene_cache_adapter_destroy)>
            scene_adapter(raw_scene_adapter, &ltd_native_scene_cache_adapter_destroy);

        // The SHA is calculated from this exact handle while FILE_SHARE_WRITE and
        // FILE_SHARE_DELETE are denied. Keep the pin alive until after the encoder
        // unloads so the authenticated sibling cannot be replaced between hash and use.
        const PinnedNativePngBackend png_backend(
            native_png_backend_sibling_path());
        if (!png_backend.authenticated()) {
            throw RuntimeError(
                "NATIVE_RENDER_PNG_BACKEND",
                "native png sha256 does not match the pinned backend");
        }
        infinimii_native_png_encoder* raw_png_encoder = nullptr;
        std::array<char, 512> png_error{};
        if (infinimii_native_png_encoder_open(
                png_backend.path().c_str(), &raw_png_encoder, png_error.data(),
                png_error.size()) != INFINIMII_NATIVE_PNG_OK ||
            raw_png_encoder == nullptr) {
            throw RuntimeError(
                "NATIVE_RENDER_PNG_BACKEND",
                png_error[0] == '\0' ? "native PNG backend creation failed"
                                     : png_error.data());
        }
        std::unique_ptr<infinimii_native_png_encoder,
                        decltype(&infinimii_native_png_encoder_close)>
            png_encoder(raw_png_encoder, &infinimii_native_png_encoder_close);

        const auto& material_report = material_bundle.report();
        const std::string asset_index_sha256 = schema_string(asset_index, "index_sha256");
        const std::string publication_sha256(material_report.publication_sha256);
        const std::string active_parts_text = Json(native_parts).dump();
        const std::string active_parts_sha256 = sha256_hex(
            reinterpret_cast<const std::uint8_t*>(active_parts_text.data()),
            active_parts_text.size());

        infinimii::native_render_orchestrator::Request render_request;
        render_request.decoded_assets = &render_decoded_cache_;
        render_request.scene_assets = scene_adapter.get();
        render_request.parts_catalog = render_parts.catalog.get();
        render_request.parts_catalog_bytes = render_parts.catalog_identity.bytes;
        render_request.parts_catalog_sha256 = decode_sha256(kNativePartsCatalogSha256);
        render_request.parts_catalog_sha256_hex = kNativePartsCatalogSha256;
        render_request.raw_char_info = raw_char_info;
        render_request.trusted_material_bundle = &material_bundle;
        render_request.png_encoder = png_encoder.get();
        render_request.frame_seals = {
            input_sha256.c_str(), active_parts_sha256.c_str(),
            asset_index_sha256.c_str(), LTD_NATIVE_SCENE_ASSEMBLER_CONTRACT_SHA256,
            publication_sha256.c_str()};
        render_request.field_seals = {
            LTD_NATIVE_SCENE_ASSEMBLER_CONTRACT_SHA256,
            LTD_NATIVE_MATERIAL_SCHEDULE_CONTRACT_SHA256,
            LTD_DRAW_RUNTIME_CONTRACT_SHA256, LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256,
            LTD_NATIVE_MATERIAL_PROVIDER_CONTRACT_SHA256,
            LTD_DRAW_RUNTIME_CURRENT_SOURCE_SHA256,
            LTD_DRAW_RUNTIME_OPAQUE_SOURCE_SHA256,
            LTD_DRAW_RUNTIME_V2_WRAPPER_SHA256};
        render_request.descriptor_seals = {
            LTD_NATIVE_MATERIAL_SCHEDULE_CONTRACT_SHA256,
            LTD_DRAW_RUNTIME_CONTRACT_SHA256, LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256,
            LTD_DRAW_RUNTIME_CURRENT_SOURCE_SHA256,
            LTD_DRAW_RUNTIME_OPAQUE_SOURCE_SHA256,
            LTD_DRAW_RUNTIME_V2_WRAPPER_SHA256};
        render_request.view_kind = view_kind;
        render_request.raster_size = static_cast<std::uint32_t>(output_size);

        infinimii::native_render_orchestrator::Output native_output;
        const auto orchestrator_status =
            infinimii::native_render_orchestrator::BuildAndExecute(
                render_request, &native_output, &native_error);
        if (orchestrator_status !=
            infinimii::native_render_orchestrator::Status::kOk) {
            throw RuntimeError(
                "NATIVE_RENDER_ORCHESTRATOR",
                "native render orchestration failed: " +
                    std::string(infinimii::native_render_orchestrator::StatusName(
                        orchestrator_status)) +
                    (native_error.empty() ? "" : ": " + native_error));
        }
        if (native_output.png.empty() || native_output.transferred_pixels.size() !=
                static_cast<std::size_t>(output_size * output_size * 4)) {
            throw RuntimeError("NATIVE_RENDER_OUTPUT",
                               "native orchestrator returned an incomplete pixel result");
        }
        if (!native_output.production_activation_ready ||
            native_output.pipeline_report.production_activation_ready == 0) {
            throw RuntimeError(
                "NATIVE_RENDER_MODULE_MISMATCH",
                "native orchestrator or render pipeline production gate is inactive");
        }
        const auto rendered_at = Clock::now();

        const Json inactive_favorite_shirt = Json::Object{
            {"policy", Json("infinimii-favorite-shirt-v1")},
            {"status", Json("inactive_no_source_context")},
            {"title_exact", Json(false)},
        };
        const std::int64_t canonical_hair_type = schema_integer(
            require_object(ltd_object, "char_info"), "hair_type");
        const Json presentation_report = Json::Object{
            {"canonical_hair_type", Json(canonical_hair_type)},
            {"favorite_color", Json(nullptr)},
            {"favorite_color_rgb_hex", Json(nullptr)},
            {"favorite_shirt", inactive_favorite_shirt},
            {"for_hat", Json(false)},
            {"kind", Json(presentation_kind)},
            {"sha256", Json(presentation_sha256)},
            {"source_hair_type", Json(nullptr)},
        };
        Json::Object submitted_triangles;
        for (std::size_t index = 0; index < native_output.draws.size(); ++index) {
            const auto& draw = native_output.draws[index];
            submitted_triangles.emplace(
                draw.resource_name + ":" + draw.group + ":" + std::to_string(index),
                Json(static_cast<std::int64_t>(draw.submitted_triangles)));
        }
        const std::string output_sha256 = sha256_hex(native_output.png);
        const std::string report_view = view == "portrait"
            ? "appearance_bust_portrait"
            : "posed_full_body";
        const std::map<std::string_view, std::string_view> classic_signatures{
            {"1c3e3ad9207f6fb92bb48628803157b54fbf45f3bf472090d2d44b7f5e222aef",
             "bbfd5c0ab4028defec1db8d94c735dcf9f8bc29f5e8555f017f8524b906263e0"},
            {"c6f39c4af77644151ab219c5fb5ae440f6ddde0594a2a600b8aa343ec238a86b",
             "020cfdb6f8fc2f0b417c29a3b6752014d1680f7ad438a589db38a0b84fcd5c91"},
            {"aa2f64e520163873f488e67e9092b979c9fda2638f169221e43e04112e76cc0d",
             "89178a7180174d322c20fa737fd418a103d5f96139b47d8aff01bfb781884103"},
            {"966fa6bf82aa46c8e5b9f16842982a3b715b86ccd1933f540044b05b8d3fc391",
             "456e3a50cefdf7e6186de80e1e80e62f7fe874b45290074c5baf9b52db668185"},
        };
        const auto classic_signature = classic_signatures.find(input_sha256);
        if (classic_signature == classic_signatures.end()) {
            throw RuntimeError("NATIVE_RENDER_SOURCE_SEAL",
                               "accepted LTD lacks a classic capability signature");
        }
        const std::string resource_signature(classic_signature->second);
        const std::string capability_key =
            "component_catalog_v1_" + resource_signature.substr(0, 20);
        const Json output_record = Json::Object{
            {"path", Json(output_basename)},
            {"sha256", Json(output_sha256)},
            {"size", Json::Array{Json(output_size), Json(output_size)}},
            {"submitted_triangles", Json(std::move(submitted_triangles))},
            {"supersampling", Json::Object{
                {"portable_profile", Json("native-resolution-v1")},
                {"raster_size", Json::Array{Json(output_size), Json(output_size)}},
            }},
            {"view", Json(report_view)},
        };
        const Json classic_bridge_report = Json::Object{
            {"capability_key", Json(capability_key)},
            {"legacy_headwear_presentation", Json::Object{
                {"status", Json("inactive_no_source_context")},
            }},
            {"resolution_status", Json("source_authenticated_native_render")},
            {"resource_signature", Json::Object{
                {"algorithm", Json("sha256(canonical-json-v1)")},
                {"record_count", Json(static_cast<std::int64_t>(23))},
                {"sha256", Json(resource_signature)},
            }},
        };
        const Json render_report = Json::Object{
            {"active_material_path", Json::Object{
                {"presentation_outfit", Json::Object{
                    {"favorite_shirt", inactive_favorite_shirt},
                }},
            }},
            {"hair_attachment_state", Json::Object{
                {"legacy_headwear", Json(nullptr)},
                {"model_selections", Json::Array{}},
            }},
            {"input_sha256", Json(input_sha256)},
            {"outputs", Json::Array{output_record}},
            {"presentation_context", presentation_report},
            {"resource_support", Json::Object{
                {"classic_bridge", classic_bridge_report},
            }},
        };
        const auto elapsed_us = [](Clock::time_point begin, Clock::time_point end) {
            return static_cast<std::int64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count());
        };
        std::string report_text = render_report.dump();
        report_text.push_back('\n');
        const std::span<const std::uint8_t> report_bytes(
            reinterpret_cast<const std::uint8_t*>(report_text.data()), report_text.size());
        const std::string report_sha256 = sha256_hex(report_bytes.data(), report_bytes.size());
        Json response = Json::Object{
            {"activation_ready", Json(true)},
            {"asset_index_sha256", Json(schema_string(asset_index, "index_sha256"))},
            {"blockers", Json::Array{}},
            {"files_written", Json(true)},
            {"input_sha256", Json(input_sha256)},
            {"modules", linked_render_module_inventory()},
            {"output_path", Json(wide_to_utf8(planned_output.wstring()))},
            {"output_sha256", Json(output_sha256)},
            {"pixels_produced", Json(true)},
            {"planned_output", output_record},
            {"png_produced", Json(true)},
            {"provider_adapters", Json::Object{
                {"decoded_asset_cache", Json::Object{
                    {"immutable_for_process_lifetime", Json(true)},
                    {"obj_entry_count", Json(schema_integer(decoded_cache, "obj_entry_count"))},
                    {"status", Json("rendered")},
                    {"texture_entry_count", Json(schema_integer(decoded_cache, "texture_entry_count"))},
                }},
                {"icon_pose", Json::Object{
                    {"sha256", Json(pose_pin.identity.sha256)},
                    {"status", Json("source_sealed")},
                }},
                {"native_parts", Json::Object{
                    {"catalog_sha256", Json(schema_string(
                        require_object(native_parts, "catalog"), "sha256"))},
                    {"status", Json("selected")},
                }},
                {"scene_model_views", Json::Object{
                    {"status", Json("assembled")},
                }},
            }},
            {"render_report", render_report},
            {"report_path", Json(wide_to_utf8(planned_report.wstring()))},
            {"report_sha256", Json(report_sha256)},
            {"schema_version", Json(static_cast<std::int64_t>(1))},
            {"stages", Json::Object{
                {"asset_prepare", Json("complete")},
                {"facepaint_decode", Json::Object{
                    {"canvas_rgba8_sha256", canvas_rgba8.empty() ? Json(nullptr) :
                        Json(sha256_hex(canvas_rgba8))},
                    {"decoded", Json(facepaint_summary.decoded != 0)},
                    {"status", Json(facepaint_status == LTD_NATIVE_FACEPAINT_ABSENT ?
                        "absent" : "complete")},
                    {"ugc_rgba8_sha256", ugc_rgba8.empty() ? Json(nullptr) :
                        Json(sha256_hex(ugc_rgba8))},
                }},
                {"material_compile", Json("complete")},
                {"png_encode", Json("complete")},
                {"scene_assemble", Json("complete")},
            }},
            {"timings_us", Json::Object{
                {"asset_prepare", Json(elapsed_us(started, prepared_at))},
                {"facepaint_decode", Json(elapsed_us(prepared_at, facepaint_at))},
                {"native_render", Json(elapsed_us(facepaint_at, rendered_at))},
                {"report_and_write", Json(static_cast<std::int64_t>(0))},
                {"total", Json(static_cast<std::int64_t>(0))},
            }},
            {"transaction_cleanup_complete", Json(false)},
        };
        response_slot = std::move(response);
        Json* const cleanup_field =
            &response_slot.as_object().find("transaction_cleanup_complete")->second;
        Json::Object& timing_fields =
            response_slot.as_object().find("timings_us")->second.as_object();
        Json* const report_and_write_field =
            &timing_fields.find("report_and_write")->second;
        Json* const total_field = &timing_fields.find("total")->second;
        std::array<StagedOutputFile, 2> staged_files;
        try {
            staged_files[0] = stage_output_file(
                output_directory, planned_output, native_output.png, "rendered PNG");
            staged_files[1] = stage_output_file(
                output_directory, planned_report, report_bytes, "render report");
        } catch (...) {
            bool clean = true;
            for (const auto& staged : staged_files) {
                clean = delete_file_if_present(staged.temporary) && clean;
            }
            if (!clean) {
                throw RuntimeError(
                    "NATIVE_RENDER_OUTPUT_IO",
                    "render output staging failed and temporary cleanup was incomplete");
            }
            throw;
        }
        const bool cleanup_complete = publish_output_transaction(staged_files);
        const auto files_at = Clock::now();
        *cleanup_field = Json(cleanup_complete);
        *report_and_write_field = Json(elapsed_us(rendered_at, files_at));
        *total_field = Json(elapsed_us(started, files_at));
        return;
    }

    Json verify_scene_pipeline(const Json::Object& request) {
        using Clock = std::chrono::steady_clock;
        const auto started = Clock::now();
        if (ltd_native_scene_abi_version() != 1 || ltd_native_pose_abi_version() != 1 ||
            ltd_native_geometry_abi_version() != 1) {
            throw RuntimeError("SCENE_PIPELINE_ABI", "one native scene module has an unsupported ABI");
        }

        const std::string view = require_string(request, "view");
        if (view != "bust" && view != "full_body") {
            throw RuntimeError("INVALID_REQUEST", "view must be bust or full_body");
        }
        const std::int64_t requested_size = require_integer(request, "output_size");
        if (requested_size != 128 && requested_size != 512) {
            throw RuntimeError("INVALID_REQUEST", "output_size must be exactly 128 or 512");
        }
        const std::size_t output_size = static_cast<std::size_t>(requested_size);
        const std::filesystem::path repository_root =
            canonical_directory(request_path(request, "repository_root"), "repository_root");
        const std::filesystem::path ltd_path =
            canonical_file(request_path(request, "ltd_path"), "ltd_path");
        const std::filesystem::path model_root =
            canonical_directory(request_path(request, "model_root"), "model_root");
        const std::filesystem::path pose_path =
            canonical_file(request_path(request, "pose_path"), "pose_path");

        // Reuse the complete checked manifest/index/cache boundary before any scene input is
        // consumed. The extra scene fields are intentionally ignored by prepare(), while the
        // RuntimeServer owns their closed request schema.
        const Json prepared = prepare(request, true);
        const auto after_prepare = Clock::now();
        const Json::Object& prepared_object = prepared.as_object();
        const Json::Object& asset_index = require_object(prepared_object, "asset_index");
        const Json::Object& prepared_decoded_cache =
            require_object(prepared_object, "decoded_cache");

        const Json ltd = ltd_parser_.parse_file(ltd_path, true);
        const Json::Object& ltd_object = ltd.as_object();
        const Json::Object& char_info = require_object(ltd_object, "char_info");
        const std::int64_t build_value = schema_integer(char_info, "build");
        const std::int64_t height_value = schema_integer(char_info, "height");
        if (build_value < 0 || build_value > 127 || height_value < 0 || height_value > 127) {
            throw RuntimeError("SCENE_PIPELINE_SCHEMA", "LTD build/height is outside CharInfo range");
        }

        const std::filesystem::path body_root = model_root / L"BodyBaseDefault";
        const std::filesystem::path body_obj_path =
            canonical_file(body_root / L"BodyBaseDefault.obj", "BodyBaseDefault OBJ");
        const std::filesystem::path body_catalog_path =
            canonical_file(body_root / L"bfres.json", "BodyBaseDefault catalog");
        const PinResult body_obj_pin =
            file_cache_.pin(body_obj_path, 64 * 1024 * 1024, "BodyBaseDefault OBJ");
        const PinResult body_catalog_pin =
            file_cache_.pin(body_catalog_path, 16 * 1024 * 1024, "BodyBaseDefault catalog");
        const PinResult pose_pin =
            file_cache_.pin(pose_path, 16 * 1024 * 1024, "static body pose");
        DecodedObjResult decoded_body;
        try {
            decoded_body = decoded_cache_.decode_obj(
                lowercase_path_key(body_obj_path), body_obj_pin.identity.sha256,
                body_obj_pin.identity.bytes);
        } catch (const DecodedAssetError& error) {
            throw RuntimeError(error.code(), error.what());
        }
        if (decoded_body.mesh == nullptr || decoded_body.metadata == nullptr) {
            throw RuntimeError("SCENE_PIPELINE_CACHE", "decoded BodyBase cache returned no mesh");
        }
        const DecodedObjMesh& mesh = *decoded_body.mesh;
        const std::size_t vertex_count = mesh.positions.size() / 3;
        if (vertex_count == 0 || mesh.positions.size() != vertex_count * 3 ||
            mesh.normals.size() != vertex_count * 3 || vertex_count > 1'000'000 ||
            mesh.triangles.size() > 2'000'000) {
            throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                               "BodyBase position/normal/triangle dimensions are unsupported");
        }

        const Json catalog = parse_json_bytes(body_catalog_pin.identity.bytes, "BodyBase catalog");
        const Json pose = parse_json_bytes(pose_pin.identity.bytes, "static body pose");
        const Json::Object& catalog_object = catalog.as_object();
        const Json::Object& pose_object = pose.as_object();
        if (schema_string(catalog_object, "ResourceName") != "BodyBaseDefault" ||
            schema_string(pose_object, "Name") != "IconPose" ||
            schema_string(pose_object, "RotationMode") != "EulerXYZ" ||
            schema_integer(pose_object, "FrameCount") != 1) {
            throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                               "BodyBaseDefault and static IconPose identities are required");
        }

        const auto require_json_object = [](const Json& value,
                                            std::string_view label) -> const Json::Object& {
            if (!value.is_object()) {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                                   std::string(label) + " must be an object");
            }
            return value.as_object();
        };
        const auto finite_number = [](const Json& value, std::string_view label) -> double {
            double result = 0.0;
            if (value.is_integer()) result = static_cast<double>(value.as_integer());
            else if (value.is_double()) result = value.as_double();
            else {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                                   std::string(label) + " must contain numbers");
            }
            if (!std::isfinite(result)) {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                                   std::string(label) + " contains a non-finite number");
            }
            return result;
        };
        const auto number_array = [&](const Json::Object& object, std::string_view key,
                                      std::size_t minimum, std::size_t maximum) {
            const Json::Array& values = require_array(object, key);
            if (values.size() < minimum || values.size() > maximum) {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                                   std::string(key) + " has an unsupported length");
            }
            std::vector<double> result;
            result.reserve(values.size());
            for (const Json& value : values) result.push_back(finite_number(value, key));
            return result;
        };

        const Json::Object* model = nullptr;
        for (const Json& value : require_array(catalog_object, "Models")) {
            const Json::Object& candidate = require_json_object(value, "catalog model");
            if (schema_string(candidate, "Name") == "BodyBaseDefault") {
                if (model != nullptr) {
                    throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                                       "BodyBaseDefault occurs more than once in its catalog");
                }
                model = &candidate;
            }
        }
        if (model == nullptr || schema_string(*model, "SkeletonRotationMode") != "EulerXYZ") {
            throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                               "BodyBaseDefault EulerXYZ model is absent from its catalog");
        }

        std::map<std::string, const Json::Object*, std::less<>> animated_bones;
        for (const Json& value : require_array(pose_object, "Bones")) {
            const Json::Object& record = require_json_object(value, "pose bone");
            if (!require_array(record, "Curves").empty()) {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA", "IconPose must remain a static pose");
            }
            const std::string name = schema_string(record, "Name");
            if (!animated_bones.emplace(name, &record).second) {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA", "IconPose contains a duplicate bone");
            }
        }

        const Json::Array& bone_records = require_array(*model, "Bones");
        if (bone_records.empty() || bone_records.size() > 1024) {
            throw RuntimeError("SCENE_PIPELINE_SCHEMA", "BodyBase bone count is unsupported");
        }
        std::vector<LtdNativeBoneInput> bones;
        std::vector<std::string> bone_names;
        bones.reserve(bone_records.size());
        bone_names.reserve(bone_records.size());
        std::size_t head_index = bone_records.size();
        for (std::size_t index = 0; index < bone_records.size(); ++index) {
            const Json::Object& record = require_json_object(bone_records[index], "model bone");
            const std::string name = schema_string(record, "Name");
            const auto animated = animated_bones.find(name);
            const Json::Object* selected = animated == animated_bones.end() ? nullptr : animated->second;
            const std::vector<double> scale = number_array(
                selected ? *selected : record, selected ? "BaseScale" : "Scale", 3, 4);
            const std::vector<double> rotation = number_array(
                selected ? *selected : record, selected ? "BaseRotation" : "Rotation", 3, 4);
            const std::vector<double> translation = number_array(
                selected ? *selected : record, selected ? "BaseTranslation" : "Position", 3, 4);
            const std::int64_t parent = schema_integer(record, "ParentIndex");
            if (parent < -1 || parent >= static_cast<std::int64_t>(index)) {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA", "BodyBase bone hierarchy is invalid");
            }
            LtdNativeBoneInput input{};
            input.parent_index = static_cast<std::int32_t>(parent);
            for (std::size_t axis = 0; axis < 3; ++axis) {
                input.scale[axis] = scale[axis];
                input.rotation[axis] = rotation[axis];
                input.translation[axis] = translation[axis];
            }
            if (name == "Head") head_index = index;
            bones.push_back(input);
            bone_names.push_back(name);
        }
        if (head_index == bones.size()) {
            throw RuntimeError("SCENE_PIPELINE_SCHEMA", "BodyBase has no Head bone");
        }

        std::vector<double> posed_world(bones.size() * 16);
        if (ltd_native_evaluate_world_matrices(bones.data(), bones.size(), posed_world.data()) !=
            LTD_NATIVE_POSE_OK) {
            throw RuntimeError("SCENE_PIPELINE_NATIVE", "native world-matrix evaluation failed");
        }

        const Json::Array& palette_values = require_array(*model, "MatrixToBoneList");
        if (palette_values.empty() || palette_values.size() > 4096) {
            throw RuntimeError("SCENE_PIPELINE_SCHEMA", "BodyBase matrix palette is unsupported");
        }
        std::vector<std::int32_t> palette;
        palette.reserve(palette_values.size());
        for (const Json& value : palette_values) {
            if (!value.is_integer() || value.as_integer() < 0 ||
                value.as_integer() >= static_cast<std::int64_t>(bones.size())) {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                                   "BodyBase matrix palette contains an invalid bone");
            }
            palette.push_back(static_cast<std::int32_t>(value.as_integer()));
        }

        const Json::Array& inverse_values = require_array(*model, "InverseModelMatrices");
        if (inverse_values.size() > palette.size()) {
            throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                               "BodyBase inverse-bind table exceeds its matrix palette");
        }
        std::vector<double> inverse_bind(inverse_values.size() * 16, 0.0);
        for (std::size_t index = 0; index < inverse_values.size(); ++index) {
            if (!inverse_values[index].is_array()) {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA", "inverse-bind record must be an array");
            }
            const Json::Array& row = inverse_values[index].as_array();
            if (row.size() != 12) {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA", "inverse-bind record must contain 12 numbers");
            }
            double* matrix = inverse_bind.data() + index * 16;
            matrix[15] = 1.0;
            for (std::size_t value_index = 0; value_index < row.size(); ++value_index) {
                matrix[value_index] = finite_number(row[value_index], "inverse bind");
            }
        }

        struct ShapeStorage final {
            std::size_t offset = 0;
            std::size_t count = 0;
            std::size_t skin_count = 0;
            std::vector<std::int32_t> indices;
            std::vector<double> weights;
        };
        std::vector<ShapeStorage> shape_storage;
        const Json::Array& shape_records = require_array(*model, "Shapes");
        if (shape_records.size() > 1024) {
            throw RuntimeError("SCENE_PIPELINE_SCHEMA", "BodyBase shape count is unsupported");
        }
        shape_storage.reserve(shape_records.size());
        std::uint64_t influence_count = 0;
        for (const Json& value : shape_records) {
            const Json::Object& shape = require_json_object(value, "model shape");
            const std::int64_t skin_count = schema_integer(shape, "VertexSkinCount");
            if (skin_count <= 0) continue;
            const std::int64_t offset = schema_integer(shape, "VertexOffset");
            const std::int64_t count = schema_integer(shape, "VertexCount");
            if (skin_count > 16 || offset < 0 || count < 0 ||
                static_cast<std::uint64_t>(offset) + static_cast<std::uint64_t>(count) >
                    vertex_count) {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA", "BodyBase shape range is invalid");
            }
            influence_count += static_cast<std::uint64_t>(skin_count) *
                               static_cast<std::uint64_t>(count);
            if (influence_count > 16'000'000) {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA", "BodyBase skin influence cap exceeded");
            }
            ShapeStorage storage{};
            storage.offset = static_cast<std::size_t>(offset);
            storage.count = static_cast<std::size_t>(count);
            storage.skin_count = static_cast<std::size_t>(skin_count);
            storage.indices.reserve(storage.count * storage.skin_count);
            const Json::Array& index_rows = require_array(shape, "SkinIndices");
            if (index_rows.size() != storage.count) {
                throw RuntimeError("SCENE_PIPELINE_SCHEMA", "BodyBase skin-index rows differ");
            }
            for (const Json& row_value : index_rows) {
                if (!row_value.is_array() || row_value.as_array().size() < storage.skin_count) {
                    throw RuntimeError("SCENE_PIPELINE_SCHEMA", "BodyBase skin-index width differs");
                }
                for (std::size_t column = 0; column < storage.skin_count; ++column) {
                    const Json& item = row_value.as_array()[column];
                    if (!item.is_integer() || item.as_integer() < 0 ||
                        item.as_integer() >= static_cast<std::int64_t>(palette.size())) {
                        throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                                           "BodyBase skin index is outside its palette");
                    }
                    storage.indices.push_back(static_cast<std::int32_t>(item.as_integer()));
                }
            }
            const Json::Array& weight_rows = require_array(shape, "SkinWeights");
            if (!(storage.skin_count == 1 && weight_rows.empty())) {
                if (weight_rows.size() != storage.count) {
                    throw RuntimeError("SCENE_PIPELINE_SCHEMA", "BodyBase skin-weight rows differ");
                }
                storage.weights.reserve(storage.count * storage.skin_count);
                for (const Json& row_value : weight_rows) {
                    if (!row_value.is_array() || row_value.as_array().size() < storage.skin_count) {
                        throw RuntimeError("SCENE_PIPELINE_SCHEMA", "BodyBase skin-weight width differs");
                    }
                    for (std::size_t column = 0; column < storage.skin_count; ++column) {
                        storage.weights.push_back(finite_number(
                            row_value.as_array()[column], "skin weight"));
                    }
                }
            }
            shape_storage.push_back(std::move(storage));
        }
        std::vector<LtdNativeShapeSkinInput> native_shapes;
        native_shapes.reserve(shape_storage.size());
        for (const ShapeStorage& storage : shape_storage) {
            native_shapes.push_back(LtdNativeShapeSkinInput{
                storage.offset,
                storage.count,
                storage.skin_count,
                storage.indices.data(),
                storage.weights.empty() ? nullptr : storage.weights.data(),
            });
        }

        const auto after_inputs = Clock::now();
        std::vector<double> posed_positions(mesh.positions.size());
        std::vector<double> posed_normals(mesh.normals.size());
        if (ltd_native_skin_mesh(
                mesh.positions.data(), mesh.normals.data(), vertex_count,
                native_shapes.data(), native_shapes.size(), palette.data(), palette.size(),
                inverse_bind.data(), inverse_values.size(), posed_world.data(), bones.size(),
                posed_positions.data(), posed_normals.data()) != LTD_NATIVE_POSE_OK) {
            throw RuntimeError("SCENE_PIPELINE_NATIVE", "native BodyBase skinning failed");
        }
        const auto after_pose = Clock::now();

        LtdNativeSceneCamera camera{};
        const int camera_status = view == "bust"
            ? ltd_native_resolve_bust_camera(
                  static_cast<int>(build_value), static_cast<int>(height_value),
                  posed_world.data() + head_index * 16, &camera)
            : ltd_native_resolve_full_body_camera(
                  static_cast<int>(build_value), static_cast<int>(height_value),
                  posed_world.data() + head_index * 16, &camera);
        if (camera_status != LTD_NATIVE_SCENE_OK) {
            throw RuntimeError("SCENE_PIPELINE_NATIVE", "native scene-camera resolution failed");
        }
        double body_transform[16]{};
        body_transform[0] = camera.body_scale[0];
        body_transform[5] = camera.body_scale[1];
        body_transform[10] = camera.body_scale[2];
        body_transform[15] = 1.0;
        LtdNativeProjection projection{};
        projection.kind = LTD_NATIVE_PERSPECTIVE;
        projection.width = output_size;
        projection.height = output_size;
        projection.camera_position[0] = 0.0;
        projection.camera_position[1] = camera.camera_position_y;
        projection.camera_position[2] = camera.camera_distance;
        projection.camera_target[0] = 0.0;
        projection.camera_target[1] = camera.camera_at_y;
        projection.camera_target[2] = 0.0;
        projection.camera_up[0] = 0.0;
        projection.camera_up[1] = 1.0;
        projection.camera_up[2] = 0.0;
        projection.vertical_fov_degrees = camera.vertical_fov_degrees;
        projection.horizontal_projection_scale = camera.horizontal_projection_scale;
        std::vector<double> world_positions(mesh.positions.size());
        std::vector<double> world_normals(mesh.normals.size());
        std::vector<double> projected(mesh.positions.size());
        if (ltd_native_transform_and_project(
                posed_positions.data(), posed_normals.data(), vertex_count, body_transform,
                &projection, world_positions.data(), world_normals.data(), projected.data()) !=
            LTD_NATIVE_GEOMETRY_OK) {
            throw RuntimeError("SCENE_PIPELINE_NATIVE", "native transform/projection failed");
        }

        std::vector<std::int32_t> triangle_indices;
        triangle_indices.reserve(mesh.triangles.size() * 3);
        for (const DecodedObjTriangle& triangle : mesh.triangles) {
            for (std::int64_t index : triangle.vertex) {
                if (index < 0 || index >= static_cast<std::int64_t>(vertex_count)) {
                    throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                                       "BodyBase triangle has an invalid vertex index");
                }
                triangle_indices.push_back(static_cast<std::int32_t>(index));
            }
        }
        std::vector<LtdNativeTriangleSetup> setups(mesh.triangles.size());
        if (ltd_native_setup_triangles(
                projected.data(), vertex_count, triangle_indices.data(), mesh.triangles.size(),
                output_size, output_size, 1, 0, setups.data()) != LTD_NATIVE_GEOMETRY_OK) {
            throw RuntimeError("SCENE_PIPELINE_NATIVE", "native triangle setup failed");
        }
        const auto after_geometry = Clock::now();

        if (ltd_native_raster_abi_version() != 1) {
            throw RuntimeError("SCENE_PIPELINE_ABI", "native raster core has an unsupported ABI");
        }
        constexpr std::size_t kCoverageTriangleLimit = 64;
        constexpr std::size_t kCoverageFragmentLimit = 4 * 1024 * 1024;
        std::vector<double> depth(output_size * output_size,
                                  -std::numeric_limits<double>::infinity());
        std::vector<std::int32_t> coverage_xy;
        std::vector<double> coverage_values;
        std::size_t coverage_triangle_count = 0;
        std::size_t coverage_fragment_count = 0;
        for (const LtdNativeTriangleSetup& setup : setups) {
            if (setup.candidate == 0 || coverage_triangle_count >= kCoverageTriangleLimit) continue;
            const std::uint64_t box_width =
                static_cast<std::uint64_t>(setup.x1 - setup.x0) + 1;
            const std::uint64_t box_height =
                static_cast<std::uint64_t>(setup.y1 - setup.y0) + 1;
            if (box_width * box_height > output_size * output_size) {
                throw RuntimeError("SCENE_PIPELINE_RANGE", "triangle coverage box exceeds frame bounds");
            }
            std::vector<LtdNativeRasterFragment> fragments(
                static_cast<std::size_t>(box_width * box_height));
            std::size_t fragment_count = 0;
            const int coverage_status = ltd_native_raster_coverage(
                setup.screen, depth.data(), output_size, output_size,
                setup.x0, setup.x1, setup.y0, setup.y1, setup.denominator,
                fragments.data(), fragments.size(), &fragment_count);
            if (coverage_status != LTD_NATIVE_RASTER_OK) {
                throw RuntimeError("SCENE_PIPELINE_NATIVE", "native raster coverage failed");
            }
            if (coverage_fragment_count + fragment_count > kCoverageFragmentLimit) {
                throw RuntimeError("SCENE_PIPELINE_RANGE",
                                   "bounded raster coverage fragment cap exceeded");
            }
            ++coverage_triangle_count;
            coverage_fragment_count += fragment_count;
            for (std::size_t index = 0; index < fragment_count; ++index) {
                const LtdNativeRasterFragment& fragment = fragments[index];
                coverage_xy.insert(coverage_xy.end(), {fragment.x, fragment.y});
                coverage_values.insert(coverage_values.end(),
                                       {fragment.weight0, fragment.weight1,
                                        fragment.weight2, fragment.z});
            }
        }

        const Json::Array& cached_textures = require_array(prepared_decoded_cache, "textures");
        if (cached_textures.empty()) {
            throw RuntimeError("SCENE_PIPELINE_SCHEMA",
                               "bounded raster sampler requires one authenticated texture");
        }
        const Json::Object& sample_texture_record =
            require_json_object(cached_textures.front(), "decoded texture record");
        const std::filesystem::path sample_texture_path = declared_path(
            repository_root, schema_string(sample_texture_record, "path"),
            "raster sample texture");
        const PinResult sample_texture_pin = file_cache_.pin(
            sample_texture_path, 64 * 1024 * 1024, "raster sample texture");
        DecodedTextureResult sample_texture_decoded;
        try {
            sample_texture_decoded = decoded_cache_.decode_png(
                lowercase_path_key(sample_texture_path), sample_texture_pin.identity.sha256,
                sample_texture_pin.identity.bytes);
        } catch (const DecodedAssetError& error) {
            throw RuntimeError(error.code(), error.what());
        }
        if (sample_texture_decoded.texture == nullptr) {
            throw RuntimeError("SCENE_PIPELINE_CACHE", "decoded sample texture is absent");
        }
        const DecodedTexture& sample_texture = *sample_texture_decoded.texture;
        std::vector<double> sample_source;
        sample_source.reserve(sample_texture.rgba8.size());
        for (std::uint8_t value : sample_texture.rgba8) {
            sample_source.push_back(static_cast<double>(value) / 255.0);
        }
        static constexpr std::array<double, 9> sample_u{
            -0.25, 0.0, 0.125, 0.25, 0.5, 0.75, 0.875, 1.0, 1.25,
        };
        static constexpr std::array<double, 9> sample_v{
            1.25, 1.0, 0.875, 0.75, 0.5, 0.25, 0.125, 0.0, -0.25,
        };
        std::vector<double> sampled_rgba;
        sampled_rgba.reserve(3 * 3 * sample_u.size() * 4);
        for (std::uint32_t wrap_x = LTD_NATIVE_WRAP_CLAMP;
             wrap_x <= LTD_NATIVE_WRAP_MIRROR; ++wrap_x) {
            for (std::uint32_t wrap_y = LTD_NATIVE_WRAP_CLAMP;
                 wrap_y <= LTD_NATIVE_WRAP_MIRROR; ++wrap_y) {
                std::array<double, sample_u.size() * 4> output{};
                if (ltd_native_raster_sample_bilinear_rgba64(
                        sample_source.data(), sample_texture.width, sample_texture.height,
                        sample_u.data(), sample_v.data(), sample_u.size(), wrap_x, wrap_y,
                        output.data()) != LTD_NATIVE_RASTER_OK) {
                    throw RuntimeError("SCENE_PIPELINE_NATIVE",
                                       "native raster bilinear sampling failed");
                }
                sampled_rgba.insert(sampled_rgba.end(), output.begin(), output.end());
            }
        }
        const auto after_raster = Clock::now();

        static constexpr std::array<const char*, 7> draw_groups{
            "ground", "Head__mt_Head", "Hair__mt_Hair", "Mask__mt_Mask",
            "NoseLine__mt_NoseLine", "Ear__mt_Ear", "Trs__mt_LensTrs",
        };
        std::array<LtdNativeDrawRecord, draw_groups.size()> draws{};
        for (std::size_t index = 0; index < draws.size(); ++index) {
            draws[index] = LtdNativeDrawRecord{
                draw_groups[index], static_cast<std::uint8_t>(index == draws.size() - 1),
                static_cast<std::uint8_t>(index != draws.size() - 1)};
        }
        std::array<std::size_t, draw_groups.size()> scheduled{};
        if (ltd_native_schedule_draws(draws.data(), draws.size(), scheduled.data(),
                                      scheduled.size()) != LTD_NATIVE_SCENE_OK) {
            throw RuntimeError("SCENE_PIPELINE_NATIVE", "native draw scheduling failed");
        }

        std::vector<double> triangle_screens;
        std::vector<double> triangle_denominators;
        std::vector<std::int32_t> triangle_bounds;
        std::vector<std::uint8_t> triangle_candidates;
        triangle_screens.reserve(setups.size() * 9);
        triangle_denominators.reserve(setups.size());
        triangle_bounds.reserve(setups.size() * 4);
        triangle_candidates.reserve(setups.size());
        std::size_t candidate_count = 0;
        for (const LtdNativeTriangleSetup& setup : setups) {
            triangle_screens.insert(triangle_screens.end(), setup.screen, setup.screen + 9);
            triangle_denominators.push_back(setup.denominator);
            triangle_bounds.insert(triangle_bounds.end(),
                                   {setup.x0, setup.x1, setup.y0, setup.y1});
            triangle_candidates.push_back(setup.candidate);
            candidate_count += setup.candidate != 0 ? 1 : 0;
        }
        std::vector<std::int64_t> scheduled_i64;
        Json::Array scheduled_json;
        Json::Array scheduled_groups;
        for (std::size_t index : scheduled) {
            scheduled_i64.push_back(static_cast<std::int64_t>(index));
            scheduled_json.emplace_back(static_cast<std::int64_t>(index));
            scheduled_groups.emplace_back(draw_groups[index]);
        }
        std::vector<double> camera_values{
            camera.camera_distance, camera.vertical_fov_degrees,
            camera.horizontal_projection_scale, camera.camera_at_y,
            camera.camera_position_y,
        };
        camera_values.insert(camera_values.end(), camera.bounds, camera.bounds + 4);
        camera_values.insert(camera_values.end(), camera.body_scale, camera.body_scale + 3);
        camera_values.insert(camera_values.end(), camera.head_transform,
                             camera.head_transform + 16);
        const auto finished = Clock::now();
        const auto elapsed_us = [](Clock::time_point begin, Clock::time_point end) {
            return static_cast<std::int64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count());
        };

        Json::Array body_scale_json;
        for (double value : camera.body_scale) body_scale_json.emplace_back(value);
        Json::Array bounds_json;
        for (double value : camera.bounds) bounds_json.emplace_back(value);
        const std::array<float, 3> body_scale_f32{
            static_cast<float>(camera.body_scale[0]),
            static_cast<float>(camera.body_scale[1]),
            static_cast<float>(camera.body_scale[2]),
        };
        return Json::Object{
            {"asset_index_sha256", Json(schema_string(asset_index, "index_sha256"))},
            {"body_scale", Json(std::move(body_scale_json))},
            {"camera", Json::Object{
                {"bounds", Json(std::move(bounds_json))},
                {"camera_at_y", Json(camera.camera_at_y)},
                {"camera_distance", Json(camera.camera_distance)},
                {"camera_position_y", Json(camera.camera_position_y)},
                {"horizontal_projection_scale", Json(camera.horizontal_projection_scale)},
                {"vertical_fov_degrees", Json(camera.vertical_fov_degrees)},
            }},
            {"counts", Json::Object{
                {"bone_count", Json(static_cast<std::int64_t>(bones.size()))},
                {"candidate_triangle_count", Json(static_cast<std::int64_t>(candidate_count))},
                {"palette_count", Json(static_cast<std::int64_t>(palette.size()))},
                {"skinned_shape_count", Json(static_cast<std::int64_t>(native_shapes.size()))},
                {"smooth_matrix_count", Json(static_cast<std::int64_t>(inverse_values.size()))},
                {"triangle_count", Json(static_cast<std::int64_t>(mesh.triangles.size()))},
                {"vertex_count", Json(static_cast<std::int64_t>(vertex_count))},
            }},
            {"fixture", Json::Object{
                {"build", Json(build_value)},
                {"height", Json(height_value)},
                {"ltd_sha256", Json(schema_string(ltd_object, "sha256"))},
                {"output_size", Json(requested_size)},
                {"view", Json(view)},
            }},
            {"raster_probe", Json::Object{
                {"coverage_fragment_count", Json(static_cast<std::int64_t>(coverage_fragment_count))},
                {"coverage_triangle_count", Json(static_cast<std::int64_t>(coverage_triangle_count))},
                {"maximum_fragment_count", Json(static_cast<std::int64_t>(kCoverageFragmentLimit))},
                {"maximum_triangle_count", Json(static_cast<std::int64_t>(kCoverageTriangleLimit))},
                {"sample_texture_path", Json(logical_path(repository_root, sample_texture_path))},
                {"sample_texture_sha256", Json(sample_texture_pin.identity.sha256)},
            }},
            {"hashes", Json::Object{
                {"body_scale_f32", Json(native_array_sha256(
                    body_scale_f32.data(), body_scale_f32.size()))},
                {"camera_f64", Json(native_array_sha256(camera_values.data(), camera_values.size()))},
                {"camera_q6", Json(quantized_f64_sha256(camera_values.data(), camera_values.size()))},
                {"coverage_values_q6", Json(quantized_f64_sha256(coverage_values.data(), coverage_values.size()))},
                {"coverage_xy_i32", Json(native_array_sha256(coverage_xy.data(), coverage_xy.size()))},
                {"posed_normals_f64", Json(native_array_sha256(posed_normals.data(), posed_normals.size()))},
                {"posed_normals_q6", Json(quantized_f64_sha256(posed_normals.data(), posed_normals.size()))},
                {"posed_positions_f64", Json(native_array_sha256(posed_positions.data(), posed_positions.size()))},
                {"posed_positions_q6", Json(quantized_f64_sha256(posed_positions.data(), posed_positions.size()))},
                {"posed_world_f64", Json(native_array_sha256(posed_world.data(), posed_world.size()))},
                {"posed_world_q6", Json(quantized_f64_sha256(posed_world.data(), posed_world.size()))},
                {"projected_f64", Json(native_array_sha256(projected.data(), projected.size()))},
                {"projected_q6", Json(quantized_f64_sha256(projected.data(), projected.size()))},
                {"schedule_i64", Json(native_array_sha256(scheduled_i64.data(), scheduled_i64.size()))},
                {"sampled_rgba_q6", Json(quantized_f64_sha256(sampled_rgba.data(), sampled_rgba.size()))},
                {"triangle_bounds_i32", Json(native_array_sha256(triangle_bounds.data(), triangle_bounds.size()))},
                {"triangle_candidates_u8", Json(native_array_sha256(triangle_candidates.data(), triangle_candidates.size()))},
                {"triangle_denominators_q6", Json(quantized_f64_sha256(triangle_denominators.data(), triangle_denominators.size()))},
                {"triangle_screens_q6", Json(quantized_f64_sha256(triangle_screens.data(), triangle_screens.size()))},
                {"world_normals_q6", Json(quantized_f64_sha256(world_normals.data(), world_normals.size()))},
                {"world_positions_q6", Json(quantized_f64_sha256(world_positions.data(), world_positions.size()))},
            }},
            {"module_abis", Json::Object{
                {"geometry", Json(static_cast<std::int64_t>(ltd_native_geometry_abi_version()))},
                {"pose", Json(static_cast<std::int64_t>(ltd_native_pose_abi_version()))},
                {"raster_core", Json(static_cast<std::int64_t>(ltd_native_raster_abi_version()))},
                {"scene_math", Json(static_cast<std::int64_t>(ltd_native_scene_abi_version()))},
            }},
            {"output", Json::Object{
                {"activation_ready", Json(false)},
                {"pixels_produced", Json(false)},
                {"verification_contract", Json("bodybase-iconpose-perspective-setup-v1")},
            }},
            {"schedule", Json::Object{
                {"contract", Json("canonical-production-state-vector-v1")},
                {"groups", Json(std::move(scheduled_groups))},
                {"indices", Json(std::move(scheduled_json))},
            }},
            {"schema_version", Json(static_cast<std::int64_t>(1))},
            {"source_seals", Json::Object{
                {"body_catalog_sha256", Json(body_catalog_pin.identity.sha256)},
                {"body_obj_sha256", Json(body_obj_pin.identity.sha256)},
                {"icon_pose_sha256", Json(pose_pin.identity.sha256)},
            }},
            {"timings_us", Json::Object{
                {"asset_prepare", Json(elapsed_us(started, after_prepare))},
                {"input_compile", Json(elapsed_us(after_prepare, after_inputs))},
                {"pose_skin", Json(elapsed_us(after_inputs, after_pose))},
                {"transform_triangle_setup", Json(elapsed_us(after_pose, after_geometry))},
                {"raster_probe", Json(elapsed_us(after_geometry, after_raster))},
                {"hash_report", Json(elapsed_us(after_raster, finished))},
                {"total", Json(elapsed_us(started, finished))},
            }},
        };
    }

private:
    static constexpr std::size_t kMaximumManifestBytes = 4 * 1024 * 1024;
    const ZstdApi& zstd_;
    LtdParser ltd_parser_;
    ImmutableFileCache& file_cache_;
    DecodedAssetCache decoded_cache_;
    DecodedAssetCache render_decoded_cache_;
    struct CachedManifest final {
        Json document;
    };
    std::map<std::wstring, CachedManifest> manifest_cache_;

    struct ManifestResult final {
        Json document;
        FileIdentity identity;
        bool cache_hit;
    };

    struct ValidationResult final {
        std::filesystem::path parts_metadata_path;
        std::vector<std::pair<std::string, std::filesystem::path>> parts_configs;
        std::vector<std::pair<std::string, std::filesystem::path>> source_textures;
        std::vector<std::pair<std::string, std::string>> texture_names;
        std::vector<ModelDraft> models;
        std::int64_t selector_count = 0;
        std::int64_t enabled_record_count = 0;
        std::int64_t unresolved_count = 0;
    };

    struct NativePartsResult final {
        ValidationResult validated;
        std::unique_ptr<infinimii::native_parts::Catalog> catalog;
        infinimii::native_parts::Selection selection;
        FileIdentity catalog_identity;
        Json records_json;
        Json active_models_json;
        Json active_textures_json;
    };

    NativePartsResult select_native_parts(
        const std::filesystem::path& repository_root,
        const FileIdentity& ltd_identity,
        const std::filesystem::path& catalog_path,
        const Json::Object& ltd_document) {
        const PinResult catalog_pin = file_cache_.pin(
            catalog_path, 4 * 1024 * 1024, "native Parts catalog");
        if (catalog_pin.identity.sha256 != kNativePartsCatalogSha256) {
            throw RuntimeError(
                "NATIVE_PARTS_CATALOG_HASH",
                "native Parts catalog differs from the independently pinned SHA-256");
        }
        const auto expected_digest = decode_sha256(kNativePartsCatalogSha256);
        std::unique_ptr<infinimii::native_parts::Catalog> catalog;
        std::string selector_error;
        if (!infinimii::native_parts::Catalog::Open(
                catalog_pin.identity.bytes, expected_digest, &catalog, &selector_error)) {
            throw RuntimeError("NATIVE_PARTS_CATALOG_INVALID", selector_error);
        }

        const Json::Object& sections = require_object(ltd_document, "serialized_sections");
        const Json::Object& char_section = require_object(sections, "char_info");
        const std::int64_t signed_offset = schema_integer(char_section, "offset");
        const std::int64_t signed_length = schema_integer(char_section, "byte_length");
        if (signed_offset < 0 ||
            signed_length != static_cast<std::int64_t>(infinimii::native_parts::kCharInfoSize)) {
            throw RuntimeError("NATIVE_PARTS_CHARINFO", "LTD CharInfoEx section is not exactly 152 bytes");
        }
        const std::size_t offset = static_cast<std::size_t>(signed_offset);
        if (offset > ltd_identity.bytes.size() ||
            infinimii::native_parts::kCharInfoSize > ltd_identity.bytes.size() - offset) {
            throw RuntimeError("NATIVE_PARTS_CHARINFO", "LTD CharInfoEx section is truncated");
        }

        NativePartsResult result;
        if (!infinimii::native_parts::Select(
                *catalog,
                std::span<const std::uint8_t>(
                    ltd_identity.bytes.data() + offset,
                    infinimii::native_parts::kCharInfoSize),
                &result.selection, &selector_error)) {
            throw RuntimeError("NATIVE_PARTS_SELECT", selector_error);
        }
        result.catalog_identity = catalog_pin.identity;
        result.validated.selector_count = static_cast<std::int64_t>(
            infinimii::native_parts::kLogicalRecordCount);

        Json::Array records;
        Json::Array active_models;
        Json::Array active_textures;
        for (std::size_t index = 0; index < result.selection.records.size(); ++index) {
            const auto& selected = result.selection.records[index];
            Json::Object record{
                {"logical_name", Json(std::string(
                    infinimii::native_parts::LogicalName(selected.logical)))},
                {"selector", Json(static_cast<std::int64_t>(selected.selector))},
                {"category", selected.has_category ?
                    Json(std::string(infinimii::native_parts::CategoryName(selected.category))) :
                    Json(nullptr)},
                {"resolved", Json(selected.resolved)},
                {"enabled", Json(selected.enabled)},
                {"is_nothing", Json(selected.is_nothing)},
                {"gate", Json(std::string(infinimii::native_parts::GateName(selected.gate)))},
                {"gate_enabled", Json(selected.gate_enabled)},
                {"inactive_projection", Json(std::string(
                    infinimii::native_parts::InactiveProjectionName(
                        selected.inactive_projection)))},
            };
            if (!selected.resolved || selected.entry == nullptr) {
                record.emplace("record", Json(nullptr));
                record.emplace("texture_name", Json(nullptr));
                record.emplace("model_resources", Json::Array{});
            } else {
                const auto& entry = *selected.entry;
                record.emplace("record", Json(std::string(entry.record_name)));
                record.emplace("parts_config", Json(std::string(entry.parts_config)));
                record.emplace("texture_name", entry.texture_name.empty() ?
                    Json(nullptr) : Json(std::string(entry.texture_name)));
                Json::Array models;
                for (const auto& model : entry.model_resources) {
                    models.emplace_back(Json::Object{
                        {"role", Json(std::string(model.role))},
                        {"resource_name", Json(std::string(model.resource_name))},
                    });
                }
                record.emplace("model_resources", Json(std::move(models)));
                const std::filesystem::path config = declared_path(
                    repository_root, entry.parts_config,
                    std::string(infinimii::native_parts::LogicalName(selected.logical)) +
                        ".parts_config");
                result.validated.parts_configs.emplace_back(
                    std::string(infinimii::native_parts::LogicalName(selected.logical)), config);
            }
            if (!selected.resolved && selected.has_category) {
                ++result.validated.unresolved_count;
            }
            if (selected.enabled) {
                ++result.validated.enabled_record_count;
                const std::string logical_name(
                    infinimii::native_parts::LogicalName(selected.logical));
                for (const auto& model : selected.entry->model_resources) {
                    if (model.role != "ModelUnit" || model.resource_name.empty()) continue;
                    if (!safe_asset_segment(model.resource_name)) {
                        throw RuntimeError("ACTIVE_PARTS_PATH", "unsafe native active model identity");
                    }
                    const std::string resource(model.resource_name);
                    result.validated.models.push_back(ModelDraft{
                        resource, resource,
                        {"active_part:" + logical_name + ":ModelUnit"}});
                }
                if (!selected.entry->texture_name.empty()) {
                    const std::string texture(selected.entry->texture_name);
                    if (!safe_asset_segment(texture)) {
                        throw RuntimeError("ACTIVE_PARTS_PATH", "unsafe native active texture identity");
                    }
                    result.validated.texture_names.emplace_back(logical_name, texture);
                    const std::filesystem::path png = declared_path(
                        repository_root,
                        "../ltdDemo_converted_assets/textures_png/1/Tex/Pack/" +
                            texture + ".png",
                        logical_name + ".texture_resource.png");
                    result.validated.source_textures.emplace_back(logical_name, png);
                }
            }
            records.emplace_back(Json(std::move(record)));
        }
        for (std::size_t index = 0; index < result.selection.active_model_count; ++index) {
            active_models.emplace_back(std::string(result.selection.active_model_resources[index]));
        }
        for (std::size_t index = 0; index < result.selection.active_texture_count; ++index) {
            active_textures.emplace_back(
                std::string(result.selection.active_texture_resources[index]));
        }
        result.records_json = Json(std::move(records));
        result.active_models_json = Json(std::move(active_models));
        result.active_textures_json = Json(std::move(active_textures));
        result.catalog = std::move(catalog);
        return result;
    }

    static std::array<std::uint8_t, 32> decode_sha256(std::string_view value) {
        if (value.size() != 64) {
            throw RuntimeError("RUNTIME_SCHEMA_ERROR", "pinned SHA-256 has invalid length");
        }
        std::array<std::uint8_t, 32> result{};
        const auto digit = [](char byte) -> int {
            if (byte >= '0' && byte <= '9') return byte - '0';
            if (byte >= 'a' && byte <= 'f') return byte - 'a' + 10;
            if (byte >= 'A' && byte <= 'F') return byte - 'A' + 10;
            return -1;
        };
        for (std::size_t index = 0; index < result.size(); ++index) {
            const int high = digit(value[index * 2]);
            const int low = digit(value[index * 2 + 1]);
            if (high < 0 || low < 0) {
                throw RuntimeError("RUNTIME_SCHEMA_ERROR", "pinned SHA-256 is not hexadecimal");
            }
            result[index] = static_cast<std::uint8_t>((high << 4) | low);
        }
        return result;
    }

    static Json parse_json_bytes(const std::vector<std::uint8_t>& bytes,
                                 std::string_view label) {
        if (bytes.size() >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf) {
            throw RuntimeError("ACTIVE_PARTS_JSON", std::string(label) + " must not contain a BOM");
        }
        const std::string_view text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        try {
            Json document = JsonParser(text).parse();
            if (!document.is_object()) {
                throw RuntimeError("ACTIVE_PARTS_SCHEMA", std::string(label) + " must be an object");
            }
            return document;
        } catch (const RuntimeError& error) {
            if (error.code() == "INVALID_JSON") {
                throw RuntimeError("ACTIVE_PARTS_JSON",
                                   std::string(label) + " is invalid JSON: " + error.what());
            }
            throw;
        }
    }

    ManifestResult load_manifest(const std::filesystem::path& path) {
        PinResult pinned = file_cache_.pin(path, kMaximumManifestBytes, "active-parts manifest");
        const std::wstring key = lowercase_path_key(pinned.identity.path);
        const auto cached = manifest_cache_.find(key);
        if (cached != manifest_cache_.end()) {
            return ManifestResult{cached->second.document, std::move(pinned.identity), true};
        }
        if (manifest_cache_.size() >= 64) {
            throw RuntimeError("MANIFEST_CACHE_CAPACITY",
                               "active-parts manifest cache reached its 64-entry limit");
        }
        Json document = parse_json_bytes(pinned.identity.bytes, "active-parts manifest");
        manifest_cache_.emplace(key, CachedManifest{document});
        return ManifestResult{std::move(document), std::move(pinned.identity), false};
    }

    static void verify_declared_file(const Json::Object& record,
                                     const FileIdentity& identity,
                                     std::string_view label) {
        const std::string expected_sha256 = schema_string(record, "sha256");
        const Json* length = find_member(record, "byte_length");
        if ((length && (!length->is_integer() || length->as_integer() < 0 ||
                        static_cast<std::uint64_t>(length->as_integer()) != identity.byte_length)) ||
            expected_sha256 != identity.sha256) {
            throw RuntimeError("ACTIVE_PARTS_HASH_MISMATCH",
                               std::string(label) + " byte length or SHA-256 changed");
        }
    }

    ValidationResult validate_manifest(const std::filesystem::path& repository_root,
                                       const std::filesystem::path& ltd_path,
                                       const std::filesystem::path& manifest_path,
                                       const Json::Object& manifest,
                                       const Json::Object& ltd) {
        (void)manifest_path;
        if (schema_integer(manifest, "schema_version") != 1) {
            throw RuntimeError("ACTIVE_PARTS_SCHEMA", "active-parts schema_version must be 1");
        }
        const Json::Object& target = require_object(manifest, "target");
        const std::string target_sha = schema_string(target, "sha256");
        if (target_sha != schema_string(ltd, "sha256")) {
            throw RuntimeError("ACTIVE_PARTS_TARGET_MISMATCH",
                               "active-parts manifest targets a different LTD SHA-256");
        }
        const std::filesystem::path declared_target =
            declared_path(repository_root, schema_string(target, "path"), "target.path");
        if (lowercase_path_key(declared_target) != lowercase_path_key(ltd_path)) {
            throw RuntimeError("ACTIVE_PARTS_TARGET_MISMATCH",
                               "active-parts target.path does not identify the live LTD");
        }
        if (schema_integer(target, "byte_length") != schema_integer(ltd, "byte_length") ||
            schema_string(target, "display_name") != schema_string(ltd, "display_name")) {
            throw RuntimeError("ACTIVE_PARTS_TARGET_MISMATCH",
                               "active-parts target size or display name differs from live LTD");
        }
        const Json::Object& char_info = require_object(ltd, "char_info");
        if (schema_string(target, "internal_name") != schema_string(char_info, "name") ||
            schema_integer(target, "gender") != schema_integer(char_info, "gender")) {
            throw RuntimeError("ACTIVE_PARTS_TARGET_MISMATCH",
                               "active-parts target CharInfo identity differs from live LTD");
        }
        const Json& target_face_gender = require_member(target, "face_gender");
        const Json& live_face_gender =
            require_member(require_object(ltd, "personality_and_voice"), "face_gender");
        if (!(target_face_gender == live_face_gender)) {
            throw RuntimeError("ACTIVE_PARTS_TARGET_MISMATCH",
                               "active-parts target face_gender differs from live LTD");
        }
        const Json* effective = find_member(manifest, "effective_char_info");
        if (effective && !(*effective == require_member(ltd, "char_info"))) {
            throw RuntimeError("ACTIVE_PARTS_CHARINFO_MISMATCH",
                               "active-parts effective_char_info differs from live LTD");
        }

        ValidationResult result;
        const Json::Object& metadata = require_object(manifest, "parts_metadata");
        result.parts_metadata_path = declared_path(
            repository_root, schema_string(metadata, "path"), "parts_metadata.path");
        PinResult metadata_pin = file_cache_.pin(
            result.parts_metadata_path, 64 * 1024 * 1024, "PartsIndex metadata");
        verify_declared_file(metadata, metadata_pin.identity, "PartsIndex metadata");

        result.selector_count = schema_integer(manifest, "selector_count");
        result.enabled_record_count = schema_integer(manifest, "enabled_record_count");
        result.unresolved_count = schema_integer(manifest, "unresolved_parts_index_count");
        const Json::Array& records = require_array(manifest, "records");
        if (result.selector_count < 0 ||
            static_cast<std::size_t>(result.selector_count) != records.size()) {
            throw RuntimeError("ACTIVE_PARTS_COUNT_MISMATCH",
                               "selector_count differs from records length");
        }
        std::set<std::string> logical_names;
        std::set<std::string> derived_model_resources;
        std::set<std::string> derived_texture_resources;
        std::int64_t enabled_count = 0;
        std::int64_t unresolved_count = 0;
        for (const Json& record_value : records) {
            if (!record_value.is_object()) {
                throw RuntimeError("ACTIVE_PARTS_SCHEMA", "records contains a non-object");
            }
            const Json::Object& record = record_value.as_object();
            const std::string logical_name = schema_string(record, "logical_name");
            if (!logical_names.insert(logical_name).second) {
                throw RuntimeError("ACTIVE_PARTS_DUPLICATE",
                                   "records contains a duplicate logical_name");
            }
            const bool resolved = require_bool(record, "resolved");
            const bool enabled = require_bool(record, "enabled");
            if (enabled) ++enabled_count;
            const Json* category = find_member(record, "category");
            // The schema retains hair_back_editor_state as a named subordinate
            // editor value with category:null. It is not a failed PartsIndex
            // lookup and is intentionally excluded from the manifest's
            // unresolved_parts_index_count.
            if (!resolved && category && !category->is_null()) ++unresolved_count;
            if (enabled && !resolved) {
                throw RuntimeError("ACTIVE_PARTS_SCHEMA",
                                   "an unresolved active-parts record cannot be enabled");
            }
            const Json* selector_field = find_member(record, "selector_field");
            if (selector_field && !selector_field->is_null()) {
                if (!selector_field->is_string()) {
                    throw RuntimeError("ACTIVE_PARTS_SCHEMA", "selector_field must be string or null");
                }
                const Json* live_selector = find_member(char_info, selector_field->as_string());
                if (!live_selector || !live_selector->is_integer() ||
                    schema_integer(record, "selector") != live_selector->as_integer()) {
                    throw RuntimeError("ACTIVE_PARTS_SELECTOR_MISMATCH",
                                       logical_name + " selector differs from live CharInfo");
                }
            }
            const Json* gate = find_member(record, "gate");
            if (gate && gate->is_string() && gate->as_string().rfind("face_flags.", 0) == 0) {
                const std::string flag = gate->as_string().substr(std::string("face_flags.").size());
                const Json::Object& flags = require_object(char_info, "face_flags");
                const Json* live_flag = find_member(flags, flag);
                if (!live_flag || !live_flag->is_bool() ||
                    require_bool(record, "gate_enabled") != live_flag->as_bool()) {
                    throw RuntimeError("ACTIVE_PARTS_GATE_MISMATCH",
                                       logical_name + " gate differs from live CharInfo");
                }
            }
            if (resolved) {
                const std::filesystem::path config = declared_path(
                    repository_root, schema_string(record, "parts_config"),
                    logical_name + ".parts_config");
                PinResult config_pin = file_cache_.pin(
                    config, 64 * 1024 * 1024, logical_name + " Parts config");
                const std::int64_t expected_size = schema_integer(record, "parts_config_byte_length");
                const std::string expected_hash = schema_string(record, "parts_config_sha256");
                if (expected_size < 0 ||
                    static_cast<std::uint64_t>(expected_size) != config_pin.identity.byte_length ||
                    expected_hash != config_pin.identity.sha256) {
                    throw RuntimeError("ACTIVE_PARTS_HASH_MISMATCH",
                                       logical_name + " Parts config hash changed");
                }
                result.parts_configs.emplace_back(logical_name, config);
            }
            const Json* models = find_member(record, "model_resources");
            if (models) {
                if (!models->is_array()) {
                    throw RuntimeError("ACTIVE_PARTS_SCHEMA", "model_resources must be an array");
                }
                for (const Json& model_value : models->as_array()) {
                    if (!model_value.is_object()) {
                        throw RuntimeError("ACTIVE_PARTS_SCHEMA",
                                           "model_resources contains a non-object");
                    }
                    const Json::Object& model = model_value.as_object();
                    if (!enabled || schema_string(model, "role") != "ModelUnit") continue;
                    const std::string resource = schema_string(model, "resource_name");
                    const std::filesystem::path fmdb(utf8_to_wide(schema_string(model, "fmdb"), "fmdb"));
                    const std::string model_name = wide_to_utf8(fmdb.stem().wstring());
                    if (!safe_asset_segment(resource) || !safe_asset_segment(model_name)) {
                        throw RuntimeError("ACTIVE_PARTS_PATH", "unsafe active model identity");
                    }
                    derived_model_resources.insert(resource);
                    result.models.push_back(ModelDraft{
                        resource, model_name, {"active_part:" + logical_name + ":ModelUnit"}});
                }
            }
            const Json* texture_name = find_member(record, "texture_name");
            if (enabled && texture_name && !texture_name->is_null()) {
                if (!texture_name->is_string() || !safe_asset_segment(texture_name->as_string())) {
                    throw RuntimeError("ACTIVE_PARTS_PATH", "unsafe active texture identity");
                }
                derived_texture_resources.insert(texture_name->as_string());
                result.texture_names.emplace_back(logical_name, texture_name->as_string());
                const Json::Object& texture_resource = require_object(record, "texture_resource");
                if (!require_bool(texture_resource, "png_exists")) {
                    throw RuntimeError("ACTIVE_PARTS_ASSET_MISSING",
                                       logical_name + " selected texture PNG is marked missing");
                }
                result.source_textures.emplace_back(
                    logical_name,
                    declared_path(repository_root, schema_string(texture_resource, "png"),
                                  logical_name + ".texture_resource.png"));
            }
        }
        if (enabled_count != result.enabled_record_count ||
            unresolved_count != result.unresolved_count) {
            throw RuntimeError("ACTIVE_PARTS_COUNT_MISMATCH",
                               "enabled or unresolved record count differs from manifest");
        }
        validate_string_set(manifest, "active_model_resources", derived_model_resources);
        validate_string_set(manifest, "active_texture_resources", derived_texture_resources);
        return result;
    }

    static void validate_string_set(const Json::Object& manifest, std::string_view key,
                                    const std::set<std::string>& expected) {
        std::set<std::string> actual;
        for (const Json& value : require_array(manifest, key)) {
            if (!value.is_string() || !actual.insert(value.as_string()).second) {
                throw RuntimeError("ACTIVE_PARTS_SCHEMA",
                                   std::string(key) + " must contain unique strings");
            }
        }
        if (actual != expected) {
            throw RuntimeError("ACTIVE_PARTS_RESOURCE_MISMATCH",
                               std::string(key) + " differs from enabled records");
        }
    }

    template <typename AddAsset>
    static void add_mip_directory(const std::filesystem::path& directory,
                                  const std::string& role, const std::string& subtype,
                                  AddAsset&& add_asset) {
        const std::filesystem::path root = canonical_directory(directory, role);
        std::vector<std::filesystem::path> files;
        std::error_code error;
        for (std::filesystem::directory_iterator iterator(root, error), end;
             !error && iterator != end; iterator.increment(error)) {
            if (!iterator->is_regular_file(error) || error) {
                throw RuntimeError("TEXTURE_MIP_INVENTORY",
                                   role + " contains a non-regular entry");
            }
            const std::filesystem::path canonical = canonical_file(iterator->path(), role);
            if (!is_within(root, canonical)) {
                throw RuntimeError("TEXTURE_MIP_INVENTORY",
                                   role + " contains a link outside its directory");
            }
            const std::string filename = wide_to_utf8(canonical.filename().wstring());
            if (filename.size() < 9 || filename.rfind("mip_", 0) != 0 ||
                filename.substr(filename.size() - 4) != ".png" ||
                !std::all_of(filename.begin() + 4, filename.end() - 4,
                             [](unsigned char byte) { return std::isdigit(byte) != 0; })) {
                throw RuntimeError("TEXTURE_MIP_INVENTORY",
                                   role + " contains a non-mip file");
            }
            files.push_back(canonical);
        }
        if (error || files.empty()) {
            throw RuntimeError("TEXTURE_MIP_INVENTORY", role + " has no readable mip files");
        }
        std::sort(files.begin(), files.end(), [](const auto& left, const auto& right) {
            return lowercase_path_key(left.filename()) < lowercase_path_key(right.filename());
        });
        for (const std::filesystem::path& path : files) {
            add_asset("texture", subtype, path, role);
        }
    }

    static std::string asset_records_dump(const Json::Array& records) {
        return Json(records).dump();
    }
};

Json zstd_readiness(const ZstdApi& zstd) {
    Json::Object result{
        {"available", Json(zstd.available())},
        {"maximum_decoded_frame_bytes", Json(static_cast<std::int64_t>(kMaximumDecodedFrameBytes))},
    };
    if (zstd.available()) {
        result.emplace("loaded_path", Json(zstd.loaded_path()));
        result.emplace("version_number", Json(static_cast<std::int64_t>(zstd.version_number())));
    } else {
        result.emplace("error", Json(zstd.availability_error()));
    }
    return Json(std::move(result));
}

Json native_png_backend_readiness(bool& authenticated) {
    authenticated = false;
    Json::Object result{
        {"authenticated", Json(false)},
        {"available", Json(false)},
        {"expected_sha256", Json(std::string(kNativePngBackendSha256))},
    };
    try {
        const PinnedNativePngBackend backend(native_png_backend_sibling_path());
        result.emplace("path", Json(wide_to_utf8(backend.path().wstring())));
        result.emplace("byte_count", Json(static_cast<std::int64_t>(backend.byte_count())));
        result.emplace("sha256", Json(backend.sha256()));
        if (!backend.authenticated()) {
            result.emplace("error", Json("native png sha256 does not match the pinned backend"));
            return Json(std::move(result));
        }

        infinimii_native_png_encoder* raw_encoder = nullptr;
        std::array<char, 512> open_error{};
        const auto open_status = infinimii_native_png_encoder_open(
            backend.path().c_str(), &raw_encoder, open_error.data(), open_error.size());
        std::unique_ptr<infinimii_native_png_encoder,
                        decltype(&infinimii_native_png_encoder_close)>
            encoder(raw_encoder, &infinimii_native_png_encoder_close);
        if (open_status != INFINIMII_NATIVE_PNG_OK || encoder == nullptr) {
            result.emplace(
                "error", Json(open_error[0] == '\0'
                    ? "native png backend identity probe failed"
                    : open_error.data()));
            return Json(std::move(result));
        }
        std::array<char, 64> version{};
        std::uint32_t probe_size = 0;
        std::uint32_t probe_crc32 = 0;
        if (infinimii_native_png_backend_identity(
                encoder.get(), version.data(), version.size(), &probe_size,
                &probe_crc32) != INFINIMII_NATIVE_PNG_OK) {
            result.emplace("error", Json("native png backend identity could not be reported"));
            return Json(std::move(result));
        }
        authenticated = true;
        result["authenticated"] = Json(true);
        result["available"] = Json(true);
        result.emplace("backend_version", Json(version.data()));
        result.emplace("probe_stream_crc32", Json(static_cast<std::int64_t>(probe_crc32)));
        result.emplace("probe_stream_size", Json(static_cast<std::int64_t>(probe_size)));
    } catch (const std::exception& error) {
        result.emplace("error", Json(std::string("native png sha256 probe failed: ") + error.what()));
    }
    return Json(std::move(result));
}

Json readiness(const ZstdApi& zstd) {
    Json modules = linked_render_module_inventory();
    bool modules_linked = true;
    for (const auto& [name, value] : modules.as_object()) {
        (void)name;
        const auto& record = value.as_object();
        const auto linked = record.find("linked");
        if (linked == record.end() || !linked->second.is_bool() ||
            !linked->second.as_bool()) {
            modules_linked = false;
            break;
        }
    }
    bool png_authenticated = false;
    Json png_backend = native_png_backend_readiness(png_authenticated);
    const bool pipeline_ready = ltd_native_render_pipeline_activation_ready() != 0;
    const bool orchestrator_ready =
        infinimii::native_render_orchestrator::ActivationReady();
    const bool activation_ready = zstd.available() && png_authenticated &&
        modules_linked && pipeline_ready && orchestrator_ready;
    Json::Array blockers;
    if (!zstd.available()) {
        blockers.emplace_back("zstd runtime dependency is unavailable");
    }
    if (!png_authenticated) {
        blockers.emplace_back("native png sha256 authentication failed");
    }
    if (!modules_linked) {
        blockers.emplace_back("one linked native render module failed ABI authentication");
    }
    if (!pipeline_ready) {
        blockers.emplace_back("native render pipeline production gate is not activated");
    }
    if (!orchestrator_ready) {
        blockers.emplace_back("native render orchestrator production gate is not activated");
    }
    return Json::Object{
        {"accepted_output_coverage", Json(activation_ready
            ? "four-fixture-two-view-two-size-byte-exact-native-png"
            : "four-fixture-two-view-two-size-native-png-activation-pending")},
        {"activation_blockers", Json(std::move(blockers))},
        {"activation_ready", Json(activation_ready)},
        {"capabilities", Json::Object{
            {"jsonl_protocol_v1", Json(true)},
            {"ltd_v2_parse", Json(true)},
            {"ltd_v3_parse", Json(true)},
            {"active_parts_manifest_ingestion", Json(true)},
            {"native_parts_index_selection", Json(true)},
            {"native_parts_asset_preparation", Json(true)},
            {"immutable_obj_material_texture_index", Json(true)},
            {"decoded_obj_named_uv_cache", Json(true)},
            {"decoded_rgba8_png_mip_cache", Json(true)},
            {"normalized_material_metadata_cache", Json(true)},
            {"native_body_pose_skinning", Json(true)},
            {"native_camera_scene_math", Json(true)},
            {"native_transform_projection_triangle_setup", Json(true)},
            {"native_bounded_coverage", Json(true)},
            {"native_bilinear_rgba64_sampling", Json(true)},
            {"bounded_scene_pipeline_verification", Json(true)},
            {"native_facepaint_decode", Json(true)},
            {"native_linked_draw_runtime_v2", Json(true)},
            {"native_linked_face_runtime", Json(true)},
            {"native_linked_material_schedule", Json(true)},
            {"native_linked_scene_assembler", Json(true)},
            {"native_linked_render_pipeline", Json(true)},
            {"native_png_module_linked", Json(true)},
            {"render_ltd_protocol_operation", Json(true)},
            {"native_png", Json(png_authenticated)},
            {"native_render", Json(activation_ready)},
            {"zstd_bounded_validation", Json(zstd.available())},
        }},
        {"maximum_ltd_bytes", Json(static_cast<std::int64_t>(kMaximumLtdBytes))},
        {"material_adapter", Json::Object{
            {"catalog_sha256", Json(std::string(
                infinimii::native_runtime_material_adapter::CatalogSha256()))},
            {"source_bundle_sha256", Json(std::string(
                infinimii::native_runtime_material_adapter::SourceBundleSha256()))},
        }},
        {"native_parts_catalog_sha256", Json(std::string(kNativePartsCatalogSha256))},
        {"native_png_backend", std::move(png_backend)},
        {"render_modules", std::move(modules)},
        {"process_launcher", Json("native-executable")},
        {"protocol_ready", Json(true)},
        {"zstd", zstd_readiness(zstd)},
    };
}

Json base_response(const Json& request_id, const Json& operation, bool ok) {
    return Json::Object{
        {"ok", Json(ok)},
        {"op", operation},
        {"protocol", Json(std::string(kProtocol))},
        {"request_id", request_id},
        {"version", Json(kProtocolVersion)},
    };
}

Json error_response(const Json& request_id, const Json& operation,
                    const RuntimeError& error) {
    Json response = base_response(request_id, operation, false);
    response.as_object().emplace("error", Json::Object{
        {"code", Json(error.code())},
        {"message", Json(error.what())},
    });
    return response;
}

class RuntimeServer final {
public:
    RuntimeServer() : parser_(zstd_), active_assets_(zstd_, file_cache_) {}

    Json handle_line(std::string_view line, bool& should_shutdown) {
        Json request_id(nullptr);
        Json operation(nullptr);
        try {
            if (line.size() > kMaximumRequestBytes) {
                throw RuntimeError("REQUEST_TOO_LARGE", "JSONL request exceeds 64 KiB limit");
            }
            Json request = JsonParser(line).parse();
            if (!request.is_object()) throw RuntimeError("INVALID_REQUEST", "request must be an object");
            const Json::Object& object = request.as_object();
            if (const Json* candidate = find_member(object, "request_id")) {
                if (candidate->is_string()) request_id = *candidate;
            }
            if (const Json* candidate = find_member(object, "op")) {
                if (candidate->is_string()) operation = *candidate;
            }
            const std::string protocol = require_string(object, "protocol");
            if (protocol != kProtocol) {
                throw RuntimeError("PROTOCOL_MISMATCH", "unsupported protocol identifier");
            }
            const std::int64_t version = require_integer(object, "version");
            if (version != kProtocolVersion) {
                throw RuntimeError("VERSION_UNSUPPORTED", "unsupported protocol version");
            }
            const std::string id = require_string(object, "request_id");
            if (id.empty() || id.size() > 128) {
                throw RuntimeError("INVALID_REQUEST", "request_id must contain 1 to 128 UTF-8 bytes");
            }
            request_id = Json(id);
            const std::string op = require_string(object, "op");
            operation = Json(op);

            if (op == "hello") {
                reject_unknown_fields(object, {"protocol", "version", "request_id", "op"});
                Json response = base_response(request_id, operation, true);
                response.as_object().emplace("result", Json::Object{
                    {"native_process_id", Json(static_cast<std::int64_t>(GetCurrentProcessId()))},
                    {"process_model", Json("persistent-stdin-stdout-jsonl")},
                    {"runtime_version", Json(std::string(kRuntimeVersion))},
                });
                return response;
            }
            if (op == "readiness") {
                reject_unknown_fields(object, {"protocol", "version", "request_id", "op"});
                Json response = base_response(request_id, operation, true);
                response.as_object().emplace("result", readiness(zstd_));
                return response;
            }
            if (op == "parse_ltd") {
                reject_unknown_fields(object,
                                      {"protocol", "version", "request_id", "op", "path",
                                       "validate_zstd"});
                const std::string path_utf8 = require_string(object, "path");
                if (path_utf8.empty()) throw RuntimeError("INVALID_REQUEST", "path must not be empty");
                const bool validate_zstd = optional_bool(object, "validate_zstd", true);
                const std::filesystem::path path(utf8_to_wide(path_utf8, "path"));
                Json response = base_response(request_id, operation, true);
                response.as_object().emplace("result", parser_.parse_file(path, validate_zstd));
                return response;
            }
            if (op == "prepare_assets") {
                reject_unknown_fields(object,
                                      {"protocol", "version", "request_id", "op",
                                       "repository_root", "ltd_path", "active_parts_path",
                                       "model_root", "face_texture_root",
                                       "material_texture_roots"});
                Json response = base_response(request_id, operation, true);
                response.as_object().emplace("result", active_assets_.prepare(object));
                return response;
            }
            if (op == "prepare_native_parts") {
                reject_unknown_fields(object,
                                      {"protocol", "version", "request_id", "op",
                                       "repository_root", "ltd_path", "catalog_path",
                                       "model_root", "face_texture_root",
                                       "material_texture_roots"});
                Json response = base_response(request_id, operation, true);
                response.as_object().emplace(
                    "result", active_assets_.prepare_native_parts(object));
                return response;
            }
            if (op == "prepare_decoded_assets") {
                reject_unknown_fields(object,
                                      {"protocol", "version", "request_id", "op",
                                       "repository_root", "ltd_path", "active_parts_path",
                                       "model_root", "face_texture_root",
                                       "material_texture_roots"});
                Json response = base_response(request_id, operation, true);
                response.as_object().emplace("result", active_assets_.prepare(object, true));
                return response;
            }
            if (op == "verify_scene_pipeline") {
                reject_unknown_fields(object,
                                      {"protocol", "version", "request_id", "op",
                                       "repository_root", "ltd_path", "active_parts_path",
                                       "model_root", "face_texture_root",
                                       "material_texture_roots", "pose_path", "view",
                                       "output_size"});
                Json response = base_response(request_id, operation, true);
                response.as_object().emplace(
                    "result", active_assets_.verify_scene_pipeline(object));
                return response;
            }
            if (op == "render_ltd") {
                reject_unknown_fields(object,
                                      {"protocol", "version", "request_id", "op",
                                       "repository_root", "ltd_path", "catalog_path",
                                       "model_root", "face_texture_root",
                                       "material_texture_roots", "pose_path", "output_dir",
                                       "view", "output_size", "supersampling",
                                       "presentation_context"});
                Json response = base_response(request_id, operation, true);
                auto [result, inserted] =
                    response.as_object().emplace("result", Json(nullptr));
                if (!inserted) {
                    throw RuntimeError("INTERNAL_ERROR", "render response slot already exists");
                }
                active_assets_.render_ltd(object, result->second);
                return response;
            }
            if (op == "shutdown") {
                reject_unknown_fields(object, {"protocol", "version", "request_id", "op"});
                should_shutdown = true;
                Json response = base_response(request_id, operation, true);
                response.as_object().emplace("result", Json::Object{{"shutdown", Json(true)}});
                return response;
            }
            throw RuntimeError("UNKNOWN_OPERATION", "unsupported operation: " + op);
        } catch (const RuntimeError& error) {
            return error_response(request_id, operation, error);
        } catch (const std::exception& error) {
            return error_response(request_id, operation,
                                  RuntimeError("INTERNAL_ERROR", error.what()));
        }
    }

    Json probe() const {
        Json response = base_response(Json("probe"), Json("readiness"), true);
        response.as_object().emplace("result", readiness(zstd_));
        return response;
    }

private:
    ZstdApi zstd_;
    LtdParser parser_;
    ImmutableFileCache file_cache_;
    ActiveAssetRuntime active_assets_;
};

} // namespace native_runtime

int main(int argc, char** argv) {
    using namespace native_runtime;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    try {
        RuntimeServer server;
        if (argc == 2 && std::string_view(argv[1]) == "--probe") {
            std::cout << server.probe().dump() << '\n';
            return 0;
        }
        if (argc == 2 && std::string_view(argv[1]) == "--version") {
            std::cout << kRuntimeVersion << '\n';
            return 0;
        }
        if (argc != 1) {
            std::cerr << "usage: ltd_native_runtime.exe [--probe|--version]\n";
            return 2;
        }
        std::ios::sync_with_stdio(false);
        std::string line;
        while (std::getline(std::cin, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            bool should_shutdown = false;
            const Json response = server.handle_line(line, should_shutdown);
            std::cout << response.dump() << '\n' << std::flush;
            if (should_shutdown) break;
        }
        return 0;
    } catch (const RuntimeError& error) {
        std::cerr << error.code() << ": " << error.what() << '\n';
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "INTERNAL_ERROR: " << error.what() << '\n';
        return 1;
    }
}
