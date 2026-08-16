#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include "native_scene_cache_adapter.h"
#include "decoded_asset_cache.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace {

constexpr std::uint64_t kMaximumCatalogBytes = UINT64_C(64) * 1024 * 1024;
constexpr std::uint64_t kMaximumObjBytes = UINT64_C(64) * 1024 * 1024;
constexpr std::uint64_t kMaximumPoseBytes = UINT64_C(4) * 1024 * 1024;
constexpr std::size_t kMaximumBones = 512;
constexpr std::size_t kMaximumShapes = 512;
constexpr std::size_t kMaximumModels = LTD_NATIVE_SCENE_ASSEMBLER_MAX_MODELS;

struct Failure final : std::runtime_error {
    ltd_native_scene_cache_adapter_status status;
    Failure(ltd_native_scene_cache_adapter_status value, std::string message)
        : std::runtime_error(std::move(message)), status(value) {}
};

[[noreturn]] void fail(ltd_native_scene_cache_adapter_status status, std::string message) {
    throw Failure(status, std::move(message));
}

void write_error(char* output, std::size_t capacity, std::string_view message) noexcept {
    if (output == nullptr || capacity == 0) return;
    const std::size_t count = std::min(capacity - 1, message.size());
    std::memcpy(output, message.data(), count);
    output[count] = '\0';
}

class Json final {
public:
    using Array = std::vector<Json>;
    using Object = std::map<std::string, Json, std::less<>>;
    using Storage = std::variant<std::nullptr_t, bool, std::int64_t, double,
                                 std::string, Array, Object>;

    Json() : value_(nullptr) {}
    explicit Json(std::nullptr_t) : value_(nullptr) {}
    explicit Json(bool value) : value_(value) {}
    explicit Json(std::int64_t value) : value_(value) {}
    explicit Json(double value) : value_(value) {}
    explicit Json(std::string value) : value_(std::move(value)) {}
    explicit Json(Array value) : value_(std::move(value)) {}
    explicit Json(Object value) : value_(std::move(value)) {}

    [[nodiscard]] bool is_null() const { return std::holds_alternative<std::nullptr_t>(value_); }
    [[nodiscard]] bool is_bool() const { return std::holds_alternative<bool>(value_); }
    [[nodiscard]] bool is_integer() const { return std::holds_alternative<std::int64_t>(value_); }
    [[nodiscard]] bool is_double() const { return std::holds_alternative<double>(value_); }
    [[nodiscard]] bool is_string() const { return std::holds_alternative<std::string>(value_); }
    [[nodiscard]] bool is_array() const { return std::holds_alternative<Array>(value_); }
    [[nodiscard]] bool is_object() const { return std::holds_alternative<Object>(value_); }
    [[nodiscard]] bool as_bool() const { return std::get<bool>(value_); }
    [[nodiscard]] std::int64_t as_integer() const { return std::get<std::int64_t>(value_); }
    [[nodiscard]] double as_double() const {
        return is_integer() ? static_cast<double>(as_integer()) : std::get<double>(value_);
    }
    [[nodiscard]] const std::string& as_string() const { return std::get<std::string>(value_); }
    [[nodiscard]] const Array& as_array() const { return std::get<Array>(value_); }
    [[nodiscard]] const Object& as_object() const { return std::get<Object>(value_); }

private:
    Storage value_;
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

class JsonParser final {
public:
    explicit JsonParser(std::string_view input) : input_(input) {}
    Json parse() {
        whitespace();
        Json result = value();
        whitespace();
        if (cursor_ != input_.size()) invalid("trailing data");
        return result;
    }

private:
    std::string_view input_;
    std::size_t cursor_ = 0;

    [[noreturn]] void invalid(std::string_view message) const {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
             "JSON " + std::string(message) + " at byte " + std::to_string(cursor_));
    }
    void whitespace() {
        while (cursor_ < input_.size() &&
               (input_[cursor_] == ' ' || input_[cursor_] == '\t' ||
                input_[cursor_] == '\r' || input_[cursor_] == '\n')) ++cursor_;
    }
    bool take(char value) {
        if (cursor_ < input_.size() && input_[cursor_] == value) {
            ++cursor_;
            return true;
        }
        return false;
    }
    Json value() {
        if (cursor_ >= input_.size()) invalid("value is truncated");
        switch (input_[cursor_]) {
        case 'n': literal("null"); return Json(nullptr);
        case 't': literal("true"); return Json(true);
        case 'f': literal("false"); return Json(false);
        case '"': return Json(string());
        case '[': return Json(array());
        case '{': return Json(object());
        default: return number();
        }
    }
    void literal(std::string_view expected) {
        if (input_.substr(cursor_, expected.size()) != expected) invalid("literal is invalid");
        cursor_ += expected.size();
    }
    std::uint32_t hex4() {
        if (cursor_ + 4 > input_.size()) invalid("Unicode escape is truncated");
        std::uint32_t result = 0;
        for (int index = 0; index < 4; ++index) {
            const char byte = input_[cursor_++];
            result <<= 4;
            if (byte >= '0' && byte <= '9') result |= static_cast<std::uint32_t>(byte - '0');
            else if (byte >= 'a' && byte <= 'f') result |= static_cast<std::uint32_t>(byte - 'a' + 10);
            else if (byte >= 'A' && byte <= 'F') result |= static_cast<std::uint32_t>(byte - 'A' + 10);
            else invalid("Unicode escape is invalid");
        }
        return result;
    }
    std::string string() {
        if (!take('"')) invalid("string expected");
        std::string result;
        while (cursor_ < input_.size()) {
            const unsigned char byte = static_cast<unsigned char>(input_[cursor_++]);
            if (byte == '"') return result;
            if (byte < 0x20) invalid("string has a control byte");
            if (byte != '\\') {
                result.push_back(static_cast<char>(byte));
                continue;
            }
            if (cursor_ >= input_.size()) invalid("escape is truncated");
            switch (input_[cursor_++]) {
            case '"': result.push_back('"'); break;
            case '\\': result.push_back('\\'); break;
            case '/': result.push_back('/'); break;
            case 'b': result.push_back('\b'); break;
            case 'f': result.push_back('\f'); break;
            case 'n': result.push_back('\n'); break;
            case 'r': result.push_back('\r'); break;
            case 't': result.push_back('\t'); break;
            case 'u': {
                std::uint32_t codepoint = hex4();
                if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
                    if (!take('\\') || !take('u')) invalid("high surrogate is unpaired");
                    const std::uint32_t low = hex4();
                    if (low < 0xdc00 || low > 0xdfff) invalid("low surrogate is invalid");
                    codepoint = UINT32_C(0x10000) + ((codepoint - 0xd800) << 10) + (low - 0xdc00);
                } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
                    invalid("low surrogate is unpaired");
                }
                append_utf8(result, codepoint);
                break;
            }
            default: invalid("escape is invalid");
            }
        }
        invalid("string is unterminated");
    }
    Json number() {
        const std::size_t start = cursor_;
        take('-');
        if (cursor_ >= input_.size()) invalid("number is truncated");
        if (input_[cursor_] == '0') {
            ++cursor_;
        } else {
            if (input_[cursor_] < '1' || input_[cursor_] > '9') invalid("value is invalid");
            while (cursor_ < input_.size() && input_[cursor_] >= '0' && input_[cursor_] <= '9') ++cursor_;
        }
        bool integral = true;
        if (cursor_ < input_.size() && input_[cursor_] == '.') {
            integral = false; ++cursor_;
            if (cursor_ >= input_.size() || input_[cursor_] < '0' || input_[cursor_] > '9') invalid("fraction is invalid");
            while (cursor_ < input_.size() && input_[cursor_] >= '0' && input_[cursor_] <= '9') ++cursor_;
        }
        if (cursor_ < input_.size() && (input_[cursor_] == 'e' || input_[cursor_] == 'E')) {
            integral = false; ++cursor_;
            if (cursor_ < input_.size() && (input_[cursor_] == '+' || input_[cursor_] == '-')) ++cursor_;
            if (cursor_ >= input_.size() || input_[cursor_] < '0' || input_[cursor_] > '9') invalid("exponent is invalid");
            while (cursor_ < input_.size() && input_[cursor_] >= '0' && input_[cursor_] <= '9') ++cursor_;
        }
        const std::string token(input_.substr(start, cursor_ - start));
        if (integral) {
            std::int64_t result = 0;
            const auto parsed = std::from_chars(token.data(), token.data() + token.size(), result);
            if (parsed.ec == std::errc{} && parsed.ptr == token.data() + token.size()) return Json(result);
        }
        char* end = nullptr;
        const double result = std::strtod(token.c_str(), &end);
        if (end != token.data() + token.size() || !std::isfinite(result)) invalid("number is invalid");
        return Json(result);
    }
    Json::Array array() {
        take('['); whitespace();
        Json::Array result;
        if (take(']')) return result;
        for (;;) {
            whitespace(); result.push_back(value()); whitespace();
            if (take(']')) return result;
            if (!take(',')) invalid("array comma expected");
        }
    }
    Json::Object object() {
        take('{'); whitespace();
        Json::Object result;
        if (take('}')) return result;
        for (;;) {
            whitespace();
            if (cursor_ >= input_.size() || input_[cursor_] != '"') invalid("object key expected");
            std::string key = string(); whitespace();
            if (!take(':')) invalid("object colon expected");
            whitespace();
            if (!result.emplace(std::move(key), value()).second) invalid("duplicate object key");
            whitespace();
            if (take('}')) return result;
            if (!take(',')) invalid("object comma expected");
        }
    }
};

const Json& field(const Json::Object& object, std::string_view key) {
    const auto found = object.find(key);
    if (found == object.end()) {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
             "required JSON field is missing: " + std::string(key));
    }
    return found->second;
}

const Json::Object& object(const Json& value, std::string_view context) {
    if (!value.is_object()) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                                 std::string(context) + " must be an object");
    return value.as_object();
}
const Json::Array& array(const Json& value, std::string_view context) {
    if (!value.is_array()) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                                std::string(context) + " must be an array");
    return value.as_array();
}
std::string text(const Json& value, std::string_view context) {
    if (!value.is_string()) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                                 std::string(context) + " must be a string");
    return value.as_string();
}
std::int64_t integer(const Json& value, std::string_view context) {
    if (!value.is_integer()) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                                  std::string(context) + " must be an integer");
    return value.as_integer();
}
double number(const Json& value, std::string_view context) {
    if (!value.is_integer() && !value.is_double()) {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
             std::string(context) + " must be a finite number");
    }
    return value.as_double();
}

std::optional<std::reference_wrapper<const Json>> optional_field(
    const Json::Object& object_value, std::string_view key) {
    const auto found = object_value.find(key);
    if (found == object_value.end()) return std::nullopt;
    return std::cref(found->second);
}

std::wstring utf8_to_wide(std::string_view input) {
    if (input.empty() || input.size() > static_cast<std::size_t>(INT_MAX)) {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT, "path is empty or too long");
    }
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                                          static_cast<int>(input.size()), nullptr, 0);
    if (count <= 0) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT,
                         "path is not valid UTF-8");
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                            static_cast<int>(input.size()), result.data(), count) != count) {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT, "path conversion failed");
    }
    return result;
}

std::filesystem::path canonical_existing(const std::filesystem::path& path,
                                         std::string_view context,
                                         bool directory = false) {
    std::error_code error;
    const auto result = std::filesystem::canonical(path, error);
    if (error || (directory ? !std::filesystem::is_directory(result, error)
                            : !std::filesystem::is_regular_file(result, error))) {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_MISSING,
             std::string(context) + " is missing");
    }
    return result;
}

bool contained_by(const std::filesystem::path& root, const std::filesystem::path& child) {
    auto left = root.begin();
    auto right = child.begin();
    for (; left != root.end(); ++left, ++right) {
        if (right == child.end()) return false;
        std::wstring a = left->wstring(), b = right->wstring();
        std::transform(a.begin(), a.end(), a.begin(), towlower);
        std::transform(b.begin(), b.end(), b.begin(), towlower);
        if (a != b) return false;
    }
    return true;
}

std::vector<std::uint8_t> read_file(const std::filesystem::path& path,
                                    std::uint64_t maximum,
                                    std::string_view context) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_MISSING,
                    std::string(context) + " cannot be sized");
    if (size == 0 || size > maximum || size > SIZE_MAX) {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_RESOURCE_LIMIT,
             std::string(context) + " has an invalid byte length");
    }
    std::vector<std::uint8_t> result(static_cast<std::size_t>(size));
    std::ifstream stream(path, std::ios::binary);
    stream.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(result.size()));
    if (!stream || stream.peek() != std::ifstream::traits_type::eof()) {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_CHANGED,
             std::string(context) + " changed while reading");
    }
    return result;
}

std::string sha256(const std::vector<std::uint8_t>& bytes) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0) {
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_INTERNAL_ERROR, "SHA-256 provider failed");
    }
    std::size_t cursor = 0;
    while (cursor < bytes.size()) {
        const std::size_t count = std::min<std::size_t>(bytes.size() - cursor, ULONG_MAX);
        if (BCryptHashData(hash, const_cast<PUCHAR>(bytes.data() + cursor),
                           static_cast<ULONG>(count), 0) < 0) {
            BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_INTERNAL_ERROR, "SHA-256 update failed");
        }
        cursor += count;
    }
    std::array<std::uint8_t, 32> digest{};
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) {
        BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_INTERNAL_ERROR, "SHA-256 finalize failed");
    }
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
    static constexpr char hex[] = "0123456789abcdef";
    std::string result(64, '\0');
    for (std::size_t index = 0; index < digest.size(); ++index) {
        result[index * 2] = hex[digest[index] >> 4];
        result[index * 2 + 1] = hex[digest[index] & 15];
    }
    return result;
}

Json parse_json(const std::vector<std::uint8_t>& bytes) {
    if (std::find(bytes.begin(), bytes.end(), UINT8_C(0)) != bytes.end()) {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID, "JSON contains NUL");
    }
    return JsonParser(std::string_view(reinterpret_cast<const char*>(bytes.data()),
                                       bytes.size())).parse();
}

template <std::size_t Count>
std::array<double, Count> number_array(const Json& value, std::string_view context) {
    const auto& values = array(value, context);
    if (values.size() < Count) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                                    std::string(context) + " is too short");
    std::array<double, Count> result{};
    for (std::size_t index = 0; index < Count; ++index) result[index] = number(values[index], context);
    return result;
}

}  // namespace

namespace {

struct PoseBoneStorage final {
    std::string name;
    ltd_native_scene_pose_bone_view view{};
};

struct PoseStorage final {
    std::string name;
    std::string source_sha256;
    std::vector<PoseBoneStorage> storage;
    std::vector<ltd_native_scene_pose_bone_view> views;
    ltd_native_scene_pose_view view{};

    void finalize() {
        views.clear();
        views.reserve(storage.size());
        for (auto& item : storage) {
            item.view.name = item.name.c_str();
            views.push_back(item.view);
        }
        view.name = name.c_str();
        view.source_sha256 = source_sha256.c_str();
        view.bones = views.data();
        view.bone_count = views.size();
    }
};

PoseStorage parse_pose(const std::vector<std::uint8_t>& bytes,
                       std::string source_sha256) {
    const Json document = parse_json(bytes);
    const auto& root = object(document, "IconPose");
    if (text(field(root, "Name"), "IconPose.Name") != "IconPose" ||
        integer(field(root, "FrameCount"), "IconPose.FrameCount") != 1 ||
        text(field(root, "RotationMode"), "IconPose.RotationMode") != "EulerXYZ") {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
             "pose must be the static one-frame EulerXYZ IconPose");
    }
    PoseStorage result;
    result.name = "IconPose";
    result.source_sha256 = std::move(source_sha256);
    const auto& bones = array(field(root, "Bones"), "IconPose.Bones");
    if (bones.empty() || bones.size() > kMaximumBones) {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_RESOURCE_LIMIT,
             "IconPose bone count is invalid");
    }
    std::set<std::string> names;
    result.storage.reserve(bones.size());
    for (const auto& value : bones) {
        const auto& bone = object(value, "IconPose bone");
        PoseBoneStorage item;
        item.name = text(field(bone, "Name"), "IconPose bone.Name");
        if (item.name.empty() || !names.insert(item.name).second) {
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                 "IconPose bone names must be nonempty and unique");
        }
        const auto& curves = array(field(bone, "Curves"), "IconPose bone.Curves");
        if (!curves.empty()) {
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                 "IconPose must not contain animation curves");
        }
        const auto scale = number_array<3>(field(bone, "BaseScale"), "BaseScale");
        const auto rotation = number_array<3>(field(bone, "BaseRotation"), "BaseRotation");
        const auto translation = number_array<3>(field(bone, "BaseTranslation"), "BaseTranslation");
        std::copy(scale.begin(), scale.end(), item.view.scale);
        std::copy(rotation.begin(), rotation.end(), item.view.rotation);
        std::copy(translation.begin(), translation.end(), item.view.translation);
        result.storage.push_back(std::move(item));
    }
    result.finalize();
    return result;
}

PoseStorage copy_pose(const ltd_native_scene_pose_view& input) {
    if (input.name == nullptr || std::string_view(input.name) != "IconPose" ||
        input.source_sha256 == nullptr || std::strlen(input.source_sha256) != 64 ||
        input.bones == nullptr || input.bone_count == 0 || input.bone_count > kMaximumBones) {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT,
             "borrowed pose view is invalid");
    }
    PoseStorage result;
    result.name = input.name;
    result.source_sha256 = input.source_sha256;
    result.storage.reserve(input.bone_count);
    std::set<std::string> names;
    for (std::size_t index = 0; index < input.bone_count; ++index) {
        const auto& source = input.bones[index];
        if (source.name == nullptr || source.name[0] == '\0' ||
            !names.insert(source.name).second) {
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT,
                 "borrowed pose contains an invalid bone name");
        }
        PoseBoneStorage item;
        item.name = source.name;
        item.view = source;
        for (double value : item.view.scale) if (!std::isfinite(value))
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT, "borrowed pose is non-finite");
        for (double value : item.view.rotation) if (!std::isfinite(value))
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT, "borrowed pose is non-finite");
        for (double value : item.view.translation) if (!std::isfinite(value))
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT, "borrowed pose is non-finite");
        result.storage.push_back(std::move(item));
    }
    result.finalize();
    return result;
}

struct ShapeStorage final {
    std::string group;
    std::string texcoord_attribute;
    std::vector<std::int32_t> palette_indices;
    std::vector<double> weights;
    ltd_native_scene_shape_view view{};
};

struct ModelStorage final {
    std::string resource;
    std::string model;
    std::string obj_sha256;
    std::string catalog_sha256;
    std::string named_uv_sha256;
    std::filesystem::path obj_path;
    std::filesystem::path catalog_path;
    std::optional<std::filesystem::path> named_uv_path;
    native_runtime::DecodedObjView decoded;
    std::vector<ltd_native_scene_triangle_view> triangles;
    std::vector<std::string> named_uv_names;
    std::vector<ltd_native_scene_named_uv_view> named_uv_views;
    std::vector<std::string> bone_names;
    std::vector<ltd_native_scene_bone_view> bones;
    std::vector<ShapeStorage> shape_storage;
    std::vector<ltd_native_scene_shape_view> shapes;
    std::vector<std::int32_t> matrix_to_bone;
    std::vector<double> inverse_bind;
    ltd_native_scene_model_view view{};

    void finalize() {
        named_uv_views.clear();
        named_uv_views.reserve(decoded.named_uv_channels.size());
        named_uv_names.clear();
        named_uv_names.reserve(decoded.named_uv_channels.size());
        for (const auto& source : decoded.named_uv_channels) {
            named_uv_names.emplace_back(source.name);
        }
        for (std::size_t index = 0; index < decoded.named_uv_channels.size(); ++index) {
            const auto& source = decoded.named_uv_channels[index];
            named_uv_views.push_back({named_uv_names[index].c_str(), source.values.data(),
                                      source.values.size()});
        }
        for (std::size_t index = 0; index < bones.size(); ++index) {
            bones[index].name = bone_names[index].c_str();
        }
        shapes.clear();
        shapes.reserve(shape_storage.size());
        for (auto& item : shape_storage) {
            item.view.group = item.group.c_str();
            item.view.texcoord_attribute = item.texcoord_attribute.c_str();
            item.view.palette_indices = item.palette_indices.empty() ? nullptr : item.palette_indices.data();
            item.view.palette_index_count = item.palette_indices.size();
            item.view.weights = item.weights.empty() ? nullptr : item.weights.data();
            item.view.weight_count = item.weights.size();
            shapes.push_back(item.view);
        }
        const auto& mesh = *decoded.mesh;
        view = {};
        view.resource_name = resource.c_str();
        view.model_name = model.c_str();
        view.obj_sha256 = obj_sha256.c_str();
        view.catalog_sha256 = catalog_sha256.c_str();
        view.named_uv_sha256 = named_uv_sha256.empty() ? nullptr : named_uv_sha256.c_str();
        view.positions = mesh.positions.data();
        view.normals = mesh.normals.data();
        view.texcoords = mesh.texcoords.data();
        view.position_count = mesh.positions.size() / 3;
        view.normal_count = mesh.normals.size() / 3;
        view.texcoord_count = mesh.texcoords.size() / 2;
        view.triangles = triangles.data();
        view.triangle_count = triangles.size();
        view.named_uv_channels = named_uv_views.empty() ? nullptr : named_uv_views.data();
        view.named_uv_channel_count = named_uv_views.size();
        view.bones = bones.data();
        view.bone_count = bones.size();
        view.shapes = shapes.data();
        view.shape_count = shapes.size();
        view.matrix_to_bone = matrix_to_bone.empty() ? nullptr : matrix_to_bone.data();
        view.palette_count = matrix_to_bone.size();
        view.inverse_bind_matrices = inverse_bind.empty() ? nullptr : inverse_bind.data();
        view.smooth_count = inverse_bind.size() / 16;
    }
};

std::wstring lowercase_key(const std::filesystem::path& path) {
    std::wstring result = path.wstring();
    std::transform(result.begin(), result.end(), result.begin(), [](wchar_t value) {
        return static_cast<wchar_t>(std::towlower(value));
    });
    return result;
}

bool safe_leaf(std::string_view value) {
    if (value.empty() || value.size() > 128 || value == "." || value == "..") return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
        return std::isalnum(byte) != 0 || byte == '_' || byte == '-';
    });
}

void append_skin_rows(const Json& input, std::size_t row_count, std::size_t width,
                      std::vector<std::int32_t>& output, std::string_view context) {
    const auto& rows = array(input, context);
    if (rows.size() != row_count) {
        fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
             std::string(context) + " row count differs from VertexCount");
    }
    output.reserve(row_count * width);
    for (const auto& row_value : rows) {
        const auto& row = array(row_value, context);
        if (row.size() < width) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                                     std::string(context) + " row is too short");
        for (std::size_t index = 0; index < width; ++index) {
            const auto value = integer(row[index], context);
            if (value < INT32_MIN || value > INT32_MAX) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                                                             std::string(context) + " index is out of range");
            output.push_back(static_cast<std::int32_t>(value));
        }
    }
}

void append_weight_rows(const Json& input, std::size_t row_count, std::size_t width,
                        std::vector<double>& output, std::string_view context) {
    const auto& rows = array(input, context);
    if (rows.empty() && width == 1) return;
    if (rows.size() != row_count) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                                       std::string(context) + " row count differs from VertexCount");
    output.reserve(row_count * width);
    for (const auto& row_value : rows) {
        const auto& row = array(row_value, context);
        if (row.size() < width) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                                     std::string(context) + " row is too short");
        for (std::size_t index = 0; index < width; ++index) output.push_back(number(row[index], context));
    }
}

}  // namespace

struct ltd_native_scene_cache_adapter final {
    std::filesystem::path model_root;
    native_runtime::DecodedAssetCache* cache = nullptr;
    std::unique_ptr<native_runtime::DecodedAssetCache> owned_cache;
    PoseStorage pose;
    std::map<std::string, std::unique_ptr<ModelStorage>, std::less<>> models;

    static int LTD_NATIVE_SCENE_ASSEMBLER_CALL get_model(
        void* context, const char* resource_name, const char* model_name,
        ltd_native_scene_model_view* output, char* error, std::size_t error_capacity) {
        if (context == nullptr || resource_name == nullptr || model_name == nullptr || output == nullptr) {
            write_error(error, error_capacity, "scene cache callback arguments are invalid");
            return 2;
        }
        try {
            *output = static_cast<ltd_native_scene_cache_adapter*>(context)
                          ->load_model(resource_name, model_name).view;
            return 0;
        } catch (const Failure& failure) {
            write_error(error, error_capacity, failure.what());
            return failure.status == LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_MISSING ? 1 : 2;
        } catch (const native_runtime::DecodedAssetError& failure) {
            write_error(error, error_capacity,
                        std::string("decoded cache ") + failure.code() + ": " + failure.what());
            return failure.code() == "DECODED_CACHE_MISS" ? 1 : 2;
        } catch (const std::exception& failure) {
            write_error(error, error_capacity, failure.what());
            return 2;
        }
    }

    ModelStorage& load_model(std::string resource, std::string model) {
        if (!safe_leaf(resource) || !safe_leaf(model)) {
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                 "model identity is not a safe source leaf");
        }
        const std::string key = resource + "\n" + model;
        if (const auto found = models.find(key); found != models.end()) return *found->second;
        if (models.size() >= kMaximumModels) {
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_RESOURCE_LIMIT,
                 "scene adapter model limit exceeded");
        }

        const auto directory = canonical_existing(model_root / utf8_to_wide(resource),
                                                  "model resource directory", true);
        if (!contained_by(model_root, directory)) {
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_CHANGED,
                 "model resource escapes the sealed model root");
        }
        const auto obj_path = canonical_existing(directory / (utf8_to_wide(model) + L".obj"),
                                                 "prepared OBJ");
        const auto catalog_path = canonical_existing(directory / L"bfres.json", "BFRES catalog");
        if (!contained_by(directory, obj_path) || !contained_by(directory, catalog_path)) {
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_CHANGED,
                 "model source escapes its resource directory");
        }
        const auto obj_bytes = read_file(obj_path, kMaximumObjBytes, "prepared OBJ");
        const auto catalog_bytes = read_file(catalog_path, kMaximumCatalogBytes, "BFRES catalog");
        auto owner = std::make_unique<ModelStorage>();
        owner->resource = resource;
        owner->model = model;
        owner->obj_path = obj_path;
        owner->catalog_path = catalog_path;
        owner->obj_sha256 = sha256(obj_bytes);
        owner->catalog_sha256 = sha256(catalog_bytes);

        const auto obj_result = cache->decode_obj(lowercase_key(obj_path), owner->obj_sha256, obj_bytes);
        if (obj_result.mesh == nullptr || obj_result.metadata == nullptr) {
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_CACHE_FAILED,
                 "decoded OBJ cache returned no immutable mesh");
        }
        const auto sidecar_candidate = directory / (utf8_to_wide(model) + L".texcoords.json");
        std::error_code sidecar_error;
        if (std::filesystem::is_regular_file(sidecar_candidate, sidecar_error) && !sidecar_error) {
            const auto sidecar_path = canonical_existing(sidecar_candidate, "named-UV sidecar");
            if (!contained_by(directory, sidecar_path)) {
                fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_CHANGED,
                     "named-UV sidecar escapes its resource directory");
            }
            auto sidecar_bytes = read_file(sidecar_path, kMaximumObjBytes, "named-UV sidecar");
            owner->named_uv_sha256 = sha256(sidecar_bytes);
            owner->named_uv_path = sidecar_path;
            cache->attach_named_uv(lowercase_key(obj_path), owner->obj_sha256, model,
                                   owner->named_uv_sha256, sidecar_bytes);
            owner->decoded = cache->get_obj_with_named_uv(
                lowercase_key(obj_path), owner->obj_sha256, owner->named_uv_sha256);
        } else {
            owner->decoded = cache->get_obj(lowercase_key(obj_path), owner->obj_sha256);
        }

        const auto& mesh = *owner->decoded.mesh;
        owner->triangles.reserve(mesh.triangles.size());
        for (const auto& source : mesh.triangles) {
            ltd_native_scene_triangle_view triangle{};
            triangle.group = source.group.c_str();
            std::copy(std::begin(source.vertex), std::end(source.vertex), triangle.vertex);
            std::copy(std::begin(source.texcoord), std::end(source.texcoord), triangle.texcoord);
            std::copy(std::begin(source.normal), std::end(source.normal), triangle.normal);
            owner->triangles.push_back(triangle);
        }

        const auto catalog = parse_json(catalog_bytes);
        const auto& root = object(catalog, "BFRES catalog");
        if (text(field(root, "ResourceName"), "ResourceName") != resource) {
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                 "BFRES ResourceName differs from requested resource");
        }
        const Json::Object* selected = nullptr;
        for (const auto& value : array(field(root, "Models"), "Models")) {
            const auto& candidate = object(value, "BFRES model");
            if (text(field(candidate, "Name"), "model.Name") == model) {
                if (selected != nullptr) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                                              "BFRES model identity occurs more than once");
                selected = &candidate;
            }
        }
        if (selected == nullptr) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                                      "requested model is absent from BFRES catalog");
        if (text(field(*selected, "SkeletonRotationMode"), "SkeletonRotationMode") != "EulerXYZ") {
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                 "only EulerXYZ skeletons are supported");
        }

        const auto& bones = array(field(*selected, "Bones"), "Bones");
        if (bones.empty() || bones.size() > kMaximumBones) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_RESOURCE_LIMIT,
                                                                "BFRES bone count is invalid");
        owner->bone_names.reserve(bones.size());
        owner->bones.reserve(bones.size());
        for (std::size_t index = 0; index < bones.size(); ++index) {
            const auto& source = object(bones[index], "BFRES bone");
            owner->bone_names.push_back(text(field(source, "Name"), "bone.Name"));
            const auto parent = integer(field(source, "ParentIndex"), "bone.ParentIndex");
            if (parent < -1 || parent >= static_cast<std::int64_t>(index)) {
                fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                     "BFRES bone parent order is invalid");
            }
            ltd_native_scene_bone_view bone{};
            bone.parent_index = static_cast<std::int32_t>(parent);
            const auto scale = number_array<3>(field(source, "Scale"), "bone.Scale");
            const auto rotation = number_array<3>(field(source, "Rotation"), "bone.Rotation");
            const auto position = number_array<3>(field(source, "Position"), "bone.Position");
            std::copy(scale.begin(), scale.end(), bone.scale);
            std::copy(rotation.begin(), rotation.end(), bone.rotation);
            std::copy(position.begin(), position.end(), bone.translation);
            owner->bones.push_back(bone);
        }
        if (std::set<std::string>(owner->bone_names.begin(), owner->bone_names.end()).size() !=
            owner->bone_names.size()) {
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                 "BFRES bone names are not unique");
        }

        const auto& shapes = array(field(*selected, "Shapes"), "Shapes");
        if (shapes.empty() || shapes.size() > kMaximumShapes) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_RESOURCE_LIMIT,
                                                                   "BFRES shape count is invalid");
        owner->shape_storage.reserve(shapes.size());
        for (const auto& value : shapes) {
            const auto& source = object(value, "BFRES shape");
            ShapeStorage shape;
            shape.group = text(field(source, "Name"), "shape.Name");
            if (const auto texcoord = optional_field(source, "TexcoordAttribute")) {
                shape.texcoord_attribute = text(texcoord->get(), "shape.TexcoordAttribute");
            }
            const auto bone_index = integer(field(source, "BoneIndex"), "shape.BoneIndex");
            const auto skin_count = integer(field(source, "VertexSkinCount"), "shape.VertexSkinCount");
            const auto vertex_offset = integer(field(source, "VertexOffset"), "shape.VertexOffset");
            const auto vertex_count = integer(field(source, "VertexCount"), "shape.VertexCount");
            if (bone_index < 0 || bone_index >= static_cast<std::int64_t>(bones.size()) ||
                skin_count < 0 || skin_count > 16 || vertex_offset < 0 || vertex_count < 0) {
                fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                     "BFRES shape dimensions are invalid");
            }
            shape.view.bone_index = static_cast<std::int32_t>(bone_index);
            shape.view.vertex_skin_count = static_cast<std::uint32_t>(skin_count);
            shape.view.vertex_offset = static_cast<std::size_t>(vertex_offset);
            shape.view.vertex_count = static_cast<std::size_t>(vertex_count);
            if (skin_count > 0) {
                append_skin_rows(field(source, "SkinIndices"), shape.view.vertex_count,
                                 shape.view.vertex_skin_count, shape.palette_indices,
                                 "shape.SkinIndices");
                append_weight_rows(field(source, "SkinWeights"), shape.view.vertex_count,
                                   shape.view.vertex_skin_count, shape.weights,
                                   "shape.SkinWeights");
            } else if (!array(field(source, "SkinIndices"), "shape.SkinIndices").empty() ||
                       !array(field(source, "SkinWeights"), "shape.SkinWeights").empty()) {
                fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                     "rigid BFRES shape carries skin arrays");
            }
            owner->shape_storage.push_back(std::move(shape));
        }

        for (const auto& value : array(field(*selected, "MatrixToBoneList"), "MatrixToBoneList")) {
            const auto index = integer(value, "MatrixToBoneList");
            if (index < 0 || index >= static_cast<std::int64_t>(bones.size())) {
                fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                     "matrix palette names an invalid bone");
            }
            owner->matrix_to_bone.push_back(static_cast<std::int32_t>(index));
        }
        const auto& inverse = array(field(*selected, "InverseModelMatrices"), "InverseModelMatrices");
        owner->inverse_bind.reserve(inverse.size() * 16);
        for (const auto& row_value : inverse) {
            const auto& row = array(row_value, "inverse bind matrix");
            if (row.size() != 12) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                                       "inverse bind matrix must contain 12 scalars");
            for (std::size_t index = 0; index < 12; ++index) owner->inverse_bind.push_back(number(row[index], "inverse bind matrix"));
            owner->inverse_bind.insert(owner->inverse_bind.end(), {0.0, 0.0, 0.0, 1.0});
        }
        if (inverse.size() > owner->matrix_to_bone.size()) {
            fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID,
                 "inverse bind count exceeds matrix palette count");
        }

        owner->finalize();
        auto [inserted, ok] = models.emplace(key, std::move(owner));
        if (!ok) fail(LTD_NATIVE_SCENE_CACHE_ADAPTER_INTERNAL_ERROR,
                      "model insertion race is unsupported");
        return *inserted->second;
    }
};

namespace {

template <typename Action>
ltd_native_scene_cache_adapter_status guarded(
    char* error, std::size_t error_capacity, Action&& action) noexcept {
    if (error != nullptr && error_capacity != 0) error[0] = '\0';
    try {
        action();
        return LTD_NATIVE_SCENE_CACHE_ADAPTER_OK;
    } catch (const Failure& failure) {
        write_error(error, error_capacity, failure.what());
        return failure.status;
    } catch (const native_runtime::DecodedAssetError& failure) {
        write_error(error, error_capacity,
                    std::string("decoded cache ") + failure.code() + ": " + failure.what());
        if (failure.code() == "DECODED_SOURCE_CHANGED") {
            return LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_CHANGED;
        }
        return LTD_NATIVE_SCENE_CACHE_ADAPTER_CACHE_FAILED;
    } catch (const std::bad_alloc&) {
        write_error(error, error_capacity, "scene cache adapter allocation failed");
        return LTD_NATIVE_SCENE_CACHE_ADAPTER_ALLOCATION_FAILED;
    } catch (const std::exception& failure) {
        write_error(error, error_capacity, failure.what());
        return LTD_NATIVE_SCENE_CACHE_ADAPTER_INTERNAL_ERROR;
    } catch (...) {
        write_error(error, error_capacity, "scene cache adapter failed unexpectedly");
        return LTD_NATIVE_SCENE_CACHE_ADAPTER_INTERNAL_ERROR;
    }
}

std::unique_ptr<ltd_native_scene_cache_adapter> make_adapter(
    std::filesystem::path model_root, PoseStorage pose,
    native_runtime::DecodedAssetCache* borrowed_cache) {
    auto result = std::make_unique<ltd_native_scene_cache_adapter>();
    result->model_root = canonical_existing(model_root, "model root", true);
    result->pose = std::move(pose);
    result->pose.finalize();
    if (borrowed_cache == nullptr) {
        result->owned_cache = std::make_unique<native_runtime::DecodedAssetCache>();
        result->cache = result->owned_cache.get();
    } else {
        result->cache = borrowed_cache;
    }
    return result;
}

}  // namespace

extern "C" {

uint32_t LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_abi_version(void) {
    return LTD_NATIVE_SCENE_CACHE_ADAPTER_ABI_VERSION;
}

const char* LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_contract_sha256(void) {
    return LTD_NATIVE_SCENE_CACHE_ADAPTER_CONTRACT_SHA256;
}

const char* LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_status_name(ltd_native_scene_cache_adapter_status status) {
    switch (status) {
    case LTD_NATIVE_SCENE_CACHE_ADAPTER_OK: return "OK";
    case LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
    case LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_MISSING: return "SOURCE_MISSING";
    case LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_CHANGED: return "SOURCE_CHANGED";
    case LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID: return "SOURCE_INVALID";
    case LTD_NATIVE_SCENE_CACHE_ADAPTER_CACHE_FAILED: return "CACHE_FAILED";
    case LTD_NATIVE_SCENE_CACHE_ADAPTER_ASSEMBLER_FAILED: return "ASSEMBLER_FAILED";
    case LTD_NATIVE_SCENE_CACHE_ADAPTER_RESOURCE_LIMIT: return "RESOURCE_LIMIT";
    case LTD_NATIVE_SCENE_CACHE_ADAPTER_ALLOCATION_FAILED: return "ALLOCATION_FAILED";
    case LTD_NATIVE_SCENE_CACHE_ADAPTER_INTERNAL_ERROR: return "INTERNAL_ERROR";
    default: return "UNKNOWN";
    }
}

int LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_activation_ready(void) {
    return 0;
}

ltd_native_scene_cache_adapter_status LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_create(
    const ltd_native_scene_cache_adapter_create_request* request,
    ltd_native_scene_cache_adapter** output,
    char* error,
    size_t error_capacity) {
    if (output != nullptr) *output = nullptr;
    if (request == nullptr || output == nullptr || request->model_root == nullptr ||
        request->icon_pose_path == nullptr) {
        write_error(error, error_capacity, "scene cache adapter create arguments are invalid");
        return LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT;
    }
    return guarded(error, error_capacity, [&] {
        const auto pose_path = canonical_existing(utf8_to_wide(request->icon_pose_path),
                                                  "IconPose");
        const auto pose_bytes = read_file(pose_path, kMaximumPoseBytes, "IconPose");
        auto result = make_adapter(utf8_to_wide(request->model_root),
                                   parse_pose(pose_bytes, sha256(pose_bytes)), nullptr);
        *output = result.release();
    });
}

void LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_destroy(ltd_native_scene_cache_adapter* adapter) {
    delete adapter;
}

ltd_native_scene_cache_adapter_status LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_assemble(
    ltd_native_scene_cache_adapter* adapter,
    const uint8_t* parts_catalog_bytes,
    size_t parts_catalog_byte_count,
    const uint8_t* parts_catalog_sha256,
    const uint8_t* raw_char_info,
    size_t raw_char_info_byte_count,
    uint32_t view_kind,
    uint32_t raster_size,
    ltd_native_scene_assembly** output,
    ltd_native_scene_assembler_status* assembler_status,
    char* error,
    size_t error_capacity) {
    if (output != nullptr) *output = nullptr;
    if (assembler_status != nullptr) *assembler_status = LTD_NATIVE_SCENE_ASSEMBLER_INVALID_ARGUMENT;
    if (adapter == nullptr || parts_catalog_bytes == nullptr || parts_catalog_byte_count == 0 ||
        parts_catalog_sha256 == nullptr || raw_char_info == nullptr ||
        raw_char_info_byte_count != 152 || output == nullptr || assembler_status == nullptr) {
        write_error(error, error_capacity, "scene cache adapter assemble arguments are invalid");
        return LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT;
    }
    ltd_native_scene_asset_provider provider{adapter, &ltd_native_scene_cache_adapter::get_model};
    ltd_native_scene_assemble_request request{};
    request.parts_catalog_bytes = parts_catalog_bytes;
    request.parts_catalog_byte_count = parts_catalog_byte_count;
    request.parts_catalog_sha256 = parts_catalog_sha256;
    request.raw_char_info = raw_char_info;
    request.raw_char_info_byte_count = raw_char_info_byte_count;
    request.assets = &provider;
    request.icon_pose = &adapter->pose.view;
    request.view_kind = view_kind;
    request.raster_size = raster_size;
    char assembler_error[512]{};
    *assembler_status = ltd_native_scene_assemble(
        &request, output, assembler_error, sizeof(assembler_error));
    if (*assembler_status != LTD_NATIVE_SCENE_ASSEMBLER_OK) {
        write_error(error, error_capacity, assembler_error[0] == '\0'
            ? ltd_native_scene_assembler_status_name(*assembler_status)
            : assembler_error);
        return LTD_NATIVE_SCENE_CACHE_ADAPTER_ASSEMBLER_FAILED;
    }
    if (error != nullptr && error_capacity != 0) error[0] = '\0';
    return LTD_NATIVE_SCENE_CACHE_ADAPTER_OK;
}

ltd_native_scene_cache_adapter_status LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_get_summary(
    const ltd_native_scene_cache_adapter* adapter,
    ltd_native_scene_cache_adapter_summary* output) {
    if (adapter == nullptr || output == nullptr) return LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT;
    *output = {};
    output->abi_version = LTD_NATIVE_SCENE_CACHE_ADAPTER_ABI_VERSION;
    output->cached_model_count = static_cast<std::uint32_t>(adapter->models.size());
    output->cached_obj_count = adapter->cache->obj_entry_count();
    output->resident_decoded_bytes = adapter->cache->resident_decoded_bytes();
    output->pose_source_seal_validated = 1;
    output->production_activation_ready = 0;
    return LTD_NATIVE_SCENE_CACHE_ADAPTER_OK;
}

ltd_native_scene_cache_adapter_status LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_get_model(
    ltd_native_scene_cache_adapter* adapter,
    const char* resource_name,
    const char* model_name,
    ltd_native_scene_model_view* output,
    char* error,
    size_t error_capacity) {
    if (output != nullptr) *output = {};
    if (adapter == nullptr || resource_name == nullptr || model_name == nullptr ||
        output == nullptr) {
        write_error(error, error_capacity, "scene cache model getter arguments are invalid");
        return LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT;
    }
    return guarded(error, error_capacity, [&] {
        *output = adapter->load_model(resource_name, model_name).view;
    });
}

}  // extern "C"

namespace native_runtime {

ltd_native_scene_cache_adapter_status create_borrowed_scene_cache_adapter(
    const char* model_root,
    DecodedAssetCache* cache,
    const ltd_native_scene_pose_view* icon_pose,
    ltd_native_scene_cache_adapter** output,
    char* error,
    size_t error_capacity) {
    if (output != nullptr) *output = nullptr;
    if (model_root == nullptr || cache == nullptr || icon_pose == nullptr || output == nullptr) {
        write_error(error, error_capacity, "borrowed scene cache adapter arguments are invalid");
        return LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT;
    }
    return guarded(error, error_capacity, [&] {
        auto result = make_adapter(utf8_to_wide(model_root), copy_pose(*icon_pose), cache);
        *output = result.release();
    });
}

}  // namespace native_runtime
