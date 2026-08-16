#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#define LTD_NATIVE_MATERIAL_PROVIDER_TRUSTED_INTERNAL
#include "native_material_provider.h"

#include "decoded_asset_cache.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace {

struct Failure final {
    ltd_native_material_provider_status status;
    std::string message;
};

[[noreturn]] void Fail(ltd_native_material_provider_status status,
                       std::string message) {
    throw Failure{status, std::move(message)};
}

void Error(char* output, std::size_t capacity, std::string_view message) {
    if (output == nullptr || capacity == 0) return;
    const std::size_t count = std::min(capacity - 1, message.size());
    std::memcpy(output, message.data(), count);
    output[count] = '\0';
}

bool Text(const char* value) {
    return value != nullptr && value[0] != '\0';
}

bool HexSeal(std::string_view value) {
    return value.size() == 64 &&
        std::all_of(value.begin(), value.end(), [](char byte) {
            return (byte >= '0' && byte <= '9') ||
                   (byte >= 'a' && byte <= 'f');
        });
}

std::array<std::uint8_t, 32> Sha256(std::span<const std::uint8_t> bytes) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED,
             "could not open SHA-256 provider");
    }
    const auto close = [&]() {
        if (hash != nullptr) BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
    };
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0) {
        close();
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED,
             "could not create SHA-256 hash");
    }
    std::size_t cursor = 0;
    while (cursor < bytes.size()) {
        const std::size_t count = std::min<std::size_t>(
            bytes.size() - cursor, std::numeric_limits<ULONG>::max());
        if (BCryptHashData(hash, const_cast<PUCHAR>(bytes.data() + cursor),
                           static_cast<ULONG>(count), 0) < 0) {
            close();
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED,
                 "could not update SHA-256 hash");
        }
        cursor += count;
    }
    std::array<std::uint8_t, 32> output{};
    if (BCryptFinishHash(hash, output.data(),
                         static_cast<ULONG>(output.size()), 0) < 0) {
        close();
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED,
             "could not finish SHA-256 hash");
    }
    close();
    return output;
}

std::string Hex(const std::array<std::uint8_t, 32>& digest) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(64);
    for (std::uint8_t byte : digest) {
        output.push_back(hex[byte >> 4]);
        output.push_back(hex[byte & 15]);
    }
    return output;
}

void Authenticate(std::string_view seal, std::span<const std::uint8_t> bytes,
                  std::string_view label) {
    if (!HexSeal(seal)) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
             std::string(label) + " has no lowercase SHA-256 seal");
    }
    if (Hex(Sha256(bytes)) != seal) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_SOURCE_MISMATCH,
             std::string(label) + " bytes differ from their SHA-256 seal");
    }
}

std::wstring Wide(std::string_view value) {
    if (value.empty() || value.size() >
            static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT,
             "UTF-8 key is empty or too long");
    }
    const int count = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (count <= 0) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT,
             "provider key is not valid UTF-8");
    }
    std::wstring output(static_cast<std::size_t>(count), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), output.data(), count) != count) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT,
             "provider key UTF-8 conversion changed length");
    }
    return output;
}

void U32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void U64(std::vector<std::uint8_t>& bytes, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
        bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void String(std::vector<std::uint8_t>& bytes, std::string_view value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
             "normalized material string is too long");
    }
    U32(bytes, static_cast<std::uint32_t>(value.size()));
    bytes.insert(bytes.end(), value.begin(), value.end());
}

void Double(std::vector<std::uint8_t>& bytes, double value) {
    U64(bytes, std::bit_cast<std::uint64_t>(value));
}

std::uint16_t ExpectedFamily(std::int32_t program) {
    switch (program) {
        case 324: case 336: case 348: return LTD_NATIVE_FAMILY_BODY;
        case 372: return LTD_NATIVE_FAMILY_EAR;
        case 756: return LTD_NATIVE_FAMILY_NOSE;
        case 0: return LTD_NATIVE_FAMILY_MASK;
        case 816: return LTD_NATIVE_FAMILY_HEAD;
        case 612: return LTD_NATIVE_FAMILY_HAIR_ANISOTROPIC;
        case 564: return LTD_NATIVE_FAMILY_HAIR_ENDPOINT;
        case 468: return LTD_NATIVE_FAMILY_BEARD_ANISOTROPIC;
        case 984: return LTD_NATIVE_FAMILY_OUTFIT_TOPS;
        case 936: return LTD_NATIVE_FAMILY_OUTFIT_BOTTOMS;
        case 912: return LTD_NATIVE_FAMILY_OUTFIT_SHOES;
        default:
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
                 "normalized material has an unsupported GameAll program");
    }
}

struct Artifact final {
    std::uint32_t role = 0;
    std::string logical_path;
    std::string sha256;
    std::vector<std::uint8_t> bytes;
    const std::uint8_t* borrowed_bytes = nullptr;
    std::size_t borrowed_byte_count = 0;

    [[nodiscard]] const std::uint8_t* data() const noexcept {
        return borrowed_bytes == nullptr ? bytes.data() : borrowed_bytes;
    }
    [[nodiscard]] std::size_t size() const noexcept {
        return borrowed_bytes == nullptr ? bytes.size() : borrowed_byte_count;
    }
};

struct TextureEntry final {
    std::string source_key;
    std::wstring cache_key;
    std::string texture_name;
    std::string authored_source_sha256;
    std::string manifest_sha256;
    std::vector<ltd_native_material_texture_level_view> levels;
    ltd_native_material_texture_chain_view view{};
};

struct MaterialEntry final {
    std::string source_key;
    std::string material_name;
    std::string model_key;
    std::string resource_name;
    std::string group;
    std::array<std::string, 10> texture_keys;
    std::array<std::string, 10> texture_source_sha256;
    std::array<std::string, 10> texture_manifest_sha256;
    std::vector<ltd_native_material_source_document> evidence;
    std::string normalized_sha256;
    ltd_native_normalized_material_view material{};
    ltd_native_material_normalized_view view{};
};

std::vector<std::uint8_t> CanonicalMaterial(const MaterialEntry& entry) {
    static constexpr char domain[] = "ltd.native.normalized-material.v1";
    std::vector<std::uint8_t> bytes(domain, domain + sizeof(domain) - 1);
    const auto& value = entry.material;
    String(bytes, entry.source_key);
    String(bytes, entry.material_name);
    String(bytes, entry.model_key);
    String(bytes, entry.resource_name);
    String(bytes, entry.group);
    U32(bytes, static_cast<std::uint32_t>(value.gameall_program));
    U32(bytes, value.family);
    U32(bytes, static_cast<std::uint16_t>(value.gsys_priority));
    U32(bytes, value.material_flags);
    const std::array<std::pair<const double*, std::size_t>, 8> vectors = {{
        {value.color_srgb, 4}, {value.body_face_color_linear, 3},
        {value.hair_primary_srgb, 3}, {value.hair_secondary_srgb, 3},
        {value.light_direction, 3}, {value.light_color, 3},
        {value.ambient_color, 3}, {value.camera_position, 3},
    }};
    for (const auto& [data, count] : vectors) {
        for (std::size_t index = 0; index < count; ++index) {
            Double(bytes, data[index]);
        }
    }
    const std::array<double, 14> scalars = {
        value.alpha_multiplier, value.alpha_cutoff, value.roughness,
        value.anisotropic_shift_scale, value.anisotropic_shift_offset,
        value.anisotropic_specular_size, value.anisotropic_toon_intensity,
        value.anisotropic_title_view_scale, value.anisotropic_radiance_scale,
        value.parallax_scale, value.light_intensity, value.ambient_intensity,
        value.light_normalization, value.flip_horizontal_sign,
    };
    for (double scalar : scalars) Double(bytes, scalar);
    bytes.push_back(value.has_camera_position);
    bytes.push_back(value.perspective_correct);
    bytes.push_back(value.mask_facepaint_mode);
    bytes.push_back(0);
    for (std::size_t role = 1; role < entry.texture_keys.size(); ++role) {
        String(bytes, entry.texture_keys[role]);
        String(bytes, entry.texture_source_sha256[role]);
        String(bytes, entry.texture_manifest_sha256[role]);
        bytes.push_back(value.texture_address_u[role]);
        bytes.push_back(value.texture_address_v[role]);
        bytes.push_back(value.texture_mip_filter[role]);
        bytes.push_back(value.texture_hardware_srgb[role]);
    }
    U32(bytes, static_cast<std::uint32_t>(entry.evidence.size()));
    for (const auto& evidence : entry.evidence) {
        U32(bytes, evidence.role);
        String(bytes, evidence.logical_path);
        String(bytes, evidence.sha256);
    }
    return bytes;
}

void ValidateFinite(const ltd_native_normalized_material_view& value) {
    const std::array<std::pair<const double*, std::size_t>, 8> vectors = {{
        {value.color_srgb, 4}, {value.body_face_color_linear, 3},
        {value.hair_primary_srgb, 3}, {value.hair_secondary_srgb, 3},
        {value.light_direction, 3}, {value.light_color, 3},
        {value.ambient_color, 3}, {value.camera_position, 3},
    }};
    for (const auto& [data, count] : vectors) {
        for (std::size_t index = 0; index < count; ++index) {
            if (!std::isfinite(data[index])) {
                Fail(LTD_NATIVE_MATERIAL_PROVIDER_NONFINITE,
                     "normalized material vector is nonfinite");
            }
        }
    }
    const std::array<double, 14> scalars = {
        value.alpha_multiplier, value.alpha_cutoff, value.roughness,
        value.anisotropic_shift_scale, value.anisotropic_shift_offset,
        value.anisotropic_specular_size, value.anisotropic_toon_intensity,
        value.anisotropic_title_view_scale, value.anisotropic_radiance_scale,
        value.parallax_scale, value.light_intensity, value.ambient_intensity,
        value.light_normalization, value.flip_horizontal_sign,
    };
    if (!std::all_of(scalars.begin(), scalars.end(), [](double item) {
            return std::isfinite(item);
        })) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_NONFINITE,
             "normalized material scalar is nonfinite");
    }
}

}  // namespace

struct ltd_native_material_provider {
    std::unique_ptr<native_runtime::DecodedAssetCache> owned_cache;
    native_runtime::DecodedAssetCache* cache = nullptr;
    std::map<std::string, Artifact, std::less<>> artifacts;
    std::map<std::string, TextureEntry, std::less<>> textures;
    std::map<std::string, MaterialEntry, std::less<>> materials;
    void* trusted_lease = nullptr;
    ltd_native_material_trusted_release_fn trusted_release = nullptr;
    bool trusted_publication_active = false;

    ltd_native_material_provider()
        : owned_cache(std::make_unique<native_runtime::DecodedAssetCache>()),
          cache(owned_cache.get()) {}

    explicit ltd_native_material_provider(
        native_runtime::DecodedAssetCache& borrowed_cache) noexcept
        : cache(&borrowed_cache) {}

    ~ltd_native_material_provider() {
        materials.clear();
        textures.clear();
        artifacts.clear();
        if (trusted_lease != nullptr && trusted_release != nullptr) {
            trusted_release(trusted_lease);
        }
    }
};

namespace {

std::string ArtifactKey(std::uint32_t role, std::string_view path,
                        std::string_view sha256) {
    return std::to_string(role) + "\n" + std::string(path) + "\n" +
           std::string(sha256);
}

const Artifact& InternArtifact(ltd_native_material_provider& provider,
                               const ltd_native_material_source_document& source) {
    if (source.role < LTD_NATIVE_MATERIAL_EVIDENCE_BFRES_CATALOG ||
        source.role > LTD_NATIVE_MATERIAL_EVIDENCE_NORMALIZATION_SOURCE ||
        source.reserved != 0 || !Text(source.logical_path) ||
        !Text(source.sha256) ||
        (source.byte_count != 0 && source.bytes == nullptr)) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
             "material evidence record is malformed");
    }
    const std::span<const std::uint8_t> bytes(source.bytes, source.byte_count);
    if (!provider.trusted_publication_active) {
        Authenticate(source.sha256, bytes, source.logical_path);
    } else if (!HexSeal(source.sha256)) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
             "trusted material evidence has no lowercase SHA-256 seal");
    }
    const std::string key = ArtifactKey(
        source.role, source.logical_path, source.sha256);
    const auto found = provider.artifacts.find(key);
    if (found != provider.artifacts.end()) {
        if (found->second.size() != source.byte_count) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_SOURCE_MISMATCH,
                 "material evidence byte count changed for a resident identity");
        }
        return found->second;
    }
    Artifact artifact;
    artifact.role = source.role;
    artifact.logical_path = source.logical_path;
    artifact.sha256 = source.sha256;
    if (provider.trusted_publication_active) {
        artifact.borrowed_bytes = source.bytes;
        artifact.borrowed_byte_count = source.byte_count;
    } else {
        artifact.bytes.assign(bytes.begin(), bytes.end());
    }
    return provider.artifacts.emplace(key, std::move(artifact)).first->second;
}

int LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL TextureCallback(
    void* context, const char* source_key,
    const char* authored_source_sha256, const char* manifest_sha256,
    ltd_native_material_texture_chain_view* output, char* error,
    std::size_t error_capacity) {
    Error(error, error_capacity, "");
    if (context == nullptr || output == nullptr || !Text(source_key) ||
        !Text(authored_source_sha256) || !Text(manifest_sha256)) {
        Error(error, error_capacity, "material texture callback arguments are invalid");
        return 0;
    }
    const auto& provider =
        *static_cast<const ltd_native_material_provider*>(context);
    const auto found = provider.textures.find(source_key);
    if (found == provider.textures.end()) {
        Error(error, error_capacity, "material texture key is not resident");
        return 0;
    }
    const TextureEntry& entry = found->second;
    if (entry.authored_source_sha256 != authored_source_sha256 ||
        entry.manifest_sha256 != manifest_sha256) {
        Error(error, error_capacity, "material texture source seal changed");
        return 0;
    }
    *output = entry.view;
    return 1;
}

std::array<std::uint8_t, 32> ParseDigest(std::string_view value,
                                         std::string_view label) {
    if (!HexSeal(value)) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
             std::string(label) + " has no lowercase SHA-256 seal");
    }
    const auto nibble = [](char value) -> std::uint8_t {
        return value <= '9' ? static_cast<std::uint8_t>(value - '0')
                            : static_cast<std::uint8_t>(value - 'a' + 10);
    };
    std::array<std::uint8_t, 32> output{};
    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] = static_cast<std::uint8_t>(
            (nibble(value[index * 2]) << 4) | nibble(value[index * 2 + 1]));
    }
    return output;
}

TextureEntry TrustedTexture(
    native_runtime::DecodedAssetCache& cache,
    const ltd_native_material_mip_chain_source& source) {
    if (!Text(source.source_key) || !Text(source.texture_name) ||
        !Text(source.source_format) || !Text(source.authored_source_sha256) ||
        !Text(source.manifest_sha256) || source.level_count == 0 ||
        source.levels == nullptr ||
        (source.color_space != LTD_NATIVE_MATERIAL_TEXTURE_LINEAR &&
         source.color_space != LTD_NATIVE_MATERIAL_TEXTURE_SRGB)) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
             "trusted material mip-chain source is incomplete");
    }
    ParseDigest(source.authored_source_sha256, "trusted authored source");
    ParseDigest(source.manifest_sha256, "trusted mip manifest");
    const std::wstring cache_key = Wide(source.source_key);
    const auto decoded = cache.get_texture_mip_chain(
        cache_key, source.manifest_sha256, source.authored_source_sha256);
    if (decoded.texture_name != source.texture_name ||
        decoded.source_format != source.source_format ||
        decoded.levels.size() != source.level_count ||
        static_cast<std::uint32_t>(decoded.color_space) != source.color_space) {
        Fail(LTD_NATIVE_MATERIAL_PROVIDER_SOURCE_MISMATCH,
             "trusted material mip-chain identity differs from its cache entry");
    }
    TextureEntry entry;
    entry.source_key = source.source_key;
    entry.cache_key = cache_key;
    entry.texture_name = source.texture_name;
    entry.authored_source_sha256 = source.authored_source_sha256;
    entry.manifest_sha256 = source.manifest_sha256;
    entry.levels.reserve(decoded.levels.size());
    for (std::size_t index = 0; index < decoded.levels.size(); ++index) {
        const auto& expected = source.levels[index];
        const auto& level = decoded.levels[index];
        if (expected.level != index || expected.reserved != 0 ||
            !Text(expected.canonical_key) || !Text(expected.source_sha256) ||
            expected.source_bytes == nullptr || expected.source_byte_count == 0 ||
            expected.width != level.width || expected.height != level.height ||
            level.level != index || level.source_sha256 != expected.source_sha256) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_SOURCE_MISMATCH,
                 "trusted material mip level differs from its cache entry");
        }
        ParseDigest(expected.source_sha256, "trusted mip level");
        entry.levels.push_back(ltd_native_material_texture_level_view{
            level.rgba8.data(), level.rgba8.size(), level.rgba64.data(),
            level.rgba64.size(), level.sampled_rgba64.data(),
            level.sampled_rgba64.size(), level.width, level.height,
            level.source_sha256.data(), level.rgba8_sha256.data(),
            level.rgba64_sha256.data(), level.sampled_rgba64_sha256.data()});
    }
    entry.view = ltd_native_material_texture_chain_view{
        entry.source_key.c_str(), entry.authored_source_sha256.c_str(),
        entry.manifest_sha256.c_str(),
        decoded.metadata->decoded_chain_sha256.c_str(),
        decoded.metadata->rgba8_chain_sha256.c_str(),
        decoded.metadata->rgba64_chain_sha256.c_str(),
        decoded.metadata->sampled_rgba64_chain_sha256.c_str(),
        source.color_space, entry.levels.data(),
        static_cast<std::uint32_t>(entry.levels.size())};
    return entry;
}

std::string TrustedPublicationDigest(
    const ltd_native_material_provider& provider,
    const ltd_native_material_trusted_bundle& bundle) {
    static constexpr char domain[] =
        "ltd.native.runtime-material-publications.v1\0";
    std::vector<std::uint8_t> bytes(domain, domain + sizeof(domain) - 1);
    U32(bytes, bundle.material_count);
    for (std::uint32_t index = 0; index < bundle.material_count; ++index) {
        U32(bytes, bundle.scene_draw_indices[index]);
        const auto found = provider.materials.find(
            bundle.materials[index].source_key);
        if (found == provider.materials.end()) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_NOT_FOUND,
                 "trusted material publication was not resident");
        }
        const auto digest = ParseDigest(
            found->second.normalized_sha256, "trusted normalized material");
        bytes.insert(bytes.end(), digest.begin(), digest.end());
    }
    return Hex(Sha256(bytes));
}

}  // namespace

extern "C" {

uint32_t LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_abi_version(void) {
    return LTD_NATIVE_MATERIAL_PROVIDER_ABI_VERSION;
}

const char* LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_contract_sha256(void) {
    return LTD_NATIVE_MATERIAL_PROVIDER_CONTRACT_SHA256;
}

const char* LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_status_name(
    ltd_native_material_provider_status status) {
    switch (status) {
        case LTD_NATIVE_MATERIAL_PROVIDER_OK: return "ok";
        case LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT: return "invalid_argument";
        case LTD_NATIVE_MATERIAL_PROVIDER_SOURCE_MISMATCH: return "source_mismatch";
        case LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH: return "schema_mismatch";
        case LTD_NATIVE_MATERIAL_PROVIDER_DUPLICATE: return "duplicate";
        case LTD_NATIVE_MATERIAL_PROVIDER_NOT_FOUND: return "not_found";
        case LTD_NATIVE_MATERIAL_PROVIDER_COLOR_SPACE_MISMATCH:
            return "color_space_mismatch";
        case LTD_NATIVE_MATERIAL_PROVIDER_NONFINITE: return "nonfinite";
        case LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED: return "cache_failed";
        case LTD_NATIVE_MATERIAL_PROVIDER_ALLOCATION_FAILED:
            return "allocation_failed";
        default: return "unknown";
    }
}

ltd_native_material_provider_status LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_create(ltd_native_material_provider** output,
                                    char* error,
                                    size_t error_capacity) {
    if (output == nullptr) return LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT;
    *output = nullptr;
    Error(error, error_capacity, "");
    try {
        *output = new ltd_native_material_provider();
        return LTD_NATIVE_MATERIAL_PROVIDER_OK;
    } catch (const Failure& failure) {
        Error(error, error_capacity, failure.message);
        return failure.status;
    } catch (const std::bad_alloc&) {
        Error(error, error_capacity, "material provider allocation failed");
        return LTD_NATIVE_MATERIAL_PROVIDER_ALLOCATION_FAILED;
    } catch (const std::exception& exception) {
        Error(error, error_capacity, exception.what());
        return LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED;
    }
}

ltd_native_material_provider_status LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_create_with_borrowed_cache(
    ltd_native_decoded_asset_cache* cache,
    ltd_native_material_provider** output,
    char* error,
    size_t error_capacity) {
    if (output == nullptr) return LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT;
    *output = nullptr;
    Error(error, error_capacity, "");
    if (cache == nullptr) {
        Error(error, error_capacity, "borrowed decoded-asset cache is required");
        return LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT;
    }
    try {
        *output = new ltd_native_material_provider(*cache);
        return LTD_NATIVE_MATERIAL_PROVIDER_OK;
    } catch (const std::bad_alloc&) {
        Error(error, error_capacity, "material provider allocation failed");
        return LTD_NATIVE_MATERIAL_PROVIDER_ALLOCATION_FAILED;
    } catch (const std::exception& exception) {
        Error(error, error_capacity, exception.what());
        return LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED;
    }
}

void LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_destroy(ltd_native_material_provider* provider) {
    delete provider;
}

ltd_native_material_provider_status LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_publish_mip_chain(
    ltd_native_material_provider* provider,
    const ltd_native_material_mip_chain_source* source,
    char* error, size_t error_capacity) {
    Error(error, error_capacity, "");
    try {
        if (provider == nullptr || source == nullptr || !Text(source->source_key) ||
            !Text(source->texture_name) || !Text(source->source_format) ||
            !Text(source->authored_source_sha256) ||
            source->authored_source_bytes == nullptr ||
            source->authored_source_byte_count == 0 ||
            !Text(source->manifest_sha256) || source->manifest_bytes == nullptr ||
            source->manifest_byte_count == 0 || source->level_count == 0 ||
            source->levels == nullptr) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT,
                 "material mip-chain source is incomplete");
        }
        if (source->color_space != LTD_NATIVE_MATERIAL_TEXTURE_LINEAR &&
            source->color_space != LTD_NATIVE_MATERIAL_TEXTURE_SRGB) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_COLOR_SPACE_MISMATCH,
                 "material mip-chain color-space identity is unsupported");
        }
        std::vector<native_runtime::DecodedTextureMipSource> levels;
        levels.reserve(source->level_count);
        for (std::uint32_t index = 0; index < source->level_count; ++index) {
            const auto& item = source->levels[index];
            if (item.level != index || item.reserved != 0 ||
                !Text(item.canonical_key) || !Text(item.source_sha256) ||
                item.source_bytes == nullptr || item.source_byte_count == 0) {
                Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
                     "material mip level is incomplete or out of order");
            }
            levels.push_back(native_runtime::DecodedTextureMipSource{
                item.level,
                item.width,
                item.height,
                Wide(item.canonical_key),
                item.source_sha256,
                std::span<const std::uint8_t>(
                    item.source_bytes, item.source_byte_count),
            });
        }
        const std::wstring cache_key = Wide(source->source_key);
        native_runtime::DecodedTextureMipChainSource cache_source{
            source->texture_name,
            source->source_format,
            source->authored_source_sha256,
            std::span<const std::uint8_t>(
                source->authored_source_bytes,
                source->authored_source_byte_count),
            source->manifest_sha256,
            std::span<const std::uint8_t>(
                source->manifest_bytes, source->manifest_byte_count),
            source->color_space == LTD_NATIVE_MATERIAL_TEXTURE_SRGB
                ? native_runtime::DecodedTextureColorSpace::kSrgb
                : native_runtime::DecodedTextureColorSpace::kLinear,
            levels,
        };
        provider->cache->decode_texture_mip_chain(cache_key, cache_source);
        const auto decoded = provider->cache->get_texture_mip_chain(
            cache_key, source->manifest_sha256,
            source->authored_source_sha256);

        const auto present = provider->textures.find(source->source_key);
        if (present != provider->textures.end()) {
            const TextureEntry& entry = present->second;
            if (entry.texture_name != source->texture_name ||
                entry.authored_source_sha256 != source->authored_source_sha256 ||
                entry.manifest_sha256 != source->manifest_sha256 ||
                entry.levels.size() != source->level_count) {
                Fail(LTD_NATIVE_MATERIAL_PROVIDER_DUPLICATE,
                     "material texture key was republished with another identity");
            }
            return LTD_NATIVE_MATERIAL_PROVIDER_OK;
        }

        TextureEntry entry;
        entry.source_key = source->source_key;
        entry.cache_key = cache_key;
        entry.texture_name = source->texture_name;
        entry.authored_source_sha256 = source->authored_source_sha256;
        entry.manifest_sha256 = source->manifest_sha256;
        entry.levels.reserve(decoded.levels.size());
        for (const auto& level : decoded.levels) {
            entry.levels.push_back(ltd_native_material_texture_level_view{
                level.rgba8.data(),
                level.rgba8.size(),
                level.rgba64.data(),
                level.rgba64.size(),
                level.sampled_rgba64.data(),
                level.sampled_rgba64.size(),
                level.width,
                level.height,
                level.source_sha256.data(),
                level.rgba8_sha256.data(),
                level.rgba64_sha256.data(),
                level.sampled_rgba64_sha256.data(),
            });
        }
        entry.view = ltd_native_material_texture_chain_view{
            entry.source_key.c_str(),
            entry.authored_source_sha256.c_str(),
            entry.manifest_sha256.c_str(),
            decoded.metadata->decoded_chain_sha256.c_str(),
            decoded.metadata->rgba8_chain_sha256.c_str(),
            decoded.metadata->rgba64_chain_sha256.c_str(),
            decoded.metadata->sampled_rgba64_chain_sha256.c_str(),
            source->color_space,
            entry.levels.data(),
            static_cast<std::uint32_t>(entry.levels.size()),
        };
        auto [inserted, unused] = provider->textures.emplace(
            entry.source_key, std::move(entry));
        (void)unused;
        /* Moving strings into a map node may change small-string pointers. */
        inserted->second.view.source_key = inserted->second.source_key.c_str();
        inserted->second.view.authored_source_sha256 =
            inserted->second.authored_source_sha256.c_str();
        inserted->second.view.manifest_sha256 =
            inserted->second.manifest_sha256.c_str();
        inserted->second.view.levels = inserted->second.levels.data();
        return LTD_NATIVE_MATERIAL_PROVIDER_OK;
    } catch (const Failure& failure) {
        Error(error, error_capacity, failure.message);
        return failure.status;
    } catch (const native_runtime::DecodedAssetError& failure) {
        Error(error, error_capacity, failure.what());
        return failure.code() == "DECODED_TEXTURE_COLOR_SPACE"
            ? LTD_NATIVE_MATERIAL_PROVIDER_COLOR_SPACE_MISMATCH
            : LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED;
    } catch (const std::bad_alloc&) {
        Error(error, error_capacity, "material mip-chain allocation failed");
        return LTD_NATIVE_MATERIAL_PROVIDER_ALLOCATION_FAILED;
    } catch (const std::exception& exception) {
        Error(error, error_capacity, exception.what());
        return LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED;
    }
}

ltd_native_material_provider_status LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_publish_material(
    ltd_native_material_provider* provider,
    const ltd_native_material_normalized_source* source,
    char* error, size_t error_capacity) {
    Error(error, error_capacity, "");
    try {
        if (provider == nullptr || source == nullptr ||
            !Text(source->source_key) || !Text(source->material_name) ||
            source->material == nullptr || source->evidence == nullptr ||
            source->evidence_count < 2) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT,
                 "normalized material source is incomplete");
        }
        const auto& value = *source->material;
        if (!Text(value.model_key) || !Text(value.resource_name) ||
            !Text(value.group) || value.family != ExpectedFamily(value.gameall_program) ||
            value.has_camera_position > 1 || value.perspective_correct > 1 ||
            value.mask_facepaint_mode > 1 || value.reserved0 != 0 ||
            value.light_normalization == 0.0) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
                 "normalized material identity/flags changed");
        }
        ValidateFinite(value);
        if (provider->materials.contains(source->source_key)) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_DUPLICATE,
                 "normalized material key was published more than once");
        }

        MaterialEntry entry;
        entry.source_key = source->source_key;
        entry.material_name = source->material_name;
        entry.model_key = value.model_key;
        entry.resource_name = value.resource_name;
        entry.group = value.group;
        entry.material = value;
        entry.material.model_key = entry.model_key.c_str();
        entry.material.resource_name = entry.resource_name.c_str();
        entry.material.group = entry.group.c_str();
        for (std::size_t role = 0; role < entry.texture_keys.size(); ++role) {
            const char* key = value.texture_keys[role];
            const char* authored = value.texture_source_sha256[role];
            const char* manifest = value.texture_manifest_sha256[role];
            const bool any = key != nullptr || authored != nullptr || manifest != nullptr;
            if (role == 0 && any) {
                Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
                     "texture role zero must remain empty");
            }
            if (!any) {
                if (value.texture_address_u[role] != 0 ||
                    value.texture_address_v[role] != 0 ||
                    value.texture_mip_filter[role] != 0 ||
                    value.texture_hardware_srgb[role] != 0) {
                    Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
                         "unbound texture role carries sampler state");
                }
                continue;
            }
            if (!Text(key) || !Text(authored) || !Text(manifest) ||
                !HexSeal(authored) || !HexSeal(manifest)) {
                Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
                     "normalized material texture binding is incomplete");
            }
            if (value.texture_address_u[role] > LTD_NATIVE_ADDRESS_MIRROR ||
                value.texture_address_v[role] > LTD_NATIVE_ADDRESS_MIRROR ||
                value.texture_mip_filter[role] > LTD_NATIVE_MIP_LINEAR ||
                value.texture_hardware_srgb[role] > 1) {
                Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
                     "normalized material sampler state is unsupported");
            }
            const auto texture = provider->textures.find(key);
            if (texture == provider->textures.end() ||
                texture->second.authored_source_sha256 != authored ||
                texture->second.manifest_sha256 != manifest) {
                Fail(LTD_NATIVE_MATERIAL_PROVIDER_NOT_FOUND,
                     "normalized material references a nonresident texture chain");
            }
            entry.texture_keys[role] = key;
            entry.texture_source_sha256[role] = authored;
            entry.texture_manifest_sha256[role] = manifest;
        }

        std::array<bool, 6> evidence_roles{};
        entry.evidence.reserve(source->evidence_count);
        for (std::uint32_t index = 0; index < source->evidence_count; ++index) {
            const Artifact& artifact = InternArtifact(*provider, source->evidence[index]);
            if (evidence_roles[artifact.role]) {
                Fail(LTD_NATIVE_MATERIAL_PROVIDER_DUPLICATE,
                     "normalized material repeats an evidence role");
            }
            evidence_roles[artifact.role] = true;
            entry.evidence.push_back(ltd_native_material_source_document{
                artifact.role,
                0,
                artifact.logical_path.c_str(),
                artifact.sha256.c_str(),
                artifact.data(),
                artifact.size(),
            });
        }
        if (!evidence_roles[LTD_NATIVE_MATERIAL_EVIDENCE_BFRES_CATALOG] ||
            !evidence_roles[LTD_NATIVE_MATERIAL_EVIDENCE_MATERIAL_STATE]) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH,
                 "normalized material lacks BFRES catalog/material-state evidence");
        }
        for (std::size_t role = 0; role < entry.texture_keys.size(); ++role) {
            entry.material.texture_keys[role] = entry.texture_keys[role].empty()
                ? nullptr : entry.texture_keys[role].c_str();
            entry.material.texture_source_sha256[role] =
                entry.texture_source_sha256[role].empty()
                ? nullptr : entry.texture_source_sha256[role].c_str();
            entry.material.texture_manifest_sha256[role] =
                entry.texture_manifest_sha256[role].empty()
                ? nullptr : entry.texture_manifest_sha256[role].c_str();
        }
        entry.normalized_sha256 = Hex(Sha256(CanonicalMaterial(entry)));
        entry.view = ltd_native_material_normalized_view{
            entry.source_key.c_str(),
            entry.material_name.c_str(),
            entry.normalized_sha256.c_str(),
            &entry.material,
            entry.evidence.data(),
            static_cast<std::uint32_t>(entry.evidence.size()),
        };
        auto [inserted, unused] = provider->materials.emplace(
            entry.source_key, std::move(entry));
        (void)unused;
        MaterialEntry& stored = inserted->second;
        stored.material.model_key = stored.model_key.c_str();
        stored.material.resource_name = stored.resource_name.c_str();
        stored.material.group = stored.group.c_str();
        for (std::size_t role = 0; role < stored.texture_keys.size(); ++role) {
            stored.material.texture_keys[role] = stored.texture_keys[role].empty()
                ? nullptr : stored.texture_keys[role].c_str();
            stored.material.texture_source_sha256[role] =
                stored.texture_source_sha256[role].empty()
                ? nullptr : stored.texture_source_sha256[role].c_str();
            stored.material.texture_manifest_sha256[role] =
                stored.texture_manifest_sha256[role].empty()
                ? nullptr : stored.texture_manifest_sha256[role].c_str();
        }
        stored.view.source_key = stored.source_key.c_str();
        stored.view.material_name = stored.material_name.c_str();
        stored.view.normalized_sha256 = stored.normalized_sha256.c_str();
        stored.view.material = &stored.material;
        stored.view.evidence = stored.evidence.data();
        return LTD_NATIVE_MATERIAL_PROVIDER_OK;
    } catch (const Failure& failure) {
        Error(error, error_capacity, failure.message);
        return failure.status;
    } catch (const std::bad_alloc&) {
        Error(error, error_capacity, "normalized material allocation failed");
        return LTD_NATIVE_MATERIAL_PROVIDER_ALLOCATION_FAILED;
    } catch (const std::exception& exception) {
        Error(error, error_capacity, exception.what());
        return LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED;
    }
}

ltd_native_material_provider_status LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_publish_trusted_bundle(
    ltd_native_material_provider* provider,
    const ltd_native_material_trusted_bundle* bundle,
    char* error, size_t error_capacity) {
    Error(error, error_capacity, "");
    try {
        static constexpr std::string_view kTrustedAdapterContract =
            "225c87ceb0042d45ced4e84d3b1e0af4f12d8a0411f3a3a03a9c12e9ebfd4769";
        if (provider == nullptr || bundle == nullptr || bundle->abi_version != 1 ||
            bundle->reserved != 0 || !Text(bundle->producer_contract_sha256) ||
            std::string_view(bundle->producer_contract_sha256) !=
                kTrustedAdapterContract ||
            bundle->decoded_cache == nullptr ||
            provider->owned_cache != nullptr ||
            provider->cache != bundle->decoded_cache ||
            !Text(bundle->catalog_sha256) || !Text(bundle->source_bundle_sha256) ||
            !Text(bundle->publication_sha256) || !Text(bundle->share_mii_sha256) ||
            !Text(bundle->effective_char_info_sha256) ||
            bundle->view_kind < 1 || bundle->view_kind > 2 ||
            (bundle->raster_size != 128 && bundle->raster_size != 512) ||
            bundle->mip_chain_count == 0 || bundle->mip_chains == nullptr ||
            bundle->material_count == 0 ||
            bundle->material_count > LTD_NATIVE_MATERIAL_SCHEDULE_MAX_DRAWS ||
            bundle->materials == nullptr || bundle->scene_draw_indices == nullptr ||
            bundle->lease_context == nullptr || bundle->authenticate == nullptr ||
            bundle->retain == nullptr || bundle->release == nullptr) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT,
                 "trusted material bundle/provider identity is invalid");
        }
        ParseDigest(bundle->catalog_sha256, "trusted material catalog");
        ParseDigest(bundle->source_bundle_sha256, "trusted source bundle");
        ParseDigest(bundle->publication_sha256, "trusted publication");
        ParseDigest(bundle->share_mii_sha256, "trusted LTD source");
        ParseDigest(bundle->effective_char_info_sha256,
                    "trusted effective CharInfo");
        if (!provider->textures.empty() || !provider->materials.empty() ||
            !provider->artifacts.empty() || provider->trusted_lease != nullptr) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_DUPLICATE,
                 "trusted publication requires a fresh borrowed-cache provider");
        }
        if (bundle->authenticate(bundle->lease_context, bundle) == 0) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_SOURCE_MISMATCH,
                 "trusted material bundle producer rejected its opaque view");
        }

        auto candidate = std::make_unique<ltd_native_material_provider>(
            *provider->cache);
        std::map<std::uint32_t, bool> scene_indices;
        for (std::uint32_t index = 0; index < bundle->mip_chain_count; ++index) {
            TextureEntry entry = TrustedTexture(*candidate->cache,
                                                bundle->mip_chains[index]);
            auto [inserted, unique] = candidate->textures.emplace(
                entry.source_key, std::move(entry));
            if (!unique) {
                Fail(LTD_NATIVE_MATERIAL_PROVIDER_DUPLICATE,
                     "trusted material bundle repeats a mip-chain key");
            }
            auto& stored = inserted->second;
            stored.view.source_key = stored.source_key.c_str();
            stored.view.authored_source_sha256 =
                stored.authored_source_sha256.c_str();
            stored.view.manifest_sha256 = stored.manifest_sha256.c_str();
            stored.view.levels = stored.levels.data();
        }
        candidate->trusted_publication_active = true;
        std::array<char, 512> detail{};
        for (std::uint32_t index = 0; index < bundle->material_count; ++index) {
            if (!scene_indices.emplace(bundle->scene_draw_indices[index], true).second) {
                Fail(LTD_NATIVE_MATERIAL_PROVIDER_DUPLICATE,
                     "trusted material bundle repeats a scene draw index");
            }
            const auto status = ltd_native_material_provider_publish_material(
                candidate.get(), &bundle->materials[index], detail.data(),
                detail.size());
            if (status != LTD_NATIVE_MATERIAL_PROVIDER_OK) {
                Fail(status, detail[0] == '\0'
                    ? "trusted normalized material publication failed"
                    : detail.data());
            }
        }
        candidate->trusted_publication_active = false;
        if (TrustedPublicationDigest(*candidate, *bundle) !=
            bundle->publication_sha256) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_SOURCE_MISMATCH,
                 "trusted material publication/draw binding digest differs");
        }
        void* lease = bundle->retain(bundle->lease_context);
        if (lease == nullptr) {
            Fail(LTD_NATIVE_MATERIAL_PROVIDER_ALLOCATION_FAILED,
                 "trusted material bundle lease allocation failed");
        }
        provider->textures.swap(candidate->textures);
        provider->materials.swap(candidate->materials);
        provider->artifacts.swap(candidate->artifacts);
        provider->trusted_lease = lease;
        provider->trusted_release = bundle->release;
        return LTD_NATIVE_MATERIAL_PROVIDER_OK;
    } catch (const Failure& failure) {
        Error(error, error_capacity, failure.message);
        return failure.status;
    } catch (const native_runtime::DecodedAssetError& failure) {
        Error(error, error_capacity, failure.what());
        return LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED;
    } catch (const std::bad_alloc&) {
        Error(error, error_capacity, "trusted material publication allocation failed");
        return LTD_NATIVE_MATERIAL_PROVIDER_ALLOCATION_FAILED;
    } catch (const std::exception& exception) {
        Error(error, error_capacity, exception.what());
        return LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED;
    }
}

ltd_native_material_provider_status LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_get_material(
    const ltd_native_material_provider* provider, const char* source_key,
    ltd_native_material_normalized_view* output,
    char* error, size_t error_capacity) {
    Error(error, error_capacity, "");
    if (provider == nullptr || !Text(source_key) || output == nullptr) {
        Error(error, error_capacity, "material lookup arguments are invalid");
        return LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT;
    }
    const auto found = provider->materials.find(source_key);
    if (found == provider->materials.end()) {
        Error(error, error_capacity, "normalized material key is not resident");
        return LTD_NATIVE_MATERIAL_PROVIDER_NOT_FOUND;
    }
    *output = found->second.view;
    return LTD_NATIVE_MATERIAL_PROVIDER_OK;
}

ltd_native_material_provider_status LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_texture_callback(
    ltd_native_material_provider* provider,
    ltd_native_material_texture_provider* output) {
    if (provider == nullptr || output == nullptr) {
        return LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT;
    }
    output->context = provider;
    output->get_texture_chain = TextureCallback;
    return LTD_NATIVE_MATERIAL_PROVIDER_OK;
}

}  // extern "C"
