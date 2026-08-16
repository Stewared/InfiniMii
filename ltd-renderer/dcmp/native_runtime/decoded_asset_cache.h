#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace native_runtime {

class DecodedAssetError final : public std::runtime_error {
public:
    DecodedAssetError(std::string code, std::string message)
        : std::runtime_error(std::move(message)), code_(std::move(code)) {}
    [[nodiscard]] const std::string& code() const noexcept { return code_; }

private:
    std::string code_;
};

struct DecodedObjTriangle final {
    std::string group;
    std::int64_t vertex[3]{};
    std::int64_t texcoord[3]{-1, -1, -1};
    std::int64_t normal[3]{-1, -1, -1};
};

struct DecodedObjMesh final {
    std::vector<double> positions;
    std::vector<double> texcoords;
    std::vector<double> normals;
    std::vector<DecodedObjTriangle> triangles;
};

struct DecodedObjMetadata final {
    std::uint64_t position_count = 0;
    std::uint64_t texcoord_count = 0;
    std::uint64_t normal_count = 0;
    std::uint64_t triangle_count = 0;
    std::map<std::string, std::uint64_t, std::less<>> group_triangle_counts;
    std::string positions_sha256;
    std::string texcoords_sha256;
    std::string normals_sha256;
    std::string topology_sha256;
    std::string decoded_sha256;
    std::uint64_t named_uv_channel_count = 0;
    std::map<std::string, std::uint64_t, std::less<>> named_uv_coverage_counts;
    std::map<std::string, std::string, std::less<>> named_uv_sha256;
    std::string named_uv_decoded_sha256;
};

struct DecodedObjResult final {
    const DecodedObjMesh* mesh = nullptr;
    const DecodedObjMetadata* metadata = nullptr;
    bool cache_hit = false;
};

// Immutable views are published by DecodedAssetCache::get/find. Their
// pointers, spans, and string_views remain valid until the owning cache is
// destroyed. The cache never evicts entries. Publishing an OBJ freezes its
// named-UV attachment state; a first attachment after publication fails
// closed, while reattaching the already-sealed sidecar remains idempotent.
struct DecodedNamedUvChannelView final {
    std::string_view name;
    std::span<const double> values;
    std::uint64_t coverage_count = 0;
    std::string_view sha256;
};

struct DecodedObjView final {
    const DecodedObjMesh* mesh = nullptr;
    const DecodedObjMetadata* metadata = nullptr;
    std::span<const DecodedNamedUvChannelView> named_uv_channels;
    std::string_view source_sha256;
    std::string_view named_uv_source_sha256;
};

struct DecodedTexture final {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::vector<std::uint8_t> rgba8;
};

struct DecodedTextureMetadata final {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::uint64_t pixel_count = 0;
    std::uint64_t rgba8_byte_length = 0;
    std::uint64_t transparent_pixel_count = 0;
    std::uint64_t opaque_pixel_count = 0;
    std::string rgba8_sha256;
};

struct DecodedTextureResult final {
    const DecodedTexture* texture = nullptr;
    const DecodedTextureMetadata* metadata = nullptr;
    bool cache_hit = false;
};

struct DecodedTextureView final {
    const DecodedTexture* texture = nullptr;
    const DecodedTextureMetadata* metadata = nullptr;
    std::string_view source_sha256;
};

/*
 * Authored material textures are mip chains, not independent base images.
 * The cache keeps all three representations needed at the native material
 * boundary: the exact decoded PNG bytes, their [0, 1] float64 expansion, and
 * the hardware-visible float64 values after an explicit color-space decode.
 */
enum class DecodedTextureColorSpace : std::uint32_t {
    kLinear = 1,
    kSrgb = 2,
};

struct DecodedTextureMipSource final {
    std::uint32_t level = 0;
    std::uint32_t expected_width = 0;
    std::uint32_t expected_height = 0;
    std::wstring canonical_path_key;
    std::string source_sha256;
    std::span<const std::uint8_t> source_bytes;
};

struct DecodedTextureMipChainSource final {
    std::string texture_name;
    std::string source_format;
    std::string authored_source_sha256;
    std::span<const std::uint8_t> authored_source_bytes;
    std::string manifest_sha256;
    std::span<const std::uint8_t> manifest_source_bytes;
    DecodedTextureColorSpace color_space = DecodedTextureColorSpace::kLinear;
    std::span<const DecodedTextureMipSource> levels;
};

struct DecodedTextureMipLevel final {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::vector<std::uint8_t> rgba8;
    std::vector<double> rgba64;
    std::vector<double> sampled_rgba64;
};

struct DecodedTextureMipLevelMetadata final {
    std::uint32_t level = 0;
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::uint64_t pixel_count = 0;
    std::uint64_t source_byte_length = 0;
    std::string source_sha256;
    std::string rgba8_sha256;
    std::string rgba64_sha256;
    std::string sampled_rgba64_sha256;
};

struct DecodedTextureMipLevelView final {
    std::uint32_t level = 0;
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::span<const std::uint8_t> rgba8;
    std::span<const double> rgba64;
    std::span<const double> sampled_rgba64;
    std::string_view source_sha256;
    std::string_view rgba8_sha256;
    std::string_view rgba64_sha256;
    std::string_view sampled_rgba64_sha256;
};

struct DecodedTextureMipChainMetadata final {
    std::uint32_t level_count = 0;
    std::uint64_t pixel_count = 0;
    std::uint64_t rgba8_byte_length = 0;
    std::uint64_t rgba64_byte_length = 0;
    std::string rgba8_chain_sha256;
    std::string rgba64_chain_sha256;
    std::string sampled_rgba64_chain_sha256;
    std::string decoded_chain_sha256;
};

struct DecodedTextureMipChainResult final {
    const DecodedTextureMipChainMetadata* metadata = nullptr;
    bool cache_hit = false;
};

struct DecodedTextureMipChainView final {
    std::string_view texture_name;
    std::string_view source_format;
    std::string_view authored_source_sha256;
    std::string_view manifest_sha256;
    DecodedTextureColorSpace color_space = DecodedTextureColorSpace::kLinear;
    std::span<const DecodedTextureMipLevelView> levels;
    const DecodedTextureMipChainMetadata* metadata = nullptr;
};

class DecodedAssetCache final {
public:
    DecodedAssetCache();
    ~DecodedAssetCache();
    DecodedAssetCache(const DecodedAssetCache&) = delete;
    DecodedAssetCache& operator=(const DecodedAssetCache&) = delete;

    DecodedObjResult decode_obj(
        const std::wstring& canonical_path_key,
        const std::string& source_sha256,
        const std::vector<std::uint8_t>& source_bytes);

    void attach_named_uv(
        const std::wstring& canonical_obj_path_key,
        const std::string& obj_source_sha256,
        const std::string& model_name,
        const std::string& sidecar_source_sha256,
        const std::vector<std::uint8_t>& sidecar_source_bytes);

    DecodedTextureResult decode_png(
        const std::wstring& canonical_path_key,
        const std::string& source_sha256,
        const std::vector<std::uint8_t>& source_bytes);

    DecodedTextureMipChainResult decode_texture_mip_chain(
        const std::wstring& canonical_chain_key,
        const DecodedTextureMipChainSource& source);

    // Keys are opaque, exact canonical/case-folded keys supplied by the host;
    // this module performs no path aliasing. Every lookup also requires the
    // exact lowercase SHA-256 source seal. A missing key yields nullopt from a
    // find call, but a known key with a different seal always throws
    // DECODED_SOURCE_CHANGED. get calls throw DECODED_CACHE_MISS when absent.
    [[nodiscard]] std::optional<DecodedObjView> find_obj(
        const std::wstring& canonical_path_key,
        const std::string& source_sha256);
    [[nodiscard]] DecodedObjView get_obj(
        const std::wstring& canonical_path_key,
        const std::string& source_sha256);
    [[nodiscard]] DecodedObjView get_obj_with_named_uv(
        const std::wstring& canonical_path_key,
        const std::string& obj_source_sha256,
        const std::string& sidecar_source_sha256);
    [[nodiscard]] std::optional<DecodedTextureView> find_texture(
        const std::wstring& canonical_path_key,
        const std::string& source_sha256);
    [[nodiscard]] DecodedTextureView get_texture(
        const std::wstring& canonical_path_key,
        const std::string& source_sha256);
    [[nodiscard]] std::optional<DecodedTextureMipChainView> find_texture_mip_chain(
        const std::wstring& canonical_chain_key,
        const std::string& manifest_sha256,
        const std::string& authored_source_sha256);
    [[nodiscard]] DecodedTextureMipChainView get_texture_mip_chain(
        const std::wstring& canonical_chain_key,
        const std::string& manifest_sha256,
        const std::string& authored_source_sha256);

    [[nodiscard]] std::size_t obj_entry_count() const noexcept;
    [[nodiscard]] std::size_t texture_entry_count() const noexcept;
    [[nodiscard]] std::size_t texture_mip_chain_entry_count() const noexcept;
    [[nodiscard]] std::uint64_t resident_decoded_bytes() const noexcept;

private:
    struct Implementation;
    std::unique_ptr<Implementation> implementation_;
};

} // namespace native_runtime
