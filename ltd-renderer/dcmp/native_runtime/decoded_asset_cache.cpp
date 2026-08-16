#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <objbase.h>
#include <wincodec.h>

#include "decoded_asset_cache.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cmath>
#include <cstring>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <utility>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "windowscodecs.lib")

namespace native_runtime {
namespace {

constexpr std::size_t kMaximumObjEntries = 256;
constexpr std::size_t kMaximumTextureEntries = 16384;
constexpr std::size_t kMaximumTextureMipChainEntries = 4096;
constexpr std::size_t kMaximumTextureMipLevels = 16;
constexpr std::uint64_t kMaximumResidentDecodedBytes = 1024ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kMaximumTexturePixels = 16384ULL * 16384ULL;
constexpr std::uint64_t kMaximumObjScalars = 64ULL * 1024ULL * 1024ULL;

[[noreturn]] void fail(std::string_view code, std::string_view message) {
    throw DecodedAssetError(std::string(code), std::string(message));
}

template <typename Interface>
class ComPointer final {
public:
    ComPointer() = default;
    ~ComPointer() { reset(); }
    ComPointer(const ComPointer&) = delete;
    ComPointer& operator=(const ComPointer&) = delete;
    Interface** output() {
        reset();
        return &pointer_;
    }
    Interface* get() const noexcept { return pointer_; }
    Interface* operator->() const noexcept { return pointer_; }
    void reset() noexcept {
        if (pointer_) pointer_->Release();
        pointer_ = nullptr;
    }

private:
    Interface* pointer_ = nullptr;
};

void require_hresult(HRESULT result, std::string_view action) {
    if (FAILED(result)) {
        std::ostringstream message;
        message << action << " failed with HRESULT 0x" << std::hex
                << static_cast<unsigned long>(result);
        fail("PNG_DECODE_FAILURE", message.str());
    }
}

std::string sha256_hex(const std::uint8_t* data, std::size_t size) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        fail("HASH_FAILURE", "could not open SHA-256 provider");
    }
    const auto close = [&]() {
        if (hash) BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
    };
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0) {
        close();
        fail("HASH_FAILURE", "could not create SHA-256 hash");
    }
    std::size_t cursor = 0;
    while (cursor < size) {
        const std::size_t chunk = std::min<std::size_t>(
            size - cursor, std::numeric_limits<ULONG>::max());
        if (BCryptHashData(hash, const_cast<PUCHAR>(data + cursor),
                           static_cast<ULONG>(chunk), 0) < 0) {
            close();
            fail("HASH_FAILURE", "could not update SHA-256 hash");
        }
        cursor += chunk;
    }
    std::array<std::uint8_t, 32> digest{};
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) {
        close();
        fail("HASH_FAILURE", "could not finish SHA-256 hash");
    }
    close();
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(64);
    for (std::uint8_t byte : digest) {
        output.push_back(hex[byte >> 4]);
        output.push_back(hex[byte & 0x0f]);
    }
    return output;
}

std::string sha256_hex(const std::vector<std::uint8_t>& bytes) {
    return sha256_hex(bytes.data(), bytes.size());
}

std::string sha256_hex(std::span<const std::uint8_t> bytes) {
    return sha256_hex(bytes.data(), bytes.size());
}

void validate_cache_key(const std::wstring& canonical_path_key) {
    if (canonical_path_key.empty() ||
        std::find(canonical_path_key.begin(), canonical_path_key.end(), L'\0') !=
            canonical_path_key.end()) {
        fail("DECODED_KEY_INVALID", "decoded-asset canonical key is empty or contains NUL");
    }
}

void validate_sha256_seal(std::string_view source_sha256) {
    if (source_sha256.size() != 64 ||
        !std::all_of(source_sha256.begin(), source_sha256.end(), [](char byte) {
            return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
        })) {
        fail("DECODED_SOURCE_SEAL_INVALID",
             "decoded-asset source seal must be 64 lowercase SHA-256 hex digits");
    }
}

void validate_source_identity(const std::wstring& canonical_path_key,
                              const std::string& source_sha256,
                              const std::vector<std::uint8_t>& source_bytes) {
    validate_cache_key(canonical_path_key);
    validate_sha256_seal(source_sha256);
    if (sha256_hex(source_bytes) != source_sha256) {
        fail("DECODED_SOURCE_HASH_MISMATCH",
             "decoded-asset source bytes differ from their supplied SHA-256 seal");
    }
}

void validate_source_identity(const std::wstring& canonical_path_key,
                              const std::string& source_sha256,
                              std::span<const std::uint8_t> source_bytes) {
    validate_cache_key(canonical_path_key);
    validate_sha256_seal(source_sha256);
    if (sha256_hex(source_bytes) != source_sha256) {
        fail("DECODED_SOURCE_HASH_MISMATCH",
             "decoded-asset source bytes differ from their supplied SHA-256 seal");
    }
}

void append_u32le(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void append_u64le(std::vector<std::uint8_t>& bytes, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
        bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::vector<std::uint8_t> doubles_as_little_endian(const std::vector<double>& values) {
    static_assert(sizeof(double) == sizeof(std::uint64_t));
    std::vector<std::uint8_t> bytes;
    bytes.reserve(values.size() * sizeof(double));
    for (double value : values) {
        std::uint64_t bits = 0;
        std::memcpy(&bits, &value, sizeof(bits));
        append_u64le(bytes, bits);
    }
    return bytes;
}

void append_text(std::vector<std::uint8_t>& bytes, std::string_view value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        fail("DECODED_TEXTURE_CHAIN_INVALID", "mip-chain identity text is too long");
    }
    append_u32le(bytes, static_cast<std::uint32_t>(value.size()));
    bytes.insert(bytes.end(), value.begin(), value.end());
}

std::string trim_copy(std::string_view input) {
    std::size_t begin = 0;
    while (begin < input.size() &&
           std::isspace(static_cast<unsigned char>(input[begin]))) ++begin;
    std::size_t end = input.size();
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(input[end - 1]))) --end;
    return std::string(input.substr(begin, end - begin));
}

std::vector<std::string_view> split_whitespace(std::string_view input) {
    std::vector<std::string_view> result;
    std::size_t cursor = 0;
    while (cursor < input.size()) {
        while (cursor < input.size() &&
               std::isspace(static_cast<unsigned char>(input[cursor]))) ++cursor;
        if (cursor == input.size()) break;
        const std::size_t begin = cursor;
        while (cursor < input.size() &&
               !std::isspace(static_cast<unsigned char>(input[cursor]))) ++cursor;
        result.push_back(input.substr(begin, cursor - begin));
    }
    return result;
}

double parse_double(std::string_view token, std::string_view record) {
    double value = 0.0;
    const auto parsed = std::from_chars(
        token.data(), token.data() + token.size(), value, std::chars_format::general);
    if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size() ||
        !std::isfinite(value)) {
        fail("OBJ_PARSE_FAILURE", std::string(record) + " contains an invalid finite float");
    }
    return value;
}

std::int64_t parse_obj_index(std::string_view token, std::size_t length,
                             std::string_view role, bool allow_empty) {
    if (token.empty()) {
        if (allow_empty) return -1;
        fail("OBJ_PARSE_FAILURE", std::string("face has no ") + std::string(role) + " index");
    }
    std::int64_t raw = 0;
    const auto parsed = std::from_chars(token.data(), token.data() + token.size(), raw);
    if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size() || raw == 0) {
        fail("OBJ_PARSE_FAILURE", std::string("invalid ") + std::string(role) + " index");
    }
    const std::int64_t resolved = raw > 0
        ? raw - 1
        : static_cast<std::int64_t>(length) + raw;
    if (resolved < 0 || static_cast<std::uint64_t>(resolved) >= length) {
        fail("OBJ_PARSE_FAILURE", std::string(role) + " index is outside the current stream");
    }
    return resolved;
}

struct Corner final {
    std::int64_t vertex = -1;
    std::int64_t texcoord = -1;
    std::int64_t normal = -1;
};

Corner parse_corner(std::string_view field, const DecodedObjMesh& mesh) {
    std::array<std::string_view, 3> tokens{};
    std::size_t token_count = 1;
    std::size_t begin = 0;
    while (true) {
        const std::size_t slash = field.find('/', begin);
        if (token_count > tokens.size()) fail("OBJ_PARSE_FAILURE", "face corner has too many fields");
        tokens[token_count - 1] = field.substr(
            begin, slash == std::string_view::npos ? field.size() - begin : slash - begin);
        if (slash == std::string_view::npos) break;
        ++token_count;
        if (token_count > tokens.size()) fail("OBJ_PARSE_FAILURE", "face corner has too many fields");
        begin = slash + 1;
    }
    return Corner{
        parse_obj_index(tokens[0], mesh.positions.size() / 3, "vertex", false),
        token_count > 1
            ? parse_obj_index(tokens[1], mesh.texcoords.size() / 2, "texcoord", true)
            : -1,
        token_count > 2
            ? parse_obj_index(tokens[2], mesh.normals.size() / 3, "normal", true)
            : -1,
    };
}

DecodedObjMesh parse_obj(const std::vector<std::uint8_t>& source) {
    if (std::find(source.begin(), source.end(), 0) != source.end()) {
        fail("OBJ_PARSE_FAILURE", "OBJ contains a NUL byte");
    }
    DecodedObjMesh mesh;
    std::string group = "unnamed";
    std::string_view text(reinterpret_cast<const char*>(source.data()), source.size());
    std::size_t cursor = 0;
    while (cursor <= text.size()) {
        const std::size_t newline = text.find('\n', cursor);
        const std::size_t end = newline == std::string_view::npos ? text.size() : newline;
        const std::string line_storage = trim_copy(text.substr(cursor, end - cursor));
        const std::string_view line(line_storage);
        if (!line.empty() && line[0] != '#') {
            const std::vector<std::string_view> fields = split_whitespace(line);
            if (!fields.empty()) {
                const std::string_view record = fields[0];
                if (record == "g") {
                    group.clear();
                    for (std::size_t index = 1; index < fields.size(); ++index) {
                        if (!group.empty()) group.push_back(' ');
                        group.append(fields[index]);
                    }
                    if (group.empty()) group = "unnamed";
                } else if (record == "v" || record == "vn") {
                    if (fields.size() < 4) fail("OBJ_PARSE_FAILURE", "v/vn record is truncated");
                    std::vector<double>& target = record == "v" ? mesh.positions : mesh.normals;
                    for (std::size_t index = 1; index <= 3; ++index) {
                        target.push_back(parse_double(fields[index], record));
                    }
                } else if (record == "vt") {
                    if (fields.size() < 3) fail("OBJ_PARSE_FAILURE", "vt record is truncated");
                    mesh.texcoords.push_back(parse_double(fields[1], record));
                    mesh.texcoords.push_back(parse_double(fields[2], record));
                } else if (record == "f") {
                    if (fields.size() < 4) fail("OBJ_PARSE_FAILURE", "face has fewer than three corners");
                    std::vector<Corner> corners;
                    corners.reserve(fields.size() - 1);
                    for (std::size_t index = 1; index < fields.size(); ++index) {
                        corners.push_back(parse_corner(fields[index], mesh));
                    }
                    for (std::size_t index = 1; index + 1 < corners.size(); ++index) {
                        const Corner fan[3] = {corners[0], corners[index], corners[index + 1]};
                        DecodedObjTriangle triangle;
                        triangle.group = group;
                        for (std::size_t corner = 0; corner < 3; ++corner) {
                            triangle.vertex[corner] = fan[corner].vertex;
                            triangle.texcoord[corner] = fan[corner].texcoord;
                            triangle.normal[corner] = fan[corner].normal;
                        }
                        mesh.triangles.push_back(std::move(triangle));
                    }
                }
            }
        }
        if (newline == std::string_view::npos) break;
        cursor = newline + 1;
    }
    const std::uint64_t scalar_count = mesh.positions.size() + mesh.texcoords.size() +
        mesh.normals.size();
    if (scalar_count > kMaximumObjScalars) fail("OBJ_TOO_LARGE", "OBJ scalar count exceeds limit");
    if (mesh.positions.empty() || mesh.triangles.empty()) {
        fail("OBJ_PARSE_FAILURE", "OBJ has no positions or triangles");
    }
    return mesh;
}

DecodedObjMetadata obj_metadata(const DecodedObjMesh& mesh) {
    DecodedObjMetadata metadata;
    metadata.position_count = mesh.positions.size() / 3;
    metadata.texcoord_count = mesh.texcoords.size() / 2;
    metadata.normal_count = mesh.normals.size() / 3;
    metadata.triangle_count = mesh.triangles.size();
    const auto positions = doubles_as_little_endian(mesh.positions);
    const auto texcoords = doubles_as_little_endian(mesh.texcoords);
    const auto normals = doubles_as_little_endian(mesh.normals);
    metadata.positions_sha256 = sha256_hex(positions);
    metadata.texcoords_sha256 = sha256_hex(texcoords);
    metadata.normals_sha256 = sha256_hex(normals);
    std::vector<std::uint8_t> topology;
    for (const DecodedObjTriangle& triangle : mesh.triangles) {
        ++metadata.group_triangle_counts[triangle.group];
        if (triangle.group.size() > std::numeric_limits<std::uint32_t>::max()) {
            fail("OBJ_PARSE_FAILURE", "OBJ group name is too long");
        }
        append_u32le(topology, static_cast<std::uint32_t>(triangle.group.size()));
        topology.insert(topology.end(), triangle.group.begin(), triangle.group.end());
        for (std::int64_t index : triangle.vertex) append_u64le(topology, static_cast<std::uint64_t>(index));
        for (std::int64_t index : triangle.texcoord) append_u64le(topology, static_cast<std::uint64_t>(index));
        for (std::int64_t index : triangle.normal) append_u64le(topology, static_cast<std::uint64_t>(index));
    }
    metadata.topology_sha256 = sha256_hex(topology);
    std::vector<std::uint8_t> decoded;
    decoded.reserve(positions.size() + texcoords.size() + normals.size() + topology.size());
    append_u64le(decoded, metadata.position_count);
    decoded.insert(decoded.end(), positions.begin(), positions.end());
    append_u64le(decoded, metadata.texcoord_count);
    decoded.insert(decoded.end(), texcoords.begin(), texcoords.end());
    append_u64le(decoded, metadata.normal_count);
    decoded.insert(decoded.end(), normals.begin(), normals.end());
    append_u64le(decoded, metadata.triangle_count);
    decoded.insert(decoded.end(), topology.begin(), topology.end());
    metadata.decoded_sha256 = sha256_hex(decoded);
    return metadata;
}

DecodedTextureMetadata texture_metadata(const DecodedTexture& texture) {
    DecodedTextureMetadata metadata;
    metadata.width = texture.width;
    metadata.height = texture.height;
    metadata.pixel_count = static_cast<std::uint64_t>(texture.width) * texture.height;
    metadata.rgba8_byte_length = texture.rgba8.size();
    for (std::size_t offset = 3; offset < texture.rgba8.size(); offset += 4) {
        if (texture.rgba8[offset] == 0) ++metadata.transparent_pixel_count;
        if (texture.rgba8[offset] == 255) ++metadata.opaque_pixel_count;
    }
    metadata.rgba8_sha256 = sha256_hex(texture.rgba8);
    return metadata;
}

double srgb_byte_to_linear(std::uint8_t value) {
    /*
     * Every authored input is RGBA8. Pin the 256 hardware-visible values to
     * the accepted NumPy float64 oracle so platform libm pow implementations
     * cannot introduce one-ULP drift before bilinear/trilinear filtering.
     */
    static constexpr std::array<double, 256> table = {{
        0x0.0p+0,
        0x1.3e45677c176f7p-12,
        0x1.3e45677c176f7p-11,
        0x1.dd681b3a23272p-11,
        0x1.3e45677c176f7p-10,
        0x1.8dd6c15b1d4b4p-10,
        0x1.dd681b3a23272p-10,
        0x1.167cba8c94818p-9,
        0x1.3e45677c176f7p-9,
        0x1.660e146b9a5d5p-9,
        0x1.8dd6c15b1d4b4p-9,
        0x1.b6a31b5259c99p-9,
        0x1.e1e31d70c99ddp-9,
        0x1.07c38bf8583a9p-8,
        0x1.1fcc2beed6421p-8,
        0x1.390ffaf95e279p-8,
        0x1.53936cc7bc928p-8,
        0x1.6f5addb50c915p-8,
        0x1.8c6a94031b561p-8,
        0x1.aac6c0fb97351p-8,
        0x1.ca7381f9f602bp-8,
        0x1.eb74e160978d0p-8,
        0x1.06e76bbda92b8p-7,
        0x1.18c2a5a8a8044p-7,
        0x1.2b4e09b3f0ae3p-7,
        0x1.3e8b7b3bde965p-7,
        0x1.527cd60af8b85p-7,
        0x1.6723eea8d3709p-7,
        0x1.7c8292a3db6b3p-7,
        0x1.929a88d67b521p-7,
        0x1.a96d91a8016bdp-7,
        0x1.c0fd67499fab6p-7,
        0x1.d94bbdefd740ep-7,
        0x1.f25a44089883fp-7,
        0x1.061551372c694p-6,
        0x1.135f3e4c2cce2p-6,
        0x1.210bb8642b172p-6,
        0x1.2f1b8c1ae46bdp-6,
        0x1.3d8f839b79c0bp-6,
        0x1.4c6866b3e9fa4p-6,
        0x1.5ba6fae794313p-6,
        0x1.6b4c0380d2deep-6,
        0x1.7b5841a1bf3acp-6,
        0x1.8bcc74542addbp-6,
        0x1.9ca95898dc8b5p-6,
        0x1.adefa9761c020p-6,
        0x1.bfa0200597bd9p-6,
        0x1.d1bb7381aec1fp-6,
        0x1.e442595227bcap-6,
        0x1.f73585185e1b5p-6,
        0x1.054ad45d76878p-5,
        0x1.0f31ba386ff26p-5,
        0x1.194fcb663747bp-5,
        0x1.23a55e62a662ap-5,
        0x1.2e32c8e148d11p-5,
        0x1.38f85fd21eacfp-5,
        0x1.43f67766310ffp-5,
        0x1.4f2d6313fa8d0p-5,
        0x1.5a9d759ba5ed0p-5,
        0x1.6647010b254eep-5,
        0x1.722a56c2239eep-5,
        0x1.7e47c775d2427p-5,
        0x1.8a9fa33494b07p-5,
        0x1.973239698b9ccp-5,
        0x1.a3ffd8e001389p-5,
        0x1.b108cfc6b7fbcp-5,
        0x1.be4d6bb31d522p-5,
        0x1.cbcdf9a4616f2p-5,
        0x1.d98ac60675833p-5,
        0x1.e7841cb4f16dfp-5,
        0x1.f5ba48fde2048p-5,
        0x1.0216cad240765p-4,
        0x1.096f2671eb815p-4,
        0x1.10e65c38a5192p-4,
        0x1.187c90bf8bce2p-4,
        0x1.2031e85f5d6dap-4,
        0x1.28068731a1952p-4,
        0x1.2ffa9111cb94bp-4,
        0x1.380e299e53f92p-4,
        0x1.40417439ca10fp-4,
        0x1.4894940bddbfbp-4,
        0x1.5107ac0261e59p-4,
        0x1.599aded247aacp-4,
        0x1.624e4ef892ed4p-4,
        0x1.6b221ebb4817ep-4,
        0x1.7416702a539d1p-4,
        0x1.7d2b65206b527p-4,
        0x1.86611f43e9e6ap-4,
        0x1.8fb7c007a4a70p-4,
        0x1.992f68abbbc89p-4,
        0x1.a2c83a3e6566dp-4,
        0x1.ac82559cb3644p-4,
        0x1.b65ddb7354604p-4,
        0x1.c05aec3f4fe5ep-4,
        0x1.ca79a84ebe030p-4,
        0x1.d4ba2fc17a6a5p-4,
        0x1.df1ca289d34b8p-4,
        0x1.e9a1206d34003p-4,
        0x1.f447c904cbb4ep-4,
        0x1.ff10bbbe302c2p-4,
        0x1.04fe0bedfe5f1p-3,
        0x1.0a84fe3b36d8fp-3,
        0x1.101d443dfc06fp-3,
        0x1.15c6ed58eefdfp-3,
        0x1.1b8208da5fef0p-3,
        0x1.214ea5fc9514ap-3,
        0x1.272cd3e610123p-3,
        0x1.2d1ca1a9d1cfbp-3,
        0x1.331e1e479cdf5p-3,
        0x1.393158ac3674ep-3,
        0x1.3f565fb1a5fd5p-3,
        0x1.458d421f735dfp-3,
        0x1.4bd60eaae3e73p-3,
        0x1.5230d3f736034p-3,
        0x1.589da095dbaa1p-3,
        0x1.5f1c8306b3a3cp-3,
        0x1.65ad89b841a2bp-3,
        0x1.6c50c307e53bfp-3,
        0x1.73063d420fc80p-3,
        0x1.79ce06a279303p-3,
        0x1.80a82d5453b5dp-3,
        0x1.8794bf727eb3fp-3,
        0x1.8e93cb07b8679p-3,
        0x1.95a55e0ecec0bp-3,
        0x1.9cc98672cf47ep-3,
        0x1.a400520f3619cp-3,
        0x1.ab49ceb01c003p-3,
        0x1.b2a60a1263b0ap-3,
        0x1.ba1511e3e632dp-3,
        0x1.c196f3c39e76fp-3,
        0x1.c92bbd41d41fep-3,
        0x1.d0d37be045851p-3,
        0x1.d88e3d1250f68p-3,
        0x1.e05c0e3d1d3e0p-3,
        0x1.e83cfcb7c16f0p-3,
        0x1.f03115cb6bfd3p-3,
        0x1.f83866b38924dp-3,
        0x1.00297e4ef4553p-2,
        0x1.044072557177ap-2,
        0x1.086115f6beb3ap-2,
        0x1.0c8b6fb5c735ep-2,
        0x1.10bf860ef039ap-2,
        0x1.14fd5f782a5a6p-2,
        0x1.1945026102997p-2,
        0x1.1d967532b31b1p-2,
        0x1.21f1be50339e7p-2,
        0x1.2656e41649ae3p-2,
        0x1.2ac5ecdb988f8p-2,
        0x1.2f3edef0b0ed8p-2,
        0x1.33c1c0a020438p-2,
        0x1.384e982e800b1p-2,
        0x1.3ce56bda84a81p-2,
        0x1.418641dd0c1bcp-2,
        0x1.463120692c7afp-2,
        0x1.4ae60dac4229dp-2,
        0x1.4fa50fcdfde15p-2,
        0x1.546e2cf0727a9p-2,
        0x1.59416b3022858p-2,
        0x1.5e1ed0a40daabp-2,
        0x1.6306635dbdd7bp-2,
        0x1.67f82969543a2p-2,
        0x1.6cf428cd96079p-2,
        0x1.71fa678bf915dp-2,
        0x1.770aeba0b042ap-2,
        0x1.7c25bb02b7ac5p-2,
        0x1.814adba3e0bd9p-2,
        0x1.867a5370de0b1p-2,
        0x1.8bb428514f067p-2,
        0x1.90f86027cb84ep-2,
        0x1.964700d1ef1b1p-2,
        0x1.9ba0102864521p-2,
        0x1.a10393feefafdp-2,
        0x1.a67192247a9bep-2,
        0x1.abea10631e195p-2,
        0x1.b16d14802d5cap-2,
        0x1.b6faa43c403bbp-2,
        0x1.bc92c5533d785p-2,
        0x1.c2357d7c64e5dp-2,
        0x1.c7e2d26a596dep-2,
        0x1.cd9ac9cb2aef2p-2,
        0x1.d35d69485ffc5p-2,
        0x1.d92ab686ff782p-2,
        0x1.df02b7279a10dp-2,
        0x1.e4e570c6539c5p-2,
        0x1.ead2e8faec526p-2,
        0x1.f0cb2558c9ea4p-2,
        0x1.f6ce2b6f00983p-2,
        0x1.fcdc00c85bec2p-2,
        0x1.017a5575b3cb2p-1,
        0x1.048c17ad3c04bp-1,
        0x1.07a349c9d9837p-1,
        0x1.0abfee888c050p-1,
        0x1.0de208a4444c8p-1,
        0x1.11099ad5e83ebp-1,
        0x1.1436a7d456eefp-1,
        0x1.176932546ca12p-1,
        0x1.1aa13d0906bdap-1,
        0x1.1ddecaa307b85p-1,
        0x1.2121ddd15aecep-1,
        0x1.246a7940f86d1p-1,
        0x1.27b89f9ce8c4bp-1,
        0x1.2b0c538e48b07p-1,
        0x1.2e6597bc4cca0p-1,
        0x1.31c46ecc4528dp-1,
        0x1.3528db61a0f73p-1,
        0x1.3892e01df1fccp-1,
        0x1.3c027fa0f01ebp-1,
        0x1.3f77bc887cd3bp-1,
        0x1.42f29970a68f8p-1,
        0x1.467318f3ac22dp-1,
        0x1.49f93daa00113p-1,
        0x1.4d850a2a4bde1p-1,
        0x1.51168109734e5p-1,
        0x1.54ada4da97a1bp-1,
        0x1.584a782f1ac23p-1,
        0x1.5becfd96a2698p-1,
        0x1.5f95379f1b3edp-1,
        0x1.634328d4bbe97p-1,
        0x1.66f6d3c2081cfp-1,
        0x1.6ab03aefd39aap-1,
        0x1.6e6f60e5452b1p-1,
        0x1.72344827d98f6p-1,
        0x1.75fef33b6669bp-1,
        0x1.79cf64a21d1e2p-1,
        0x1.7da59edc8dab0p-1,
        0x1.8181a469a9787p-1,
        0x1.856377c6c6224p-1,
        0x1.894b1b6fa0377p-1,
        0x1.8d3891de5df49p-1,
        0x1.912bdd8b91f45p-1,
        0x1.952500ee3dda5p-1,
        0x1.9923fe7bd4f67p-1,
        0x1.9d28d8a83edfcp-1,
        0x1.a13391e5da09fp-1,
        0x1.a5442ca57e52ep-1,
        0x1.a95aab567f88fp-1,
        0x1.ad771066afec2p-1,
        0x1.b1995e4262a69p-1,
        0x1.b5c197546e3f8p-1,
        0x1.b9efbe062f086p-1,
        0x1.be23d4bf8981bp-1,
        0x1.c25ddde6ecbbbp-1,
        0x1.c69ddbe154af1p-1,
        0x1.cae3d1124c90bp-1,
        0x1.cf2fbfdbf11f1p-1,
        0x1.d381aa9ef2e82p-1,
        0x1.d7d993ba988d4p-1,
        0x1.dc377d8cc0fd5p-1,
        0x1.e09b6a71e5aa6p-1,
        0x1.e5055cc51cbb4p-1,
        0x1.e97556e01b351p-1,
        0x1.edeb5b1b37216p-1,
        0x1.f2676bcd69adep-1,
        0x1.f6e98b4c51466p-1,
        0x1.fb71bbec33ab2p-1,
        0x1.0000000000000p+0,
    }};
    return table[value];
}

std::vector<std::uint8_t> encoded_mip_chain(
    std::string_view domain,
    const std::vector<DecodedTextureMipLevel>& levels,
    int representation) {
    std::vector<std::uint8_t> bytes(domain.begin(), domain.end());
    for (const DecodedTextureMipLevel& level : levels) {
        append_u32le(bytes, level.height);
        append_u32le(bytes, level.width);
        if (representation == 0) {
            append_u64le(bytes, static_cast<std::uint64_t>(level.rgba8.size()));
            bytes.insert(bytes.end(), level.rgba8.begin(), level.rgba8.end());
        } else {
            const std::vector<double>& values = representation == 1
                ? level.rgba64
                : level.sampled_rgba64;
            const std::vector<std::uint8_t> encoded = doubles_as_little_endian(values);
            append_u64le(bytes, static_cast<std::uint64_t>(encoded.size()));
            bytes.insert(bytes.end(), encoded.begin(), encoded.end());
        }
    }
    return bytes;
}

DecodedTextureMipChainMetadata mip_chain_metadata(
    std::string_view texture_name,
    std::string_view source_format,
    std::string_view authored_source_sha256,
    std::string_view manifest_sha256,
    DecodedTextureColorSpace color_space,
    const std::vector<DecodedTextureMipLevel>& levels,
    const std::vector<DecodedTextureMipLevelMetadata>& level_metadata) {
    DecodedTextureMipChainMetadata metadata;
    metadata.level_count = static_cast<std::uint32_t>(levels.size());
    for (const DecodedTextureMipLevel& level : levels) {
        const std::uint64_t pixels =
            static_cast<std::uint64_t>(level.width) * level.height;
        metadata.pixel_count += pixels;
        metadata.rgba8_byte_length += level.rgba8.size();
        metadata.rgba64_byte_length += level.rgba64.size() * sizeof(double);
    }
    metadata.rgba8_chain_sha256 = sha256_hex(encoded_mip_chain(
        "ltd.decoded.texture-chain.rgba8.v1", levels, 0));
    metadata.rgba64_chain_sha256 = sha256_hex(encoded_mip_chain(
        "ltd.decoded.texture-chain.v1", levels, 1));
    metadata.sampled_rgba64_chain_sha256 = sha256_hex(encoded_mip_chain(
        "ltd.decoded.texture-chain.v1", levels, 2));

    std::vector<std::uint8_t> authenticated{
        'l','t','d','.','d','e','c','o','d','e','d','.','a','u','t','h','o','r','e','d','-',
        'm','i','p','-','c','h','a','i','n','.','v','1'};
    append_text(authenticated, texture_name);
    append_text(authenticated, source_format);
    append_text(authenticated, authored_source_sha256);
    append_text(authenticated, manifest_sha256);
    append_u32le(authenticated, static_cast<std::uint32_t>(color_space));
    append_u32le(authenticated, static_cast<std::uint32_t>(level_metadata.size()));
    for (const DecodedTextureMipLevelMetadata& level : level_metadata) {
        append_u32le(authenticated, level.level);
        append_u32le(authenticated, level.width);
        append_u32le(authenticated, level.height);
        append_u64le(authenticated, level.source_byte_length);
        append_text(authenticated, level.source_sha256);
        append_text(authenticated, level.rgba8_sha256);
        append_text(authenticated, level.rgba64_sha256);
        append_text(authenticated, level.sampled_rgba64_sha256);
    }
    append_text(authenticated, metadata.rgba8_chain_sha256);
    append_text(authenticated, metadata.rgba64_chain_sha256);
    append_text(authenticated, metadata.sampled_rgba64_chain_sha256);
    metadata.decoded_chain_sha256 = sha256_hex(authenticated);
    return metadata;
}

} // namespace

struct DecodedAssetCache::Implementation final {
    struct ObjEntry final {
        std::string source_sha256;
        DecodedObjMesh mesh;
        DecodedObjMetadata metadata;
        std::string sidecar_source_sha256;
        std::map<std::string, std::vector<double>, std::less<>> named_uv_channels;
        std::vector<DecodedNamedUvChannelView> named_uv_views;
        bool getter_published = false;
    };
    struct TextureEntry final {
        std::string source_sha256;
        DecodedTexture texture;
        DecodedTextureMetadata metadata;
    };
    struct TextureMipChainEntry final {
        std::string texture_name;
        std::string source_format;
        std::string authored_source_sha256;
        std::string manifest_sha256;
        DecodedTextureColorSpace color_space = DecodedTextureColorSpace::kLinear;
        std::vector<DecodedTextureMipLevel> levels;
        std::vector<DecodedTextureMipLevelMetadata> level_metadata;
        std::vector<DecodedTextureMipLevelView> level_views;
        DecodedTextureMipChainMetadata metadata;
    };

    HRESULT com_result = E_FAIL;
    bool uninitialize_com = false;
    ComPointer<IWICImagingFactory> factory;
    std::map<std::wstring, ObjEntry> obj_entries;
    std::map<std::wstring, TextureEntry> texture_entries;
    std::map<std::wstring, TextureMipChainEntry> texture_mip_chain_entries;
    std::uint64_t resident_decoded_bytes = 0;

    Implementation() {
        com_result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(com_result)) uninitialize_com = true;
        else if (com_result != RPC_E_CHANGED_MODE) require_hresult(com_result, "CoInitializeEx");
        HRESULT factory_result = CoCreateInstance(
            CLSID_WICImagingFactory2, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(factory.output()));
        if (FAILED(factory_result)) {
            factory_result = CoCreateInstance(
                CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                IID_PPV_ARGS(factory.output()));
        }
        require_hresult(factory_result, "create WIC imaging factory");
    }

    ~Implementation() {
        factory.reset();
        if (uninitialize_com) CoUninitialize();
    }

    DecodedTexture decode_png_bytes(std::span<const std::uint8_t> source) {
        if (source.size() > std::numeric_limits<DWORD>::max()) {
            fail("PNG_TOO_LARGE", "PNG source exceeds WIC memory-stream limit");
        }
        ComPointer<IWICStream> stream;
        require_hresult(factory->CreateStream(stream.output()), "create WIC stream");
        require_hresult(stream->InitializeFromMemory(
                            const_cast<BYTE*>(source.data()), static_cast<DWORD>(source.size())),
                        "initialize WIC stream");
        ComPointer<IWICBitmapDecoder> decoder;
        require_hresult(factory->CreateDecoderFromStream(
                            stream.get(), nullptr, WICDecodeMetadataCacheOnLoad, decoder.output()),
                        "create PNG decoder");
        GUID container{};
        require_hresult(decoder->GetContainerFormat(&container), "read image container format");
        if (container != GUID_ContainerFormatPng) fail("PNG_FORMAT_MISMATCH", "asset is not PNG");
        UINT frame_count = 0;
        require_hresult(decoder->GetFrameCount(&frame_count), "read PNG frame count");
        if (frame_count != 1) fail("PNG_FRAME_COUNT", "PNG must contain exactly one frame");
        ComPointer<IWICBitmapFrameDecode> frame;
        require_hresult(decoder->GetFrame(0, frame.output()), "read PNG frame");
        UINT width = 0;
        UINT height = 0;
        require_hresult(frame->GetSize(&width, &height), "read PNG dimensions");
        if (width == 0 || height == 0 ||
            static_cast<std::uint64_t>(width) * height > kMaximumTexturePixels) {
            fail("PNG_DIMENSIONS", "PNG dimensions are empty or exceed limit");
        }
        ComPointer<IWICFormatConverter> converter;
        require_hresult(factory->CreateFormatConverter(converter.output()),
                        "create RGBA format converter");
        require_hresult(converter->Initialize(
                            frame.get(), GUID_WICPixelFormat32bppRGBA,
                            WICBitmapDitherTypeNone, nullptr, 0.0,
                            WICBitmapPaletteTypeCustom),
                        "convert PNG to RGBA8");
        const std::uint64_t stride64 = static_cast<std::uint64_t>(width) * 4;
        const std::uint64_t byte_length64 = stride64 * height;
        if (stride64 > std::numeric_limits<UINT>::max() ||
            byte_length64 > std::numeric_limits<UINT>::max()) {
            fail("PNG_TOO_LARGE", "decoded PNG exceeds WIC CopyPixels limit");
        }
        DecodedTexture texture;
        texture.width = width;
        texture.height = height;
        texture.rgba8.resize(static_cast<std::size_t>(byte_length64));
        require_hresult(converter->CopyPixels(
                            nullptr, static_cast<UINT>(stride64),
                            static_cast<UINT>(byte_length64), texture.rgba8.data()),
                        "copy RGBA8 pixels");
        return texture;
    }
};

DecodedAssetCache::DecodedAssetCache() : implementation_(std::make_unique<Implementation>()) {}
DecodedAssetCache::~DecodedAssetCache() = default;

DecodedObjResult DecodedAssetCache::decode_obj(
    const std::wstring& canonical_path_key, const std::string& source_sha256,
    const std::vector<std::uint8_t>& source_bytes) {
    validate_source_identity(canonical_path_key, source_sha256, source_bytes);
    const auto cached = implementation_->obj_entries.find(canonical_path_key);
    if (cached != implementation_->obj_entries.end()) {
        if (cached->second.source_sha256 != source_sha256) {
            fail("DECODED_SOURCE_CHANGED", "cached OBJ source seal changed");
        }
        return DecodedObjResult{&cached->second.mesh, &cached->second.metadata, true};
    }
    if (implementation_->obj_entries.size() >= kMaximumObjEntries) {
        fail("DECODED_CACHE_CAPACITY", "decoded OBJ cache reached entry limit");
    }
    DecodedObjMesh mesh = parse_obj(source_bytes);
    DecodedObjMetadata metadata = obj_metadata(mesh);
    const std::uint64_t resident =
        mesh.positions.size() * sizeof(double) + mesh.texcoords.size() * sizeof(double) +
        mesh.normals.size() * sizeof(double) +
        mesh.triangles.size() * sizeof(DecodedObjTriangle);
    if (resident > kMaximumResidentDecodedBytes - implementation_->resident_decoded_bytes) {
        fail("DECODED_CACHE_CAPACITY", "decoded asset cache exceeds 1 GiB limit");
    }
    implementation_->resident_decoded_bytes += resident;
    auto [inserted, unused] = implementation_->obj_entries.emplace(
        canonical_path_key,
        Implementation::ObjEntry{source_sha256, std::move(mesh), std::move(metadata)});
    (void)unused;
    return DecodedObjResult{&inserted->second.mesh, &inserted->second.metadata, false};
}

void DecodedAssetCache::attach_named_uv(
    const std::wstring& canonical_obj_path_key, const std::string& obj_source_sha256,
    const std::string& model_name, const std::string& sidecar_source_sha256,
    const std::vector<std::uint8_t>& sidecar_source_bytes) {
    validate_cache_key(canonical_obj_path_key);
    validate_sha256_seal(obj_source_sha256);
    validate_sha256_seal(sidecar_source_sha256);
    if (sha256_hex(sidecar_source_bytes) != sidecar_source_sha256) {
        fail("DECODED_SOURCE_HASH_MISMATCH",
             "named-UV source bytes differ from their supplied SHA-256 seal");
    }
    auto found = implementation_->obj_entries.find(canonical_obj_path_key);
    if (found == implementation_->obj_entries.end()) {
        fail("NAMED_UV_OBJ_MISSING", "named-UV sidecar has no matching sealed OBJ cache entry");
    }
    if (found->second.source_sha256 != obj_source_sha256) {
        fail("DECODED_SOURCE_CHANGED", "cached OBJ source seal changed");
    }
    auto& entry = found->second;
    if (!entry.sidecar_source_sha256.empty()) {
        if (entry.sidecar_source_sha256 != sidecar_source_sha256) {
            fail("DECODED_SOURCE_CHANGED", "cached named-UV source seal changed");
        }
        return;
    }
    if (entry.getter_published) {
        fail("DECODED_ENTRY_PUBLISHED",
             "cannot attach named UV after publishing an immutable OBJ getter view");
    }
    if (model_name.empty()) {
        fail("NAMED_UV_SCHEMA", "named-UV model name must not be empty");
    }
    if (std::find(sidecar_source_bytes.begin(), sidecar_source_bytes.end(), 0) !=
        sidecar_source_bytes.end()) {
        fail("NAMED_UV_PARSE_FAILURE", "named-UV JSON contains a NUL byte");
    }

    // This strict parser consumes only the exporter-owned sidecar contract.
    // It intentionally scans numeric channel arrays directly after validating
    // the scalar schema keys, avoiding a second general-purpose JSON DOM in
    // this independently compiled cache module.
    const std::string text(
        reinterpret_cast<const char*>(sidecar_source_bytes.data()), sidecar_source_bytes.size());
    auto require_token = [&](const std::string& token) {
        if (text.find(token) == std::string::npos) {
            fail("NAMED_UV_SCHEMA", "named-UV sidecar lacks required schema token");
        }
    };
    require_token("\"SchemaVersion\":1");
    require_token("\"VertexIndexing\":\"obj_position_zero_based\"");
    require_token("\"CoordinateConvention\":\"u_bfres_x__v_one_minus_bfres_y\"");
    require_token("\"Model\":\"" + model_name + "\"");
    DecodedObjMetadata metadata = entry.metadata;
    std::map<std::string, std::vector<double>, std::less<>> named_uv_channels;
    const std::string vertex_token =
        "\"VertexCount\":" + std::to_string(metadata.position_count);
    require_token(vertex_token);

    const std::size_t shapes_key = text.find("\"Shapes\":[");
    if (shapes_key == std::string::npos) fail("NAMED_UV_SCHEMA", "named-UV Shapes is missing");
    std::vector<bool> occupied(static_cast<std::size_t>(metadata.position_count), false);
    std::map<std::string, std::vector<bool>, std::less<>> channel_coverage;
    std::size_t cursor = shapes_key + std::string("\"Shapes\":[").size();

    auto parse_json_string = [&](std::size_t& position) -> std::string {
        if (position >= text.size() || text[position] != '"') {
            fail("NAMED_UV_PARSE_FAILURE", "expected JSON string");
        }
        ++position;
        std::string value;
        while (position < text.size()) {
            const char byte = text[position++];
            if (byte == '"') return value;
            if (byte == '\\' || static_cast<unsigned char>(byte) < 0x20) {
                fail("NAMED_UV_PARSE_FAILURE", "sidecar identifiers must be unescaped ASCII");
            }
            value.push_back(byte);
        }
        fail("NAMED_UV_PARSE_FAILURE", "unterminated JSON string");
    };
    auto skip_space = [&](std::size_t& position) {
        while (position < text.size() &&
               std::isspace(static_cast<unsigned char>(text[position]))) ++position;
    };
    auto peek = [&](std::size_t position) -> char {
        if (position >= text.size()) {
            fail("NAMED_UV_PARSE_FAILURE", "truncated named-UV sidecar");
        }
        return text[position];
    };
    auto parse_unsigned = [&](std::size_t& position) -> std::uint64_t {
        skip_space(position);
        std::uint64_t value = 0;
        const char* begin = text.data() + position;
        const auto result = std::from_chars(begin, text.data() + text.size(), value);
        if (result.ec != std::errc{}) fail("NAMED_UV_PARSE_FAILURE", "invalid unsigned integer");
        position = static_cast<std::size_t>(result.ptr - text.data());
        return value;
    };
    auto parse_number = [&](std::size_t& position) -> double {
        skip_space(position);
        const char* begin = text.data() + position;
        double value = 0.0;
        const auto result = std::from_chars(
            begin, text.data() + text.size(), value, std::chars_format::general);
        if (result.ec != std::errc{} || !std::isfinite(value)) {
            fail("NAMED_UV_PARSE_FAILURE", "invalid finite channel number");
        }
        position = static_cast<std::size_t>(result.ptr - text.data());
        return value;
    };
    auto require_char = [&](std::size_t& position, char expected) {
        skip_space(position);
        if (position >= text.size() || text[position] != expected) {
            fail("NAMED_UV_PARSE_FAILURE", "unexpected sidecar punctuation");
        }
        ++position;
    };
    while (true) {
        skip_space(cursor);
        if (cursor >= text.size()) fail("NAMED_UV_PARSE_FAILURE", "truncated Shapes array");
        if (text[cursor] == ']') break;
        require_char(cursor, '{');
        std::string group;
        std::uint64_t vertex_offset = std::numeric_limits<std::uint64_t>::max();
        std::uint64_t vertex_count = 0;
        bool parsed_channels = false;
        while (true) {
            skip_space(cursor);
            const std::string key = parse_json_string(cursor);
            require_char(cursor, ':');
            if (key == "Group" || key == "ObjChannel") {
                const std::string value = parse_json_string(cursor);
                if (key == "Group") group = value;
            } else if (key == "VertexOffset") {
                vertex_offset = parse_unsigned(cursor);
            } else if (key == "VertexCount") {
                vertex_count = parse_unsigned(cursor);
            } else if (key == "Channels") {
                if (group.empty() || vertex_offset == std::numeric_limits<std::uint64_t>::max() ||
                    vertex_count == 0 || vertex_offset > metadata.position_count ||
                    vertex_count > metadata.position_count - vertex_offset) {
                    fail("NAMED_UV_SCHEMA", "shape metadata is malformed before Channels");
                }
                for (std::uint64_t index = vertex_offset; index < vertex_offset + vertex_count; ++index) {
                    if (occupied[static_cast<std::size_t>(index)]) {
                        fail("NAMED_UV_SCHEMA", "shape ranges overlap");
                    }
                    occupied[static_cast<std::size_t>(index)] = true;
                }
                require_char(cursor, '{');
                while (true) {
                    skip_space(cursor);
                    if (peek(cursor) == '}') { ++cursor; break; }
                    const std::string channel = parse_json_string(cursor);
                    if (channel.size() < 3 || channel.rfind("_u", 0) != 0 ||
                        !std::all_of(channel.begin() + 2, channel.end(),
                                     [](unsigned char value) { return std::isdigit(value) != 0; })) {
                        fail("NAMED_UV_SCHEMA", "channel name is malformed");
                    }
                    require_char(cursor, ':');
                    require_char(cursor, '[');
                    auto& values = named_uv_channels[channel];
                    if (values.empty()) {
                        values.assign(static_cast<std::size_t>(metadata.position_count * 2),
                                      std::numeric_limits<double>::quiet_NaN());
                    }
                    auto& coverage = channel_coverage[channel];
                    if (coverage.empty()) coverage.assign(occupied.size(), false);
                    for (std::uint64_t local = 0; local < vertex_count; ++local) {
                        if (local != 0) require_char(cursor, ',');
                        require_char(cursor, '[');
                        const double u = parse_number(cursor);
                        require_char(cursor, ',');
                        const double v = parse_number(cursor);
                        require_char(cursor, ']');
                        const std::size_t index = static_cast<std::size_t>(vertex_offset + local);
                        if (coverage[index]) fail("NAMED_UV_SCHEMA", "channel coverage overlaps");
                        coverage[index] = true;
                        values[index * 2] = u;
                        values[index * 2 + 1] = v;
                    }
                    require_char(cursor, ']');
                    skip_space(cursor);
                    if (peek(cursor) == ',') { ++cursor; continue; }
                    if (peek(cursor) != '}') fail("NAMED_UV_PARSE_FAILURE", "bad Channels delimiter");
                }
                parsed_channels = true;
            } else {
                fail("NAMED_UV_SCHEMA", "unexpected sidecar shape field");
            }
            skip_space(cursor);
            if (peek(cursor) == ',') { ++cursor; continue; }
            if (peek(cursor) == '}') { ++cursor; break; }
            fail("NAMED_UV_PARSE_FAILURE", "bad shape delimiter");
        }
        if (!parsed_channels) fail("NAMED_UV_SCHEMA", "shape has no Channels object");
        skip_space(cursor);
        if (peek(cursor) == ',') { ++cursor; continue; }
        if (peek(cursor) == ']') break;
        fail("NAMED_UV_PARSE_FAILURE", "bad Shapes delimiter");
    }
    if (!std::all_of(occupied.begin(), occupied.end(), [](bool value) { return value; })) {
        fail("NAMED_UV_SCHEMA", "shape ranges do not cover every OBJ position");
    }
    if (named_uv_channels.size() < 2) {
        fail("NAMED_UV_SCHEMA", "sidecar does not preserve multiple channels");
    }
    std::vector<std::uint8_t> combined;
    for (const auto& [name, values] : named_uv_channels) {
        const auto& coverage = channel_coverage.at(name);
        const std::uint64_t count = static_cast<std::uint64_t>(
            std::count(coverage.begin(), coverage.end(), true));
        metadata.named_uv_coverage_counts[name] = count;
        const std::vector<std::uint8_t> encoded = doubles_as_little_endian(values);
        metadata.named_uv_sha256[name] = sha256_hex(encoded);
        if (name.size() > std::numeric_limits<std::uint32_t>::max()) {
            fail("NAMED_UV_SCHEMA", "named-UV channel name is too long");
        }
        append_u32le(combined, static_cast<std::uint32_t>(name.size()));
        combined.insert(combined.end(), name.begin(), name.end());
        append_u64le(combined, count);
        combined.insert(combined.end(), encoded.begin(), encoded.end());
    }
    metadata.named_uv_channel_count = named_uv_channels.size();
    metadata.named_uv_decoded_sha256 = sha256_hex(combined);
    const std::uint64_t per_channel_resident =
        metadata.position_count * 2 * sizeof(double);
    if (per_channel_resident != 0 &&
        named_uv_channels.size() >
            kMaximumResidentDecodedBytes / per_channel_resident) {
        fail("DECODED_CACHE_CAPACITY", "decoded named-UV cache exceeds 1 GiB limit");
    }
    const std::uint64_t resident =
        static_cast<std::uint64_t>(named_uv_channels.size()) * per_channel_resident;
    if (resident > kMaximumResidentDecodedBytes - implementation_->resident_decoded_bytes) {
        fail("DECODED_CACHE_CAPACITY", "decoded named-UV cache exceeds 1 GiB limit");
    }
    // Allocate the only potentially-throwing view storage before committing
    // any decoded channel state. Pushes below cannot allocate.
    entry.named_uv_views.reserve(named_uv_channels.size());
    entry.named_uv_channels = std::move(named_uv_channels);
    entry.metadata = std::move(metadata);
    entry.sidecar_source_sha256 = sidecar_source_sha256;
    entry.named_uv_views.clear();
    entry.named_uv_views.reserve(entry.named_uv_channels.size());
    for (const auto& [name, values] : entry.named_uv_channels) {
        entry.named_uv_views.push_back(DecodedNamedUvChannelView{
            name,
            values,
            entry.metadata.named_uv_coverage_counts.at(name),
            entry.metadata.named_uv_sha256.at(name),
        });
    }
    implementation_->resident_decoded_bytes += resident;
}

DecodedTextureResult DecodedAssetCache::decode_png(
    const std::wstring& canonical_path_key, const std::string& source_sha256,
    const std::vector<std::uint8_t>& source_bytes) {
    validate_source_identity(canonical_path_key, source_sha256, source_bytes);
    const auto cached = implementation_->texture_entries.find(canonical_path_key);
    if (cached != implementation_->texture_entries.end()) {
        if (cached->second.source_sha256 != source_sha256) {
            fail("DECODED_SOURCE_CHANGED", "cached PNG source seal changed");
        }
        return DecodedTextureResult{
            &cached->second.texture, &cached->second.metadata, true};
    }
    if (implementation_->texture_entries.size() >= kMaximumTextureEntries) {
        fail("DECODED_CACHE_CAPACITY", "decoded texture cache reached entry limit");
    }
    DecodedTexture texture = implementation_->decode_png_bytes(source_bytes);
    DecodedTextureMetadata metadata = texture_metadata(texture);
    const std::uint64_t resident = texture.rgba8.size();
    if (resident > kMaximumResidentDecodedBytes - implementation_->resident_decoded_bytes) {
        fail("DECODED_CACHE_CAPACITY", "decoded asset cache exceeds 1 GiB limit");
    }
    implementation_->resident_decoded_bytes += resident;
    auto [inserted, unused] = implementation_->texture_entries.emplace(
        canonical_path_key,
        Implementation::TextureEntry{source_sha256, std::move(texture), std::move(metadata)});
    (void)unused;
    return DecodedTextureResult{
        &inserted->second.texture, &inserted->second.metadata, false};
}

DecodedTextureMipChainResult DecodedAssetCache::decode_texture_mip_chain(
    const std::wstring& canonical_chain_key,
    const DecodedTextureMipChainSource& source) {
    validate_cache_key(canonical_chain_key);
    validate_sha256_seal(source.manifest_sha256);
    validate_sha256_seal(source.authored_source_sha256);
    if (source.authored_source_bytes.empty() ||
        sha256_hex(source.authored_source_bytes) != source.authored_source_sha256) {
        fail("DECODED_SOURCE_HASH_MISMATCH",
             "authored material texture bytes differ from their SHA-256 seal");
    }
    if (sha256_hex(source.manifest_source_bytes) != source.manifest_sha256) {
        fail("DECODED_SOURCE_HASH_MISMATCH",
             "material mip manifest bytes differ from their supplied SHA-256 seal");
    }
    const auto valid_text = [](std::string_view value) {
        return !value.empty() && value.find('\0') == std::string_view::npos;
    };
    if (!valid_text(source.texture_name) || !valid_text(source.source_format)) {
        fail("DECODED_TEXTURE_CHAIN_INVALID",
             "material texture name/format is empty or contains NUL");
    }
    if (source.color_space != DecodedTextureColorSpace::kLinear &&
        source.color_space != DecodedTextureColorSpace::kSrgb) {
        fail("DECODED_TEXTURE_COLOR_SPACE",
             "material texture color-space identity is unsupported");
    }
    const bool format_is_srgb = source.source_format.find("SRGB") != std::string::npos;
    if (format_is_srgb != (source.color_space == DecodedTextureColorSpace::kSrgb)) {
        fail("DECODED_TEXTURE_COLOR_SPACE",
             "material texture format and explicit color-space identity disagree");
    }
    if (source.levels.empty() || source.levels.size() > kMaximumTextureMipLevels) {
        fail("DECODED_TEXTURE_CHAIN_INVALID",
             "material texture mip count is empty or exceeds 16");
    }
    std::map<std::wstring, bool> level_keys;
    for (std::size_t index = 0; index < source.levels.size(); ++index) {
        const DecodedTextureMipSource& level = source.levels[index];
        if (level.level != index || level.expected_width == 0 ||
            level.expected_height == 0 ||
            static_cast<std::uint64_t>(level.expected_width) * level.expected_height >
                kMaximumTexturePixels) {
            fail("DECODED_TEXTURE_CHAIN_INVALID",
                 "material texture mip order/dimensions are invalid");
        }
        if (!level_keys.emplace(level.canonical_path_key, true).second) {
            fail("DECODED_TEXTURE_CHAIN_INVALID",
                 "material texture mip source key occurs more than once");
        }
        validate_source_identity(
            level.canonical_path_key, level.source_sha256, level.source_bytes);
    }

    const auto cached =
        implementation_->texture_mip_chain_entries.find(canonical_chain_key);
    if (cached != implementation_->texture_mip_chain_entries.end()) {
        const auto& entry = cached->second;
        if (entry.manifest_sha256 != source.manifest_sha256 ||
            entry.authored_source_sha256 != source.authored_source_sha256 ||
            entry.texture_name != source.texture_name ||
            entry.source_format != source.source_format ||
            entry.color_space != source.color_space ||
            entry.level_metadata.size() != source.levels.size()) {
            fail("DECODED_SOURCE_CHANGED", "cached material mip-chain identity changed");
        }
        for (std::size_t index = 0; index < source.levels.size(); ++index) {
            const auto& expected = source.levels[index];
            const auto& actual = entry.level_metadata[index];
            if (actual.level != expected.level || actual.width != expected.expected_width ||
                actual.height != expected.expected_height ||
                actual.source_sha256 != expected.source_sha256 ||
                actual.source_byte_length != expected.source_bytes.size()) {
                fail("DECODED_SOURCE_CHANGED",
                     "cached material mip-chain level identity changed");
            }
        }
        return DecodedTextureMipChainResult{&entry.metadata, true};
    }
    if (implementation_->texture_mip_chain_entries.size() >=
        kMaximumTextureMipChainEntries) {
        fail("DECODED_CACHE_CAPACITY",
             "decoded material mip-chain cache reached entry limit");
    }

    Implementation::TextureMipChainEntry entry;
    entry.texture_name = source.texture_name;
    entry.source_format = source.source_format;
    entry.authored_source_sha256 = source.authored_source_sha256;
    entry.manifest_sha256 = source.manifest_sha256;
    entry.color_space = source.color_space;
    entry.levels.reserve(source.levels.size());
    entry.level_metadata.reserve(source.levels.size());
    std::uint64_t resident = 0;
    for (const DecodedTextureMipSource& level_source : source.levels) {
        DecodedTexture decoded = implementation_->decode_png_bytes(level_source.source_bytes);
        if (decoded.width != level_source.expected_width ||
            decoded.height != level_source.expected_height) {
            fail("DECODED_TEXTURE_CHAIN_INVALID",
                 "decoded material mip dimensions differ from the manifest");
        }
        DecodedTextureMipLevel level;
        level.width = decoded.width;
        level.height = decoded.height;
        level.rgba8 = std::move(decoded.rgba8);
        level.rgba64.resize(level.rgba8.size());
        level.sampled_rgba64.resize(level.rgba8.size());
        for (std::size_t index = 0; index < level.rgba8.size(); ++index) {
            const double normalized = static_cast<double>(level.rgba8[index]) / 255.0;
            level.rgba64[index] = normalized;
            const bool rgb = (index & 3U) != 3U;
            level.sampled_rgba64[index] =
                source.color_space == DecodedTextureColorSpace::kSrgb && rgb
                ? srgb_byte_to_linear(level.rgba8[index])
                : normalized;
        }
        DecodedTextureMipLevelMetadata level_metadata;
        level_metadata.level = level_source.level;
        level_metadata.width = level.width;
        level_metadata.height = level.height;
        level_metadata.pixel_count =
            static_cast<std::uint64_t>(level.width) * level.height;
        level_metadata.source_byte_length = level_source.source_bytes.size();
        level_metadata.source_sha256 = level_source.source_sha256;
        level_metadata.rgba8_sha256 = sha256_hex(level.rgba8);
        level_metadata.rgba64_sha256 =
            sha256_hex(doubles_as_little_endian(level.rgba64));
        level_metadata.sampled_rgba64_sha256 =
            sha256_hex(doubles_as_little_endian(level.sampled_rgba64));
        const std::uint64_t level_resident = level.rgba8.size() +
            static_cast<std::uint64_t>(level.rgba64.size()) * sizeof(double) +
            static_cast<std::uint64_t>(level.sampled_rgba64.size()) * sizeof(double);
        if (level_resident > kMaximumResidentDecodedBytes - resident) {
            fail("DECODED_CACHE_CAPACITY",
                 "one decoded material mip-chain exceeds the resident limit");
        }
        resident += level_resident;
        entry.levels.push_back(std::move(level));
        entry.level_metadata.push_back(std::move(level_metadata));
    }
    if (resident > kMaximumResidentDecodedBytes -
                       implementation_->resident_decoded_bytes) {
        fail("DECODED_CACHE_CAPACITY",
             "decoded material mip-chain cache exceeds 1 GiB limit");
    }
    entry.metadata = mip_chain_metadata(
        entry.texture_name, entry.source_format, entry.authored_source_sha256,
        entry.manifest_sha256, entry.color_space, entry.levels,
        entry.level_metadata);
    entry.level_views.resize(entry.levels.size());
    for (std::size_t index = 0; index < entry.levels.size(); ++index) {
        const auto& level = entry.levels[index];
        const auto& metadata = entry.level_metadata[index];
        entry.level_views[index] = DecodedTextureMipLevelView{
            metadata.level,
            level.width,
            level.height,
            level.rgba8,
            level.rgba64,
            level.sampled_rgba64,
            metadata.source_sha256,
            metadata.rgba8_sha256,
            metadata.rgba64_sha256,
            metadata.sampled_rgba64_sha256,
        };
    }
    implementation_->resident_decoded_bytes += resident;
    auto [inserted, unused] = implementation_->texture_mip_chain_entries.emplace(
        canonical_chain_key, std::move(entry));
    (void)unused;
    return DecodedTextureMipChainResult{&inserted->second.metadata, false};
}

std::optional<DecodedObjView> DecodedAssetCache::find_obj(
    const std::wstring& canonical_path_key, const std::string& source_sha256) {
    validate_cache_key(canonical_path_key);
    validate_sha256_seal(source_sha256);
    const auto found = implementation_->obj_entries.find(canonical_path_key);
    if (found == implementation_->obj_entries.end()) return std::nullopt;
    auto& entry = found->second;
    if (entry.source_sha256 != source_sha256) {
        fail("DECODED_SOURCE_CHANGED", "cached OBJ source seal changed");
    }
    entry.getter_published = true;
    return DecodedObjView{
        &entry.mesh,
        &entry.metadata,
        entry.named_uv_views,
        entry.source_sha256,
        entry.sidecar_source_sha256,
    };
}

DecodedObjView DecodedAssetCache::get_obj(
    const std::wstring& canonical_path_key, const std::string& source_sha256) {
    std::optional<DecodedObjView> found = find_obj(canonical_path_key, source_sha256);
    if (!found.has_value()) {
        fail("DECODED_CACHE_MISS", "decoded OBJ key is not resident");
    }
    return *found;
}

DecodedObjView DecodedAssetCache::get_obj_with_named_uv(
    const std::wstring& canonical_path_key, const std::string& obj_source_sha256,
    const std::string& sidecar_source_sha256) {
    validate_cache_key(canonical_path_key);
    validate_sha256_seal(obj_source_sha256);
    validate_sha256_seal(sidecar_source_sha256);
    const auto found = implementation_->obj_entries.find(canonical_path_key);
    if (found == implementation_->obj_entries.end()) {
        fail("DECODED_CACHE_MISS", "decoded OBJ key is not resident");
    }
    auto& entry = found->second;
    if (entry.source_sha256 != obj_source_sha256) {
        fail("DECODED_SOURCE_CHANGED", "cached OBJ source seal changed");
    }
    if (entry.sidecar_source_sha256.empty()) {
        fail("NAMED_UV_NOT_ATTACHED", "decoded OBJ has no attached named-UV sidecar");
    }
    if (entry.sidecar_source_sha256 != sidecar_source_sha256) {
        fail("DECODED_SOURCE_CHANGED", "cached named-UV source seal changed");
    }
    entry.getter_published = true;
    return DecodedObjView{
        &entry.mesh,
        &entry.metadata,
        entry.named_uv_views,
        entry.source_sha256,
        entry.sidecar_source_sha256,
    };
}

std::optional<DecodedTextureView> DecodedAssetCache::find_texture(
    const std::wstring& canonical_path_key, const std::string& source_sha256) {
    validate_cache_key(canonical_path_key);
    validate_sha256_seal(source_sha256);
    const auto found = implementation_->texture_entries.find(canonical_path_key);
    if (found == implementation_->texture_entries.end()) return std::nullopt;
    const auto& entry = found->second;
    if (entry.source_sha256 != source_sha256) {
        fail("DECODED_SOURCE_CHANGED", "cached PNG source seal changed");
    }
    return DecodedTextureView{&entry.texture, &entry.metadata, entry.source_sha256};
}

DecodedTextureView DecodedAssetCache::get_texture(
    const std::wstring& canonical_path_key, const std::string& source_sha256) {
    std::optional<DecodedTextureView> found =
        find_texture(canonical_path_key, source_sha256);
    if (!found.has_value()) {
        fail("DECODED_CACHE_MISS", "decoded texture key is not resident");
    }
    return *found;
}

std::optional<DecodedTextureMipChainView>
DecodedAssetCache::find_texture_mip_chain(
    const std::wstring& canonical_chain_key,
    const std::string& manifest_sha256,
    const std::string& authored_source_sha256) {
    validate_cache_key(canonical_chain_key);
    validate_sha256_seal(manifest_sha256);
    validate_sha256_seal(authored_source_sha256);
    const auto found =
        implementation_->texture_mip_chain_entries.find(canonical_chain_key);
    if (found == implementation_->texture_mip_chain_entries.end()) {
        return std::nullopt;
    }
    const auto& entry = found->second;
    if (entry.manifest_sha256 != manifest_sha256 ||
        entry.authored_source_sha256 != authored_source_sha256) {
        fail("DECODED_SOURCE_CHANGED", "cached material mip-chain source seal changed");
    }
    return DecodedTextureMipChainView{
        entry.texture_name,
        entry.source_format,
        entry.authored_source_sha256,
        entry.manifest_sha256,
        entry.color_space,
        entry.level_views,
        &entry.metadata,
    };
}

DecodedTextureMipChainView DecodedAssetCache::get_texture_mip_chain(
    const std::wstring& canonical_chain_key,
    const std::string& manifest_sha256,
    const std::string& authored_source_sha256) {
    std::optional<DecodedTextureMipChainView> found = find_texture_mip_chain(
        canonical_chain_key, manifest_sha256, authored_source_sha256);
    if (!found.has_value()) {
        fail("DECODED_CACHE_MISS", "decoded material mip-chain key is not resident");
    }
    return *found;
}

std::size_t DecodedAssetCache::obj_entry_count() const noexcept {
    return implementation_->obj_entries.size();
}

std::size_t DecodedAssetCache::texture_entry_count() const noexcept {
    return implementation_->texture_entries.size();
}

std::size_t DecodedAssetCache::texture_mip_chain_entry_count() const noexcept {
    return implementation_->texture_mip_chain_entries.size();
}

std::uint64_t DecodedAssetCache::resident_decoded_bytes() const noexcept {
    return implementation_->resident_decoded_bytes;
}

} // namespace native_runtime
