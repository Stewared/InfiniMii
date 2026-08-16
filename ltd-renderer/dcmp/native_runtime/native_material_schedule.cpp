#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include "native_material_schedule.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstring>
#include <limits>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace {

class Sha256 final {
 public:
  void Update(const void* source, std::size_t size) {
    const auto* bytes = static_cast<const std::uint8_t*>(source);
    total_ += size;
    for (std::size_t index = 0; index < size; ++index) {
      block_[used_++] = bytes[index];
      if (used_ == block_.size()) {
        Compress(block_.data());
        used_ = 0;
      }
    }
  }

  template <class Integer>
  void Little(Integer value) {
    static_assert(std::is_unsigned_v<Integer>);
    std::array<std::uint8_t, sizeof(Integer)> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
      bytes[index] = static_cast<std::uint8_t>(value >> (index * 8u));
    }
    Update(bytes.data(), bytes.size());
  }

  std::array<std::uint8_t, 32> Final() {
    const std::uint64_t bit_count = static_cast<std::uint64_t>(total_) * 8u;
    block_[used_++] = 0x80u;
    if (used_ > 56) {
      std::fill(block_.begin() + static_cast<std::ptrdiff_t>(used_), block_.end(),
                static_cast<std::uint8_t>(0));
      Compress(block_.data());
      used_ = 0;
    }
    std::fill(block_.begin() + static_cast<std::ptrdiff_t>(used_), block_.begin() + 56,
              static_cast<std::uint8_t>(0));
    for (std::size_t index = 0; index < 8; ++index) {
      block_[63 - index] = static_cast<std::uint8_t>(bit_count >> (index * 8u));
    }
    Compress(block_.data());
    std::array<std::uint8_t, 32> result{};
    for (std::size_t index = 0; index < state_.size(); ++index) {
      result[index * 4] = static_cast<std::uint8_t>(state_[index] >> 24u);
      result[index * 4 + 1] = static_cast<std::uint8_t>(state_[index] >> 16u);
      result[index * 4 + 2] = static_cast<std::uint8_t>(state_[index] >> 8u);
      result[index * 4 + 3] = static_cast<std::uint8_t>(state_[index]);
    }
    return result;
  }

 private:
  static constexpr std::array<std::uint32_t, 64> kRound = {
      0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
      0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
      0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
      0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
      0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
      0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
      0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
      0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
      0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
      0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
      0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
      0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
      0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
  };

  static std::uint32_t Rotate(std::uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32u - bits));
  }

  void Compress(const std::uint8_t* input) {
    std::array<std::uint32_t, 64> words{};
    for (std::size_t index = 0; index < 16; ++index) {
      const std::size_t offset = index * 4;
      words[index] = (static_cast<std::uint32_t>(input[offset]) << 24u) |
                     (static_cast<std::uint32_t>(input[offset + 1]) << 16u) |
                     (static_cast<std::uint32_t>(input[offset + 2]) << 8u) |
                     static_cast<std::uint32_t>(input[offset + 3]);
    }
    for (std::size_t index = 16; index < words.size(); ++index) {
      const std::uint32_t s0 = Rotate(words[index - 15], 7) ^
                               Rotate(words[index - 15], 18) ^
                               (words[index - 15] >> 3u);
      const std::uint32_t s1 = Rotate(words[index - 2], 17) ^
                               Rotate(words[index - 2], 19) ^
                               (words[index - 2] >> 10u);
      words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (std::size_t index = 0; index < words.size(); ++index) {
      const std::uint32_t big1 = Rotate(e, 6) ^ Rotate(e, 11) ^ Rotate(e, 25);
      const std::uint32_t choice = (e & f) ^ (~e & g);
      const std::uint32_t temp1 = h + big1 + choice + kRound[index] + words[index];
      const std::uint32_t big0 = Rotate(a, 2) ^ Rotate(a, 13) ^ Rotate(a, 22);
      const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t temp2 = big0 + majority;
      h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
  }

  std::array<std::uint32_t, 8> state_ = {
      0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
      0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
  };
  std::array<std::uint8_t, 64> block_{};
  std::size_t used_ = 0;
  std::size_t total_ = 0;
};

class PlatformSha256 final {
 public:
  PlatformSha256() {
    ok_ = BCryptOpenAlgorithmProvider(
              &algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
          BCryptCreateHash(algorithm_, &hash_, nullptr, 0, nullptr, 0, 0) >= 0;
    if (!ok_) Reset();
  }
  ~PlatformSha256() { Reset(); }
  PlatformSha256(const PlatformSha256&) = delete;
  PlatformSha256& operator=(const PlatformSha256&) = delete;

  bool ok() const noexcept { return ok_; }
  bool Update(const void* source, std::size_t size) {
    if (!ok_ || (size != 0 && source == nullptr) || finalized_) return false;
    const auto* bytes = static_cast<const std::uint8_t*>(source);
    std::size_t cursor = 0;
    while (cursor < size) {
      const std::size_t count = std::min<std::size_t>(
          size - cursor, std::numeric_limits<ULONG>::max());
      if (BCryptHashData(hash_, const_cast<PUCHAR>(bytes + cursor),
                         static_cast<ULONG>(count), 0) < 0) return false;
      cursor += count;
    }
    return true;
  }
  template <class Integer> bool Little(Integer value) {
    static_assert(std::is_unsigned_v<Integer>);
    std::array<std::uint8_t, sizeof(Integer)> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index)
      bytes[index] = static_cast<std::uint8_t>(value >> (index * 8u));
    return Update(bytes.data(), bytes.size());
  }
  bool Final(std::uint8_t output[32]) {
    if (!ok_ || finalized_ || output == nullptr ||
        BCryptFinishHash(hash_, output, 32, 0) < 0) return false;
    finalized_ = true;
    return true;
  }

 private:
  void Reset() noexcept {
    if (hash_ != nullptr) BCryptDestroyHash(hash_);
    if (algorithm_ != nullptr) BCryptCloseAlgorithmProvider(algorithm_, 0);
    hash_ = nullptr;algorithm_ = nullptr;ok_ = false;
  }
  BCRYPT_ALG_HANDLE algorithm_ = nullptr;
  BCRYPT_HASH_HANDLE hash_ = nullptr;
  bool ok_ = false;
  bool finalized_ = false;
};

constexpr std::uint32_t kKnownFlags =
    LTD_NATIVE_MATERIAL_LINEAR_FRAMEBUFFER | LTD_NATIVE_MATERIAL_PERSPECTIVE |
    LTD_NATIVE_MATERIAL_DEPTH_WRITE | LTD_NATIVE_MATERIAL_BLEND |
    LTD_NATIVE_MATERIAL_CULL_BACK | LTD_NATIVE_MATERIAL_CLOCKWISE |
    LTD_NATIVE_MATERIAL_LINEAR_LIGHTING | LTD_NATIVE_MATERIAL_GAMMA_LIGHTING |
    LTD_NATIVE_MATERIAL_CHEAP_SSS | LTD_NATIVE_MATERIAL_ANISOTROPIC |
    LTD_NATIVE_MATERIAL_FRONT_EDGE | LTD_NATIVE_MATERIAL_RECEIVES_FACE_SHADOW |
    LTD_NATIVE_MATERIAL_CASTS_FACE_SHADOW | LTD_NATIVE_MATERIAL_HAS_UV |
    LTD_NATIVE_MATERIAL_HAS_NORMAL | LTD_NATIVE_MATERIAL_HAS_U2 |
    LTD_NATIVE_MATERIAL_MASK_USER0;

constexpr std::uint32_t kBase = LTD_NATIVE_MATERIAL_LINEAR_FRAMEBUFFER |
                                LTD_NATIVE_MATERIAL_PERSPECTIVE |
                                LTD_NATIVE_MATERIAL_DEPTH_WRITE;
constexpr std::uint32_t kGeometry = LTD_NATIVE_MATERIAL_HAS_UV |
                                    LTD_NATIVE_MATERIAL_HAS_NORMAL;

struct Classification {
  ltd_native_draw_kernel kernel = LTD_NATIVE_DRAW_NONE;
  std::uint16_t profile = 0;
  std::uint8_t abi = 0;
  bool accepted = false;
};

struct BodyRule {
  std::string_view group;
  std::uint16_t program;
  std::uint32_t triangles;
  bool tops;
};

constexpr std::array<BodyRule, 9> kBodyRules = {{
    {"BodyElbow__mt_Tops", 336, 212, true},
    {"BodyFoot__mt_Socks", 324, 268, false},
    {"BodyHand__mt_Tops", 336, 392, true},
    {"BodyHip__mt_Socks", 324, 12, false},
    {"BodyKnee__mt_Socks", 336, 124, false},
    {"BodyLeg__mt_Socks", 324, 240, false},
    {"BodyShoulder__mt_Tops", 348, 226, true},
    {"BodyThigh__mt_Socks", 336, 96, false},
    {"BodyWaist__mt_Tops", 336, 80, true},
}};

std::array<std::uint8_t, 32> Hex(std::string_view text) {
  std::array<std::uint8_t, 32> result{};
  auto nibble = [](char value) -> std::uint8_t {
    if (value >= '0' && value <= '9') return static_cast<std::uint8_t>(value - '0');
    return static_cast<std::uint8_t>(value - 'a' + 10);
  };
  for (std::size_t index = 0; index < result.size(); ++index) {
    result[index] = static_cast<std::uint8_t>((nibble(text[index * 2]) << 4u) |
                                              nibble(text[index * 2 + 1]));
  }
  return result;
}

bool Equals(const std::uint8_t* left, const std::array<std::uint8_t, 32>& right) {
  return std::memcmp(left, right.data(), right.size()) == 0;
}

bool ValidString(const char* value) {
  if (value == nullptr) return false;
  for (std::size_t index = 0; index < 128; ++index) {
    const unsigned char byte = static_cast<unsigned char>(value[index]);
    if (byte == 0) return index != 0;
    if (byte < 0x20 || byte > 0x7e) return false;
  }
  return false;
}

bool Finite(const double* values, std::size_t count) {
  for (std::size_t index = 0; index < count; ++index) {
    if (!std::isfinite(values[index])) return false;
  }
  return true;
}

const ltd_native_source_texture* FindTexture(
    const ltd_native_source_draw& draw, std::uint16_t role) {
  const ltd_native_source_texture* found = nullptr;
  for (std::uint32_t index = 0; index < draw.texture_count; ++index) {
    if (draw.textures[index].role != role) continue;
    if (found != nullptr) return reinterpret_cast<const ltd_native_source_texture*>(1);
    found = &draw.textures[index];
  }
  return found;
}

bool ValidTexture(const ltd_native_source_texture& texture) {
  if (!ValidString(texture.source_key) || texture.reserved != 0 ||
      texture.levels == nullptr || texture.level_count == 0 ||
      texture.level_count > LTD_NATIVE_MATERIAL_SCHEDULE_MAX_MIPS ||
      texture.address_u > LTD_NATIVE_ADDRESS_MIRROR ||
      texture.address_v > LTD_NATIVE_ADDRESS_MIRROR ||
      texture.mip_filter > LTD_NATIVE_MIP_LINEAR || texture.hardware_srgb > 1) {
    return false;
  }
  for (std::uint32_t index = 0; index < texture.level_count; ++index) {
    if (texture.levels[index].height == 0 || texture.levels[index].width == 0) return false;
    if (index != 0 &&
        (texture.levels[index].height > texture.levels[index - 1].height ||
         texture.levels[index].width > texture.levels[index - 1].width)) return false;
  }
  return true;
}

bool Extents(
    const ltd_native_source_texture* texture,
    std::span<const ltd_native_mip_extent> expected) {
  if (texture == nullptr || texture == reinterpret_cast<const ltd_native_source_texture*>(1) ||
      texture->level_count != expected.size()) return false;
  return std::equal(expected.begin(), expected.end(), texture->levels,
                    [](const auto& left, const auto& right) {
                      return left.height == right.height && left.width == right.width;
                    });
}

constexpr std::array<ltd_native_mip_extent, 9> kTops = {{
    {480,384},{240,192},{120,96},{60,48},{30,24},{15,12},{7,6},{3,3},{1,1}
}};
constexpr std::array<ltd_native_mip_extent, 9> kBottoms = {{
    {288,384},{144,192},{72,96},{36,48},{18,24},{9,12},{4,6},{2,3},{1,1}
}};
constexpr std::array<ltd_native_mip_extent, 9> kShoes = {{
    {256,256},{128,128},{64,64},{32,32},{16,16},{8,8},{4,4},{2,2},{1,1}
}};
constexpr std::array<ltd_native_mip_extent, 4> kMic = {{{8,8},{4,4},{2,2},{1,1}}};
constexpr std::array<ltd_native_mip_extent, 8> kNose = {{
    {128,128},{64,64},{32,32},{16,16},{8,8},{4,4},{2,2},{1,1}
}};
constexpr std::array<ltd_native_mip_extent, 10> kHeadNormal = {{
    {512,512},{256,256},{128,128},{64,64},{32,32},{16,16},{8,8},{4,4},{2,2},{1,1}
}};

bool Sampler(const ltd_native_source_texture* texture, std::uint8_t address_u,
             std::uint8_t address_v, std::uint8_t filter, std::uint8_t srgb) {
  return texture != nullptr && texture != reinterpret_cast<const ltd_native_source_texture*>(1) &&
         texture->address_u == address_u && texture->address_v == address_v &&
         texture->mip_filter == filter && texture->hardware_srgb == srgb;
}

bool ValidateTexturePlan(const ltd_native_source_draw& draw, const Classification& kind) {
  if (draw.texture_count > LTD_NATIVE_MATERIAL_SCHEDULE_MAX_TEXTURES ||
      (draw.texture_count != 0 && draw.textures == nullptr)) return false;
  for (std::uint32_t index = 0; index < draw.texture_count; ++index) {
    if (!ValidTexture(draw.textures[index])) return false;
    for (std::uint32_t other = index + 1; other < draw.texture_count; ++other) {
      if (draw.textures[index].role == draw.textures[other].role) return false;
    }
  }
  const auto* albedo = FindTexture(draw, LTD_NATIVE_TEXTURE_ALBEDO);
  const auto* normal = FindTexture(draw, LTD_NATIVE_TEXTURE_NORMAL);
  const auto* skin = FindTexture(draw, LTD_NATIVE_TEXTURE_SKIN_MASK);
  const auto* mic = FindTexture(draw, LTD_NATIVE_TEXTURE_MATERIAL_INFORMATION);
  const auto* parallax = FindTexture(draw, LTD_NATIVE_TEXTURE_PARALLAX);
  const auto* specular = FindTexture(draw, LTD_NATIVE_TEXTURE_SPECULAR);
  const auto* gradient = FindTexture(draw, LTD_NATIVE_TEXTURE_GRADIENT);
  const auto* generated = FindTexture(draw, LTD_NATIVE_TEXTURE_MASK_GENERATED);
  const auto* user0 = FindTexture(draw, LTD_NATIVE_TEXTURE_MASK_USER0);

  switch (kind.kernel) {
    case LTD_NATIVE_DRAW_BODY_ABI1: {
      const auto& shapes = std::string_view(draw.group).find("_Tops") != std::string_view::npos
                               ? std::span<const ltd_native_mip_extent>(kTops)
                               : std::span<const ltd_native_mip_extent>(kBottoms);
      return draw.texture_count == 4 && Extents(albedo, shapes) && Extents(normal, shapes) &&
             Extents(skin, shapes) && Extents(mic, kMic) &&
             Sampler(albedo, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_MIP_LINEAR, 1) &&
             Sampler(normal, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_MIP_POINT, 0) &&
             Sampler(skin, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_MIP_LINEAR, 0) &&
             Sampler(mic, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_MIP_POINT, 0);
    }
    case LTD_NATIVE_DRAW_OUTFIT_ABI2: {
      const auto shapes = kind.profile == 984 ? std::span<const ltd_native_mip_extent>(kTops) :
                          kind.profile == 936 ? std::span<const ltd_native_mip_extent>(kBottoms) :
                                                std::span<const ltd_native_mip_extent>(kShoes);
      const auto roughness_shapes = kind.profile == 936
                                        ? std::span<const ltd_native_mip_extent>(kMic)
                                        : shapes;
      const auto* roughness = FindTexture(draw, LTD_NATIVE_TEXTURE_MATERIAL_INFORMATION);
      return draw.texture_count == 3 && Extents(albedo, shapes) && Extents(normal, shapes) &&
             Extents(roughness, roughness_shapes) &&
             Sampler(albedo, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_MIP_LINEAR, 1) &&
             Sampler(normal, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_MIP_POINT, 0) &&
             Sampler(roughness, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_MIP_POINT, 0);
    }
    case LTD_NATIVE_DRAW_MASK0_ABI1:
      return (draw.texture_count == 1 || draw.texture_count == 2) && generated != nullptr &&
             generated->level_count == 1 && generated->levels[0].height == 256 &&
             generated->levels[0].width == 256 && generated->mip_filter == LTD_NATIVE_MIP_POINT &&
             ((draw.material_flags & LTD_NATIVE_MATERIAL_MASK_USER0) != 0) == (user0 != nullptr) &&
             (user0 == nullptr || (user0->level_count == 1 && user0->levels[0].height == 512 &&
                                   user0->levels[0].width == 512));
    case LTD_NATIVE_DRAW_HEAD816_ABI2:
      return (draw.texture_count == 1 || draw.texture_count == 2) && Extents(normal, kHeadNormal) &&
             Sampler(normal, LTD_NATIVE_ADDRESS_REPEAT, LTD_NATIVE_ADDRESS_REPEAT, LTD_NATIVE_MIP_POINT, 0) &&
             (albedo == nullptr || (albedo->level_count == 1 &&
                                    Sampler(albedo, LTD_NATIVE_ADDRESS_MIRROR, LTD_NATIVE_ADDRESS_REPEAT,
                                            LTD_NATIVE_MIP_POINT, 1)));
    case LTD_NATIVE_DRAW_PLAIN_SKIN_ABI1:
      if (kind.profile == 372) return draw.texture_count == 0;
      return draw.texture_count == 2 && Extents(parallax, kNose) && Extents(specular, kNose) &&
             Sampler(parallax, LTD_NATIVE_ADDRESS_REPEAT, LTD_NATIVE_ADDRESS_REPEAT, LTD_NATIVE_MIP_POINT, 0) &&
             Sampler(specular, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_ADDRESS_CLAMP, LTD_NATIVE_MIP_POINT, 0);
    case LTD_NATIVE_DRAW_HAIR_ABI2:
      if (kind.profile == 468) return draw.texture_count == 1 && specular != nullptr;
      return draw.texture_count == 2 && specular != nullptr && gradient != nullptr &&
             gradient->mip_filter == LTD_NATIVE_MIP_LINEAR;
    default:
      return false;
  }
}

bool ExactFlags(const ltd_native_source_draw& draw, std::uint32_t expected,
                std::uint32_t allowed_variation = 0) {
  if ((draw.material_flags & ~kKnownFlags) != 0) return false;
  return (draw.material_flags & ~allowed_variation) == expected;
}

Classification Classify(const ltd_native_source_draw& draw) {
  const std::string_view group(draw.group);
  Classification result{};
  switch (draw.family) {
    case LTD_NATIVE_FAMILY_BODY:
      for (const auto& rule : kBodyRules) {
        if (group == rule.group && draw.gameall_program == rule.program &&
            draw.submitted_triangle_count == rule.triangles &&
            ExactFlags(draw, kBase | LTD_NATIVE_MATERIAL_CULL_BACK |
                                 LTD_NATIVE_MATERIAL_LINEAR_LIGHTING |
                                 LTD_NATIVE_MATERIAL_CHEAP_SSS | kGeometry)) {
          return {LTD_NATIVE_DRAW_BODY_ABI1, rule.program, 1, true};
        }
      }
      break;
    case LTD_NATIVE_FAMILY_OUTFIT_TOPS:
    case LTD_NATIVE_FAMILY_OUTFIT_BOTTOMS:
    case LTD_NATIVE_FAMILY_OUTFIT_SHOES: {
      const bool tops = draw.family == LTD_NATIVE_FAMILY_OUTFIT_TOPS;
      const bool bottoms = draw.family == LTD_NATIVE_FAMILY_OUTFIT_BOTTOMS;
      const std::uint16_t profile = tops ? 984 : bottoms ? 936 : 912;
      const std::uint32_t triangles = tops ? 1104 : bottoms ? 774 : 508;
      const std::string_view expected = tops ? "Tops__mt_Body" :
                                        bottoms ? "Bottoms__mt_Body" : "Shoes__mt_Body";
      if (draw.gameall_program == profile && group == expected &&
          draw.submitted_triangle_count == triangles &&
          ExactFlags(draw, kBase | LTD_NATIVE_MATERIAL_LINEAR_LIGHTING | kGeometry)) {
        return {LTD_NATIVE_DRAW_OUTFIT_ABI2, profile, 2, true};
      }
      break;
    }
    case LTD_NATIVE_FAMILY_MASK:
      if (draw.gameall_program == 0 && group == "Mask__mt_Mask" &&
          draw.submitted_triangle_count == 288 &&
          ExactFlags(draw, kBase | LTD_NATIVE_MATERIAL_LINEAR_LIGHTING | kGeometry,
                     LTD_NATIVE_MATERIAL_MASK_USER0 | LTD_NATIVE_MATERIAL_HAS_U2)) {
        return {LTD_NATIVE_DRAW_MASK0_ABI1, 0, 1, true};
      }
      break;
    case LTD_NATIVE_FAMILY_HEAD:
      if (draw.gameall_program == 816 && group == "Head__mt_Head" &&
          draw.submitted_triangle_count != 0 &&
          ExactFlags(draw, kBase | LTD_NATIVE_MATERIAL_CULL_BACK |
                               LTD_NATIVE_MATERIAL_LINEAR_LIGHTING |
                               LTD_NATIVE_MATERIAL_CHEAP_SSS |
                               LTD_NATIVE_MATERIAL_RECEIVES_FACE_SHADOW |
                               LTD_NATIVE_MATERIAL_HAS_NORMAL | LTD_NATIVE_MATERIAL_HAS_U2,
                     LTD_NATIVE_MATERIAL_HAS_UV)) {
        return {LTD_NATIVE_DRAW_HEAD816_ABI2, 816, 2, true};
      }
      break;
    case LTD_NATIVE_FAMILY_EAR:
      if (draw.gameall_program == 372 && group == "Ear__mt_Ear" &&
          draw.submitted_triangle_count == 360 &&
          ExactFlags(draw, kBase | LTD_NATIVE_MATERIAL_CULL_BACK |
                               LTD_NATIVE_MATERIAL_LINEAR_LIGHTING |
                               LTD_NATIVE_MATERIAL_CHEAP_SSS |
                               LTD_NATIVE_MATERIAL_RECEIVES_FACE_SHADOW |
                               LTD_NATIVE_MATERIAL_HAS_NORMAL |
                               LTD_NATIVE_MATERIAL_HAS_UV,
                     LTD_NATIVE_MATERIAL_CLOCKWISE)) {
        return {LTD_NATIVE_DRAW_PLAIN_SKIN_ABI1, 372, 1, true};
      }
      break;
    case LTD_NATIVE_FAMILY_NOSE:
      if (draw.gameall_program == 756 && group == "Nose__mt_Nose" &&
          draw.submitted_triangle_count == 370 &&
          ExactFlags(draw, kBase | LTD_NATIVE_MATERIAL_CULL_BACK |
                               LTD_NATIVE_MATERIAL_LINEAR_LIGHTING |
                               LTD_NATIVE_MATERIAL_CHEAP_SSS |
                               LTD_NATIVE_MATERIAL_RECEIVES_FACE_SHADOW | kGeometry)) {
        return {LTD_NATIVE_DRAW_PLAIN_SKIN_ABI1, 756, 1, true};
      }
      break;
    case LTD_NATIVE_FAMILY_HAIR_ANISOTROPIC:
      if (draw.gameall_program == 612 && group == "Hair__mt_Hair" &&
          draw.submitted_triangle_count != 0 &&
          ExactFlags(draw, kBase | LTD_NATIVE_MATERIAL_CULL_BACK |
                               LTD_NATIVE_MATERIAL_GAMMA_LIGHTING |
                               LTD_NATIVE_MATERIAL_ANISOTROPIC |
                               LTD_NATIVE_MATERIAL_FRONT_EDGE |
                               LTD_NATIVE_MATERIAL_CASTS_FACE_SHADOW | kGeometry)) {
        return {LTD_NATIVE_DRAW_HAIR_ABI2, 612, 2, true};
      }
      break;
    case LTD_NATIVE_FAMILY_HAIR_ENDPOINT:
      if (draw.gameall_program == 564 && group == "Hair__mt_Hair" &&
          draw.submitted_triangle_count != 0 &&
          ExactFlags(draw, kBase | LTD_NATIVE_MATERIAL_CULL_BACK |
                               LTD_NATIVE_MATERIAL_GAMMA_LIGHTING |
                               LTD_NATIVE_MATERIAL_CASTS_FACE_SHADOW | kGeometry)) {
        return {LTD_NATIVE_DRAW_HAIR_ABI2, 564, 2, true};
      }
      break;
    case LTD_NATIVE_FAMILY_BEARD_ANISOTROPIC:
      if (draw.gameall_program == 468 && group == "Beard__mt_Beard" &&
          draw.submitted_triangle_count != 0 &&
          ExactFlags(draw, kBase | LTD_NATIVE_MATERIAL_CULL_BACK |
                               LTD_NATIVE_MATERIAL_LINEAR_LIGHTING |
                               LTD_NATIVE_MATERIAL_ANISOTROPIC |
                               LTD_NATIVE_MATERIAL_FRONT_EDGE | kGeometry)) {
        return {LTD_NATIVE_DRAW_HAIR_ABI2, 468, 2, true};
      }
      break;
    default:
      break;
  }
  return result;
}

void HashTextures(const ltd_native_source_draw& draw, std::uint8_t output[32]) {
  Sha256 sha;
  static constexpr std::string_view domain = "ltd.material.texture-plan.v1\0";
  sha.Update(domain.data(), domain.size());
  sha.Little<std::uint32_t>(draw.texture_count);
  std::vector<const ltd_native_source_texture*> ordered;
  ordered.reserve(draw.texture_count);
  for (std::uint32_t index = 0; index < draw.texture_count; ++index) ordered.push_back(&draw.textures[index]);
  std::sort(ordered.begin(), ordered.end(), [](const auto* left, const auto* right) {
    return left->role < right->role;
  });
  for (const auto* texture : ordered) {
    sha.Little<std::uint16_t>(texture->role);
    sha.Little<std::uint8_t>(texture->address_u);
    sha.Little<std::uint8_t>(texture->address_v);
    sha.Little<std::uint8_t>(texture->mip_filter);
    sha.Little<std::uint8_t>(texture->hardware_srgb);
    const std::string_view key(texture->source_key);
    sha.Little<std::uint32_t>(static_cast<std::uint32_t>(key.size()));
    sha.Update(key.data(), key.size());
    sha.Little<std::uint32_t>(texture->level_count);
    for (std::uint32_t level = 0; level < texture->level_count; ++level) {
      sha.Little<std::uint32_t>(texture->levels[level].height);
      sha.Little<std::uint32_t>(texture->levels[level].width);
    }
    sha.Update(texture->decoded_chain_sha256, 32);
  }
  const auto digest = sha.Final();
  std::memcpy(output, digest.data(), digest.size());
}

bool HashPacked(const ltd_native_source_draw& draw, std::uint8_t output[32]) {
  if (draw.packed_field_count == 0 || draw.packed_fields == nullptr) return false;
  PlatformSha256 sha;
  if (!sha.ok()) return false;
  static constexpr std::string_view domain = "ltd.material.packed-abi.v1\0";
  if (!sha.Update(domain.data(), domain.size()) ||
      !sha.Little<std::uint16_t>(static_cast<std::uint16_t>(draw.family)) ||
      !sha.Little<std::uint16_t>(static_cast<std::uint16_t>(draw.gameall_program)) ||
      !sha.Little<std::uint32_t>(draw.packed_field_count)) return false;
  std::uint16_t previous = 0;
  for (std::uint32_t index = 0; index < draw.packed_field_count; ++index) {
    const auto& field = draw.packed_fields[index];
    if (field.tag == 0 || (index != 0 && field.tag <= previous) ||
        field.element_width == 0 || field.reserved != 0 ||
        (field.byte_count != 0 && field.bytes == nullptr) ||
        field.byte_count % field.element_width != 0) return false;
    previous = field.tag;
    if (!sha.Little<std::uint16_t>(field.tag) ||
        !sha.Little<std::uint16_t>(field.element_width) ||
        !sha.Little<std::uint64_t>(static_cast<std::uint64_t>(field.byte_count)) ||
        !sha.Update(field.bytes, field.byte_count)) return false;
  }
  return sha.Final(output);
}

bool ValidSeals(const ltd_native_material_source_seals& seals) {
  return Equals(seals.compose_sha256, Hex(LTD_NATIVE_MATERIAL_SCHEDULE_COMPOSE_SHA256)) &&
         Equals(seals.wrapper_sha256, Hex(LTD_NATIVE_MATERIAL_SCHEDULE_WRAPPER_SHA256)) &&
         Equals(seals.current_kernel_sha256, Hex(LTD_NATIVE_MATERIAL_SCHEDULE_CURRENT_KERNEL_SHA256)) &&
         Equals(seals.opaque_kernel_sha256, Hex(LTD_NATIVE_MATERIAL_SCHEDULE_OPAQUE_KERNEL_SHA256));
}

}  // namespace

uint32_t LTD_NATIVE_MATERIAL_SCHEDULE_CALL ltd_native_material_schedule_abi_version(void) {
  return LTD_NATIVE_MATERIAL_SCHEDULE_ABI_VERSION;
}

const char* LTD_NATIVE_MATERIAL_SCHEDULE_CALL ltd_native_material_schedule_contract_sha256(void) {
  return LTD_NATIVE_MATERIAL_SCHEDULE_CONTRACT_SHA256;
}

ltd_native_material_status LTD_NATIVE_MATERIAL_SCHEDULE_CALL
ltd_native_compile_material_schedule(
    const ltd_native_material_source_seals* seals,
    const ltd_native_source_draw* source_draws,
    size_t source_draw_count,
    ltd_native_compiled_draw* output,
    size_t output_capacity,
    size_t* output_count) {
  if (output_count == nullptr) return LTD_NATIVE_MATERIAL_INVALID_ARGUMENT;
  *output_count = 0;
  if (seals == nullptr || !ValidSeals(*seals)) return LTD_NATIVE_MATERIAL_SOURCE_MISMATCH;
  if (source_draws == nullptr || source_draw_count == 0 ||
      source_draw_count > LTD_NATIVE_MATERIAL_SCHEDULE_MAX_DRAWS) {
    return LTD_NATIVE_MATERIAL_INVALID_ARGUMENT;
  }

  std::vector<std::size_t> prefix;
  std::vector<std::size_t> opaque;
  std::vector<std::size_t> translucent;
  std::size_t head = source_draw_count;
  std::size_t accepted = 0;
  std::vector<Classification> classifications(source_draw_count);
  for (std::size_t index = 0; index < source_draw_count; ++index) {
    const auto& draw = source_draws[index];
    if (!ValidString(draw.model_key) || !ValidString(draw.resource_name) ||
        !ValidString(draw.group) || draw.authored_index != index ||
        draw.submitted_triangle_count == 0 || draw.candidate_triangle_count > draw.submitted_triangle_count ||
        !Finite(draw.transform, 16) || !Finite(draw.dynamic_values, 16) ||
        draw.gsys_priority < -32 || draw.gsys_priority > 31 ||
        (draw.material_flags & ~kKnownFlags) != 0) {
      return LTD_NATIVE_MATERIAL_INVALID_ARGUMENT;
    }
    if (std::string_view(draw.group) == "Head__mt_Head" && head == source_draw_count) head = index;
    classifications[index] = Classify(draw);
    if (classifications[index].accepted) {
      if (!ValidateTexturePlan(draw, classifications[index])) return LTD_NATIVE_MATERIAL_FINGERPRINT_MISMATCH;
      ++accepted;
    } else if (draw.family != LTD_NATIVE_FAMILY_UNSUPPORTED &&
               draw.family != LTD_NATIVE_FAMILY_NOSE_LINE) {
      return LTD_NATIVE_MATERIAL_UNSUPPORTED_PROFILE;
    }
  }
  if (head == source_draw_count) return LTD_NATIVE_MATERIAL_NO_HEAD_ANCHOR;
  if (output_capacity < accepted || (accepted != 0 && output == nullptr)) {
    *output_count = accepted;
    return LTD_NATIVE_MATERIAL_OUTPUT_TOO_SMALL;
  }

  for (std::size_t index = 0; index < head; ++index) prefix.push_back(index);
  for (std::size_t index = head; index < source_draw_count; ++index) {
    const auto flags = source_draws[index].material_flags;
    if ((flags & LTD_NATIVE_MATERIAL_BLEND) != 0 ||
        (flags & LTD_NATIVE_MATERIAL_DEPTH_WRITE) == 0) {
      translucent.push_back(index);
    } else {
      opaque.push_back(index);
    }
  }
  std::stable_sort(opaque.begin(), opaque.end(), [&](std::size_t left, std::size_t right) {
    return source_draws[left].gsys_priority < source_draws[right].gsys_priority;
  });
  std::vector<std::size_t> scheduled;
  scheduled.reserve(source_draw_count);
  scheduled.insert(scheduled.end(), prefix.begin(), prefix.end());
  scheduled.insert(scheduled.end(), opaque.begin(), opaque.end());
  scheduled.insert(scheduled.end(), translucent.begin(), translucent.end());

  std::size_t output_index = 0;
  for (std::size_t scheduled_index = 0; scheduled_index < scheduled.size(); ++scheduled_index) {
    const std::size_t source_index = scheduled[scheduled_index];
    const auto& kind = classifications[source_index];
    if (!kind.accepted) continue;
    const auto& source = source_draws[source_index];
    auto& target = output[output_index++];
    std::memset(&target, 0, sizeof(target));
    target.model_key = source.model_key;
    target.resource_name = source.resource_name;
    target.group = source.group;
    target.authored_index = source.authored_index;
    target.scheduled_index = static_cast<std::uint32_t>(scheduled_index);
    target.submitted_triangle_count = source.submitted_triangle_count;
    target.candidate_triangle_count = source.candidate_triangle_count;
    target.kernel = static_cast<std::uint16_t>(kind.kernel);
    target.profile = kind.profile;
    target.draw_abi_version = kind.abi;
    target.material_flags = source.material_flags;
    std::copy_n(source.transform, 16, target.transform);
    std::copy_n(source.dynamic_values, 16, target.dynamic_values);
    HashTextures(source, target.texture_plan_sha256);
    if (!HashPacked(source, target.packed_abi_input_sha256)) {
      *output_count = 0;
      return LTD_NATIVE_MATERIAL_FINGERPRINT_MISMATCH;
    }
  }
  *output_count = output_index;
  return LTD_NATIVE_MATERIAL_OK;
}

const char* LTD_NATIVE_MATERIAL_SCHEDULE_CALL
ltd_native_material_status_name(ltd_native_material_status status) {
  switch (status) {
    case LTD_NATIVE_MATERIAL_OK: return "ok";
    case LTD_NATIVE_MATERIAL_INVALID_ARGUMENT: return "invalid_argument";
    case LTD_NATIVE_MATERIAL_SOURCE_MISMATCH: return "source_mismatch";
    case LTD_NATIVE_MATERIAL_UNSUPPORTED_PROFILE: return "unsupported_profile";
    case LTD_NATIVE_MATERIAL_FINGERPRINT_MISMATCH: return "fingerprint_mismatch";
    case LTD_NATIVE_MATERIAL_OUTPUT_TOO_SMALL: return "output_too_small";
    case LTD_NATIVE_MATERIAL_NO_HEAD_ANCHOR: return "no_head_anchor";
    case LTD_NATIVE_MATERIAL_SCHEDULE_MISMATCH: return "schedule_mismatch";
    case LTD_NATIVE_MATERIAL_NONFINITE: return "nonfinite";
    case LTD_NATIVE_MATERIAL_DUPLICATE_BINDING: return "duplicate_binding";
    default: return "unknown";
  }
}
