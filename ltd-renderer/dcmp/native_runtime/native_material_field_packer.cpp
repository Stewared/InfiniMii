#include "native_material_field_packer.h"

#include "native_draw_runtime.h"
#include "native_draw_runtime_v2.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace {

class Sha256 final {
 public:
  void Update(const void* source, std::size_t size) {
    const auto* bytes = static_cast<const std::uint8_t*>(source);
    total_ += size;
    for (std::size_t index = 0; index < size; ++index) {
      block_[used_++] = bytes[index];
      if (used_ == block_.size()) { Compress(block_.data()); used_ = 0; }
    }
  }
  template <class Integer> void Little(Integer value) {
    static_assert(std::is_unsigned_v<Integer>);
    std::array<std::uint8_t, sizeof(Integer)> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index)
      bytes[index] = static_cast<std::uint8_t>(value >> (index * 8u));
    Update(bytes.data(), bytes.size());
  }
  std::array<std::uint8_t, 32> Final() {
    const std::uint64_t bits = static_cast<std::uint64_t>(total_) * 8u;
    block_[used_++] = 0x80u;
    if (used_ > 56) {
      std::fill(block_.begin() + static_cast<std::ptrdiff_t>(used_), block_.end(),
                std::uint8_t{0});
      Compress(block_.data()); used_ = 0;
    }
    std::fill(block_.begin() + static_cast<std::ptrdiff_t>(used_), block_.begin() + 56,
              std::uint8_t{0});
    for (std::size_t index = 0; index < 8; ++index)
      block_[63 - index] = static_cast<std::uint8_t>(bits >> (index * 8u));
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
      0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
      0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
      0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
      0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
      0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
      0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
      0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
      0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
      0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
      0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
      0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
  static std::uint32_t Rotate(std::uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32u - bits));
  }
  void Compress(const std::uint8_t* input) {
    std::array<std::uint32_t,64> words{};
    for(std::size_t index=0;index<16;++index){const std::size_t offset=index*4;
      words[index]=(static_cast<std::uint32_t>(input[offset])<<24u)|
        (static_cast<std::uint32_t>(input[offset+1])<<16u)|
        (static_cast<std::uint32_t>(input[offset+2])<<8u)|input[offset+3];}
    for(std::size_t index=16;index<64;++index){const auto s0=Rotate(words[index-15],7)^
      Rotate(words[index-15],18)^(words[index-15]>>3u);const auto s1=Rotate(words[index-2],17)^
      Rotate(words[index-2],19)^(words[index-2]>>10u);words[index]=words[index-16]+s0+words[index-7]+s1;}
    auto a=state_[0],b=state_[1],c=state_[2],d=state_[3],e=state_[4],f=state_[5],g=state_[6],h=state_[7];
    for(std::size_t index=0;index<64;++index){const auto big1=Rotate(e,6)^Rotate(e,11)^Rotate(e,25);
      const auto choice=(e&f)^(~e&g);const auto t1=h+big1+choice+kRound[index]+words[index];
      const auto big0=Rotate(a,2)^Rotate(a,13)^Rotate(a,22);const auto majority=(a&b)^(a&c)^(b&c);
      const auto t2=big0+majority;h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
    state_[0]+=a;state_[1]+=b;state_[2]+=c;state_[3]+=d;state_[4]+=e;state_[5]+=f;state_[6]+=g;state_[7]+=h;
  }
  std::array<std::uint32_t,8> state_={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,
      0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
  std::array<std::uint8_t,64> block_{};std::size_t used_=0,total_=0;
};

struct Failure final {
  ltd_native_material_field_status status;
  std::string message;
};

[[noreturn]] void Fail(ltd_native_material_field_status status, std::string message) {
  throw Failure{status, std::move(message)};
}

void Error(char* output, std::size_t capacity, std::string_view message) {
  if (output == nullptr || capacity == 0) return;
  const std::size_t count = std::min(capacity - 1, message.size());
  std::memcpy(output, message.data(), count);
  output[count] = '\0';
}

bool Text(const char* left, const char* right) {
  return left != nullptr && right != nullptr && std::strcmp(left, right) == 0;
}

bool Finite(const double* values, std::size_t count) {
  if (count != 0 && values == nullptr) return false;
  for (std::size_t index = 0; index < count; ++index) {
    if (!std::isfinite(values[index])) return false;
  }
  return true;
}

bool Seals(const ltd_native_material_field_source_seals& seals) {
  return Text(seals.scene_assembler_contract_sha256,
              LTD_NATIVE_SCENE_ASSEMBLER_CONTRACT_SHA256) &&
         Text(seals.material_schedule_contract_sha256,
              LTD_NATIVE_MATERIAL_SCHEDULE_CONTRACT_SHA256) &&
         Text(seals.draw_runtime_v1_contract_sha256,
              LTD_DRAW_RUNTIME_CONTRACT_SHA256) &&
         Text(seals.draw_runtime_v2_contract_sha256,
              LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256) &&
         Text(seals.material_provider_contract_sha256,
              "5dd81063b68f0badf794a00f1ee5a307f93316843721aaac36f81a9a5881e302") &&
         Text(seals.current_source_sha256,
              LTD_DRAW_RUNTIME_CURRENT_SOURCE_SHA256) &&
         Text(seals.opaque_source_sha256,
              LTD_DRAW_RUNTIME_OPAQUE_SOURCE_SHA256) &&
         Text(seals.wrapper_source_sha256,
              LTD_DRAW_RUNTIME_V2_WRAPPER_SHA256);
}

struct Profile final {
  std::uint32_t scene_profile;
  std::uint16_t family;
};

Profile Resolve(std::int32_t program) {
  switch (program) {
    case 324: return {LTD_NATIVE_SCENE_PROFILE_BODY324, LTD_NATIVE_FAMILY_BODY};
    case 336: return {LTD_NATIVE_SCENE_PROFILE_BODY336, LTD_NATIVE_FAMILY_BODY};
    case 348: return {LTD_NATIVE_SCENE_PROFILE_BODY348, LTD_NATIVE_FAMILY_BODY};
    case 372: return {LTD_NATIVE_SCENE_PROFILE_EAR372, LTD_NATIVE_FAMILY_EAR};
    case 756: return {LTD_NATIVE_SCENE_PROFILE_NOSE756, LTD_NATIVE_FAMILY_NOSE};
    case 0: return {LTD_NATIVE_SCENE_PROFILE_MASK0, LTD_NATIVE_FAMILY_MASK};
    case 816: return {LTD_NATIVE_SCENE_PROFILE_HEAD816, LTD_NATIVE_FAMILY_HEAD};
    case 612: return {LTD_NATIVE_SCENE_PROFILE_HAIR612,
                      LTD_NATIVE_FAMILY_HAIR_ANISOTROPIC};
    case 564: return {LTD_NATIVE_SCENE_PROFILE_HAIR564_EQUAL_ENDPOINT,
                      LTD_NATIVE_FAMILY_HAIR_ENDPOINT};
    case 468: return {LTD_NATIVE_SCENE_PROFILE_BEARD468,
                      LTD_NATIVE_FAMILY_BEARD_ANISOTROPIC};
    case 984: return {LTD_NATIVE_SCENE_PROFILE_OUTFIT_TOPS984,
                      LTD_NATIVE_FAMILY_OUTFIT_TOPS};
    case 936: return {LTD_NATIVE_SCENE_PROFILE_OUTFIT_BOTTOMS936,
                      LTD_NATIVE_FAMILY_OUTFIT_BOTTOMS};
    case 912: return {LTD_NATIVE_SCENE_PROFILE_OUTFIT_SHOES912,
                      LTD_NATIVE_FAMILY_OUTFIT_SHOES};
    default: Fail(LTD_NATIVE_MATERIAL_FIELD_PROFILE_UNSUPPORTED,
                  "unsupported GameAll profile " + std::to_string(program));
  }
}

}  // namespace

struct AlignedFieldBytes final {
  static constexpr std::size_t kAlignment = alignof(std::uint64_t);

  void Assign(const void* source, std::size_t size) {
    byte_count = size;
    words.assign((size + sizeof(std::uint64_t) - 1) / sizeof(std::uint64_t), 0);
    if (size != 0) std::memcpy(words.data(), source, size);
  }
  std::uint8_t* data() noexcept {
    return words.empty() ? nullptr : reinterpret_cast<std::uint8_t*>(words.data());
  }
  const std::uint8_t* data() const noexcept {
    return words.empty() ? nullptr :
        reinterpret_cast<const std::uint8_t*>(words.data());
  }

  std::vector<std::uint64_t> words;
  std::size_t byte_count = 0;
};

struct ltd_native_material_field_pack {
  ltd_native_source_draw source{};
  std::string model_key;
  std::string resource_name;
  std::string group;
  std::vector<std::string> texture_keys;
  std::vector<std::vector<ltd_native_mip_extent>> texture_extents;
  std::vector<ltd_native_source_texture> textures;
  std::vector<AlignedFieldBytes> field_bytes;
  std::vector<ltd_native_packed_field> fields;
};

namespace {

std::array<std::uint8_t, 32> ParseHex(const char* value, std::string_view label) {
  if (value == nullptr || std::strlen(value) != 64) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISMATCH,
         std::string(label) + " has no 64-digit SHA-256");
  }
  const auto nibble = [](char byte) -> int {
    if (byte >= '0' && byte <= '9') return byte - '0';
    if (byte >= 'a' && byte <= 'f') return byte - 'a' + 10;
    return -1;
  };
  std::array<std::uint8_t, 32> output{};
  for (std::size_t index = 0; index < output.size(); ++index) {
    const int high = nibble(value[index * 2]);
    const int low = nibble(value[index * 2 + 1]);
    if (high < 0 || low < 0) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISMATCH,
           std::string(label) + " is not lowercase SHA-256 hex");
    }
    output[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return output;
}

template <class Value>
void AddField(ltd_native_material_field_pack& pack, std::uint16_t tag,
              const Value* values, std::size_t count) {
  if (count != 0 && values == nullptr) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_INVALID_ARGUMENT,
         "packed field source is null");
  }
  if (tag == 0 || (!pack.fields.empty() && tag <= pack.fields.back().tag)) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_INVALID_ARGUMENT,
         "packed field tag order is invalid");
  }
  const std::size_t byte_count = count * sizeof(Value);
  pack.field_bytes.emplace_back();
  auto& bytes = pack.field_bytes.back();
  bytes.Assign(values, byte_count);
  pack.fields.push_back(ltd_native_packed_field{
      tag, static_cast<std::uint16_t>(sizeof(Value)), 0,
      bytes.data(), bytes.byte_count});
}

std::uint32_t ExpectedFieldCount(std::int32_t program) {
  switch (program) {
    case 324: case 336: case 348: return 26;
    case 372: case 756: return 11;
    case 0: return 12;
    case 816: return 22;
    case 612: case 564: case 468: return 10;
    case 984: case 936: case 912: return 20;
    default:
      Fail(LTD_NATIVE_MATERIAL_FIELD_PROFILE_UNSUPPORTED,
           "unsupported packed-proof profile " + std::to_string(program));
  }
}

void ValidateFieldCount(const ltd_native_material_field_pack& pack) {
  if (pack.fields.size() != ExpectedFieldCount(pack.source.gameall_program)) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_MATERIAL_MISMATCH,
         "packed field count differs from authenticated profile");
  }
}

void AddF64(ltd_native_material_field_pack& pack, std::uint16_t tag,
            const double* values, std::size_t count) {
  if (!Finite(values, count)) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_NONFINITE,
         "packed F64 field " + std::to_string(tag) + " is nonfinite");
  }
  AddField(pack, tag, values, count);
}
void AddI64(ltd_native_material_field_pack& pack, std::uint16_t tag,
            const std::int64_t* values, std::size_t count) {
  AddField(pack, tag, values, count);
}
void AddU8(ltd_native_material_field_pack& pack, std::uint16_t tag,
           const std::uint8_t* values, std::size_t count) {
  AddField(pack, tag, values, count);
}
void AddScalarF64(ltd_native_material_field_pack& pack, std::uint16_t tag,
                  double value) { AddF64(pack, tag, &value, 1); }
void AddScalarI64(ltd_native_material_field_pack& pack, std::uint16_t tag,
                  std::int64_t value) { AddI64(pack, tag, &value, 1); }

double Srgb(double value) {
  return value <= 0.04045
      ? value / 12.92
      : std::pow((value + 0.055) / 1.055, 2.4);
}

struct MipBank final {
  std::vector<double> texels;
  std::vector<std::int64_t> levels;
  std::uint32_t base_height = 0;
  std::uint32_t base_width = 0;
};

void ValidateImage(const ltd_face_const_rgba64_image& image,
                   std::string_view label) {
  const std::size_t row = static_cast<std::size_t>(image.width) * 4 * sizeof(double);
  if (image.pixels == nullptr || image.width == 0 || image.height == 0 ||
      image.row_stride_bytes < row ||
      image.buffer_size_bytes < image.row_stride_bytes * image.height) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISMATCH,
         std::string(label) + " RGBA64 image is invalid");
  }
}

std::vector<double> FaceImage(const ltd_face_const_rgba64_image& image,
                              bool hardware_srgb,
                              std::string_view label) {
  ValidateImage(image, label);
  std::vector<double> output(static_cast<std::size_t>(image.width) * image.height * 4);
  for (std::uint32_t y = 0; y < image.height; ++y) {
    const auto* source = reinterpret_cast<const double*>(
        reinterpret_cast<const std::uint8_t*>(image.pixels) +
        static_cast<std::size_t>(y) * image.row_stride_bytes);
    double* target = output.data() + static_cast<std::size_t>(y) * image.width * 4;
    for (std::size_t index = 0; index < static_cast<std::size_t>(image.width) * 4; ++index) {
      const double value = source[index];
      if (!std::isfinite(value)) {
        Fail(LTD_NATIVE_MATERIAL_FIELD_NONFINITE,
             std::string(label) + " contains nonfinite texels");
      }
      target[index] = hardware_srgb && (index & 3U) != 3U ? Srgb(value) : value;
    }
  }
  return output;
}

std::array<std::uint8_t,32> DynamicChainHash(
    const ltd_face_const_rgba64_image& image) {
  ValidateImage(image, "dynamic texture");
  Sha256 sha;
  static constexpr std::string_view domain = "ltd.decoded.texture-chain.v1";
  sha.Update(domain.data(), domain.size());
  sha.Little<std::uint32_t>(image.height);
  sha.Little<std::uint32_t>(image.width);
  const std::uint64_t byte_count =
      static_cast<std::uint64_t>(image.width) * image.height * 4 * sizeof(double);
  sha.Little<std::uint64_t>(byte_count);
  for (std::uint32_t y = 0; y < image.height; ++y) {
    const auto* row = reinterpret_cast<const std::uint8_t*>(image.pixels) +
        static_cast<std::size_t>(y) * image.row_stride_bytes;
    sha.Update(row, static_cast<std::size_t>(image.width) * 4 * sizeof(double));
  }
  return sha.Final();
}

ltd_native_material_texture_chain_view GetTexture(
    const ltd_native_material_field_pack_request& request, std::uint16_t role) {
  const auto& material = *request.material;
  const char* key = material.texture_keys[role];
  const char* authored = material.texture_source_sha256[role];
  const char* manifest = material.texture_manifest_sha256[role];
  if (key == nullptr || authored == nullptr || manifest == nullptr ||
      request.textures == nullptr || request.textures->get_texture_chain == nullptr) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISSING,
         "required material texture role " + std::to_string(role) + " is missing");
  }
  ltd_native_material_texture_chain_view view{};
  std::array<char,256> error{};
  if (request.textures->get_texture_chain(
          request.textures->context, key, authored, manifest, &view,
          error.data(), error.size()) == 0) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_PROVIDER_FAILED,
         "material texture provider failed for " + std::string(key) + ": " +
             error.data());
  }
  if (!Text(view.source_key,key) || !Text(view.authored_source_sha256,authored) ||
      !Text(view.manifest_sha256,manifest) || view.levels == nullptr ||
      view.level_count == 0 || view.level_count > LTD_NATIVE_MATERIAL_SCHEDULE_MAX_MIPS ||
      (view.color_space != LTD_NATIVE_MATERIAL_TEXTURE_LINEAR &&
       view.color_space != LTD_NATIVE_MATERIAL_TEXTURE_SRGB) ||
      material.texture_hardware_srgb[role] !=
          static_cast<std::uint8_t>(view.color_space == LTD_NATIVE_MATERIAL_TEXTURE_SRGB)) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISMATCH,
         "material texture provider identity/color space changed");
  }
  return view;
}

MipBank PackMips(const ltd_native_material_texture_chain_view& view,
                 bool sampled) {
  MipBank output;
  std::size_t offset = 0;
  for (std::uint32_t index = 0; index < view.level_count; ++index) {
    const auto& level = view.levels[index];
    const std::size_t count = static_cast<std::size_t>(level.width) * level.height * 4;
    const double* values = sampled ? level.sampled_rgba64 : level.rgba64;
    const std::size_t available = sampled
        ? level.sampled_rgba64_element_count : level.rgba64_element_count;
    if (values == nullptr || available != count || level.width == 0 || level.height == 0 ||
        !Finite(values, count)) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISMATCH,
           "decoded material mip payload changed");
    }
    output.levels.push_back(static_cast<std::int64_t>(offset));
    output.levels.push_back(level.height);
    output.levels.push_back(level.width);
    output.texels.insert(output.texels.end(), values, values + count);
    offset += static_cast<std::size_t>(level.width) * level.height;
    if (index == 0) { output.base_height = level.height; output.base_width = level.width; }
  }
  return output;
}

void AddSourceTexture(ltd_native_material_field_pack& pack,
                      const ltd_native_normalized_material_view& material,
                      std::uint16_t role,
                      const ltd_native_material_texture_chain_view& view) {
  pack.texture_keys.emplace_back(view.source_key);
  pack.texture_extents.emplace_back();
  auto& extents = pack.texture_extents.back();
  extents.reserve(view.level_count);
  for (std::uint32_t index = 0; index < view.level_count; ++index)
    extents.push_back({view.levels[index].height, view.levels[index].width});
  ltd_native_source_texture texture{};
  texture.role = role;
  texture.address_u = material.texture_address_u[role];
  texture.address_v = material.texture_address_v[role];
  texture.mip_filter = material.texture_mip_filter[role];
  texture.hardware_srgb = material.texture_hardware_srgb[role];
  texture.source_key = pack.texture_keys.back().c_str();
  texture.levels = extents.data();
  texture.level_count = static_cast<std::uint32_t>(extents.size());
  const auto digest = ParseHex(view.rgba64_chain_sha256, "normalized RGBA64 chain");
  std::copy(digest.begin(), digest.end(), texture.decoded_chain_sha256);
  pack.textures.push_back(texture);
}

void AddDynamicTexture(ltd_native_material_field_pack& pack, std::uint16_t role,
                       const char* source_key,
                       const ltd_face_const_rgba64_image& image,
                       std::uint8_t address_u, std::uint8_t address_v,
                       std::uint8_t mip_filter, bool hardware_srgb) {
  if (source_key == nullptr || source_key[0] == '\0') {
    Fail(LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISSING,
         "dynamic face texture has no source key");
  }
  pack.texture_keys.emplace_back(source_key);
  pack.texture_extents.push_back({{image.height,image.width}});
  ltd_native_source_texture texture{};
  texture.role = role;
  texture.address_u = address_u;
  texture.address_v = address_v;
  texture.mip_filter = mip_filter;
  texture.hardware_srgb = static_cast<std::uint8_t>(hardware_srgb);
  texture.source_key = pack.texture_keys.back().c_str();
  texture.levels = pack.texture_extents.back().data();
  texture.level_count = 1;
  const auto digest = DynamicChainHash(image);
  std::copy(digest.begin(),digest.end(),texture.decoded_chain_sha256);
  pack.textures.push_back(texture);
}

double Lod(const double* screen, const double* uv, std::uint32_t base_height,
           std::uint32_t base_width, std::uint32_t levels) {
  if (levels <= 1) return 0.0;
  const double a=screen[3]-screen[0], b=screen[4]-screen[1];
  const double c=screen[6]-screen[0], d=screen[7]-screen[1];
  const double e=uv[2]-uv[0], f=uv[3]-uv[1];
  const double g=uv[4]-uv[0], h=uv[5]-uv[1];
  const double determinant=a*d-b*c;
  if (!std::isfinite(determinant) || determinant == 0.0)
    Fail(LTD_NATIVE_MATERIAL_FIELD_SCENE_MISMATCH,"mip gradient is singular");
  const double x0=(d*e-b*g)/determinant, x1=(d*f-b*h)/determinant;
  const double y0=(-c*e+a*g)/determinant, y1=(-c*f+a*h)/determinant;
  const double rho_x=std::hypot(x0*base_width,x1*base_height);
  const double rho_y=std::hypot(y0*base_width,y1*base_height);
  const double lod=std::log2(std::max({rho_x,rho_y,1.0}));
  return std::clamp(lod,0.0,static_cast<double>(levels-1));
}

std::vector<std::int64_t> PointMips(const ltd_native_scene_draw_view& scene,
                                    const double* uv,const MipBank& bank) {
  std::vector<std::int64_t> output(scene.candidate_triangle_count);
  for(std::size_t index=0;index<output.size();++index){
    const double lod=Lod(scene.screen+index*9,uv+index*6,bank.base_height,
                         bank.base_width,static_cast<std::uint32_t>(bank.levels.size()/3));
    output[index]=std::min<std::int64_t>(static_cast<std::int64_t>(bank.levels.size()/3-1),
                                        static_cast<std::int64_t>(std::floor(lod+0.5)));
  }
  return output;
}

struct LinearMips final {std::vector<std::int64_t> lower,upper;std::vector<double> amount;};
LinearMips TrilinearMips(const ltd_native_scene_draw_view& scene,const double* uv,
                         const MipBank& bank) {
  LinearMips output;const std::size_t count=scene.candidate_triangle_count;
  output.lower.resize(count);output.upper.resize(count);output.amount.resize(count);
  const auto levels=static_cast<std::int64_t>(bank.levels.size()/3);
  for(std::size_t index=0;index<count;++index){const double lod=Lod(
      scene.screen+index*9,uv+index*6,bank.base_height,bank.base_width,
      static_cast<std::uint32_t>(levels));const auto lower=static_cast<std::int64_t>(std::floor(lod));
    output.lower[index]=lower;output.upper[index]=std::min(levels-1,lower+1);output.amount[index]=lod-lower;}
  return output;
}

void AddCommonFields(ltd_native_material_field_pack& pack,
                     const ltd_native_scene_draw_view& scene) {
  const auto count = static_cast<std::size_t>(scene.candidate_triangle_count);
  AddF64(pack, 1, scene.screen, count * 9);
  AddI64(pack, 2, scene.bounds, count * 4);
  AddF64(pack, 3, scene.denominators, count);
}

void AddLightingFields(ltd_native_material_field_pack& pack, std::uint16_t first,
                       const ltd_native_normalized_material_view& material,
                       bool include_scalars, bool include_perspective) {
  AddF64(pack, first, material.light_direction, 3);
  AddF64(pack, static_cast<std::uint16_t>(first + 1), material.light_color, 3);
  AddF64(pack, static_cast<std::uint16_t>(first + 2), material.ambient_color, 3);
  if (include_scalars) {
    AddScalarF64(pack, static_cast<std::uint16_t>(first + 3),
                 material.light_intensity);
    AddScalarF64(pack, static_cast<std::uint16_t>(first + 4),
                 material.ambient_intensity);
  }
  if (include_perspective) {
    AddScalarI64(pack, static_cast<std::uint16_t>(first + 5),
                 material.perspective_correct);
  }
}

std::array<double, 3> LinearColor(const double* source) {
  return {Srgb(source[0]), Srgb(source[1]), Srgb(source[2])};
}

void RequireGeometry(const ltd_native_scene_draw_view& scene, bool vertices,
                     bool material_uv, bool uv2 = false) {
  const auto count = static_cast<std::size_t>(scene.candidate_triangle_count);
  if ((vertices && count != 0 && scene.world_vertices == nullptr) ||
      (count != 0 && scene.world_normals == nullptr) ||
      (material_uv && count != 0 && scene.material_uv == nullptr) ||
      (uv2 && count != 0 && scene.uv2 == nullptr)) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_SCENE_MISMATCH,
         "profile-required flattened scene attributes are missing");
  }
}

void AddAllProviderTextures(ltd_native_material_field_pack& pack,
                            const ltd_native_material_field_pack_request& request,
                            std::uint16_t excluded_a,
                            std::uint16_t excluded_b = 0) {
  for (std::uint16_t role = 1; role <= 9; ++role) {
    if (role == excluded_a || role == excluded_b) continue;
    const char* key = request.material->texture_keys[role];
    if (key == nullptr) continue;
    const auto view = GetTexture(request, role);
    AddSourceTexture(pack, *request.material, role, view);
  }
}

void AddBodyFields(ltd_native_material_field_pack& pack,
                   const ltd_native_material_field_pack_request& request) {
  const auto& scene = *request.scene;
  const auto& material = *request.material;
  const auto count = static_cast<std::size_t>(scene.candidate_triangle_count);
  RequireGeometry(scene, true, true);
  const auto albedo_view = GetTexture(request, LTD_NATIVE_TEXTURE_ALBEDO);
  const auto skin_view = GetTexture(request, LTD_NATIVE_TEXTURE_SKIN_MASK);
  const auto normal_view = GetTexture(request, LTD_NATIVE_TEXTURE_NORMAL);
  const auto albedo = PackMips(albedo_view, true);
  const auto skin = PackMips(skin_view, false);
  const auto normal = PackMips(normal_view, false);
  const auto albedo_lod = TrilinearMips(scene, scene.material_uv, albedo);
  const auto skin_lod = TrilinearMips(scene, scene.material_uv, skin);
  const auto normal_lod = PointMips(scene, scene.material_uv, normal);
  AddF64(pack, 4, scene.world_vertices, count * 9);
  AddF64(pack, 5, scene.world_normals, count * 9);
  AddF64(pack, 6, scene.material_uv, count * 6);
  AddF64(pack, 7, albedo.texels.data(), albedo.texels.size());
  AddI64(pack, 8, albedo.levels.data(), albedo.levels.size());
  AddI64(pack, 9, albedo_lod.lower.data(), count);
  AddI64(pack, 10, albedo_lod.upper.data(), count);
  AddF64(pack, 11, albedo_lod.amount.data(), count);
  AddF64(pack, 12, skin.texels.data(), skin.texels.size());
  AddI64(pack, 13, skin.levels.data(), skin.levels.size());
  AddI64(pack, 14, skin_lod.lower.data(), count);
  AddI64(pack, 15, skin_lod.upper.data(), count);
  AddF64(pack, 16, skin_lod.amount.data(), count);
  AddF64(pack, 17, normal.texels.data(), normal.texels.size());
  AddI64(pack, 18, normal.levels.data(), normal.levels.size());
  AddI64(pack, 19, normal_lod.data(), count);
  AddF64(pack, 20, material.body_face_color_linear, 3);
  AddLightingFields(pack, 21, material, true, true);
}

void AddPlainFields(ltd_native_material_field_pack& pack,
                    const ltd_native_material_field_pack_request& request) {
  const auto& scene = *request.scene;
  const auto& material = *request.material;
  const auto count = static_cast<std::size_t>(scene.candidate_triangle_count);
  RequireGeometry(scene, false, false);
  const auto base = LinearColor(material.color_srgb);
  AddF64(pack, 4, scene.world_normals, count * 9);
  AddF64(pack, 5, base.data(), base.size());
  AddLightingFields(pack, 6, material, true, true);
}

void AddMaskFields(ltd_native_material_field_pack& pack,
                   const ltd_native_material_field_pack_request& request) {
  const auto& scene = *request.scene;
  const auto& material = *request.material;
  const auto count = static_cast<std::size_t>(scene.candidate_triangle_count);
  RequireGeometry(scene, true, true);
  if (request.face == nullptr || !request.face->has_generated_mask) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISSING,
         "Mask0 requires the native generated-mask face output");
  }
  const auto generated = FaceImage(request.face->generated_mask, true,
                                   "Mask0 generated texture");
  std::vector<double> user;
  if (material.mask_facepaint_mode != 0) {
    if (!request.face->has_user_facepaint) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISSING,
           "UGC Mask0 requires the decoded native user facepaint");
    }
    user = FaceImage(request.face->user_facepaint, true,
                     "Mask0 user texture");
  } else {
    user.assign(4, 1.0);
  }
  std::array<double, 10> parameters = {
      material.light_intensity, material.ambient_intensity,
      static_cast<double>(material.perspective_correct),
      static_cast<double>(material.mask_facepaint_mode), 0, 0, 0, 0, 0, 0};
  if (material.mask_facepaint_mode != 0) {
    for (std::size_t index = 0; index < 6; ++index)
      parameters[4 + index] = request.face->user_facepaint_srt.affine_rows[index];
  }
  AddF64(pack, 4, scene.world_vertices, count * 9);
  AddF64(pack, 5, scene.world_normals, count * 9);
  AddF64(pack, 6, scene.material_uv, count * 6);
  AddF64(pack, 7, generated.data(), generated.size());
  AddF64(pack, 8, user.data(), user.size());
  AddF64(pack, 9, material.light_direction, 3);
  AddF64(pack, 10, material.light_color, 3);
  AddF64(pack, 11, material.ambient_color, 3);
  AddF64(pack, 12, parameters.data(), parameters.size());
}

std::vector<std::uint8_t> HeadNormalValidity(
    const ltd_native_scene_draw_view& scene,
    const ltd_native_scene_model_view& model) {
  const auto count = static_cast<std::size_t>(scene.candidate_triangle_count);
  if (count != 0 && (scene.source_triangle_indices == nullptr ||
                     model.triangles == nullptr)) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_SCENE_MISMATCH,
         "Head816 source triangle provenance is missing");
  }
  std::vector<std::uint8_t> output(count);
  for (std::size_t index = 0; index < count; ++index) {
    const auto source = scene.source_triangle_indices[index];
    if (source >= model.triangle_count ||
        !Text(model.triangles[source].group, scene.group)) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_SCENE_MISMATCH,
           "Head816 source triangle provenance changed");
    }
    const auto& triangle = model.triangles[source];
    output[index] = static_cast<std::uint8_t>(
        triangle.normal[0] >= 0 && triangle.normal[1] >= 0 &&
        triangle.normal[2] >= 0);
  }
  return output;
}

void AddHeadFields(ltd_native_material_field_pack& pack,
                   const ltd_native_material_field_pack_request& request) {
  const auto& scene = *request.scene;
  const auto& material = *request.material;
  const auto count = static_cast<std::size_t>(scene.candidate_triangle_count);
  RequireGeometry(scene, true, false, true);
  const auto normal_view = GetTexture(request, LTD_NATIVE_TEXTURE_NORMAL);
  const auto normal = PackMips(normal_view, false);
  const auto normal_lod = PointMips(scene, scene.uv2, normal);
  const auto valid = HeadNormalValidity(scene, *request.model);
  const bool has_albedo = request.face != nullptr &&
      request.face->has_generated_head_albedo != 0;
  std::vector<double> albedo;
  if (has_albedo) {
    if (count != 0 && scene.uv0 == nullptr) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_SCENE_MISMATCH,
           "Head816 generated albedo requires authored _u0");
    }
    albedo = FaceImage(request.face->generated_head_albedo, true,
                       "Head816 generated albedo");
  } else {
    albedo.assign(4, 1.0);
  }
  std::vector<double> albedo_uv(count * 6, 0.0);
  if (has_albedo && !albedo_uv.empty())
    std::copy_n(scene.uv0, albedo_uv.size(), albedo_uv.data());
  const auto base = LinearColor(material.color_srgb);
  AddF64(pack, 4, scene.world_vertices, count * 9);
  AddF64(pack, 5, scene.world_normals, count * 9);
  AddU8(pack, 6, valid.data(), count);
  AddF64(pack, 7, albedo_uv.data(), albedo_uv.size());
  AddF64(pack, 8, scene.uv2, count * 6);
  AddF64(pack, 9, albedo.data(), albedo.size());
  AddF64(pack, 10, normal.texels.data(), normal.texels.size());
  AddI64(pack, 11, normal.levels.data(), normal.levels.size());
  AddI64(pack, 12, normal_lod.data(), count);
  AddF64(pack, 13, base.data(), base.size());
  AddLightingFields(pack, 14, material, true, false);
  AddScalarF64(pack, 19, material.color_srgb[3] * material.alpha_multiplier);
  AddScalarF64(pack, 20, material.alpha_cutoff);
  AddScalarI64(pack, 21, material.perspective_correct);
  AddScalarI64(pack, 22, has_albedo ? 1 : 0);
}

std::array<double, 33> HairParameters(
    const ltd_native_normalized_material_view& material, std::int32_t program) {
  std::array<double, 33> output{};
  std::array<double, 3> base{};
  if (program == 468) {
    base = LinearColor(material.color_srgb);
  } else {
    for (std::size_t index = 0; index < 3; ++index)
      base[index] = std::pow(std::abs(material.hair_primary_srgb[index]), 2.2);
  }
  const double norm = std::sqrt(
      material.light_direction[0] * material.light_direction[0] +
      material.light_direction[1] * material.light_direction[1] +
      material.light_direction[2] * material.light_direction[2]);
  if (!std::isfinite(norm) || norm <= 1e-12) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_MATERIAL_MISMATCH,
         "anisotropic light direction is degenerate");
  }
  std::array<double, 3> ambient{}, key{}, front{}, radiance{}, anisotropic{};
  const double front_weight = std::clamp(
      0.5 + 0.5 * material.light_direction[2], 0.0, 1.0);
  for (std::size_t index = 0; index < 3; ++index) {
    ambient[index] = material.ambient_color[index] * material.ambient_intensity;
    key[index] = material.light_color[index] * material.light_intensity;
    front[index] = ambient[index] + key[index] * front_weight;
    radiance[index] = key[index] / material.light_normalization;
    anisotropic[index] = material.light_direction[index] / norm;
  }
  const double roughness = std::max(material.roughness, 1e-12);
  const double inverse_r2 = 1.0 / std::max(roughness * roughness, 1e-12);
  const double kernel_factor = inverse_r2 * material.anisotropic_specular_size *
      0.0795774683356285 * material.anisotropic_toon_intensity *
      material.anisotropic_radiance_scale;
  std::size_t cursor = 0;
  auto append = [&](const double* values, std::size_t size) {
    std::copy_n(values, size, output.begin() + static_cast<std::ptrdiff_t>(cursor));
    cursor += size;
  };
  append(base.data(), 3);
  append(material.light_direction, 3);
  append(ambient.data(), 3);
  append(key.data(), 3);
  append(front.data(), 3);
  if (material.has_camera_position) append(material.camera_position, 3);
  else { const std::array<double,3> zero{}; append(zero.data(), 3); }
  append(radiance.data(), 3);
  const std::array<double, 8> scalars = {
      inverse_r2, kernel_factor, material.anisotropic_shift_scale,
      material.anisotropic_shift_offset, material.flip_horizontal_sign,
      static_cast<double>(material.has_camera_position),
      static_cast<double>(material.perspective_correct),
      material.anisotropic_title_view_scale};
  append(scalars.data(), scalars.size());
  append(anisotropic.data(), 3);
  output[cursor++] = program == 564 ? 0.0 : 1.0;
  if (cursor != output.size()) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_MATERIAL_MISMATCH,
         "anisotropic parameter layout changed");
  }
  return output;
}

void AddHairFields(ltd_native_material_field_pack& pack,
                   const ltd_native_material_field_pack_request& request) {
  const auto& scene = *request.scene;
  const auto& material = *request.material;
  const auto count = static_cast<std::size_t>(scene.candidate_triangle_count);
  RequireGeometry(scene, true, true);
  const auto mim_view = GetTexture(request, LTD_NATIVE_TEXTURE_SPECULAR);
  const auto mim = PackMips(mim_view, false);
  const auto mip_indices = PointMips(scene, scene.material_uv, mim);
  const auto parameters = HairParameters(material, material.gameall_program);
  AddF64(pack, 4, scene.world_vertices, count * 9);
  AddF64(pack, 5, scene.world_normals, count * 9);
  AddF64(pack, 6, scene.material_uv, count * 6);
  AddF64(pack, 7, mim.texels.data(), mim.texels.size());
  AddI64(pack, 8, mim.levels.data(), mim.levels.size());
  AddI64(pack, 9, mip_indices.data(), count);
  AddF64(pack, 10, parameters.data(), parameters.size());
}

void AddOutfitFields(ltd_native_material_field_pack& pack,
                     const ltd_native_material_field_pack_request& request) {
  const auto& scene = *request.scene;
  const auto& material = *request.material;
  const auto count = static_cast<std::size_t>(scene.candidate_triangle_count);
  RequireGeometry(scene, true, true);
  const auto albedo_view = GetTexture(request, LTD_NATIVE_TEXTURE_ALBEDO);
  const auto normal_view = GetTexture(request, LTD_NATIVE_TEXTURE_NORMAL);
  const auto albedo = PackMips(albedo_view, true);
  const auto normal = PackMips(normal_view, false);
  const auto albedo_lod = TrilinearMips(scene, scene.material_uv, albedo);
  const auto normal_lod = PointMips(scene, scene.material_uv, normal);
  AddF64(pack, 4, scene.world_vertices, count * 9);
  AddF64(pack, 5, scene.world_normals, count * 9);
  AddF64(pack, 6, scene.material_uv, count * 6);
  AddF64(pack, 7, albedo.texels.data(), albedo.texels.size());
  AddI64(pack, 8, albedo.levels.data(), albedo.levels.size());
  AddI64(pack, 9, albedo_lod.lower.data(), count);
  AddI64(pack, 10, albedo_lod.upper.data(), count);
  AddF64(pack, 11, albedo_lod.amount.data(), count);
  AddF64(pack, 12, normal.texels.data(), normal.texels.size());
  AddI64(pack, 13, normal.levels.data(), normal.levels.size());
  AddI64(pack, 14, normal_lod.data(), count);
  AddLightingFields(pack, 15, material, true, true);
}

void AddProfileFields(ltd_native_material_field_pack& pack,
                      const ltd_native_material_field_pack_request& request,
                      const Profile& profile) {
  AddCommonFields(pack, *request.scene);
  switch (profile.family) {
    case LTD_NATIVE_FAMILY_BODY: AddBodyFields(pack, request); break;
    case LTD_NATIVE_FAMILY_EAR:
    case LTD_NATIVE_FAMILY_NOSE: AddPlainFields(pack, request); break;
    case LTD_NATIVE_FAMILY_MASK: AddMaskFields(pack, request); break;
    case LTD_NATIVE_FAMILY_HEAD: AddHeadFields(pack, request); break;
    case LTD_NATIVE_FAMILY_HAIR_ANISOTROPIC:
    case LTD_NATIVE_FAMILY_HAIR_ENDPOINT:
    case LTD_NATIVE_FAMILY_BEARD_ANISOTROPIC: AddHairFields(pack, request); break;
    case LTD_NATIVE_FAMILY_OUTFIT_TOPS:
    case LTD_NATIVE_FAMILY_OUTFIT_BOTTOMS:
    case LTD_NATIVE_FAMILY_OUTFIT_SHOES: AddOutfitFields(pack, request); break;
    default: Fail(LTD_NATIVE_MATERIAL_FIELD_PROFILE_UNSUPPORTED,
                  "unsupported typed material family");
  }
}

void AddTextures(ltd_native_material_field_pack& pack,
                 const ltd_native_material_field_pack_request& request,
                 const Profile& profile) {
  const auto& material = *request.material;
  if (profile.family == LTD_NATIVE_FAMILY_MASK) {
    if (material.texture_keys[LTD_NATIVE_TEXTURE_MASK_GENERATED] != nullptr ||
        material.texture_keys[LTD_NATIVE_TEXTURE_MASK_USER0] != nullptr) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_MATERIAL_MISMATCH,
           "Mask0 dynamic face targets cannot be replaced by asset textures");
    }
    AddAllProviderTextures(pack, request, LTD_NATIVE_TEXTURE_MASK_GENERATED,
                           LTD_NATIVE_TEXTURE_MASK_USER0);
    const bool ugc = material.mask_facepaint_mode != 0;
    AddDynamicTexture(pack, LTD_NATIVE_TEXTURE_MASK_GENERATED,
                      request.face->generated_mask_source_key,
                      request.face->generated_mask,
                      static_cast<std::uint8_t>(
                          ugc ? LTD_NATIVE_ADDRESS_REPEAT : LTD_NATIVE_ADDRESS_CLAMP),
                      static_cast<std::uint8_t>(
                          ugc ? LTD_NATIVE_ADDRESS_REPEAT : LTD_NATIVE_ADDRESS_CLAMP),
                      static_cast<std::uint8_t>(LTD_NATIVE_MIP_POINT), false);
    if (ugc) {
      AddDynamicTexture(pack, LTD_NATIVE_TEXTURE_MASK_USER0,
                        request.face->user_facepaint_source_key,
                        request.face->user_facepaint,
                        static_cast<std::uint8_t>(LTD_NATIVE_ADDRESS_CLAMP),
                        static_cast<std::uint8_t>(LTD_NATIVE_ADDRESS_CLAMP),
                        static_cast<std::uint8_t>(LTD_NATIVE_MIP_POINT), false);
    }
  } else if (profile.family == LTD_NATIVE_FAMILY_HEAD) {
    if (request.face != nullptr && request.face->has_generated_head_albedo) {
      if (material.texture_keys[LTD_NATIVE_TEXTURE_ALBEDO] != nullptr) {
        Fail(LTD_NATIVE_MATERIAL_FIELD_MATERIAL_MISMATCH,
             "Head816 generated albedo cannot be replaced by an asset texture");
      }
      AddAllProviderTextures(pack, request, LTD_NATIVE_TEXTURE_ALBEDO);
      AddDynamicTexture(pack, LTD_NATIVE_TEXTURE_ALBEDO,
                        request.face->generated_head_albedo_source_key,
                        request.face->generated_head_albedo,
                        static_cast<std::uint8_t>(LTD_NATIVE_ADDRESS_MIRROR),
                        static_cast<std::uint8_t>(LTD_NATIVE_ADDRESS_REPEAT),
                        static_cast<std::uint8_t>(LTD_NATIVE_MIP_POINT), true);
    } else {
      AddAllProviderTextures(pack, request, 0);
    }
  } else {
    AddAllProviderTextures(pack, request, 0);
  }
}

void InitializeSource(ltd_native_material_field_pack& pack,
                      const ltd_native_material_field_pack_request& request,
                      const Profile& profile) {
  const auto& scene = *request.scene;
  const auto& material = *request.material;
  pack.model_key = material.model_key;
  pack.resource_name = material.resource_name;
  pack.group = material.group;
  auto& source = pack.source;
  source.model_key = pack.model_key.c_str();
  source.resource_name = pack.resource_name.c_str();
  source.group = pack.group.c_str();
  source.authored_index = request.authored_index;
  source.submitted_triangle_count = static_cast<std::uint32_t>(scene.submitted_triangle_count);
  source.candidate_triangle_count = static_cast<std::uint32_t>(scene.candidate_triangle_count);
  source.gameall_program = material.gameall_program;
  source.family = profile.family;
  source.gsys_priority = material.gsys_priority;
  source.material_flags = material.material_flags;
  std::copy_n(scene.transform, 16, source.transform);
  const std::array<double,16> dynamic = {
      material.color_srgb[0], material.color_srgb[1], material.color_srgb[2],
      material.color_srgb[3], material.alpha_multiplier, material.alpha_cutoff,
      material.roughness, material.anisotropic_shift_scale,
      material.anisotropic_shift_offset, material.anisotropic_specular_size,
      material.anisotropic_toon_intensity, material.anisotropic_title_view_scale,
      material.anisotropic_radiance_scale, material.parallax_scale,
      material.light_intensity, material.ambient_intensity};
  std::copy(dynamic.begin(), dynamic.end(), source.dynamic_values);
}

void ValidateRequest(const ltd_native_material_field_pack_request& request,
                     const Profile& profile) {
  if (request.effective_char_info == nullptr ||
      request.effective_char_info_byte_count !=
          LTD_NATIVE_MATERIAL_FIELD_PACKER_CHARINFO_SIZE) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_INVALID_ARGUMENT,
         "effective CharInfo must be exactly 152 bytes");
  }
  const auto& scene = *request.scene;
  const auto& model = *request.model;
  const auto& material = *request.material;
  if (!Text(scene.resource_name, material.resource_name) ||
      !Text(scene.group, material.group) || scene.profile != profile.scene_profile ||
      material.family != profile.family ||
      !Text(scene.resource_name, model.resource_name) ||
      !Text(scene.model_name, model.model_name)) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_SCENE_MISMATCH,
         "scene/model/material identity changed");
  }
  const std::size_t count = static_cast<std::size_t>(scene.candidate_triangle_count);
  if ((count != 0 && (scene.screen == nullptr || scene.bounds == nullptr ||
                      scene.denominators == nullptr ||
                      scene.world_normals == nullptr)) ||
      !Finite(scene.screen, count * 9) || !Finite(scene.denominators, count) ||
      !Finite(scene.world_normals, count * 9) ||
      (scene.world_vertices != nullptr && !Finite(scene.world_vertices, count * 9)) ||
      (scene.material_uv != nullptr && !Finite(scene.material_uv, count * 6)) ||
      (scene.uv0 != nullptr && !Finite(scene.uv0, count * 6)) ||
      (scene.uv2 != nullptr && !Finite(scene.uv2, count * 6))) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_NONFINITE,
         "scene flattened geometry is missing or nonfinite");
  }
  const std::array<const double*, 8> vectors = {
      material.color_srgb, material.body_face_color_linear,
      material.hair_primary_srgb, material.hair_secondary_srgb,
      material.light_direction, material.light_color, material.ambient_color,
      material.camera_position};
  const std::array<std::size_t, 8> lengths = {4, 3, 3, 3, 3, 3, 3, 3};
  for (std::size_t index = 0; index < vectors.size(); ++index) {
    if (!Finite(vectors[index], lengths[index])) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_NONFINITE,
           "normalized material vector is nonfinite");
    }
  }
  const std::array<double, 14> scalars = {
      material.alpha_multiplier, material.alpha_cutoff, material.roughness,
      material.anisotropic_shift_scale, material.anisotropic_shift_offset,
      material.anisotropic_specular_size, material.anisotropic_toon_intensity,
      material.anisotropic_title_view_scale,
      material.anisotropic_radiance_scale, material.parallax_scale,
      material.light_intensity, material.ambient_intensity,
      material.light_normalization, material.flip_horizontal_sign};
  if (!std::all_of(scalars.begin(), scalars.end(),
                   [](double value) { return std::isfinite(value); })) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_NONFINITE,
         "normalized material scalar is nonfinite");
  }
  if (material.perspective_correct > 1 || material.has_camera_position > 1 ||
      material.mask_facepaint_mode > 1 || material.light_normalization == 0.0) {
    Fail(LTD_NATIVE_MATERIAL_FIELD_MATERIAL_MISMATCH,
         "normalized material flags/normalization changed");
  }
}

void ProbeTextures(const ltd_native_material_field_pack_request& request) {
  const auto& material = *request.material;
  bool requested = false;
  for (std::uint16_t role = 1; role <= 9; ++role) {
    const char* key = material.texture_keys[role];
    const char* seal = material.texture_source_sha256[role];
    const char* manifest = material.texture_manifest_sha256[role];
    if (key == nullptr && seal == nullptr && manifest == nullptr) continue;
    requested = true;
    if (key == nullptr || seal == nullptr || manifest == nullptr ||
        request.textures == nullptr ||
        request.textures->get_texture_chain == nullptr) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISSING,
           "sealed decoded texture provider is missing for role " +
               std::to_string(role));
    }
    ltd_native_material_texture_chain_view view{};
    std::array<char, 256> error{};
    if (request.textures->get_texture_chain(
            request.textures->context, key, seal, manifest, &view, error.data(),
            error.size()) == 0) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_PROVIDER_FAILED,
           std::string("decoded texture provider failed for ") + key + ": " +
               error.data());
    }
    if (!Text(view.source_key, key) ||
        !Text(view.authored_source_sha256, seal) ||
        !Text(view.manifest_sha256, manifest) ||
        view.decoded_chain_sha256 == nullptr ||
        view.rgba8_chain_sha256 == nullptr ||
        view.rgba64_chain_sha256 == nullptr ||
        view.sampled_rgba64_chain_sha256 == nullptr ||
        view.level_count == 0 ||
        view.level_count > LTD_NATIVE_MATERIAL_SCHEDULE_MAX_MIPS ||
        view.levels == nullptr ||
        (view.color_space != LTD_NATIVE_MATERIAL_TEXTURE_LINEAR &&
         view.color_space != LTD_NATIVE_MATERIAL_TEXTURE_SRGB)) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISMATCH,
           "decoded texture chain identity/shape changed");
    }
    for (std::uint32_t level = 0; level < view.level_count; ++level) {
      const auto& image = view.levels[level];
      const std::size_t elements =
          static_cast<std::size_t>(image.width) * image.height * 4;
      if (image.rgba8 == nullptr || image.rgba64 == nullptr ||
          image.sampled_rgba64 == nullptr || image.width == 0 ||
          image.height == 0 || image.rgba8_byte_count != elements ||
          image.rgba64_element_count != elements ||
          image.sampled_rgba64_element_count != elements ||
          image.source_sha256 == nullptr || image.rgba8_sha256 == nullptr ||
          image.rgba64_sha256 == nullptr ||
          image.sampled_rgba64_sha256 == nullptr) {
        Fail(LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISMATCH,
             "decoded texture level buffer is invalid");
      }
    }
  }
  (void)requested;
}

}  // namespace

extern "C" {

uint32_t LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
ltd_native_material_field_packer_abi_version(void) {
  return LTD_NATIVE_MATERIAL_FIELD_PACKER_ABI_VERSION;
}

const char* LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
ltd_native_material_field_packer_contract_sha256(void) {
  return LTD_NATIVE_MATERIAL_FIELD_PACKER_CONTRACT_SHA256;
}

const char* LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
ltd_native_material_field_status_name(ltd_native_material_field_status status) {
  switch (status) {
    case LTD_NATIVE_MATERIAL_FIELD_OK: return "ok";
    case LTD_NATIVE_MATERIAL_FIELD_INVALID_ARGUMENT: return "invalid_argument";
    case LTD_NATIVE_MATERIAL_FIELD_SOURCE_MISMATCH: return "source_mismatch";
    case LTD_NATIVE_MATERIAL_FIELD_SCENE_MISMATCH: return "scene_mismatch";
    case LTD_NATIVE_MATERIAL_FIELD_MATERIAL_MISMATCH: return "material_mismatch";
    case LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISSING: return "texture_missing";
    case LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISMATCH: return "texture_mismatch";
    case LTD_NATIVE_MATERIAL_FIELD_PROFILE_UNSUPPORTED: return "profile_unsupported";
    case LTD_NATIVE_MATERIAL_FIELD_NONFINITE: return "nonfinite";
    case LTD_NATIVE_MATERIAL_FIELD_ALLOCATION_FAILED: return "allocation_failed";
    case LTD_NATIVE_MATERIAL_FIELD_PROVIDER_FAILED: return "provider_failed";
    default: return "unknown";
  }
}

ltd_native_material_field_status LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
ltd_native_material_field_pack_build(
    const ltd_native_material_field_pack_request* request,
    ltd_native_material_field_pack** output, char* error,
    size_t error_capacity) {
  if (output == nullptr) return LTD_NATIVE_MATERIAL_FIELD_INVALID_ARGUMENT;
  *output = nullptr;
  Error(error, error_capacity, "");
  try {
    if (request == nullptr || request->seals == nullptr ||
        request->scene == nullptr || request->model == nullptr ||
        request->material == nullptr) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_INVALID_ARGUMENT,
           "request, seals, scene, model, and material are required");
    }
    if (!Seals(*request->seals)) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_SOURCE_MISMATCH,
           "native field-packer dependency seal changed");
    }
    const Profile profile = Resolve(request->material->gameall_program);
    ValidateRequest(*request, profile);
    ProbeTextures(*request);
    if (request->scene->submitted_triangle_count >
            std::numeric_limits<std::uint32_t>::max() ||
        request->scene->candidate_triangle_count >
            std::numeric_limits<std::uint32_t>::max()) {
      Fail(LTD_NATIVE_MATERIAL_FIELD_SCENE_MISMATCH,
           "typed draw triangle count exceeds the material ABI");
    }
    auto pack = std::make_unique<ltd_native_material_field_pack>();
    pack->texture_keys.reserve(LTD_NATIVE_MATERIAL_FIELD_PACKER_MAX_TEXTURES);
    pack->texture_extents.reserve(LTD_NATIVE_MATERIAL_FIELD_PACKER_MAX_TEXTURES);
    pack->textures.reserve(LTD_NATIVE_MATERIAL_FIELD_PACKER_MAX_TEXTURES);
    pack->field_bytes.reserve(26);
    pack->fields.reserve(26);
    InitializeSource(*pack, *request, profile);
    AddProfileFields(*pack, *request, profile);
    AddTextures(*pack, *request, profile);
    ValidateFieldCount(*pack);
    pack->source.textures = pack->textures.empty() ? nullptr : pack->textures.data();
    pack->source.texture_count = static_cast<std::uint32_t>(pack->textures.size());
    pack->source.packed_fields = pack->fields.data();
    pack->source.packed_field_count = static_cast<std::uint32_t>(pack->fields.size());
    *output = pack.release();
    return LTD_NATIVE_MATERIAL_FIELD_OK;
  } catch (const Failure& failure) {
    Error(error, error_capacity, failure.message);
    return failure.status;
  } catch (const std::bad_alloc&) {
    Error(error, error_capacity, "material field-pack allocation failed");
    return LTD_NATIVE_MATERIAL_FIELD_ALLOCATION_FAILED;
  } catch (...) {
    Error(error, error_capacity, "unexpected material field-packer failure");
    return LTD_NATIVE_MATERIAL_FIELD_INVALID_ARGUMENT;
  }
}

ltd_native_material_field_status LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
ltd_native_material_field_pack_get_source_draw(
    const ltd_native_material_field_pack* pack, ltd_native_source_draw* output) {
  if (pack == nullptr || output == nullptr) {
    return LTD_NATIVE_MATERIAL_FIELD_INVALID_ARGUMENT;
  }
  *output = pack->source;
  return LTD_NATIVE_MATERIAL_FIELD_OK;
}

void LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
ltd_native_material_field_pack_destroy(ltd_native_material_field_pack* pack) {
  delete pack;
}

}  // extern "C"
