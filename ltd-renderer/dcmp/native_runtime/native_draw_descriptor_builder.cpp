#include "native_draw_descriptor_builder.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdio>
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
    const std::uint64_t bits = static_cast<std::uint64_t>(total_) * 8u;
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
      block_[63 - index] = static_cast<std::uint8_t>(bits >> (index * 8u));
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
    std::uint32_t a=state_[0],b=state_[1],c=state_[2],d=state_[3];
    std::uint32_t e=state_[4],f=state_[5],g=state_[6],h=state_[7];
    for (std::size_t index = 0; index < words.size(); ++index) {
      const std::uint32_t big1 = Rotate(e,6)^Rotate(e,11)^Rotate(e,25);
      const std::uint32_t choice = (e&f)^(~e&g);
      const std::uint32_t temp1 = h+big1+choice+kRound[index]+words[index];
      const std::uint32_t big0 = Rotate(a,2)^Rotate(a,13)^Rotate(a,22);
      const std::uint32_t majority = (a&b)^(a&c)^(b&c);
      const std::uint32_t temp2 = big0+majority;
      h=g;g=f;f=e;e=d+temp1;d=c;c=b;b=a;a=temp1+temp2;
    }
    state_[0]+=a;state_[1]+=b;state_[2]+=c;state_[3]+=d;
    state_[4]+=e;state_[5]+=f;state_[6]+=g;state_[7]+=h;
  }

  std::array<std::uint32_t,8> state_={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,
      0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
  std::array<std::uint8_t,64> block_{};
  std::size_t used_=0,total_=0;
};

struct Failure final {
  ltd_native_draw_descriptor_status status;
  std::string message;
};

[[noreturn]] void Fail(ltd_native_draw_descriptor_status status, std::string message) {
  throw Failure{status, std::move(message)};
}

#if defined(_WIN32)

class BCryptSha256 final {
  static constexpr ULONG kDigestBytes = 32;

 public:
  BCryptSha256() {
    Check(BCryptOpenAlgorithmProvider(
              &algorithm_.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0),
          "open algorithm provider");

    ULONG copied = 0;
    ULONG object_length = 0;
    Check(BCryptGetProperty(
              algorithm_.value, BCRYPT_OBJECT_LENGTH,
              reinterpret_cast<PUCHAR>(&object_length),
              static_cast<ULONG>(sizeof(object_length)), &copied, 0),
          "query hash-object length");
    if (copied != sizeof(object_length) || object_length == 0) {
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SOURCE_MISMATCH,
           "Windows BCrypt SHA-256 returned an invalid hash-object length");
    }

    ULONG hash_length = 0;
    copied = 0;
    Check(BCryptGetProperty(
              algorithm_.value, BCRYPT_HASH_LENGTH,
              reinterpret_cast<PUCHAR>(&hash_length),
              static_cast<ULONG>(sizeof(hash_length)), &copied, 0),
          "query digest length");
    if (copied != sizeof(hash_length) || hash_length != kDigestBytes) {
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SOURCE_MISMATCH,
           "Windows BCrypt SHA-256 returned an invalid digest length");
    }

    object_.resize(object_length);
    Check(BCryptCreateHash(
              algorithm_.value, &hash_.value, object_.data(), object_length,
              nullptr, 0, 0),
          "create streaming hash");
  }

  BCryptSha256(const BCryptSha256&) = delete;
  BCryptSha256& operator=(const BCryptSha256&) = delete;

  void Update(const void* source, std::size_t size) {
    if (finished_) {
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SOURCE_MISMATCH,
           "Windows BCrypt SHA-256 update followed finalization");
    }
    if (size != 0 && source == nullptr) {
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_INVALID_ARGUMENT,
           "Windows BCrypt SHA-256 input is null");
    }
    const auto* cursor = static_cast<const std::uint8_t*>(source);
    while (size != 0) {
      const ULONG chunk = size > static_cast<std::size_t>(ULONG_MAX)
          ? ULONG_MAX
          : static_cast<ULONG>(size);
      Check(BCryptHashData(hash_.value, const_cast<PUCHAR>(cursor), chunk, 0),
            "stream packed bytes");
      cursor += chunk;
      size -= chunk;
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

  std::array<std::uint8_t, kDigestBytes> Final() {
    if (finished_) {
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SOURCE_MISMATCH,
           "Windows BCrypt SHA-256 was finalized twice");
    }
    std::array<std::uint8_t, kDigestBytes> output{};
    Check(BCryptFinishHash(hash_.value, output.data(),
                           static_cast<ULONG>(output.size()), 0),
          "finish packed digest");
    finished_ = true;
    return output;
  }

 private:
  struct AlgorithmHandle final {
    ~AlgorithmHandle() {
      if (value != nullptr) BCryptCloseAlgorithmProvider(value, 0);
    }
    BCRYPT_ALG_HANDLE value = nullptr;
  };

  struct HashHandle final {
    ~HashHandle() {
      if (value != nullptr) BCryptDestroyHash(value);
    }
    BCRYPT_HASH_HANDLE value = nullptr;
  };

  static void Check(NTSTATUS status, std::string_view operation) {
    if (status >= 0) return;
    char detail[16]{};
    std::snprintf(detail, sizeof(detail), "0x%08lX",
                  static_cast<unsigned long>(status));
    Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SOURCE_MISMATCH,
         "Windows BCrypt SHA-256 failed to " + std::string(operation) +
             " (" + detail + ")");
  }

  AlgorithmHandle algorithm_;
  std::vector<std::uint8_t> object_;
  HashHandle hash_;
  bool finished_ = false;
};

#else

using BCryptSha256 = Sha256;

#endif

bool Text(const char* left, const char* right) {
  return left != nullptr && right != nullptr && std::strcmp(left, right) == 0;
}

void Error(char* output, std::size_t capacity, std::string_view message) {
  if (output == nullptr || capacity == 0) return;
  const std::size_t count = std::min(capacity - 1, message.size());
  std::memcpy(output, message.data(), count);
  output[count] = '\0';
}

bool Finite(std::span<const double> values) {
  return std::all_of(values.begin(), values.end(), [](double value) {
    return std::isfinite(value);
  });
}

enum class FieldKind { kF64, kI64, kU8 };

struct OwnedField final {
  FieldKind kind = FieldKind::kU8;
  std::vector<double> f64;
  std::vector<std::int64_t> i64;
  std::vector<std::uint8_t> u8;
};

struct Profile final {
  std::uint16_t kernel;
  std::uint16_t program;
  std::uint16_t family;
  std::uint32_t scene_profile;
  std::uint8_t abi;
  std::uint32_t field_count;
};

Profile Resolve(std::uint16_t program) {
  switch (program) {
    case 324: case 336: case 348:
      return {LTD_NATIVE_DRAW_BODY_ABI1,program,LTD_NATIVE_FAMILY_BODY,
              static_cast<std::uint32_t>(program==324?LTD_NATIVE_SCENE_PROFILE_BODY324:
              program==336?LTD_NATIVE_SCENE_PROFILE_BODY336:LTD_NATIVE_SCENE_PROFILE_BODY348),1,26};
    case 372: return {LTD_NATIVE_DRAW_PLAIN_SKIN_ABI1,372,LTD_NATIVE_FAMILY_EAR,
                      LTD_NATIVE_SCENE_PROFILE_EAR372,1,11};
    case 756: return {LTD_NATIVE_DRAW_PLAIN_SKIN_ABI1,756,LTD_NATIVE_FAMILY_NOSE,
                      LTD_NATIVE_SCENE_PROFILE_NOSE756,1,11};
    case 0: return {LTD_NATIVE_DRAW_MASK0_ABI1,0,LTD_NATIVE_FAMILY_MASK,
                    LTD_NATIVE_SCENE_PROFILE_MASK0,1,12};
    case 816: return {LTD_NATIVE_DRAW_HEAD816_ABI2,816,LTD_NATIVE_FAMILY_HEAD,
                      LTD_NATIVE_SCENE_PROFILE_HEAD816,2,22};
    case 612: return {LTD_NATIVE_DRAW_HAIR_ABI2,612,LTD_NATIVE_FAMILY_HAIR_ANISOTROPIC,
                      LTD_NATIVE_SCENE_PROFILE_HAIR612,2,10};
    case 564: return {LTD_NATIVE_DRAW_HAIR_ABI2,564,LTD_NATIVE_FAMILY_HAIR_ENDPOINT,
                      LTD_NATIVE_SCENE_PROFILE_HAIR564_EQUAL_ENDPOINT,2,10};
    case 468: return {LTD_NATIVE_DRAW_HAIR_ABI2,468,LTD_NATIVE_FAMILY_BEARD_ANISOTROPIC,
                      LTD_NATIVE_SCENE_PROFILE_BEARD468,2,10};
    case 984: return {LTD_NATIVE_DRAW_OUTFIT_ABI2,984,LTD_NATIVE_FAMILY_OUTFIT_TOPS,
                      LTD_NATIVE_SCENE_PROFILE_OUTFIT_TOPS984,2,20};
    case 936: return {LTD_NATIVE_DRAW_OUTFIT_ABI2,936,LTD_NATIVE_FAMILY_OUTFIT_BOTTOMS,
                      LTD_NATIVE_SCENE_PROFILE_OUTFIT_BOTTOMS936,2,20};
    case 912: return {LTD_NATIVE_DRAW_OUTFIT_ABI2,912,LTD_NATIVE_FAMILY_OUTFIT_SHOES,
                      LTD_NATIVE_SCENE_PROFILE_OUTFIT_SHOES912,2,20};
    default: Fail(LTD_NATIVE_DRAW_DESCRIPTOR_UNSUPPORTED_PROFILE,
                  "unsupported scheduled draw profile " + std::to_string(program));
  }
}

std::array<std::uint8_t,32> HashPacked(const ltd_native_source_draw& source) {
  BCryptSha256 sha;
  static constexpr std::string_view domain="ltd.material.packed-abi.v1";
  sha.Update(domain.data(),domain.size());
  sha.Little<std::uint16_t>(source.family);
  sha.Little<std::uint16_t>(static_cast<std::uint16_t>(source.gameall_program));
  sha.Little<std::uint32_t>(source.packed_field_count);
  std::uint16_t previous=0;
  for(std::uint32_t index=0;index<source.packed_field_count;++index){
    const auto& field=source.packed_fields[index];
    if(field.tag==0 || (index!=0 && field.tag<=previous) || field.reserved!=0 ||
       field.element_width==0 || (field.byte_count!=0 && field.bytes==nullptr) ||
       field.byte_count%field.element_width!=0){
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH,
           "malformed packed field at index "+std::to_string(index));
    }
    previous=field.tag;
    sha.Little<std::uint16_t>(field.tag);
    sha.Little<std::uint16_t>(field.element_width);
    sha.Little<std::uint64_t>(static_cast<std::uint64_t>(field.byte_count));
    sha.Update(field.bytes,field.byte_count);
  }
  return sha.Final();
}

std::array<std::uint8_t,32> HashTextures(const ltd_native_source_draw& source) {
  Sha256 sha;
  static constexpr std::string_view domain="ltd.material.texture-plan.v1";
  sha.Update(domain.data(),domain.size());
  sha.Little<std::uint32_t>(source.texture_count);
  std::vector<const ltd_native_source_texture*> ordered;
  ordered.reserve(source.texture_count);
  for(std::uint32_t index=0;index<source.texture_count;++index) ordered.push_back(source.textures+index);
  std::sort(ordered.begin(),ordered.end(),[](const auto* left,const auto* right){return left->role<right->role;});
  std::uint16_t previous=0;
  for(const auto* texture:ordered){
    if(texture->role==0 || texture->role==previous || texture->reserved!=0 ||
       texture->source_key==nullptr || texture->level_count==0 || texture->levels==nullptr ||
       texture->level_count>LTD_NATIVE_MATERIAL_SCHEDULE_MAX_MIPS){
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_TEXTURE_MISMATCH,"malformed texture-plan binding");
    }
    previous=texture->role;
    const std::string_view key(texture->source_key);
    sha.Little<std::uint16_t>(texture->role);
    sha.Little<std::uint8_t>(texture->address_u);
    sha.Little<std::uint8_t>(texture->address_v);
    sha.Little<std::uint8_t>(texture->mip_filter);
    sha.Little<std::uint8_t>(texture->hardware_srgb);
    sha.Little<std::uint32_t>(static_cast<std::uint32_t>(key.size()));
    sha.Update(key.data(),key.size());
    sha.Little<std::uint32_t>(texture->level_count);
    for(std::uint32_t level=0;level<texture->level_count;++level){
      if(texture->levels[level].height==0 || texture->levels[level].width==0)
        Fail(LTD_NATIVE_DRAW_DESCRIPTOR_TEXTURE_MISMATCH,"zero texture extent");
      sha.Little<std::uint32_t>(texture->levels[level].height);
      sha.Little<std::uint32_t>(texture->levels[level].width);
    }
    sha.Update(texture->decoded_chain_sha256,32);
  }
  return sha.Final();
}

const ltd_native_source_texture* Texture(const ltd_native_source_draw& source,
                                         std::uint16_t role) {
  for(std::uint32_t index=0;index<source.texture_count;++index)
    if(source.textures[index].role==role) return source.textures+index;
  return nullptr;
}

bool Bytes(const void* left,const void* right,std::size_t bytes){
  return bytes==0 || (left!=nullptr && right!=nullptr && std::memcmp(left,right,bytes)==0);
}

}  // namespace

struct ltd_native_draw_descriptor {
  std::vector<OwnedField> fields;
  ltd_draw_plain_skin_input plain{};
  ltd_draw_body_input body{};
  ltd_draw_mask0_input mask{};
  ltd_draw_head816_input head{};
  ltd_draw_hair_input hair{};
  ltd_draw_outfit_input outfit{};
  ltd_native_draw_command_view view{};
};

namespace {

OwnedField CopyField(const ltd_native_packed_field& source,FieldKind kind,
                     std::size_t expected_count,std::uint16_t expected_tag) {
  const std::size_t width=kind==FieldKind::kU8?1:8;
  if(source.tag!=expected_tag || source.element_width!=width ||
     source.byte_count!=expected_count*width || (source.byte_count!=0 && source.bytes==nullptr)){
    Fail(LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH,
         "packed field "+std::to_string(expected_tag)+" shape/type mismatch");
  }
  OwnedField output;
  output.kind=kind;
  if(kind==FieldKind::kF64){
    output.f64.resize(expected_count);
    std::memcpy(output.f64.data(),source.bytes,source.byte_count);
    if(!Finite(output.f64)) Fail(LTD_NATIVE_DRAW_DESCRIPTOR_NONFINITE,
                                "packed field "+std::to_string(expected_tag)+" is nonfinite");
  }else if(kind==FieldKind::kI64){
    output.i64.resize(expected_count);
    std::memcpy(output.i64.data(),source.bytes,source.byte_count);
  }else{
    output.u8.assign(source.bytes,source.bytes+source.byte_count);
  }
  return output;
}

const double* F64(const ltd_native_draw_descriptor& owner,std::size_t tag){
  return owner.fields[tag-1].f64.data();
}
const std::int64_t* I64(const ltd_native_draw_descriptor& owner,std::size_t tag){
  return owner.fields[tag-1].i64.data();
}
const std::uint8_t* U8(const ltd_native_draw_descriptor& owner,std::size_t tag){
  return owner.fields[tag-1].u8.data();
}
std::size_t CountF64(const ltd_native_draw_descriptor& owner,std::size_t tag){
  return owner.fields[tag-1].f64.size();
}
std::size_t CountI64(const ltd_native_draw_descriptor& owner,std::size_t tag){
  return owner.fields[tag-1].i64.size();
}

void Add(ltd_native_draw_descriptor& owner,const ltd_native_source_draw& source,
         std::uint16_t tag,FieldKind kind,std::size_t count){
  owner.fields.push_back(CopyField(source.packed_fields[tag-1],kind,count,tag));
}

double ScalarF64(const ltd_native_draw_descriptor& owner,std::size_t tag){return F64(owner,tag)[0];}
std::int64_t ScalarI64(const ltd_native_draw_descriptor& owner,std::size_t tag){return I64(owner,tag)[0];}

ltd_draw_const_f64_buffer F64Buffer(const ltd_native_draw_descriptor& owner,std::size_t tag){
  return {F64(owner,tag),CountF64(owner,tag)};
}
ltd_draw_const_i64_buffer I64Buffer(const ltd_native_draw_descriptor& owner,std::size_t tag){
  return {I64(owner,tag),CountI64(owner,tag)};
}
ltd_draw_const_u8_buffer U8Buffer(const ltd_native_draw_descriptor& owner,std::size_t tag){
  return {U8(owner,tag),owner.fields[tag-1].u8.size()};
}

void Vec3(double target[3],const ltd_native_draw_descriptor& owner,std::size_t tag){
  std::copy_n(F64(owner,tag),3,target);
}

void Triangles(ltd_draw_triangle_batch& target,const ltd_native_draw_descriptor& owner,
               std::uint32_t count){
  target.screen=F64Buffer(owner,1);target.bounds=I64Buffer(owner,2);
  target.denominators=F64Buffer(owner,3);target.triangle_count=count;
}

void ValidateLevels(const ltd_native_draw_descriptor& owner,std::size_t texels_tag,
                    std::size_t levels_tag,const ltd_native_source_texture* texture){
  const auto* levels=I64(owner,levels_tag);
  const std::size_t level_count=CountI64(owner,levels_tag)/3;
  const std::size_t texel_count=CountF64(owner,texels_tag)/4;
  if(CountF64(owner,texels_tag)%4!=0 || CountI64(owner,levels_tag)%3!=0 || level_count==0)
    Fail(LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH,"invalid packed mip-bank shape");
  std::uint64_t expected_offset=0;
  for(std::size_t index=0;index<level_count;++index){
    const auto offset=levels[index*3],height=levels[index*3+1],width=levels[index*3+2];
    if(offset<0 || height<=0 || width<=0 || static_cast<std::uint64_t>(offset)!=expected_offset)
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH,"invalid packed mip offsets/extents");
    if(texture!=nullptr && (index>=texture->level_count ||
       static_cast<std::uint64_t>(height)!=texture->levels[index].height ||
       static_cast<std::uint64_t>(width)!=texture->levels[index].width))
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_TEXTURE_MISMATCH,"packed mip extents differ from material view");
    expected_offset+=static_cast<std::uint64_t>(height)*static_cast<std::uint64_t>(width);
  }
  if(expected_offset!=texel_count || (texture!=nullptr && level_count!=texture->level_count))
    Fail(LTD_NATIVE_DRAW_DESCRIPTOR_TEXTURE_MISMATCH,"packed mip-bank length differs from material view");
}

ltd_draw_mip_bank Mips(const ltd_native_draw_descriptor& owner,std::size_t texels_tag,
                       std::size_t levels_tag){
  return {F64(owner,texels_tag),CountF64(owner,texels_tag)/4,I64(owner,levels_tag),
          static_cast<std::uint32_t>(CountI64(owner,levels_tag)/3)};
}

const ltd_native_source_texture& RequireTexture(const ltd_native_source_draw& source,
                                                std::uint16_t role){
  const auto* texture=Texture(source,role);
  if(texture==nullptr) Fail(LTD_NATIVE_DRAW_DESCRIPTOR_TEXTURE_MISMATCH,
                           "required texture role "+std::to_string(role)+" is missing");
  return *texture;
}

void Texture2D(ltd_draw_texture2d& target,const ltd_native_draw_descriptor& owner,
               std::size_t tag,std::uint32_t height,std::uint32_t width){
  if(CountF64(owner,tag)!=static_cast<std::size_t>(height)*width*4)
    Fail(LTD_NATIVE_DRAW_DESCRIPTOR_TEXTURE_MISMATCH,"packed 2D texture extent mismatch");
  target={F64(owner,tag),static_cast<std::size_t>(height)*width,width,height};
}

void ValidateScene(const ltd_native_draw_descriptor_request& request,const Profile& profile){
  const auto& source=*request.material;const auto& scheduled=*request.scheduled;
  const auto& scene=*request.scene;const auto& model=*request.model;
  if(!Text(source.model_key,scheduled.model_key) || !Text(source.resource_name,scheduled.resource_name) ||
     !Text(source.group,scheduled.group) || source.authored_index!=scheduled.authored_index ||
     source.submitted_triangle_count!=scheduled.submitted_triangle_count ||
     source.candidate_triangle_count!=scheduled.candidate_triangle_count ||
     source.material_flags!=scheduled.material_flags ||
     std::memcmp(source.transform,scheduled.transform,sizeof(source.transform))!=0 ||
     std::memcmp(source.dynamic_values,scheduled.dynamic_values,sizeof(source.dynamic_values))!=0)
    Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SCHEDULE_MISMATCH,"material/schedule record mismatch");
  if(scheduled.kernel!=profile.kernel || scheduled.profile!=profile.program ||
     scheduled.draw_abi_version!=profile.abi || source.family!=profile.family ||
     source.gameall_program!=profile.program)
    Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SCHEDULE_MISMATCH,"scheduled kernel/profile/family mismatch");
  if(!Text(source.resource_name,scene.resource_name) || !Text(source.group,scene.group) ||
     scene.profile!=profile.scene_profile || scene.submitted_triangle_count!=source.submitted_triangle_count ||
     scene.candidate_triangle_count!=source.candidate_triangle_count ||
     std::memcmp(scene.transform,source.transform,sizeof(source.transform))!=0)
    Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SCENE_MISMATCH,"scene/material identity or counts changed");
  if(!Text(model.resource_name,scene.resource_name) || !Text(model.model_name,scene.model_name) ||
     model.triangles==nullptr || (scene.candidate_triangle_count!=0 && scene.source_triangle_indices==nullptr))
    Fail(LTD_NATIVE_DRAW_DESCRIPTOR_MODEL_MISMATCH,"model/scene provenance is unavailable");
  for(std::size_t index=0;index<scene.candidate_triangle_count;++index){
    const std::uint64_t source_index=scene.source_triangle_indices[index];
    if(source_index>=model.triangle_count || !Text(model.triangles[source_index].group,scene.group))
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_MODEL_MISMATCH,"candidate source-triangle provenance changed");
  }
}

void ValidateGeometry(const ltd_native_draw_descriptor& owner,
                      const ltd_native_draw_descriptor_request& request,const Profile& profile){
  const auto& scene=*request.scene;const std::size_t count=scene.candidate_triangle_count;
  if(!Bytes(F64(owner,1),scene.screen,count*9*sizeof(double)) ||
     !Bytes(I64(owner,2),scene.bounds,count*4*sizeof(std::int64_t)) ||
     !Bytes(F64(owner,3),scene.denominators,count*sizeof(double)))
    Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SCENE_MISMATCH,"triangle setup differs from scene view");
  if(profile.kernel==LTD_NATIVE_DRAW_PLAIN_SKIN_ABI1){
    if(!Bytes(F64(owner,4),scene.world_normals,count*9*sizeof(double)))
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SCENE_MISMATCH,"plain-skin normals differ from scene view");
    return;
  }
  if(!Bytes(F64(owner,4),scene.world_vertices,count*9*sizeof(double)) ||
     !Bytes(F64(owner,5),scene.world_normals,count*9*sizeof(double)))
    Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SCENE_MISMATCH,"world geometry differs from scene view");
  if(profile.kernel==LTD_NATIVE_DRAW_HEAD816_ABI2){
    const auto has_albedo=ScalarI64(owner,22);
    if((has_albedo!=0 && has_albedo!=1) ||
       (has_albedo!=0 && !Bytes(F64(owner,7),scene.uv0,count*6*sizeof(double))) ||
       (has_albedo==0 && count!=0 &&
        !std::all_of(F64(owner,7),F64(owner,7)+count*6,
                                      [](double value){return value==0.0;})) ||
       !Bytes(F64(owner,8),scene.uv2,count*6*sizeof(double)))
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SCENE_MISMATCH,"Head816 _u0/_u2 selection changed");
    for(std::size_t index=0;index<count;++index){
      const auto& triangle=request.model->triangles[scene.source_triangle_indices[index]];
      const std::uint8_t valid=static_cast<std::uint8_t>(triangle.normal[0]>=0 &&
          triangle.normal[1]>=0 && triangle.normal[2]>=0);
      if(U8(owner,6)[index]!=valid)
        Fail(LTD_NATIVE_DRAW_DESCRIPTOR_MODEL_MISMATCH,"Head816 normal-valid mask changed");
    }
  }else if(!Bytes(F64(owner,6),scene.material_uv,count*6*sizeof(double))){
    Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SCENE_MISMATCH,"material UV selection changed");
  }
}

void LoadFields(ltd_native_draw_descriptor& owner,const ltd_native_source_draw& source,
                 const Profile& profile,std::size_t count){
  owner.fields.reserve(profile.field_count);
  auto f=[&](std::uint16_t tag,std::size_t elements){Add(owner,source,tag,FieldKind::kF64,elements);};
  auto i=[&](std::uint16_t tag,std::size_t elements){Add(owner,source,tag,FieldKind::kI64,elements);};
  auto u=[&](std::uint16_t tag,std::size_t elements){Add(owner,source,tag,FieldKind::kU8,elements);};
  f(1,count*9);i(2,count*4);f(3,count);
  switch(profile.kernel){
    case LTD_NATIVE_DRAW_PLAIN_SKIN_ABI1:
      f(4,count*9);f(5,3);f(6,3);f(7,3);f(8,3);f(9,1);f(10,1);i(11,1);break;
    case LTD_NATIVE_DRAW_BODY_ABI1:
      f(4,count*9);f(5,count*9);f(6,count*6);
      f(7,source.packed_fields[6].byte_count/8);i(8,source.packed_fields[7].byte_count/8);
      i(9,count);i(10,count);f(11,count);
      f(12,source.packed_fields[11].byte_count/8);i(13,source.packed_fields[12].byte_count/8);
      i(14,count);i(15,count);f(16,count);
      f(17,source.packed_fields[16].byte_count/8);i(18,source.packed_fields[17].byte_count/8);
      i(19,count);f(20,3);f(21,3);f(22,3);f(23,3);f(24,1);f(25,1);i(26,1);break;
    case LTD_NATIVE_DRAW_MASK0_ABI1:
      f(4,count*9);f(5,count*9);f(6,count*6);
      f(7,source.packed_fields[6].byte_count/8);f(8,source.packed_fields[7].byte_count/8);
      f(9,3);f(10,3);f(11,3);f(12,10);break;
    case LTD_NATIVE_DRAW_HEAD816_ABI2:
      f(4,count*9);f(5,count*9);u(6,count);f(7,count*6);f(8,count*6);
      f(9,source.packed_fields[8].byte_count/8);f(10,source.packed_fields[9].byte_count/8);
      i(11,source.packed_fields[10].byte_count/8);i(12,count);f(13,3);f(14,3);f(15,3);
      f(16,3);f(17,1);f(18,1);f(19,1);f(20,1);i(21,1);i(22,1);break;
    case LTD_NATIVE_DRAW_HAIR_ABI2:
      f(4,count*9);f(5,count*9);f(6,count*6);f(7,source.packed_fields[6].byte_count/8);
      i(8,source.packed_fields[7].byte_count/8);i(9,count);f(10,33);break;
    case LTD_NATIVE_DRAW_OUTFIT_ABI2:
      f(4,count*9);f(5,count*9);f(6,count*6);f(7,source.packed_fields[6].byte_count/8);
      i(8,source.packed_fields[7].byte_count/8);i(9,count);i(10,count);f(11,count);
      f(12,source.packed_fields[11].byte_count/8);i(13,source.packed_fields[12].byte_count/8);
      i(14,count);f(15,3);f(16,3);f(17,3);f(18,1);f(19,1);i(20,1);break;
    default: Fail(LTD_NATIVE_DRAW_DESCRIPTOR_UNSUPPORTED_PROFILE,"unsupported draw kernel");
  }
}

void BuildInput(ltd_native_draw_descriptor& owner,const ltd_native_source_draw& source,
                const Profile& profile,std::uint32_t count){
  switch(profile.kernel){
    case LTD_NATIVE_DRAW_PLAIN_SKIN_ABI1:{
      auto& input=owner.plain;Triangles(input.triangles,owner,count);input.vertex_normals=F64Buffer(owner,4);
      Vec3(input.base_color_linear,owner,5);Vec3(input.light_direction,owner,6);
      Vec3(input.light_color,owner,7);Vec3(input.ambient_color,owner,8);
      input.light_intensity=ScalarF64(owner,9);input.ambient_intensity=ScalarF64(owner,10);
      const auto perspective=ScalarI64(owner,11);if(perspective<0 || perspective>1)
        Fail(LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH,"plain-skin perspective flag changed");
      input.perspective_correct=static_cast<std::int32_t>(perspective);input.reserved=0;
      owner.view.plain_skin=&input;break;}
    case LTD_NATIVE_DRAW_BODY_ABI1:{
      ValidateLevels(owner,7,8,Texture(source,LTD_NATIVE_TEXTURE_ALBEDO));
      ValidateLevels(owner,12,13,Texture(source,LTD_NATIVE_TEXTURE_SKIN_MASK));
      ValidateLevels(owner,17,18,Texture(source,LTD_NATIVE_TEXTURE_NORMAL));
      auto& input=owner.body;Triangles(input.triangles,owner,count);input.world_vertices=F64Buffer(owner,4);
      input.vertex_normals=F64Buffer(owner,5);input.material_uv=F64Buffer(owner,6);
      input.albedo=Mips(owner,7,8);input.albedo_lower_indices=I64Buffer(owner,9);
      input.albedo_upper_indices=I64Buffer(owner,10);input.albedo_mip_amounts=F64Buffer(owner,11);
      input.skin=Mips(owner,12,13);input.skin_lower_indices=I64Buffer(owner,14);
      input.skin_upper_indices=I64Buffer(owner,15);input.skin_mip_amounts=F64Buffer(owner,16);
      input.normal=Mips(owner,17,18);input.normal_level_indices=I64Buffer(owner,19);
      Vec3(input.face_color_linear,owner,20);Vec3(input.light_direction,owner,21);
      Vec3(input.light_color,owner,22);Vec3(input.ambient_color,owner,23);
      input.light_intensity=ScalarF64(owner,24);input.ambient_intensity=ScalarF64(owner,25);
      const auto perspective=ScalarI64(owner,26);if(perspective<0 || perspective>1)
        Fail(LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH,"body perspective flag changed");
      input.perspective_correct=static_cast<std::int32_t>(perspective);input.reserved=0;
      owner.view.body=&input;break;}
    case LTD_NATIVE_DRAW_MASK0_ABI1:{
      auto& input=owner.mask;Triangles(input.triangles,owner,count);input.vertex_normals=F64Buffer(owner,5);
      input.material_uv=F64Buffer(owner,6);const auto& generated=RequireTexture(source,LTD_NATIVE_TEXTURE_MASK_GENERATED);
      if(generated.level_count!=1) Fail(LTD_NATIVE_DRAW_DESCRIPTOR_TEXTURE_MISMATCH,"Mask0 generated mip count changed");
      Texture2D(input.generated_texture,owner,7,generated.levels[0].height,generated.levels[0].width);
      const auto* user=Texture(source,LTD_NATIVE_TEXTURE_MASK_USER0);
      Texture2D(input.user_texture,owner,8,user==nullptr?1:user->levels[0].height,
                user==nullptr?1:user->levels[0].width);
      Vec3(input.light_direction,owner,9);Vec3(input.light_color,owner,10);
      Vec3(input.ambient_color,owner,11);std::copy_n(F64(owner,12),10,input.parameters);
      owner.view.mask0=&input;break;}
    case LTD_NATIVE_DRAW_HEAD816_ABI2:{
      ValidateLevels(owner,10,11,Texture(source,LTD_NATIVE_TEXTURE_NORMAL));
      auto& input=owner.head;Triangles(input.triangles,owner,count);input.world_vertices=F64Buffer(owner,4);
      input.vertex_normals=F64Buffer(owner,5);input.vertex_normal_valid=U8Buffer(owner,6);
      input.albedo_uv=F64Buffer(owner,7);input.normal_uv=F64Buffer(owner,8);
      const auto has_albedo=ScalarI64(owner,22);if(has_albedo<0 || has_albedo>1)
        Fail(LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH,"Head816 albedo flag changed");
      if(has_albedo!=0){const auto& albedo=RequireTexture(source,LTD_NATIVE_TEXTURE_ALBEDO);
        if(albedo.level_count!=1) Fail(LTD_NATIVE_DRAW_DESCRIPTOR_TEXTURE_MISMATCH,"Head816 albedo mip count changed");
        Texture2D(input.albedo_texture,owner,9,albedo.levels[0].height,albedo.levels[0].width);
      }else Texture2D(input.albedo_texture,owner,9,1,1);
      input.normal=Mips(owner,10,11);input.normal_level_indices=I64Buffer(owner,12);
      Vec3(input.base_color_linear,owner,13);Vec3(input.light_direction,owner,14);
      Vec3(input.light_color,owner,15);Vec3(input.ambient_color,owner,16);
      input.light_intensity=ScalarF64(owner,17);input.ambient_intensity=ScalarF64(owner,18);
      input.alpha_scalar=ScalarF64(owner,19);input.alpha_cutoff=ScalarF64(owner,20);
      const auto perspective=ScalarI64(owner,21);if(perspective<0 || perspective>1)
        Fail(LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH,"Head816 perspective flag changed");
      input.perspective_correct=static_cast<std::int32_t>(perspective);
      input.has_albedo=static_cast<std::int32_t>(has_albedo);owner.view.head816=&input;break;}
    case LTD_NATIVE_DRAW_HAIR_ABI2:{
      ValidateLevels(owner,7,8,Texture(source,LTD_NATIVE_TEXTURE_SPECULAR));
      auto& input=owner.hair;Triangles(input.triangles,owner,count);input.world_vertices=F64Buffer(owner,4);
      input.vertex_normals=F64Buffer(owner,5);input.material_uv=F64Buffer(owner,6);
      input.mim=Mips(owner,7,8);input.mim_level_indices=I64Buffer(owner,9);
      std::copy_n(F64(owner,10),LTD_DRAW_RUNTIME_V2_HAIR_PARAMETER_COUNT,input.parameters);
      input.profile=profile.program;input.reserved=0;owner.view.hair=&input;break;}
    case LTD_NATIVE_DRAW_OUTFIT_ABI2:{
      ValidateLevels(owner,7,8,Texture(source,LTD_NATIVE_TEXTURE_ALBEDO));
      ValidateLevels(owner,12,13,Texture(source,LTD_NATIVE_TEXTURE_NORMAL));
      auto& input=owner.outfit;Triangles(input.triangles,owner,count);input.world_vertices=F64Buffer(owner,4);
      input.vertex_normals=F64Buffer(owner,5);input.material_uv=F64Buffer(owner,6);
      input.albedo=Mips(owner,7,8);input.albedo_lower_indices=I64Buffer(owner,9);
      input.albedo_upper_indices=I64Buffer(owner,10);input.albedo_mip_amounts=F64Buffer(owner,11);
      input.normal=Mips(owner,12,13);input.normal_level_indices=I64Buffer(owner,14);
      Vec3(input.light_direction,owner,15);Vec3(input.light_color,owner,16);
      Vec3(input.ambient_color,owner,17);input.light_intensity=ScalarF64(owner,18);
      input.ambient_intensity=ScalarF64(owner,19);const auto perspective=ScalarI64(owner,20);
      if(perspective<0 || perspective>1) Fail(LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH,
                                              "outfit perspective flag changed");
      input.perspective_correct=static_cast<std::int32_t>(perspective);input.profile=profile.program;
      owner.view.outfit=&input;break;}
    default: Fail(LTD_NATIVE_DRAW_DESCRIPTOR_UNSUPPORTED_PROFILE,"unsupported draw kernel");
  }
}

bool Seals(const ltd_native_draw_descriptor_source_seals& seals){
  return Text(seals.material_schedule_contract_sha256,LTD_NATIVE_MATERIAL_SCHEDULE_CONTRACT_SHA256) &&
         Text(seals.draw_runtime_v1_contract_sha256,LTD_DRAW_RUNTIME_CONTRACT_SHA256) &&
         Text(seals.draw_runtime_v2_contract_sha256,LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256) &&
         Text(seals.current_source_sha256,LTD_DRAW_RUNTIME_CURRENT_SOURCE_SHA256) &&
         Text(seals.opaque_source_sha256,LTD_DRAW_RUNTIME_OPAQUE_SOURCE_SHA256) &&
         Text(seals.wrapper_source_sha256,LTD_DRAW_RUNTIME_V2_WRAPPER_SHA256);
}

}  // namespace

extern "C" {

uint32_t LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_builder_abi_version(void){return LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_ABI_VERSION;}

const char* LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_builder_contract_sha256(void){return LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CONTRACT_SHA256;}

const char* LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_status_name(ltd_native_draw_descriptor_status status){
  switch(status){
    case LTD_NATIVE_DRAW_DESCRIPTOR_OK:return "ok";
    case LTD_NATIVE_DRAW_DESCRIPTOR_INVALID_ARGUMENT:return "invalid_argument";
    case LTD_NATIVE_DRAW_DESCRIPTOR_SOURCE_MISMATCH:return "source_mismatch";
    case LTD_NATIVE_DRAW_DESCRIPTOR_SCHEDULE_MISMATCH:return "schedule_mismatch";
    case LTD_NATIVE_DRAW_DESCRIPTOR_SCENE_MISMATCH:return "scene_mismatch";
    case LTD_NATIVE_DRAW_DESCRIPTOR_MODEL_MISMATCH:return "model_mismatch";
    case LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH:return "packed_field_mismatch";
    case LTD_NATIVE_DRAW_DESCRIPTOR_TEXTURE_MISMATCH:return "texture_mismatch";
    case LTD_NATIVE_DRAW_DESCRIPTOR_UNSUPPORTED_PROFILE:return "unsupported_profile";
    case LTD_NATIVE_DRAW_DESCRIPTOR_NONFINITE:return "nonfinite";
    case LTD_NATIVE_DRAW_DESCRIPTOR_ALLOCATION_FAILED:return "allocation_failed";
    default:return "unknown";
  }
}

ltd_native_draw_descriptor_status LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_builder_require(uint32_t expected_abi,const char* expected_contract_sha256){
  if(expected_abi!=LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_ABI_VERSION)
    return LTD_NATIVE_DRAW_DESCRIPTOR_SOURCE_MISMATCH;
  if(!Text(expected_contract_sha256,LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CONTRACT_SHA256))
    return LTD_NATIVE_DRAW_DESCRIPTOR_SOURCE_MISMATCH;
  return LTD_NATIVE_DRAW_DESCRIPTOR_OK;
}

ltd_native_draw_descriptor_status LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_build(const ltd_native_draw_descriptor_request* request,
                                 ltd_native_draw_descriptor** output,char* error,
                                 size_t error_capacity){
  if(output==nullptr) return LTD_NATIVE_DRAW_DESCRIPTOR_INVALID_ARGUMENT;
  *output=nullptr;Error(error,error_capacity,"");
  try{
    if(request==nullptr || request->seals==nullptr || request->material==nullptr ||
       request->scheduled==nullptr || request->scene==nullptr || request->model==nullptr)
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_INVALID_ARGUMENT,"request and all immutable views are required");
    if(!Seals(*request->seals)) Fail(LTD_NATIVE_DRAW_DESCRIPTOR_SOURCE_MISMATCH,
                                    "descriptor dependency source seal changed");
    const auto& source=*request->material;const auto& scheduled=*request->scheduled;
    if(source.packed_field_count==0 || source.packed_field_count>LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_MAX_FIELDS ||
       source.packed_fields==nullptr || source.texture_count>LTD_NATIVE_MATERIAL_SCHEDULE_MAX_TEXTURES ||
       (source.texture_count!=0 && source.textures==nullptr))
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_INVALID_ARGUMENT,"material view is incomplete");
    const Profile profile=Resolve(scheduled.profile);
    if(source.packed_field_count!=profile.field_count)
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH,"profile packed-field count changed");
    ValidateScene(*request,profile);
    const auto packed=HashPacked(source);const auto textures=HashTextures(source);
    if(std::memcmp(packed.data(),scheduled.packed_abi_input_sha256,32)!=0)
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH,"packed ABI digest differs from schedule");
    if(std::memcmp(textures.data(),scheduled.texture_plan_sha256,32)!=0)
      Fail(LTD_NATIVE_DRAW_DESCRIPTOR_TEXTURE_MISMATCH,"texture-plan digest differs from schedule");
    auto owner=std::make_unique<ltd_native_draw_descriptor>();
    LoadFields(*owner,source,profile,source.candidate_triangle_count);
    ValidateGeometry(*owner,*request,profile);
    owner->view.kernel=profile.kernel;owner->view.profile=profile.program;
    owner->view.draw_abi_version=profile.abi;
    owner->view.submitted_triangle_count=source.submitted_triangle_count;
    owner->view.candidate_triangle_count=source.candidate_triangle_count;
    std::copy(packed.begin(),packed.end(),owner->view.packed_abi_input_sha256);
    std::copy(textures.begin(),textures.end(),owner->view.texture_plan_sha256);
    BuildInput(*owner,source,profile,source.candidate_triangle_count);
    *output=owner.release();return LTD_NATIVE_DRAW_DESCRIPTOR_OK;
  }catch(const Failure& failure){Error(error,error_capacity,failure.message);return failure.status;
  }catch(const std::bad_alloc&){Error(error,error_capacity,"descriptor allocation failed");
    return LTD_NATIVE_DRAW_DESCRIPTOR_ALLOCATION_FAILED;
  }catch(...){Error(error,error_capacity,"unexpected descriptor-builder failure");
    return LTD_NATIVE_DRAW_DESCRIPTOR_INVALID_ARGUMENT;}
}

ltd_native_draw_descriptor_status LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_get_command(const ltd_native_draw_descriptor* descriptor,
                                       ltd_native_draw_command_view* output){
  if(descriptor==nullptr || output==nullptr) return LTD_NATIVE_DRAW_DESCRIPTOR_INVALID_ARGUMENT;
  *output=descriptor->view;return LTD_NATIVE_DRAW_DESCRIPTOR_OK;
}

void LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_destroy(ltd_native_draw_descriptor* descriptor){delete descriptor;}

}  // extern "C"
