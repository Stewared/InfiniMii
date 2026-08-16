#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include "native_face_plan.h"

#include <algorithm>
#include <array>
#include <cfenv>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <set>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace infinimii::native_face_plan {
namespace generated {

struct PaletteEntry final {
  std::uint16_t selector;
  std::uint8_t rgba8[4];
  std::uint64_t srgb_bits[4];
  std::uint64_t linear_bits[4];
};

struct AssetRecord final {
  const char* texture_name;
  std::uint32_t mip_level;
  const char* canonical_key;
  const char* png_sha256;
  const char* decoded_rgba8_sha256;
  std::uint32_t width;
  std::uint32_t height;
  const char* packed_bntx_sha256;
};

struct LayerRecord final {
  const char* fixture_name;
  const char* logical_name;
  std::int32_t dispatcher_case;
  std::uint16_t selector;
  const char* record_name;
  const char* parts_config_sha256;
  std::int32_t asset_index;
  std::uint32_t shader_kind;
  std::uint32_t mirrored;
  std::uint64_t affine_bits[6];
  std::uint64_t center_bits[2];
  std::uint64_t extent_bits[2];
  std::uint64_t rotation_bits;
  std::uint64_t rho_bits;
  std::uint64_t biased_lod_bits;
  std::uint64_t rotate_axis_bits[2];
};

struct FixtureRecord final {
  const char* name;
  const char* share_mii_sha256;
  const char* char_info_sha256;
  const char* active_parts_sha256;
  std::uint32_t first_layer;
  std::uint32_t layer_count;
  std::uint32_t faceline_kind;
  std::int32_t faceline_asset_index;
  std::uint32_t faceline_parameters[4];
  const char* mask_final_rgba8_sha256;
  const char* mask_mesh_rgba8_sha256;
  const char* mask_rgba64_sha256;
  const char* head_rgba8_sha256;
  const char* head_rgba64_sha256;
};

}  // namespace generated
}  // namespace infinimii::native_face_plan

#include "generated/native_face_plan_catalog.inc"

namespace infinimii::native_face_plan {
namespace {

struct Failure final {
  Status status;
  std::string message;
};

[[noreturn]] void Fail(Status status, std::string message) {
  throw Failure{status, std::move(message)};
}

double DoubleFromBits(std::uint64_t bits) {
  double value = 0.0;
  static_assert(sizeof(value) == sizeof(bits));
  std::memcpy(&value, &bits, sizeof(value));
  return value;
}

float FloatFromBits(std::uint32_t bits) {
  float value = 0.0F;
  static_assert(sizeof(value) == sizeof(bits));
  std::memcpy(&value, &bits, sizeof(value));
  return value;
}

std::string Hex(std::span<const std::uint8_t> bytes) {
  constexpr char alphabet[] = "0123456789abcdef";
  std::string output(bytes.size() * 2, '\0');
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    output[index * 2] = alphabet[bytes[index] >> 4];
    output[index * 2 + 1] = alphabet[bytes[index] & 15];
  }
  return output;
}

template <typename Value>
std::span<const std::uint8_t> Bytes(std::span<const Value> values) {
  return {reinterpret_cast<const std::uint8_t*>(values.data()),
          values.size_bytes()};
}

std::string Sha256(std::span<const std::uint8_t> bytes) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_size = 0;
  DWORD returned = 0;
  std::vector<std::uint8_t> object;
  std::array<std::uint8_t, 32> digest{};
  auto cleanup = [&]() {
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
  };
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
      BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
                        &returned, 0) < 0) {
    cleanup();
    Fail(Status::kSourceMismatch, "Windows SHA-256 provider is unavailable");
  }
  try {
    object.resize(object_size);
  } catch (const std::bad_alloc&) {
    cleanup();
    throw;
  }
  if (BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0) < 0 ||
      (bytes.size() != 0 && BCryptHashData(
          hash, const_cast<PUCHAR>(bytes.data()),
          static_cast<ULONG>(bytes.size()), 0) < 0) ||
      BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) {
    cleanup();
    Fail(Status::kSourceMismatch, "Windows SHA-256 operation failed");
  }
  cleanup();
  return Hex(digest);
}

std::wstring Wide(std::string_view value) {
  std::wstring output;
  output.reserve(value.size());
  for (const unsigned char character : value) {
    if (character == 0 || character > 0x7f) {
      Fail(Status::kSourceMismatch, "face asset key is not canonical ASCII");
    }
    output.push_back(static_cast<wchar_t>(character));
  }
  return output;
}

const generated::PaletteEntry& PaletteEntry(std::uint16_t selector) {
  const auto found = std::find_if(
      std::begin(generated::kPalette), std::end(generated::kPalette),
      [selector](const generated::PaletteEntry& value) {
        return value.selector == selector;
      });
  if (found == std::end(generated::kPalette)) {
    Fail(Status::kPlanMismatch, "CharInfo color selector is outside the sealed palette");
  }
  return *found;
}

ColorVector ResolveColor(std::uint16_t selector) {
  const auto& source = PaletteEntry(selector);
  ColorVector output{};
  output.selector = selector;
  std::copy_n(source.rgba8, 4, output.rgba8.begin());
  for (std::size_t index = 0; index < 4; ++index) {
    output.srgb[index] = DoubleFromBits(source.srgb_bits[index]);
    output.linear[index] = DoubleFromBits(source.linear_bits[index]);
  }
  return output;
}

Palette BuildPalette(std::span<const std::uint8_t> info) {
  Palette output{};
  constexpr std::array<std::size_t, static_cast<std::size_t>(PaletteRole::kCount)>
      offsets = {45, 70, 71, 133, 79, 85, 117, 127, 137, 135};
  for (std::size_t index = 0; index < offsets.size(); ++index) {
    const std::uint16_t selector = info[offsets[index]];
    if (index != static_cast<std::size_t>(PaletteRole::kSkin) && selector > 99) {
      Fail(Status::kPlanMismatch, "non-faceline CharInfo color is outside CommonColor");
    }
    output.colors[index] = ResolveColor(selector);
  }
  return output;
}

native_parts::Logical Logical(std::string_view name) {
  using L = native_parts::Logical;
  if (name == "eye") return L::kEye;
  if (name == "eyebrow") return L::kEyebrow;
  if (name == "mouth") return L::kMouth;
  if (name == "mustache") return L::kMustache;
  Fail(Status::kPlanMismatch, "sealed ordinary face plan contains an unknown logical name");
}

const native_parts::SelectedRecord& Selected(
    const native_parts::Selection& selection, native_parts::Logical logical) {
  const std::size_t index = static_cast<std::size_t>(logical);
  if (index >= selection.records.size() || selection.records[index].logical != logical) {
    Fail(Status::kPartsMismatch, "native Parts logical record ordering changed");
  }
  return selection.records[index];
}

bool Near(double left, double right) {
  return std::isfinite(left) && std::isfinite(right) &&
         std::abs(left - right) <= 1.0e-11;
}

constexpr std::array<int, 64> kEyeRotationBase = {
    3,4,4,4,3,4,4,4,3,4,4,4,4,3,3,4,4,4,3,3,4,3,4,3,3,4,3,4,4,3,4,4,
    4,3,3,3,4,4,3,3,3,4,4,3,3,3,3,3,3,3,3,3,4,4,4,4,3,4,4,3,4,4,4,4};
constexpr std::array<int, 28> kEyebrowRotationBase = {
    6,6,5,7,6,7,6,7,4,7,6,8,5,5,6,6,7,7,6,6,5,6,7,5,6,6,6,6};

double Rotation(std::uint8_t selector, std::uint8_t user,
                std::span<const int> table) {
  const int base = selector < table.size() ? table[selector] : 4;
  return static_cast<double>((static_cast<int>(user) + 32 - base) % 32) * 11.25;
}

std::array<double, 2> SideCenter(double origin_x, double origin_y,
                                 double raw_width, double rotation,
                                 double direction) {
  const double radians = rotation * (3.141592653589793238462643383279502884 / 180.0);
  return {origin_x + 0.88961464 * std::cos(radians) * direction * raw_width / 2.0,
          origin_y + 0.9276675 * std::sin(radians) * direction * raw_width / 2.0};
}

void ValidateDerivedPlacement(const generated::LayerRecord& layer,
                              std::span<const std::uint8_t> info) {
  std::array<double, 2> center{};
  std::array<double, 2> extent{};
  double rotation = 0.0;
  if (std::string_view(layer.logical_name) == "eye") {
    const double scale = 0.4 * info[80] + 1.0;
    const double aspect = 0.12 * info[81] + 0.64;
    extent = {5.34375 * scale * 0.88961464,
              4.5 * scale * aspect * 0.9276675};
    const double spacing = info[83] * 0.88961464;
    const double y = info[84] * 1.0760943 + 18.451523;
    const double right_rotation = Rotation(info[78], info[82], kEyeRotationBase);
    const bool left = layer.dispatcher_case == 17;
    rotation = left ? std::fmod(360.0 - right_rotation, 360.0) : right_rotation;
    center = SideCenter(32.0 + (left ? spacing : -spacing), y,
                        extent[0] / 0.88961464, rotation, left ? 1.0 : -1.0);
  } else if (std::string_view(layer.logical_name) == "eyebrow") {
    const double scale = 0.4 * info[118] + 1.0;
    const double aspect = 0.12 * info[119] + 0.64;
    extent = {5.0625 * scale * 0.88961464,
              4.5 * scale * aspect * 0.9276675};
    const double spacing = info[121] * 0.88961464 - 1.7792293;
    const double y = info[122] * 1.0760943 + 16.549807;
    const double right_rotation = Rotation(info[116], info[120], kEyebrowRotationBase);
    const bool left = layer.dispatcher_case == 5;
    rotation = left ? std::fmod(360.0 - right_rotation, 360.0) : right_rotation;
    center = SideCenter(32.0 + (left ? spacing : -spacing), y,
                        extent[0] / 0.88961464, rotation, left ? 1.0 : -1.0);
  } else if (std::string_view(layer.logical_name) == "mouth") {
    const double scale = 0.4 * info[128] + 1.0;
    const double aspect = 0.12 * info[129] + 0.64;
    extent = {6.1875 * scale * 0.88961464,
              4.5 * scale * aspect * 0.9276675};
    center = {32.0, info[131] * 1.0760943 + 4.629278 + 24.629572};
    rotation = info[130] * 11.25;
  } else if (std::string_view(layer.logical_name) == "mustache") {
    const double scale = 0.4 * info[138] + 1.0;
    const double aspect = 0.12 * info[139] + 0.64;
    const double raw_width = 4.5 * scale;
    const double raw_height = 9.0 * scale * aspect;
    extent = {raw_width * 0.88961464, raw_height * 0.9276675};
    const bool left = layer.dispatcher_case == 1;
    const double direction = left ? 1.0 : -1.0;
    rotation = (info[43] & 0x40u) != 0 ? (left ? -180.0 : 180.0) : 0.0;
    const double axis_x = DoubleFromBits(layer.rotate_axis_bits[0]);
    const double axis_y = DoubleFromBits(layer.rotate_axis_bits[1]);
    if (!Near(axis_x, 0.0) || !Near(axis_y, 0.048)) {
      Fail(Status::kPlanMismatch, "Mustache03 RotateAxis evidence changed");
    }
    const double radians = rotation * (3.141592653589793238462643383279502884 / 180.0);
    const double pivot_x = direction * raw_width * axis_x;
    const double pivot_y = raw_height * axis_y;
    const double delta_x = direction * raw_width / 2.0 - pivot_x;
    const double delta_y = -pivot_y;
    const double local_x = pivot_x + std::cos(radians) * delta_x - std::sin(radians) * delta_y;
    const double local_y = pivot_y + std::sin(radians) * delta_x + std::cos(radians) * delta_y;
    center = {32.0 + 0.88961464 * local_x,
              info[140] * 1.0760943 + 31.763554 + 0.9276675 * local_y};
    rotation = std::fmod(rotation + 360.0, 360.0);
  } else {
    Fail(Status::kPlanMismatch, "unknown face placement formula");
  }
  for (std::size_t index = 0; index < 2; ++index) {
    if (!Near(center[index], DoubleFromBits(layer.center_bits[index])) ||
        !Near(extent[index], DoubleFromBits(layer.extent_bits[index]))) {
      Fail(Status::kPlanMismatch,
           std::string("CharInfo-derived face placement changed for ") +
               layer.fixture_name + "/" + layer.logical_name + "/" +
               std::to_string(layer.dispatcher_case) + " component " +
               std::to_string(index) + ": center " +
               std::to_string(center[index]) + " expected " +
               std::to_string(DoubleFromBits(layer.center_bits[index])) +
               ", extent " + std::to_string(extent[index]) + " expected " +
               std::to_string(DoubleFromBits(layer.extent_bits[index])));
    }
  }
  if (!Near(rotation, DoubleFromBits(layer.rotation_bits))) {
    Fail(Status::kPlanMismatch, "CharInfo-derived face rotation changed");
  }
  const double a = DoubleFromBits(layer.affine_bits[0]);
  const double b = DoubleFromBits(layer.affine_bits[1]);
  const double d = DoubleFromBits(layer.affine_bits[3]);
  const double e = DoubleFromBits(layer.affine_bits[4]);
  const auto& asset = generated::kAssets[layer.asset_index];
  const double rho = std::max(std::hypot(a, d), std::hypot(b, e)) *
                     static_cast<double>(std::uint32_t{1} << asset.mip_level);
  const double lod = std::clamp(std::log2(rho) - 0.7, 0.0, 13.0);
  if (!Near(rho, DoubleFromBits(layer.rho_bits)) ||
      !Near(lod, DoubleFromBits(layer.biased_lod_bits))) {
    Fail(Status::kPlanMismatch, "sealed face sprite LOD calculation changed");
  }
}

AssetRequirement Requirement(const generated::AssetRecord& source) {
  return {source.texture_name, source.mip_level, source.canonical_key,
          source.png_sha256, source.decoded_rgba8_sha256, source.width,
          source.height, source.packed_bntx_sha256};
}

ltd_face_const_rgba8_image ConstImage(const native_runtime::DecodedTexture& texture) {
  return {texture.rgba8.data(), texture.rgba8.size(),
          static_cast<std::size_t>(texture.width) * 4, texture.width,
          texture.height};
}

ltd_face_rgba8_image MutableImage(std::vector<std::uint8_t>& pixels,
                                  std::uint32_t width,
                                  std::uint32_t height) {
  return {pixels.data(), pixels.size(), static_cast<std::size_t>(width) * 4,
          width, height};
}

ltd_face_rgba64_image MutableImage64(std::vector<double>& pixels,
                                    std::uint32_t width,
                                    std::uint32_t height) {
  return {pixels.data(), pixels.size() * sizeof(double),
          static_cast<std::size_t>(width) * 4 * sizeof(double), width, height};
}

const native_runtime::DecodedTexture& GetAsset(
    native_runtime::DecodedAssetCache& cache,
    const generated::AssetRecord& asset) {
  try {
    const auto view = cache.get_texture(Wide(asset.canonical_key), asset.png_sha256);
    if (view.texture == nullptr || view.metadata == nullptr ||
        view.texture->width != asset.width || view.texture->height != asset.height ||
        view.metadata->rgba8_sha256 != asset.decoded_rgba8_sha256 ||
        view.texture->rgba8.size() != static_cast<std::size_t>(asset.width) * asset.height * 4) {
      Fail(Status::kAssetMismatch, "decoded face sprite identity changed");
    }
    return *view.texture;
  } catch (const native_runtime::DecodedAssetError& error) {
    Fail(error.code() == "DECODED_CACHE_MISS" ? Status::kAssetMissing
                                               : Status::kAssetMismatch,
         std::string("decoded face sprite lookup failed: ") + error.code());
  }
}

const generated::FixtureRecord& Fixture(std::string_view char_info_sha256) {
  const auto found = std::find_if(
      std::begin(generated::kFixtures), std::end(generated::kFixtures),
      [char_info_sha256](const generated::FixtureRecord& value) {
        return char_info_sha256 == value.char_info_sha256;
      });
  if (found == std::end(generated::kFixtures)) {
    Fail(Status::kFixtureUnsupported,
         "effective CharInfo is outside the four authoritative face-plan fixtures");
  }
  return *found;
}

void ValidateParts(const native_parts::Selection& selection,
                   const generated::FixtureRecord& fixture) {
  std::set<native_parts::Logical> expected;
  for (std::uint32_t index = 0; index < fixture.layer_count; ++index) {
    const auto& layer = generated::kLayers[fixture.first_layer + index];
    const auto logical = Logical(layer.logical_name);
    expected.insert(logical);
    const auto& selected = Selected(selection, logical);
    if (!selected.resolved || !selected.enabled || selected.is_nothing ||
        selected.selector != layer.selector || selected.entry == nullptr ||
        selected.entry->record_name != layer.record_name ||
        selected.entry->texture_name != generated::kAssets[layer.asset_index].texture_name) {
      Fail(Status::kPartsMismatch, "native Parts ordinary face selection changed");
    }
  }
  constexpr std::array<native_parts::Logical, 10> ordinary = {
      native_parts::Logical::kEye, native_parts::Logical::kEyeHighlight,
      native_parts::Logical::kEyelashUpper, native_parts::Logical::kEyelashLower,
      native_parts::Logical::kEyelidUpper, native_parts::Logical::kEyelidLower,
      native_parts::Logical::kEyebrow, native_parts::Logical::kMouth,
      native_parts::Logical::kMustache, native_parts::Logical::kMole};
  for (const auto logical : ordinary) {
    const bool enabled = Selected(selection, logical).enabled;
    if (enabled != expected.contains(logical)) {
      Fail(Status::kPartsMismatch, "native Parts ordinary face enabled inventory changed");
    }
  }
  if (fixture.faceline_kind == 1) {
    const auto& wrinkle = Selected(selection, native_parts::Logical::kWrinkleUpper);
    if (!wrinkle.enabled || wrinkle.selector != 1 || wrinkle.entry == nullptr ||
        wrinkle.entry->record_name != "WrinkleUpper00") {
      Fail(Status::kPartsMismatch, "Spider-Man Noir wrinkle selection changed");
    }
  } else if (fixture.faceline_kind == 2) {
    const auto& beard = Selected(selection, native_parts::Logical::kBeardShort);
    if (!beard.enabled || beard.selector != 8 || beard.entry == nullptr ||
        beard.entry->record_name != "BeardShort07") {
      Fail(Status::kPartsMismatch, "Johnny BeardShort selection changed");
    }
  }
}

void RequireHash(std::span<const std::uint8_t> bytes, const char* expected,
                 Status status, std::string_view description) {
  if (Sha256(bytes) != expected) {
    Fail(status, std::string(description) + " digest changed");
  }
}

}  // namespace

struct FacePlan::Storage final {
  Palette palette{};
  std::vector<LayerPlanView> layer_views;
  std::vector<std::vector<double>> layer_pixels;
  std::vector<std::uint8_t> pass0;
  std::vector<std::uint8_t> case21;
  std::vector<std::uint8_t> mask_final;
  std::vector<std::uint8_t> mask_mesh;
  std::vector<std::uint8_t> audit0;
  std::vector<std::uint8_t> audit1;
  std::vector<double> mask_rgba64;
  std::vector<std::uint8_t> head_rgba8;
  std::vector<double> head_rgba64;
  Report report{};
};

const ColorVector& Palette::get(PaletteRole role) const {
  const std::size_t index = static_cast<std::size_t>(role);
  if (index >= colors.size()) throw std::out_of_range("native face palette role");
  return colors[index];
}

FacePlan::FacePlan() = default;
FacePlan::~FacePlan() = default;
FacePlan::FacePlan(FacePlan&&) noexcept = default;
FacePlan& FacePlan::operator=(FacePlan&&) noexcept = default;

const Palette& FacePlan::palette() const {
  if (!storage_) throw std::logic_error("native face plan is empty");
  return storage_->palette;
}
std::span<const LayerPlanView> FacePlan::layers() const {
  return storage_ ? std::span<const LayerPlanView>(storage_->layer_views)
                  : std::span<const LayerPlanView>();
}
ConstRgba8View FacePlan::mask_final_rgba8() const {
  return storage_ ? ConstRgba8View{storage_->mask_final.data(), storage_->mask_final.size(),
                                  kMaskWidth * 4, kMaskWidth, kMaskHeight}
                  : ConstRgba8View{};
}
ConstRgba8View FacePlan::mask_mesh_rgba8() const {
  return storage_ ? ConstRgba8View{storage_->mask_mesh.data(), storage_->mask_mesh.size(),
                                  kMaskWidth * 4, kMaskWidth, kMaskHeight}
                  : ConstRgba8View{};
}
ConstRgba64View FacePlan::generated_mask_rgba64() const {
  return storage_ ? ConstRgba64View{storage_->mask_rgba64.data(), storage_->mask_rgba64.size(),
                                   kMaskWidth * 4 * sizeof(double), kMaskWidth, kMaskHeight}
                  : ConstRgba64View{};
}
ConstRgba8View FacePlan::head_albedo_rgba8() const {
  return storage_ && !storage_->head_rgba8.empty()
             ? ConstRgba8View{storage_->head_rgba8.data(), storage_->head_rgba8.size(),
                              LTD_FACE_RUNTIME_FACELINE_WIDTH * 4,
                              LTD_FACE_RUNTIME_FACELINE_WIDTH,
                              LTD_FACE_RUNTIME_FACELINE_HEIGHT}
             : ConstRgba8View{};
}
ConstRgba64View FacePlan::generated_head_albedo_rgba64() const {
  return storage_ && !storage_->head_rgba64.empty()
             ? ConstRgba64View{storage_->head_rgba64.data(), storage_->head_rgba64.size(),
                               LTD_FACE_RUNTIME_FACELINE_WIDTH * 4 * sizeof(double),
                               LTD_FACE_RUNTIME_FACELINE_WIDTH,
                               LTD_FACE_RUNTIME_FACELINE_HEIGHT}
             : ConstRgba64View{};
}
const Report& FacePlan::report() const {
  if (!storage_) throw std::logic_error("native face plan is empty");
  return storage_->report;
}

std::span<const AssetRequirement> RequiredAssets() {
  static const std::array<AssetRequirement, std::size(generated::kAssets)> assets = [] {
    std::array<AssetRequirement, std::size(generated::kAssets)> output{};
    for (std::size_t index = 0; index < output.size(); ++index) {
      output[index] = Requirement(generated::kAssets[index]);
    }
    return output;
  }();
  return assets;
}

std::string_view SourceBundleSha256() { return generated::kSourceBundleSha256; }
std::string_view ColorTableSha256() { return generated::kColorTableSha256; }
std::string_view FaceMipManifestSha256() { return generated::kFaceMipsSha256; }
std::string_view FacelineLedgerSha256() { return generated::kFacelineLedgerSha256; }

std::string_view StatusName(Status status) {
  constexpr std::array<std::string_view, 13> names = {
      "ok", "invalid_argument", "source_mismatch", "fixture_unsupported",
      "parts_selection_failed", "parts_mismatch", "asset_missing",
      "asset_mismatch", "plan_mismatch", "face_runtime_failed",
      "output_mismatch", "rounding_mode", "allocation_failed"};
  const std::size_t index = static_cast<std::size_t>(status);
  return index < names.size() ? names[index] : std::string_view("unknown");
}

Status Build(const BuildRequest& request, FacePlan* output, std::string* error) {
  if (error != nullptr) error->clear();
  try {
    if (output == nullptr || request.parts_catalog == nullptr ||
        request.decoded_assets == nullptr || request.raw_char_info.size() != kCharInfoSize) {
      Fail(Status::kInvalidArgument, "native face-plan request is incomplete");
    }
    if (request.parts_catalog_sha256 != kPartsCatalogSha256 ||
        request.parts_catalog_sha256 != generated::kPartsCatalogSha256) {
      Fail(Status::kSourceMismatch, "native Parts catalog pin changed");
    }
    if (std::fegetround() != FE_TONEAREST) {
      Fail(Status::kRoundingMode, "native face plan requires FE_TONEAREST");
    }
    native_parts::Selection selection{};
    std::string selection_error;
    if (!native_parts::Select(*request.parts_catalog, request.raw_char_info,
                              &selection, &selection_error)) {
      Fail(Status::kPartsSelectionFailed, selection_error);
    }
    const auto effective = std::span<const std::uint8_t>(selection.effective_char_info);
    const std::string effective_sha = Sha256(effective);
    const auto& fixture = Fixture(effective_sha);
    ValidateParts(selection, fixture);

    auto storage = std::make_unique<FacePlan::Storage>();
    storage->palette = BuildPalette(effective);
    storage->layer_views.reserve(fixture.layer_count);
    storage->layer_pixels.reserve(fixture.layer_count);
    std::vector<ltd_face_mask_layer> native_layers;
    native_layers.reserve(fixture.layer_count);

    for (std::uint32_t layer_index = 0; layer_index < fixture.layer_count;
         ++layer_index) {
      const auto& source = generated::kLayers[fixture.first_layer + layer_index];
      if (std::string_view(source.fixture_name) != fixture.name || source.asset_index < 0 ||
          static_cast<std::size_t>(source.asset_index) >= std::size(generated::kAssets)) {
        Fail(Status::kSourceMismatch, "generated face layer catalog is internally inconsistent");
      }
      ValidateDerivedPlacement(source, effective);
      const auto& asset = generated::kAssets[source.asset_index];
      if (static_cast<std::uint32_t>(std::floor(DoubleFromBits(source.biased_lod_bits) + 0.5)) !=
          asset.mip_level) {
        Fail(Status::kPlanMismatch, "face sprite point-mip selection changed");
      }
      const auto& texture = GetAsset(*request.decoded_assets, asset);
      storage->layer_pixels.emplace_back(kMaskWidth * kMaskHeight * 4);
      auto& pixels = storage->layer_pixels.back();
      std::array<double, 6> affine{};
      for (std::size_t index = 0; index < affine.size(); ++index) {
        affine[index] = DoubleFromBits(source.affine_bits[index]);
      }
      std::array<double, 3> c1{};
      std::array<double, 3> c2{};
      PaletteRole color_role = PaletteRole::kEye;
      if (std::string_view(source.logical_name) == "mustache") color_role = PaletteRole::kMustache;
      else if (std::string_view(source.logical_name) == "eyebrow") color_role = PaletteRole::kEyebrow;
      else if (std::string_view(source.logical_name) == "eye") color_role = PaletteRole::kEye;
      const auto& color = storage->palette.get(color_role);
      if (source.shader_kind == LTD_FACE_MASK_SHADER_CONSTANT_RGB_SAMPLED_R_ALPHA ||
          source.shader_kind == LTD_FACE_MASK_SHADER_EYE_MODE_7) {
        std::copy_n(color.srgb.begin(), 3, c1.begin());
      }
      auto source_image = ConstImage(texture);
      auto destination = MutableImage64(pixels, kMaskWidth, kMaskHeight);
      const auto status = ltd_face_mask_sample_shade_affine(
          &source_image, affine.data(), static_cast<std::int32_t>(source.mirrored),
          static_cast<std::int32_t>(source.shader_kind), c1.data(), c2.data(),
          &destination);
      if (status != LTD_FACE_RUNTIME_OK) {
        Fail(Status::kFaceRuntimeFailed,
             std::string("native face layer kernel failed: ") +
                 ltd_face_runtime_status_name(status));
      }
      LayerPlanView view{};
      view.logical_name = source.logical_name;
      view.dispatcher_case = source.dispatcher_case;
      view.selector = source.selector;
      view.record_name = source.record_name;
      view.parts_config_sha256 = source.parts_config_sha256;
      view.asset = Requirement(asset);
      view.shader_kind = source.shader_kind;
      view.mirrored = source.mirrored != 0;
      view.affine = affine;
      for (std::size_t index = 0; index < 2; ++index) {
        view.center[index] = DoubleFromBits(source.center_bits[index]);
        view.extent[index] = DoubleFromBits(source.extent_bits[index]);
        view.rotate_axis[index] = DoubleFromBits(source.rotate_axis_bits[index]);
      }
      view.rotation_degrees = DoubleFromBits(source.rotation_bits);
      view.rho = DoubleFromBits(source.rho_bits);
      view.biased_lod = DoubleFromBits(source.biased_lod_bits);
      storage->layer_views.push_back(view);
      native_layers.push_back({source.dispatcher_case, 0,
          {pixels.data(), pixels.size() * sizeof(double),
           kMaskWidth * 4 * sizeof(double), kMaskWidth, kMaskHeight}});
    }

    constexpr std::size_t mask_bytes = kMaskWidth * kMaskHeight * 4;
    storage->pass0.resize(mask_bytes);
    storage->case21.resize(mask_bytes);
    storage->mask_final.resize(mask_bytes);
    storage->mask_mesh.resize(mask_bytes);
    storage->audit0.resize(mask_bytes * fixture.layer_count);
    storage->audit1.resize(mask_bytes * fixture.layer_count);
    auto pass0 = MutableImage(storage->pass0, kMaskWidth, kMaskHeight);
    auto case21 = MutableImage(storage->case21, kMaskWidth, kMaskHeight);
    auto final_target = MutableImage(storage->mask_final, kMaskWidth, kMaskHeight);
    auto mesh = MutableImage(storage->mask_mesh, kMaskWidth, kMaskHeight);
    ltd_face_rgba8_stack audit0{storage->audit0.empty() ? nullptr : storage->audit0.data(),
                                storage->audit0.size(), fixture.layer_count ? mask_bytes : 0,
                                fixture.layer_count ? kMaskWidth * 4 : 0};
    ltd_face_rgba8_stack audit1{storage->audit1.empty() ? nullptr : storage->audit1.data(),
                                storage->audit1.size(), fixture.layer_count ? mask_bytes : 0,
                                fixture.layer_count ? kMaskWidth * 4 : 0};
    const auto pipeline_status = ltd_face_mask_pipeline(
        native_layers.empty() ? nullptr : native_layers.data(), fixture.layer_count,
        kMaskWidth, kMaskHeight, &pass0, &case21, &final_target, &mesh,
        &audit0, &audit1);
    if (pipeline_status != LTD_FACE_RUNTIME_OK) {
      Fail(Status::kFaceRuntimeFailed,
           std::string("native MiiMask pipeline failed: ") +
               ltd_face_runtime_status_name(pipeline_status));
    }
    RequireHash(storage->mask_final, fixture.mask_final_rgba8_sha256,
                Status::kOutputMismatch, "Mask0 final RGBA8");
    RequireHash(storage->mask_mesh, fixture.mask_mesh_rgba8_sha256,
                Status::kOutputMismatch, "Mask0 mesh RGBA8");
    storage->mask_rgba64.resize(mask_bytes);
    for (std::size_t index = 0; index < mask_bytes; ++index) {
      storage->mask_rgba64[index] = static_cast<double>(storage->mask_mesh[index]) / 255.0;
    }
    RequireHash(Bytes(std::span<const double>(storage->mask_rgba64)),
                fixture.mask_rgba64_sha256, Status::kOutputMismatch,
                "Mask0 generated RGBA64");

    ltd_face_faceline_raster_report raster{};
    if (fixture.faceline_kind != 0) {
      if (fixture.faceline_asset_index < 0 ||
          static_cast<std::size_t>(fixture.faceline_asset_index) >=
              std::size(generated::kAssets)) {
        Fail(Status::kSourceMismatch, "faceline asset index is invalid");
      }
      const auto& asset = generated::kAssets[fixture.faceline_asset_index];
      const auto& texture = GetAsset(*request.decoded_assets, asset);
      auto source_image = ConstImage(texture);
      storage->head_rgba8.resize(
          LTD_FACE_RUNTIME_FACELINE_WIDTH * LTD_FACE_RUNTIME_FACELINE_HEIGHT * 4);
      auto destination = MutableImage(storage->head_rgba8,
                                      LTD_FACE_RUNTIME_FACELINE_WIDTH,
                                      LTD_FACE_RUNTIME_FACELINE_HEIGHT);
      const auto& skin = storage->palette.get(PaletteRole::kSkin).rgba8;
      ltd_face_runtime_status status = LTD_FACE_RUNTIME_INVALID_ARGUMENT;
      if (fixture.faceline_kind == 1) {
        status = ltd_face_faceline_wrinkle(
            &source_image, skin.data(),
            static_cast<double>(FloatFromBits(fixture.faceline_parameters[0])),
            static_cast<double>(FloatFromBits(fixture.faceline_parameters[1])),
            static_cast<double>(FloatFromBits(fixture.faceline_parameters[2])),
            static_cast<double>(FloatFromBits(fixture.faceline_parameters[3])),
            &destination, &raster);
      } else if (fixture.faceline_kind == 2) {
        const std::array<double, 4> c1 = {
            static_cast<double>(FloatFromBits(0x3eaaaa9fu)),
            static_cast<double>(FloatFromBits(0x3ecccccdu)),
            static_cast<double>(FloatFromBits(0x3ecccccdu)), 1.0};
        const auto& stubble = storage->palette.get(PaletteRole::kStubble).srgb;
        status = ltd_face_faceline_johnny(&source_image, skin.data(), c1.data(),
                                          stubble.data(), &destination);
      }
      if (status != LTD_FACE_RUNTIME_OK) {
        Fail(Status::kFaceRuntimeFailed,
             std::string("native faceline kernel failed: ") +
                 ltd_face_runtime_status_name(status));
      }
      RequireHash(storage->head_rgba8, fixture.head_rgba8_sha256,
                  Status::kOutputMismatch, "Head816 generated RGBA8");
      storage->head_rgba64.resize(storage->head_rgba8.size());
      for (std::size_t index = 0; index < storage->head_rgba8.size(); ++index) {
        storage->head_rgba64[index] =
            static_cast<double>(storage->head_rgba8[index]) / 255.0;
      }
      RequireHash(Bytes(std::span<const double>(storage->head_rgba64)),
                  fixture.head_rgba64_sha256, Status::kOutputMismatch,
                  "Head816 generated RGBA64");
    }

    storage->report = {
        fixture.name, fixture.share_mii_sha256, fixture.char_info_sha256,
        fixture.layer_count, fixture.faceline_kind,
        fixture.mask_final_rgba8_sha256, fixture.mask_mesh_rgba8_sha256,
        fixture.mask_rgba64_sha256, fixture.head_rgba8_sha256,
        fixture.head_rgba64_sha256, raster};
    output->storage_ = std::move(storage);
    return Status::kOk;
  } catch (const Failure& failure) {
    if (error != nullptr) *error = failure.message;
    return failure.status;
  } catch (const std::bad_alloc&) {
    if (error != nullptr) *error = "native face-plan allocation failed";
    return Status::kAllocationFailed;
  } catch (const std::exception& exception) {
    if (error != nullptr) *error = exception.what();
    return Status::kSourceMismatch;
  }
}

}  // namespace infinimii::native_face_plan
