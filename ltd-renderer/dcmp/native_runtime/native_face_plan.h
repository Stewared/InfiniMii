#pragma once

#include "decoded_asset_cache.h"
#include "native_face_runtime.h"
#include "native_parts_selector.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace infinimii::native_face_plan {

inline constexpr std::uint32_t kAbiVersion = 1;
inline constexpr std::size_t kCharInfoSize = 152;
inline constexpr std::size_t kMaskWidth = 256;
inline constexpr std::size_t kMaskHeight = 256;
inline constexpr std::string_view kContractSha256 =
    "1afd8e391d2d7b2f6e50971e8c575a258eb2921e20e39522b000f515854b406d";
inline constexpr std::string_view kPartsCatalogSha256 =
    "d8d56e7ee1e291e2e4cc213ef88521b594093a83952747f1d3c8ab0ca5b00523";

enum class Status : std::uint32_t {
  kOk = 0,
  kInvalidArgument,
  kSourceMismatch,
  kFixtureUnsupported,
  kPartsSelectionFailed,
  kPartsMismatch,
  kAssetMissing,
  kAssetMismatch,
  kPlanMismatch,
  kFaceRuntimeFailed,
  kOutputMismatch,
  kRoundingMode,
  kAllocationFailed,
};

enum class PaletteRole : std::uint32_t {
  kSkin = 0,
  kHairPrimary,
  kHairSecondary,
  kBeard,
  kEye,
  kEyeShadow,
  kEyebrow,
  kMouth,
  kMustache,
  kStubble,
  kCount,
};

struct ColorVector final {
  std::uint16_t selector = 0;
  std::array<std::uint8_t, 4> rgba8{};
  std::array<double, 4> srgb{};
  std::array<double, 4> linear{};
};

struct Palette final {
  std::array<ColorVector, static_cast<std::size_t>(PaletteRole::kCount)> colors{};
  [[nodiscard]] const ColorVector& get(PaletteRole role) const;
};

struct AssetRequirement final {
  std::string_view texture_name;
  std::uint32_t mip_level = 0;
  std::string_view canonical_key;
  std::string_view png_sha256;
  std::string_view decoded_rgba8_sha256;
  std::uint32_t width = 0;
  std::uint32_t height = 0;
  std::string_view packed_bntx_sha256;
};

struct LayerPlanView final {
  std::string_view logical_name;
  std::int32_t dispatcher_case = -1;
  std::uint16_t selector = 0;
  std::string_view record_name;
  std::string_view parts_config_sha256;
  AssetRequirement asset;
  std::uint32_t shader_kind = 0;
  bool mirrored = false;
  std::array<double, 6> affine{};
  std::array<double, 2> center{};
  std::array<double, 2> extent{};
  double rotation_degrees = 0.0;
  double rho = 0.0;
  double biased_lod = 0.0;
  std::array<double, 2> rotate_axis{};
};

struct ConstRgba8View final {
  const std::uint8_t* pixels = nullptr;
  std::size_t byte_count = 0;
  std::size_t row_stride = 0;
  std::uint32_t width = 0;
  std::uint32_t height = 0;
};

struct ConstRgba64View final {
  const double* pixels = nullptr;
  std::size_t element_count = 0;
  std::size_t row_stride_bytes = 0;
  std::uint32_t width = 0;
  std::uint32_t height = 0;
};

struct Report final {
  std::string_view fixture_name;
  std::string_view share_mii_sha256;
  std::string_view effective_char_info_sha256;
  std::uint32_t ordinary_layer_count = 0;
  std::uint32_t faceline_kind = 0;  // 0 none, 1 Noir wrinkle, 2 Johnny
  std::string_view mask_final_rgba8_sha256;
  std::string_view mask_mesh_rgba8_sha256;
  std::string_view mask_rgba64_sha256;
  std::string_view head_rgba8_sha256;
  std::string_view head_rgba64_sha256;
  ltd_face_faceline_raster_report faceline_raster{};
};

struct BuildRequest final {
  const native_parts::Catalog* parts_catalog = nullptr;
  std::string_view parts_catalog_sha256;
  std::span<const std::uint8_t> raw_char_info;
  native_runtime::DecodedAssetCache* decoded_assets = nullptr;
};

class FacePlan final {
 public:
  FacePlan();
  ~FacePlan();
  FacePlan(const FacePlan&) = delete;
  FacePlan& operator=(const FacePlan&) = delete;
  FacePlan(FacePlan&&) noexcept;
  FacePlan& operator=(FacePlan&&) noexcept;

  [[nodiscard]] const Palette& palette() const;
  [[nodiscard]] std::span<const LayerPlanView> layers() const;
  [[nodiscard]] ConstRgba8View mask_final_rgba8() const;
  [[nodiscard]] ConstRgba8View mask_mesh_rgba8() const;
  [[nodiscard]] ConstRgba64View generated_mask_rgba64() const;
  [[nodiscard]] ConstRgba8View head_albedo_rgba8() const;
  [[nodiscard]] ConstRgba64View generated_head_albedo_rgba64() const;
  [[nodiscard]] const Report& report() const;

 private:
  struct Storage;
  std::unique_ptr<Storage> storage_;
  friend Status Build(const BuildRequest&, FacePlan*, std::string*);
};

[[nodiscard]] std::span<const AssetRequirement> RequiredAssets();
[[nodiscard]] std::string_view SourceBundleSha256();
[[nodiscard]] std::string_view ColorTableSha256();
[[nodiscard]] std::string_view FaceMipManifestSha256();
[[nodiscard]] std::string_view FacelineLedgerSha256();
[[nodiscard]] std::string_view StatusName(Status status);

// Transactional: output is replaced only after every source, selection,
// decoded asset, kernel result, and output digest has been authenticated.
Status Build(const BuildRequest& request, FacePlan* output, std::string* error);

}  // namespace infinimii::native_face_plan
