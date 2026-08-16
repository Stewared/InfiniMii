#pragma once

/*
 * Four-fixture native material publication producer.
 *
 * The offline generated catalog fixes normalized renderer constants and
 * source identities.  Build authenticates the exact LTD/CharInfo case and
 * every live evidence/BNTX/manifest/mip byte before exposing immutable typed
 * provider inputs.  No Python-shaped state, packed geometry, or final pixels
 * cross this boundary.
 */

#include "decoded_asset_cache.h"
#include "native_face_plan.h"
#include "native_material_provider.h"
#include "native_noseline_pipeline_bridge.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace infinimii::native_runtime_material_adapter {

inline constexpr std::uint32_t kAbiVersion = 2;
inline constexpr std::size_t kCharInfoSize = 152;
inline constexpr std::string_view kContractCanonical =
    "ltd.native.runtime-material-adapter|abi=2|fixtures=mii0,mii1,mii2,mii4|"
    "catalog=typed-generated1|inputs=ltd+charinfo+view+size+repository|"
    "assets=authored-bntx+manifest+all-mips+evidence|cache=decoded-chain|"
    "publications=normalized-source+unique-mips+scene-index|"
    "trusted-provider=opaque-lease+same-decoded-cache+publication-digest|"
    "face=face-plan+ugc-rgba64|noseline=owned-nine-mips|"
    "ownership=raii|source-sealed=1";
inline constexpr std::string_view kContractSha256 =
    "225c87ceb0042d45ced4e84d3b1e0af4f12d8a0411f3a3a03a9c12e9ebfd4769";

enum class Status : std::uint32_t {
  kOk = 0,
  kInvalidArgument,
  kModuleMismatch,
  kCatalogMismatch,
  kFixtureUnsupported,
  kSourceMismatch,
  kCaseUnsupported,
  kAssetMissing,
  kAssetMismatch,
  kCacheFailed,
  kFaceMismatch,
  kProviderFailed,
  kAllocationFailed,
};

struct BuildRequest final {
  std::filesystem::path repository_root;
  std::span<const std::uint8_t> share_mii;
  std::span<const std::uint8_t> effective_char_info;
  std::uint32_t view_kind = 0;
  std::uint32_t raster_size = 0;
  std::string_view expected_catalog_sha256;
  std::string_view expected_source_bundle_sha256;
  native_runtime::DecodedAssetCache* decoded_assets = nullptr;
  const native_face_plan::FacePlan* face_plan = nullptr;
  /* Empty only for the one accepted fixture whose native decoder reports ABSENT. */
  std::span<const std::uint8_t> user_facepaint_rgba8;
};

struct MaterialPublicationView final {
  std::uint32_t scene_draw_index = 0;
  const ltd_native_material_normalized_source* material = nullptr;
  /* Each authored chain appears exactly once across a case's publications. */
  std::span<const ltd_native_material_mip_chain_source> mip_chains;
};

struct UgcPublicationView final {
  std::string_view source_key;
  std::span<const std::uint8_t> rgba8;
  std::uint32_t width = 0;
  std::uint32_t height = 0;
  ltd_native_facepaint_tex_srt tex_srt{};
};

struct NoseLinePublicationView final {
  std::string_view source_key;
  std::span<const double> mip_rgba;
  std::array<ltd_noseline12_mip_level, LTD_NOSELINE12_MIP_LEVEL_COUNT> levels{};
  std::string_view texture_manifest_sha256;
  std::string_view decoded_mips_sha256;
  std::uint32_t scene_draw_index = UINT32_MAX;
};

struct Report final {
  std::string_view fixture_name;
  std::string_view share_mii_sha256;
  std::string_view effective_char_info_sha256;
  std::string_view catalog_sha256;
  std::string_view source_bundle_sha256;
  std::string_view publication_sha256;
  std::uint32_t view_kind = 0;
  std::uint32_t raster_size = 0;
  std::uint32_t material_count = 0;
  std::uint32_t unique_mip_chain_count = 0;
  std::uint32_t mip_level_count = 0;
  std::uint32_t noseline_mip_level_count = 0;
  std::uint32_t evidence_document_count = 0;
  std::uint64_t authenticated_source_bytes = 0;
  bool has_generated_head_albedo = false;
  bool has_generated_mask = false;
  bool has_user_facepaint = false;
  bool has_noseline = false;
  std::uint32_t noseline_scene_draw_index = UINT32_MAX;
};

class MaterialBundle final {
 public:
  MaterialBundle();
  ~MaterialBundle();
  MaterialBundle(const MaterialBundle&) = delete;
  MaterialBundle& operator=(const MaterialBundle&) = delete;
  MaterialBundle(MaterialBundle&&) noexcept;
  MaterialBundle& operator=(MaterialBundle&&) noexcept;

  [[nodiscard]] std::span<const MaterialPublicationView> publications() const;
  [[nodiscard]] std::span<const ltd_native_material_mip_chain_source>
  unique_mip_chains() const;
  [[nodiscard]] const ltd_native_material_face_views& face_views() const;
  [[nodiscard]] UgcPublicationView ugc() const;
  [[nodiscard]] NoseLinePublicationView noseline() const;
  [[nodiscard]] const Report& report() const;

  /* Publish exactly once into a fresh provider; provider copies every input. */
  Status Publish(ltd_native_material_provider* provider, std::string* error) const;

  /* Publish into a fresh provider backed by this bundle's decoded cache.
   * The provider retains an opaque bundle lease and borrows authenticated
   * evidence bytes; no STL ownership crosses the provider boundary. */
  Status PublishTrusted(ltd_native_material_provider* provider,
                        std::string* error) const;

 private:
  struct Storage;
  std::shared_ptr<Storage> storage_;
  friend Status Build(const BuildRequest&, MaterialBundle*, std::string*);
};

[[nodiscard]] std::string_view CatalogSha256();
[[nodiscard]] std::string_view SourceBundleSha256();
[[nodiscard]] std::string_view StatusName(Status status);

/* Transactional: output is replaced only after all live sources authenticate. */
Status Build(const BuildRequest& request, MaterialBundle* output, std::string* error);

}  // namespace infinimii::native_runtime_material_adapter
