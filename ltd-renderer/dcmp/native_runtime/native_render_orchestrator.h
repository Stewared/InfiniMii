#ifndef LTD_NATIVE_RENDER_ORCHESTRATOR_H
#define LTD_NATIVE_RENDER_ORCHESTRATOR_H

/*
 * Lifetime-owning end-to-end boundary for one authenticated LTD render.
 *
 * Prepare copies every caller publication needed by the draw pipeline and is
 * side-effect free. Execute is the only operation that allocates a frame or
 * produces pixels. No Python-shaped packed draw record is accepted here:
 * native scene geometry and native_material_field_packer create every draw
 * input consumed by native_render_pipeline ABI 2.
 */

#include "decoded_asset_cache.h"
#include "native_draw_descriptor_builder.h"
#include "native_face_plan.h"
#include "native_material_provider.h"
#include "native_noseline_pipeline_bridge.h"
#include "native_render_pipeline.h"
#include "native_scene_cache_adapter.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace infinimii::native_runtime_material_adapter {
class MaterialBundle;
}

namespace infinimii::native_render_orchestrator {

inline constexpr std::uint32_t kAbiVersion = 4;
inline constexpr std::string_view kContractCanonical =
    "ltd.native.render.orchestrator|abi=4|scene-cache-adapter=1|parts=1|"
    "face-plan=1|material-provider=2|runtime-material-adapter=2|"
    "trusted-provider=optional-opaque-bundle-lease+same-borrowed-cache|"
    "trusted-authority=bundle-report+materials+face+ugc+noseline|"
    "provider-lifetime=prepare-pack-loop|"
    "field-packer=1|material-schedule=1|"
    "descriptor=1|draw=2|noseline-bridge=1|pipeline=2|"
    "schedule=single-authenticated-mixed-loop|presentation=premultiplied-rgba,"
    "portrait-linear,full-body-linear,ss1|ownership=prepare-raii-execute-copy|"
    "reusable-execute=detached-authenticated-plan,fresh-png-cancel-context,"
    "module-and-fenv-recheck,no-output-cache,caller-serialized|"
    "per-draw-written=unavailable|activation_ready=1";
inline constexpr std::string_view kContractSha256 =
    "3be14b1a393a6cc0f7ecfd72624b106550813319debac4341c3f424a3de7c1fa";

enum class Status : std::uint32_t {
  kOk = 0,
  kInvalidArgument,
  kModuleMismatch,
  kPartsFailed,
  kSceneFailed,
  kFaceFailed,
  kMaterialProviderFailed,
  kMaterialInventoryIncomplete,
  kMaterialPackFailed,
  kScheduleFailed,
  kDescriptorFailed,
  kNoseLineFailed,
  kPipelineFailed,
  kOutputFailed,
  kCancelled,
  kNotAdmitted,
  kAllocationFailed,
};

/* One native-source publication, keyed to its authored scene draw index. */
struct MaterialPublication final {
  std::uint32_t scene_draw_index = 0;
  const ltd_native_material_normalized_source* material = nullptr;
  std::span<const ltd_native_material_mip_chain_source> mip_chains;
};

struct UgcPublication final {
  std::string_view source_key;
  std::span<const std::uint8_t> rgba8;
  std::uint32_t width = 0;
  std::uint32_t height = 0;
  ltd_native_facepaint_tex_srt tex_srt{};
};

struct NoseLinePublication final {
  std::string_view source_key;
  std::span<const double> mip_rgba;
  std::array<ltd_noseline12_mip_level, LTD_NOSELINE12_MIP_LEVEL_COUNT> levels{};
  std::string_view texture_manifest_sha256;
  std::string_view decoded_mips_sha256;
};

struct Request final {
  native_runtime::DecodedAssetCache* decoded_assets = nullptr;
  ltd_native_scene_cache_adapter* scene_assets = nullptr;
  const native_parts::Catalog* parts_catalog = nullptr;
  std::span<const std::uint8_t> parts_catalog_bytes;
  std::array<std::uint8_t, 32> parts_catalog_sha256{};
  std::string_view parts_catalog_sha256_hex;
  std::span<const std::uint8_t> raw_char_info;

  std::span<const MaterialPublication> materials;
  /* Optional production fast path. When present, this exact authenticated
   * bundle is the sole material/face/UGC/NoseLine authority and publishes
   * transactionally into a provider borrowing decoded_assets. All request-side
   * material and dynamic publications must then be empty. The ordinary typed-
   * publication path remains available to isolated callers. */
  const native_runtime_material_adapter::MaterialBundle* trusted_material_bundle = nullptr;
  /* The orchestrator copies these exact dynamic pixels during Prepare. */
  std::string_view generated_mask_source_key;
  std::string_view generated_head_source_key;
  UgcPublication ugc;
  NoseLinePublication noseline;

  infinimii_native_png_encoder* png_encoder = nullptr;
  ltd_native_render_source_seals frame_seals{};
  ltd_native_material_field_source_seals field_seals{};
  ltd_native_draw_descriptor_source_seals descriptor_seals{};
  ltd_native_render_cancel_fn is_cancelled = nullptr;
  void* cancel_context = nullptr;
  std::uint32_t view_kind = 0;
  std::uint32_t raster_size = 0;
  std::uint32_t maximum_draws = LTD_NATIVE_SCENE_ASSEMBLER_MAX_DRAWS;
};

struct PrepareReport final {
  std::uint32_t scene_draw_count = 0;
  std::uint32_t general_draw_count = 0;
  std::uint32_t material_count = 0;
  std::uint32_t descriptor_count = 0;
  bool parts_selected = false;
  bool face_plan_built = false;
  bool nose_line_present = false;
  bool field_packer_admitted = false;
};

struct DrawReport final {
  std::string resource_name;
  std::string model_name;
  std::string group;
  std::uint32_t profile = 0;
  std::uint32_t authored_index = 0;
  std::uint32_t scheduled_index = 0;
  std::uint64_t submitted_triangles = 0;
  bool nose_line = false;
  bool written_fragments_available = false;
};

struct FaceReport final {
  std::string fixture_name;
  std::string share_mii_sha256;
  std::string effective_char_info_sha256;
  std::string mask_final_rgba8_sha256;
  std::string mask_mesh_rgba8_sha256;
  std::string mask_rgba64_sha256;
  std::string head_rgba8_sha256;
  std::string head_rgba64_sha256;
  std::uint32_t ordinary_layer_count = 0;
  std::uint32_t faceline_kind = 0;
};

struct Output final {
  std::vector<std::uint8_t> png;
  std::vector<std::uint8_t> transferred_pixels;
  std::vector<DrawReport> draws;
  ltd_native_render_report pipeline_report{};
  ltd_native_scene_assembly_summary scene_summary{};
  FaceReport face_report{};
  bool prepared = false;
  bool executed = false;
  bool production_activation_ready = false;
};

/* Request-scoped resources that must never be retained by a cached plan. */
struct ExecutionContext final {
  infinimii_native_png_encoder* png_encoder = nullptr;
  ltd_native_render_cancel_fn is_cancelled = nullptr;
  void* cancel_context = nullptr;
};

class PreparedRender final {
 public:
  PreparedRender();
  ~PreparedRender();
  PreparedRender(const PreparedRender&) = delete;
  PreparedRender& operator=(const PreparedRender&) = delete;
  PreparedRender(PreparedRender&&) noexcept;
  PreparedRender& operator=(PreparedRender&&) noexcept;

 private:
  struct Storage;
  std::unique_ptr<Storage> storage_;
  friend Status Prepare(const Request&, PreparedRender*, PrepareReport*, std::string*);
  friend Status Execute(PreparedRender*, Output*, std::string*);
  friend Status ExecuteReusable(
      PreparedRender*, const ExecutionContext&, Output*, std::string*);
  friend Status DetachRequestContext(PreparedRender*, std::string*);
};

[[nodiscard]] std::string_view StatusName(Status status);
[[nodiscard]] bool ActivationReady();

/* Transactional: output is replaced only after all inputs authenticate. */
Status Prepare(const Request& request, PreparedRender* prepared,
               PrepareReport* report, std::string* error);
Status Execute(PreparedRender* prepared, Output* output, std::string* error);
/* Clears retained request-scoped pointers and permanently disables Execute. */
Status DetachRequestContext(PreparedRender* prepared, std::string* error);
/*
 * Re-rasterizes an already authenticated immutable plan. This never caches or
 * reuses output bytes. Callers must serialize access and must reauthenticate
 * every request/source seal before choosing an existing plan.
 */
Status ExecuteReusable(PreparedRender* prepared, const ExecutionContext& context,
                       Output* output, std::string* error);
Status BuildAndExecute(const Request& request, Output* output, std::string* error);

}  // namespace infinimii::native_render_orchestrator

#endif
