#include "native_render_orchestrator.h"

#include "native_draw_runtime.h"
#include "native_draw_runtime_v2.h"
#include "native_material_schedule.h"
#include "native_runtime_material_adapter.h"

#include <algorithm>
#include <array>
#include <cfenv>
#include <cstring>
#include <limits>
#include <new>
#include <optional>
#include <utility>

namespace infinimii::native_render_orchestrator {
namespace {

template <typename Type, void (*Destroy)(Type*)>
using Handle = std::unique_ptr<Type, decltype(Destroy)>;

Status fail(Status status, std::string message, std::string* error) {
  if (error != nullptr) *error = std::move(message);
  return status;
}

bool text(std::string_view value) { return !value.empty() && value.find('\0') == value.npos; }

bool lower_sha(std::string_view value) {
  return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char value) {
    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
  });
}

bool same_text(const char* actual, std::string_view expected) {
  return actual != nullptr && std::string_view(actual) == expected;
}

bool all_zero(const std::array<std::uint8_t, 32>& value) {
  return std::all_of(value.begin(), value.end(), [](std::uint8_t byte) { return byte == 0; });
}

bool cancelled(const Request& request) {
  return request.is_cancelled != nullptr && request.is_cancelled(request.cancel_context) != 0;
}

bool zero_tex_srt(const ltd_native_facepaint_tex_srt& value) {
  const auto all_zero_values = [](const auto& values) {
    return std::all_of(std::begin(values), std::end(values),
                       [](const auto item) { return item == 0; });
  };
  return all_zero_values(value.size) && all_zero_values(value.offset) &&
         all_zero_values(value.scaling) && all_zero_values(value.translation) &&
         all_zero_values(value.affine_rows) && value.mode == 0 && value.rotation == 0;
}

bool same_tex_srt(const ltd_native_facepaint_tex_srt& left,
                  const ltd_native_facepaint_tex_srt& right) {
  return std::equal(std::begin(left.size), std::end(left.size), std::begin(right.size)) &&
         std::equal(std::begin(left.offset), std::end(left.offset), std::begin(right.offset)) &&
         std::equal(std::begin(left.scaling), std::end(left.scaling),
                    std::begin(right.scaling)) &&
         std::equal(std::begin(left.translation), std::end(left.translation),
                    std::begin(right.translation)) &&
         std::equal(std::begin(left.affine_rows), std::end(left.affine_rows),
                    std::begin(right.affine_rows)) &&
         left.mode == right.mode && left.rotation == right.rotation;
}

bool empty_trusted_ugc(const UgcPublication& value) {
  return value.source_key.empty() && value.rgba8.empty() && value.width == 0 &&
         value.height == 0 && zero_tex_srt(value.tex_srt);
}

bool empty_trusted_noseline(const NoseLinePublication& value) {
  return value.source_key.empty() && value.mip_rgba.empty() &&
         value.texture_manifest_sha256.empty() && value.decoded_mips_sha256.empty() &&
         std::all_of(value.levels.begin(), value.levels.end(), [](const auto& level) {
           return level.rgba_element_offset == 0 && level.width == 0 && level.height == 0;
         });
}

bool same_rgba64(const ltd_face_const_rgba64_image& actual,
                 const native_face_plan::ConstRgba64View& expected) {
  const std::size_t expected_bytes = expected.element_count * sizeof(double);
  return actual.width == expected.width && actual.height == expected.height &&
         actual.row_stride_bytes == expected.row_stride_bytes &&
         actual.buffer_size_bytes == expected_bytes &&
         (expected_bytes == 0 ||
          (actual.pixels != nullptr && expected.pixels != nullptr &&
           std::memcmp(actual.pixels, expected.pixels, expected_bytes) == 0));
}

std::uint32_t pipeline_profile(std::uint16_t program) {
  switch (program) {
    case 816: return LTD_NATIVE_RENDER_PROFILE_HEAD816;
    case 324: return LTD_NATIVE_RENDER_PROFILE_BODY324;
    case 336: return LTD_NATIVE_RENDER_PROFILE_BODY336;
    case 348: return LTD_NATIVE_RENDER_PROFILE_BODY348;
    case 372: return LTD_NATIVE_RENDER_PROFILE_EAR372;
    case 756: return LTD_NATIVE_RENDER_PROFILE_NOSE756;
    case 0: return LTD_NATIVE_RENDER_PROFILE_MASK0;
    case 612: return LTD_NATIVE_RENDER_PROFILE_HAIR612;
    case 564: return LTD_NATIVE_RENDER_PROFILE_HAIR564_EQUAL_ENDPOINT;
    case 468: return LTD_NATIVE_RENDER_PROFILE_BEARD468;
    case 984: return LTD_NATIVE_RENDER_PROFILE_OUTFIT_TOPS984;
    case 936: return LTD_NATIVE_RENDER_PROFILE_OUTFIT_BOTTOMS936;
    case 912: return LTD_NATIVE_RENDER_PROFILE_OUTFIT_SHOES912;
    default: return 0;
  }
}

bool valid_seals(const ltd_native_render_source_seals& seals) {
  return seals.ltd_source_sha256 != nullptr && lower_sha(seals.ltd_source_sha256) &&
         seals.active_parts_sha256 != nullptr && lower_sha(seals.active_parts_sha256) &&
         seals.asset_index_sha256 != nullptr && lower_sha(seals.asset_index_sha256) &&
         seals.scene_plan_sha256 != nullptr && lower_sha(seals.scene_plan_sha256) &&
         seals.material_plan_sha256 != nullptr && lower_sha(seals.material_plan_sha256);
}

Status authenticate_modules(std::string* error) {
  const auto mismatch = [&] { return fail(Status::kModuleMismatch,
      "one native orchestration dependency differs from its pinned ABI", error); };
  if (ltd_native_scene_cache_adapter_abi_version() !=
          LTD_NATIVE_SCENE_CACHE_ADAPTER_ABI_VERSION ||
      !same_text(ltd_native_scene_cache_adapter_contract_sha256(),
                 LTD_NATIVE_SCENE_CACHE_ADAPTER_CONTRACT_SHA256) ||
      ltd_native_material_provider_abi_version() != LTD_NATIVE_MATERIAL_PROVIDER_ABI_VERSION ||
      !same_text(ltd_native_material_provider_contract_sha256(),
                 LTD_NATIVE_MATERIAL_PROVIDER_CONTRACT_SHA256) ||
      ltd_native_material_field_packer_abi_version() !=
          LTD_NATIVE_MATERIAL_FIELD_PACKER_ABI_VERSION ||
      !same_text(ltd_native_material_field_packer_contract_sha256(),
                 LTD_NATIVE_MATERIAL_FIELD_PACKER_CONTRACT_SHA256) ||
      ltd_native_material_schedule_abi_version() != LTD_NATIVE_MATERIAL_SCHEDULE_ABI_VERSION ||
      !same_text(ltd_native_material_schedule_contract_sha256(),
                 LTD_NATIVE_MATERIAL_SCHEDULE_CONTRACT_SHA256) ||
      ltd_native_draw_descriptor_builder_require(
          LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_ABI_VERSION,
          LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CONTRACT_SHA256) !=
          LTD_NATIVE_DRAW_DESCRIPTOR_OK ||
      ltd_native_noseline_pipeline_bridge_abi_version() !=
          LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_ABI_VERSION ||
      !same_text(ltd_native_noseline_pipeline_bridge_contract_sha256(),
                 LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_CONTRACT_SHA256) ||
      ltd_native_render_pipeline_abi_version() != LTD_NATIVE_RENDER_PIPELINE_ABI_VERSION ||
      !same_text(ltd_native_render_pipeline_contract_sha256(),
                 LTD_NATIVE_RENDER_PIPELINE_CONTRACT_SHA256) ||
      ltd_draw_runtime_v2_require(LTD_DRAW_RUNTIME_V2_ABI_VERSION,
                                  LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256) !=
          LTD_DRAW_RUNTIME_OK) {
    return mismatch();
  }
  return Status::kOk;
}

bool valid_request(const Request& request) {
  const bool trusted_inputs_valid = request.trusted_material_bundle == nullptr
      ? text(request.generated_mask_source_key) &&
            text(request.generated_head_source_key)
      : request.materials.empty() && request.generated_mask_source_key.empty() &&
            request.generated_head_source_key.empty() && empty_trusted_ugc(request.ugc) &&
            empty_trusted_noseline(request.noseline);
  return request.decoded_assets != nullptr && request.scene_assets != nullptr &&
         request.parts_catalog != nullptr && !request.parts_catalog_bytes.empty() &&
         !all_zero(request.parts_catalog_sha256) &&
         lower_sha(request.parts_catalog_sha256_hex) &&
         request.raw_char_info.size() == native_parts::kCharInfoSize &&
         request.png_encoder != nullptr && valid_seals(request.frame_seals) &&
         trusted_inputs_valid &&
         (request.view_kind == LTD_NATIVE_SCENE_VIEW_PORTRAIT ||
          request.view_kind == LTD_NATIVE_SCENE_VIEW_FULL_BODY) &&
         (request.raster_size == 128 || request.raster_size == 512) &&
         request.maximum_draws > 0 &&
         request.maximum_draws <= LTD_NATIVE_SCENE_ASSEMBLER_MAX_DRAWS;
}

void copy_face_report(const native_face_plan::Report& source, FaceReport& target) {
  target.fixture_name = source.fixture_name;
  target.share_mii_sha256 = source.share_mii_sha256;
  target.effective_char_info_sha256 = source.effective_char_info_sha256;
  target.mask_final_rgba8_sha256 = source.mask_final_rgba8_sha256;
  target.mask_mesh_rgba8_sha256 = source.mask_mesh_rgba8_sha256;
  target.mask_rgba64_sha256 = source.mask_rgba64_sha256;
  target.head_rgba8_sha256 = source.head_rgba8_sha256;
  target.head_rgba64_sha256 = source.head_rgba64_sha256;
  target.ordinary_layer_count = source.ordinary_layer_count;
  target.faceline_kind = source.faceline_kind;
}

}  // namespace

struct PreparedRender::Storage final {
  Request request{};
  std::array<std::string, 5> frame_seal_strings;
  std::string generated_mask_source_key;
  std::string generated_head_source_key;
  std::string ugc_source_key;
  std::vector<MaterialPublication> material_publications;
  native_parts::Selection selection{};
  Handle<ltd_native_scene_assembly, ltd_native_scene_assembly_destroy> scene{
      nullptr, ltd_native_scene_assembly_destroy};
  Handle<ltd_native_material_provider, ltd_native_material_provider_destroy> provider{
      nullptr, ltd_native_material_provider_destroy};
  std::vector<Handle<ltd_native_material_field_pack,
                     ltd_native_material_field_pack_destroy>> packs;
  std::vector<Handle<ltd_native_draw_descriptor,
                     ltd_native_draw_descriptor_destroy>> descriptors;
  native_face_plan::FacePlan face;
  ltd_native_material_texture_provider texture_provider{};
  ltd_native_material_face_views face_views{};
  std::vector<double> ugc_rgba64;

  std::vector<ltd_native_scene_draw_view> scene_draws;
  std::vector<ltd_native_scene_model_view> models;
  std::vector<ltd_native_source_draw> source_draws;
  std::vector<ltd_native_compiled_draw> compiled_draws;
  std::vector<ltd_native_draw_command_view> command_views;
  std::vector<ltd_native_render_draw_command> commands;
  std::vector<DrawReport> draw_reports;
  std::vector<std::size_t> scene_to_general;
  std::optional<std::size_t> noseline_scene_index;
  ltd_native_render_noseline_input noseline_input{};
  ltd_native_noseline_pipeline_texture noseline_texture{};
  std::vector<double> noseline_rgba;
  std::string noseline_manifest;
  std::string noseline_decoded;
  ltd_native_scene_assembly_summary scene_summary{};
  FaceReport face_report{};
  bool executed = false;
  bool request_context_detached = false;
};

PreparedRender::PreparedRender() = default;
PreparedRender::~PreparedRender() = default;
PreparedRender::PreparedRender(PreparedRender&&) noexcept = default;
PreparedRender& PreparedRender::operator=(PreparedRender&&) noexcept = default;

std::string_view StatusName(Status status) {
  switch (status) {
    case Status::kOk: return "ok";
    case Status::kInvalidArgument: return "invalid_argument";
    case Status::kModuleMismatch: return "module_mismatch";
    case Status::kPartsFailed: return "parts_failed";
    case Status::kSceneFailed: return "scene_failed";
    case Status::kFaceFailed: return "face_failed";
    case Status::kMaterialProviderFailed: return "material_provider_failed";
    case Status::kMaterialInventoryIncomplete: return "material_inventory_incomplete";
    case Status::kMaterialPackFailed: return "material_pack_failed";
    case Status::kScheduleFailed: return "schedule_failed";
    case Status::kDescriptorFailed: return "descriptor_failed";
    case Status::kNoseLineFailed: return "noseline_failed";
    case Status::kPipelineFailed: return "pipeline_failed";
    case Status::kOutputFailed: return "output_failed";
    case Status::kCancelled: return "cancelled";
    case Status::kNotAdmitted: return "not_admitted";
    case Status::kAllocationFailed: return "allocation_failed";
  }
  return "unknown";
}

bool ActivationReady() { return true; }

Status Prepare(const Request& request, PreparedRender* prepared,
               PrepareReport* report, std::string* error) {
  if (prepared == nullptr || report == nullptr || !valid_request(request)) {
    return fail(Status::kInvalidArgument, "native orchestrator request is invalid", error);
  }
  if (error != nullptr) error->clear();
  if (cancelled(request)) return fail(Status::kCancelled, "render cancelled", error);
  if (const auto status = authenticate_modules(error); status != Status::kOk) return status;
  if (std::fegetround() != FE_TONEAREST) {
    return fail(Status::kInvalidArgument, "native render requires FE_TONEAREST", error);
  }

  try {
    auto storage = std::make_unique<PreparedRender::Storage>();
    storage->request = request;
    const std::array<const char*, 5> frame_seals{
        request.frame_seals.ltd_source_sha256,
        request.frame_seals.active_parts_sha256,
        request.frame_seals.asset_index_sha256,
        request.frame_seals.scene_plan_sha256,
        request.frame_seals.material_plan_sha256};
    for (std::size_t index = 0; index < frame_seals.size(); ++index) {
      storage->frame_seal_strings[index] = frame_seals[index];
    }
    storage->request.frame_seals = {
        storage->frame_seal_strings[0].c_str(), storage->frame_seal_strings[1].c_str(),
        storage->frame_seal_strings[2].c_str(), storage->frame_seal_strings[3].c_str(),
        storage->frame_seal_strings[4].c_str()};
    const bool trusted = request.trusted_material_bundle != nullptr;
    ltd_native_material_face_views trusted_face_views{};
    native_runtime_material_adapter::UgcPublicationView trusted_ugc{};
    native_runtime_material_adapter::NoseLinePublicationView trusted_noseline{};
    if (trusted) {
      const auto& trusted_report = request.trusted_material_bundle->report();
      if (trusted_report.share_mii_sha256 != request.frame_seals.ltd_source_sha256 ||
          trusted_report.publication_sha256 !=
              request.frame_seals.material_plan_sha256 ||
          trusted_report.view_kind != request.view_kind ||
          trusted_report.raster_size != request.raster_size) {
        return fail(Status::kMaterialInventoryIncomplete,
                    "trusted material bundle identity differs from the render request",
                    error);
      }
      trusted_face_views = request.trusted_material_bundle->face_views();
      trusted_ugc = request.trusted_material_bundle->ugc();
      trusted_noseline = request.trusted_material_bundle->noseline();
      if (!text(trusted_face_views.generated_mask_source_key) ||
          !text(trusted_face_views.generated_head_albedo_source_key) ||
          (trusted_report.has_user_facepaint &&
           (!text(trusted_face_views.user_facepaint_source_key) ||
            trusted_face_views.user_facepaint_source_key != trusted_ugc.source_key)) ||
          trusted_report.has_user_facepaint != !trusted_ugc.rgba8.empty() ||
          trusted_report.has_noseline != !trusted_noseline.mip_rgba.empty()) {
        return fail(Status::kMaterialInventoryIncomplete,
                    "trusted material bundle dynamic inventory is invalid", error);
      }
      storage->generated_mask_source_key =
          trusted_face_views.generated_mask_source_key;
      storage->generated_head_source_key =
          trusted_face_views.generated_head_albedo_source_key;
      storage->ugc_source_key = trusted_ugc.source_key;
      const auto trusted_publications =
          request.trusted_material_bundle->publications();
      storage->material_publications.reserve(trusted_publications.size());
      for (const auto& publication : trusted_publications) {
        storage->material_publications.push_back(
            {publication.scene_draw_index, publication.material,
             publication.mip_chains});
      }
    } else {
      storage->generated_mask_source_key = request.generated_mask_source_key;
      storage->generated_head_source_key = request.generated_head_source_key;
      storage->ugc_source_key = request.ugc.source_key;
      storage->material_publications.assign(
          request.materials.begin(), request.materials.end());
    }
    storage->request.materials = storage->material_publications;
    /* The trusted provider retains its own opaque adapter lease during
     * Prepare; never retain the caller's bundle pointer in a prepared plan. */
    storage->request.trusted_material_bundle = nullptr;
    /* These caller spans are consumed and copied during Prepare; never leave
     * dangling views in the retained execution request. */
    storage->request.parts_catalog_bytes = {};
    storage->request.raw_char_info = {};
    storage->request.ugc.rgba8 = {};
    storage->request.noseline.mip_rgba = {};
    std::string detail;
    if (!native_parts::Select(*request.parts_catalog, request.raw_char_info,
                              &storage->selection, &detail)) {
      return fail(Status::kPartsFailed, "native Parts selection failed: " + detail, error);
    }
    if (cancelled(request)) return fail(Status::kCancelled, "render cancelled", error);

    ltd_native_scene_assembly* raw_scene = nullptr;
    ltd_native_scene_assembler_status assembler_status = LTD_NATIVE_SCENE_ASSEMBLER_INVALID_ARGUMENT;
    std::array<char, 512> native_error{};
    const auto adapter_status = ltd_native_scene_cache_adapter_assemble(
        request.scene_assets, request.parts_catalog_bytes.data(),
        request.parts_catalog_bytes.size(), request.parts_catalog_sha256.data(),
        request.raw_char_info.data(), request.raw_char_info.size(), request.view_kind,
        request.raster_size, &raw_scene, &assembler_status,
        native_error.data(), native_error.size());
    if (adapter_status != LTD_NATIVE_SCENE_CACHE_ADAPTER_OK ||
        assembler_status != LTD_NATIVE_SCENE_ASSEMBLER_OK || raw_scene == nullptr) {
      return fail(Status::kSceneFailed,
          native_error[0] == '\0' ? "native scene assembly failed" : native_error.data(), error);
    }
    storage->scene.reset(raw_scene);
    if (ltd_native_scene_assembly_get_summary(storage->scene.get(),
                                               &storage->scene_summary) !=
            LTD_NATIVE_SCENE_ASSEMBLER_OK ||
        storage->scene_summary.draw_count == 0 ||
        storage->scene_summary.draw_count > request.maximum_draws) {
      return fail(Status::kSceneFailed, "native scene summary is invalid", error);
    }

    const auto face_status = native_face_plan::Build(
        {request.parts_catalog, request.parts_catalog_sha256_hex,
         request.raw_char_info, request.decoded_assets}, &storage->face, &detail);
    if (face_status != native_face_plan::Status::kOk) {
      return fail(Status::kFaceFailed,
          "native face plan failed: " + std::string(native_face_plan::StatusName(face_status)) +
              (detail.empty() ? "" : ": " + detail), error);
    }
    copy_face_report(storage->face.report(), storage->face_report);
    if (trusted) {
      const auto& trusted_report = request.trusted_material_bundle->report();
      const auto mask = storage->face.generated_mask_rgba64();
      const auto head = storage->face.generated_head_albedo_rgba64();
      if (trusted_report.effective_char_info_sha256 !=
              storage->face.report().effective_char_info_sha256 ||
          trusted_report.share_mii_sha256 != storage->face.report().share_mii_sha256 ||
          !same_rgba64(trusted_face_views.generated_mask, mask) ||
          trusted_report.has_generated_mask != (mask.pixels != nullptr && mask.element_count != 0) ||
          !same_rgba64(trusted_face_views.generated_head_albedo, head) ||
          trusted_report.has_generated_head_albedo !=
              (head.pixels != nullptr && head.element_count != 0) ||
          (trusted_face_views.has_generated_mask != 0) !=
              trusted_report.has_generated_mask ||
          (trusted_face_views.has_generated_head_albedo != 0) !=
              trusted_report.has_generated_head_albedo ||
          (trusted_face_views.has_user_facepaint != 0) !=
              trusted_report.has_user_facepaint) {
        return fail(Status::kMaterialInventoryIncomplete,
                    "trusted material bundle face identity differs from the rebuilt face plan",
                    error);
      }
    }

    const auto materials = std::span<const MaterialPublication>(
        storage->material_publications);
    const auto material_count = materials.size();
    const auto scene_count = static_cast<std::size_t>(storage->scene_summary.draw_count);
    if (material_count > scene_count || scene_count - material_count > 1) {
      return fail(Status::kMaterialInventoryIncomplete,
                  "material publications do not cover the scene", error);
    }
    storage->scene_draws.resize(scene_count);
    storage->models.resize(scene_count);
    storage->scene_to_general.assign(scene_count, std::numeric_limits<std::size_t>::max());
    std::vector<const MaterialPublication*> by_scene(scene_count, nullptr);
    for (const auto& publication : materials) {
      if (publication.scene_draw_index >= scene_count || publication.material == nullptr ||
          by_scene[publication.scene_draw_index] != nullptr) {
        return fail(Status::kMaterialInventoryIncomplete,
                    "material scene indices are incomplete or duplicated", error);
      }
      by_scene[publication.scene_draw_index] = &publication;
    }
    for (std::size_t index = 0; index < scene_count; ++index) {
      auto& draw = storage->scene_draws[index];
      if (ltd_native_scene_assembly_get_draw(storage->scene.get(), index, &draw) !=
              LTD_NATIVE_SCENE_ASSEMBLER_OK ||
          ltd_native_scene_cache_adapter_get_model(
              request.scene_assets, draw.resource_name, draw.model_name,
              &storage->models[index], native_error.data(), native_error.size()) !=
              LTD_NATIVE_SCENE_CACHE_ADAPTER_OK) {
        return fail(Status::kSceneFailed,
            native_error[0] == '\0' ? "native model view lookup failed" : native_error.data(),
            error);
      }
      if (draw.profile == LTD_NATIVE_SCENE_PROFILE_NOSE_LINE12) {
        if (storage->noseline_scene_index.has_value() || by_scene[index] != nullptr) {
          return fail(Status::kNoseLineFailed, "NoseLine scene publication is ambiguous", error);
        }
        storage->noseline_scene_index = index;
      } else if (by_scene[index] == nullptr) {
        return fail(Status::kMaterialInventoryIncomplete,
                    "a non-NoseLine scene draw has no material publication", error);
      }
    }
    const bool noseline_published = trusted
        ? !trusted_noseline.mip_rgba.empty()
        : !request.noseline.mip_rgba.empty();
    if (storage->noseline_scene_index.has_value() != noseline_published) {
      return fail(Status::kNoseLineFailed, "NoseLine scene and texture presence differ", error);
    }
    if (trusted && storage->noseline_scene_index.has_value() &&
        trusted_noseline.scene_draw_index != *storage->noseline_scene_index) {
      return fail(Status::kNoseLineFailed,
                  "trusted NoseLine publication scene index differs", error);
    }

    ltd_native_material_provider* raw_provider = nullptr;
    const auto provider_create_status = request.trusted_material_bundle == nullptr
        ? ltd_native_material_provider_create(
              &raw_provider, native_error.data(), native_error.size())
        : ltd_native_material_provider_create_with_borrowed_cache(
              request.decoded_assets, &raw_provider,
              native_error.data(), native_error.size());
    if (provider_create_status !=
            LTD_NATIVE_MATERIAL_PROVIDER_OK || raw_provider == nullptr) {
      return fail(Status::kMaterialProviderFailed,
                  native_error[0] == '\0' ? "material provider create failed" : native_error.data(),
                  error);
    }
    storage->provider.reset(raw_provider);
    if (request.trusted_material_bundle != nullptr) {
      const auto status = request.trusted_material_bundle->PublishTrusted(
          storage->provider.get(), &detail);
      if (status != native_runtime_material_adapter::Status::kOk) {
        return fail(Status::kMaterialProviderFailed,
                    "trusted material publication failed: " +
                        std::string(native_runtime_material_adapter::StatusName(status)) +
                        (detail.empty() ? "" : ": " + detail),
                    error);
      }
    } else {
      for (const auto& publication : materials) {
        for (const auto& chain : publication.mip_chains) {
          const auto status = ltd_native_material_provider_publish_mip_chain(
              storage->provider.get(), &chain, native_error.data(), native_error.size());
          if (status != LTD_NATIVE_MATERIAL_PROVIDER_OK &&
              status != LTD_NATIVE_MATERIAL_PROVIDER_DUPLICATE) {
            return fail(Status::kMaterialProviderFailed,
                        native_error[0] == '\0' ? "material mip publication failed"
                                                : native_error.data(),
                        error);
          }
        }
        if (ltd_native_material_provider_publish_material(
                storage->provider.get(), publication.material,
                native_error.data(), native_error.size()) !=
            LTD_NATIVE_MATERIAL_PROVIDER_OK) {
          return fail(Status::kMaterialProviderFailed,
                      native_error[0] == '\0' ? "material publication failed"
                                              : native_error.data(),
                      error);
        }
      }
    }
    if (ltd_native_material_provider_texture_callback(
            storage->provider.get(), &storage->texture_provider) !=
        LTD_NATIVE_MATERIAL_PROVIDER_OK) {
      return fail(Status::kMaterialProviderFailed, "material texture callback failed", error);
    }

    storage->face_views.generated_mask_source_key = storage->generated_mask_source_key.c_str();
    storage->face_views.generated_head_albedo_source_key =
        storage->generated_head_source_key.c_str();
    const auto mask = storage->face.generated_mask_rgba64();
    storage->face_views.generated_mask = {
        mask.pixels, mask.element_count * sizeof(double), mask.row_stride_bytes,
        mask.width, mask.height};
    storage->face_views.has_generated_mask = 1;
    const auto head = storage->face.generated_head_albedo_rgba64();
    if (head.pixels != nullptr && head.element_count != 0) {
      storage->face_views.generated_head_albedo = {
          head.pixels, head.element_count * sizeof(double), head.row_stride_bytes,
          head.width, head.height};
      storage->face_views.has_generated_head_albedo = 1;
    }
    const auto ugc_source_key = trusted ? trusted_ugc.source_key : request.ugc.source_key;
    const auto ugc_rgba8 = trusted ? trusted_ugc.rgba8 : request.ugc.rgba8;
    const auto ugc_width = trusted ? trusted_ugc.width : request.ugc.width;
    const auto ugc_height = trusted ? trusted_ugc.height : request.ugc.height;
    const auto& ugc_srt = trusted ? trusted_ugc.tex_srt : request.ugc.tex_srt;
    if (!ugc_rgba8.empty()) {
      if (!text(ugc_source_key) || ugc_width != 512 || ugc_height != 512 ||
          ugc_rgba8.size() != static_cast<std::size_t>(512 * 512 * 4) ||
          (trusted && (!same_tex_srt(ugc_srt, trusted_face_views.user_facepaint_srt) ||
                       trusted_face_views.user_facepaint.width != 512 ||
                       trusted_face_views.user_facepaint.height != 512 ||
                       trusted_face_views.user_facepaint.pixels == nullptr ||
                       trusted_face_views.user_facepaint.buffer_size_bytes !=
                           static_cast<std::size_t>(512 * 512 * 4 * sizeof(double))))) {
        return fail(Status::kFaceFailed, "UGC facepaint publication is invalid", error);
      }
      storage->ugc_rgba64.reserve(ugc_rgba8.size());
      for (const std::uint8_t value : ugc_rgba8) {
        storage->ugc_rgba64.push_back(static_cast<double>(value) / 255.0);
      }
      if (trusted &&
          std::memcmp(storage->ugc_rgba64.data(), trusted_face_views.user_facepaint.pixels,
                      storage->ugc_rgba64.size() * sizeof(double)) != 0) {
        return fail(Status::kFaceFailed,
                    "trusted UGC pixels differ from the bundle face publication", error);
      }
      storage->face_views.user_facepaint_source_key = storage->ugc_source_key.c_str();
      storage->face_views.user_facepaint = {
          storage->ugc_rgba64.data(), storage->ugc_rgba64.size() * sizeof(double),
          static_cast<std::size_t>(512 * 4 * sizeof(double)), 512, 512};
      storage->face_views.user_facepaint_srt = ugc_srt;
      storage->face_views.has_user_facepaint = 1;
    }

    storage->packs.reserve(material_count);
    storage->source_draws.resize(material_count);
    storage->scene_to_general.assign(scene_count, std::numeric_limits<std::size_t>::max());
    std::size_t general_index = 0;
    for (std::size_t scene_index = 0; scene_index < scene_count; ++scene_index) {
      if (scene_index == storage->noseline_scene_index) continue;
      const auto& publication = *by_scene[scene_index];
      ltd_native_material_normalized_view resident{};
      if (ltd_native_material_provider_get_material(
              storage->provider.get(), publication.material->source_key,
              &resident, native_error.data(), native_error.size()) !=
              LTD_NATIVE_MATERIAL_PROVIDER_OK || resident.material == nullptr) {
        return fail(Status::kMaterialProviderFailed, "resident material lookup failed", error);
      }
      ltd_native_material_field_pack* raw_pack = nullptr;
      const ltd_native_material_field_pack_request pack_request{
          &request.field_seals, storage->selection.effective_char_info.data(),
          storage->selection.effective_char_info.size(), &storage->scene_draws[scene_index],
          &storage->models[scene_index], resident.material, &storage->texture_provider,
          &storage->face_views, static_cast<std::uint32_t>(scene_index)};
      const auto pack_status = ltd_native_material_field_pack_build(
          &pack_request, &raw_pack, native_error.data(), native_error.size());
      if (pack_status != LTD_NATIVE_MATERIAL_FIELD_OK || raw_pack == nullptr) {
        return fail(Status::kMaterialPackFailed,
                    native_error[0] == '\0' ? "native material field packing failed" : native_error.data(),
                    error);
      }
      storage->packs.emplace_back(raw_pack, ltd_native_material_field_pack_destroy);
      if (ltd_native_material_field_pack_get_source_draw(
              storage->packs.back().get(), &storage->source_draws[general_index]) !=
              LTD_NATIVE_MATERIAL_FIELD_OK) {
        return fail(Status::kMaterialPackFailed, "field pack source getter failed", error);
      }
      /* Schedule ABI requires a dense authored inventory. Preserve the full
       * scene slot separately in reports and descriptors. */
      storage->source_draws[general_index].authored_index =
          static_cast<std::uint32_t>(general_index);
      storage->scene_to_general[scene_index] = general_index++;
    }

    /* Every field pack owns its material, texture, and face inputs. The
     * provider is not used during scheduling or execution, so release its
     * opaque adapter lease and borrowed cache pointer before Prepare returns. */
    storage->texture_provider = {};
    storage->provider.reset();
    storage->request.materials = {};
    storage->material_publications.clear();

    storage->compiled_draws.resize(material_count);
    std::size_t compiled_count = 0;
    ltd_native_material_source_seals schedule_seals{};
    auto decode = [](const char* source, std::uint8_t* output) {
      auto nibble = [](char value) -> std::uint8_t {
        if (value >= '0' && value <= '9') return static_cast<std::uint8_t>(value - '0');
        return static_cast<std::uint8_t>(value - 'a' + 10);
      };
      for (std::size_t index = 0; index < 32; ++index) {
        output[index] = static_cast<std::uint8_t>(
            (nibble(source[index * 2]) << 4) | nibble(source[index * 2 + 1]));
      }
    };
    decode(LTD_NATIVE_MATERIAL_SCHEDULE_COMPOSE_SHA256, schedule_seals.compose_sha256);
    decode(LTD_NATIVE_MATERIAL_SCHEDULE_WRAPPER_SHA256, schedule_seals.wrapper_sha256);
    decode(LTD_NATIVE_MATERIAL_SCHEDULE_CURRENT_KERNEL_SHA256,
           schedule_seals.current_kernel_sha256);
    decode(LTD_NATIVE_MATERIAL_SCHEDULE_OPAQUE_KERNEL_SHA256,
           schedule_seals.opaque_kernel_sha256);
    const auto schedule_status = ltd_native_compile_material_schedule(
        &schedule_seals, storage->source_draws.data(), storage->source_draws.size(),
        storage->compiled_draws.data(), storage->compiled_draws.size(), &compiled_count);
    if (schedule_status != LTD_NATIVE_MATERIAL_OK || compiled_count != material_count) {
      return fail(Status::kScheduleFailed,
                  "native material schedule failed: " +
                      std::string(ltd_native_material_status_name(schedule_status)), error);
    }
    storage->compiled_draws.resize(compiled_count);
    storage->descriptors.reserve(compiled_count);
    storage->command_views.resize(compiled_count);
    storage->commands.resize(scene_count);
    storage->draw_reports.resize(scene_count);

    for (std::size_t index = 0; index < compiled_count; ++index) {
      const auto& compiled = storage->compiled_draws[index];
      if (compiled.authored_index >= storage->source_draws.size()) {
        return fail(Status::kScheduleFailed, "scheduled authored index is invalid", error);
      }
      std::size_t scene_index = scene_count;
      for (std::size_t candidate = 0; candidate < scene_count; ++candidate) {
        if (storage->scene_to_general[candidate] == compiled.authored_index) {
          scene_index = candidate;
          break;
        }
      }
      if (scene_index == scene_count) {
        return fail(Status::kScheduleFailed, "scheduled draw lost its scene identity", error);
      }
      ltd_native_draw_descriptor* raw_descriptor = nullptr;
      const ltd_native_draw_descriptor_request descriptor_request{
          &request.descriptor_seals, &storage->source_draws[compiled.authored_index],
          &compiled, &storage->scene_draws[scene_index], &storage->models[scene_index]};
      const auto descriptor_status = ltd_native_draw_descriptor_build(
          &descriptor_request, &raw_descriptor, native_error.data(), native_error.size());
      if (descriptor_status != LTD_NATIVE_DRAW_DESCRIPTOR_OK || raw_descriptor == nullptr) {
        return fail(Status::kDescriptorFailed,
                    native_error[0] == '\0' ? "native descriptor build failed" : native_error.data(),
                    error);
      }
      storage->descriptors.emplace_back(raw_descriptor, ltd_native_draw_descriptor_destroy);
      auto& command_view = storage->command_views[index];
      if (ltd_native_draw_descriptor_get_command(storage->descriptors.back().get(),
                                                  &command_view) !=
          LTD_NATIVE_DRAW_DESCRIPTOR_OK) {
        return fail(Status::kDescriptorFailed, "native descriptor getter failed", error);
      }
      ltd_native_render_draw_command command{};
      command.profile = pipeline_profile(command_view.profile);
      command.group = storage->scene_draws[scene_index].group;
      command.blend = storage->scene_draws[scene_index].blend;
      command.depth_write = storage->scene_draws[scene_index].depth_write;
      switch (command_view.kernel) {
        case LTD_NATIVE_DRAW_BODY_ABI1: command.input.body = command_view.body; break;
        case LTD_NATIVE_DRAW_PLAIN_SKIN_ABI1:
          command.input.plain_skin = command_view.plain_skin; break;
        case LTD_NATIVE_DRAW_MASK0_ABI1: command.input.mask0 = command_view.mask0; break;
        case LTD_NATIVE_DRAW_HEAD816_ABI2: command.input.head816 = command_view.head816; break;
        case LTD_NATIVE_DRAW_HAIR_ABI2: command.input.hair = command_view.hair; break;
        case LTD_NATIVE_DRAW_OUTFIT_ABI2: command.input.outfit = command_view.outfit; break;
        default: return fail(Status::kDescriptorFailed, "descriptor kernel is unsupported", error);
      }
      if (command.profile == 0 || command.input.opaque == nullptr) {
        return fail(Status::kDescriptorFailed, "descriptor command profile is invalid", error);
      }
      storage->commands[scene_index] = command;
      storage->draw_reports[scene_index] = {
          storage->scene_draws[scene_index].resource_name,
          storage->scene_draws[scene_index].model_name,
          storage->scene_draws[scene_index].group,
          command.profile, static_cast<std::uint32_t>(scene_index),
          compiled.scheduled_index,
          storage->scene_draws[scene_index].submitted_triangle_count, false, false};
    }

    if (storage->noseline_scene_index.has_value()) {
      const auto scene_index = *storage->noseline_scene_index;
      const auto noseline_source_key =
          trusted ? trusted_noseline.source_key : request.noseline.source_key;
      const auto noseline_rgba =
          trusted ? trusted_noseline.mip_rgba : request.noseline.mip_rgba;
      const auto noseline_manifest = trusted
          ? trusted_noseline.texture_manifest_sha256
          : request.noseline.texture_manifest_sha256;
      const auto noseline_decoded = trusted
          ? trusted_noseline.decoded_mips_sha256
          : request.noseline.decoded_mips_sha256;
      const auto& noseline_levels =
          trusted ? trusted_noseline.levels : request.noseline.levels;
      if (!text(noseline_source_key) || noseline_rgba.empty() ||
          !lower_sha(noseline_manifest) || !lower_sha(noseline_decoded)) {
        return fail(Status::kNoseLineFailed, "NoseLine publication is invalid", error);
      }
      storage->noseline_rgba.assign(noseline_rgba.begin(), noseline_rgba.end());
      storage->noseline_manifest = noseline_manifest;
      storage->noseline_decoded = noseline_decoded;
      storage->noseline_texture.mip_rgba = storage->noseline_rgba.data();
      storage->noseline_texture.mip_rgba_element_count = storage->noseline_rgba.size();
      std::copy(noseline_levels.begin(), noseline_levels.end(),
                std::begin(storage->noseline_texture.levels));
      storage->noseline_texture.texture_manifest_sha256 = storage->noseline_manifest.c_str();
      storage->noseline_texture.decoded_mips_sha256 = storage->noseline_decoded.c_str();
      storage->noseline_input = {&storage->scene_draws[scene_index],
                                 &storage->noseline_texture};
      auto& command = storage->commands[scene_index];
      command.profile = LTD_NATIVE_RENDER_PROFILE_NOSE_LINE12;
      command.group = storage->scene_draws[scene_index].group;
      command.blend = storage->scene_draws[scene_index].blend;
      command.depth_write = storage->scene_draws[scene_index].depth_write;
      command.input.noseline = &storage->noseline_input;
      storage->draw_reports[scene_index] = {
          storage->scene_draws[scene_index].resource_name,
          storage->scene_draws[scene_index].model_name,
          storage->scene_draws[scene_index].group,
          LTD_NATIVE_RENDER_PROFILE_NOSE_LINE12,
          static_cast<std::uint32_t>(scene_index), 0,
          storage->scene_draws[scene_index].submitted_triangle_count, true, false};
    }
    for (const auto& command : storage->commands) {
      if (command.profile == 0 || command.input.opaque == nullptr) {
        return fail(Status::kMaterialInventoryIncomplete,
                    "one scene command was not prepared", error);
      }
    }

    PrepareReport completed{};
    completed.scene_draw_count = static_cast<std::uint32_t>(scene_count);
    completed.general_draw_count = static_cast<std::uint32_t>(material_count);
    completed.material_count = static_cast<std::uint32_t>(material_count);
    completed.descriptor_count = static_cast<std::uint32_t>(compiled_count);
    completed.parts_selected = true;
    completed.face_plan_built = true;
    completed.nose_line_present = storage->noseline_scene_index.has_value();
    completed.field_packer_admitted = true;
    prepared->storage_ = std::move(storage);
    *report = completed;
    return Status::kOk;
  } catch (const std::bad_alloc&) {
    return fail(Status::kAllocationFailed, "native orchestration allocation failed", error);
  } catch (const std::exception& exception) {
    return fail(Status::kInvalidArgument, exception.what(), error);
  }
}

Status Execute(PreparedRender* prepared, Output* output, std::string* error) {
  if (prepared == nullptr || prepared->storage_ == nullptr || output == nullptr) {
    return fail(Status::kInvalidArgument, "prepared render or output is invalid", error);
  }
  auto& storage = *prepared->storage_;
  if (storage.request_context_detached) {
    return fail(Status::kInvalidArgument,
                "prepared render request context was detached", error);
  }
  if (storage.executed) {
    return fail(Status::kInvalidArgument, "prepared render was already executed", error);
  }
  if (cancelled(storage.request)) return fail(Status::kCancelled, "render cancelled", error);
  ltd_native_render_pipeline* raw_pipeline = nullptr;
  const ltd_native_render_config config{
      storage.request.raster_size, storage.request.raster_size,
      static_cast<std::uint64_t>(storage.request.raster_size) * storage.request.raster_size,
      storage.request.maximum_draws, LTD_FACE_RUNTIME_MAX_MASK_LAYERS,
      storage.request.png_encoder,
      storage.request.is_cancelled, storage.request.cancel_context};
  const auto create_status = ltd_native_render_pipeline_create(&config, &raw_pipeline);
  if (create_status != LTD_NATIVE_RENDER_OK || raw_pipeline == nullptr) {
    return fail(Status::kPipelineFailed,
                "native render pipeline create failed: " +
                    std::string(ltd_native_render_status_name(create_status)), error);
  }
  Handle<ltd_native_render_pipeline, ltd_native_render_pipeline_destroy> pipeline{
      raw_pipeline, ltd_native_render_pipeline_destroy};
  ltd_native_render_frame_desc frame{};
  frame.width = storage.request.raster_size;
  frame.height = storage.request.raster_size;
  frame.output_mode = LTD_NATIVE_RENDER_OUTPUT_PREMULTIPLIED_RGBA;
  frame.seals = storage.request.frame_seals;
  auto status = ltd_native_render_begin_frame(pipeline.get(), &frame);
  if (status != LTD_NATIVE_RENDER_OK) {
    return fail(Status::kPipelineFailed,
                "native render begin failed: " + std::string(ltd_native_render_status_name(status)),
                error);
  }
  status = ltd_native_render_execute_precompiled_draws(
      pipeline.get(), storage.commands.data(), storage.commands.size());
  if (status == LTD_NATIVE_RENDER_CANCELLED) {
    return fail(Status::kCancelled, "render cancelled", error);
  }
  if (status != LTD_NATIVE_RENDER_OK) {
    return fail(Status::kPipelineFailed,
                "native draw execution failed: " +
                    std::string(ltd_native_render_status_name(status)), error);
  }
  ltd_native_render_finish_desc finish{};
  // InfiniMii's accepted portrait is the classic-bridge bust route.  Like the
  // full-body route it includes the body scene and therefore bypasses the
  // detached-head MiiIcon SnapshotPfx gamma0 specialization.
  finish.apply_snapshot_pfx_gamma0 = 0;
  ltd_native_render_output_view view{};
  ltd_native_render_report pipeline_report{};
  status = ltd_native_render_finish_precompiled_frame(
      pipeline.get(), &finish, &view, &pipeline_report);
  if (status != LTD_NATIVE_RENDER_OK || view.png_bytes == nullptr || view.png_size == 0 ||
      view.transferred_pixels == nullptr || view.channels != 4) {
    return fail(Status::kOutputFailed,
                "native render finish failed: " + std::string(ltd_native_render_status_name(status)),
                error);
  }
  try {
    Output completed;
    completed.png.assign(view.png_bytes, view.png_bytes + view.png_size);
    completed.transferred_pixels.assign(
        view.transferred_pixels, view.transferred_pixels + view.transferred_size);
    completed.draws = storage.draw_reports;
    completed.pipeline_report = pipeline_report;
    completed.scene_summary = storage.scene_summary;
    completed.face_report = storage.face_report;
    completed.prepared = true;
    completed.executed = true;
    completed.production_activation_ready = true;
    *output = std::move(completed);
    storage.executed = true;
    return Status::kOk;
  } catch (const std::bad_alloc&) {
    return fail(Status::kAllocationFailed, "native output copy allocation failed", error);
  }
}

Status DetachRequestContext(PreparedRender* prepared, std::string* error) {
  if (prepared == nullptr || prepared->storage_ == nullptr) {
    return fail(Status::kInvalidArgument, "prepared render is invalid", error);
  }
  if (error != nullptr) error->clear();
  auto& storage = *prepared->storage_;
  storage.request.decoded_assets = nullptr;
  storage.request.scene_assets = nullptr;
  storage.request.parts_catalog = nullptr;
  storage.request.parts_catalog_bytes = {};
  storage.request.raw_char_info = {};
  storage.request.materials = {};
  storage.request.generated_mask_source_key = {};
  storage.request.generated_head_source_key = {};
  storage.request.ugc = {};
  storage.request.noseline = {};
  storage.request.png_encoder = nullptr;
  storage.request.is_cancelled = nullptr;
  storage.request.cancel_context = nullptr;
  storage.request_context_detached = true;
  return Status::kOk;
}

Status ExecuteReusable(PreparedRender* prepared, const ExecutionContext& context,
                       Output* output, std::string* error) {
  if (prepared == nullptr || prepared->storage_ == nullptr || output == nullptr ||
      context.png_encoder == nullptr || !prepared->storage_->request_context_detached) {
    return fail(Status::kInvalidArgument, "prepared render or output is invalid", error);
  }
  if (const auto status = authenticate_modules(error); status != Status::kOk) return status;
  if (std::fegetround() != FE_TONEAREST) {
    return fail(Status::kInvalidArgument, "native render requires FE_TONEAREST", error);
  }
  /*
   * Execute mutates only this one-shot admission bit; all scene, field-pack,
   * descriptor, command, face, and texture owners remain immutable. Restore
   * the bit on every return so each call creates a fresh pipeline/frame and
   * re-rasterizes instead of reusing output. Callers serialize this operation.
   */
  struct Restore final {
    PreparedRender::Storage& storage;
    bool executed;
    infinimii_native_png_encoder* png_encoder;
    ltd_native_render_cancel_fn is_cancelled;
    void* cancel_context;
    bool request_context_detached;
    ~Restore() {
      storage.executed = executed;
      storage.request.png_encoder = png_encoder;
      storage.request.is_cancelled = is_cancelled;
      storage.request.cancel_context = cancel_context;
      storage.request_context_detached = request_context_detached;
    }
  } restore{*prepared->storage_, prepared->storage_->executed,
            prepared->storage_->request.png_encoder,
            prepared->storage_->request.is_cancelled,
            prepared->storage_->request.cancel_context,
            prepared->storage_->request_context_detached};
  prepared->storage_->executed = false;
  prepared->storage_->request.png_encoder = context.png_encoder;
  prepared->storage_->request.is_cancelled = context.is_cancelled;
  prepared->storage_->request.cancel_context = context.cancel_context;
  prepared->storage_->request_context_detached = false;
  return Execute(prepared, output, error);
}

Status BuildAndExecute(const Request& request, Output* output, std::string* error) {
  if (output == nullptr) {
    return fail(Status::kInvalidArgument, "native output is null", error);
  }
  PreparedRender prepared;
  PrepareReport report{};
  const auto prepare_status = Prepare(request, &prepared, &report, error);
  if (prepare_status != Status::kOk) return prepare_status;
  return Execute(&prepared, output, error);
}

}  // namespace infinimii::native_render_orchestrator
