#include "native_render_pipeline.h"

#include "native_geometry.h"
#include "native_pose.h"
#include "native_postprocess.h"
#include "native_raster_core.h"
#include "native_scene_math.h"

#include <algorithm>
#include <array>
#include <cfenv>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <vector>

namespace {

enum class PipelineState : std::uint8_t { idle, frame, draws, finished, failed };

constexpr char kAcceptedZlibVersion[] = "1.3.1.zlib-ng";
constexpr std::uint32_t kAcceptedZlibProbeSize = 887;
constexpr std::uint32_t kAcceptedZlibProbeCrc32 = 0xd3cdd49bU;
constexpr char kHeadGroup[] = "Head__mt_Head";
constexpr char kMaskGroup[] = "Mask__mt_Mask";
constexpr char kNoseLineGroup[] = "NoseLine__mt_NoseLine";

constexpr ltd_native_render_profile_support kProfiles[] = {
    {LTD_NATIVE_RENDER_PROFILE_HEAD816, "Head816", 816, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_BODY324, "Body324", 324, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_BODY336, "Body336", 336, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_BODY348, "Body348", 348, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_EAR372, "Ear372", 372, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_NOSE756, "Nose756", 756, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_MASK0, "Mask0", 0, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_HAIR612, "Hair612", 612, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_HAIR564_EQUAL_ENDPOINT,
     "Hair564EqualEndpoint", 564, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_BEARD468, "Beard468", 468, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_OUTFIT_TOPS984, "OutfitTops984", 984, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_OUTFIT_BOTTOMS936,
     "OutfitBottoms936", 936, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_OUTFIT_SHOES912,
     "OutfitShoes912", 912, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_NOSE_LINE12, "NoseLine12", 12, 1, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_GLASS_FRAME360, "GlassFrame360", 360, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_GLASS_LENS60_OPAQUE,
     "GlassLens60Opaque", 60, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_GLASS_LENS60_TRANSLUCENT,
     "GlassLens60Translucent", 60, 0, 0, 0, 1},
    {LTD_NATIVE_RENDER_PROFILE_DECORATION480, "Decoration480", 480, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_DECORATION492, "Decoration492", 492, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_HAIR396, "Hair396", 396, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_HAIR408, "Hair408", 408, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_HAIR420, "Hair420", 420, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_HAIR432, "Hair432", 432, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_HAIR672, "Hair672", 672, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_HAIR708, "Hair708", 708, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_HAIR1056, "Hair1056", 1056, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_HAIR1116, "Hair1116", 1116, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_BEARD456, "Beard456", 456, 0, 0, 0, 0},
    {LTD_NATIVE_RENDER_PROFILE_LEGACY_HEADWEAR96,
     "LegacyHeadwear96", 96, 0, 0, 0, 0},
};

static_assert(std::size(kProfiles) == LTD_NATIVE_RENDER_PIPELINE_PROFILE_COUNT);

bool checked_mul(std::size_t left, std::size_t right, std::size_t& output) {
    if (left != 0 && right > std::numeric_limits<std::size_t>::max() / left) return false;
    output = left * right;
    return true;
}

bool valid_sha256(const char* value) {
    if (value == nullptr) return false;
    for (std::size_t index = 0; index < 64; ++index) {
        const char c = value[index];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return value[64] == '\0';
}

const ltd_native_render_profile_support* profile_support(std::uint32_t profile) {
    for (const auto& row : kProfiles) {
        if (row.profile == profile) return &row;
    }
    return nullptr;
}

bool is_body(std::uint32_t profile) {
    return profile == LTD_NATIVE_RENDER_PROFILE_BODY324 ||
           profile == LTD_NATIVE_RENDER_PROFILE_BODY336 ||
           profile == LTD_NATIVE_RENDER_PROFILE_BODY348;
}

bool cancelled(const ltd_native_render_pipeline* pipeline);

ltd_face_const_rgba8_image const_image(
    const std::vector<std::uint8_t>& bytes, std::uint32_t width, std::uint32_t height) {
    const std::size_t stride = static_cast<std::size_t>(width) * 4;
    return {bytes.empty() ? nullptr : bytes.data(), bytes.size(), stride, width, height};
}

ltd_face_rgba8_image mutable_image(
    std::vector<std::uint8_t>& bytes, std::uint32_t width, std::uint32_t height) {
    const std::size_t stride = static_cast<std::size_t>(width) * 4;
    return {bytes.empty() ? nullptr : bytes.data(), bytes.size(), stride, width, height};
}

}  // namespace

struct ltd_native_render_pipeline {
    ltd_native_render_config config{};
    PipelineState state = PipelineState::idle;
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::uint32_t output_mode = 0;
    std::size_t pixel_count = 0;
    std::array<std::array<char, 65>, 5> seals{};
    std::vector<double> color;
    std::vector<double> depth;
    std::vector<double> alpha;
    std::vector<double> post;
    std::vector<double> rgba;
    std::vector<std::uint8_t> transferred;
    std::vector<std::uint8_t> png;
    std::vector<std::uint8_t> face_pass0;
    std::vector<std::uint8_t> face_case21;
    std::vector<std::uint8_t> face_final;
    std::vector<std::uint8_t> face_mesh;
    std::vector<std::uint8_t> face_audit0;
    std::vector<std::uint8_t> face_audit1;
    std::vector<std::uint8_t> faceline;
    std::uint32_t face_width = 0;
    std::uint32_t face_height = 0;
    std::uint32_t face_layers = 0;
    std::size_t draw_count = 0;
    std::uint64_t written_fragments = 0;
    bool mask_prepared = false;
    bool faceline_prepared = false;
    bool post_applied = false;
};

namespace {

bool cancelled(const ltd_native_render_pipeline* pipeline) {
    return pipeline != nullptr && pipeline->config.is_cancelled != nullptr &&
           pipeline->config.is_cancelled(pipeline->config.cancel_context) != 0;
}

void copy_seal(std::array<char, 65>& target, const char* source) {
    std::memcpy(target.data(), source, 65);
}

ltd_native_render_status validate_modules(const ltd_native_render_config& config) {
    if (std::fegetround() != FE_TONEAREST) return LTD_NATIVE_RENDER_MODULE_MISMATCH;
    if (ltd_native_scene_abi_version() != 1 || ltd_native_pose_abi_version() != 1 ||
        ltd_native_geometry_abi_version() != 1 || ltd_native_raster_abi_version() != 1 ||
        ltd_native_postprocess_abi_version() != 1 ||
        infinimii_native_png_abi_version() != INFINIMII_NATIVE_PNG_ABI_VERSION) {
        return LTD_NATIVE_RENDER_MODULE_MISMATCH;
    }
    if (ltd_draw_runtime_require(
            LTD_DRAW_RUNTIME_ABI_VERSION, LTD_DRAW_RUNTIME_CONTRACT_SHA256) !=
            LTD_DRAW_RUNTIME_OK ||
        ltd_draw_runtime_v2_require(
            LTD_DRAW_RUNTIME_V2_ABI_VERSION, LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256) !=
            LTD_DRAW_RUNTIME_OK ||
        ltd_face_runtime_require(
            LTD_FACE_RUNTIME_ABI_VERSION, LTD_FACE_RUNTIME_CONTRACT_SHA256) !=
            LTD_FACE_RUNTIME_OK ||
        ltd_native_noseline_pipeline_bridge_abi_version() !=
            LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_ABI_VERSION ||
        std::strcmp(ltd_native_noseline_pipeline_bridge_contract_sha256(),
                    LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_CONTRACT_SHA256) != 0 ||
        ltd_noseline12_require(LTD_NOSELINE12_ABI_VERSION,
                              LTD_NOSELINE12_CONTRACT_SHA256) != LTD_NOSELINE12_OK) {
        return LTD_NATIVE_RENDER_MODULE_MISMATCH;
    }
    char version[64]{};
    std::uint32_t probe_size = 0;
    std::uint32_t probe_crc = 0;
    if (config.png_encoder == nullptr ||
        infinimii_native_png_backend_identity(
            config.png_encoder, version, sizeof(version), &probe_size, &probe_crc) !=
            INFINIMII_NATIVE_PNG_OK ||
        std::strcmp(version, kAcceptedZlibVersion) != 0 ||
        probe_size != kAcceptedZlibProbeSize || probe_crc != kAcceptedZlibProbeCrc32) {
        return LTD_NATIVE_RENDER_MODULE_MISMATCH;
    }
    return LTD_NATIVE_RENDER_OK;
}

bool valid_state_for_face(const ltd_native_render_pipeline* pipeline) {
    return pipeline != nullptr && pipeline->state == PipelineState::frame;
}

ltd_native_render_status validate_command(const ltd_native_render_draw_command& command) {
    const auto* support = profile_support(command.profile);
    if (support == nullptr || command.group == nullptr || command.group[0] == '\0' ||
        command.reserved != 0 || command.input.opaque == nullptr) {
        return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
    }
    if (!support->kernel_available) return LTD_NATIVE_RENDER_PROFILE_UNIMPLEMENTED;
    if (command.blend != 0 || command.depth_write != 1) {
        return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
    }
    if (command.profile == LTD_NATIVE_RENDER_PROFILE_HEAD816 &&
        std::strcmp(command.group, kHeadGroup) != 0) {
        return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
    }
    if (command.profile == LTD_NATIVE_RENDER_PROFILE_MASK0 &&
        std::strcmp(command.group, kMaskGroup) != 0) {
        return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
    }
    if (command.profile == LTD_NATIVE_RENDER_PROFILE_NOSE_LINE12) {
        if (std::strcmp(command.group, kNoseLineGroup) != 0 ||
            command.input.noseline == nullptr ||
            command.input.noseline->scene == nullptr ||
            command.input.noseline->texture == nullptr) {
            return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
        }
        if (command.input.noseline->scene->profile !=
                LTD_NATIVE_SCENE_PROFILE_NOSE_LINE12 ||
            command.input.noseline->scene->blend != command.blend ||
            command.input.noseline->scene->depth_write != command.depth_write ||
            command.input.noseline->scene->group == nullptr ||
            std::strcmp(command.input.noseline->scene->group, command.group) != 0) {
            return LTD_NATIVE_RENDER_CONTRACT_MISMATCH;
        }
    }
    if (command.profile == LTD_NATIVE_RENDER_PROFILE_HAIR612 &&
        command.input.hair->profile != LTD_DRAW_HAIR612) {
        return LTD_NATIVE_RENDER_CONTRACT_MISMATCH;
    }
    if (command.profile == LTD_NATIVE_RENDER_PROFILE_HAIR564_EQUAL_ENDPOINT &&
        command.input.hair->profile != LTD_DRAW_HAIR564_EQUAL_ENDPOINT) {
        return LTD_NATIVE_RENDER_CONTRACT_MISMATCH;
    }
    if (command.profile == LTD_NATIVE_RENDER_PROFILE_BEARD468 &&
        command.input.hair->profile != LTD_DRAW_BEARD468) {
        return LTD_NATIVE_RENDER_CONTRACT_MISMATCH;
    }
    const int expected_outfit =
        command.profile == LTD_NATIVE_RENDER_PROFILE_OUTFIT_TOPS984
            ? LTD_DRAW_OUTFIT_TOPS984
            : command.profile == LTD_NATIVE_RENDER_PROFILE_OUTFIT_BOTTOMS936
                  ? LTD_DRAW_OUTFIT_BOTTOMS936
                  : command.profile == LTD_NATIVE_RENDER_PROFILE_OUTFIT_SHOES912
                        ? LTD_DRAW_OUTFIT_SHOES912
                        : 0;
    if (expected_outfit != 0 && command.input.outfit->profile != expected_outfit) {
        return LTD_NATIVE_RENDER_CONTRACT_MISMATCH;
    }
    return LTD_NATIVE_RENDER_OK;
}

ltd_draw_runtime_status execute_draw(
    ltd_draw_attachments& attachments,
    const ltd_native_render_draw_command& command,
    std::uint64_t& written) {
    if (command.profile == LTD_NATIVE_RENDER_PROFILE_HEAD816) {
        return ltd_draw_head816(&attachments, command.input.head816, &written);
    }
    if (is_body(command.profile)) {
        return ltd_draw_body(&attachments, command.input.body, &written);
    }
    if (command.profile == LTD_NATIVE_RENDER_PROFILE_EAR372 ||
        command.profile == LTD_NATIVE_RENDER_PROFILE_NOSE756) {
        return ltd_draw_plain_skin(&attachments, command.input.plain_skin, &written);
    }
    if (command.profile == LTD_NATIVE_RENDER_PROFILE_MASK0) {
        return ltd_draw_mask0(&attachments, command.input.mask0, &written);
    }
    if (command.profile == LTD_NATIVE_RENDER_PROFILE_HAIR612 ||
        command.profile == LTD_NATIVE_RENDER_PROFILE_HAIR564_EQUAL_ENDPOINT ||
        command.profile == LTD_NATIVE_RENDER_PROFILE_BEARD468) {
        return ltd_draw_hair(&attachments, command.input.hair, &written);
    }
    return ltd_draw_outfit(&attachments, command.input.outfit, &written);
}

ltd_native_render_status execute_command(
    ltd_draw_attachments& attachments,
    const ltd_native_render_draw_command& command,
    std::uint64_t& written) {
    written = 0;
    if (command.profile != LTD_NATIVE_RENDER_PROFILE_NOSE_LINE12) {
        return execute_draw(attachments, command, written) == LTD_DRAW_RUNTIME_OK
            ? LTD_NATIVE_RENDER_OK : LTD_NATIVE_RENDER_DRAW_FAILED;
    }
    ltd_native_noseline_pipeline_attachments destination{
        attachments.color, attachments.color_capacity_bytes,
        attachments.color_row_stride_bytes, attachments.depth,
        attachments.depth_capacity_bytes, attachments.depth_row_stride_bytes,
        attachments.alpha, attachments.alpha_capacity_bytes,
        attachments.alpha_row_stride_bytes, attachments.width, attachments.height};
    ltd_noseline12_report report{};
    char error[256]{};
    const auto status = ltd_native_noseline_pipeline_draw(
        &destination, command.input.noseline->scene,
        command.input.noseline->texture, &report, error, sizeof(error));
    if (status != LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_OK) {
        return LTD_NATIVE_RENDER_DRAW_FAILED;
    }
    written = report.written_fragments;
    return LTD_NATIVE_RENDER_OK;
}

void fill_output(
    const ltd_native_render_pipeline& pipeline,
    ltd_native_render_output_view& output,
    ltd_native_render_report& report) {
    output.png_bytes = pipeline.png.data();
    output.png_size = pipeline.png.size();
    output.transferred_pixels = pipeline.transferred.data();
    output.transferred_size = pipeline.transferred.size();
    output.channels = pipeline.output_mode == LTD_NATIVE_RENDER_OUTPUT_RGB ? 3U : 4U;
    output.transferred_row_stride = static_cast<std::size_t>(pipeline.width) * output.channels;
    output.width = pipeline.width;
    output.height = pipeline.height;
    output.linear_rgb = pipeline.post_applied ? pipeline.post.data() : pipeline.color.data();
    output.depth = pipeline.depth.data();
    output.alpha = pipeline.alpha.empty() ? nullptr : pipeline.alpha.data();
    report = {};
    report.abi_version = LTD_NATIVE_RENDER_PIPELINE_ABI_VERSION;
    report.draw_count = static_cast<std::uint32_t>(pipeline.draw_count);
    report.written_fragments = pipeline.written_fragments;
    report.pixel_count = pipeline.pixel_count;
    report.png_size = pipeline.png.size();
    report.face_mask_prepared = pipeline.mask_prepared ? 1 : 0;
    report.faceline_prepared = pipeline.faceline_prepared ? 1 : 0;
    report.postprocess_applied = pipeline.post_applied ? 1 : 0;
    report.source_seals_validated = 1;
    report.production_activation_ready = 1;
    report.pixels_produced = 1;
    report.png_produced = pipeline.png.empty() ? 0 : 1;
}

}  // namespace

extern "C" {

std::uint32_t LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_pipeline_abi_version(void) {
    return LTD_NATIVE_RENDER_PIPELINE_ABI_VERSION;
}

const char* LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_pipeline_contract_sha256(void) {
    return LTD_NATIVE_RENDER_PIPELINE_CONTRACT_SHA256;
}

const char* LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_status_name(
    ltd_native_render_status status) {
    switch (status) {
        case LTD_NATIVE_RENDER_OK: return "OK";
        case LTD_NATIVE_RENDER_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
        case LTD_NATIVE_RENDER_ABI_MISMATCH: return "ABI_MISMATCH";
        case LTD_NATIVE_RENDER_CONTRACT_MISMATCH: return "CONTRACT_MISMATCH";
        case LTD_NATIVE_RENDER_MODULE_MISMATCH: return "MODULE_MISMATCH";
        case LTD_NATIVE_RENDER_SOURCE_SEAL_INVALID: return "SOURCE_SEAL_INVALID";
        case LTD_NATIVE_RENDER_RESOURCE_LIMIT: return "RESOURCE_LIMIT";
        case LTD_NATIVE_RENDER_ALLOCATION_FAILED: return "ALLOCATION_FAILED";
        case LTD_NATIVE_RENDER_INVALID_STATE: return "INVALID_STATE";
        case LTD_NATIVE_RENDER_PROFILE_UNIMPLEMENTED: return "PROFILE_UNIMPLEMENTED";
        case LTD_NATIVE_RENDER_SCENE_SCHEDULE_FAILED: return "SCENE_SCHEDULE_FAILED";
        case LTD_NATIVE_RENDER_DRAW_FAILED: return "DRAW_FAILED";
        case LTD_NATIVE_RENDER_FACE_FAILED: return "FACE_FAILED";
        case LTD_NATIVE_RENDER_POSTPROCESS_FAILED: return "POSTPROCESS_FAILED";
        case LTD_NATIVE_RENDER_PNG_FAILED: return "PNG_FAILED";
        case LTD_NATIVE_RENDER_CANCELLED: return "CANCELLED";
        default: return "UNKNOWN";
    }
}

int LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_pipeline_activation_ready(void) {
    return 1;
}

const ltd_native_render_profile_support* LTD_NATIVE_RENDER_PIPELINE_CALL
ltd_native_render_profile_support_table(size_t* profile_count) {
    if (profile_count != nullptr) *profile_count = std::size(kProfiles);
    return kProfiles;
}

ltd_native_render_status LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_pipeline_create(
    const ltd_native_render_config* config, ltd_native_render_pipeline** output) {
    if (output == nullptr) return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
    *output = nullptr;
    if (config == nullptr || config->max_width == 0 || config->max_height == 0 ||
        config->max_width > LTD_NATIVE_RENDER_PIPELINE_MAX_DIMENSION ||
        config->max_height > LTD_NATIVE_RENDER_PIPELINE_MAX_DIMENSION ||
        config->max_pixels == 0 || config->max_draws == 0 ||
        config->max_face_layers > LTD_FACE_RUNTIME_MAX_MASK_LAYERS) {
        return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
    }
    const auto modules = validate_modules(*config);
    if (modules != LTD_NATIVE_RENDER_OK) return modules;
    auto* pipeline = new (std::nothrow) ltd_native_render_pipeline();
    if (pipeline == nullptr) return LTD_NATIVE_RENDER_ALLOCATION_FAILED;
    pipeline->config = *config;
    *output = pipeline;
    return LTD_NATIVE_RENDER_OK;
}

void LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_pipeline_destroy(
    ltd_native_render_pipeline* pipeline) {
    delete pipeline;
}

ltd_native_render_status LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_begin_frame(
    ltd_native_render_pipeline* pipeline, const ltd_native_render_frame_desc* frame) {
    if (pipeline == nullptr || frame == nullptr || frame->reserved != 0) {
        return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
    }
    if (cancelled(pipeline)) return LTD_NATIVE_RENDER_CANCELLED;
    if (frame->width == 0 || frame->height == 0 ||
        frame->width > pipeline->config.max_width || frame->height > pipeline->config.max_height ||
        frame->output_mode < LTD_NATIVE_RENDER_OUTPUT_RGB ||
        frame->output_mode > LTD_NATIVE_RENDER_OUTPUT_PREMULTIPLIED_RGBA) {
        return LTD_NATIVE_RENDER_RESOURCE_LIMIT;
    }
    const char* seals[] = {
        frame->seals.ltd_source_sha256, frame->seals.active_parts_sha256,
        frame->seals.asset_index_sha256, frame->seals.scene_plan_sha256,
        frame->seals.material_plan_sha256};
    for (const char* seal : seals) {
        if (!valid_sha256(seal)) return LTD_NATIVE_RENDER_SOURCE_SEAL_INVALID;
    }
    for (double value : frame->background_linear_rgba) {
        if (!std::isfinite(value) || value < 0.0) return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
    }
    if (frame->background_linear_rgba[3] > 1.0) return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
    std::size_t pixels = 0;
    std::size_t color_elements = 0;
    if (!checked_mul(frame->width, frame->height, pixels) ||
        pixels > pipeline->config.max_pixels || !checked_mul(pixels, 3, color_elements)) {
        return LTD_NATIVE_RENDER_RESOURCE_LIMIT;
    }
    try {
        std::vector<double> color(color_elements);
        std::vector<double> depth(pixels, -std::numeric_limits<double>::infinity());
        std::vector<double> alpha;
        if (frame->output_mode == LTD_NATIVE_RENDER_OUTPUT_PREMULTIPLIED_RGBA) {
            alpha.assign(pixels, frame->background_linear_rgba[3]);
        }
        const double multiplier =
            frame->output_mode == LTD_NATIVE_RENDER_OUTPUT_PREMULTIPLIED_RGBA
                ? frame->background_linear_rgba[3]
                : 1.0;
        for (std::size_t pixel = 0; pixel < pixels; ++pixel) {
            for (std::size_t channel = 0; channel < 3; ++channel) {
                color[pixel * 3 + channel] =
                    frame->background_linear_rgba[channel] * multiplier;
            }
        }
        pipeline->color.swap(color);
        pipeline->depth.swap(depth);
        pipeline->alpha.swap(alpha);
    } catch (const std::bad_alloc&) {
        return LTD_NATIVE_RENDER_ALLOCATION_FAILED;
    }
    pipeline->post.clear();
    pipeline->rgba.clear();
    pipeline->transferred.clear();
    pipeline->png.clear();
    pipeline->face_pass0.clear();
    pipeline->face_case21.clear();
    pipeline->face_final.clear();
    pipeline->face_mesh.clear();
    pipeline->face_audit0.clear();
    pipeline->face_audit1.clear();
    pipeline->faceline.clear();
    pipeline->width = frame->width;
    pipeline->height = frame->height;
    pipeline->output_mode = frame->output_mode;
    pipeline->pixel_count = pixels;
    pipeline->draw_count = 0;
    pipeline->written_fragments = 0;
    pipeline->mask_prepared = false;
    pipeline->faceline_prepared = false;
    pipeline->post_applied = false;
    pipeline->face_width = pipeline->face_height = pipeline->face_layers = 0;
    for (std::size_t index = 0; index < 5; ++index) copy_seal(pipeline->seals[index], seals[index]);
    pipeline->state = PipelineState::frame;
    return LTD_NATIVE_RENDER_OK;
}

ltd_native_render_status LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_prepare_face_mask(
    ltd_native_render_pipeline* pipeline, const ltd_face_mask_layer* layers,
    std::uint32_t layer_count, std::uint32_t width, std::uint32_t height) {
    if (!valid_state_for_face(pipeline)) return LTD_NATIVE_RENDER_INVALID_STATE;
    if (cancelled(pipeline)) return LTD_NATIVE_RENDER_CANCELLED;
    if (layer_count > pipeline->config.max_face_layers || width == 0 || height == 0 ||
        width > pipeline->config.max_width || height > pipeline->config.max_height) {
        return LTD_NATIVE_RENDER_RESOURCE_LIMIT;
    }
    std::size_t pixels = 0, image_bytes = 0, audit_bytes = 0;
    if (!checked_mul(width, height, pixels) || pixels > pipeline->config.max_pixels ||
        !checked_mul(pixels, 4, image_bytes) ||
        !checked_mul(image_bytes, layer_count, audit_bytes)) {
        return LTD_NATIVE_RENDER_RESOURCE_LIMIT;
    }
    try {
        std::vector<std::uint8_t> pass0(image_bytes), case21(image_bytes), final_target(image_bytes),
            mesh(image_bytes), audit0(audit_bytes), audit1(audit_bytes);
        auto pass0_view = mutable_image(pass0, width, height);
        auto case21_view = mutable_image(case21, width, height);
        auto final_view = mutable_image(final_target, width, height);
        auto mesh_view = mutable_image(mesh, width, height);
        ltd_face_rgba8_stack audit0_view{
            audit0.empty() ? nullptr : audit0.data(), audit0.size(), image_bytes,
            static_cast<std::size_t>(width) * 4};
        ltd_face_rgba8_stack audit1_view{
            audit1.empty() ? nullptr : audit1.data(), audit1.size(), image_bytes,
            static_cast<std::size_t>(width) * 4};
        if (ltd_face_mask_pipeline(
                layers, layer_count, width, height, &pass0_view, &case21_view, &final_view,
                &mesh_view, &audit0_view, &audit1_view) != LTD_FACE_RUNTIME_OK) {
            return LTD_NATIVE_RENDER_FACE_FAILED;
        }
        pipeline->face_pass0.swap(pass0);
        pipeline->face_case21.swap(case21);
        pipeline->face_final.swap(final_target);
        pipeline->face_mesh.swap(mesh);
        pipeline->face_audit0.swap(audit0);
        pipeline->face_audit1.swap(audit1);
    } catch (const std::bad_alloc&) {
        return LTD_NATIVE_RENDER_ALLOCATION_FAILED;
    }
    pipeline->face_width = width;
    pipeline->face_height = height;
    pipeline->face_layers = layer_count;
    pipeline->mask_prepared = true;
    return LTD_NATIVE_RENDER_OK;
}

ltd_native_render_status LTD_NATIVE_RENDER_PIPELINE_CALL
ltd_native_render_prepare_faceline_wrinkle(
    ltd_native_render_pipeline* pipeline, const ltd_face_const_rgba8_image* source,
    const std::uint8_t skin_rgba8[4], double left, double right, double bottom, double top,
    ltd_face_faceline_raster_report* report) {
    if (!valid_state_for_face(pipeline)) return LTD_NATIVE_RENDER_INVALID_STATE;
    if (cancelled(pipeline)) return LTD_NATIVE_RENDER_CANCELLED;
    try {
        std::vector<std::uint8_t> output(
            static_cast<std::size_t>(LTD_FACE_RUNTIME_FACELINE_WIDTH) *
            LTD_FACE_RUNTIME_FACELINE_HEIGHT * 4);
        auto view = mutable_image(
            output, LTD_FACE_RUNTIME_FACELINE_WIDTH, LTD_FACE_RUNTIME_FACELINE_HEIGHT);
        if (ltd_face_faceline_wrinkle(
                source, skin_rgba8, left, right, bottom, top, &view, report) !=
            LTD_FACE_RUNTIME_OK) {
            return LTD_NATIVE_RENDER_FACE_FAILED;
        }
        pipeline->faceline.swap(output);
    } catch (const std::bad_alloc&) {
        return LTD_NATIVE_RENDER_ALLOCATION_FAILED;
    }
    pipeline->faceline_prepared = true;
    return LTD_NATIVE_RENDER_OK;
}

ltd_native_render_status LTD_NATIVE_RENDER_PIPELINE_CALL
ltd_native_render_prepare_faceline_johnny(
    ltd_native_render_pipeline* pipeline, const ltd_face_const_rgba8_image* source,
    const std::uint8_t skin_rgba8[4], const double c1_rgba[4], const double c2_rgba[4]) {
    if (!valid_state_for_face(pipeline)) return LTD_NATIVE_RENDER_INVALID_STATE;
    if (cancelled(pipeline)) return LTD_NATIVE_RENDER_CANCELLED;
    try {
        std::vector<std::uint8_t> output(
            static_cast<std::size_t>(LTD_FACE_RUNTIME_FACELINE_WIDTH) *
            LTD_FACE_RUNTIME_FACELINE_HEIGHT * 4);
        auto view = mutable_image(
            output, LTD_FACE_RUNTIME_FACELINE_WIDTH, LTD_FACE_RUNTIME_FACELINE_HEIGHT);
        if (ltd_face_faceline_johnny(source, skin_rgba8, c1_rgba, c2_rgba, &view) !=
            LTD_FACE_RUNTIME_OK) {
            return LTD_NATIVE_RENDER_FACE_FAILED;
        }
        pipeline->faceline.swap(output);
    } catch (const std::bad_alloc&) {
        return LTD_NATIVE_RENDER_ALLOCATION_FAILED;
    }
    pipeline->faceline_prepared = true;
    return LTD_NATIVE_RENDER_OK;
}

ltd_native_render_status LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_get_face_views(
    const ltd_native_render_pipeline* pipeline, ltd_native_render_face_views* output) {
    if (pipeline == nullptr || output == nullptr || pipeline->state == PipelineState::idle) {
        return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
    }
    *output = {};
    if (pipeline->mask_prepared) {
        output->pass0 = const_image(pipeline->face_pass0, pipeline->face_width, pipeline->face_height);
        output->case21 = const_image(
            pipeline->face_case21, pipeline->face_width, pipeline->face_height);
        output->final_target = const_image(
            pipeline->face_final, pipeline->face_width, pipeline->face_height);
        output->mesh_input = const_image(
            pipeline->face_mesh, pipeline->face_width, pipeline->face_height);
    }
    if (pipeline->faceline_prepared) {
        output->faceline = const_image(
            pipeline->faceline, LTD_FACE_RUNTIME_FACELINE_WIDTH,
            LTD_FACE_RUNTIME_FACELINE_HEIGHT);
    }
    output->mask_layer_count = pipeline->face_layers;
    output->mask_prepared = pipeline->mask_prepared ? 1 : 0;
    output->faceline_prepared = pipeline->faceline_prepared ? 1 : 0;
    return LTD_NATIVE_RENDER_OK;
}

ltd_native_render_status LTD_NATIVE_RENDER_PIPELINE_CALL
ltd_native_render_execute_precompiled_draws(
    ltd_native_render_pipeline* pipeline, const ltd_native_render_draw_command* draws,
    std::size_t draw_count) {
    if (pipeline == nullptr || pipeline->state != PipelineState::frame) {
        return LTD_NATIVE_RENDER_INVALID_STATE;
    }
    if (draws == nullptr || draw_count == 0 || draw_count > pipeline->config.max_draws ||
        draw_count > std::numeric_limits<std::uint32_t>::max()) {
        return LTD_NATIVE_RENDER_RESOURCE_LIMIT;
    }
    if (cancelled(pipeline)) return LTD_NATIVE_RENDER_CANCELLED;
    std::size_t head_count = 0;
    std::vector<LtdNativeDrawRecord> records;
    std::vector<std::size_t> order;
    try {
        records.resize(draw_count);
        order.resize(draw_count);
    } catch (const std::bad_alloc&) {
        return LTD_NATIVE_RENDER_ALLOCATION_FAILED;
    }
    for (std::size_t index = 0; index < draw_count; ++index) {
        const auto status = validate_command(draws[index]);
        if (status != LTD_NATIVE_RENDER_OK) return status;
        if (draws[index].profile == LTD_NATIVE_RENDER_PROFILE_HEAD816) ++head_count;
        records[index] = {draws[index].group, draws[index].blend, draws[index].depth_write};
    }
    if (head_count != 1) return LTD_NATIVE_RENDER_SCENE_SCHEDULE_FAILED;
    if (ltd_native_schedule_draws(
            records.data(), records.size(), order.data(), order.size()) !=
        LTD_NATIVE_SCENE_OK) {
        return LTD_NATIVE_RENDER_SCENE_SCHEDULE_FAILED;
    }
    ltd_draw_attachments attachments{
        pipeline->color.data(), pipeline->color.size() * sizeof(double),
        static_cast<std::size_t>(pipeline->width) * 3 * sizeof(double),
        pipeline->depth.data(), pipeline->depth.size() * sizeof(double),
        static_cast<std::size_t>(pipeline->width) * sizeof(double),
        pipeline->alpha.empty() ? nullptr : pipeline->alpha.data(),
        pipeline->alpha.size() * sizeof(double),
        pipeline->alpha.empty() ? 0 : static_cast<std::size_t>(pipeline->width) * sizeof(double),
        pipeline->width, pipeline->height};
    std::uint64_t total = 0;
    for (const std::size_t index : order) {
        if (cancelled(pipeline)) {
            pipeline->state = PipelineState::failed;
            return LTD_NATIVE_RENDER_CANCELLED;
        }
        std::uint64_t written = 0;
        if (execute_command(attachments, draws[index], written) != LTD_NATIVE_RENDER_OK ||
            written > std::numeric_limits<std::uint64_t>::max() - total) {
            pipeline->state = PipelineState::failed;
            return LTD_NATIVE_RENDER_DRAW_FAILED;
        }
        total += written;
    }
    pipeline->draw_count = draw_count;
    pipeline->written_fragments = total;
    pipeline->state = PipelineState::draws;
    return LTD_NATIVE_RENDER_OK;
}

ltd_native_render_status LTD_NATIVE_RENDER_PIPELINE_CALL
ltd_native_render_finish_precompiled_frame(
    ltd_native_render_pipeline* pipeline, const ltd_native_render_finish_desc* finish,
    ltd_native_render_output_view* output, ltd_native_render_report* report) {
    if (pipeline == nullptr || finish == nullptr || output == nullptr || report == nullptr ||
        pipeline->state != PipelineState::draws) {
        return LTD_NATIVE_RENDER_INVALID_STATE;
    }
    for (std::uint8_t value : finish->reserved) {
        if (value != 0) return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
    }
    if (cancelled(pipeline)) return LTD_NATIVE_RENDER_CANCELLED;
    const std::size_t expected_bloom = pipeline->pixel_count * 3;
    if ((finish->bloom_linear_rgb == nullptr && finish->bloom_element_count != 0) ||
        (finish->bloom_linear_rgb != nullptr && finish->bloom_element_count != expected_bloom) ||
        (!finish->apply_snapshot_pfx_gamma0 && finish->bloom_linear_rgb != nullptr)) {
        return LTD_NATIVE_RENDER_INVALID_ARGUMENT;
    }
    try {
        std::vector<double> post;
        const double* transfer_rgb = pipeline->color.data();
        if (finish->apply_snapshot_pfx_gamma0) {
            post.resize(expected_bloom);
            if (ltd_native_snapshot_pfx_gamma0(
                    pipeline->color.data(), finish->bloom_linear_rgb,
                    pipeline->pixel_count, post.data()) != LTD_NATIVE_POST_OK) {
                return LTD_NATIVE_RENDER_POSTPROCESS_FAILED;
            }
            transfer_rgb = post.data();
        }
        const std::size_t channels =
            pipeline->output_mode == LTD_NATIVE_RENDER_OUTPUT_RGB ? 3 : 4;
        std::vector<std::uint8_t> transferred(pipeline->pixel_count * channels);
        char error[256]{};
        infinimii_native_png_status transfer_status = INFINIMII_NATIVE_PNG_OK;
        std::vector<double> rgba;
        if (channels == 3) {
            transfer_status = infinimii_native_png_transfer_linear_rgb64_to_rgb8(
                transfer_rgb, pipeline->width, pipeline->height,
                static_cast<std::size_t>(pipeline->width) * 3 * sizeof(double),
                transferred.data(), static_cast<std::size_t>(pipeline->width) * 3,
                error, sizeof(error));
        } else {
            rgba.resize(pipeline->pixel_count * 4);
            for (std::size_t pixel = 0; pixel < pipeline->pixel_count; ++pixel) {
                rgba[pixel * 4] = transfer_rgb[pixel * 3];
                rgba[pixel * 4 + 1] = transfer_rgb[pixel * 3 + 1];
                rgba[pixel * 4 + 2] = transfer_rgb[pixel * 3 + 2];
                rgba[pixel * 4 + 3] = pipeline->alpha[pixel];
            }
            transfer_status =
                infinimii_native_png_transfer_premultiplied_linear_rgba64_to_rgba8(
                    rgba.data(), pipeline->width, pipeline->height,
                    static_cast<std::size_t>(pipeline->width) * 4 * sizeof(double),
                    transferred.data(), static_cast<std::size_t>(pipeline->width) * 4,
                    error, sizeof(error));
        }
        if (transfer_status != INFINIMII_NATIVE_PNG_OK) return LTD_NATIVE_RENDER_PNG_FAILED;
        infinimii_native_png_bytes encoded{};
        const auto encode_status = channels == 3
            ? infinimii_native_png_encode_rgb8(
                  pipeline->config.png_encoder, transferred.data(), pipeline->width,
                  pipeline->height, static_cast<std::size_t>(pipeline->width) * 3,
                  &encoded, error, sizeof(error))
            : infinimii_native_png_encode_rgba8(
                  pipeline->config.png_encoder, transferred.data(), pipeline->width,
                  pipeline->height, static_cast<std::size_t>(pipeline->width) * 4,
                  &encoded, error, sizeof(error));
        if (encode_status != INFINIMII_NATIVE_PNG_OK) {
            infinimii_native_png_bytes_free(&encoded);
            return LTD_NATIVE_RENDER_PNG_FAILED;
        }
        std::vector<std::uint8_t> png(encoded.data, encoded.data + encoded.size);
        infinimii_native_png_bytes_free(&encoded);
        pipeline->post.swap(post);
        pipeline->rgba.swap(rgba);
        pipeline->transferred.swap(transferred);
        pipeline->png.swap(png);
    } catch (const std::bad_alloc&) {
        return LTD_NATIVE_RENDER_ALLOCATION_FAILED;
    }
    pipeline->post_applied = finish->apply_snapshot_pfx_gamma0 != 0;
    pipeline->state = PipelineState::finished;
    fill_output(*pipeline, *output, *report);
    return LTD_NATIVE_RENDER_OK;
}

}  // extern "C"
