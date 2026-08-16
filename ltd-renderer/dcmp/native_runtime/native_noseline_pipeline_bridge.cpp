#include "native_noseline_pipeline_bridge.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <new>
#include <string>
#include <string_view>

namespace {

void write_error(char* output, std::size_t capacity, std::string_view message) {
    if (output == nullptr || capacity == 0) return;
    const std::size_t count = std::min(capacity - 1, message.size());
    std::memcpy(output, message.data(), count);
    output[count] = '\0';
}

bool exact_seal(const char* actual, const char* expected) {
    return actual != nullptr && std::strcmp(actual, expected) == 0;
}

}  // namespace

extern "C" {

uint32_t ltd_native_noseline_pipeline_bridge_abi_version(void) {
    return LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_ABI_VERSION;
}

const char* ltd_native_noseline_pipeline_bridge_contract_sha256(void) {
    return LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_CONTRACT_SHA256;
}

int ltd_native_noseline_pipeline_bridge_activation_ready(void) {
    return 0;
}

ltd_native_noseline_pipeline_bridge_status ltd_native_noseline_pipeline_draw(
    ltd_native_noseline_pipeline_attachments* attachments,
    const ltd_native_scene_draw_view* scene,
    const ltd_native_noseline_pipeline_texture* texture,
    ltd_noseline12_report* report,
    char* error,
    size_t error_capacity) {
    if (error != nullptr && error_capacity != 0) error[0] = '\0';
    if (attachments == nullptr || scene == nullptr || texture == nullptr || report == nullptr ||
        attachments->color == nullptr || attachments->depth == nullptr ||
        attachments->width == 0 || attachments->height == 0 ||
        scene->resource_name == nullptr || scene->model_name == nullptr ||
        scene->group == nullptr || scene->screen == nullptr ||
        scene->source_triangle_indices == nullptr || texture->mip_rgba == nullptr ||
        texture->texture_manifest_sha256 == nullptr || texture->decoded_mips_sha256 == nullptr) {
        write_error(error, error_capacity, "NoseLine pipeline bridge arguments are invalid");
        return LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_INVALID_ARGUMENT;
    }
    if (ltd_noseline12_require(
            LTD_NOSELINE12_ABI_VERSION, LTD_NOSELINE12_CONTRACT_SHA256) != LTD_NOSELINE12_OK) {
        write_error(error, error_capacity, "frozen NoseLine12 module identity differs");
        return LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_SOURCE_MISMATCH;
    }
    if (scene->profile != LTD_NATIVE_SCENE_PROFILE_NOSE_LINE12 ||
        std::strcmp(scene->resource_name, "MiiNose06") != 0 ||
        std::strcmp(scene->model_name, "MiiNose06") != 0 ||
        std::strcmp(scene->group, "NoseLine__mt_NoseLine") != 0 ||
        scene->blend != 0 || scene->depth_write != 1 ||
        scene->submitted_triangle_count != 2 || scene->candidate_triangle_count != 2 ||
        scene->source_triangle_indices[0] != 370 || scene->source_triangle_indices[1] != 371 ||
        scene->material_uv == nullptr || scene->uv0 == nullptr || scene->uv2 != nullptr) {
        write_error(error, error_capacity,
                    "scene draw is not the source-authenticated MiiNose06 NoseLine12 carrier");
        return LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_GEOMETRY_MISMATCH;
    }
    /*
     * Assembler rows are triangles (402,403,404) then (404,403,405).  Preserve
     * exact carrier order and additionally reject a broken shared edge.
     */
    const double* first = scene->screen;
    const double* second = scene->screen + 9;
    if (std::memcmp(first + 6, second, 3 * sizeof(double)) != 0 ||
        std::memcmp(first + 3, second + 3, 3 * sizeof(double)) != 0) {
        write_error(error, error_capacity, "NoseLine carrier shared edge differs");
        return LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_GEOMETRY_MISMATCH;
    }
    static constexpr double expected_uv[12] = {
        0x1.7f7f7f3c2041cp-1, 0x1.9191900acf91dp-4,
        0x1.7f7f7f3c2041cp-1, 0x1.cbcbcb450d505p-1,
        0x1.01010187bf7c8p-2, 0x1.9191900acf91dp-4,
        0x1.01010187bf7c8p-2, 0x1.9191900acf91dp-4,
        0x1.7f7f7f3c2041cp-1, 0x1.cbcbcb450d505p-1,
        0x1.01010187bf7c8p-2, 0x1.cbcbcb450d505p-1};
    if (std::memcmp(scene->material_uv, expected_uv, sizeof(expected_uv)) != 0 ||
        std::memcmp(scene->uv0, expected_uv, sizeof(expected_uv)) != 0) {
        write_error(error, error_capacity, "NoseLine carrier UV topology differs");
        return LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_GEOMETRY_MISMATCH;
    }
    if (!exact_seal(texture->texture_manifest_sha256,
                    LTD_NOSELINE12_TEXTURE_MANIFEST_SHA256) ||
        !exact_seal(texture->decoded_mips_sha256, LTD_NOSELINE12_DECODED_MIPS_SHA256)) {
        write_error(error, error_capacity, "NoseLine texture source seals differ");
        return LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_TEXTURE_MISMATCH;
    }
    ltd_noseline12_attachments destination{
        attachments->color, attachments->color_capacity_bytes,
        attachments->color_row_stride_bytes, attachments->depth,
        attachments->depth_capacity_bytes, attachments->depth_row_stride_bytes,
        attachments->alpha, attachments->alpha_capacity_bytes,
        attachments->alpha_row_stride_bytes, attachments->width, attachments->height};
    ltd_noseline12_input input{};
    std::copy(first, first + 9, input.screen);
    std::copy(second + 6, second + 9, input.screen + 9);
    input.mip_rgba = texture->mip_rgba;
    input.mip_rgba_element_count = texture->mip_rgba_element_count;
    std::copy(std::begin(texture->levels), std::end(texture->levels),
              std::begin(input.levels));
    std::memcpy(input.obj_source_sha256, LTD_NOSELINE12_OBJ_SOURCE_SHA256, 65);
    std::memcpy(input.texture_manifest_sha256,
                LTD_NOSELINE12_TEXTURE_MANIFEST_SHA256, 65);
    std::memcpy(input.decoded_mips_sha256, LTD_NOSELINE12_DECODED_MIPS_SHA256, 65);
    input.perspective_correct = 1;
    const auto status = ltd_noseline12_draw(&destination, &input, report);
    if (status != LTD_NOSELINE12_OK) {
        write_error(error, error_capacity,
                    std::string("NoseLine12 draw failed: ") + ltd_noseline12_status_name(status));
        return LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_DRAW_FAILED;
    }
    return LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_OK;
}

}  // extern "C"
