#include "native_scene_math.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <vector>

namespace {

constexpr std::uint32_t kAbiVersion = 1;
constexpr char kHeadGroup[] = "Head__mt_Head";
constexpr char kLensGroup[] = "Trs__mt_LensTrs";
constexpr char kMaskGroup[] = "Mask__mt_Mask";
constexpr char kNoseLineGroup[] = "NoseLine__mt_NoseLine";

bool finite_matrix(const double* values) {
    if (values == nullptr) return false;
    for (std::size_t index = 0; index < 16; ++index) {
        if (!std::isfinite(values[index])) return false;
    }
    return true;
}

void identity(double out[16]) {
    std::fill(out, out + 16, 0.0);
    out[0] = 1.0;
    out[5] = 1.0;
    out[10] = 1.0;
    out[15] = 1.0;
}

int priority_for(const char* group) {
    if (group != nullptr &&
        (std::strcmp(group, kMaskGroup) == 0 ||
         std::strcmp(group, kNoseLineGroup) == 0)) {
        return -10;
    }
    return 0;
}

int resolve_common(
    int build,
    int height,
    const double head_world[16],
    LtdNativeSceneCamera* out_camera) {
    if (out_camera == nullptr || !finite_matrix(head_world)) {
        return LTD_NATIVE_SCENE_INVALID_ARGUMENT;
    }
    float scale[3]{};
    const int scale_status = ltd_native_mii_body_scale(build, height, -1, scale);
    if (scale_status != LTD_NATIVE_SCENE_OK) return scale_status;
    const int transform_status =
        ltd_native_attached_part_transform(head_world, scale, out_camera->head_transform);
    if (transform_status != LTD_NATIVE_SCENE_OK) return transform_status;
    for (int index = 0; index < 3; ++index) {
        out_camera->body_scale[index] = static_cast<double>(scale[index]);
    }
    return LTD_NATIVE_SCENE_OK;
}

}  // namespace

std::uint32_t ltd_native_scene_abi_version() { return kAbiVersion; }

int ltd_native_mii_body_scale(
    int build,
    int height,
    int model_provider_index,
    float out_scale[3]) {
    if (out_scale == nullptr || build < 0 || build > 127 || height < 0 || height > 127) {
        return LTD_NATIVE_SCENE_INVALID_ARGUMENT;
    }
    int selected_build = build;
    int selected_height = height;
    if (model_provider_index != -1) {
        selected_build = std::min(selected_build, 85);
        selected_height = std::min(selected_height, 103);
    }

    // Every assignment deliberately materializes the source float operation.
    // /fp:strict plus these sequence points reproduces the recovered C float
    // expression rather than contracting or evaluating it as a double tree.
    const float build_f32 = static_cast<float>(selected_build);
    const float height_f32 = static_cast<float>(selected_height);
    float x = build_f32 * 0.006015625f;
    x = x + 0.5f;
    x = x * 0.79114896f;

    float yz = build_f32 * 0.003671875f;
    yz = yz + 0.4f;
    yz = yz * height_f32;
    yz = yz * 0.0078125f;
    float build_term = build_f32 * 0.0017968749f;
    yz = yz + build_term;
    yz = yz + 0.4f;
    yz = yz * 0.7908809f;

    out_scale[0] = x;
    out_scale[1] = yz;
    out_scale[2] = yz;
    return LTD_NATIVE_SCENE_OK;
}

int ltd_native_attached_part_transform(
    const double head_world[16],
    const float body_scale[3],
    double out_transform[16]) {
    if (!finite_matrix(head_world) || body_scale == nullptr || out_transform == nullptr) {
        return LTD_NATIVE_SCENE_INVALID_ARGUMENT;
    }
    for (int index = 0; index < 3; ++index) {
        if (!std::isfinite(body_scale[index]) || body_scale[index] == 0.0f) {
            return LTD_NATIVE_SCENE_INVALID_ARGUMENT;
        }
    }
    identity(out_transform);
    out_transform[3] = static_cast<double>(body_scale[0]) * head_world[3];
    out_transform[7] =
        static_cast<double>(body_scale[1]) * head_world[7] -
        static_cast<double>(body_scale[0]) * 0.09074663;
    out_transform[11] = static_cast<double>(body_scale[2]) * head_world[11];
    return LTD_NATIVE_SCENE_OK;
}

int ltd_native_resolve_bust_camera(
    int build,
    int height,
    const double head_world[16],
    LtdNativeSceneCamera* out_camera) {
    const int status = resolve_common(build, height, head_world, out_camera);
    if (status != LTD_NATIVE_SCENE_OK) return status;

    constexpr double camera_distance = 9.4;
    constexpr double base_vertical_fov = 15.0;
    constexpr double viewport_height = 512.0;
    constexpr double crop_width = 200.0;
    constexpr double crop_height = 208.0;
    constexpr double camera_offset_y = 0.325790523170393;
    constexpr double pi = 3.141592653589793238462643383279502884;

    const double base_radians = base_vertical_fov * pi / 180.0;
    const double vertical_fov =
        2.0 * std::atan(std::tan(base_radians * 0.5) * (crop_height / viewport_height)) *
        180.0 / pi;
    const double horizontal_scale = crop_height / crop_width;
    const double camera_at_y = out_camera->head_transform[7] + camera_offset_y;
    const double half_height =
        camera_distance * std::tan((vertical_fov * pi / 180.0) * 0.5);

    out_camera->camera_distance = camera_distance;
    out_camera->vertical_fov_degrees = vertical_fov;
    out_camera->horizontal_projection_scale = horizontal_scale;
    out_camera->camera_at_y = camera_at_y;
    out_camera->camera_position_y = camera_at_y - 0.01;
    out_camera->bounds[0] = -half_height / horizontal_scale;
    out_camera->bounds[1] = half_height / horizontal_scale;
    out_camera->bounds[2] = camera_at_y - half_height;
    out_camera->bounds[3] = camera_at_y + half_height;
    return LTD_NATIVE_SCENE_OK;
}

int ltd_native_resolve_full_body_camera(
    int build,
    int height,
    const double head_world[16],
    LtdNativeSceneCamera* out_camera) {
    const int status = resolve_common(build, height, head_world, out_camera);
    if (status != LTD_NATIVE_SCENE_OK) return status;

    constexpr double camera_distance = 9.4;
    constexpr double vertical_fov = 15.0;
    constexpr double camera_at_y = 0.97;
    constexpr double pi = 3.141592653589793238462643383279502884;
    const double half_height =
        camera_distance * std::tan((vertical_fov * pi / 180.0) * 0.5);

    out_camera->camera_distance = camera_distance;
    out_camera->vertical_fov_degrees = vertical_fov;
    out_camera->horizontal_projection_scale = 1.0;
    out_camera->camera_at_y = camera_at_y;
    out_camera->camera_position_y = camera_at_y - 0.01;
    out_camera->bounds[0] = -half_height;
    out_camera->bounds[1] = half_height;
    out_camera->bounds[2] = camera_at_y - half_height;
    out_camera->bounds[3] = camera_at_y + half_height;
    return LTD_NATIVE_SCENE_OK;
}

int ltd_native_schedule_draws(
    const LtdNativeDrawRecord* draws,
    std::size_t draw_count,
    std::size_t* out_indices,
    std::size_t out_capacity) {
    if ((draw_count != 0 && draws == nullptr) || out_indices == nullptr) {
        return LTD_NATIVE_SCENE_INVALID_ARGUMENT;
    }
    if (out_capacity < draw_count) return LTD_NATIVE_SCENE_OUTPUT_TOO_SMALL;

    std::size_t head_index = draw_count;
    for (std::size_t index = 0; index < draw_count; ++index) {
        if (draws[index].group == nullptr) return LTD_NATIVE_SCENE_INVALID_ARGUMENT;
        if (std::strcmp(draws[index].group, kHeadGroup) == 0) {
            head_index = index;
            break;
        }
    }
    if (head_index == draw_count) return LTD_NATIVE_SCENE_MISSING_HEAD_ANCHOR;

    std::vector<std::size_t> opaque;
    std::vector<std::size_t> translucent;
    opaque.reserve(draw_count - head_index);
    translucent.reserve(1);
    for (std::size_t index = head_index; index < draw_count; ++index) {
        const auto& draw = draws[index];
        if (std::strcmp(draw.group, kLensGroup) == 0) {
            if (draw.blend == 0 || draw.depth_write != 0) {
                return LTD_NATIVE_SCENE_INVALID_DRAW_STATE;
            }
            translucent.push_back(index);
        } else {
            if (draw.blend != 0 || draw.depth_write == 0) {
                return LTD_NATIVE_SCENE_INVALID_DRAW_STATE;
            }
            opaque.push_back(index);
        }
    }
    std::stable_sort(opaque.begin(), opaque.end(), [&](std::size_t left, std::size_t right) {
        return priority_for(draws[left].group) < priority_for(draws[right].group);
    });

    std::size_t output = 0;
    for (std::size_t index = 0; index < head_index; ++index) out_indices[output++] = index;
    for (const std::size_t index : opaque) out_indices[output++] = index;
    for (const std::size_t index : translucent) out_indices[output++] = index;
    return LTD_NATIVE_SCENE_OK;
}

