#pragma once

#include <cstddef>
#include <cstdint>

#if defined(_WIN32)
#define LTD_NATIVE_SCENE_API extern "C" __declspec(dllexport)
#else
#define LTD_NATIVE_SCENE_API extern "C"
#endif

// This ABI contains only plain fixed-size values so the standalone renderer
// can consume it without Python, NumPy, a C++ runtime object graph, or JSON.
struct LtdNativeSceneCamera final {
    double camera_distance;
    double vertical_fov_degrees;
    double horizontal_projection_scale;
    double camera_at_y;
    double camera_position_y;
    double bounds[4];
    double body_scale[3];
    double head_transform[16];
};

struct LtdNativeDrawRecord final {
    const char* group;
    std::uint8_t blend;
    std::uint8_t depth_write;
};

enum LtdNativeSceneStatus : int {
    LTD_NATIVE_SCENE_OK = 0,
    LTD_NATIVE_SCENE_INVALID_ARGUMENT = 1,
    LTD_NATIVE_SCENE_MISSING_HEAD_ANCHOR = 2,
    LTD_NATIVE_SCENE_INVALID_DRAW_STATE = 3,
    LTD_NATIVE_SCENE_OUTPUT_TOO_SMALL = 4,
};

LTD_NATIVE_SCENE_API std::uint32_t ltd_native_scene_abi_version();

LTD_NATIVE_SCENE_API int ltd_native_mii_body_scale(
    int build,
    int height,
    int model_provider_index,
    float out_scale[3]);

LTD_NATIVE_SCENE_API int ltd_native_attached_part_transform(
    const double head_world[16],
    const float body_scale[3],
    double out_transform[16]);

LTD_NATIVE_SCENE_API int ltd_native_resolve_bust_camera(
    int build,
    int height,
    const double head_world[16],
    LtdNativeSceneCamera* out_camera);

LTD_NATIVE_SCENE_API int ltd_native_resolve_full_body_camera(
    int build,
    int height,
    const double head_world[16],
    LtdNativeSceneCamera* out_camera);

LTD_NATIVE_SCENE_API int ltd_native_schedule_draws(
    const LtdNativeDrawRecord* draws,
    std::size_t draw_count,
    std::size_t* out_indices,
    std::size_t out_capacity);

