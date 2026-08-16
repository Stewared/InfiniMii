#pragma once

#include <cstddef>
#include <cstdint>

#if defined(_WIN32)
#define LTD_NATIVE_POSE_API extern "C" __declspec(dllexport)
#else
#define LTD_NATIVE_POSE_API extern "C"
#endif

struct LtdNativeBoneInput final {
    std::int32_t parent_index;
    double scale[3];
    double rotation[3];
    double translation[3];
};

struct LtdNativeShapeSkinInput final {
    std::size_t vertex_offset;
    std::size_t vertex_count;
    std::size_t skin_count;
    const std::int32_t* palette_indices;  // vertex_count * skin_count
    const double* weights;               // null only for skin_count == 1
};

enum LtdNativePoseStatus : int {
    LTD_NATIVE_POSE_OK = 0,
    LTD_NATIVE_POSE_INVALID_ARGUMENT = 1,
    LTD_NATIVE_POSE_INVALID_HIERARCHY = 2,
    LTD_NATIVE_POSE_INVALID_PALETTE = 3,
    LTD_NATIVE_POSE_INVALID_SKIN = 4,
};

LTD_NATIVE_POSE_API std::uint32_t ltd_native_pose_abi_version();

LTD_NATIVE_POSE_API int ltd_native_evaluate_world_matrices(
    const LtdNativeBoneInput* bones,
    std::size_t bone_count,
    double* out_world_matrices);  // bone_count * 16

LTD_NATIVE_POSE_API int ltd_native_skin_mesh(
    const double* source_positions,  // vertex_count * 3
    const double* source_normals,    // vertex_count * 3
    std::size_t vertex_count,
    const LtdNativeShapeSkinInput* shapes,
    std::size_t shape_count,
    const std::int32_t* matrix_to_bone,
    std::size_t palette_count,
    const double* inverse_bind_matrices,  // smooth_count * 16
    std::size_t smooth_count,
    const double* posed_world_matrices,   // bone_count * 16
    std::size_t bone_count,
    double* out_positions,  // vertex_count * 3
    double* out_normals);   // vertex_count * 3

