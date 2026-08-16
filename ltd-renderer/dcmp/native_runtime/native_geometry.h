#pragma once

#include <cstddef>
#include <cstdint>

#if defined(_WIN32)
#define LTD_NATIVE_GEOMETRY_API extern "C" __declspec(dllexport)
#else
#define LTD_NATIVE_GEOMETRY_API extern "C"
#endif

enum LtdNativeProjectionKind : std::uint32_t {
    LTD_NATIVE_ORTHOGRAPHIC = 0,
    LTD_NATIVE_PERSPECTIVE = 1,
};

struct LtdNativeProjection final {
    std::uint32_t kind;
    std::size_t width;
    std::size_t height;
    double world_bounds[4];  // ortho: x_min,x_max,y_min,y_max
    double camera_position[3];
    double camera_target[3];
    double camera_up[3];
    double vertical_fov_degrees;
    double horizontal_projection_scale;
};

struct LtdNativeTriangleSetup final {
    double screen[9];
    std::int32_t x0;
    std::int32_t x1;
    std::int32_t y0;
    std::int32_t y1;
    double denominator;
    std::uint8_t candidate;
};

enum LtdNativeGeometryStatus : int {
    LTD_NATIVE_GEOMETRY_OK = 0,
    LTD_NATIVE_GEOMETRY_INVALID_ARGUMENT = 1,
    LTD_NATIVE_GEOMETRY_SINGULAR_TRANSFORM = 2,
    LTD_NATIVE_GEOMETRY_INVALID_CAMERA = 3,
    LTD_NATIVE_GEOMETRY_INVALID_INDEX = 4,
};

LTD_NATIVE_GEOMETRY_API std::uint32_t ltd_native_geometry_abi_version();

LTD_NATIVE_GEOMETRY_API int ltd_native_transform_and_project(
    const double* positions,
    const double* normals,
    std::size_t vertex_count,
    const double transform[16],
    const LtdNativeProjection* projection,
    double* out_world_positions,
    double* out_world_normals,
    double* out_projected);

LTD_NATIVE_GEOMETRY_API int ltd_native_setup_triangles(
    const double* projected,
    std::size_t vertex_count,
    const std::int32_t* triangle_indices,
    std::size_t triangle_count,
    std::size_t width,
    std::size_t height,
    std::uint8_t cull_back_faces,
    std::uint8_t clockwise_front_face,
    LtdNativeTriangleSetup* out_triangles);

