#pragma once

#include <cstddef>
#include <cstdint>

#if defined(_WIN32)
#define LTD_NATIVE_POST_API extern "C" __declspec(dllexport)
#else
#define LTD_NATIVE_POST_API extern "C"
#endif

enum LtdNativePostStatus : int {
    LTD_NATIVE_POST_OK = 0,
    LTD_NATIVE_POST_INVALID_ARGUMENT = 1,
};

LTD_NATIVE_POST_API std::uint32_t ltd_native_postprocess_abi_version();

// Exact accepted portable SnapshotPfx gamma0 core with an explicit optional
// zero-or-authenticated bloom input. All arrays are pixel_count * 3 float64.
LTD_NATIVE_POST_API int ltd_native_snapshot_pfx_gamma0(
    const double* scene_linear_rgb,
    const double* bloom_linear_rgb,
    std::size_t pixel_count,
    double* output_linear_rgb);

