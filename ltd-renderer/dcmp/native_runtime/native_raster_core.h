#pragma once

#include <cstddef>
#include <cstdint>

#if defined(_WIN32)
#define LTD_NATIVE_RASTER_API extern "C" __declspec(dllexport)
#else
#define LTD_NATIVE_RASTER_API extern "C"
#endif

enum LtdNativeRasterWrap : std::uint32_t {
    LTD_NATIVE_WRAP_CLAMP = 0,
    LTD_NATIVE_WRAP_REPEAT = 1,
    LTD_NATIVE_WRAP_MIRROR = 2,
};

struct LtdNativeRasterFragment final {
    std::int32_t x;
    std::int32_t y;
    double weight0;
    double weight1;
    double weight2;
    double z;
};

enum LtdNativeRasterStatus : int {
    LTD_NATIVE_RASTER_OK = 0,
    LTD_NATIVE_RASTER_INVALID_ARGUMENT = 1,
    LTD_NATIVE_RASTER_OUTPUT_TOO_SMALL = 2,
};

LTD_NATIVE_RASTER_API std::uint32_t ltd_native_raster_abi_version();

LTD_NATIVE_RASTER_API int ltd_native_raster_coverage(
    const double screen[9],
    const double* depth,
    std::size_t depth_width,
    std::size_t depth_height,
    std::int32_t x0,
    std::int32_t x1,
    std::int32_t y0,
    std::int32_t y1,
    double denominator,
    LtdNativeRasterFragment* output,
    std::size_t output_capacity,
    std::size_t* output_count);

LTD_NATIVE_RASTER_API int ltd_native_raster_sample_bilinear_rgba64(
    const double* source,
    std::size_t width,
    std::size_t height,
    const double* u,
    const double* v,
    std::size_t sample_count,
    std::uint32_t wrap_x,
    std::uint32_t wrap_y,
    double* output_rgba);

