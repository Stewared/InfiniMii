#include "native_raster_core.h"

#include <cmath>

namespace {

constexpr std::uint32_t kAbiVersion = 1;

std::ptrdiff_t wrapped(std::ptrdiff_t index, std::ptrdiff_t size, std::uint32_t mode) {
    if (mode == LTD_NATIVE_WRAP_CLAMP) {
        if (index < 0) return 0;
        return index >= size ? size - 1 : index;
    }
    if (mode == LTD_NATIVE_WRAP_REPEAT) {
        const std::ptrdiff_t value = index % size;
        return value < 0 ? value + size : value;
    }
    const std::ptrdiff_t period = size * 2;
    std::ptrdiff_t value = index % period;
    if (value < 0) value += period;
    return value < size ? value : period - 1 - value;
}

bool visible(
    const double screen[9],
    const double* depth,
    std::size_t depth_width,
    std::int32_t x,
    std::int32_t y,
    double denominator,
    LtdNativeRasterFragment* output) {
    const double sample_x = static_cast<double>(x) + 0.5;
    const double sample_y = static_cast<double>(y) + 0.5;
    const double edge0_left = (sample_x - screen[3]) * (screen[7] - screen[4]);
    const double edge0_right = (sample_y - screen[4]) * (screen[6] - screen[3]);
    const double weight0 = (edge0_left - edge0_right) / denominator;
    const double edge1_left = (sample_x - screen[6]) * (screen[1] - screen[7]);
    const double edge1_right = (sample_y - screen[7]) * (screen[0] - screen[6]);
    const double weight1 = (edge1_left - edge1_right) / denominator;
    const double weight2 = (1.0 - weight0) - weight1;
    if (weight0 < -1e-7 || weight1 < -1e-7 || weight2 < -1e-7) return false;
    const double z01 = weight0 * screen[2] + weight1 * screen[5];
    const double z = z01 + weight2 * screen[8];
    if (z < depth[static_cast<std::size_t>(y) * depth_width + static_cast<std::size_t>(x)]) {
        return false;
    }
    if (output != nullptr) {
        *output = LtdNativeRasterFragment{x, y, weight0, weight1, weight2, z};
    }
    return true;
}

}  // namespace

std::uint32_t ltd_native_raster_abi_version() { return kAbiVersion; }

int ltd_native_raster_coverage(
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
    std::size_t* output_count) {
    if (screen == nullptr || depth == nullptr || output_count == nullptr || depth_width == 0 ||
        depth_height == 0 || x0 < 0 || y0 < 0 || x1 < x0 || y1 < y0 ||
        static_cast<std::size_t>(x1) >= depth_width ||
        static_cast<std::size_t>(y1) >= depth_height || !std::isfinite(denominator) ||
        denominator == 0.0) {
        return LTD_NATIVE_RASTER_INVALID_ARGUMENT;
    }
    std::size_t required = 0;
    for (std::int32_t y = y0; y <= y1; ++y) {
        for (std::int32_t x = x0; x <= x1; ++x) {
            required += visible(screen, depth, depth_width, x, y, denominator, nullptr);
        }
    }
    *output_count = required;
    if (required > output_capacity || (required != 0 && output == nullptr)) {
        return LTD_NATIVE_RASTER_OUTPUT_TOO_SMALL;
    }
    std::size_t index = 0;
    for (std::int32_t y = y0; y <= y1; ++y) {
        for (std::int32_t x = x0; x <= x1; ++x) {
            if (visible(screen, depth, depth_width, x, y, denominator, output + index)) {
                ++index;
            }
        }
    }
    return LTD_NATIVE_RASTER_OK;
}

int ltd_native_raster_sample_bilinear_rgba64(
    const double* source,
    std::size_t width,
    std::size_t height,
    const double* u,
    const double* v,
    std::size_t sample_count,
    std::uint32_t wrap_x,
    std::uint32_t wrap_y,
    double* output_rgba) {
    if (source == nullptr || width == 0 || height == 0 || u == nullptr || v == nullptr ||
        output_rgba == nullptr || wrap_x > LTD_NATIVE_WRAP_MIRROR ||
        wrap_y > LTD_NATIVE_WRAP_MIRROR) {
        return LTD_NATIVE_RASTER_INVALID_ARGUMENT;
    }
    for (std::size_t sample = 0; sample < sample_count; ++sample) {
        if (!std::isfinite(u[sample]) || !std::isfinite(v[sample])) {
            return LTD_NATIVE_RASTER_INVALID_ARGUMENT;
        }
        const double tex_x = u[sample] * static_cast<double>(width) - 0.5;
        const double tex_y = (1.0 - v[sample]) * static_cast<double>(height) - 0.5;
        const double floor_x = std::floor(tex_x);
        const double floor_y = std::floor(tex_y);
        const auto x0 = wrapped(static_cast<std::ptrdiff_t>(floor_x),
                                static_cast<std::ptrdiff_t>(width), wrap_x);
        const auto x1 = wrapped(static_cast<std::ptrdiff_t>(floor_x) + 1,
                                static_cast<std::ptrdiff_t>(width), wrap_x);
        const auto y0 = wrapped(static_cast<std::ptrdiff_t>(floor_y),
                                static_cast<std::ptrdiff_t>(height), wrap_y);
        const auto y1 = wrapped(static_cast<std::ptrdiff_t>(floor_y) + 1,
                                static_cast<std::ptrdiff_t>(height), wrap_y);
        const double x_amount = tex_x - floor_x;
        const double y_amount = tex_y - floor_y;
        const double inverse_x = 1.0 - x_amount;
        const double inverse_y = 1.0 - y_amount;
        for (int channel = 0; channel < 4; ++channel) {
            const double top =
                source[(static_cast<std::size_t>(y0) * width + static_cast<std::size_t>(x0)) * 4 + channel] * inverse_x +
                source[(static_cast<std::size_t>(y0) * width + static_cast<std::size_t>(x1)) * 4 + channel] * x_amount;
            const double bottom =
                source[(static_cast<std::size_t>(y1) * width + static_cast<std::size_t>(x0)) * 4 + channel] * inverse_x +
                source[(static_cast<std::size_t>(y1) * width + static_cast<std::size_t>(x1)) * 4 + channel] * x_amount;
            output_rgba[sample * 4 + channel] = top * inverse_y + bottom * y_amount;
        }
    }
    return LTD_NATIVE_RASTER_OK;
}

