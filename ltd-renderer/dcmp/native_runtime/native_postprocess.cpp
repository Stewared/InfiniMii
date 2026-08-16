#include "native_postprocess.h"

#include <algorithm>
#include <cmath>

std::uint32_t ltd_native_postprocess_abi_version() { return 1; }

int ltd_native_snapshot_pfx_gamma0(
    const double* scene,
    const double* bloom,
    std::size_t pixel_count,
    double* output) {
    if (scene == nullptr || output == nullptr) return LTD_NATIVE_POST_INVALID_ARGUMENT;
    constexpr double weights[3]{
        0.2989000082015991,
        0.5866000056266785,
        0.1143999993801117,
    };
    for (std::size_t pixel = 0; pixel < pixel_count; ++pixel) {
        double combined[3]{};
        for (int channel = 0; channel < 3; ++channel) {
            const double scene_value = scene[pixel * 3 + channel];
            const double bloom_value = bloom == nullptr ? 0.0 : bloom[pixel * 3 + channel];
            if (!std::isfinite(scene_value) || !std::isfinite(bloom_value) ||
                scene_value < 0.0 || bloom_value < 0.0) {
                return LTD_NATIVE_POST_INVALID_ARGUMENT;
            }
            combined[channel] = scene_value + bloom_value;
        }
        const double luminance =
            combined[0] * weights[0] + combined[1] * weights[1] +
            combined[2] * weights[2];
        const double exposure = -std::expm1(-luminance);
        const double ratio = luminance == 0.0 ? 1.0 : exposure / luminance;
        const double shoulder = exposure * exposure;
        for (int channel = 0; channel < 3; ++channel) {
            const double base = combined[channel] * ratio;
            const double target = -std::expm1(-combined[channel]);
            output[pixel * 3 + channel] =
                std::clamp(base + (target - base) * shoulder, 0.0, 1.0);
        }
    }
    return LTD_NATIVE_POST_OK;
}

