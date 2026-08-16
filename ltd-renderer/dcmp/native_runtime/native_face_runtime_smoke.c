#include "native_face_runtime.h"

#include <stdint.h>
#include <string.h>

/* Static-link smoke proof: no CPython, NumPy, asset loader, or renderer host. */
int main(void) {
    static const uint8_t source_pixels[4] = {255, 64, 0, 255};
    static const double affine[6] = {1.0, 0.0, 0.0, 0.0, 1.0, 0.0};
    double output_pixels[4] = {-1.0, -1.0, -1.0, -1.0};
    ltd_face_const_rgba8_image source = {
        source_pixels, sizeof(source_pixels), 4, 1, 1
    };
    ltd_face_rgba64_image output = {
        output_pixels, sizeof(output_pixels), sizeof(output_pixels), 1, 1
    };
    if (ltd_face_runtime_abi_version() != LTD_FACE_RUNTIME_ABI_VERSION) return 10;
    if (strcmp(
        ltd_face_runtime_contract_sha256(), LTD_FACE_RUNTIME_CONTRACT_SHA256
    ) != 0) return 11;
    if (ltd_face_runtime_require(
        LTD_FACE_RUNTIME_ABI_VERSION, LTD_FACE_RUNTIME_CONTRACT_SHA256
    ) != LTD_FACE_RUNTIME_OK) return 12;
    if (ltd_face_runtime_require(
        LTD_FACE_RUNTIME_ABI_VERSION + 1, LTD_FACE_RUNTIME_CONTRACT_SHA256
    ) != LTD_FACE_RUNTIME_ABI_MISMATCH) return 13;
    if (ltd_face_mask_sample_affine(
        &source, affine, 0, 0, &output
    ) != LTD_FACE_RUNTIME_OK) return 14;
    if (
        output_pixels[0] != 1.0 ||
        output_pixels[1] != 64.0 / 255.0 ||
        output_pixels[2] != 0.0 ||
        output_pixels[3] != 1.0
    ) return 15;
    return 0;
}
