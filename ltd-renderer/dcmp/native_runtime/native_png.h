#ifndef INFINIMII_NATIVE_PNG_H
#define INFINIMII_NATIVE_PNG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define INFINIMII_NATIVE_PNG_ABI_VERSION 1u

typedef enum infinimii_native_png_status {
    INFINIMII_NATIVE_PNG_OK = 0,
    INFINIMII_NATIVE_PNG_INVALID_ARGUMENT = 1,
    INFINIMII_NATIVE_PNG_BACKEND_LOAD_FAILED = 2,
    INFINIMII_NATIVE_PNG_BACKEND_IDENTITY_MISMATCH = 3,
    INFINIMII_NATIVE_PNG_COMPRESSION_FAILED = 4,
    INFINIMII_NATIVE_PNG_ALLOCATION_FAILED = 5,
    INFINIMII_NATIVE_PNG_NUMERIC_CONTRACT_FAILED = 6
} infinimii_native_png_status;

typedef struct infinimii_native_png_encoder infinimii_native_png_encoder;

typedef struct infinimii_native_png_bytes {
    uint8_t* data;
    size_t size;
} infinimii_native_png_bytes;

/*
 * Load an explicitly named, absolute-path zlib-ng compatibility DLL.
 * The backend must identify as 1.3.1.zlib-ng and pass the component's
 * accepted-output compression probe. No DLL search-path fallback is used.
 */
infinimii_native_png_status infinimii_native_png_encoder_open(
    const wchar_t* zlib_ng_compat_dll,
    infinimii_native_png_encoder** output,
    char* error,
    size_t error_capacity
);

void infinimii_native_png_encoder_close(infinimii_native_png_encoder* encoder);

/*
 * Encode top-left-origin packed RGB8/RGBA8 through the exact Pillow 12.2.0
 * optimize=True profile used by renderer/render_mii.py. Rows may have a
 * larger caller-owned stride. The returned allocation is released with
 * infinimii_native_png_bytes_free.
 */
infinimii_native_png_status infinimii_native_png_encode_rgb8(
    infinimii_native_png_encoder* encoder,
    const uint8_t* pixels,
    uint32_t width,
    uint32_t height,
    size_t stride,
    infinimii_native_png_bytes* output,
    char* error,
    size_t error_capacity
);

infinimii_native_png_status infinimii_native_png_encode_rgba8(
    infinimii_native_png_encoder* encoder,
    const uint8_t* pixels,
    uint32_t width,
    uint32_t height,
    size_t stride,
    infinimii_native_png_bytes* output,
    char* error,
    size_t error_capacity
);

void infinimii_native_png_bytes_free(infinimii_native_png_bytes* bytes);

/*
 * Exact accepted-output transfer boundaries corresponding to
 * OrthographicRasterizer.image(): IEC-sRGB encode followed by round-to-nearest
 * even RGBA8/RGB8 storage. Inputs and outputs are top-left-origin row-major.
 */
infinimii_native_png_status infinimii_native_png_transfer_linear_rgb64_to_rgb8(
    const double* linear_rgb,
    uint32_t width,
    uint32_t height,
    size_t input_stride,
    uint8_t* rgb8,
    size_t output_stride,
    char* error,
    size_t error_capacity
);

infinimii_native_png_status
infinimii_native_png_transfer_premultiplied_linear_rgba64_to_rgba8(
    const double* premultiplied_linear_rgba,
    uint32_t width,
    uint32_t height,
    size_t input_stride,
    uint8_t* rgba8,
    size_t output_stride,
    char* error,
    size_t error_capacity
);

uint32_t infinimii_native_png_abi_version(void);

infinimii_native_png_status infinimii_native_png_backend_identity(
    const infinimii_native_png_encoder* encoder,
    char* version,
    size_t version_capacity,
    uint32_t* probe_stream_size,
    uint32_t* probe_stream_crc32
);

#ifdef __cplusplus
}
#endif

#endif
