#ifndef LTD_NATIVE_FACE_RUNTIME_H
#define LTD_NATIVE_FACE_RUNTIME_H

/*
 * CPython-free exact-current face-target kernels.
 *
 * The API never allocates. Every image is row-major RGBA and every destination
 * buffer is owned by the caller. The caller must keep input and output buffers
 * disjoint for the duration of a call. All functions require the process
 * floating-point environment to use round-to-nearest-even.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LTD_FACE_RUNTIME_BUILD_DLL)
#define LTD_FACE_RUNTIME_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_FACE_RUNTIME_USE_DLL)
#define LTD_FACE_RUNTIME_API __declspec(dllimport)
#else
#define LTD_FACE_RUNTIME_API
#endif

#if defined(_WIN32)
#define LTD_FACE_RUNTIME_CALL __cdecl
#else
#define LTD_FACE_RUNTIME_CALL
#endif

#define LTD_FACE_RUNTIME_ABI_VERSION UINT32_C(1)
#define LTD_FACE_RUNTIME_CONTRACT_SHA256 \
    "5b856b6ab60fcfc3a37a03d8153c1a11217bc23ed39803e0a350bb02fd163c3c"
#define LTD_FACE_RUNTIME_ORACLE_SOURCE_SHA256 \
    "d14b5e39d37e9ebcb315924b863c6ca65d3be075fc7edc067d1fecd49181a62a"
#define LTD_FACE_RUNTIME_CONTRACT_CANONICAL \
    "ltd.native.face.runtime|abi=1|rgba=RGBA,row-major,top-left|" \
    "scalar=IEEE754-binary64|round=FE_TONEAREST|" \
    "ops=mask_pipeline,mask_sample_affine,mask_sample_shade_affine," \
    "faceline_wrinkle,faceline_johnny|oracle=" \
    LTD_FACE_RUNTIME_ORACLE_SOURCE_SHA256

#define LTD_FACE_RUNTIME_MAX_DIMENSION UINT32_C(4096)
#define LTD_FACE_RUNTIME_MAX_MASK_LAYERS UINT32_C(21)
#define LTD_FACE_RUNTIME_FACELINE_WIDTH UINT32_C(128)
#define LTD_FACE_RUNTIME_FACELINE_HEIGHT UINT32_C(256)

typedef enum ltd_face_runtime_status {
    LTD_FACE_RUNTIME_OK = 0,
    LTD_FACE_RUNTIME_INVALID_ARGUMENT = 1,
    LTD_FACE_RUNTIME_BUFFER_TOO_SMALL = 2,
    LTD_FACE_RUNTIME_NONFINITE = 3,
    LTD_FACE_RUNTIME_VALUE_OUT_OF_RANGE = 4,
    LTD_FACE_RUNTIME_ROUNDING_MODE = 5,
    LTD_FACE_RUNTIME_ABI_MISMATCH = 6,
    LTD_FACE_RUNTIME_CONTRACT_MISMATCH = 7,
    LTD_FACE_RUNTIME_BUFFER_ALIAS = 8
} ltd_face_runtime_status;

typedef enum ltd_face_mask_shader_kind {
    LTD_FACE_MASK_SHADER_CONSTANT_RGB_SAMPLED_R_ALPHA = 1,
    LTD_FACE_MASK_SHADER_MOUTH_MODE_2 = 2,
    LTD_FACE_MASK_SHADER_EYE_MODE_2 = 3,
    LTD_FACE_MASK_SHADER_EYE_MODE_7 = 4,
    LTD_FACE_MASK_SHADER_MODE_8 = 5
} ltd_face_mask_shader_kind;

typedef struct ltd_face_const_rgba8_image {
    const uint8_t *pixels;
    size_t buffer_size_bytes;
    size_t row_stride_bytes;
    uint32_t width;
    uint32_t height;
} ltd_face_const_rgba8_image;

typedef struct ltd_face_rgba8_image {
    uint8_t *pixels;
    size_t buffer_size_bytes;
    size_t row_stride_bytes;
    uint32_t width;
    uint32_t height;
} ltd_face_rgba8_image;

typedef struct ltd_face_const_rgba64_image {
    const double *pixels;
    size_t buffer_size_bytes;
    size_t row_stride_bytes;
    uint32_t width;
    uint32_t height;
} ltd_face_const_rgba64_image;

typedef struct ltd_face_rgba64_image {
    double *pixels;
    size_t buffer_size_bytes;
    size_t row_stride_bytes;
    uint32_t width;
    uint32_t height;
} ltd_face_rgba64_image;

typedef struct ltd_face_rgba8_stack {
    uint8_t *pixels;
    size_t buffer_size_bytes;
    size_t layer_stride_bytes;
    size_t row_stride_bytes;
} ltd_face_rgba8_stack;

typedef struct ltd_face_mask_layer {
    int32_t dispatcher_case;
    uint32_t reserved;
    ltd_face_const_rgba64_image image;
} ltd_face_mask_layer;

typedef struct ltd_face_faceline_raster_report {
    int32_t row_min_inclusive;
    int32_t row_max_inclusive;
    int32_t column_min_inclusive;
    int32_t column_max_inclusive;
    uint32_t covered_pixel_count;
} ltd_face_faceline_raster_report;

LTD_FACE_RUNTIME_API uint32_t LTD_FACE_RUNTIME_CALL
ltd_face_runtime_abi_version(void);

LTD_FACE_RUNTIME_API const char *LTD_FACE_RUNTIME_CALL
ltd_face_runtime_contract_sha256(void);

LTD_FACE_RUNTIME_API const char *LTD_FACE_RUNTIME_CALL
ltd_face_runtime_oracle_source_sha256(void);

LTD_FACE_RUNTIME_API const char *LTD_FACE_RUNTIME_CALL
ltd_face_runtime_status_name(ltd_face_runtime_status status);

/* Call once at integration startup and reject any non-OK result. */
LTD_FACE_RUNTIME_API ltd_face_runtime_status LTD_FACE_RUNTIME_CALL
ltd_face_runtime_require(
    uint32_t expected_abi_version,
    const char *expected_contract_sha256
);

/*
 * Execute the exact two-pass MiiMask blend/store target. All six destinations
 * are required. Audit stacks contain layer_count tightly ordered images but
 * may use caller-selected row/layer strides. For layer_count == 0, stack
 * pointers may be NULL and their sizes/strides may be zero.
 */
LTD_FACE_RUNTIME_API ltd_face_runtime_status LTD_FACE_RUNTIME_CALL
ltd_face_mask_pipeline(
    const ltd_face_mask_layer *layers,
    uint32_t layer_count,
    uint32_t width,
    uint32_t height,
    ltd_face_rgba8_image *pass0,
    ltd_face_rgba8_image *case21,
    ltd_face_rgba8_image *final_target,
    ltd_face_rgba8_image *mesh_input,
    ltd_face_rgba8_stack *pass0_audit,
    ltd_face_rgba8_stack *pass1_audit
);

/* affine is Pillow's inverse transform in a0..a5 expression order. */
LTD_FACE_RUNTIME_API ltd_face_runtime_status LTD_FACE_RUNTIME_CALL
ltd_face_mask_sample_affine(
    const ltd_face_const_rgba8_image *source,
    const double affine[6],
    int32_t mirrored,
    int32_t float_planes,
    ltd_face_rgba64_image *output
);

LTD_FACE_RUNTIME_API ltd_face_runtime_status LTD_FACE_RUNTIME_CALL
ltd_face_mask_sample_shade_affine(
    const ltd_face_const_rgba8_image *source,
    const double affine[6],
    int32_t mirrored,
    int32_t shader_kind,
    const double c1_rgb[3],
    const double c2_rgb[3],
    ltd_face_rgba64_image *output
);

/* Output must be exactly 128x256 RGBA8. */
LTD_FACE_RUNTIME_API ltd_face_runtime_status LTD_FACE_RUNTIME_CALL
ltd_face_faceline_wrinkle(
    const ltd_face_const_rgba8_image *source,
    const uint8_t skin_rgba8[4],
    double left,
    double right,
    double bottom,
    double top,
    ltd_face_rgba8_image *output,
    ltd_face_faceline_raster_report *report
);

/* Source must be exactly 256x512 and output exactly 128x256 RGBA8. */
LTD_FACE_RUNTIME_API ltd_face_runtime_status LTD_FACE_RUNTIME_CALL
ltd_face_faceline_johnny(
    const ltd_face_const_rgba8_image *source,
    const uint8_t skin_rgba8[4],
    const double c1_rgba[4],
    const double c2_rgba[4],
    ltd_face_rgba8_image *output
);

#ifdef __cplusplus
}
#endif

#endif
