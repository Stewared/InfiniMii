#ifndef LTD_NATIVE_DRAW_RUNTIME_H
#define LTD_NATIVE_DRAW_RUNTIME_H

/* CPython-free exact-current whole-draw buffer kernels. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LTD_DRAW_RUNTIME_BUILD_DLL)
#define LTD_DRAW_RUNTIME_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_DRAW_RUNTIME_USE_DLL)
#define LTD_DRAW_RUNTIME_API __declspec(dllimport)
#else
#define LTD_DRAW_RUNTIME_API
#endif

#if defined(_WIN32)
#define LTD_DRAW_RUNTIME_CALL __cdecl
#else
#define LTD_DRAW_RUNTIME_CALL
#endif

#define LTD_DRAW_RUNTIME_ABI_VERSION UINT32_C(1)
#define LTD_DRAW_RUNTIME_CONTRACT_SHA256 \
    "64db57c14e2ccf01eff2f24fa158caf7ef7635877f75645a3fa109c792cce283"
#define LTD_DRAW_RUNTIME_CURRENT_SOURCE_SHA256 \
    "14ae1dc7cacbe16cf73cbf473d5220bf50340cbe9e0560f00bbe65f3f1123d7d"
#define LTD_DRAW_RUNTIME_OPAQUE_SOURCE_SHA256 \
    "f03b17eac2eb4c16293ae9ddbc40710fb9f3507ad880060e131959b54daadf0c"
#define LTD_DRAW_RUNTIME_MAX_DIMENSION UINT32_C(4096)

typedef enum ltd_draw_runtime_status {
    LTD_DRAW_RUNTIME_OK = 0,
    LTD_DRAW_RUNTIME_INVALID_ARGUMENT = 1,
    LTD_DRAW_RUNTIME_BUFFER_TOO_SMALL = 2,
    LTD_DRAW_RUNTIME_NONFINITE = 3,
    LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE = 4,
    LTD_DRAW_RUNTIME_ROUNDING_MODE = 5,
    LTD_DRAW_RUNTIME_ABI_MISMATCH = 6,
    LTD_DRAW_RUNTIME_CONTRACT_MISMATCH = 7,
    LTD_DRAW_RUNTIME_BUFFER_ALIAS = 8
} ltd_draw_runtime_status;

typedef struct ltd_draw_const_f64_buffer {
    const double *data;
    size_t element_count;
} ltd_draw_const_f64_buffer;

typedef struct ltd_draw_const_i64_buffer {
    const int64_t *data;
    size_t element_count;
} ltd_draw_const_i64_buffer;

/* Color is RGB64; depth and optional alpha are scalar binary64. */
typedef struct ltd_draw_attachments {
    double *color;
    size_t color_capacity_bytes;
    size_t color_row_stride_bytes;
    double *depth;
    size_t depth_capacity_bytes;
    size_t depth_row_stride_bytes;
    double *alpha;
    size_t alpha_capacity_bytes;
    size_t alpha_row_stride_bytes;
    uint32_t width;
    uint32_t height;
} ltd_draw_attachments;

/* Arrays are tightly packed: screen count*9, bounds count*4, denominators count. */
typedef struct ltd_draw_triangle_batch {
    ltd_draw_const_f64_buffer screen;
    ltd_draw_const_i64_buffer bounds;
    ltd_draw_const_f64_buffer denominators;
    uint32_t triangle_count;
} ltd_draw_triangle_batch;

/* Texels contain texel_count RGBA64 values; levels contain level_count rows of offset,height,width. */
typedef struct ltd_draw_mip_bank {
    const double *texels;
    size_t texel_count;
    const int64_t *levels;
    uint32_t level_count;
} ltd_draw_mip_bank;

typedef struct ltd_draw_texture2d {
    const double *texels;
    size_t texel_count;
    uint32_t width;
    uint32_t height;
} ltd_draw_texture2d;

typedef struct ltd_draw_plain_skin_input {
    ltd_draw_triangle_batch triangles;
    ltd_draw_const_f64_buffer vertex_normals; /* triangle_count * 9 */
    double base_color_linear[3];
    double light_direction[3];
    double light_color[3];
    double ambient_color[3];
    double light_intensity;
    double ambient_intensity;
    int32_t perspective_correct;
    uint32_t reserved;
} ltd_draw_plain_skin_input;

typedef struct ltd_draw_body_input {
    ltd_draw_triangle_batch triangles;
    ltd_draw_const_f64_buffer world_vertices; /* triangle_count * 9 */
    ltd_draw_const_f64_buffer vertex_normals; /* triangle_count * 9 */
    ltd_draw_const_f64_buffer material_uv;    /* triangle_count * 6 */
    ltd_draw_mip_bank albedo;
    ltd_draw_const_i64_buffer albedo_lower_indices;
    ltd_draw_const_i64_buffer albedo_upper_indices;
    ltd_draw_const_f64_buffer albedo_mip_amounts;
    ltd_draw_mip_bank skin;
    ltd_draw_const_i64_buffer skin_lower_indices;
    ltd_draw_const_i64_buffer skin_upper_indices;
    ltd_draw_const_f64_buffer skin_mip_amounts;
    ltd_draw_mip_bank normal;
    ltd_draw_const_i64_buffer normal_level_indices;
    double face_color_linear[3];
    double light_direction[3];
    double light_color[3];
    double ambient_color[3];
    double light_intensity;
    double ambient_intensity;
    int32_t perspective_correct;
    uint32_t reserved;
} ltd_draw_body_input;

typedef struct ltd_draw_mask0_input {
    ltd_draw_triangle_batch triangles;
    ltd_draw_const_f64_buffer vertex_normals; /* triangle_count * 9 */
    ltd_draw_const_f64_buffer material_uv;    /* triangle_count * 6 */
    ltd_draw_texture2d generated_texture;
    ltd_draw_texture2d user_texture;
    double light_direction[3];
    double light_color[3];
    double ambient_color[3];
    /* light intensity, ambient intensity, perspective, mode, then affine a0..a5 */
    double parameters[10];
} ltd_draw_mask0_input;

LTD_DRAW_RUNTIME_API uint32_t LTD_DRAW_RUNTIME_CALL
ltd_draw_runtime_abi_version(void);

LTD_DRAW_RUNTIME_API const char *LTD_DRAW_RUNTIME_CALL
ltd_draw_runtime_contract_sha256(void);

LTD_DRAW_RUNTIME_API const char *LTD_DRAW_RUNTIME_CALL
ltd_draw_runtime_current_source_sha256(void);

LTD_DRAW_RUNTIME_API const char *LTD_DRAW_RUNTIME_CALL
ltd_draw_runtime_opaque_source_sha256(void);

LTD_DRAW_RUNTIME_API const char *LTD_DRAW_RUNTIME_CALL
ltd_draw_runtime_status_name(ltd_draw_runtime_status status);

LTD_DRAW_RUNTIME_API ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL
ltd_draw_runtime_require(uint32_t expected_abi, const char *expected_contract_sha256);

/* Exact shared Ear372/Nose756 texture-free response. */
LTD_DRAW_RUNTIME_API ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL
ltd_draw_plain_skin(
    ltd_draw_attachments *attachments,
    const ltd_draw_plain_skin_input *input,
    uint64_t *written_fragments
);

/* Exact shared Body324/336/348 response. */
LTD_DRAW_RUNTIME_API ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL
ltd_draw_body(
    ltd_draw_attachments *attachments,
    const ltd_draw_body_input *input,
    uint64_t *written_fragments
);

/* Exact generated-only and UGC Mask0 response. */
LTD_DRAW_RUNTIME_API ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL
ltd_draw_mask0(
    ltd_draw_attachments *attachments,
    const ltd_draw_mask0_input *input,
    uint64_t *written_fragments
);

#ifdef __cplusplus
}
#endif

#endif
