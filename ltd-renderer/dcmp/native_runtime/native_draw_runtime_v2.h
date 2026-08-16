#ifndef LTD_NATIVE_DRAW_RUNTIME_V2_H
#define LTD_NATIVE_DRAW_RUNTIME_V2_H

#include "native_draw_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LTD_DRAW_RUNTIME_V2_BUILD_DLL)
#define LTD_DRAW_RUNTIME_V2_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_DRAW_RUNTIME_V2_USE_DLL)
#define LTD_DRAW_RUNTIME_V2_API __declspec(dllimport)
#else
#define LTD_DRAW_RUNTIME_V2_API
#endif

#define LTD_DRAW_RUNTIME_V2_ABI_VERSION UINT32_C(2)
#define LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256 \
    "6f136e1133dbce3396157a53907fa0167743443c798a40d57fa40cff9192e5f2"
#define LTD_DRAW_RUNTIME_V2_WRAPPER_SHA256 \
    "405365df31ca29e5938acb63ec59a53b30c7130c4fbc6e1d97d83bfc910ae7d4"
#define LTD_DRAW_RUNTIME_V2_HAIR_PARAMETER_COUNT UINT32_C(33)

typedef struct ltd_draw_const_u8_buffer {
    const uint8_t *data;
    size_t element_count;
} ltd_draw_const_u8_buffer;

typedef enum ltd_draw_hair_profile {
    LTD_DRAW_HAIR612 = 612,
    LTD_DRAW_HAIR564_EQUAL_ENDPOINT = 564,
    LTD_DRAW_BEARD468 = 468
} ltd_draw_hair_profile;

typedef enum ltd_draw_outfit_profile {
    LTD_DRAW_OUTFIT_TOPS984 = 984,
    LTD_DRAW_OUTFIT_BOTTOMS936 = 936,
    LTD_DRAW_OUTFIT_SHOES912 = 912
} ltd_draw_outfit_profile;

typedef struct ltd_draw_head816_input {
    ltd_draw_triangle_batch triangles;
    ltd_draw_const_f64_buffer world_vertices; /* count * 9 */
    ltd_draw_const_f64_buffer vertex_normals; /* count * 9 */
    ltd_draw_const_u8_buffer vertex_normal_valid; /* count */
    ltd_draw_const_f64_buffer albedo_uv; /* count * 6 */
    ltd_draw_const_f64_buffer normal_uv; /* count * 6 */
    ltd_draw_texture2d albedo_texture;
    ltd_draw_mip_bank normal;
    ltd_draw_const_i64_buffer normal_level_indices;
    double base_color_linear[3];
    double light_direction[3];
    double light_color[3];
    double ambient_color[3];
    double light_intensity;
    double ambient_intensity;
    double alpha_scalar;
    double alpha_cutoff;
    int32_t perspective_correct;
    int32_t has_albedo;
} ltd_draw_head816_input;

typedef struct ltd_draw_hair_input {
    ltd_draw_triangle_batch triangles;
    ltd_draw_const_f64_buffer world_vertices; /* count * 9 */
    ltd_draw_const_f64_buffer vertex_normals; /* count * 9 */
    ltd_draw_const_f64_buffer material_uv; /* count * 6 */
    ltd_draw_mip_bank mim;
    ltd_draw_const_i64_buffer mim_level_indices;
    double parameters[LTD_DRAW_RUNTIME_V2_HAIR_PARAMETER_COUNT];
    int32_t profile;
    uint32_t reserved;
} ltd_draw_hair_input;

typedef struct ltd_draw_outfit_input {
    ltd_draw_triangle_batch triangles;
    ltd_draw_const_f64_buffer world_vertices; /* count * 9 */
    ltd_draw_const_f64_buffer vertex_normals; /* count * 9 */
    ltd_draw_const_f64_buffer material_uv; /* count * 6 */
    ltd_draw_mip_bank albedo;
    ltd_draw_const_i64_buffer albedo_lower_indices;
    ltd_draw_const_i64_buffer albedo_upper_indices;
    ltd_draw_const_f64_buffer albedo_mip_amounts;
    ltd_draw_mip_bank normal;
    ltd_draw_const_i64_buffer normal_level_indices;
    double light_direction[3];
    double light_color[3];
    double ambient_color[3];
    double light_intensity;
    double ambient_intensity;
    int32_t perspective_correct;
    int32_t profile;
} ltd_draw_outfit_input;

LTD_DRAW_RUNTIME_V2_API uint32_t LTD_DRAW_RUNTIME_CALL
ltd_draw_runtime_v2_abi_version(void);

LTD_DRAW_RUNTIME_V2_API const char *LTD_DRAW_RUNTIME_CALL
ltd_draw_runtime_v2_contract_sha256(void);

LTD_DRAW_RUNTIME_V2_API const char *LTD_DRAW_RUNTIME_CALL
ltd_draw_runtime_v2_wrapper_sha256(void);

LTD_DRAW_RUNTIME_V2_API ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL
ltd_draw_runtime_v2_require(uint32_t expected_abi, const char *expected_contract_sha256);

LTD_DRAW_RUNTIME_V2_API ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL
ltd_draw_head816(
    ltd_draw_attachments *attachments,
    const ltd_draw_head816_input *input,
    uint64_t *written_fragments
);

/* Shared exact loop; profile is mandatory and fail-closed. */
LTD_DRAW_RUNTIME_V2_API ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL
ltd_draw_hair(
    ltd_draw_attachments *attachments,
    const ltd_draw_hair_input *input,
    uint64_t *written_fragments
);

/* Shared exact loop; profile is mandatory and fail-closed. */
LTD_DRAW_RUNTIME_V2_API ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL
ltd_draw_outfit(
    ltd_draw_attachments *attachments,
    const ltd_draw_outfit_input *input,
    uint64_t *written_fragments
);

#ifdef __cplusplus
}
#endif

#endif
