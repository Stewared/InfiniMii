#ifndef LTD_NATIVE_MATERIAL_FIELD_PACKER_H
#define LTD_NATIVE_MATERIAL_FIELD_PACKER_H

/*
 * Standalone producer for native_material_schedule source records and their
 * exact native_draw_runtime ABI1/2 packed fields.  No Python-shaped opaque
 * payload is accepted: geometry, decoded texture levels, normalized material
 * constants, effective CharInfo, and face/facepaint outputs are typed views.
 */

#include <stddef.h>
#include <stdint.h>

#include "native_face_runtime.h"
#include "native_facepaint_decode.h"
#include "native_material_schedule.h"
#include "native_scene_assembler.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LTD_NATIVE_MATERIAL_FIELD_PACKER_BUILD_DLL)
#define LTD_NATIVE_MATERIAL_FIELD_PACKER_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_NATIVE_MATERIAL_FIELD_PACKER_USE_DLL)
#define LTD_NATIVE_MATERIAL_FIELD_PACKER_API __declspec(dllimport)
#else
#define LTD_NATIVE_MATERIAL_FIELD_PACKER_API
#endif

#if defined(_WIN32)
#define LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL __cdecl
#else
#define LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
#endif

#define LTD_NATIVE_MATERIAL_FIELD_PACKER_ABI_VERSION UINT32_C(1)
#define LTD_NATIVE_MATERIAL_FIELD_PACKER_CONTRACT_CANONICAL \
    "ltd.native.material-field-packer|abi=1|scene=assembler1|charinfo=152|" \
    "textures=rgba64-mips|face=rgba64|facepaint=rgba64|profiles=body324," \
    "body336,body348,ear372,nose756,mask0,head816,hair612,hair564," \
    "beard468,outfit984,outfit936,outfit912|source-sealed=1"
#define LTD_NATIVE_MATERIAL_FIELD_PACKER_CONTRACT_SHA256 \
    "38fa7d4f96d8beb2c5d29bc0d1139008e72ce1f4338c4505c4461f163697be4d"
#define LTD_NATIVE_MATERIAL_FIELD_PACKER_CHARINFO_SIZE UINT32_C(152)
#define LTD_NATIVE_MATERIAL_FIELD_PACKER_MAX_TEXTURES UINT32_C(8)

typedef struct ltd_native_material_field_pack ltd_native_material_field_pack;

typedef enum ltd_native_material_field_status {
    LTD_NATIVE_MATERIAL_FIELD_OK = 0,
    LTD_NATIVE_MATERIAL_FIELD_INVALID_ARGUMENT = 1,
    LTD_NATIVE_MATERIAL_FIELD_SOURCE_MISMATCH = 2,
    LTD_NATIVE_MATERIAL_FIELD_SCENE_MISMATCH = 3,
    LTD_NATIVE_MATERIAL_FIELD_MATERIAL_MISMATCH = 4,
    LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISSING = 5,
    LTD_NATIVE_MATERIAL_FIELD_TEXTURE_MISMATCH = 6,
    LTD_NATIVE_MATERIAL_FIELD_PROFILE_UNSUPPORTED = 7,
    LTD_NATIVE_MATERIAL_FIELD_NONFINITE = 8,
    LTD_NATIVE_MATERIAL_FIELD_ALLOCATION_FAILED = 9,
    LTD_NATIVE_MATERIAL_FIELD_PROVIDER_FAILED = 10
} ltd_native_material_field_status;

typedef enum ltd_native_material_texture_color_space {
    LTD_NATIVE_MATERIAL_TEXTURE_LINEAR = 1,
    LTD_NATIVE_MATERIAL_TEXTURE_SRGB = 2
} ltd_native_material_texture_color_space;

/* One caller/cache-owned decoded mip. Row stride may exceed width * 4 values. */
typedef struct ltd_native_material_texture_level_view {
    const uint8_t *rgba8;
    size_t rgba8_byte_count;
    const double *rgba64;
    size_t rgba64_element_count;
    const double *sampled_rgba64;
    size_t sampled_rgba64_element_count;
    uint32_t width;
    uint32_t height;
    const char *source_sha256;
    const char *rgba8_sha256;
    const char *rgba64_sha256;
    const char *sampled_rgba64_sha256;
} ltd_native_material_texture_level_view;

/* Immutable DecodedAssetCache-compatible chain returned by a provider. */
typedef struct ltd_native_material_texture_chain_view {
    const char *source_key;
    const char *authored_source_sha256;
    const char *manifest_sha256;
    const char *decoded_chain_sha256;
    const char *rgba8_chain_sha256;
    const char *rgba64_chain_sha256;
    const char *sampled_rgba64_chain_sha256;
    uint32_t color_space;
    const ltd_native_material_texture_level_view *levels;
    uint32_t level_count;
} ltd_native_material_texture_chain_view;

typedef int (LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL *
ltd_native_material_get_texture_chain_fn)(
    void *context,
    const char *source_key,
    const char *authored_source_sha256,
    const char *manifest_sha256,
    ltd_native_material_texture_chain_view *output,
    char *error,
    size_t error_capacity
);

typedef struct ltd_native_material_texture_provider {
    void *context;
    ltd_native_material_get_texture_chain_fn get_texture_chain;
} ltd_native_material_texture_provider;

/*
 * Normalized renderer/material metadata. Every scalar is explicit; the packer
 * never supplies an unstated portable default. `texture_keys[role]` and seals
 * identify provider records using ltd_native_texture_role values (1..9).
 */
typedef struct ltd_native_normalized_material_view {
    const char *model_key;
    const char *resource_name;
    const char *group;
    int32_t gameall_program;
    uint16_t family;
    int16_t gsys_priority;
    uint32_t material_flags;
    double color_srgb[4];
    double alpha_multiplier;
    double alpha_cutoff;
    double roughness;
    double anisotropic_shift_scale;
    double anisotropic_shift_offset;
    double anisotropic_specular_size;
    double anisotropic_toon_intensity;
    double anisotropic_title_view_scale;
    double anisotropic_radiance_scale;
    double parallax_scale;
    double body_face_color_linear[3];
    double hair_primary_srgb[3];
    double hair_secondary_srgb[3];
    double light_direction[3];
    double light_color[3];
    double ambient_color[3];
    double camera_position[3];
    double light_intensity;
    double ambient_intensity;
    double light_normalization;
    double flip_horizontal_sign;
    uint8_t has_camera_position;
    uint8_t perspective_correct;
    uint8_t mask_facepaint_mode;
    uint8_t reserved0;
    const char *texture_keys[10];
    const char *texture_source_sha256[10];
    const char *texture_manifest_sha256[10];
    uint8_t texture_address_u[10];
    uint8_t texture_address_v[10];
    uint8_t texture_mip_filter[10];
    uint8_t texture_hardware_srgb[10];
} ltd_native_normalized_material_view;

/* Face products are optional by profile but, when flagged, must be exact. */
typedef struct ltd_native_material_face_views {
    const char *generated_head_albedo_source_key;
    const char *generated_mask_source_key;
    const char *user_facepaint_source_key;
    ltd_face_const_rgba64_image generated_head_albedo;
    ltd_face_const_rgba64_image generated_mask;
    ltd_face_const_rgba64_image user_facepaint;
    ltd_native_facepaint_tex_srt user_facepaint_srt;
    uint8_t has_generated_head_albedo;
    uint8_t has_generated_mask;
    uint8_t has_user_facepaint;
    uint8_t reserved;
} ltd_native_material_face_views;

typedef struct ltd_native_material_field_source_seals {
    const char *scene_assembler_contract_sha256;
    const char *material_schedule_contract_sha256;
    const char *draw_runtime_v1_contract_sha256;
    const char *draw_runtime_v2_contract_sha256;
    const char *material_provider_contract_sha256;
    const char *current_source_sha256;
    const char *opaque_source_sha256;
    const char *wrapper_source_sha256;
} ltd_native_material_field_source_seals;

typedef struct ltd_native_material_field_pack_request {
    const ltd_native_material_field_source_seals *seals;
    const uint8_t *effective_char_info; /* exactly 152 authenticated bytes */
    size_t effective_char_info_byte_count;
    const ltd_native_scene_draw_view *scene;
    const ltd_native_scene_model_view *model;
    const ltd_native_normalized_material_view *material;
    const ltd_native_material_texture_provider *textures;
    const ltd_native_material_face_views *face;
    uint32_t authored_index;
} ltd_native_material_field_pack_request;

LTD_NATIVE_MATERIAL_FIELD_PACKER_API uint32_t
LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
ltd_native_material_field_packer_abi_version(void);

LTD_NATIVE_MATERIAL_FIELD_PACKER_API const char *
LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
ltd_native_material_field_packer_contract_sha256(void);

LTD_NATIVE_MATERIAL_FIELD_PACKER_API const char *
LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
ltd_native_material_field_status_name(ltd_native_material_field_status status);

LTD_NATIVE_MATERIAL_FIELD_PACKER_API ltd_native_material_field_status
LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
ltd_native_material_field_pack_build(
    const ltd_native_material_field_pack_request *request,
    ltd_native_material_field_pack **output,
    char *error,
    size_t error_capacity
);

/* All recursively referenced storage is pack-owned until destroy. */
LTD_NATIVE_MATERIAL_FIELD_PACKER_API ltd_native_material_field_status
LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
ltd_native_material_field_pack_get_source_draw(
    const ltd_native_material_field_pack *pack,
    ltd_native_source_draw *output
);

LTD_NATIVE_MATERIAL_FIELD_PACKER_API void
LTD_NATIVE_MATERIAL_FIELD_PACKER_CALL
ltd_native_material_field_pack_destroy(ltd_native_material_field_pack *pack);

#ifdef __cplusplus
}
#endif

#endif
