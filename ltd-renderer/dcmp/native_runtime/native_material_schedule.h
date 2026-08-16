#ifndef INFINIMII_NATIVE_MATERIAL_SCHEDULE_H_
#define INFINIMII_NATIVE_MATERIAL_SCHEDULE_H_

/*
 * Standalone accepted-material compiler for the current renderer.
 *
 * Inputs are normalized records obtainable from native Parts selection and a
 * DecodedAssetCache-backed model/material inventory.  Outputs are immutable
 * dispatch records for native_draw_runtime ABI 1/2.  The API owns no input
 * storage and performs no allocation, filesystem access, or Python calls.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LTD_NATIVE_MATERIAL_SCHEDULE_BUILD_DLL)
#define LTD_NATIVE_MATERIAL_SCHEDULE_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_NATIVE_MATERIAL_SCHEDULE_USE_DLL)
#define LTD_NATIVE_MATERIAL_SCHEDULE_API __declspec(dllimport)
#else
#define LTD_NATIVE_MATERIAL_SCHEDULE_API
#endif

#if defined(_WIN32)
#define LTD_NATIVE_MATERIAL_SCHEDULE_CALL __cdecl
#else
#define LTD_NATIVE_MATERIAL_SCHEDULE_CALL
#endif

#define LTD_NATIVE_MATERIAL_SCHEDULE_ABI_VERSION UINT32_C(1)
#define LTD_NATIVE_MATERIAL_SCHEDULE_MAX_DRAWS UINT32_C(64)
#define LTD_NATIVE_MATERIAL_SCHEDULE_MAX_TEXTURES UINT32_C(8)
#define LTD_NATIVE_MATERIAL_SCHEDULE_MAX_MIPS UINT32_C(16)
#define LTD_NATIVE_MATERIAL_SCHEDULE_CONTRACT_SHA256 \
    "ae8bac4873568bb7c3d3ac02e9808afa8d2f69290585b9ecae2ebae8c9323a88"
#define LTD_NATIVE_MATERIAL_SCHEDULE_COMPOSE_SHA256 \
    "2cb56971a3ba7ce7d527ed415d8d9d2a201782a107ed277766a9608c4f9533d4"
#define LTD_NATIVE_MATERIAL_SCHEDULE_WRAPPER_SHA256 \
    "405365df31ca29e5938acb63ec59a53b30c7130c4fbc6e1d97d83bfc910ae7d4"
#define LTD_NATIVE_MATERIAL_SCHEDULE_CURRENT_KERNEL_SHA256 \
    "14ae1dc7cacbe16cf73cbf473d5220bf50340cbe9e0560f00bbe65f3f1123d7d"
#define LTD_NATIVE_MATERIAL_SCHEDULE_OPAQUE_KERNEL_SHA256 \
    "f03b17eac2eb4c16293ae9ddbc40710fb9f3507ad880060e131959b54daadf0c"

typedef enum ltd_native_material_status {
    LTD_NATIVE_MATERIAL_OK = 0,
    LTD_NATIVE_MATERIAL_INVALID_ARGUMENT = 1,
    LTD_NATIVE_MATERIAL_SOURCE_MISMATCH = 2,
    LTD_NATIVE_MATERIAL_UNSUPPORTED_PROFILE = 3,
    LTD_NATIVE_MATERIAL_FINGERPRINT_MISMATCH = 4,
    LTD_NATIVE_MATERIAL_OUTPUT_TOO_SMALL = 5,
    LTD_NATIVE_MATERIAL_NO_HEAD_ANCHOR = 6,
    LTD_NATIVE_MATERIAL_SCHEDULE_MISMATCH = 7,
    LTD_NATIVE_MATERIAL_NONFINITE = 8,
    LTD_NATIVE_MATERIAL_DUPLICATE_BINDING = 9
} ltd_native_material_status;

typedef enum ltd_native_material_family {
    LTD_NATIVE_FAMILY_UNSUPPORTED = 0,
    LTD_NATIVE_FAMILY_BODY = 1,
    LTD_NATIVE_FAMILY_OUTFIT_TOPS = 2,
    LTD_NATIVE_FAMILY_OUTFIT_BOTTOMS = 3,
    LTD_NATIVE_FAMILY_OUTFIT_SHOES = 4,
    LTD_NATIVE_FAMILY_MASK = 5,
    LTD_NATIVE_FAMILY_HEAD = 6,
    LTD_NATIVE_FAMILY_EAR = 7,
    LTD_NATIVE_FAMILY_HAIR_ANISOTROPIC = 8,
    LTD_NATIVE_FAMILY_HAIR_ENDPOINT = 9,
    LTD_NATIVE_FAMILY_NOSE = 10,
    LTD_NATIVE_FAMILY_BEARD_ANISOTROPIC = 11,
    LTD_NATIVE_FAMILY_NOSE_LINE = 12
} ltd_native_material_family;

typedef enum ltd_native_draw_kernel {
    LTD_NATIVE_DRAW_NONE = 0,
    LTD_NATIVE_DRAW_BODY_ABI1 = 1,
    LTD_NATIVE_DRAW_PLAIN_SKIN_ABI1 = 2,
    LTD_NATIVE_DRAW_MASK0_ABI1 = 3,
    LTD_NATIVE_DRAW_HEAD816_ABI2 = 4,
    LTD_NATIVE_DRAW_HAIR_ABI2 = 5,
    LTD_NATIVE_DRAW_OUTFIT_ABI2 = 6
} ltd_native_draw_kernel;

typedef enum ltd_native_texture_role {
    LTD_NATIVE_TEXTURE_ALBEDO = 1,
    LTD_NATIVE_TEXTURE_NORMAL = 2,
    LTD_NATIVE_TEXTURE_SKIN_MASK = 3,
    LTD_NATIVE_TEXTURE_MATERIAL_INFORMATION = 4,
    LTD_NATIVE_TEXTURE_PARALLAX = 5,
    LTD_NATIVE_TEXTURE_SPECULAR = 6,
    LTD_NATIVE_TEXTURE_GRADIENT = 7,
    LTD_NATIVE_TEXTURE_MASK_GENERATED = 8,
    LTD_NATIVE_TEXTURE_MASK_USER0 = 9
} ltd_native_texture_role;

typedef enum ltd_native_texture_address {
    LTD_NATIVE_ADDRESS_CLAMP = 0,
    LTD_NATIVE_ADDRESS_REPEAT = 1,
    LTD_NATIVE_ADDRESS_MIRROR = 2
} ltd_native_texture_address;

typedef enum ltd_native_mip_filter {
    LTD_NATIVE_MIP_POINT = 0,
    LTD_NATIVE_MIP_LINEAR = 1
} ltd_native_mip_filter;

typedef enum ltd_native_material_flags {
    LTD_NATIVE_MATERIAL_LINEAR_FRAMEBUFFER = UINT32_C(1) << 0,
    LTD_NATIVE_MATERIAL_PERSPECTIVE = UINT32_C(1) << 1,
    LTD_NATIVE_MATERIAL_DEPTH_WRITE = UINT32_C(1) << 2,
    LTD_NATIVE_MATERIAL_BLEND = UINT32_C(1) << 3,
    LTD_NATIVE_MATERIAL_CULL_BACK = UINT32_C(1) << 4,
    LTD_NATIVE_MATERIAL_CLOCKWISE = UINT32_C(1) << 5,
    LTD_NATIVE_MATERIAL_LINEAR_LIGHTING = UINT32_C(1) << 6,
    LTD_NATIVE_MATERIAL_GAMMA_LIGHTING = UINT32_C(1) << 7,
    LTD_NATIVE_MATERIAL_CHEAP_SSS = UINT32_C(1) << 8,
    LTD_NATIVE_MATERIAL_ANISOTROPIC = UINT32_C(1) << 9,
    LTD_NATIVE_MATERIAL_FRONT_EDGE = UINT32_C(1) << 10,
    LTD_NATIVE_MATERIAL_RECEIVES_FACE_SHADOW = UINT32_C(1) << 11,
    LTD_NATIVE_MATERIAL_CASTS_FACE_SHADOW = UINT32_C(1) << 12,
    LTD_NATIVE_MATERIAL_HAS_UV = UINT32_C(1) << 13,
    LTD_NATIVE_MATERIAL_HAS_NORMAL = UINT32_C(1) << 14,
    LTD_NATIVE_MATERIAL_HAS_U2 = UINT32_C(1) << 15,
    LTD_NATIVE_MATERIAL_MASK_USER0 = UINT32_C(1) << 16
} ltd_native_material_flags;

typedef struct ltd_native_material_source_seals {
    uint8_t compose_sha256[32];
    uint8_t wrapper_sha256[32];
    uint8_t current_kernel_sha256[32];
    uint8_t opaque_kernel_sha256[32];
} ltd_native_material_source_seals;

typedef struct ltd_native_mip_extent {
    uint32_t height;
    uint32_t width;
} ltd_native_mip_extent;

/* DecodedAssetCache-compatible binding metadata; pixels remain cache-owned. */
typedef struct ltd_native_source_texture {
    uint16_t role;
    uint8_t address_u;
    uint8_t address_v;
    uint8_t mip_filter;
    uint8_t hardware_srgb;
    uint16_t reserved;
    const char *source_key;
    const ltd_native_mip_extent *levels;
    uint32_t level_count;
    uint8_t decoded_chain_sha256[32];
} ltd_native_source_texture;

/* One canonical packed ABI field, before pointer-bearing C descriptor layout. */
typedef struct ltd_native_packed_field {
    uint16_t tag;
    uint16_t element_width;
    uint32_t reserved;
    const uint8_t *bytes;
    size_t byte_count;
} ltd_native_packed_field;

/* One authored model/material draw from Parts + decoded model inventories. */
typedef struct ltd_native_source_draw {
    const char *model_key;
    const char *resource_name;
    const char *group;
    uint32_t authored_index;
    uint32_t submitted_triangle_count;
    uint32_t candidate_triangle_count;
    int32_t gameall_program;
    uint16_t family;
    int16_t gsys_priority;
    uint32_t material_flags;
    double transform[16];
    double dynamic_values[16];
    const ltd_native_source_texture *textures;
    uint32_t texture_count;
    const ltd_native_packed_field *packed_fields;
    uint32_t packed_field_count;
} ltd_native_source_draw;

/* Output views refer to source-owned strings; all scalar/digest data is copied. */
typedef struct ltd_native_compiled_draw {
    const char *model_key;
    const char *resource_name;
    const char *group;
    uint32_t authored_index;
    uint32_t scheduled_index;
    uint32_t submitted_triangle_count;
    uint32_t candidate_triangle_count;
    uint16_t kernel;
    uint16_t profile;
    uint8_t draw_abi_version;
    uint8_t reserved[3];
    uint32_t material_flags;
    double transform[16];
    double dynamic_values[16];
    uint8_t texture_plan_sha256[32];
    uint8_t packed_abi_input_sha256[32];
} ltd_native_compiled_draw;

LTD_NATIVE_MATERIAL_SCHEDULE_API uint32_t LTD_NATIVE_MATERIAL_SCHEDULE_CALL
ltd_native_material_schedule_abi_version(void);

LTD_NATIVE_MATERIAL_SCHEDULE_API const char *LTD_NATIVE_MATERIAL_SCHEDULE_CALL
ltd_native_material_schedule_contract_sha256(void);

LTD_NATIVE_MATERIAL_SCHEDULE_API ltd_native_material_status LTD_NATIVE_MATERIAL_SCHEDULE_CALL
ltd_native_compile_material_schedule(
    const ltd_native_material_source_seals *seals,
    const ltd_native_source_draw *source_draws,
    size_t source_draw_count,
    ltd_native_compiled_draw *output,
    size_t output_capacity,
    size_t *output_count
);

LTD_NATIVE_MATERIAL_SCHEDULE_API const char *LTD_NATIVE_MATERIAL_SCHEDULE_CALL
ltd_native_material_status_name(ltd_native_material_status status);

#ifdef __cplusplus
}
#endif

#endif
