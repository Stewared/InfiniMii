#ifndef LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_H
#define LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_H

/*
 * Source-sealed bridge from immutable scene/material records to the exact
 * pointer-bearing native_draw_runtime ABI 1/2 command structures.
 *
 * The builder copies every packed field into type-aligned owned storage.  A
 * returned command view and all pointers reachable from it remain valid until
 * ltd_native_draw_descriptor_destroy() is called.
 */

#include <stddef.h>
#include <stdint.h>

#include "native_draw_runtime.h"
#include "native_draw_runtime_v2.h"
#include "native_material_schedule.h"
#include "native_scene_assembler.h"


#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_BUILD_DLL)
#define LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_USE_DLL)
#define LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_API __declspec(dllimport)
#else
#define LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_API
#endif

#if defined(_WIN32)
#define LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL __cdecl
#else
#define LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
#endif

#define LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_ABI_VERSION UINT32_C(1)
#define LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_MAX_FIELDS UINT32_C(32)
#define LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CONTRACT_CANONICAL \
    "ltd.native.draw-descriptor-builder|abi=1|schedule=1|draw=1,2|" \
    "ownership=copied-packed-fields|profiles=body324,body336,body348," \
    "ear372,nose756,mask0,head816,hair612,hair564,beard468,outfit984," \
    "outfit936,outfit912|source-sealed=1"
#define LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CONTRACT_SHA256 \
    "1b0cf40fa382949f7600610f9c0e1a55c6af33d654cf55cd503ec3fd15e71b07"

typedef struct ltd_native_draw_descriptor ltd_native_draw_descriptor;

typedef enum ltd_native_draw_descriptor_status {
    LTD_NATIVE_DRAW_DESCRIPTOR_OK = 0,
    LTD_NATIVE_DRAW_DESCRIPTOR_INVALID_ARGUMENT = 1,
    LTD_NATIVE_DRAW_DESCRIPTOR_SOURCE_MISMATCH = 2,
    LTD_NATIVE_DRAW_DESCRIPTOR_SCHEDULE_MISMATCH = 3,
    LTD_NATIVE_DRAW_DESCRIPTOR_SCENE_MISMATCH = 4,
    LTD_NATIVE_DRAW_DESCRIPTOR_MODEL_MISMATCH = 5,
    LTD_NATIVE_DRAW_DESCRIPTOR_PACKED_FIELD_MISMATCH = 6,
    LTD_NATIVE_DRAW_DESCRIPTOR_TEXTURE_MISMATCH = 7,
    LTD_NATIVE_DRAW_DESCRIPTOR_UNSUPPORTED_PROFILE = 8,
    LTD_NATIVE_DRAW_DESCRIPTOR_NONFINITE = 9,
    LTD_NATIVE_DRAW_DESCRIPTOR_ALLOCATION_FAILED = 10
} ltd_native_draw_descriptor_status;

/* Exact identities supplied by the host that loaded the participating ABIs. */
typedef struct ltd_native_draw_descriptor_source_seals {
    const char *material_schedule_contract_sha256;
    const char *draw_runtime_v1_contract_sha256;
    const char *draw_runtime_v2_contract_sha256;
    const char *current_source_sha256;
    const char *opaque_source_sha256;
    const char *wrapper_source_sha256;
} ltd_native_draw_descriptor_source_seals;

/*
 * One scheduled draw.  `material` is the same immutable source record used by
 * native_material_schedule; `scheduled` is its authenticated compiler output.
 * `scene` supplies candidate geometry, UV streams, and projection results.
 * `model` supplies source-triangle provenance for normal-validity validation.
 */
typedef struct ltd_native_draw_descriptor_request {
    const ltd_native_draw_descriptor_source_seals *seals;
    const ltd_native_source_draw *material;
    const ltd_native_compiled_draw *scheduled;
    const ltd_native_scene_draw_view *scene;
    const ltd_native_scene_model_view *model;
} ltd_native_draw_descriptor_request;


/* Exactly one typed pointer is non-NULL and agrees with kernel/profile/ABI. */
typedef struct ltd_native_draw_command_view {
    uint16_t kernel;
    uint16_t profile;
    uint8_t draw_abi_version;
    uint8_t reserved[3];
    uint32_t submitted_triangle_count;
    uint32_t candidate_triangle_count;
    const ltd_draw_plain_skin_input *plain_skin;
    const ltd_draw_body_input *body;
    const ltd_draw_mask0_input *mask0;
    const ltd_draw_head816_input *head816;
    const ltd_draw_hair_input *hair;
    const ltd_draw_outfit_input *outfit;
    uint8_t texture_plan_sha256[32];
    uint8_t packed_abi_input_sha256[32];
} ltd_native_draw_command_view;

LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_API uint32_t
LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_builder_abi_version(void);

LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_API const char *
LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_builder_contract_sha256(void);

LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_API const char *
LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_status_name(ltd_native_draw_descriptor_status status);

LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_API ltd_native_draw_descriptor_status
LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_builder_require(
    uint32_t expected_abi,
    const char *expected_contract_sha256
);

LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_API ltd_native_draw_descriptor_status
LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_build(
    const ltd_native_draw_descriptor_request *request,
    ltd_native_draw_descriptor **output,
    char *error,
    size_t error_capacity
);


LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_API ltd_native_draw_descriptor_status
LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_get_command(
    const ltd_native_draw_descriptor *descriptor,
    ltd_native_draw_command_view *output
);

LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_API void
LTD_NATIVE_DRAW_DESCRIPTOR_BUILDER_CALL
ltd_native_draw_descriptor_destroy(ltd_native_draw_descriptor *descriptor);

#ifdef __cplusplus
}
#endif

#endif
