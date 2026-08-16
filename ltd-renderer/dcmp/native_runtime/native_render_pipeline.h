#ifndef LTD_NATIVE_RENDER_PIPELINE_H
#define LTD_NATIVE_RENDER_PIPELINE_H

/*
 * CPython-free orchestration boundary for the current accepted renderer.
 *
 * This ABI accepts source-authenticated, already compiled draw inputs.  The
 * pipeline owns all destination buffers and executes synchronously; pointers
 * contained in draw commands only need to remain valid for the duration of
 * ltd_native_render_execute_precompiled_draws().  The owning standalone
 * orchestrator now supplies the authenticated scene/material inputs.
 */

#include <stddef.h>
#include <stdint.h>

#include "native_draw_runtime_v2.h"
#include "native_face_runtime.h"
#include "native_png.h"
#include "native_noseline_pipeline_bridge.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LTD_NATIVE_RENDER_PIPELINE_BUILD_DLL)
#define LTD_NATIVE_RENDER_PIPELINE_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_NATIVE_RENDER_PIPELINE_USE_DLL)
#define LTD_NATIVE_RENDER_PIPELINE_API __declspec(dllimport)
#else
#define LTD_NATIVE_RENDER_PIPELINE_API
#endif

#if defined(_WIN32)
#define LTD_NATIVE_RENDER_PIPELINE_CALL __cdecl
#else
#define LTD_NATIVE_RENDER_PIPELINE_CALL
#endif

#define LTD_NATIVE_RENDER_PIPELINE_ABI_VERSION UINT32_C(2)
#define LTD_NATIVE_RENDER_PIPELINE_CONTRACT_CANONICAL \
    "ltd.native.render.pipeline|abi=2|input=authenticated-precompiled-draws|" \
    "scene=1|pose=1|geometry=1|raster=1|draw=2:" \
    LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256 "|face=1:" \
    LTD_FACE_RUNTIME_CONTRACT_SHA256 "|noseline=1:" \
    LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_CONTRACT_SHA256 \
    "|schedule=mixed-single-loop|post=1|png=1|activation_ready=1"
#define LTD_NATIVE_RENDER_PIPELINE_CONTRACT_SHA256 \
    "27b8e25646528722cbf65069e0fab2037ff7b35182d480540c1e0e6419a1650a"

#define LTD_NATIVE_RENDER_PIPELINE_MAX_DIMENSION UINT32_C(4096)
#define LTD_NATIVE_RENDER_PIPELINE_PROFILE_COUNT UINT32_C(29)

typedef struct ltd_native_render_pipeline ltd_native_render_pipeline;

typedef enum ltd_native_render_status {
    LTD_NATIVE_RENDER_OK = 0,
    LTD_NATIVE_RENDER_INVALID_ARGUMENT = 1,
    LTD_NATIVE_RENDER_ABI_MISMATCH = 2,
    LTD_NATIVE_RENDER_CONTRACT_MISMATCH = 3,
    LTD_NATIVE_RENDER_MODULE_MISMATCH = 4,
    LTD_NATIVE_RENDER_SOURCE_SEAL_INVALID = 5,
    LTD_NATIVE_RENDER_RESOURCE_LIMIT = 6,
    LTD_NATIVE_RENDER_ALLOCATION_FAILED = 7,
    LTD_NATIVE_RENDER_INVALID_STATE = 8,
    LTD_NATIVE_RENDER_PROFILE_UNIMPLEMENTED = 9,
    LTD_NATIVE_RENDER_SCENE_SCHEDULE_FAILED = 10,
    LTD_NATIVE_RENDER_DRAW_FAILED = 11,
    LTD_NATIVE_RENDER_FACE_FAILED = 12,
    LTD_NATIVE_RENDER_POSTPROCESS_FAILED = 13,
    LTD_NATIVE_RENDER_PNG_FAILED = 14,
    LTD_NATIVE_RENDER_CANCELLED = 15
} ltd_native_render_status;

typedef enum ltd_native_render_output_mode {
    LTD_NATIVE_RENDER_OUTPUT_RGB = 1,
    LTD_NATIVE_RENDER_OUTPUT_PREMULTIPLIED_RGBA = 2
} ltd_native_render_output_mode;

/* Stable identities, independent of duplicated GameAll numeric programs. */
typedef enum ltd_native_render_profile {
    LTD_NATIVE_RENDER_PROFILE_HEAD816 = 1,
    LTD_NATIVE_RENDER_PROFILE_BODY324 = 2,
    LTD_NATIVE_RENDER_PROFILE_BODY336 = 3,
    LTD_NATIVE_RENDER_PROFILE_BODY348 = 4,
    LTD_NATIVE_RENDER_PROFILE_EAR372 = 5,
    LTD_NATIVE_RENDER_PROFILE_NOSE756 = 6,
    LTD_NATIVE_RENDER_PROFILE_MASK0 = 7,
    LTD_NATIVE_RENDER_PROFILE_HAIR612 = 8,
    LTD_NATIVE_RENDER_PROFILE_HAIR564_EQUAL_ENDPOINT = 9,
    LTD_NATIVE_RENDER_PROFILE_BEARD468 = 10,
    LTD_NATIVE_RENDER_PROFILE_OUTFIT_TOPS984 = 11,
    LTD_NATIVE_RENDER_PROFILE_OUTFIT_BOTTOMS936 = 12,
    LTD_NATIVE_RENDER_PROFILE_OUTFIT_SHOES912 = 13,
    LTD_NATIVE_RENDER_PROFILE_NOSE_LINE12 = 14,
    LTD_NATIVE_RENDER_PROFILE_GLASS_FRAME360 = 15,
    LTD_NATIVE_RENDER_PROFILE_GLASS_LENS60_OPAQUE = 16,
    LTD_NATIVE_RENDER_PROFILE_GLASS_LENS60_TRANSLUCENT = 17,
    LTD_NATIVE_RENDER_PROFILE_DECORATION480 = 18,
    LTD_NATIVE_RENDER_PROFILE_DECORATION492 = 19,
    LTD_NATIVE_RENDER_PROFILE_HAIR396 = 20,
    LTD_NATIVE_RENDER_PROFILE_HAIR408 = 21,
    LTD_NATIVE_RENDER_PROFILE_HAIR420 = 22,
    LTD_NATIVE_RENDER_PROFILE_HAIR432 = 23,
    LTD_NATIVE_RENDER_PROFILE_HAIR672 = 24,
    LTD_NATIVE_RENDER_PROFILE_HAIR708 = 25,
    LTD_NATIVE_RENDER_PROFILE_HAIR1056 = 26,
    LTD_NATIVE_RENDER_PROFILE_HAIR1116 = 27,
    LTD_NATIVE_RENDER_PROFILE_BEARD456 = 28,
    LTD_NATIVE_RENDER_PROFILE_LEGACY_HEADWEAR96 = 29
} ltd_native_render_profile;

typedef struct ltd_native_render_profile_support {
    uint32_t profile;
    const char *name;
    int32_t gameall_program;
    uint8_t kernel_available;
    uint8_t material_compiler_available;
    uint8_t production_draw_ready;
    uint8_t translucent;
} ltd_native_render_profile_support;

typedef int (LTD_NATIVE_RENDER_PIPELINE_CALL *ltd_native_render_cancel_fn)(
    void *context
);

typedef struct ltd_native_render_config {
    uint32_t max_width;
    uint32_t max_height;
    uint64_t max_pixels;
    uint32_t max_draws;
    uint32_t max_face_layers;
    infinimii_native_png_encoder *png_encoder; /* borrowed, never closed */
    ltd_native_render_cancel_fn is_cancelled;
    void *cancel_context;
} ltd_native_render_config;

/* Every seal must point to exactly 64 lower-case hexadecimal characters. */
typedef struct ltd_native_render_source_seals {
    const char *ltd_source_sha256;
    const char *active_parts_sha256;
    const char *asset_index_sha256;
    const char *scene_plan_sha256;
    const char *material_plan_sha256;
} ltd_native_render_source_seals;

typedef struct ltd_native_render_frame_desc {
    uint32_t width;
    uint32_t height;
    uint32_t output_mode;
    uint32_t reserved;
    double background_linear_rgba[4]; /* straight alpha; stored premultiplied */
    ltd_native_render_source_seals seals;
} ltd_native_render_frame_desc;

/*
 * This union is the material-compiler handoff.  The pointed-to descriptor and
 * all recursively referenced buffers are immutable and borrowed for one
 * synchronous execute call.  No input memory is retained by the pipeline.
 */
typedef union ltd_native_render_draw_input {
    const ltd_draw_head816_input *head816;
    const ltd_draw_body_input *body;
    const ltd_draw_plain_skin_input *plain_skin;
    const ltd_draw_mask0_input *mask0;
    const ltd_draw_hair_input *hair;
    const ltd_draw_outfit_input *outfit;
    const struct ltd_native_render_noseline_input *noseline;
    const void *opaque;
} ltd_native_render_draw_input;

typedef struct ltd_native_render_noseline_input {
    const ltd_native_scene_draw_view *scene;
    const ltd_native_noseline_pipeline_texture *texture;
} ltd_native_render_noseline_input;

typedef struct ltd_native_render_draw_command {
    uint32_t profile;
    const char *group;
    uint8_t blend;
    uint8_t depth_write;
    uint16_t reserved;
    ltd_native_render_draw_input input;
} ltd_native_render_draw_command;

typedef struct ltd_native_render_finish_desc {
    uint8_t apply_snapshot_pfx_gamma0;
    uint8_t reserved[7];
    const double *bloom_linear_rgb; /* optional, tightly packed */
    size_t bloom_element_count;     /* zero or width * height * 3 */
} ltd_native_render_finish_desc;

typedef struct ltd_native_render_face_views {
    ltd_face_const_rgba8_image pass0;
    ltd_face_const_rgba8_image case21;
    ltd_face_const_rgba8_image final_target;
    ltd_face_const_rgba8_image mesh_input;
    ltd_face_const_rgba8_image faceline;
    uint32_t mask_layer_count;
    uint8_t mask_prepared;
    uint8_t faceline_prepared;
    uint8_t reserved[2];
} ltd_native_render_face_views;

typedef struct ltd_native_render_output_view {
    const uint8_t *png_bytes;
    size_t png_size;
    const uint8_t *transferred_pixels;
    size_t transferred_size;
    size_t transferred_row_stride;
    uint32_t width;
    uint32_t height;
    uint32_t channels;
    const double *linear_rgb;
    const double *depth;
    const double *alpha;
} ltd_native_render_output_view;

typedef struct ltd_native_render_report {
    uint32_t abi_version;
    uint32_t draw_count;
    uint64_t written_fragments;
    uint64_t pixel_count;
    uint64_t png_size;
    uint8_t face_mask_prepared;
    uint8_t faceline_prepared;
    uint8_t postprocess_applied;
    uint8_t source_seals_validated;
    uint8_t production_activation_ready;
    uint8_t pixels_produced;
    uint8_t png_produced;
    uint8_t reserved;
} ltd_native_render_report;

LTD_NATIVE_RENDER_PIPELINE_API uint32_t LTD_NATIVE_RENDER_PIPELINE_CALL
ltd_native_render_pipeline_abi_version(void);

LTD_NATIVE_RENDER_PIPELINE_API const char *LTD_NATIVE_RENDER_PIPELINE_CALL
ltd_native_render_pipeline_contract_sha256(void);

LTD_NATIVE_RENDER_PIPELINE_API const char *LTD_NATIVE_RENDER_PIPELINE_CALL
ltd_native_render_status_name(ltd_native_render_status status);

LTD_NATIVE_RENDER_PIPELINE_API int LTD_NATIVE_RENDER_PIPELINE_CALL
ltd_native_render_pipeline_activation_ready(void);

LTD_NATIVE_RENDER_PIPELINE_API const ltd_native_render_profile_support *
LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_profile_support_table(
    size_t *profile_count
);

/* Authenticates every linked native module and the explicitly opened PNG backend. */
LTD_NATIVE_RENDER_PIPELINE_API ltd_native_render_status
LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_pipeline_create(
    const ltd_native_render_config *config,
    ltd_native_render_pipeline **output
);

LTD_NATIVE_RENDER_PIPELINE_API void LTD_NATIVE_RENDER_PIPELINE_CALL
ltd_native_render_pipeline_destroy(ltd_native_render_pipeline *pipeline);

/* Replaces any completed or failed frame and invalidates prior output views. */
LTD_NATIVE_RENDER_PIPELINE_API ltd_native_render_status
LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_begin_frame(
    ltd_native_render_pipeline *pipeline,
    const ltd_native_render_frame_desc *frame
);

LTD_NATIVE_RENDER_PIPELINE_API ltd_native_render_status
LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_prepare_face_mask(
    ltd_native_render_pipeline *pipeline,
    const ltd_face_mask_layer *layers,
    uint32_t layer_count,
    uint32_t width,
    uint32_t height
);

LTD_NATIVE_RENDER_PIPELINE_API ltd_native_render_status
LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_prepare_faceline_wrinkle(
    ltd_native_render_pipeline *pipeline,
    const ltd_face_const_rgba8_image *source,
    const uint8_t skin_rgba8[4],
    double left,
    double right,
    double bottom,
    double top,
    ltd_face_faceline_raster_report *report
);

LTD_NATIVE_RENDER_PIPELINE_API ltd_native_render_status
LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_prepare_faceline_johnny(
    ltd_native_render_pipeline *pipeline,
    const ltd_face_const_rgba8_image *source,
    const uint8_t skin_rgba8[4],
    const double c1_rgba[4],
    const double c2_rgba[4]
);

LTD_NATIVE_RENDER_PIPELINE_API ltd_native_render_status
LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_get_face_views(
    const ltd_native_render_pipeline *pipeline,
    ltd_native_render_face_views *output
);

LTD_NATIVE_RENDER_PIPELINE_API ltd_native_render_status
LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_execute_precompiled_draws(
    ltd_native_render_pipeline *pipeline,
    const ltd_native_render_draw_command *draws,
    size_t draw_count
);

/* Diagnostic output only until every support-table row is production ready. */
LTD_NATIVE_RENDER_PIPELINE_API ltd_native_render_status
LTD_NATIVE_RENDER_PIPELINE_CALL ltd_native_render_finish_precompiled_frame(
    ltd_native_render_pipeline *pipeline,
    const ltd_native_render_finish_desc *finish,
    ltd_native_render_output_view *output,
    ltd_native_render_report *report
);

#ifdef __cplusplus
}
#endif

#endif
