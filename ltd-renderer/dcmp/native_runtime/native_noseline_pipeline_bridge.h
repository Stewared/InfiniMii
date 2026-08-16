#ifndef LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_H
#define LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_H

/* Isolated NoseLine12 command/attachment bridge for native_render_pipeline. */

#include "native_noseline12.h"
#include "native_scene_assembler.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_BUILD_DLL)
#define LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_USE_DLL)
#define LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_API __declspec(dllimport)
#else
#define LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_API
#endif

#define LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_ABI_VERSION UINT32_C(1)
#define LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_CONTRACT_CANONICAL \
    "ltd.native.noseline.pipeline.bridge|abi=1|scene-assembler=1|noseline=1:" \
    LTD_NOSELINE12_CONTRACT_SHA256 "|profile=14|group=NoseLine__mt_NoseLine|" \
    "geometry=exact-four-carrier-vertices|uv=sealed-material+u0|" \
    "attachments=borrowed-pipeline|activation_ready=0"
#define LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_CONTRACT_SHA256 \
    "1e5c608b45459991cef4979212929ec24f63e7f3e4d49b81defed4cb5b414ce1"

typedef enum ltd_native_noseline_pipeline_bridge_status {
    LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_OK = 0,
    LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_INVALID_ARGUMENT = 1,
    LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_SOURCE_MISMATCH = 2,
    LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_GEOMETRY_MISMATCH = 3,
    LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_TEXTURE_MISMATCH = 4,
    LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_DRAW_FAILED = 5,
    LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_ALLOCATION_FAILED = 6
} ltd_native_noseline_pipeline_bridge_status;

typedef struct ltd_native_noseline_pipeline_attachments {
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
} ltd_native_noseline_pipeline_attachments;

typedef struct ltd_native_noseline_pipeline_texture {
    const double *mip_rgba;
    size_t mip_rgba_element_count;
    ltd_noseline12_mip_level levels[LTD_NOSELINE12_MIP_LEVEL_COUNT];
    const char *texture_manifest_sha256;
    const char *decoded_mips_sha256;
} ltd_native_noseline_pipeline_texture;

LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_API uint32_t
ltd_native_noseline_pipeline_bridge_abi_version(void);
LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_API const char *
ltd_native_noseline_pipeline_bridge_contract_sha256(void);
LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_API int
ltd_native_noseline_pipeline_bridge_activation_ready(void);

/*
 * Validates the assembler draw identity/source triangle provenance, extracts
 * the exact four carrier screen vertices, and runs the frozen NoseLine kernel.
 * The kernel is transactional, so destination buffers are unchanged on error.
 */
LTD_NATIVE_NOSELINE_PIPELINE_BRIDGE_API ltd_native_noseline_pipeline_bridge_status
ltd_native_noseline_pipeline_draw(
    ltd_native_noseline_pipeline_attachments *attachments,
    const ltd_native_scene_draw_view *scene,
    const ltd_native_noseline_pipeline_texture *texture,
    ltd_noseline12_report *report,
    char *error,
    size_t error_capacity
);

#ifdef __cplusplus
}
#endif

#endif
