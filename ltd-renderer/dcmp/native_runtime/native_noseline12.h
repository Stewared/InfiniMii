#ifndef LTD_NATIVE_NOSELINE12_H
#define LTD_NATIVE_NOSELINE12_H

/*
 * CPython-free exact-current MiiNose06/NoseLine12 draw kernel.
 *
 * This fixed admission accepts the four unique carrier vertices in OBJ order
 * 402..405 and submits exactly triangles (0,1,2) and (2,1,3).  Screen values
 * are x, y, reciprocal camera depth for each vertex.  All images are
 * row-major binary64; RGB color has three channels and optional alpha/depth
 * have one.  The caller owns every allocation.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LTD_NOSELINE12_BUILD_DLL)
#define LTD_NOSELINE12_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_NOSELINE12_USE_DLL)
#define LTD_NOSELINE12_API __declspec(dllimport)
#else
#define LTD_NOSELINE12_API
#endif

#if defined(_WIN32)
#define LTD_NOSELINE12_CALL __cdecl
#else
#define LTD_NOSELINE12_CALL
#endif

#define LTD_NOSELINE12_ABI_VERSION UINT32_C(1)
#define LTD_NOSELINE12_TRIANGLE_COUNT UINT32_C(2)
#define LTD_NOSELINE12_VERTEX_COUNT UINT32_C(4)
#define LTD_NOSELINE12_MIP_LEVEL_COUNT UINT32_C(9)
#define LTD_NOSELINE12_MAX_DIMENSION UINT32_C(4096)

#define LTD_NOSELINE12_SOFTWARE_RENDERER_SHA256 \
    "ce9f75165fa427fb1eb09594d1dcf3d6ae43fe3302936a5400e36ce95f4c337c"
#define LTD_NOSELINE12_RENDER_MII_SHA256 \
    "2cb56971a3ba7ce7d527ed415d8d9d2a201782a107ed277766a9608c4f9533d4"
#define LTD_NOSELINE12_OBJ_SOURCE_SHA256 \
    "992a9f79c6de93ac87bcb6bc1539b36f53b178be875403b233c39c3d00e80bf7"
#define LTD_NOSELINE12_TEXTURE_MANIFEST_SHA256 \
    "1b98dd4b795e4530fbf582d335320a68e3ab603a79f023232de30a8d3845fdf5"
#define LTD_NOSELINE12_DECODED_MIPS_SHA256 \
    "a76794e3b30862281ef4908f2661f8a9f44d321b14bb57b07e3410230ca5d5e6"

#define LTD_NOSELINE12_CONTRACT_CANONICAL \
    "ltd.native.noseline12|abi=1|asset=MiiNose06|group=NoseLine__mt_NoseLine|" \
    "vertices=4|triangles=0,1,2;2,1,3|projection=screen-xy,reciprocal-depth|" \
    "interpolation=perspective-correct|lod=point-nearest|sample=repeat-bilinear-red|" \
    "alpha=gequal-0.5|rgb=srgb(34,24,23)-decoded-linear|blend=opaque|" \
    "depth=reverse-gequal-write|alpha-target=optional-replace-one|round=FE_TONEAREST|" \
    "obj=" LTD_NOSELINE12_OBJ_SOURCE_SHA256 "|texture-manifest=" \
    LTD_NOSELINE12_TEXTURE_MANIFEST_SHA256 "|decoded-mips=" \
    LTD_NOSELINE12_DECODED_MIPS_SHA256 "|software-renderer=" \
    LTD_NOSELINE12_SOFTWARE_RENDERER_SHA256 "|render-mii=" \
    LTD_NOSELINE12_RENDER_MII_SHA256

/* SHA-256 of LTD_NOSELINE12_CONTRACT_CANONICAL. */
#define LTD_NOSELINE12_CONTRACT_SHA256 \
    "bb99ca045c2347a101ce9ded45234170312a25a4ee89326b0bf2c0c385490a67"

typedef enum ltd_noseline12_status {
    LTD_NOSELINE12_OK = 0,
    LTD_NOSELINE12_INVALID_ARGUMENT = 1,
    LTD_NOSELINE12_BUFFER_TOO_SMALL = 2,
    LTD_NOSELINE12_NONFINITE = 3,
    LTD_NOSELINE12_VALUE_OUT_OF_RANGE = 4,
    LTD_NOSELINE12_ROUNDING_MODE = 5,
    LTD_NOSELINE12_ABI_MISMATCH = 6,
    LTD_NOSELINE12_CONTRACT_MISMATCH = 7,
    LTD_NOSELINE12_SOURCE_FINGERPRINT_MISMATCH = 8,
    LTD_NOSELINE12_SOURCE_CONTENT_MISMATCH = 9,
    LTD_NOSELINE12_BUFFER_ALIAS = 10,
    LTD_NOSELINE12_FENV_FAILURE = 11
} ltd_noseline12_status;

typedef struct ltd_noseline12_attachments {
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
} ltd_noseline12_attachments;

typedef struct ltd_noseline12_mip_level {
    size_t rgba_element_offset;
    uint32_t width;
    uint32_t height;
} ltd_noseline12_mip_level;

typedef struct ltd_noseline12_input {
    /* Four rows of x,y,reciprocal-depth in OBJ vertex order 402..405. */
    double screen[12];
    const double *mip_rgba;
    size_t mip_rgba_element_count;
    ltd_noseline12_mip_level levels[LTD_NOSELINE12_MIP_LEVEL_COUNT];
    char obj_source_sha256[65];
    char texture_manifest_sha256[65];
    char decoded_mips_sha256[65];
    uint32_t perspective_correct;
    uint32_t reserved;
} ltd_noseline12_input;

typedef struct ltd_noseline12_report {
    uint32_t submitted_triangles;
    uint32_t selected_mip_levels[LTD_NOSELINE12_TRIANGLE_COUNT];
    uint64_t candidate_fragments;
    uint64_t alpha_selected_fragments;
    uint64_t written_fragments;
} ltd_noseline12_report;

LTD_NOSELINE12_API uint32_t LTD_NOSELINE12_CALL
ltd_noseline12_abi_version(void);

LTD_NOSELINE12_API const char *LTD_NOSELINE12_CALL
ltd_noseline12_contract_sha256(void);

LTD_NOSELINE12_API const char *LTD_NOSELINE12_CALL
ltd_noseline12_software_renderer_sha256(void);

LTD_NOSELINE12_API const char *LTD_NOSELINE12_CALL
ltd_noseline12_render_mii_sha256(void);

LTD_NOSELINE12_API const char *LTD_NOSELINE12_CALL
ltd_noseline12_obj_source_sha256(void);

LTD_NOSELINE12_API const char *LTD_NOSELINE12_CALL
ltd_noseline12_texture_manifest_sha256(void);

LTD_NOSELINE12_API const char *LTD_NOSELINE12_CALL
ltd_noseline12_decoded_mips_sha256(void);

LTD_NOSELINE12_API const char *LTD_NOSELINE12_CALL
ltd_noseline12_status_name(ltd_noseline12_status status);

LTD_NOSELINE12_API ltd_noseline12_status LTD_NOSELINE12_CALL
ltd_noseline12_require(uint32_t expected_abi, const char *expected_contract_sha256);

/*
 * Validation is transactional: on any non-OK status, attachments and report
 * are unchanged.  On success, submitted_triangles is always exactly two.
 */
LTD_NOSELINE12_API ltd_noseline12_status LTD_NOSELINE12_CALL
ltd_noseline12_draw(
    ltd_noseline12_attachments *attachments,
    const ltd_noseline12_input *input,
    ltd_noseline12_report *report
);

#ifdef __cplusplus
}
#endif

#endif
