#ifndef LTD_NATIVE_FACEPAINT_DECODE_H
#define LTD_NATIVE_FACEPAINT_DECODE_H

/*
 * ShareMii v3 Canvas/UGC decoder.
 *
 * The caller owns the compressed spans, the two RGBA8 output buffers, and the
 * native zstd function table.  No Python, NumPy, allocator-owned result, file
 * access, or process launch is part of this ABI.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LTD_NATIVE_FACEPAINT_DECODE_BUILD_DLL)
#define LTD_NATIVE_FACEPAINT_DECODE_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_NATIVE_FACEPAINT_DECODE_USE_DLL)
#define LTD_NATIVE_FACEPAINT_DECODE_API __declspec(dllimport)
#else
#define LTD_NATIVE_FACEPAINT_DECODE_API
#endif

#if defined(_WIN32)
#define LTD_NATIVE_FACEPAINT_DECODE_CALL __cdecl
#else
#define LTD_NATIVE_FACEPAINT_DECODE_CALL
#endif

#define LTD_NATIVE_FACEPAINT_DECODE_ABI_VERSION UINT32_C(1)
#define LTD_NATIVE_FACEPAINT_ZSTD_ABI_VERSION UINT32_C(1)
#define LTD_NATIVE_FACEPAINT_CANVAS_WIDTH UINT32_C(256)
#define LTD_NATIVE_FACEPAINT_CANVAS_HEIGHT UINT32_C(256)
#define LTD_NATIVE_FACEPAINT_CANVAS_RGBA8_BYTES ((size_t)UINT32_C(262144))
#define LTD_NATIVE_FACEPAINT_UGC_WIDTH UINT32_C(512)
#define LTD_NATIVE_FACEPAINT_UGC_HEIGHT UINT32_C(512)
#define LTD_NATIVE_FACEPAINT_UGC_RGBA8_BYTES ((size_t)UINT32_C(1048576))
#define LTD_NATIVE_FACEPAINT_CONTRACT_CANONICAL \
    "ltd.native.facepaint.decode|abi=1|zstd_adapter=1|canvas=256x256-rgba8-nvn16|" \
    "ugc=512x512-bc1-nvn16-to-rgba8|texsrt=systemparam-f32|caller_buffers=1"
#define LTD_NATIVE_FACEPAINT_CONTRACT_SHA256 \
    "cb2b4f259dd07144db1c0bb71a4d79db1be2d53aa0fd406b96280ea2e98b375d"

typedef enum ltd_native_facepaint_status {
    LTD_NATIVE_FACEPAINT_OK = 0,
    LTD_NATIVE_FACEPAINT_ABSENT = 1,
    LTD_NATIVE_FACEPAINT_INVALID_ARGUMENT = 2,
    LTD_NATIVE_FACEPAINT_UNSUPPORTED_VERSION = 3,
    LTD_NATIVE_FACEPAINT_INCOMPLETE_PAIR = 4,
    LTD_NATIVE_FACEPAINT_OUTPUT_TOO_SMALL = 5,
    LTD_NATIVE_FACEPAINT_ZSTD_UNAVAILABLE = 6,
    LTD_NATIVE_FACEPAINT_NOT_ZSTD = 7,
    LTD_NATIVE_FACEPAINT_ZSTD_INVALID = 8,
    LTD_NATIVE_FACEPAINT_ZSTD_TRAILING_DATA = 9,
    LTD_NATIVE_FACEPAINT_ZSTD_UNKNOWN_SIZE = 10,
    LTD_NATIVE_FACEPAINT_ZSTD_SIZE_MISMATCH = 11,
    LTD_NATIVE_FACEPAINT_BLOCK_LINEAR_INVALID = 12,
    LTD_NATIVE_FACEPAINT_ALLOCATION_FAILED = 13
} ltd_native_facepaint_status;

typedef size_t (LTD_NATIVE_FACEPAINT_DECODE_CALL *ltd_native_facepaint_zstd_find_frame_size_fn)(
    const void *source, size_t source_size);
typedef unsigned long long
    (LTD_NATIVE_FACEPAINT_DECODE_CALL *ltd_native_facepaint_zstd_get_content_size_fn)(
        const void *source, size_t source_size);
typedef size_t (LTD_NATIVE_FACEPAINT_DECODE_CALL *ltd_native_facepaint_zstd_decompress_fn)(
    void *destination, size_t destination_capacity,
    const void *source, size_t source_size);
typedef unsigned (LTD_NATIVE_FACEPAINT_DECODE_CALL *ltd_native_facepaint_zstd_is_error_fn)(
    size_t code);

typedef struct ltd_native_facepaint_zstd_api {
    uint32_t abi_version;
    uint32_t reserved;
    ltd_native_facepaint_zstd_find_frame_size_fn find_frame_compressed_size;
    ltd_native_facepaint_zstd_get_content_size_fn get_frame_content_size;
    ltd_native_facepaint_zstd_decompress_fn decompress;
    ltd_native_facepaint_zstd_is_error_fn is_error;
} ltd_native_facepaint_zstd_api;

typedef struct ltd_native_facepaint_tex_srt {
    float size[2];
    float offset[2];
    float scaling[2];
    float translation[2];
    /* row-major (m00,m01,tx,m10,m11,ty), BFRES UV domain */
    float affine_rows[6];
    uint32_t mode; /* 0 = ModeMaya */
    float rotation;
} ltd_native_facepaint_tex_srt;

typedef struct ltd_native_facepaint_decode_request {
    uint32_t container_version;
    uint8_t has_canvas;
    uint8_t has_ugc_texture;
    uint8_t reserved[2];
    const uint8_t *canvas_encoded;
    size_t canvas_encoded_byte_count;
    const uint8_t *ugc_encoded;
    size_t ugc_encoded_byte_count;
    const ltd_native_facepaint_zstd_api *zstd;
    uint8_t *canvas_rgba8;
    size_t canvas_rgba8_capacity;
    uint8_t *ugc_rgba8;
    size_t ugc_rgba8_capacity;
} ltd_native_facepaint_decode_request;

typedef struct ltd_native_facepaint_decode_summary {
    uint32_t abi_version;
    uint32_t container_version;
    uint32_t canvas_width;
    uint32_t canvas_height;
    uint32_t ugc_width;
    uint32_t ugc_height;
    size_t canvas_encoded_byte_count;
    size_t ugc_encoded_byte_count;
    size_t canvas_rgba8_byte_count;
    size_t ugc_rgba8_byte_count;
    uint8_t decoded;
    uint8_t reserved[7];
} ltd_native_facepaint_decode_summary;

LTD_NATIVE_FACEPAINT_DECODE_API uint32_t LTD_NATIVE_FACEPAINT_DECODE_CALL
ltd_native_facepaint_decode_abi_version(void);

LTD_NATIVE_FACEPAINT_DECODE_API const char *LTD_NATIVE_FACEPAINT_DECODE_CALL
ltd_native_facepaint_decode_contract_sha256(void);

LTD_NATIVE_FACEPAINT_DECODE_API const char *LTD_NATIVE_FACEPAINT_DECODE_CALL
ltd_native_facepaint_status_name(ltd_native_facepaint_status status);

LTD_NATIVE_FACEPAINT_DECODE_API void LTD_NATIVE_FACEPAINT_DECODE_CALL
ltd_native_facepaint_get_tex_srt(ltd_native_facepaint_tex_srt *output);

LTD_NATIVE_FACEPAINT_DECODE_API ltd_native_facepaint_status
LTD_NATIVE_FACEPAINT_DECODE_CALL ltd_native_facepaint_decode(
    const ltd_native_facepaint_decode_request *request,
    ltd_native_facepaint_decode_summary *summary,
    char *error,
    size_t error_capacity);

#ifdef __cplusplus
}
#endif

#endif
