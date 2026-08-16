#ifndef LTD_NATIVE_SCENE_CACHE_ADAPTER_H
#define LTD_NATIVE_SCENE_CACHE_ADAPTER_H

/*
 * Filesystem/source-seal adapter from DecodedAssetCache to the immutable
 * native_scene_assembler provider ABI.
 *
 * The adapter owns its cache and every catalog/pose backing allocation.  An
 * assembly returned by ltd_native_scene_cache_adapter_assemble is independent
 * of the adapter and is destroyed with ltd_native_scene_assembly_destroy.
 * No Python process or Python-owned pointer participates in this boundary.
 */

#include "native_scene_assembler.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LTD_NATIVE_SCENE_CACHE_ADAPTER_BUILD_DLL)
#define LTD_NATIVE_SCENE_CACHE_ADAPTER_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_NATIVE_SCENE_CACHE_ADAPTER_USE_DLL)
#define LTD_NATIVE_SCENE_CACHE_ADAPTER_API __declspec(dllimport)
#else
#define LTD_NATIVE_SCENE_CACHE_ADAPTER_API
#endif

#if defined(_WIN32)
#define LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL __cdecl
#else
#define LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
#endif

#define LTD_NATIVE_SCENE_CACHE_ADAPTER_ABI_VERSION UINT32_C(1)
#define LTD_NATIVE_SCENE_CACHE_ADAPTER_CONTRACT_CANONICAL \
    "ltd.native.scene.cache.adapter|abi=1|decoded-cache=immutable-getters-v1+borrowed-runtime-cache|" \
    "parts=1|pose=IconPose-static-EulerXYZ|models=sealed-bfres-json+obj+named-uv|" \
    "model-getter=borrowed-immutable|" \
    "assembler=1|fixtures=mii0,mii1,mii2,mii4|views=portrait,full_body|" \
    "sizes=128,512|activation_ready=0"
#define LTD_NATIVE_SCENE_CACHE_ADAPTER_CONTRACT_SHA256 \
    "6a50862b20a7f11d6b3c59295bfe36b426f5774b65be4146e434ee8117e65eb8"

typedef struct ltd_native_scene_cache_adapter ltd_native_scene_cache_adapter;

typedef enum ltd_native_scene_cache_adapter_status {
    LTD_NATIVE_SCENE_CACHE_ADAPTER_OK = 0,
    LTD_NATIVE_SCENE_CACHE_ADAPTER_INVALID_ARGUMENT = 1,
    LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_MISSING = 2,
    LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_CHANGED = 3,
    LTD_NATIVE_SCENE_CACHE_ADAPTER_SOURCE_INVALID = 4,
    LTD_NATIVE_SCENE_CACHE_ADAPTER_CACHE_FAILED = 5,
    LTD_NATIVE_SCENE_CACHE_ADAPTER_ASSEMBLER_FAILED = 6,
    LTD_NATIVE_SCENE_CACHE_ADAPTER_RESOURCE_LIMIT = 7,
    LTD_NATIVE_SCENE_CACHE_ADAPTER_ALLOCATION_FAILED = 8,
    LTD_NATIVE_SCENE_CACHE_ADAPTER_INTERNAL_ERROR = 9
} ltd_native_scene_cache_adapter_status;

typedef struct ltd_native_scene_cache_adapter_create_request {
    /* UTF-8 absolute/canonicalizable paths. */
    const char *model_root;
    const char *icon_pose_path;
} ltd_native_scene_cache_adapter_create_request;

typedef struct ltd_native_scene_cache_adapter_summary {
    uint32_t abi_version;
    uint32_t cached_model_count;
    uint64_t cached_obj_count;
    uint64_t resident_decoded_bytes;
    uint8_t pose_source_seal_validated;
    uint8_t production_activation_ready;
    uint8_t reserved[6];
} ltd_native_scene_cache_adapter_summary;

LTD_NATIVE_SCENE_CACHE_ADAPTER_API uint32_t LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_abi_version(void);

LTD_NATIVE_SCENE_CACHE_ADAPTER_API const char *LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_contract_sha256(void);

LTD_NATIVE_SCENE_CACHE_ADAPTER_API const char *LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_status_name(ltd_native_scene_cache_adapter_status status);

LTD_NATIVE_SCENE_CACHE_ADAPTER_API int LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_activation_ready(void);

LTD_NATIVE_SCENE_CACHE_ADAPTER_API ltd_native_scene_cache_adapter_status
LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL ltd_native_scene_cache_adapter_create(
    const ltd_native_scene_cache_adapter_create_request *request,
    ltd_native_scene_cache_adapter **output,
    char *error,
    size_t error_capacity
);

LTD_NATIVE_SCENE_CACHE_ADAPTER_API void LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL
ltd_native_scene_cache_adapter_destroy(ltd_native_scene_cache_adapter *adapter);

/*
 * Calls native_scene_assembler synchronously. On adapter success,
 * assembler_status is LTD_NATIVE_SCENE_ASSEMBLER_OK and output is non-null.
 * Any assembler rejection maps to ADAPTER_ASSEMBLER_FAILED while preserving
 * its exact status in assembler_status.
 */
LTD_NATIVE_SCENE_CACHE_ADAPTER_API ltd_native_scene_cache_adapter_status
LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL ltd_native_scene_cache_adapter_assemble(
    ltd_native_scene_cache_adapter *adapter,
    const uint8_t *parts_catalog_bytes,
    size_t parts_catalog_byte_count,
    const uint8_t *parts_catalog_sha256,
    const uint8_t *raw_char_info,
    size_t raw_char_info_byte_count,
    uint32_t view_kind,
    uint32_t raster_size,
    ltd_native_scene_assembly **output,
    ltd_native_scene_assembler_status *assembler_status,
    char *error,
    size_t error_capacity
);

LTD_NATIVE_SCENE_CACHE_ADAPTER_API ltd_native_scene_cache_adapter_status
LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL ltd_native_scene_cache_adapter_get_summary(
    const ltd_native_scene_cache_adapter *adapter,
    ltd_native_scene_cache_adapter_summary *output
);

/* Borrowed immutable view, valid until adapter destruction. */
LTD_NATIVE_SCENE_CACHE_ADAPTER_API ltd_native_scene_cache_adapter_status
LTD_NATIVE_SCENE_CACHE_ADAPTER_CALL ltd_native_scene_cache_adapter_get_model(
    ltd_native_scene_cache_adapter *adapter,
    const char *resource_name,
    const char *model_name,
    ltd_native_scene_model_view *output,
    char *error,
    size_t error_capacity
);

#ifdef __cplusplus
}

namespace native_runtime {
class DecodedAssetCache;

/*
 * Integration path for the persistent runtime: borrows the already-populated
 * cache and copies the already-authenticated pose view.  It performs no Parts
 * reconstruction and does not own either input.
 */
ltd_native_scene_cache_adapter_status create_borrowed_scene_cache_adapter(
    const char *model_root,
    DecodedAssetCache *cache,
    const ltd_native_scene_pose_view *icon_pose,
    ltd_native_scene_cache_adapter **output,
    char *error,
    size_t error_capacity
);
}  // namespace native_runtime
#endif

#endif
