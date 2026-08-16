#ifndef LTD_NATIVE_MATERIAL_PROVIDER_H
#define LTD_NATIVE_MATERIAL_PROVIDER_H

/*
 * Immutable source-authenticated provider for normalized material records and
 * complete authored texture mip chains.  The C ABI is intentionally suitable
 * for both the standalone executable and native_material_field_packer.
 */

#include <stddef.h>
#include <stdint.h>

#include "native_material_field_packer.h"

#ifdef __cplusplus
namespace native_runtime {
class DecodedAssetCache;
}
typedef native_runtime::DecodedAssetCache ltd_native_decoded_asset_cache;
extern "C" {
#else
typedef struct ltd_native_decoded_asset_cache ltd_native_decoded_asset_cache;
#endif

#if defined(_WIN32) && defined(LTD_NATIVE_MATERIAL_PROVIDER_BUILD_DLL)
#define LTD_NATIVE_MATERIAL_PROVIDER_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_NATIVE_MATERIAL_PROVIDER_USE_DLL)
#define LTD_NATIVE_MATERIAL_PROVIDER_API __declspec(dllimport)
#else
#define LTD_NATIVE_MATERIAL_PROVIDER_API
#endif

#if defined(_WIN32)
#define LTD_NATIVE_MATERIAL_PROVIDER_CALL __cdecl
#else
#define LTD_NATIVE_MATERIAL_PROVIDER_CALL
#endif

#define LTD_NATIVE_MATERIAL_PROVIDER_ABI_VERSION UINT32_C(2)
#define LTD_NATIVE_MATERIAL_PROVIDER_CONTRACT_CANONICAL \
    "ltd.native.material-provider|abi=2|material=typed-immutable|" \
    "texture=authored-rgba8+rgba64+sampled-rgba64|colorspace=linear,srgb|" \
    "seals=manifest+authored-source+every-mip+normalization-evidence|" \
    "cache=owned-or-borrowed-authenticated-immutable|" \
    "trusted-bundle=opaque-adapter-lease+same-cache+publication-sealed|" \
    "field-packer-callback=1|source-sealed=1"
#define LTD_NATIVE_MATERIAL_PROVIDER_CONTRACT_SHA256 \
    "5dd81063b68f0badf794a00f1ee5a307f93316843721aaac36f81a9a5881e302"

typedef struct ltd_native_material_provider ltd_native_material_provider;

typedef enum ltd_native_material_provider_status {
    LTD_NATIVE_MATERIAL_PROVIDER_OK = 0,
    LTD_NATIVE_MATERIAL_PROVIDER_INVALID_ARGUMENT = 1,
    LTD_NATIVE_MATERIAL_PROVIDER_SOURCE_MISMATCH = 2,
    LTD_NATIVE_MATERIAL_PROVIDER_SCHEMA_MISMATCH = 3,
    LTD_NATIVE_MATERIAL_PROVIDER_DUPLICATE = 4,
    LTD_NATIVE_MATERIAL_PROVIDER_NOT_FOUND = 5,
    LTD_NATIVE_MATERIAL_PROVIDER_COLOR_SPACE_MISMATCH = 6,
    LTD_NATIVE_MATERIAL_PROVIDER_NONFINITE = 7,
    LTD_NATIVE_MATERIAL_PROVIDER_CACHE_FAILED = 8,
    LTD_NATIVE_MATERIAL_PROVIDER_ALLOCATION_FAILED = 9
} ltd_native_material_provider_status;

typedef enum ltd_native_material_evidence_role {
    LTD_NATIVE_MATERIAL_EVIDENCE_BFRES_CATALOG = 1,
    LTD_NATIVE_MATERIAL_EVIDENCE_MATERIAL_STATE = 2,
    LTD_NATIVE_MATERIAL_EVIDENCE_PROGRAM_LEDGER = 3,
    LTD_NATIVE_MATERIAL_EVIDENCE_COLOR_TABLE = 4,
    LTD_NATIVE_MATERIAL_EVIDENCE_NORMALIZATION_SOURCE = 5
} ltd_native_material_evidence_role;

typedef struct ltd_native_material_source_document {
    uint32_t role;
    uint32_t reserved;
    const char *logical_path;
    const char *sha256;
    const uint8_t *bytes;
    size_t byte_count;
} ltd_native_material_source_document;

typedef struct ltd_native_material_mip_level_source {
    uint32_t level;
    uint32_t width;
    uint32_t height;
    uint32_t reserved;
    const char *canonical_key;
    const char *source_sha256;
    const uint8_t *source_bytes;
    size_t source_byte_count;
} ltd_native_material_mip_level_source;

typedef struct ltd_native_material_mip_chain_source {
    const char *source_key;
    const char *texture_name;
    const char *source_format;
    const char *authored_source_sha256;
    const uint8_t *authored_source_bytes;
    size_t authored_source_byte_count;
    const char *manifest_sha256;
    const uint8_t *manifest_bytes;
    size_t manifest_byte_count;
    uint32_t color_space;
    uint32_t level_count;
    const ltd_native_material_mip_level_source *levels;
} ltd_native_material_mip_chain_source;

typedef struct ltd_native_material_normalized_source {
    const char *source_key;
    const char *material_name;
    const ltd_native_normalized_material_view *material;
    const ltd_native_material_source_document *evidence;
    uint32_t evidence_count;
} ltd_native_material_normalized_source;

typedef struct ltd_native_material_normalized_view {
    const char *source_key;
    const char *material_name;
    const char *normalized_sha256;
    const ltd_native_normalized_material_view *material;
    const ltd_native_material_source_document *evidence;
    uint32_t evidence_count;
} ltd_native_material_normalized_view;

/* Private ABI between the sealed native runtime material adapter and this
 * provider. Ordinary callers see only the opaque tag and cannot construct a
 * trusted publication. Both implementation translation units opt into the
 * POD layout; no STL object crosses the boundary. */
typedef struct ltd_native_material_trusted_bundle
    ltd_native_material_trusted_bundle;

#if defined(LTD_NATIVE_MATERIAL_PROVIDER_TRUSTED_INTERNAL)
typedef int (LTD_NATIVE_MATERIAL_PROVIDER_CALL *
ltd_native_material_trusted_authenticate_fn)(
    void *context,
    const ltd_native_material_trusted_bundle *bundle);
typedef void *(LTD_NATIVE_MATERIAL_PROVIDER_CALL *
ltd_native_material_trusted_retain_fn)(void *context);
typedef void (LTD_NATIVE_MATERIAL_PROVIDER_CALL *
ltd_native_material_trusted_release_fn)(void *lease);

struct ltd_native_material_trusted_bundle {
    uint32_t abi_version;
    uint32_t reserved;
    const char *producer_contract_sha256;
    ltd_native_decoded_asset_cache *decoded_cache;
    const char *catalog_sha256;
    const char *source_bundle_sha256;
    const char *publication_sha256;
    const char *share_mii_sha256;
    const char *effective_char_info_sha256;
    uint32_t view_kind;
    uint32_t raster_size;
    const ltd_native_material_mip_chain_source *mip_chains;
    uint32_t mip_chain_count;
    const ltd_native_material_normalized_source *materials;
    const uint32_t *scene_draw_indices;
    uint32_t material_count;
    void *lease_context;
    ltd_native_material_trusted_authenticate_fn authenticate;
    ltd_native_material_trusted_retain_fn retain;
    ltd_native_material_trusted_release_fn release;
};
#endif

LTD_NATIVE_MATERIAL_PROVIDER_API uint32_t LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_abi_version(void);

LTD_NATIVE_MATERIAL_PROVIDER_API const char *LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_contract_sha256(void);

LTD_NATIVE_MATERIAL_PROVIDER_API const char *LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_status_name(ltd_native_material_provider_status status);

LTD_NATIVE_MATERIAL_PROVIDER_API ltd_native_material_provider_status
LTD_NATIVE_MATERIAL_PROVIDER_CALL ltd_native_material_provider_create(
    ltd_native_material_provider **output,
    char *error,
    size_t error_capacity);

/*
 * Additive ABI 2 constructor. `cache` is borrowed: it must outlive the
 * provider and must not be mutated concurrently with provider calls. Every
 * publication is still source/seal authenticated by decode_texture_mip_chain;
 * an existing immutable entry is used only through that authenticated hit.
 */
LTD_NATIVE_MATERIAL_PROVIDER_API ltd_native_material_provider_status
LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_create_with_borrowed_cache(
    ltd_native_decoded_asset_cache *cache,
    ltd_native_material_provider **output,
    char *error,
    size_t error_capacity);

/* Adapter-only transactional fast path. Success retains the opaque producer
 * lease until provider destruction; failure retains nothing and publishes no
 * partial record. The provider and bundle must name the same borrowed cache. */
LTD_NATIVE_MATERIAL_PROVIDER_API ltd_native_material_provider_status
LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_publish_trusted_bundle(
    ltd_native_material_provider *provider,
    const ltd_native_material_trusted_bundle *bundle,
    char *error,
    size_t error_capacity);

LTD_NATIVE_MATERIAL_PROVIDER_API void LTD_NATIVE_MATERIAL_PROVIDER_CALL
ltd_native_material_provider_destroy(ltd_native_material_provider *provider);

LTD_NATIVE_MATERIAL_PROVIDER_API ltd_native_material_provider_status
LTD_NATIVE_MATERIAL_PROVIDER_CALL ltd_native_material_provider_publish_mip_chain(
    ltd_native_material_provider *provider,
    const ltd_native_material_mip_chain_source *source,
    char *error,
    size_t error_capacity);

LTD_NATIVE_MATERIAL_PROVIDER_API ltd_native_material_provider_status
LTD_NATIVE_MATERIAL_PROVIDER_CALL ltd_native_material_provider_publish_material(
    ltd_native_material_provider *provider,
    const ltd_native_material_normalized_source *source,
    char *error,
    size_t error_capacity);

LTD_NATIVE_MATERIAL_PROVIDER_API ltd_native_material_provider_status
LTD_NATIVE_MATERIAL_PROVIDER_CALL ltd_native_material_provider_get_material(
    const ltd_native_material_provider *provider,
    const char *source_key,
    ltd_native_material_normalized_view *output,
    char *error,
    size_t error_capacity);

/* Returned callback/context remain valid until provider destruction. */
LTD_NATIVE_MATERIAL_PROVIDER_API ltd_native_material_provider_status
LTD_NATIVE_MATERIAL_PROVIDER_CALL ltd_native_material_provider_texture_callback(
    ltd_native_material_provider *provider,
    ltd_native_material_texture_provider *output);

#ifdef __cplusplus
}
#endif

#endif
