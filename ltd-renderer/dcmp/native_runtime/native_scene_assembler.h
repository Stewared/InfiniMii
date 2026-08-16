#ifndef LTD_NATIVE_SCENE_ASSEMBLER_H
#define LTD_NATIVE_SCENE_ASSEMBLER_H

/*
 * Source-authenticated, cache-neutral multi-model scene assembly.
 *
 * The adapter returns borrowed immutable views.  The assembler copies every
 * output needed after the synchronous assemble call and never retains adapter
 * pointers.  The current admission is deliberately limited to the exact
 * mii0/mii1/mii2/mii4 native-Parts model/profile set.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(LTD_NATIVE_SCENE_ASSEMBLER_BUILD_DLL)
#define LTD_NATIVE_SCENE_ASSEMBLER_API __declspec(dllexport)
#elif defined(_WIN32) && defined(LTD_NATIVE_SCENE_ASSEMBLER_USE_DLL)
#define LTD_NATIVE_SCENE_ASSEMBLER_API __declspec(dllimport)
#else
#define LTD_NATIVE_SCENE_ASSEMBLER_API
#endif

#if defined(_WIN32)
#define LTD_NATIVE_SCENE_ASSEMBLER_CALL __cdecl
#else
#define LTD_NATIVE_SCENE_ASSEMBLER_CALL
#endif

#define LTD_NATIVE_SCENE_ASSEMBLER_ABI_VERSION UINT32_C(1)
#define LTD_NATIVE_SCENE_ASSEMBLER_CONTRACT_CANONICAL \
    "ltd.native.scene.assembler|abi=1|parts=1|pose=1|scene=1|geometry=1|" \
    "fixtures=mii0,mii1,mii2,mii4|views=portrait,full_body|" \
    "sizes=128,512|adapter=immutable-model-v1|activation_ready=0"
#define LTD_NATIVE_SCENE_ASSEMBLER_CONTRACT_SHA256 \
    "18ced4a2c965f721e05c41751dfa32b3ce9629d6d3694ab0436f61a0919c386c"

#define LTD_NATIVE_SCENE_ASSEMBLER_MAX_MODELS UINT32_C(32)
#define LTD_NATIVE_SCENE_ASSEMBLER_MAX_DRAWS UINT32_C(64)
#define LTD_NATIVE_SCENE_ASSEMBLER_MAX_DIMENSION UINT32_C(4096)

typedef struct ltd_native_scene_assembly ltd_native_scene_assembly;

typedef enum ltd_native_scene_assembler_status {
    LTD_NATIVE_SCENE_ASSEMBLER_OK = 0,
    LTD_NATIVE_SCENE_ASSEMBLER_INVALID_ARGUMENT = 1,
    LTD_NATIVE_SCENE_ASSEMBLER_MODULE_MISMATCH = 2,
    LTD_NATIVE_SCENE_ASSEMBLER_PARTS_FAILED = 3,
    LTD_NATIVE_SCENE_ASSEMBLER_ASSET_MISSING = 4,
    LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID = 5,
    LTD_NATIVE_SCENE_ASSEMBLER_SOURCE_SEAL_INVALID = 6,
    LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED = 7,
    LTD_NATIVE_SCENE_ASSEMBLER_POSE_FAILED = 8,
    LTD_NATIVE_SCENE_ASSEMBLER_TRANSFORM_FAILED = 9,
    LTD_NATIVE_SCENE_ASSEMBLER_GEOMETRY_FAILED = 10,
    LTD_NATIVE_SCENE_ASSEMBLER_SCHEDULE_FAILED = 11,
    LTD_NATIVE_SCENE_ASSEMBLER_RESOURCE_LIMIT = 12,
    LTD_NATIVE_SCENE_ASSEMBLER_ALLOCATION_FAILED = 13,
    LTD_NATIVE_SCENE_ASSEMBLER_PROVIDER_FAILED = 14
} ltd_native_scene_assembler_status;

typedef enum ltd_native_scene_view_kind {
    LTD_NATIVE_SCENE_VIEW_PORTRAIT = 1,
    LTD_NATIVE_SCENE_VIEW_FULL_BODY = 2
} ltd_native_scene_view_kind;

/* Values intentionally match native_render_pipeline profile ABI 1. */
typedef enum ltd_native_scene_draw_profile {
    LTD_NATIVE_SCENE_PROFILE_HEAD816 = 1,
    LTD_NATIVE_SCENE_PROFILE_BODY324 = 2,
    LTD_NATIVE_SCENE_PROFILE_BODY336 = 3,
    LTD_NATIVE_SCENE_PROFILE_BODY348 = 4,
    LTD_NATIVE_SCENE_PROFILE_EAR372 = 5,
    LTD_NATIVE_SCENE_PROFILE_NOSE756 = 6,
    LTD_NATIVE_SCENE_PROFILE_MASK0 = 7,
    LTD_NATIVE_SCENE_PROFILE_HAIR612 = 8,
    LTD_NATIVE_SCENE_PROFILE_HAIR564_EQUAL_ENDPOINT = 9,
    LTD_NATIVE_SCENE_PROFILE_BEARD468 = 10,
    LTD_NATIVE_SCENE_PROFILE_OUTFIT_TOPS984 = 11,
    LTD_NATIVE_SCENE_PROFILE_OUTFIT_BOTTOMS936 = 12,
    LTD_NATIVE_SCENE_PROFILE_OUTFIT_SHOES912 = 13,
    LTD_NATIVE_SCENE_PROFILE_NOSE_LINE12 = 14
} ltd_native_scene_draw_profile;

typedef struct ltd_native_scene_triangle_view {
    const char *group;
    int64_t vertex[3];
    int64_t texcoord[3];
    int64_t normal[3];
} ltd_native_scene_triangle_view;

typedef struct ltd_native_scene_named_uv_view {
    const char *name;
    const double *values; /* position_count * 2, NaN marks unauthored vertices */
    size_t element_count;
} ltd_native_scene_named_uv_view;

typedef struct ltd_native_scene_bone_view {
    const char *name;
    int32_t parent_index;
    uint32_t reserved;
    double scale[3];
    double rotation[3];
    double translation[3];
} ltd_native_scene_bone_view;

typedef struct ltd_native_scene_shape_view {
    const char *group;
    const char *texcoord_attribute;
    int32_t bone_index;
    uint32_t vertex_skin_count;
    size_t vertex_offset;
    size_t vertex_count;
    const int32_t *palette_indices; /* vertex_count * vertex_skin_count */
    size_t palette_index_count;
    const double *weights;          /* optional only for vertex_skin_count == 1 */
    size_t weight_count;
} ltd_native_scene_shape_view;

typedef struct ltd_native_scene_model_view {
    const char *resource_name;
    const char *model_name;
    const char *obj_sha256;
    const char *catalog_sha256;
    const char *named_uv_sha256; /* 64 hex or NULL when no sidecar exists */
    const double *positions;
    const double *normals;
    const double *texcoords;
    size_t position_count;
    size_t normal_count;
    size_t texcoord_count;
    const ltd_native_scene_triangle_view *triangles;
    size_t triangle_count;
    const ltd_native_scene_named_uv_view *named_uv_channels;
    size_t named_uv_channel_count;
    const ltd_native_scene_bone_view *bones;
    size_t bone_count;
    const ltd_native_scene_shape_view *shapes;
    size_t shape_count;
    const int32_t *matrix_to_bone;
    size_t palette_count;
    const double *inverse_bind_matrices; /* smooth_count * 16 */
    size_t smooth_count;
} ltd_native_scene_model_view;

typedef int (LTD_NATIVE_SCENE_ASSEMBLER_CALL *ltd_native_scene_get_model_fn)(
    void *context,
    const char *resource_name,
    const char *model_name,
    ltd_native_scene_model_view *output,
    char *error,
    size_t error_capacity
);

typedef struct ltd_native_scene_asset_provider {
    void *context;
    ltd_native_scene_get_model_fn get_model;
} ltd_native_scene_asset_provider;

typedef struct ltd_native_scene_pose_bone_view {
    const char *name;
    double scale[3];
    double rotation[3];
    double translation[3];
} ltd_native_scene_pose_bone_view;

typedef struct ltd_native_scene_pose_view {
    const char *name;
    const char *source_sha256;
    const ltd_native_scene_pose_bone_view *bones;
    size_t bone_count;
} ltd_native_scene_pose_view;

typedef struct ltd_native_scene_assemble_request {
    const uint8_t *parts_catalog_bytes;
    size_t parts_catalog_byte_count;
    const uint8_t *parts_catalog_sha256; /* exactly 32 bytes */
    const uint8_t *raw_char_info;
    size_t raw_char_info_byte_count;
    const ltd_native_scene_asset_provider *assets;
    const ltd_native_scene_pose_view *icon_pose;
    uint32_t view_kind;
    uint32_t raster_size;
} ltd_native_scene_assemble_request;

typedef struct ltd_native_scene_camera_view {
    uint32_t projection_kind; /* 1 = perspective */
    uint32_t width;
    uint32_t height;
    uint32_t reserved;
    double camera_position[3];
    double camera_target[3];
    double camera_up[3];
    double vertical_fov_degrees;
    double horizontal_projection_scale;
    double body_scale[3];
    double head_transform[16];
} ltd_native_scene_camera_view;

typedef struct ltd_native_scene_draw_view {
    const char *resource_name;
    const char *model_name;
    const char *group;
    uint32_t profile;
    uint8_t blend;
    uint8_t depth_write;
    uint8_t cull_back_faces;
    uint8_t clockwise_front_face;
    double transform[16];
    uint64_t submitted_triangle_count;
    uint64_t candidate_triangle_count;
    const uint64_t *source_triangle_indices;
    const double *world_vertices; /* candidate_count * 9 */
    const double *world_normals;  /* candidate_count * 9 */
    const double *screen;         /* candidate_count * 9 */
    const int64_t *bounds;        /* candidate_count * 4 */
    const double *denominators;   /* candidate_count */
    const double *material_uv;    /* candidate_count * 6 or NULL */
    const double *uv0;            /* candidate_count * 6 or NULL */
    const double *uv2;            /* candidate_count * 6 or NULL */
} ltd_native_scene_draw_view;

typedef struct ltd_native_scene_assembly_summary {
    uint32_t abi_version;
    uint32_t view_kind;
    uint32_t raster_size;
    uint32_t model_count;
    uint32_t draw_count;
    uint64_t submitted_triangle_count;
    uint64_t candidate_triangle_count;
    uint8_t source_seals_validated;
    uint8_t native_parts_selected;
    uint8_t production_activation_ready;
    uint8_t reserved;
} ltd_native_scene_assembly_summary;

LTD_NATIVE_SCENE_ASSEMBLER_API uint32_t LTD_NATIVE_SCENE_ASSEMBLER_CALL
ltd_native_scene_assembler_abi_version(void);

LTD_NATIVE_SCENE_ASSEMBLER_API const char *LTD_NATIVE_SCENE_ASSEMBLER_CALL
ltd_native_scene_assembler_contract_sha256(void);

LTD_NATIVE_SCENE_ASSEMBLER_API const char *LTD_NATIVE_SCENE_ASSEMBLER_CALL
ltd_native_scene_assembler_status_name(ltd_native_scene_assembler_status status);

LTD_NATIVE_SCENE_ASSEMBLER_API int LTD_NATIVE_SCENE_ASSEMBLER_CALL
ltd_native_scene_assembler_activation_ready(void);

LTD_NATIVE_SCENE_ASSEMBLER_API ltd_native_scene_assembler_status
LTD_NATIVE_SCENE_ASSEMBLER_CALL ltd_native_scene_assemble(
    const ltd_native_scene_assemble_request *request,
    ltd_native_scene_assembly **output,
    char *error,
    size_t error_capacity
);

LTD_NATIVE_SCENE_ASSEMBLER_API void LTD_NATIVE_SCENE_ASSEMBLER_CALL
ltd_native_scene_assembly_destroy(ltd_native_scene_assembly *assembly);

LTD_NATIVE_SCENE_ASSEMBLER_API ltd_native_scene_assembler_status
LTD_NATIVE_SCENE_ASSEMBLER_CALL ltd_native_scene_assembly_get_summary(
    const ltd_native_scene_assembly *assembly,
    ltd_native_scene_assembly_summary *output
);

LTD_NATIVE_SCENE_ASSEMBLER_API ltd_native_scene_assembler_status
LTD_NATIVE_SCENE_ASSEMBLER_CALL ltd_native_scene_assembly_get_camera(
    const ltd_native_scene_assembly *assembly,
    ltd_native_scene_camera_view *output
);

LTD_NATIVE_SCENE_ASSEMBLER_API ltd_native_scene_assembler_status
LTD_NATIVE_SCENE_ASSEMBLER_CALL ltd_native_scene_assembly_get_draw(
    const ltd_native_scene_assembly *assembly,
    size_t index,
    ltd_native_scene_draw_view *output
);

#ifdef __cplusplus
}
#endif

#endif
