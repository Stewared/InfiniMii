#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ffl_high_texture.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define CFL_RECORD_OFFSET_MASK 0x003fffffu
#define CGFX_MAX_BONE_INFLUENCES 4

enum {
    CFL_SHAPE_BEARD = 0,
    CFL_SHAPE_HAT = 1,
    CFL_SHAPE_FACELINE = 2,
    CFL_SHAPE_FOREHEAD = 3,
    CFL_SHAPE_GLASSES = 4,
    CFL_SHAPE_HAIR = 5,
    CFL_SHAPE_MASK = 6,
    CFL_SHAPE_NOSELINE = 7,
    CFL_SHAPE_NOSE = 8,

    CFL_TEX_CAP = 9,
    CFL_TEX_EYES = 10,
    CFL_TEX_EYEBROWS = 11,
    CFL_TEX_BEARD = 12,
    CFL_TEX_FACELINE = 13,
    CFL_TEX_FACE_MAKEUP = 14,
    CFL_TEX_GLASSES = 15,
    CFL_TEX_MOLE = 16,
    CFL_TEX_MOUTH = 17,
    CFL_TEX_MUSTACHE = 18,
    CFL_TEX_NOSELINE = 19
};

typedef struct {
    uint8_t *data;
    size_t size;
} Buffer;

typedef struct {
    const uint8_t *bytes;
    size_t size;
    uint32_t *offsets;
    uint32_t offset_count;
    const FflHighResource *high_textures;
} CflResource;

typedef struct {
    int width;
    int height;
    int format;
    uint8_t *rgba;
} CflTexture;

typedef struct {
    int width;
    int height;
    uint8_t *rgba;
} Image;

typedef struct {
    double x;
    double y;
} Vec2;

typedef struct {
    double x;
    double y;
    double z;
} Vec3;

typedef struct {
    int vertex_count;
    int normal_count;
    int texcoord_count;
    int index_count;
    int extra_count;
    Vec3 *vertices;
    Vec3 *normals;
    Vec2 *texcoords;
    uint8_t *indices;
    Vec3 extra[6];
} CflShape;

typedef struct {
    int vertex_count;
    int index_count;
    int has_normals;
    int has_tangents;
    int has_uvs;
    int has_uv1s;
    int has_uv2s;
    int has_colors;
    int has_skin;
    int material_index;
    char mesh_node_name[64];
    Vec3 *vertices;
    Vec3 *normals;
    Vec3 *tangents;
    Vec2 *uvs;
    Vec2 *uv1s;
    Vec2 *uv2s;
    uint32_t *colors;
    uint8_t *bone_indices;
    double *bone_weights;
    uint32_t *indices;
    Vec3 min;
    Vec3 max;
} CgfxMesh;

typedef struct {
    char name[64];
    int index;
    int parent_index;
    uint32_t flags;
    Vec3 base_scale;
    Vec3 base_rotation;
    Vec3 base_translation;
    double local[12];
    double inv_world[12];
    double scaled_world[12];
    double skin_matrix[12];
} CgfxBone;

typedef struct {
    int source_color[3];
    int source_alpha[3];
    int operand_color[3];
    int operand_alpha[3];
    int combiner_color;
    int combiner_alpha;
    int scale_color;
    int scale_alpha;
    int constant_selector;
    double constant[4];
    int update_color_buffer;
    int update_alpha_buffer;
} CgfxTexEnvStage;

typedef struct {
    int has_texenv;
    CgfxTexEnvStage stages[6];
    double buffer_color[4];
    double emission[4];
    double ambient[4];
    double diffuse[4];
    double specular0[4];
    double specular1[4];
    double constant_colors[6][4];
    double tex_scale[3][2];
    double tex_rotation[3];
    double tex_translate[3][2];
    int tex_transform_type[3];
    int tex_source_coord[3];
    int tex_mapping_type[3];
    int has_texcoord[3];
} CgfxMaterial;

typedef struct {
    CgfxMesh *meshes;
    int mesh_count;
    CgfxBone *bones;
    int bone_count;
    int has_skeleton;
    Image texture;
    int has_texture;
    Image mask_texture;
    int has_mask_texture;
    Image normal_texture;
    int has_normal_texture;
    CgfxMaterial material;
    CgfxMaterial *materials;
    int material_count;
    uint32_t average_color;
    Vec3 min;
    Vec3 max;
} CgfxModel;

typedef struct {
    Vec3 hair;
    Vec3 nose;
    Vec3 beard;
    Vec3 hat_angle[3];
    Vec3 hat_position[3];
} CflPartsTransform;

typedef struct {
    int head_type;
    int hair_index;
    int has_offset;
    double offset[6];
    int variant_count;
    int variant_hair_index[16];
    int variant_has_offset[16];
    double variant_offset[16][6];
} HeadwearMetadata;

typedef struct {
    double scale_x;
    double scale_y;
    double scale_z;
    double translate_x;
    double translate_y;
    double translate_z;
    int has_matrix;
    double matrix[12];
    int mirror_x;
} ShapeTransform;

typedef struct {
    Image *image;
    double *depth;
    double center_x;
    double base_y;
    double scale;
    int perspective;
    double focal_length;
    double camera_y;
    double camera_z;
    double world_scale;
    double world_origin_x;
    double world_origin_y;
    double world_origin_z;
} MeshCanvas;

/*
 * BodyUtilities.attachHeadToBody() uses 0.1 * (10 / 7), exactly 1 / 7,
 * for the FFL head's world scale. This renderer keeps the head in native FFL
 * coordinates and scales the physical body into those same coordinates, so
 * the full-body camera uses that source-backed bridge at projection time.
 */
static const double tomodachi_head_to_body_world_scale = 1.0 / 7.0;

static void mesh_canvas_set_orthographic(MeshCanvas *canvas,
    double center_x, double base_y, double scale) {
    canvas->center_x = center_x;
    canvas->base_y = base_y;
    canvas->scale = scale;
    canvas->perspective = 0;
    canvas->focal_length = 0.0;
    canvas->camera_y = 0.0;
    canvas->camera_z = 0.0;
    canvas->world_scale = 1.0;
    canvas->world_origin_x = 0.0;
    canvas->world_origin_y = 0.0;
    canvas->world_origin_z = 0.0;
}

static void mesh_canvas_set_whole_body_camera(MeshCanvas *canvas,
    int width, int height, int mii_height) {
    const double y_factor_1 = 10.85;
    const double y_factor_2 = 90.0;
    const double coefficient_z_min = 0.85;
    const double coefficient_z_max = 1.32;
    double clamped_height = mii_height;
    double height_factor;
    double z;

    if (clamped_height < 0.0) clamped_height = 0.0;
    if (clamped_height > 127.0) clamped_height = 127.0;
    height_factor = (clamped_height / 127.0 - 0.5) * 2.0;
    z = ((coefficient_z_max + coefficient_z_min) * 0.5 - 1.0) *
        height_factor * height_factor +
        (coefficient_z_max - coefficient_z_min) * 0.5 * height_factor + 1.0;

    canvas->center_x = width * 0.5;
    canvas->base_y = height * 0.5;
    canvas->scale = 1.0;
    canvas->perspective = 1;
    canvas->focal_length = (height * 0.5) / tan(15.0 * M_PI / 360.0);
    canvas->camera_y = y_factor_1 *
        (clamped_height / 64.0 * 0.15 + 0.85);
    canvas->camera_z = z * y_factor_2;
    canvas->world_scale = tomodachi_head_to_body_world_scale;
    canvas->world_origin_x = 0.0;
    canvas->world_origin_y = 0.0;
    canvas->world_origin_z = 0.0;
}

static void mesh_canvas_set_world_origin(MeshCanvas *canvas, Vec3 origin) {
    if (!canvas || !canvas->perspective) return;
    canvas->world_origin_x = origin.x;
    canvas->world_origin_y = origin.y;
    canvas->world_origin_z = origin.z;
}

static int mesh_canvas_project(const MeshCanvas *canvas, Vec3 world,
    double *screen_x, double *screen_y, double *reciprocal_w) {
    if (!canvas || !screen_x || !screen_y || !reciprocal_w) return 0;
    if (!canvas->perspective) {
        *screen_x = canvas->center_x + world.x * canvas->scale;
        *screen_y = canvas->base_y - world.y * canvas->scale;
        *reciprocal_w = 1.0;
        return 1;
    }
    {
        double view_x = (world.x - canvas->world_origin_x) * canvas->world_scale;
        double view_y = (world.y - canvas->world_origin_y) * canvas->world_scale -
            canvas->camera_y;
        double view_z = (world.z - canvas->world_origin_z) * canvas->world_scale;
        double distance = canvas->camera_z - view_z;
        if (distance <= 0.000001) return 0;
        *reciprocal_w = 1.0 / distance;
        *screen_x = canvas->center_x +
            canvas->focal_length * view_x * *reciprocal_w;
        *screen_y = canvas->base_y -
            canvas->focal_length * view_y * *reciprocal_w;
        return 1;
    }
}

static int mesh_canvas_correct_barycentrics(const MeshCanvas *canvas,
    double reciprocal_w0, double reciprocal_w1, double reciprocal_w2,
    double *weight0, double *weight1, double *weight2) {
    double denominator;
    if (!canvas || !canvas->perspective) return 1;
    denominator = *weight0 * reciprocal_w0 +
        *weight1 * reciprocal_w1 + *weight2 * reciprocal_w2;
    if (fabs(denominator) <= 1.0e-20) return 0;
    *weight0 = *weight0 * reciprocal_w0 / denominator;
    *weight1 = *weight1 * reciprocal_w1 / denominator;
    *weight2 = *weight2 * reciprocal_w2 / denominator;
    return 1;
}

typedef struct {
    double x;
    double y;
    double width;
    double height;
} RawMaskPart;

typedef struct {
    double x;
    double y;
    double scale_x;
    double scale_y;
    double rotation;
    int origin;
} RawMaskDesc;

typedef struct {
    int mirror_x;
    double rotation;
    int target_width;
    int target_height;
    int mode;
    int mirror_repeat_x;
    uint32_t colors[3];
} OverlayOptions;

typedef struct {
    double ambient[3];
    double diffuse[3];
    double specular[3];
    double specular_power;
    int specular_mode;
} ShaderMaterial;

typedef struct {
    int gender;
    int favorite_color;
    int height;
    int weight;

    int face_color;
    int face_type;
    int face_feature;
    int face_makeup;
    int hair_type;
    int hair_flipped;
    int hair_color;
    int hair_dye_color;
    int hair_dye_mode;

    int eye_type;
    int eye_color;
    int eye_size;
    int eye_squash;
    int eye_rotation;
    int eye_distance;
    int eye_y;

    int eyebrow_type;
    int eyebrow_color;
    int eyebrow_size;
    int eyebrow_squash;
    int eyebrow_rotation;
    int eyebrow_distance;
    int eyebrow_y;

    int nose_type;
    int nose_size;
    int nose_y;

    int mouth_type;
    int mouth_color;
    int mouth_size;
    int mouth_squash;
    int mouth_y;

    int mustache_type;
    int mustache_size;
    int mustache_y;

    int beard_type;
    int beard_color;

    int glasses_type;
    int glasses_color;
    int glasses_size;
    int glasses_y;

    int mole_on;
    int mole_size;
    int mole_x;
    int mole_y;

    int body_index;
    int body_color;
    int headwear_index;
    int headwear_color;
    int draw_body;
    int draw_headwear;
    int full_body;
} MiiFaceParams;

enum {
    MOD_TINT = 0,
    MOD_TEXTURE = 1,
    MOD_MODE2 = 2,
    MOD_MODE3 = 3,
    MOD_MODE4 = 4,
    MOD_MODE5 = 5
};

enum {
    BLEND_SOURCE_OVER = 0,
    BLEND_RAW_MASK_FIRST_PASS = 1,
    BLEND_RAW_MASK_SECOND_PASS = 2
};

enum {
    RAW_MASK_ORIGIN_CENTER = 0,
    RAW_MASK_ORIGIN_RIGHT = 1,
    RAW_MASK_ORIGIN_LEFT = 2
};

enum {
    CGFX_IMAGE_SOLID = 0,
    CGFX_IMAGE_DIRECT = 1,
    CGFX_IMAGE_ALPHA_MASK = 2,
    CGFX_IMAGE_RED_OPAQUE = 3,
    CGFX_IMAGE_DIRECT_MODULATE = 4
};

enum {
    SHADER_SPECULAR_NORMAL = 0,
    SHADER_SPECULAR_ANISOTROPIC = 1
};

enum {
    SHADER_MAT_NONE = -1,
    SHADER_MAT_FACELINE = 0,
    SHADER_MAT_BEARD = 1,
    SHADER_MAT_NOSE = 2,
    SHADER_MAT_FOREHEAD = 3,
    SHADER_MAT_HAIR = 4,
    SHADER_MAT_CAP = 5,
    SHADER_MAT_MASK = 6,
    SHADER_MAT_NOSELINE = 7,
    SHADER_MAT_GLASS = 8,
    SHADER_MAT_BODY = 9,
    SHADER_MAT_PANTS = 10,
    SHADER_MAT_COUNT = 11
};

static const uint32_t mii_skin_colors[] = {
    0xffd3ad, 0xffb66b, 0xde7942, 0xffaa8c, 0xad5129,
    0x632c18, 0xffbea5, 0xffc58f, 0x8c3c23, 0x3c2d23
};
static const uint32_t mii_favorite_colors[] = {
    0xd21e14, 0xff6e19, 0xffd820, 0x78d220, 0x007830, 0x0a48b4,
    0x3caae0, 0xf55a7d, 0x7328ad, 0x483818, 0xe0e0e0, 0x181814
};
static const uint32_t mii_common_colors[] = {
    0x2d2828, 0x402010, 0x5c180a, 0x7c3a14, 0x787880, 0x4e3e10,
    0x885818, 0xd0a04a, 0x000000, 0x6c7070, 0x663c2c, 0x605e30,
    0x4654a8, 0x387058, 0x603810, 0xa81008, 0x203068, 0xa86000,
    0x787068, 0xd85208, 0xf00c08, 0xf54848, 0xf09a74, 0x8c5040,
    0x842626, 0xff7366, 0xffa6a6, 0xffc0ba, 0x732e3b, 0x991f3d,
    0x8a173e, 0xb53e42, 0xc71e56, 0xb05381, 0xc7546e, 0xfa7597,
    0xfcacc9, 0xffc9d8, 0x311c40, 0x37283d, 0x4c184d, 0x6f42b3,
    0x855cb8, 0xc083cc, 0xa893c9, 0xc5ace6, 0xeebefa, 0xd2c5ed,
    0x191f40, 0x123f66, 0x2a82d4, 0x57b4f2, 0x7ac5de, 0x89a6fa,
    0x84bdfa, 0xa1e3ff, 0x0b2e36, 0x013d3b, 0x0d4f59, 0x236663,
    0x307e8c, 0x4faeb0, 0x7ac49e, 0x7fd4c0, 0x87e5b6, 0x0a4a35,
    0x437a00, 0x027562, 0x369970, 0x4bad1a, 0x92bf0a, 0x63c788,
    0x9ee042, 0x96de7e, 0xbbf2aa, 0x99932b, 0xa69563, 0xccc039,
    0xccb987, 0xd9cc82, 0xd5d96f, 0xd5e683, 0xd8fa9d, 0x7d4500,
    0xe6bb7a, 0xfee24a, 0xfade82, 0xf7ea9c, 0xfaf89b, 0xa64d1e,
    0xff960d, 0xd19b69, 0xffb266, 0xffc28c, 0xe5cfb1, 0x414141,
    0x9b9b9b, 0xbebebe, 0xdcd7cd, 0xffffff
};

/* Exact sRGB UpperLipColorTable from the decomp's FFL Switch color reference. */
static const uint32_t mii_upper_lip_colors[] = {
    0x171414, 0x201008, 0x2e0c05, 0x4a230c, 0x54545a, 0x271f08,
    0x52350e, 0xb18028, 0x000000, 0x4c4e4e, 0x331e16, 0x3a381d,
    0x2a3265, 0x274e3e, 0x301c08, 0x650a05, 0x101834, 0x764300,
    0x544e49, 0x823018, 0x780c0c, 0x882028, 0xdc7850, 0x461e0a,
    0x4f1717, 0x99453d, 0xe68585, 0xe6a19b, 0x451c23, 0x5c1325,
    0x530e25, 0x6d2528, 0x771234, 0x6a324d, 0x773242, 0xaf526a,
    0xe38cac, 0xe6abbb, 0x190e20, 0x1c141f, 0x260c27, 0x43286b,
    0x50376e, 0x865c8f, 0x76678d, 0xab90cf, 0xd4a0e1, 0xb8aad5,
    0x0d1020, 0x092033, 0x1d5b94, 0x3297da, 0x5cadc8, 0x6786e1,
    0x629fe1, 0x80c7e6, 0x06171b, 0x011f1e, 0x07282d, 0x184745,
    0x225862, 0x308b8d, 0x60b087, 0x63bfa9, 0x69ce9b, 0x05251b,
    0x284900, 0x01463b, 0x266b4e, 0x2c8a00, 0x6e9900, 0x47b36f,
    0x82ca1f, 0x7ac860, 0x9eda8c, 0x6b671e, 0x746845, 0xa39816,
    0xb8a36d, 0xc3b565, 0xbfc351, 0xbdcf64, 0xbce17d, 0x4b2900,
    0xcfa15a, 0xe5c622, 0xe1c35f, 0xded07c, 0xe1df7a, 0x642e12,
    0xcc780a, 0xbc824c, 0xe69240, 0xe6a469, 0xceb696, 0x212121,
    0x7c7c7c, 0xababab, 0xc6c1b6, 0xd9d9d9
};

/*
 * Tomodachi Life stores temporary hair-dye state in InternalMii::rng_seed:
 * bits 25..29 select this 32-entry palette and bits 30..31 select the mode.
 * The decomp reads a runtime table at 0xb64fec for this palette. That table
 * lives in BSS, but its order matches the hair-dye menu and these RGB values
 * come from the local Clothes color table used by the game.
 */
static const uint32_t tomodachi_hair_dye_colors[] = {
    0xe0ffff, 0x87cefa, 0x00bfff, 0x0066ff,
    0x323296, 0x0000ff, 0x008b8b, 0x00ced1,
    0x00ffff, 0x98fb98, 0x00ff00, 0x3cb371,
    0x006400, 0xffec65, 0xffff00, 0xffdab9,
    0xffa500, 0xff6600, 0xff0000, 0xcb0f0f,
    0x8b0000, 0xff1493, 0xff82ab, 0xffc0cb,
    0x4b0082, 0x9933ff, 0xdda0dd, 0x8b008b,
    0x333333, 0xd3d3d3, 0xa9a9a9, 0xffffff
};

static const ShaderMaterial shader_materials[SHADER_MAT_COUNT] = {
    { { 0.85, 0.75, 0.75 }, { 0.75, 0.75, 0.75 }, { 0.30, 0.30, 0.30 }, 1.2, SHADER_SPECULAR_NORMAL },
    { { 1.00, 1.00, 1.00 }, { 0.70, 0.70, 0.70 }, { 0.00, 0.00, 0.00 }, 40.0, SHADER_SPECULAR_NORMAL },
    { { 0.90, 0.85, 0.85 }, { 0.75, 0.75, 0.75 }, { 0.22, 0.22, 0.22 }, 1.5, SHADER_SPECULAR_NORMAL },
    { { 0.85, 0.75, 0.75 }, { 0.75, 0.75, 0.75 }, { 0.30, 0.30, 0.30 }, 1.2, SHADER_SPECULAR_NORMAL },
    { { 1.00, 1.00, 1.00 }, { 0.70, 0.70, 0.70 }, { 0.35, 0.35, 0.35 }, 10.0, SHADER_SPECULAR_ANISOTROPIC },
    { { 0.75, 0.75, 0.75 }, { 0.72, 0.72, 0.72 }, { 0.30, 0.30, 0.30 }, 1.5, SHADER_SPECULAR_NORMAL },
    { { 1.00, 1.00, 1.00 }, { 0.70, 0.70, 0.70 }, { 0.00, 0.00, 0.00 }, 40.0, SHADER_SPECULAR_ANISOTROPIC },
    { { 1.00, 1.00, 1.00 }, { 0.70, 0.70, 0.70 }, { 0.00, 0.00, 0.00 }, 40.0, SHADER_SPECULAR_ANISOTROPIC },
    { { 1.00, 1.00, 1.00 }, { 0.70, 0.70, 0.70 }, { 0.00, 0.00, 0.00 }, 40.0, SHADER_SPECULAR_ANISOTROPIC },
    { { 0.95622, 0.95622, 0.95622 }, { 0.496733, 0.496733, 0.496733 }, { 0.2409, 0.2409, 0.2409 }, 3.0, SHADER_SPECULAR_NORMAL },
    { { 0.95622, 0.95622, 0.95622 }, { 1.084967, 1.084967, 1.084967 }, { 0.2409, 0.2409, 0.2409 }, 3.0, SHADER_SPECULAR_NORMAL }
};

static const double shader_light_ambient[3] = { 0.73, 0.73, 0.73 };
static const double shader_light_diffuse[3] = { 0.60, 0.60, 0.60 };
static const double shader_light_specular[3] = { 0.70, 0.70, 0.70 };
static const Vec3 shader_light_dir = { -0.4531539381, 0.4226179123, 0.7848858833 };
static const double shader_rim_color[3] = { 0.30, 0.30, 0.30 };
static const double shader_rim_color_body[3] = { 0.40, 0.40, 0.40 };
static const double shader_rim_power = 2.0;

static const int eye_rotation_neutral[] = {
    3, 4, 4, 4, 3, 4, 4, 4, 3, 4, 4, 4, 4, 3, 3, 4,
    4, 4, 3, 3, 4, 3, 4, 3, 3, 4, 3, 4, 4, 3, 4, 4,
    4, 3, 3, 3, 4, 4, 3, 3, 3, 4, 4, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 4, 4, 4, 4, 3, 4, 4, 3, 4, 4
};

static const int eyebrow_rotation_neutral[] = {
    6, 6, 5, 7, 6, 7, 6, 7, 4, 7, 6, 8,
    5, 5, 6, 6, 7, 7, 6, 6, 5, 6, 7, 5
};

static uint16_t rd_u16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static int16_t rd_i16(const uint8_t *p) {
    return (int16_t)rd_u16(p);
}

static uint32_t rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] |
        ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) |
        ((uint32_t)p[3] << 24);
}

static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
        ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) |
        (uint32_t)p[3];
}

static int32_t rd_i32(const uint8_t *p) {
    return (int32_t)rd_u32(p);
}

static float rd_f32(const uint8_t *p) {
    uint32_t bits = rd_u32(p);
    float value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static int checked_range(size_t size, size_t offset, size_t length) {
    return offset <= size && length <= size - offset;
}

static int read_file(const char *path, Buffer *out) {
    FILE *fp = fopen(path, "rb");
    long size;
    size_t got;

    memset(out, 0, sizeof(*out));
    if (!fp) {
        fprintf(stderr, "Could not open %s: %s\n", path, strerror(errno));
        return 0;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 0;
    }
    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return 0;
    }
    rewind(fp);

    out->data = (uint8_t *)malloc((size_t)size);
    if (!out->data) {
        fclose(fp);
        return 0;
    }
    got = fread(out->data, 1, (size_t)size, fp);
    fclose(fp);

    if (got != (size_t)size) {
        free(out->data);
        memset(out, 0, sizeof(*out));
        return 0;
    }
    out->size = (size_t)size;
    return 1;
}

static void put_u16_le(uint8_t *dst, uint16_t value) {
    dst[0] = (uint8_t)(value & 0xffu);
    dst[1] = (uint8_t)(value >> 8);
}

static void put_u32_le(uint8_t *dst, uint32_t value) {
    dst[0] = (uint8_t)(value & 0xffu);
    dst[1] = (uint8_t)((value >> 8) & 0xffu);
    dst[2] = (uint8_t)((value >> 16) & 0xffu);
    dst[3] = (uint8_t)((value >> 24) & 0xffu);
}

static int write_tga(const char *path, const Image *image) {
    FILE *fp = fopen(path, "wb");
    uint8_t header[18];
    int x, y;

    if (!fp) {
        fprintf(stderr, "Could not write %s: %s\n", path, strerror(errno));
        return 0;
    }
    memset(header, 0, sizeof(header));
    header[2] = 2;
    header[12] = (uint8_t)(image->width & 0xff);
    header[13] = (uint8_t)((image->width >> 8) & 0xff);
    header[14] = (uint8_t)(image->height & 0xff);
    header[15] = (uint8_t)((image->height >> 8) & 0xff);
    header[16] = 32;
    header[17] = 0x28;
    fwrite(header, 1, sizeof(header), fp);
    for (y = 0; y < image->height; y++) {
        for (x = 0; x < image->width; x++) {
            const uint8_t *src = image->rgba + (size_t)(y * image->width + x) * 4u;
            uint8_t bgra[4] = { src[2], src[1], src[0], src[3] };
            fwrite(bgra, 1, sizeof(bgra), fp);
        }
    }
    fclose(fp);
    return 1;
}

static int write_bmp(const char *path, const Image *image) {
    FILE *fp = fopen(path, "wb");
    uint8_t header[54];
    uint32_t pixel_bytes = (uint32_t)image->width * (uint32_t)image->height * 4u;
    uint32_t file_size = 54u + pixel_bytes;
    int x, y;

    if (!fp) {
        fprintf(stderr, "Could not write %s: %s\n", path, strerror(errno));
        return 0;
    }

    memset(header, 0, sizeof(header));
    header[0] = 'B';
    header[1] = 'M';
    put_u32_le(header + 2, file_size);
    put_u32_le(header + 10, 54);
    put_u32_le(header + 14, 40);
    put_u32_le(header + 18, (uint32_t)image->width);
    put_u32_le(header + 22, (uint32_t)(-image->height));
    put_u16_le(header + 26, 1);
    put_u16_le(header + 28, 32);
    put_u32_le(header + 34, pixel_bytes);

    if (fwrite(header, 1, sizeof(header), fp) != sizeof(header)) {
        fclose(fp);
        return 0;
    }

    for (y = 0; y < image->height; y++) {
        for (x = 0; x < image->width; x++) {
            size_t src = ((size_t)y * (size_t)image->width + (size_t)x) * 4u;
            uint8_t bgra[4] = {
                image->rgba[src + 2],
                image->rgba[src + 1],
                image->rgba[src + 0],
                image->rgba[src + 3]
            };
            if (fwrite(bgra, 1, 4, fp) != 4) {
                fclose(fp);
                return 0;
            }
        }
    }

    fclose(fp);
    return 1;
}

static int ends_with_ci(const char *text, const char *suffix) {
    size_t text_len = strlen(text);
    size_t suffix_len = strlen(suffix);
    size_t i;
    if (suffix_len > text_len) return 0;
    text += text_len - suffix_len;
    for (i = 0; i < suffix_len; i++) {
        if (tolower((unsigned char)text[i]) != tolower((unsigned char)suffix[i])) return 0;
    }
    return 1;
}

static int write_image(const char *path, const Image *image) {
    if (ends_with_ci(path, ".bmp")) return write_bmp(path, image);
    return write_tga(path, image);
}

static int cfl_parse(CflResource *resource, const uint8_t *bytes, size_t size) {
    uint32_t header_size;
    uint32_t i;

    memset(resource, 0, sizeof(*resource));
    if (!checked_range(size, 4, 4)) return 0;
    header_size = rd_u32(bytes + 4);
    if (header_size < 8 || header_size > size || ((header_size - 4) % 4) != 0) return 0;

    resource->bytes = bytes;
    resource->size = size;
    resource->offset_count = (header_size - 4) / 4;
    resource->offsets = (uint32_t *)calloc(resource->offset_count, sizeof(uint32_t));
    if (!resource->offsets) return 0;

    for (i = 0; i < resource->offset_count; i++) {
        resource->offsets[i] = rd_u32(bytes + 4 + i * 4u);
    }
    return 1;
}

static void cfl_free(CflResource *resource) {
    free(resource->offsets);
    memset(resource, 0, sizeof(*resource));
}

static int cfl_record_bounds(const CflResource *resource, int section_index, int item_index,
    size_t *record_offset, size_t *record_end) {
    uint32_t section;
    uint32_t count;
    uint32_t index;
    int guard;
    size_t records_base;
    uint32_t rel;
    uint32_t end_rel;

    if (section_index < 0 || (uint32_t)section_index >= resource->offset_count) return 0;
    section = resource->offsets[section_index];
    if (!checked_range(resource->size, section, 8)) return 0;

    count = rd_u16(resource->bytes + section);
    if (count == 0) return 0;
    index = (uint32_t)item_index;
    if (item_index < 0) index = 0;
    if (index >= count) index = count - 1;

    records_base = (size_t)section + 8u + (size_t)count * 4u;
    if (!checked_range(resource->size, records_base, 0)) return 0;

    for (guard = 0; guard < 16; guard++) {
        size_t table = (size_t)section + 4u + (size_t)index * 4u;
        size_t next_table = (size_t)section + 4u + (size_t)(index + 1u) * 4u;
        uint32_t entry;
        uint32_t next_entry;
        uint32_t redirect;

        if (!checked_range(resource->size, table, 4) ||
            !checked_range(resource->size, next_table, 4)) {
            return 0;
        }

        entry = rd_u32(resource->bytes + table);
        next_entry = rd_u32(resource->bytes + next_table);
        rel = entry & CFL_RECORD_OFFSET_MASK;
        end_rel = next_entry & CFL_RECORD_OFFSET_MASK;
        redirect = entry >> 22;

        if (redirect != 0 && rel == end_rel) {
            index = redirect - 1u;
            if (index >= count) return 0;
            continue;
        }
        break;
    }
    if (guard >= 16) return 0;

    rel = rd_u32(resource->bytes + (size_t)section + 4u + (size_t)index * 4u) & CFL_RECORD_OFFSET_MASK;
    *record_offset = records_base + rel;
    if (index + 1 < count) {
        size_t next_table = (size_t)section + 4u + (size_t)(index + 1u) * 4u;
        if (!checked_range(resource->size, next_table, 4)) return 0;
        end_rel = rd_u32(resource->bytes + next_table) & CFL_RECORD_OFFSET_MASK;
    } else {
        size_t end_table = (size_t)section + 4u + (size_t)count * 4u;
        if (!checked_range(resource->size, end_table, 4)) return 0;
        end_rel = rd_u32(resource->bytes + end_table) & CFL_RECORD_OFFSET_MASK;
    }
    *record_end = records_base + end_rel;
    return *record_offset <= *record_end && *record_end <= resource->size;
}

static uint8_t expand4(unsigned value) {
    return (uint8_t)((value & 0x0fu) * 0x11u);
}

static uint8_t expand5(unsigned value) {
    value &= 0x1fu;
    return (uint8_t)((value << 3) | (value >> 2));
}

static uint8_t expand6(unsigned value) {
    value &= 0x3fu;
    return (uint8_t)((value << 2) | (value >> 4));
}

static int next_power_of_two(int value) {
    int out = 1;
    while (out < value) out <<= 1;
    return out;
}

static void storage_dimensions(int width, int height, size_t payload_bytes, double bytes_per_pixel,
    int *storage_width, int *storage_height) {
    int pixel_count = (int)floor((double)payload_bytes / bytes_per_pixel);
    int sw = next_power_of_two(width);
    int sh;

    if (sw < 8) sw = 8;
    sh = (pixel_count + sw - 1) / sw;
    if (sh < 8) sh = 8;

    if (sw < 64 && sh > next_power_of_two(height)) {
        if (pixel_count % 64 == 0) {
            int square_height = pixel_count / 64;
            if (square_height >= height && (square_height % 8) == 0) {
                sw = 64;
                sh = square_height;
            }
        }
    }

    *storage_width = ((sw + 7) / 8) * 8;
    *storage_height = ((sh + 7) / 8) * 8;
}

static double texture_bpp(int format) {
    switch (format) {
        case 0x00: return 0.5;
        case 0x01: return 3.0;
        case 0x02: return 0.5;
        case 0x03: return 2.0;
        case 0x04: return 1.0;
        case 0x05: return 2.0;
        case 0x07: return 1.0;
        case 0x08: return 1.0;
        case 0x09: return 1.0;
        case 0x0a: return 2.0;
        default: return 0.0;
    }
}

static void read_pixel(const uint8_t *bytes, int format, size_t offset, uint8_t out[4]) {
    uint16_t value;

    out[0] = out[1] = out[2] = 255;
    out[3] = 0;
    switch (format) {
        case 0x00:
            out[0] = out[1] = out[2] = expand4(bytes[offset] & 0x0fu);
            out[3] = 255;
            break;
        case 0x01:
            out[0] = bytes[offset + 0];
            out[1] = bytes[offset + 1];
            out[2] = bytes[offset + 2];
            out[3] = 255;
            break;
        case 0x02:
            value = rd_u16(bytes + offset);
            out[0] = expand5(value >> 11);
            out[1] = expand5(value >> 6);
            out[2] = expand5(value >> 1);
            out[3] = (value & 1) ? 255 : 0;
            break;
        case 0x03:
            value = rd_u16(bytes + offset);
            out[0] = expand5(value >> 11);
            out[1] = expand6(value >> 5);
            out[2] = expand5(value);
            out[3] = 255;
            break;
        case 0x04: {
            uint8_t packed = bytes[offset];
            uint8_t lum = expand4(packed >> 4);
            out[0] = out[1] = out[2] = lum;
            out[3] = expand4(packed);
            break;
        }
        case 0x05:
            out[0] = out[1] = out[2] = bytes[offset + 0];
            out[3] = bytes[offset + 1];
            break;
        case 0x07:
            out[0] = out[1] = out[2] = bytes[offset];
            out[3] = 255;
            break;
        case 0x08:
            out[0] = out[1] = out[2] = 255;
            out[3] = bytes[offset];
            break;
        case 0x09:
            out[0] = out[1] = out[2] = expand4(bytes[offset] >> 4);
            out[3] = expand4(bytes[offset]);
            break;
        case 0x0a:
            value = rd_u16(bytes + offset);
            out[0] = expand4(value >> 12);
            out[1] = expand4(value >> 8);
            out[2] = expand4(value >> 4);
            out[3] = expand4(value);
            break;
        default:
            break;
    }
}

static void read_tiled_mask_pixel(const uint8_t *bytes, int format, size_t tile_src,
    int pixel_in_tile, uint8_t out[4]) {
    if (format == 0x00 || format == 0x02) {
        uint8_t packed = bytes[tile_src + (size_t)(pixel_in_tile >> 1)];
        uint8_t value = (uint8_t)((pixel_in_tile & 1) ? (packed >> 4) : (packed & 0x0f));
        uint8_t l = expand4(value);
        out[0] = out[1] = out[2] = l;
        out[3] = 255;
    } else if (format == 0x0a) {
        size_t offset = tile_src + (size_t)pixel_in_tile * 2u;
        uint16_t value = rd_u16(bytes + offset);
        out[0] = expand4(value >> 12);
        out[1] = expand4(value >> 8);
        out[2] = expand4(value >> 4);
        out[3] = expand4(value);
    }
}

static int cfl_decode_texture(const CflResource *resource, int section_index, int item_index,
    CflTexture *out) {
    size_t record_offset;
    size_t record_end;
    size_t payload_bytes;
    double bpp;
    int storage_width;
    int storage_height;
    int tile_x, tile_y, morton;
    size_t src;

    memset(out, 0, sizeof(*out));
    if (!cfl_record_bounds(resource, section_index, item_index, &record_offset, &record_end)) return 0;
    if (!checked_range(resource->size, record_offset, 8)) return 0;

    out->width = rd_u16(resource->bytes + record_offset);
    out->height = rd_u16(resource->bytes + record_offset + 2);
    out->format = resource->bytes[record_offset + 5];
    bpp = texture_bpp(out->format);
    if (out->width <= 0 || out->height <= 0 || bpp <= 0.0) return 0;

    payload_bytes = record_end - record_offset - 8u;
    storage_dimensions(out->width, out->height, payload_bytes, bpp, &storage_width, &storage_height);

    out->rgba = (uint8_t *)calloc((size_t)out->width * (size_t)out->height * 4u, 1);
    if (!out->rgba) return 0;

    src = record_offset + 8u;
    for (tile_y = 0; tile_y < storage_height; tile_y += 8) {
        for (tile_x = 0; tile_x < storage_width; tile_x += 8) {
            size_t tile_src = src;
            for (morton = 0; morton < 64; morton++) {
                int bit;
                int x = 0;
                int y = 0;
                int dst_x;
                int dst_y;
                uint8_t pixel[4];

                for (bit = 0; bit < 3; bit++) {
                    x |= ((morton >> (bit * 2)) & 1) << bit;
                    y |= ((morton >> (bit * 2 + 1)) & 1) << bit;
                }
                dst_x = tile_x + x;
                dst_y = tile_y + y;

                if (out->format == 0x00 || out->format == 0x02 || out->format == 0x0a) {
                    read_tiled_mask_pixel(resource->bytes, out->format, tile_src, morton, pixel);
                } else {
                    read_pixel(resource->bytes, out->format, src, pixel);
                }
                if (out->format != 0x00 && out->format != 0x02) {
                    src += (size_t)bpp;
                }

                if (dst_x < out->width && dst_y < out->height) {
                    size_t dst = ((size_t)dst_y * (size_t)out->width + (size_t)dst_x) * 4u;
                    out->rgba[dst + 0] = pixel[0];
                    out->rgba[dst + 1] = pixel[1];
                    out->rgba[dst + 2] = pixel[2];
                    out->rgba[dst + 3] = pixel[3];
                }
            }
            if (out->format == 0x00 || out->format == 0x02) {
                src += 32u;
            }
        }
    }
    return 1;
}

static void cfl_texture_free(CflTexture *texture) {
    free(texture->rgba);
    memset(texture, 0, sizeof(*texture));
}

static void cfl_shape_free(CflShape *shape) {
    free(shape->vertices);
    free(shape->normals);
    free(shape->texcoords);
    free(shape->indices);
    memset(shape, 0, sizeof(*shape));
}

static int cfl_read_vec3(const CflResource *resource, size_t *cursor, size_t end, Vec3 *out) {
    if (!checked_range(resource->size, *cursor, 12) || *cursor + 12u > end) return 0;
    out->x = rd_f32(resource->bytes + *cursor);
    out->y = rd_f32(resource->bytes + *cursor + 4);
    out->z = rd_f32(resource->bytes + *cursor + 8);
    *cursor += 12u;
    return 1;
}

static int cfl_decode_shape(const CflResource *resource, int section_index, int item_index,
    CflShape *out) {
    size_t record_offset;
    size_t record_end;
    size_t cursor;
    uint16_t vertex_count;
    uint16_t normal_count;
    uint16_t texcoord_count;
    uint16_t index_flag;
    int i;

    memset(out, 0, sizeof(*out));
    if (!cfl_record_bounds(resource, section_index, item_index, &record_offset, &record_end)) return 0;
    cursor = record_offset;

    /* FFL accepts zero-sized records as intentionally empty parts.  They
       preserve the selected normal/cap family and are not decode failures. */
    if (record_offset == record_end) return 1;

    if (section_index == CFL_SHAPE_FACELINE) {
        out->extra_count = 3;
        for (i = 0; i < out->extra_count; i++) {
            if (!cfl_read_vec3(resource, &cursor, record_end, &out->extra[i])) {
                cfl_shape_free(out);
                return 0;
            }
        }
    } else if (section_index == CFL_SHAPE_HAIR) {
        out->extra_count = 6;
        for (i = 0; i < out->extra_count; i++) {
            if (!cfl_read_vec3(resource, &cursor, record_end, &out->extra[i])) {
                cfl_shape_free(out);
                return 0;
            }
        }
    }

    if (!checked_range(resource->size, cursor, 8) || cursor + 8u > record_end) return 0;
    vertex_count = rd_u16(resource->bytes + cursor);
    normal_count = rd_u16(resource->bytes + cursor + 2);
    texcoord_count = rd_u16(resource->bytes + cursor + 4);
    index_flag = rd_u16(resource->bytes + cursor + 6);
    cursor += 8u;

    if (vertex_count == 0) {
        return normal_count == 0 && texcoord_count == 0 && index_flag == 0;
    }
    if (normal_count != 0 && normal_count != 1 && normal_count != vertex_count) return 0;
    if (texcoord_count != 0 && texcoord_count != 1 && texcoord_count != vertex_count) return 0;

    out->vertex_count = vertex_count;
    out->normal_count = normal_count;
    out->texcoord_count = texcoord_count;
    out->vertices = (Vec3 *)calloc(vertex_count, sizeof(Vec3));
    if (!out->vertices) {
        cfl_shape_free(out);
        return 0;
    }
    if (normal_count) {
        out->normals = (Vec3 *)calloc(normal_count == 1 ? 1u : (size_t)vertex_count, sizeof(Vec3));
        if (!out->normals) {
            cfl_shape_free(out);
            return 0;
        }
    }
    if (texcoord_count) {
        out->texcoords = (Vec2 *)calloc(texcoord_count == 1 ? 1u : (size_t)vertex_count, sizeof(Vec2));
        if (!out->texcoords) {
            cfl_shape_free(out);
            return 0;
        }
    }

    for (i = 0; i < vertex_count; i++) {
        if (!checked_range(resource->size, cursor, 6) || cursor + 6u > record_end) {
            cfl_shape_free(out);
            return 0;
        }
        out->vertices[i].x = rd_i16(resource->bytes + cursor) / 256.0;
        out->vertices[i].y = rd_i16(resource->bytes + cursor + 2) / 256.0;
        out->vertices[i].z = rd_i16(resource->bytes + cursor + 4) / 256.0;
        cursor += 6u;

        if (normal_count == vertex_count) {
            if (!checked_range(resource->size, cursor, 6) || cursor + 6u > record_end) {
                cfl_shape_free(out);
                return 0;
            }
            out->normals[i].x = rd_i16(resource->bytes + cursor) / 256.0;
            out->normals[i].y = rd_i16(resource->bytes + cursor + 2) / 256.0;
            out->normals[i].z = rd_i16(resource->bytes + cursor + 4) / 256.0;
            cursor += 6u;
        }

        if (texcoord_count == vertex_count) {
            if (!checked_range(resource->size, cursor, 4) || cursor + 4u > record_end) {
                cfl_shape_free(out);
                return 0;
            }
            out->texcoords[i].x = rd_i16(resource->bytes + cursor) / 8192.0;
            out->texcoords[i].y = rd_i16(resource->bytes + cursor + 2) / 8192.0;
            cursor += 4u;
        }
    }

    if (normal_count == 1) {
        if (!checked_range(resource->size, cursor, 6) || cursor + 6u > record_end) {
            cfl_shape_free(out);
            return 0;
        }
        out->normals[0].x = rd_i16(resource->bytes + cursor) / 256.0;
        out->normals[0].y = rd_i16(resource->bytes + cursor + 2) / 256.0;
        out->normals[0].z = rd_i16(resource->bytes + cursor + 4) / 256.0;
        cursor += 6u;
    }

    if (texcoord_count == 1) {
        if (!checked_range(resource->size, cursor, 4) || cursor + 4u > record_end) {
            cfl_shape_free(out);
            return 0;
        }
        out->texcoords[0].x = rd_i16(resource->bytes + cursor) / 8192.0;
        out->texcoords[0].y = rd_i16(resource->bytes + cursor + 2) / 8192.0;
        cursor += 4u;
    }

    if (index_flag) {
        uint16_t command;
        uint16_t index_count;

        if (!checked_range(resource->size, cursor, 4) || cursor + 4u > record_end) {
            cfl_shape_free(out);
            return 0;
        }
        command = rd_u16(resource->bytes + cursor);
        index_count = rd_u16(resource->bytes + cursor + 2);
        cursor += 4u;
        if (command != 4 || index_count == 0 || !checked_range(resource->size, cursor, index_count) ||
            cursor + (size_t)index_count > record_end) {
            cfl_shape_free(out);
            return 0;
        }
        out->indices = (uint8_t *)malloc(index_count);
        if (!out->indices) {
            cfl_shape_free(out);
            return 0;
        }
        memcpy(out->indices, resource->bytes + cursor, index_count);
        out->index_count = index_count;
        cursor += index_count;
    }

    if (section_index == CFL_SHAPE_MASK && out->index_count > 0) {
        size_t extra_size = (size_t)(out->index_count / 3) * 2u;
        if (checked_range(resource->size, cursor, extra_size) && cursor + extra_size <= record_end) {
            cursor += extra_size;
        }
    }

    return 1;
}

static int clamp_int(int value, int min, int max) {
    if (value < min) return min;
    if (value > max) return max;
    return value;
}

static uint32_t palette_color(const uint32_t *palette, int count, int index, int fallback) {
    int safe = clamp_int(index, 0, count - 1);
    if (index < 0 || index >= count) safe = clamp_int(fallback, 0, count - 1);
    return palette[safe];
}

static uint32_t common_color(int index, uint32_t fallback) {
    int count = (int)(sizeof(mii_common_colors) / sizeof(mii_common_colors[0]));
    if (index >= 0 && index < count) return mii_common_colors[index];
    return fallback;
}

static uint32_t mii_hair_color(int index, int fallback) {
    return common_color(index, common_color(fallback, mii_common_colors[1]));
}

static int tomodachi_has_valid_hair_dye(const MiiFaceParams *params) {
    return params && params->hair_dye_color >= 0 && params->hair_dye_color < 32;
}

static uint32_t tomodachi_hair_dye_color(const MiiFaceParams *params) {
    return palette_color(tomodachi_hair_dye_colors, 32, params->hair_dye_color, 0);
}

static uint32_t mii_render_hair_color(const MiiFaceParams *params, int index, int fallback) {
    if (tomodachi_has_valid_hair_dye(params) &&
        (params->hair_dye_mode == 1 || params->hair_dye_mode == 2)) {
        return tomodachi_hair_dye_color(params);
    }
    return mii_hair_color(index, fallback);
}

static uint32_t mii_render_eyebrow_color(const MiiFaceParams *params, int index, int fallback) {
    if (tomodachi_has_valid_hair_dye(params) && params->hair_dye_mode == 2) {
        return tomodachi_hair_dye_color(params);
    }
    return mii_hair_color(index, fallback);
}

static uint32_t mii_render_facial_hair_color(const MiiFaceParams *params, int index, int fallback) {
    if (tomodachi_has_valid_hair_dye(params) && params->hair_dye_mode == 2) {
        return tomodachi_hair_dye_color(params);
    }
    return mii_hair_color(index, fallback);
}

static uint32_t mii_eye_color(int index, int fallback) {
    return common_color(index, common_color(fallback, mii_common_colors[8]));
}

static uint32_t mii_glasses_color(int index, int fallback) {
    return common_color(index, common_color(fallback, mii_common_colors[8]));
}

static uint32_t mii_skin_color(int index) {
    int count = (int)(sizeof(mii_skin_colors) / sizeof(mii_skin_colors[0]));
    return palette_color(mii_skin_colors, count, index, 0);
}

static void mouth_colors(int index, uint32_t *lower, uint32_t *upper) {
    int upper_count = (int)(sizeof(mii_upper_lip_colors) / sizeof(mii_upper_lip_colors[0]));
    *lower = common_color(index, mii_common_colors[19]);
    *upper = palette_color(mii_upper_lip_colors, upper_count, index, 19);
}

static void color_to_unit(uint32_t color, double rgb[3]) {
    rgb[0] = ((color >> 16) & 0xff) / 255.0;
    rgb[1] = ((color >> 8) & 0xff) / 255.0;
    rgb[2] = (color & 0xff) / 255.0;
}

static double clamp_unit(double value) {
    if (value < 0.0) return 0.0;
    if (value > 1.0) return 1.0;
    return value;
}

static uint8_t max3(uint8_t a, uint8_t b, uint8_t c) {
    uint8_t m = a > b ? a : b;
    return m > c ? m : c;
}

static uint8_t min2(uint8_t a, uint8_t b) {
    return a < b ? a : b;
}

static double wrap_texture_coord(double coord, int mirrored) {
    if (coord < 0.0 || coord > 1.0) {
        int tile = (int)floor(coord);
        coord -= tile;
        if (coord < 0.0) coord += 1.0;
        if (mirrored && (tile & 1)) coord = 1.0 - coord;
    }
    return coord;
}

static uint8_t coverage_alpha(const CflTexture *texture, size_t offset) {
    uint8_t rgb_alpha = max3(texture->rgba[offset + 0], texture->rgba[offset + 1], texture->rgba[offset + 2]);
    switch (texture->format) {
        case 0x00:
        case 0x02:
        case 0x04:
        case 0x05:
        case 0x08:
        case 0x09:
        case 0x0a:
            return min2(texture->rgba[offset + 3], rgb_alpha ? rgb_alpha : texture->rgba[offset + 3]);
        default:
            return rgb_alpha;
    }
}

static void sample_modulated_pixel(const CflTexture *texture, size_t offset,
    uint32_t color, const OverlayOptions *options, uint8_t out[4]) {
    double r = texture->rgba[offset + 0] / 255.0;
    double g = texture->rgba[offset + 1] / 255.0;
    double b = texture->rgba[offset + 2] / 255.0;
    int mode = options ? options->mode : MOD_TINT;
    double tint[3];

    if (mode == MOD_TEXTURE) {
        out[0] = texture->rgba[offset + 0];
        out[1] = texture->rgba[offset + 1];
        out[2] = texture->rgba[offset + 2];
        out[3] = texture->rgba[offset + 3];
        return;
    }

    if (mode == MOD_MODE2) {
        double cr[3], cg[3], cb[3];
        color_to_unit(options->colors[0], cr);
        color_to_unit(options->colors[1], cg);
        color_to_unit(options->colors[2], cb);
        out[0] = (uint8_t)lrint(clamp_unit(cr[0] * r + cg[0] * g + cb[0] * b) * 255.0);
        out[1] = (uint8_t)lrint(clamp_unit(cr[1] * r + cg[1] * g + cb[1] * b) * 255.0);
        out[2] = (uint8_t)lrint(clamp_unit(cr[2] * r + cg[2] * g + cb[2] * b) * 255.0);
        out[3] = texture->rgba[offset + 3];
        return;
    }

    if (mode == MOD_MODE3) {
        double value = texture->rgba[offset + 0] / 255.0;
        color_to_unit(color, tint);
        /* FFLModulateParam mode 3 premultiplies tint RGB by texture R and
           also uses texture R as alpha. This matters for FFL's raw-mask
           blend, whose RGB equation does not multiply source alpha again. */
        out[0] = (uint8_t)lrint(tint[0] * value * 255.0);
        out[1] = (uint8_t)lrint(tint[1] * value * 255.0);
        out[2] = (uint8_t)lrint(tint[2] * value * 255.0);
        out[3] = texture->rgba[offset + 0];
        return;
    }

    if (mode == MOD_MODE4) {
        /* MiiJS's Decomp-backed sampleCflModulatedPixel and FFL MODE4 use
           texture G as tint intensity. Coverage comes from A only for the
           packed LA4 format; every other format, including FFL RG8 glass,
           uses texture R. Keep R/G distinct when importing FFL textures. */
        double alpha = texture->rgba[offset +
            (texture->format == 0x04 ? 3 : 0)] / 255.0;
        double value = texture->rgba[offset + 1] / 255.0;
        color_to_unit(color, tint);
        out[0] = (uint8_t)lrint(tint[0] * value * 255.0);
        out[1] = (uint8_t)lrint(tint[1] * value * 255.0);
        out[2] = (uint8_t)lrint(tint[2] * value * 255.0);
        out[3] = (uint8_t)lrint(alpha * 255.0);
        return;
    }

    if (mode == MOD_MODE5) {
        double value = texture->rgba[offset + 0] / 255.0;
        color_to_unit(color, tint);
        out[0] = (uint8_t)lrint(tint[0] * value * 255.0);
        out[1] = (uint8_t)lrint(tint[1] * value * 255.0);
        out[2] = (uint8_t)lrint(tint[2] * value * 255.0);
        out[3] = 255;
        return;
    }

    color_to_unit(color, tint);
    out[0] = (uint8_t)lrint(tint[0] * 255.0);
    out[1] = (uint8_t)lrint(tint[1] * 255.0);
    out[2] = (uint8_t)lrint(tint[2] * 255.0);
    out[3] = coverage_alpha(texture, offset);
}

static void blend_source_over(uint8_t *dst, const uint8_t src[4]) {
    double alpha = src[3] / 255.0;
    double existing_alpha;
    double out_alpha;

    if (alpha <= 0.0) return;
    existing_alpha = dst[3] / 255.0;
    out_alpha = alpha + existing_alpha * (1.0 - alpha);
    if (out_alpha <= 0.0) return;

    dst[0] = (uint8_t)lrint((src[0] * alpha + dst[0] * existing_alpha * (1.0 - alpha)) / out_alpha);
    dst[1] = (uint8_t)lrint((src[1] * alpha + dst[1] * existing_alpha * (1.0 - alpha)) / out_alpha);
    dst[2] = (uint8_t)lrint((src[2] * alpha + dst[2] * existing_alpha * (1.0 - alpha)) / out_alpha);
    dst[3] = (uint8_t)lrint(out_alpha * 255.0);
}

static uint8_t clamp_byte_from_double(double value) {
    if (value <= 0.0) return 0;
    if (value >= 255.0) return 255;
    return (uint8_t)lrint(value);
}

static void blend_raw_mask_first_pass(uint8_t *dst, const uint8_t src[4]) {
    double dst_alpha;

    if (src[3] == 0) return;
    dst_alpha = dst[3] / 255.0;
    dst[0] = clamp_byte_from_double(src[0] * (1.0 - dst_alpha) + dst[0] * dst_alpha);
    dst[1] = clamp_byte_from_double(src[1] * (1.0 - dst_alpha) + dst[1] * dst_alpha);
    dst[2] = clamp_byte_from_double(src[2] * (1.0 - dst_alpha) + dst[2] * dst_alpha);
    if (src[3] > dst[3]) dst[3] = src[3];
}

static void blend_raw_mask_second_pass(uint8_t *dst, const uint8_t src[4]) {
    double src_alpha;

    if (src[3] == 0) return;
    /* FFLiDrawRawMask keeps GX2_CHANNEL_MASK_A active for this pass and
       disables separate alpha blending. The color equation therefore applies
       to alpha: source alpha squared plus the accumulated destination alpha.
       RGB is not writable during this pass. */
    src_alpha = src[3] / 255.0;
    dst[3] = clamp_byte_from_double(src[3] * src_alpha + dst[3]);
}

static void blend_pixel(uint8_t *dst, const uint8_t src[4], int blend_mode) {
    switch (blend_mode) {
        case BLEND_RAW_MASK_FIRST_PASS:
            blend_raw_mask_first_pass(dst, src);
            break;
        case BLEND_RAW_MASK_SECOND_PASS:
            blend_raw_mask_second_pass(dst, src);
            break;
        default:
            blend_source_over(dst, src);
            break;
    }
}

static void overlay_texture_blend(Image *target, const CflTexture *texture, double cx, double cy,
    double width, double height, uint32_t color, const OverlayOptions *options, int blend_mode) {
    int target_width = options && options->target_width > 0 ? options->target_width : target->width;
    int target_height = options && options->target_height > 0 ? options->target_height : target->height;
    double rotation = options ? options->rotation : 0.0;
    double cosv = cos(-rotation);
    double sinv = sin(-rotation);
    double half_w = width / 2.0;
    double half_h = height / 2.0;
    int radius = (int)ceil((width > height ? width : height) * 0.75);
    int min_x = clamp_int((int)floor(cx - radius), 0, target_width - 1);
    int max_x = clamp_int((int)ceil(cx + radius), 0, target_width - 1);
    int min_y = clamp_int((int)floor(cy - radius), 0, target_height - 1);
    int max_y = clamp_int((int)ceil(cy + radius), 0, target_height - 1);
    int x, y;

    if (!texture || !texture->rgba || width <= 0.0 || height <= 0.0) return;

    for (y = min_y; y <= max_y; y++) {
        for (x = min_x; x <= max_x; x++) {
            double dx = x - cx;
            double dy = y - cy;
            double local_x = dx * cosv - dy * sinv;
            double local_y = dx * sinv + dy * cosv;
            int u, v;
            size_t src;
            size_t dst;
            uint8_t pixel[4];

            if (options && options->mirror_x) local_x = -local_x;
            if (local_x < -half_w || local_x > half_w || local_y < -half_h || local_y > half_h) continue;

            u = (int)floor(((local_x / width) + 0.5) * texture->width);
            v = (int)floor(((local_y / height) + 0.5) * texture->height);
            u = clamp_int(u, 0, texture->width - 1);
            v = clamp_int(v, 0, texture->height - 1);
            src = ((size_t)v * (size_t)texture->width + (size_t)u) * 4u;
            dst = ((size_t)y * (size_t)target_width + (size_t)x) * 4u;
            sample_modulated_pixel(texture, src, color, options, pixel);
            blend_pixel(target->rgba + dst, pixel, blend_mode);
        }
    }
}

static void overlay_texture(Image *target, const CflTexture *texture, double cx, double cy,
    double width, double height, uint32_t color, const OverlayOptions *options) {
    overlay_texture_blend(target, texture, cx, cy, width, height, color, options, BLEND_SOURCE_OVER);
}

static double edge_function(double ax, double ay, double bx, double by, double cx, double cy);

static void raw_mask_desc_vertices(const RawMaskDesc *desc,
    double x[4], double y[4], double u[4], double v[4]) {
    static const double pos_x[4] = { 1.0, 1.0, 0.0, 0.0 };
    static const double pos_y[4] = { -0.5, 0.5, 0.5, -0.5 };
    static const double tex_y[4] = { 0.0, 1.0, 1.0, 0.0 };
    const double tex_scale_x = 0.88961464;
    const double tex_scale_y = 0.9276675;
    double pos_x_add = 0.0;
    double tex_x_01 = 0.0;
    double tex_x_23 = 0.0;
    double c = cos(desc->rotation);
    double s = sin(desc->rotation);
    int i;

    switch (desc->origin) {
        case RAW_MASK_ORIGIN_CENTER:
            pos_x_add = -0.5;
            tex_x_01 = 1.0;
            break;
        case RAW_MASK_ORIGIN_RIGHT:
            tex_x_23 = 1.0;
            break;
        case RAW_MASK_ORIGIN_LEFT:
        default:
            pos_x_add = -1.0;
            tex_x_01 = 1.0;
            break;
    }

    for (i = 0; i < 4; i++) {
        double lx = (pos_x[i] + pos_x_add) * desc->scale_x;
        double ly = pos_y[i] * desc->scale_y;
        double rx = lx * c - ly * s;
        double ry = lx * s + ly * c;
        x[i] = desc->x + rx * tex_scale_x;
        y[i] = desc->y + ry * tex_scale_y;
        u[i] = i < 2 ? tex_x_01 : tex_x_23;
        v[i] = tex_y[i];
    }
}

static void draw_raw_mask_triangle(Image *target, const CflTexture *texture,
    double x0, double y0, double u0, double v0,
    double x1, double y1, double u1, double v1,
    double x2, double y2, double u2, double v2,
    uint32_t color, const OverlayOptions *options, int blend_mode) {
    double area = edge_function(x0, y0, x1, y1, x2, y2);
    int min_x, max_x, min_y, max_y;
    int x, y;

    if (!texture || !texture->rgba || fabs(area) < 0.0001) return;

    min_x = clamp_int((int)floor(fmin(x0, fmin(x1, x2))), 0, target->width - 1);
    max_x = clamp_int((int)ceil(fmax(x0, fmax(x1, x2))), 0, target->width - 1);
    min_y = clamp_int((int)floor(fmin(y0, fmin(y1, y2))), 0, target->height - 1);
    max_y = clamp_int((int)ceil(fmax(y0, fmax(y1, y2))), 0, target->height - 1);

    for (y = min_y; y <= max_y; y++) {
        for (x = min_x; x <= max_x; x++) {
            double px = x + 0.5;
            double py = y + 0.5;
            double w0 = edge_function(x1, y1, x2, y2, px, py) / area;
            double w1 = edge_function(x2, y2, x0, y0, px, py) / area;
            double w2 = edge_function(x0, y0, x1, y1, px, py) / area;
            double u;
            double v;
            int tx;
            int ty;
            size_t src;
            size_t dst;
            uint8_t pixel[4];

            if (w0 < -0.0001 || w1 < -0.0001 || w2 < -0.0001) continue;

            u = u0 * w0 + u1 * w1 + u2 * w2;
            v = v0 * w0 + v1 * w1 + v2 * w2;
            tx = clamp_int((int)floor(u * (texture->width - 1) + 0.5), 0, texture->width - 1);
            ty = clamp_int((int)floor(v * (texture->height - 1) + 0.5), 0, texture->height - 1);
            src = ((size_t)ty * (size_t)texture->width + (size_t)tx) * 4u;
            dst = ((size_t)y * (size_t)target->width + (size_t)x) * 4u;
            sample_modulated_pixel(texture, src, color, options, pixel);
            blend_pixel(target->rgba + dst, pixel, blend_mode);
        }
    }
}

static void overlay_raw_mask_desc_blend(Image *target, const CflTexture *texture,
    const RawMaskDesc *desc, uint32_t color, const OverlayOptions *options, int blend_mode) {
    double x[4], y[4], u[4], v[4];
    raw_mask_desc_vertices(desc, x, y, u, v);
    draw_raw_mask_triangle(target, texture,
        x[2], y[2], u[2], v[2],
        x[1], y[1], u[1], v[1],
        x[3], y[3], u[3], v[3],
        color, options, blend_mode);
    draw_raw_mask_triangle(target, texture,
        x[1], y[1], u[1], v[1],
        x[3], y[3], u[3], v[3],
        x[0], y[0], u[0], v[0],
        color, options, blend_mode);
}

static double raw_mask_unit(int texture_size) {
    return texture_size * (1.0 / 64.0);
}

static RawMaskDesc raw_mask_desc(int texture_size, double x, double y,
    double scale_x, double scale_y, int origin, double rotation, double min_height) {
    double unit = raw_mask_unit(texture_size);
    RawMaskDesc desc;
    desc.x = x * unit;
    desc.y = y * unit;
    desc.scale_x = scale_x * unit;
    desc.scale_y = scale_y * unit;
    if (desc.scale_y < min_height) desc.scale_y = min_height;
    desc.rotation = rotation;
    desc.origin = origin;
    return desc;
}

static RawMaskPart raw_mask_part(int texture_size, double x, double y,
    double width, double height, int origin, double min_height) {
    double unit = raw_mask_unit(texture_size);
    double final_width = width * unit * 0.88961464;
    double raw_height = height * unit;
    RawMaskPart part;

    if (raw_height < min_height) raw_height = min_height;
    part.x = x * unit;
    part.y = y * unit;
    part.width = final_width;
    part.height = raw_height * 0.9276675;
    if (origin < 0) part.x -= final_width / 2.0;
    else if (origin > 0) part.x += final_width / 2.0;
    return part;
}

static double raw_mask_rotation(int value, const int *neutral_by_type, int neutral_count,
    int type, int fallback_neutral) {
    int neutral = fallback_neutral;
    int ticks;

    if (type >= 0 && type < neutral_count) neutral = neutral_by_type[type];
    ticks = (value + 32 - neutral) % 32;
    return ticks * (M_PI * 2.0 / 32.0);
}

static double adjusted_eye_height(double height, int type) {
    return (type == 14 || type == 26) && height < 12.0 ? 12.0 : height;
}

static double adjusted_mouth_height(double height, int type) {
    switch (type) {
        case 3:
        case 15:
        case 19:
        case 20:
        case 21:
        case 23:
        case 25:
            return height < 12.0 ? 12.0 : height;
        default:
            return height;
    }
}

static int image_create(Image *image, int width, int height) {
    image->width = width;
    image->height = height;
    image->rgba = (uint8_t *)calloc((size_t)width * (size_t)height * 4u, 1);
    return image->rgba != NULL;
}

static void image_free(Image *image) {
    free(image->rgba);
    memset(image, 0, sizeof(*image));
}

static void image_fill(Image *image, uint32_t color) {
    uint8_t r = (uint8_t)((color >> 16) & 0xffu);
    uint8_t g = (uint8_t)((color >> 8) & 0xffu);
    uint8_t b = (uint8_t)(color & 0xffu);
    int i;
    for (i = 0; i < image->width * image->height; i++) {
        image->rgba[i * 4 + 0] = r;
        image->rgba[i * 4 + 1] = g;
        image->rgba[i * 4 + 2] = b;
        image->rgba[i * 4 + 3] = 255;
    }
}

static void fill_depth(double *depth, int count, double value) {
    int i;
    for (i = 0; i < count; i++) depth[i] = value;
}

static int file_exists(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    fclose(fp);
    return 1;
}

static void bounds_reset(Vec3 *min, Vec3 *max) {
    min->x = min->y = min->z = 1.0e30;
    max->x = max->y = max->z = -1.0e30;
}

static void bounds_include(Vec3 *min, Vec3 *max, Vec3 p) {
    if (p.x < min->x) min->x = p.x;
    if (p.y < min->y) min->y = p.y;
    if (p.z < min->z) min->z = p.z;
    if (p.x > max->x) max->x = p.x;
    if (p.y > max->y) max->y = p.y;
    if (p.z > max->z) max->z = p.z;
}

static int bounds_are_valid(Vec3 min, Vec3 max) {
    return min.x <= max.x && min.y <= max.y && min.z <= max.z;
}

static void mtx34_identity(double out[12]) {
    int i;
    for (i = 0; i < 12; i++) out[i] = 0.0;
    out[0] = 1.0;
    out[5] = 1.0;
    out[10] = 1.0;
}

static void mtx34_copy(double out[12], const double in[12]) {
    memcpy(out, in, sizeof(double) * 12u);
}

static void mtx34_read(const uint8_t *bytes, size_t offset, double out[12]) {
    int i;
    for (i = 0; i < 12; i++) {
        out[i] = rd_f32(bytes + offset + (size_t)i * 4u);
    }
}

static void mtx34_mul(double out[12], const double a[12], const double b[12]) {
    double r[12];
    int row;
    int col;
    for (row = 0; row < 3; row++) {
        for (col = 0; col < 3; col++) {
            r[row * 4 + col] =
                a[row * 4 + 0] * b[col + 0] +
                a[row * 4 + 1] * b[col + 4] +
                a[row * 4 + 2] * b[col + 8];
        }
        r[row * 4 + 3] =
            a[row * 4 + 0] * b[3] +
            a[row * 4 + 1] * b[7] +
            a[row * 4 + 2] * b[11] +
            a[row * 4 + 3];
    }
    mtx34_copy(out, r);
}

static Vec3 mtx34_transform_point(const double m[12], Vec3 p) {
    Vec3 out;
    out.x = m[0] * p.x + m[1] * p.y + m[2] * p.z + m[3];
    out.y = m[4] * p.x + m[5] * p.y + m[6] * p.z + m[7];
    out.z = m[8] * p.x + m[9] * p.y + m[10] * p.z + m[11];
    return out;
}

static Vec3 mtx34_transform_vector(const double m[12], Vec3 p) {
    Vec3 out;
    out.x = m[0] * p.x + m[1] * p.y + m[2] * p.z;
    out.y = m[4] * p.x + m[5] * p.y + m[6] * p.z;
    out.z = m[8] * p.x + m[9] * p.y + m[10] * p.z;
    return out;
}

static void mtx34_make_srt(double m[12], double sx, double sy, double sz, Vec3 r, Vec3 t) {
    double sin_x = sin(r.x);
    double sin_y = sin(r.y);
    double sin_z = sin(r.z);
    double cos_x = cos(r.x);
    double cos_y = cos(r.y);
    double cos_z = cos(r.z);

    m[0] = sx * (cos_y * cos_z);
    m[4] = sx * (cos_y * sin_z);
    m[8] = sx * -sin_y;

    m[1] = sy * (sin_x * sin_y * cos_z - cos_x * sin_z);
    m[5] = sy * (sin_x * sin_y * sin_z + cos_x * cos_z);
    m[9] = sy * (sin_x * cos_y);

    m[2] = sz * (cos_x * cos_z * sin_y + sin_x * sin_z);
    m[6] = sz * (cos_x * sin_z * sin_y - sin_x * cos_z);
    m[10] = sz * (cos_x * cos_y);

    m[3] = t.x;
    m[7] = t.y;
    m[11] = t.z;
}

static void mtx34_get_translation(const double m[12], Vec3 *out) {
    out->x = m[3];
    out->y = m[7];
    out->z = m[11];
}

static void mtx34_set_translation(double m[12], Vec3 value) {
    m[3] = value.x;
    m[7] = value.y;
    m[11] = value.z;
}

static int cgfx_magic(const uint8_t *bytes, size_t size, size_t offset, const char *magic) {
    size_t i;
    size_t length = strlen(magic);
    if (!checked_range(size, offset, length)) return 0;
    for (i = 0; i < length; i++) {
        if (bytes[offset + i] != (uint8_t)magic[i]) return 0;
    }
    return 1;
}

static size_t cgfx_rel(const uint8_t *bytes, size_t size, size_t field_offset) {
    int32_t rel;
    int64_t target;
    if (!checked_range(size, field_offset, 4)) return 0;
    rel = rd_i32(bytes + field_offset);
    if (rel == 0) return 0;
    target = (int64_t)field_offset + (int64_t)rel;
    if (target < 0 || (uint64_t)target > (uint64_t)size) return 0;
    return (size_t)target;
}

static void cgfx_string(const uint8_t *bytes, size_t size, size_t offset, char *out, size_t out_size) {
    size_t i = 0;
    if (out_size == 0) return;
    out[0] = '\0';
    if (offset >= size) return;
    while (offset + i < size && i + 1 < out_size) {
        uint8_t c = bytes[offset + i];
        if (c == 0 || c < 0x20 || c > 0x7e) break;
        out[i] = (char)c;
        i++;
    }
    out[i] = '\0';
}

static int cgfx_data_dict(const uint8_t *bytes, size_t size, int slot, size_t *dict_offset) {
    const size_t data = 0x14u;
    size_t count_offset;
    uint32_t count;
    size_t dict;

    if (slot < 0 || slot >= 16) return 0;
    if (!cgfx_magic(bytes, size, 0, "CGFX") || !cgfx_magic(bytes, size, data, "DATA")) return 0;
    count_offset = data + 0x08u + (size_t)slot * 8u;
    if (!checked_range(size, count_offset, 8)) return 0;
    count = rd_u32(bytes + count_offset);
    if (count == 0) return 0;
    dict = cgfx_rel(bytes, size, data + 0x0cu + (size_t)slot * 8u);
    if (!dict || !cgfx_magic(bytes, size, dict, "DICT")) return 0;
    *dict_offset = dict;
    return 1;
}

static uint32_t cgfx_dict_count(const uint8_t *bytes, size_t size, size_t dict_offset) {
    if (!checked_range(size, dict_offset + 0x08u, 4)) return 0;
    return rd_u32(bytes + dict_offset + 0x08u);
}

static int cgfx_dict_entry(const uint8_t *bytes, size_t size, size_t dict_offset, uint32_t index,
    size_t *object_offset, char *name, size_t name_size) {
    size_t entry = dict_offset + 0x1cu + (size_t)index * 0x10u;
    size_t name_offset;
    size_t object;
    if (!checked_range(size, entry, 0x10)) return 0;
    name_offset = cgfx_rel(bytes, size, entry + 0x08u);
    object = cgfx_rel(bytes, size, entry + 0x0cu);
    if (!object) return 0;
    if (name) cgfx_string(bytes, size, name_offset, name, name_size);
    *object_offset = object;
    return 1;
}

static uint8_t cgfx_expand4(uint32_t value) {
    value &= 0x0fu;
    return (uint8_t)((value << 4) | value);
}

static uint8_t cgfx_expand5(uint32_t value) {
    value &= 0x1fu;
    return (uint8_t)((value << 3) | (value >> 2));
}

static uint8_t cgfx_expand6(uint32_t value) {
    value &= 0x3fu;
    return (uint8_t)((value << 2) | (value >> 4));
}

static uint8_t cgfx_saturate_byte(int value) {
    if (value < 0) return 0;
    if (value > 255) return 255;
    return (uint8_t)value;
}

static uint64_t cgfx_bswap64(uint64_t value) {
    return ((value & 0x00000000000000ffull) << 56) |
        ((value & 0x000000000000ff00ull) << 40) |
        ((value & 0x0000000000ff0000ull) << 24) |
        ((value & 0x00000000ff000000ull) << 8) |
        ((value & 0x000000ff00000000ull) >> 8) |
        ((value & 0x0000ff0000000000ull) >> 24) |
        ((value & 0x00ff000000000000ull) >> 40) |
        ((value & 0xff00000000000000ull) >> 56);
}

static uint64_t cgfx_rd_u64(const uint8_t *p) {
    return (uint64_t)p[0] |
        ((uint64_t)p[1] << 8) |
        ((uint64_t)p[2] << 16) |
        ((uint64_t)p[3] << 24) |
        ((uint64_t)p[4] << 32) |
        ((uint64_t)p[5] << 40) |
        ((uint64_t)p[6] << 48) |
        ((uint64_t)p[7] << 56);
}

static int cgfx_texture_bytes_per_pixel(uint32_t format) {
    switch (format) {
        case 0x00: return 4;
        case 0x01: return 3;
        case 0x02: return 2;
        case 0x03: return 2;
        case 0x04: return 2;
        case 0x05: return 2;
        case 0x06: return 2;
        case 0x07: return 1;
        case 0x08: return 1;
        case 0x09: return 1;
        case 0x0a: return 1;
        default: return 0;
    }
}

static void cgfx_decode_pixel(const uint8_t *bytes, uint32_t format, size_t src, uint8_t *rgba) {
    uint16_t value;
    uint8_t l;
    switch (format) {
        case 0x00:
            rgba[0] = bytes[src + 3];
            rgba[1] = bytes[src + 2];
            rgba[2] = bytes[src + 1];
            rgba[3] = bytes[src + 0];
            break;
        case 0x01:
            rgba[0] = bytes[src + 2];
            rgba[1] = bytes[src + 1];
            rgba[2] = bytes[src + 0];
            rgba[3] = 255;
            break;
        case 0x02:
            value = rd_u16(bytes + src);
            rgba[0] = cgfx_expand5(value >> 1);
            rgba[1] = cgfx_expand5(value >> 6);
            rgba[2] = cgfx_expand5(value >> 11);
            rgba[3] = (value & 1u) ? 255 : 0;
            break;
        case 0x03:
            value = rd_u16(bytes + src);
            rgba[0] = cgfx_expand5(value);
            rgba[1] = cgfx_expand6(value >> 5);
            rgba[2] = cgfx_expand5(value >> 11);
            rgba[3] = 255;
            break;
        case 0x04:
            value = rd_u16(bytes + src);
            rgba[0] = cgfx_expand4(value >> 4);
            rgba[1] = cgfx_expand4(value >> 8);
            rgba[2] = cgfx_expand4(value >> 12);
            rgba[3] = cgfx_expand4(value);
            break;
        case 0x05:
            l = bytes[src + 0];
            rgba[0] = l;
            rgba[1] = l;
            rgba[2] = l;
            rgba[3] = bytes[src + 1];
            break;
        case 0x06:
            rgba[0] = bytes[src + 1];
            rgba[1] = bytes[src + 0];
            rgba[2] = 0;
            rgba[3] = 255;
            break;
        case 0x07:
            l = bytes[src];
            rgba[0] = l;
            rgba[1] = l;
            rgba[2] = l;
            rgba[3] = 255;
            break;
        case 0x08:
            rgba[0] = rgba[1] = rgba[2] = 255;
            rgba[3] = bytes[src];
            break;
        case 0x09:
            value = bytes[src];
            l = cgfx_expand4(value >> 4);
            rgba[0] = l;
            rgba[1] = l;
            rgba[2] = l;
            rgba[3] = cgfx_expand4(value);
            break;
        case 0x0a:
            l = cgfx_expand4(bytes[src] >> 4);
            rgba[0] = l;
            rgba[1] = l;
            rgba[2] = l;
            rgba[3] = 255;
            break;
        default:
            rgba[0] = rgba[1] = rgba[2] = rgba[3] = 0;
            break;
    }
}

static void cgfx_read_etc_alpha(const uint8_t *bytes, size_t offset, uint8_t alpha[16]) {
    int i;
    for (i = 0; i < 8; i++) {
        uint8_t value = bytes[offset + (size_t)i];
        alpha[i * 2 + 0] = cgfx_expand4(value & 0x0f);
        alpha[i * 2 + 1] = cgfx_expand4(value >> 4);
    }
}

static void cgfx_decode_etc_color_block(uint64_t block, Image *image,
    int dst_x, int dst_y, const uint8_t *alpha) {
    static const int modifiers[8][4] = {
        { 2, 8, -2, -8 },
        { 5, 17, -5, -17 },
        { 9, 29, -9, -29 },
        { 13, 42, -13, -42 },
        { 18, 60, -18, -60 },
        { 24, 80, -24, -80 },
        { 33, 106, -33, -106 },
        { 47, 183, -47, -183 }
    };
    uint32_t low = (uint32_t)(block >> 32);
    uint32_t high = (uint32_t)block;
    int flip = (high & 0x01000000u) != 0;
    int diff = (high & 0x02000000u) != 0;
    int table0 = (int)((high >> 29) & 7u);
    int table1 = (int)((high >> 26) & 7u);
    uint32_t r0, g0, b0, r1, g1, b1;
    int px, py;

    if (diff) {
        b0 = (high & 0x0000f8u) >> 0;
        g0 = (high & 0x00f800u) >> 8;
        r0 = (high & 0xf80000u) >> 16;
        b1 = (uint32_t)((int8_t)(b0 >> 3) + ((int8_t)((high & 0x000007u) << 5) >> 5));
        g1 = (uint32_t)((int8_t)(g0 >> 3) + ((int8_t)((high & 0x000700u) >> 3) >> 5));
        r1 = (uint32_t)((int8_t)(r0 >> 3) + ((int8_t)((high & 0x070000u) >> 11) >> 5));
        b0 |= b0 >> 5;
        g0 |= g0 >> 5;
        r0 |= r0 >> 5;
        b1 = (b1 << 3) | (b1 >> 2);
        g1 = (g1 << 3) | (g1 >> 2);
        r1 = (r1 << 3) | (r1 >> 2);
    } else {
        b0 = (high & 0x0000f0u) >> 0;
        g0 = (high & 0x00f000u) >> 8;
        r0 = (high & 0xf00000u) >> 16;
        b1 = (high & 0x00000fu) << 4;
        g1 = (high & 0x000f00u) >> 4;
        r1 = (high & 0x0f0000u) >> 12;
        b0 |= b0 >> 4;
        g0 |= g0 >> 4;
        r0 |= r0 >> 4;
        b1 |= b1 >> 4;
        g1 |= g1 >> 4;
        r1 |= r1 >> 4;
    }

    for (py = 0; py < 4; py++) {
        for (px = 0; px < 4; px++) {
            int pixel = px * 4 + py;
            uint32_t msb = low << 1;
            int code = pixel < 8 ?
                (int)(((low >> (pixel + 24)) & 1u) + ((msb >> (pixel + 8)) & 2u)) :
                (int)(((low >> (pixel + 8)) & 1u) + ((msb >> (pixel - 8)) & 2u));
            int use_second = flip ? py >= 2 : px >= 2;
            int x = dst_x + px;
            int y = dst_y - py;
            int modifier = modifiers[use_second ? table1 : table0][code];
            size_t dst;
            if (x < 0 || y < 0 || x >= image->width || y >= image->height) continue;
            dst = ((size_t)y * (size_t)image->width + (size_t)x) * 4u;
            image->rgba[dst + 0] = cgfx_saturate_byte((int)(use_second ? r1 : r0) + modifier);
            image->rgba[dst + 1] = cgfx_saturate_byte((int)(use_second ? g1 : g0) + modifier);
            image->rgba[dst + 2] = cgfx_saturate_byte((int)(use_second ? b1 : b0) + modifier);
            image->rgba[dst + 3] = alpha ? alpha[pixel] : 255;
        }
    }
}

static int cgfx_decode_etc_tiled(const uint8_t *bytes, size_t size, uint32_t format,
    size_t data, Image *image) {
    static const int block_offsets[4][2] = {
        { 0, 0 }, { 4, 0 }, { 0, 4 }, { 4, 4 }
    };
    int has_alpha = format == 0x0d;
    size_t block_size = has_alpha ? 16u : 8u;
    size_t src = data;
    int tile_x, tile_y, block;

    for (tile_y = 0; tile_y < image->height; tile_y += 8) {
        for (tile_x = 0; tile_x < image->width; tile_x += 8) {
            for (block = 0; block < 4; block++) {
                uint8_t alpha[16];
                int src_x = tile_x + block_offsets[block][0];
                int src_y = tile_y + block_offsets[block][1];
                int dst_y = image->height - 1 - src_y;
                uint64_t color_block;
                if (!checked_range(size, src, block_size)) return 0;
                if (has_alpha) cgfx_read_etc_alpha(bytes, src, alpha);
                color_block = cgfx_bswap64(cgfx_rd_u64(bytes + src + (has_alpha ? 8u : 0u)));
                cgfx_decode_etc_color_block(color_block, image,
                    src_x, dst_y, has_alpha ? alpha : NULL);
                src += block_size;
            }
        }
    }
    return 1;
}

static uint32_t cgfx_average_color(const Image *image, uint32_t fallback) {
    uint64_t r = 0, g = 0, b = 0, count = 0;
    int i;
    for (i = 0; i < image->width * image->height; i++) {
        size_t offset = (size_t)i * 4u;
        if (image->rgba[offset + 3] < 16) continue;
        r += image->rgba[offset + 0];
        g += image->rgba[offset + 1];
        b += image->rgba[offset + 2];
        count++;
    }
    if (!count) return fallback;
    return ((uint32_t)clamp_int((int)(r / count), 36, 255) << 16) |
        ((uint32_t)clamp_int((int)(g / count), 36, 255) << 8) |
        (uint32_t)clamp_int((int)(b / count), 36, 255);
}

static int cgfx_decode_texture(const uint8_t *bytes, size_t size, size_t txob_offset,
    Image *texture, uint32_t *average_color, uint32_t fallback_color, uint32_t *format_out) {
    uint32_t height;
    uint32_t width;
    uint32_t format;
    size_t data;
    int bytes_per_pixel;

    memset(texture, 0, sizeof(*texture));
    if (!checked_range(size, txob_offset + 0x48u, 4) ||
        !cgfx_magic(bytes, size, txob_offset + 4u, "TXOB")) {
        return 0;
    }
    height = rd_u32(bytes + txob_offset + 0x18u);
    width = rd_u32(bytes + txob_offset + 0x1cu);
    format = rd_u32(bytes + txob_offset + 0x34u);
    if (format_out) *format_out = format;
    data = cgfx_rel(bytes, size, txob_offset + 0x48u);
    if (!data || width == 0 || height == 0 || width > 4096u || height > 4096u) return 0;
    if (!image_create(texture, (int)width, (int)height)) return 0;

    if (format == 0x0c || format == 0x0d) {
        if (!cgfx_decode_etc_tiled(bytes, size, format, data, texture)) {
            image_free(texture);
            return 0;
        }
    } else {
        size_t src = data;
        int tile_x, tile_y, morton;
        bytes_per_pixel = cgfx_texture_bytes_per_pixel(format);
        if (!bytes_per_pixel) {
            image_free(texture);
            return 0;
        }
        for (tile_y = 0; tile_y < texture->height; tile_y += 8) {
            for (tile_x = 0; tile_x < texture->width; tile_x += 8) {
                for (morton = 0; morton < 64; morton++) {
                    int x = 0;
                    int y = 0;
                    int bit;
                    for (bit = 0; bit < 3; bit++) {
                        x |= ((morton >> (bit * 2)) & 1) << bit;
                        y |= ((morton >> (bit * 2 + 1)) & 1) << bit;
                    }
                    if (!checked_range(size, src, (size_t)bytes_per_pixel)) {
                        image_free(texture);
                        return 0;
                    }
                    if (tile_x + x < texture->width && tile_y + y < texture->height) {
                        int dst_y = texture->height - 1 - (tile_y + y);
                        size_t dst = ((size_t)dst_y * (size_t)texture->width + (size_t)(tile_x + x)) * 4u;
                        cgfx_decode_pixel(bytes, format, src, texture->rgba + dst);
                    }
                    src += (size_t)bytes_per_pixel;
                }
            }
        }
    }
    *average_color = cgfx_average_color(texture, fallback_color);
    return 1;
}

static void headwear_metadata_init(HeadwearMetadata *metadata) {
    int i;
    memset(metadata, 0, sizeof(*metadata));
    metadata->head_type = -1;
    metadata->hair_index = -1;
    for (i = 0; i < 16; i++) {
        int j;
        metadata->variant_hair_index[i] = -1;
        for (j = 0; j < 6; j++) metadata->variant_offset[i][j] = 0.0;
    }
    for (i = 0; i < 6; i++) metadata->offset[i] = 0.0;
}

static int cgfx_read_named_metadata(const uint8_t *bytes, size_t size, HeadwearMetadata *metadata) {
    size_t offset;
    int found = 0;
    int last_hair_variant = -1;
    for (offset = 0; offset + 0x10u <= size; offset += 4u) {
        uint32_t kind = rd_u32(bytes + offset);
        size_t name_offset;
        char name[64];
        int variant = -1;
        int value;
        uint32_t count;
        if (kind != 0x20000000u && kind != 0x80000000u) continue;
        name_offset = cgfx_rel(bytes, size, offset + 0x04u);
        if (!name_offset) continue;
        cgfx_string(bytes, size, name_offset, name, sizeof(name));
        if (strncmp(name, "Hair", 4) == 0 &&
            isdigit((unsigned char)name[4]) &&
            isdigit((unsigned char)name[5]) &&
            name[6] == '\0') {
            variant = (name[4] - '0') * 10 + (name[5] - '0');
        } else if (strncmp(name, "Offset", 6) == 0 &&
            isdigit((unsigned char)name[6]) &&
            isdigit((unsigned char)name[7]) &&
            name[8] == '\0') {
            variant = (name[6] - '0') * 10 + (name[7] - '0');
        } else if (strcmp(name, "HeadType") != 0 && strcmp(name, "Offset") != 0) {
                continue;
        }
        if (kind == 0x20000000u && checked_range(size, offset + 0x14u, 4)) {
            count = rd_u32(bytes + offset + 0x08u);
            if (count < 1u) continue;
            value = rd_i32(bytes + offset + 0x10u);
            if (strcmp(name, "HeadType") == 0) {
                metadata->head_type = value;
                found = 1;
            } else if (variant >= 0 && variant < 16) {
                last_hair_variant = variant;
                metadata->variant_hair_index[variant] = value;
                if (metadata->variant_count <= variant) metadata->variant_count = variant + 1;
                if (metadata->hair_index < 0) metadata->hair_index = value;
                found = 1;
            }
        } else if (kind == 0x80000000u && (strcmp(name, "Offset") == 0 || (variant >= 0 && variant < 16)) &&
            checked_range(size, offset + 0x10u, 24)) {
            int i;
            count = rd_u32(bytes + offset + 0x0cu);
            if (count < 6u) continue;
            /* Some archives serialize a numbered HairNN record followed by a
               plain Offset record.  That Offset belongs to the immediately
               preceding HairNN variant (not unconditionally to variant 00).
               ID 059, whose final pair is Hair04/Offset, is one concrete
               example in this RomFS. */
            if (variant < 0) variant = last_hair_variant >= 0 ? last_hair_variant : 0;
            for (i = 0; i < 6; i++) {
                double fvalue = rd_f32(bytes + offset + 0x10u + (size_t)i * 4u);
                metadata->variant_offset[variant][i] = fvalue;
                if (variant == 0) metadata->offset[i] = fvalue;
            }
            metadata->variant_has_offset[variant] = 1;
            if (metadata->variant_count <= variant) metadata->variant_count = variant + 1;
            metadata->has_offset = 1;
            found = 1;
        }
    }
    return found;
}

static int cgfx_read_headwear_metadata_file(const char *path, HeadwearMetadata *metadata) {
    Buffer buffer;
    int ok;
    headwear_metadata_init(metadata);
    memset(&buffer, 0, sizeof(buffer));
    if (!path || !read_file(path, &buffer)) return 0;
    ok = cgfx_read_named_metadata(buffer.data, buffer.size, metadata);
    free(buffer.data);
    return ok;
}

static int headwear_metadata_select_variant(const HeadwearMetadata *metadata, int hair_type) {
    int i;
    if (!metadata) return 0;
    for (i = 0; i < metadata->variant_count && i < 16; i++) {
        if (metadata->variant_hair_index[i] == hair_type) return i;
    }
    return -1;
}

static int tomodachi_headwear_visibility_animation_index(int head_type) {
    switch (head_type) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 9:
        case 10:
            return 0;
        case 6:
            return 1;
        case 7:
        case 8:
            return 2;
        default:
            return 0;
    }
}

static Vec3 tomodachi_cfl_headwear_rotation_to_render(Vec3 rotation) {
    Vec3 converted;
    converted.x = rotation.x;
    converted.y = rotation.y;
    converted.z = rotation.z;
    return converted;
}

static void cgfx_apply_alpha_image(Image *color, const Image *alpha) {
    int width;
    int height;
    int x, y;
    if (!color || !alpha || !color->rgba || !alpha->rgba) return;
    width = color->width < alpha->width ? color->width : alpha->width;
    height = color->height < alpha->height ? color->height : alpha->height;
    for (y = 0; y < height; y++) {
        for (x = 0; x < width; x++) {
            size_t c = ((size_t)y * (size_t)color->width + (size_t)x) * 4u;
            size_t a = ((size_t)y * (size_t)alpha->width + (size_t)x) * 4u;
            uint8_t luminance = max3(alpha->rgba[a + 0], alpha->rgba[a + 1], alpha->rgba[a + 2]);
            uint8_t channel_alpha = alpha->rgba[a + 3];
            color->rgba[c + 3] = luminance < channel_alpha ? luminance : channel_alpha;
        }
    }
}

typedef struct {
    uint32_t type;
    uint8_t data_type;
    uint32_t count;
    double multiplier;
    uint32_t offset;
} CgfxVertexComponent;

static int cgfx_component_byte_size(uint8_t data_type) {
    switch (data_type) {
        case 0:
        case 1:
            return 1;
        case 2:
        case 3:
            return 2;
        case 4:
        case 5:
        case 6:
            return 4;
        default:
            return 0;
    }
}

static double cgfx_component_value(const uint8_t *bytes, size_t offset, uint8_t data_type) {
    switch (data_type) {
        case 0: return (double)(int8_t)bytes[offset];
        case 1: return (double)bytes[offset];
        case 2: return (double)rd_i16(bytes + offset);
        case 3: return (double)rd_u16(bytes + offset);
        case 4: return (double)rd_i32(bytes + offset);
        case 5: return (double)rd_u32(bytes + offset);
        case 6: return (double)rd_f32(bytes + offset);
        default: return 0.0;
    }
}

static void cgfx_mesh_free(CgfxMesh *mesh) {
    free(mesh->vertices);
    free(mesh->normals);
    free(mesh->tangents);
    free(mesh->uvs);
    free(mesh->uv1s);
    free(mesh->uv2s);
    free(mesh->colors);
    free(mesh->bone_indices);
    free(mesh->bone_weights);
    free(mesh->indices);
    memset(mesh, 0, sizeof(*mesh));
}

static Vec3 vec3_sub(Vec3 a, Vec3 b) {
    Vec3 out;
    out.x = a.x - b.x;
    out.y = a.y - b.y;
    out.z = a.z - b.z;
    return out;
}

static Vec3 vec3_cross(Vec3 a, Vec3 b) {
    Vec3 out;
    out.x = a.y * b.z - a.z * b.y;
    out.y = a.z * b.x - a.x * b.z;
    out.z = a.x * b.y - a.y * b.x;
    return out;
}

static double vec3_dot(Vec3 a, Vec3 b) {
    return a.x * b.x + a.y * b.y + a.z * b.z;
}

static Vec3 vec3_reflect(Vec3 incoming, Vec3 normal) {
    double scale = 2.0 * vec3_dot(normal, incoming);
    Vec3 out;
    out.x = incoming.x - scale * normal.x;
    out.y = incoming.y - scale * normal.y;
    out.z = incoming.z - scale * normal.z;
    return out;
}

static Vec3 vec3_normalize(Vec3 v) {
    double len = sqrt(v.x * v.x + v.y * v.y + v.z * v.z);
    if (len <= 0.000001) {
        v.x = 0.0;
        v.y = 0.0;
        v.z = 1.0;
        return v;
    }
    v.x /= len;
    v.y /= len;
    v.z /= len;
    return v;
}

static void cgfx_mesh_compute_normals(CgfxMesh *mesh) {
    int i;
    if (mesh->has_normals || !mesh->vertices || !mesh->indices || mesh->vertex_count <= 0) return;
    mesh->normals = (Vec3 *)calloc((size_t)mesh->vertex_count, sizeof(Vec3));
    if (!mesh->normals) return;
    for (i = 0; i + 2 < mesh->index_count; i += 3) {
        uint32_t i0 = mesh->indices[i + 0];
        uint32_t i1 = mesh->indices[i + 1];
        uint32_t i2 = mesh->indices[i + 2];
        Vec3 normal;
        if (i0 >= (uint32_t)mesh->vertex_count ||
            i1 >= (uint32_t)mesh->vertex_count ||
            i2 >= (uint32_t)mesh->vertex_count) {
            continue;
        }
        normal = vec3_cross(vec3_sub(mesh->vertices[i1], mesh->vertices[i0]),
            vec3_sub(mesh->vertices[i2], mesh->vertices[i0]));
        mesh->normals[i0].x += normal.x;
        mesh->normals[i0].y += normal.y;
        mesh->normals[i0].z += normal.z;
        mesh->normals[i1].x += normal.x;
        mesh->normals[i1].y += normal.y;
        mesh->normals[i1].z += normal.z;
        mesh->normals[i2].x += normal.x;
        mesh->normals[i2].y += normal.y;
        mesh->normals[i2].z += normal.z;
    }
    for (i = 0; i < mesh->vertex_count; i++) {
        mesh->normals[i] = vec3_normalize(mesh->normals[i]);
    }
    mesh->has_normals = 1;
}

static int cgfx_parse_vertex_group(const uint8_t *bytes, size_t size, size_t offset, CgfxMesh *mesh) {
    uint32_t byte_length;
    size_t vertex_data;
    uint32_t stride;
    uint32_t component_count;
    size_t component_offsets;
    CgfxVertexComponent *components = NULL;
    int i;
    int component_total = 0;
    int has_positions = 0;
    int has_bone_indices = 0;
    int has_bone_weights = 0;

    if (!checked_range(size, offset, 0x30) || rd_u32(bytes + offset) != 0x40000002u) return 0;
    byte_length = rd_u32(bytes + offset + 0x14u);
    vertex_data = cgfx_rel(bytes, size, offset + 0x18u);
    stride = rd_u32(bytes + offset + 0x24u);
    component_count = rd_u32(bytes + offset + 0x28u);
    component_offsets = cgfx_rel(bytes, size, offset + 0x2cu);
    if (!vertex_data || !stride || !component_offsets || component_count > 64u) return 0;
    if (!checked_range(size, vertex_data, byte_length)) return 0;

    memset(mesh, 0, sizeof(*mesh));
    mesh->vertex_count = (int)(byte_length / stride);
    if (mesh->vertex_count <= 0) return 0;
    mesh->vertices = (Vec3 *)calloc((size_t)mesh->vertex_count, sizeof(Vec3));
    mesh->normals = (Vec3 *)calloc((size_t)mesh->vertex_count, sizeof(Vec3));
    mesh->tangents = (Vec3 *)calloc((size_t)mesh->vertex_count, sizeof(Vec3));
    mesh->uvs = (Vec2 *)calloc((size_t)mesh->vertex_count, sizeof(Vec2));
    mesh->uv1s = (Vec2 *)calloc((size_t)mesh->vertex_count, sizeof(Vec2));
    mesh->uv2s = (Vec2 *)calloc((size_t)mesh->vertex_count, sizeof(Vec2));
    mesh->colors = (uint32_t *)calloc((size_t)mesh->vertex_count, sizeof(uint32_t));
    mesh->bone_indices = (uint8_t *)calloc((size_t)mesh->vertex_count * CGFX_MAX_BONE_INFLUENCES, sizeof(uint8_t));
    mesh->bone_weights = (double *)calloc((size_t)mesh->vertex_count * CGFX_MAX_BONE_INFLUENCES, sizeof(double));
    components = (CgfxVertexComponent *)calloc((size_t)component_count, sizeof(CgfxVertexComponent));
    if (!mesh->vertices || !mesh->normals || !mesh->tangents || !mesh->uvs ||
        !mesh->uv1s || !mesh->uv2s || !mesh->colors ||
        !mesh->bone_indices || !mesh->bone_weights || !components) {
        free(components);
        cgfx_mesh_free(mesh);
        return 0;
    }
    bounds_reset(&mesh->min, &mesh->max);

    for (i = 0; i < (int)component_count; i++) {
        size_t field = component_offsets + (size_t)i * 4u;
        size_t component;
        if (!checked_range(size, field, 4)) continue;
        component = (size_t)((int64_t)field + (int64_t)rd_i32(bytes + field));
        if (!checked_range(size, component, 0x34) || rd_u32(bytes + component) != 0x40000001u) continue;
        components[component_total].type = rd_u32(bytes + component + 0x04u);
        components[component_total].data_type = bytes[component + 0x24u];
        components[component_total].count = rd_u32(bytes + component + 0x28u);
        components[component_total].multiplier = rd_f32(bytes + component + 0x2cu);
        components[component_total].offset = rd_u32(bytes + component + 0x30u);
        if (components[component_total].count <= 4u &&
            cgfx_component_byte_size(components[component_total].data_type) > 0) {
            component_total++;
        }
    }

    for (i = 0; i < mesh->vertex_count; i++) {
        size_t base = vertex_data + (size_t)i * (size_t)stride;
        int c;
        for (c = 0; c < component_total; c++) {
            CgfxVertexComponent *component = &components[c];
            int size_per = cgfx_component_byte_size(component->data_type);
            double values[4] = { 0.0, 0.0, 0.0, 0.0 };
            uint32_t n;
            if (component->offset >= stride) continue;
            if ((uint64_t)component->offset + (uint64_t)component->count * (uint64_t)size_per > stride) continue;
            for (n = 0; n < component->count; n++) {
                values[n] = cgfx_component_value(bytes,
                    base + (size_t)component->offset + (size_t)n * (size_t)size_per,
                    component->data_type) * component->multiplier;
            }
            if (component->type == 0u && component->count >= 3u) {
                mesh->vertices[i].x = values[0];
                mesh->vertices[i].y = values[1];
                mesh->vertices[i].z = values[2];
                has_positions = 1;
            } else if (component->type == 1u && component->count >= 3u) {
                mesh->normals[i].x = values[0];
                mesh->normals[i].y = values[1];
                mesh->normals[i].z = values[2];
                mesh->has_normals = 1;
            } else if (component->type == 2u && component->count >= 3u) {
                mesh->tangents[i].x = values[0];
                mesh->tangents[i].y = values[1];
                mesh->tangents[i].z = values[2];
                mesh->has_tangents = 1;
            } else if (component->type == 4u && component->count >= 2u) {
                mesh->uvs[i].x = values[0];
                mesh->uvs[i].y = values[1];
                mesh->has_uvs = 1;
            } else if (component->type == 5u && component->count >= 2u) {
                mesh->uv1s[i].x = values[0];
                mesh->uv1s[i].y = values[1];
                mesh->has_uv1s = 1;
            } else if (component->type == 6u && component->count >= 2u) {
                mesh->uv2s[i].x = values[0];
                mesh->uv2s[i].y = values[1];
                mesh->has_uv2s = 1;
            } else if (component->type == 3u && component->count >= 3u) {
                double scale = (values[0] <= 1.0 && values[1] <= 1.0 &&
                    values[2] <= 1.0 && (component->count < 4u || values[3] <= 1.0)) ? 255.0 : 1.0;
                uint32_t r = (uint32_t)clamp_int((int)lrint(values[0] * scale), 0, 255);
                uint32_t g = (uint32_t)clamp_int((int)lrint(values[1] * scale), 0, 255);
                uint32_t b = (uint32_t)clamp_int((int)lrint(values[2] * scale), 0, 255);
                uint32_t a = component->count >= 4u ?
                    (uint32_t)clamp_int((int)lrint(values[3] * scale), 0, 255) : 255u;
                mesh->colors[i] = (r << 24) | (g << 16) | (b << 8) | a;
                mesh->has_colors = 1;
            } else if (component->type == 7u && component->count >= 1u) {
                uint32_t influence;
                for (influence = 0; influence < component->count && influence < CGFX_MAX_BONE_INFLUENCES; influence++) {
                    mesh->bone_indices[(size_t)i * CGFX_MAX_BONE_INFLUENCES + influence] =
                        (uint8_t)clamp_int((int)lrint(values[influence]), 0, 255);
                }
                has_bone_indices = 1;
            } else if (component->type == 8u && component->count >= 1u) {
                uint32_t influence;
                for (influence = 0; influence < component->count && influence < CGFX_MAX_BONE_INFLUENCES; influence++) {
                    mesh->bone_weights[(size_t)i * CGFX_MAX_BONE_INFLUENCES + influence] = values[influence];
                }
                has_bone_weights = 1;
            }
        }
        if (has_bone_indices || has_bone_weights) {
            double weight_sum = 0.0;
            int influence;
            for (influence = 0; influence < CGFX_MAX_BONE_INFLUENCES; influence++) {
                double *weight = &mesh->bone_weights[(size_t)i * CGFX_MAX_BONE_INFLUENCES + (size_t)influence];
                if (*weight < 0.0) *weight = 0.0;
                weight_sum += *weight;
            }
            if (weight_sum <= 0.000001) {
                mesh->bone_weights[(size_t)i * CGFX_MAX_BONE_INFLUENCES] = 1.0;
            } else {
                for (influence = 0; influence < CGFX_MAX_BONE_INFLUENCES; influence++) {
                    mesh->bone_weights[(size_t)i * CGFX_MAX_BONE_INFLUENCES + (size_t)influence] /= weight_sum;
                }
            }
            mesh->has_skin = 1;
        }
        bounds_include(&mesh->min, &mesh->max, mesh->vertices[i]);
    }

    free(components);
    if (!has_positions || !bounds_are_valid(mesh->min, mesh->max)) {
        cgfx_mesh_free(mesh);
        return 0;
    }
    if (!mesh->has_normals) {
        free(mesh->normals);
        mesh->normals = NULL;
    }
    if (!mesh->has_tangents) {
        free(mesh->tangents);
        mesh->tangents = NULL;
    }
    if (!mesh->has_uvs) {
        free(mesh->uvs);
        mesh->uvs = NULL;
    }
    if (!mesh->has_uv1s) {
        free(mesh->uv1s);
        mesh->uv1s = NULL;
    }
    if (!mesh->has_uv2s) {
        free(mesh->uv2s);
        mesh->uv2s = NULL;
    }
    if (!mesh->has_colors) {
        free(mesh->colors);
        mesh->colors = NULL;
    }
    if (!mesh->has_skin) {
        free(mesh->bone_indices);
        free(mesh->bone_weights);
        mesh->bone_indices = NULL;
        mesh->bone_weights = NULL;
    }
    return 1;
}

static int cgfx_append_index(uint32_t **indices, int *count, int *capacity, uint32_t value) {
    if (*count >= *capacity) {
        int next_capacity = *capacity ? *capacity * 2 : 256;
        uint32_t *next = (uint32_t *)realloc(*indices, (size_t)next_capacity * sizeof(uint32_t));
        if (!next) return 0;
        *indices = next;
        *capacity = next_capacity;
    }
    (*indices)[(*count)++] = value;
    return 1;
}

static int cgfx_append_triangle(uint32_t **indices, int *count, int *capacity,
    uint32_t a, uint32_t b, uint32_t c) {
    if (a == b || b == c || a == c) return 1;
    return cgfx_append_index(indices, count, capacity, a) &&
        cgfx_append_index(indices, count, capacity, b) &&
        cgfx_append_index(indices, count, capacity, c);
}

static int cgfx_mesh_reserve_vertices(CgfxMesh *mesh, int *capacity, int needed) {
    Vec3 *vertices;
    Vec3 *normals = NULL;
    Vec3 *tangents = NULL;
    Vec2 *uvs = NULL;
    Vec2 *uv1s = NULL;
    Vec2 *uv2s = NULL;
    uint32_t *colors = NULL;
    uint8_t *bone_indices = NULL;
    double *bone_weights = NULL;
    int next_capacity = *capacity ? *capacity : 256;
    if (needed <= *capacity) return 1;
    while (next_capacity < needed) next_capacity *= 2;

    vertices = (Vec3 *)realloc(mesh->vertices, (size_t)next_capacity * sizeof(Vec3));
    if (!vertices) return 0;
    mesh->vertices = vertices;

    if (mesh->has_normals) {
        normals = (Vec3 *)realloc(mesh->normals, (size_t)next_capacity * sizeof(Vec3));
        if (!normals) return 0;
        mesh->normals = normals;
    }
    if (mesh->has_tangents) {
        tangents = (Vec3 *)realloc(mesh->tangents, (size_t)next_capacity * sizeof(Vec3));
        if (!tangents) return 0;
        mesh->tangents = tangents;
    }
    if (mesh->has_uvs) {
        uvs = (Vec2 *)realloc(mesh->uvs, (size_t)next_capacity * sizeof(Vec2));
        if (!uvs) return 0;
        mesh->uvs = uvs;
    }
    if (mesh->has_uv1s) {
        uv1s = (Vec2 *)realloc(mesh->uv1s, (size_t)next_capacity * sizeof(Vec2));
        if (!uv1s) return 0;
        mesh->uv1s = uv1s;
    }
    if (mesh->has_uv2s) {
        uv2s = (Vec2 *)realloc(mesh->uv2s, (size_t)next_capacity * sizeof(Vec2));
        if (!uv2s) return 0;
        mesh->uv2s = uv2s;
    }
    if (mesh->has_colors) {
        colors = (uint32_t *)realloc(mesh->colors, (size_t)next_capacity * sizeof(uint32_t));
        if (!colors) return 0;
        mesh->colors = colors;
    }
    if (mesh->has_skin) {
        bone_indices = (uint8_t *)realloc(mesh->bone_indices,
            (size_t)next_capacity * CGFX_MAX_BONE_INFLUENCES * sizeof(uint8_t));
        if (!bone_indices) return 0;
        mesh->bone_indices = bone_indices;
        bone_weights = (double *)realloc(mesh->bone_weights,
            (size_t)next_capacity * CGFX_MAX_BONE_INFLUENCES * sizeof(double));
        if (!bone_weights) return 0;
        mesh->bone_weights = bone_weights;
    }

    *capacity = next_capacity;
    return 1;
}

static int cgfx_append_remapped_vertex(CgfxMesh *mesh, int *vertex_capacity,
    const CgfxMesh *source, uint32_t raw_index, const int *palette, int palette_count,
    uint32_t *out_index) {
    int dst;
    int influence;
    if (!source || raw_index >= (uint32_t)source->vertex_count) return 0;
    if (!cgfx_mesh_reserve_vertices(mesh, vertex_capacity, mesh->vertex_count + 1)) return 0;

    dst = mesh->vertex_count++;
    mesh->vertices[dst] = source->vertices[raw_index];
    bounds_include(&mesh->min, &mesh->max, mesh->vertices[dst]);
    if (mesh->has_normals) mesh->normals[dst] = source->normals[raw_index];
    if (mesh->has_tangents) mesh->tangents[dst] = source->tangents[raw_index];
    if (mesh->has_uvs) mesh->uvs[dst] = source->uvs[raw_index];
    if (mesh->has_uv1s) mesh->uv1s[dst] = source->uv1s[raw_index];
    if (mesh->has_uv2s) mesh->uv2s[dst] = source->uv2s[raw_index];
    if (mesh->has_colors) mesh->colors[dst] = source->colors[raw_index];
    if (mesh->has_skin) {
        size_t src_base = (size_t)raw_index * CGFX_MAX_BONE_INFLUENCES;
        size_t dst_base = (size_t)dst * CGFX_MAX_BONE_INFLUENCES;
        for (influence = 0; influence < CGFX_MAX_BONE_INFLUENCES; influence++) {
            int local_bone = source->bone_indices[src_base + (size_t)influence];
            int mapped_bone = local_bone;
            if (palette && local_bone >= 0 && local_bone < palette_count) {
                mapped_bone = palette[local_bone];
            }
            mesh->bone_indices[dst_base + (size_t)influence] =
                (uint8_t)clamp_int(mapped_bone, 0, 255);
            mesh->bone_weights[dst_base + (size_t)influence] =
                source->bone_weights[src_base + (size_t)influence];
        }
    }
    *out_index = (uint32_t)dst;
    return 1;
}

static int cgfx_append_remapped_triangle(CgfxMesh *mesh, int *vertex_capacity,
    int *index_capacity, const CgfxMesh *source, const int *palette, int palette_count,
    uint32_t a, uint32_t b, uint32_t c) {
    uint32_t out_a;
    uint32_t out_b;
    uint32_t out_c;
    if (a == b || b == c || a == c) return 1;
    if (!cgfx_append_remapped_vertex(mesh, vertex_capacity, source, a, palette, palette_count, &out_a) ||
        !cgfx_append_remapped_vertex(mesh, vertex_capacity, source, b, palette, palette_count, &out_b) ||
        !cgfx_append_remapped_vertex(mesh, vertex_capacity, source, c, palette, palette_count, &out_c)) {
        return 0;
    }
    return cgfx_append_index(&mesh->indices, &mesh->index_count, index_capacity, out_a) &&
        cgfx_append_index(&mesh->indices, &mesh->index_count, index_capacity, out_b) &&
        cgfx_append_index(&mesh->indices, &mesh->index_count, index_capacity, out_c);
}

static int cgfx_parse_face_descriptors(const uint8_t *bytes, size_t size, size_t sobj_offset,
    const CgfxMesh *source, CgfxMesh *mesh) {
    uint32_t face_group_count;
    size_t face_group_offsets;
    int index_capacity = 0;
    int vertex_capacity = 0;
    uint32_t group_index;

    memset(mesh, 0, sizeof(*mesh));
    mesh->has_normals = source->has_normals;
    mesh->has_tangents = source->has_tangents;
    mesh->has_uvs = source->has_uvs;
    mesh->has_uv1s = source->has_uv1s;
    mesh->has_uv2s = source->has_uv2s;
    mesh->has_colors = source->has_colors;
    mesh->has_skin = source->has_skin;
    bounds_reset(&mesh->min, &mesh->max);

    if (!checked_range(size, sobj_offset + 0x30u, 4)) return 0;
    face_group_count = rd_u32(bytes + sobj_offset + 0x2cu);
    face_group_offsets = cgfx_rel(bytes, size, sobj_offset + 0x30u);
    if (!face_group_offsets || face_group_count > 4096u) return 0;

    for (group_index = 0; group_index < face_group_count; group_index++) {
        size_t group_field = face_group_offsets + (size_t)group_index * 4u;
        size_t face_group;
        uint32_t palette_raw_count;
        size_t palette_offsets;
        int palette[256];
        int palette_count = 0;
        uint32_t descriptor_group_count;
        size_t descriptor_group_offsets;
        uint32_t dg;
        if (!checked_range(size, group_field, 4)) break;
        face_group = (size_t)((int64_t)group_field + (int64_t)rd_i32(bytes + group_field));
        if (!checked_range(size, face_group + 0x14u, 4)) continue;
        palette_raw_count = rd_u32(bytes + face_group + 0x00u);
        palette_offsets = cgfx_rel(bytes, size, face_group + 0x04u);
        if (palette_offsets && palette_raw_count <= (uint32_t)(sizeof(palette) / sizeof(palette[0]))) {
            uint32_t p;
            for (p = 0; p < palette_raw_count; p++) {
                if (!checked_range(size, palette_offsets + (size_t)p * 4u, 4)) break;
                palette[p] = rd_i32(bytes + palette_offsets + (size_t)p * 4u);
            }
            palette_count = (int)p;
        }
        descriptor_group_count = rd_u32(bytes + face_group + 0x0cu);
        descriptor_group_offsets = cgfx_rel(bytes, size, face_group + 0x10u);
        if (!descriptor_group_offsets || descriptor_group_count > 4096u) continue;

        for (dg = 0; dg < descriptor_group_count; dg++) {
            size_t descriptor_group_field = descriptor_group_offsets + (size_t)dg * 4u;
            size_t descriptor_group;
            uint32_t descriptor_count;
            size_t descriptor_offsets;
            uint32_t descriptor_index;
            if (!checked_range(size, descriptor_group_field, 4)) break;
            descriptor_group = (size_t)((int64_t)descriptor_group_field + (int64_t)rd_i32(bytes + descriptor_group_field));
            if (!checked_range(size, descriptor_group + 0x04u, 4)) continue;
            descriptor_count = rd_u32(bytes + descriptor_group + 0x00u);
            descriptor_offsets = cgfx_rel(bytes, size, descriptor_group + 0x04u);
            if (!descriptor_offsets || descriptor_count > 4096u) continue;

            for (descriptor_index = 0; descriptor_index < descriptor_count; descriptor_index++) {
                size_t descriptor_field = descriptor_offsets + (size_t)descriptor_index * 4u;
                size_t descriptor;
                uint32_t flags;
                uint8_t primitive;
                uint32_t byte_length;
                size_t data;
                int index_size;
                uint32_t *raw = NULL;
                uint32_t raw_count = 0;
                uint32_t raw_capacity;
                uint32_t cursor;
                if (!checked_range(size, descriptor_field, 4)) break;
                descriptor = (size_t)((int64_t)descriptor_field + (int64_t)rd_i32(bytes + descriptor_field));
                if (!checked_range(size, descriptor + 0x0cu, 4)) continue;
                flags = rd_u32(bytes + descriptor + 0x00u);
                primitive = bytes[descriptor + 0x04u];
                byte_length = rd_u32(bytes + descriptor + 0x08u);
                data = cgfx_rel(bytes, size, descriptor + 0x0cu);
                index_size = (flags & 0x02u) ? 2 : 1;
                if (!data || !checked_range(size, data, byte_length)) continue;
                raw_capacity = byte_length / (uint32_t)index_size;
                raw = (uint32_t *)malloc((size_t)raw_capacity * sizeof(uint32_t));
                if (!raw) {
                    return 0;
                }
                for (cursor = 0; cursor + (uint32_t)index_size <= byte_length; cursor += (uint32_t)index_size) {
                    raw[raw_count++] = index_size == 2 ?
                        (uint32_t)rd_u16(bytes + data + cursor) :
                        (uint32_t)bytes[data + cursor];
                }
                if (primitive == 1u) {
                    uint32_t r;
                    for (r = 0; r + 2u < raw_count; r++) {
                        uint32_t a = raw[r + 0u];
                        uint32_t b = raw[r + 1u];
                        uint32_t c = raw[r + 2u];
                        if (r & 1u) {
                            uint32_t swap = a;
                            a = b;
                            b = swap;
                        }
                        if (!cgfx_append_remapped_triangle(mesh, &vertex_capacity, &index_capacity,
                            source, palette_count ? palette : NULL, palette_count, a, b, c)) {
                            free(raw);
                            return 0;
                        }
                    }
                } else if (primitive == 2u) {
                    uint32_t r;
                    for (r = 1; r + 1u < raw_count; r++) {
                        if (!cgfx_append_remapped_triangle(mesh, &vertex_capacity, &index_capacity,
                            source, palette_count ? palette : NULL, palette_count,
                            raw[0], raw[r], raw[r + 1u])) {
                            free(raw);
                            return 0;
                        }
                    }
                } else {
                    uint32_t r;
                    for (r = 0; r + 2u < raw_count; r += 3u) {
                        if (!cgfx_append_remapped_triangle(mesh, &vertex_capacity, &index_capacity,
                            source, palette_count ? palette : NULL, palette_count,
                            raw[r + 0u], raw[r + 1u], raw[r + 2u])) {
                            free(raw);
                            return 0;
                        }
                    }
                }
                free(raw);
            }
        }
    }

    return mesh->index_count > 0 && bounds_are_valid(mesh->min, mesh->max);
}

static int cgfx_find_primary_vertex_group(const uint8_t *bytes, size_t size, size_t sobj_offset,
    CgfxMesh *mesh) {
    uint32_t count;
    size_t offsets;
    uint32_t i;
    if (!checked_range(size, sobj_offset + 0x3cu, 4)) return 0;
    count = rd_u32(bytes + sobj_offset + 0x38u);
    offsets = cgfx_rel(bytes, size, sobj_offset + 0x3cu);
    if (!offsets || count > 4096u) return 0;
    for (i = 0; i < count; i++) {
        size_t field = offsets + (size_t)i * 4u;
        size_t vertex_group;
        if (!checked_range(size, field, 4)) break;
        vertex_group = (size_t)((int64_t)field + (int64_t)rd_i32(bytes + field));
        if (cgfx_parse_vertex_group(bytes, size, vertex_group, mesh)) return 1;
    }
    return 0;
}

static int cgfx_parse_sobj_mesh(const uint8_t *bytes, size_t size, size_t sobj_offset, CgfxMesh *mesh) {
    CgfxMesh source;
    int ok;
    memset(&source, 0, sizeof(source));
    if (!cgfx_magic(bytes, size, sobj_offset + 4u, "SOBJ")) return 0;
    if (!cgfx_find_primary_vertex_group(bytes, size, sobj_offset, &source)) return 0;
    ok = cgfx_parse_face_descriptors(bytes, size, sobj_offset, &source, mesh);
    cgfx_mesh_free(&source);
    if (!ok) {
        cgfx_mesh_free(mesh);
        return 0;
    }
    cgfx_mesh_compute_normals(mesh);
    return 1;
}

static int cgfx_model_add_mesh(CgfxModel *model, const CgfxMesh *mesh) {
    CgfxMesh *next = (CgfxMesh *)realloc(model->meshes, (size_t)(model->mesh_count + 1) * sizeof(CgfxMesh));
    if (!next) return 0;
    model->meshes = next;
    model->meshes[model->mesh_count] = *mesh;
    model->mesh_count++;
    return 1;
}

static void cgfx_update_body_skin_matrices(CgfxModel *model);
static int cgfx_find_bone_index(const CgfxModel *model, const char *name);

static void cgfx_model_update_bounds(CgfxModel *model) {
    int i;
    bounds_reset(&model->min, &model->max);
    for (i = 0; i < model->mesh_count; i++) {
        if (!bounds_are_valid(model->meshes[i].min, model->meshes[i].max)) continue;
        bounds_include(&model->min, &model->max, model->meshes[i].min);
        bounds_include(&model->min, &model->max, model->meshes[i].max);
    }
}

static int mtx34_is_identity_near(const double m[12]) {
    int i;
    static const double identity[12] = {
        1.0, 0.0, 0.0, 0.0,
        0.0, 1.0, 0.0, 0.0,
        0.0, 0.0, 1.0, 0.0
    };
    for (i = 0; i < 12; i++) {
        if (fabs(m[i] - identity[i]) > 0.000001) return 0;
    }
    return 1;
}

static int cgfx_apply_single_bone_unskinned_transform(CgfxModel *model) {
    int mesh_index;
    int any = 0;
    const double *matrix;
    if (!model || !model->has_skeleton || model->bone_count != 1) return 0;
    matrix = model->bones[0].local;
    if (mtx34_is_identity_near(matrix)) return 0;

    /* Tomodachi's render resource path consumes authored CGFX node transforms.
       The CPU loader must bake them before deriving bounds or placement. */
    for (mesh_index = 0; mesh_index < model->mesh_count; mesh_index++) {
        CgfxMesh *mesh = &model->meshes[mesh_index];
        int i;
        if (mesh->has_skin || !mesh->vertices || mesh->vertex_count <= 0) continue;
        bounds_reset(&mesh->min, &mesh->max);
        for (i = 0; i < mesh->vertex_count; i++) {
            mesh->vertices[i] = mtx34_transform_point(matrix, mesh->vertices[i]);
            if (mesh->has_normals && mesh->normals) {
                mesh->normals[i] = vec3_normalize(mtx34_transform_vector(matrix, mesh->normals[i]));
            }
            if (mesh->has_tangents && mesh->tangents) {
                mesh->tangents[i] = vec3_normalize(mtx34_transform_vector(matrix, mesh->tangents[i]));
            }
            bounds_include(&mesh->min, &mesh->max, mesh->vertices[i]);
        }
        any = 1;
    }
    if (any) cgfx_model_update_bounds(model);
    return any;
}

static int cgfx_apply_rigid_node_unskinned_transforms(CgfxModel *model) {
    int mesh_index;
    int any = 0;
    int use_named_nodes = 0;
    int use_ordered_fallback = 0;
    if (!model || !model->has_skeleton || model->bone_count <= 1 || model->mesh_count <= 0) return 0;

    /* CGFX rigid pieces are unskinned meshes whose MeshNodeName names the
       skeleton node supplying their model transform. Do not infer a flat
       hierarchy from mesh/bone counts: some files insert grouping nodes, and
       others bind several material meshes to the same node. */
    for (mesh_index = 0; mesh_index < model->mesh_count; mesh_index++) {
        CgfxMesh *mesh = &model->meshes[mesh_index];
        if (!mesh->has_skin && mesh->vertices && mesh->vertex_count > 0 &&
            mesh->mesh_node_name[0] &&
            cgfx_find_bone_index(model, mesh->mesh_node_name) >= 0) {
            use_named_nodes = 1;
        }
    }

    /* Retain the original ordered convention for files whose mesh-node string
       is absent, but only when the complete flat layout is unambiguous. */
    if (!use_named_nodes && model->mesh_count == model->bone_count - 1 &&
        model->bones[0].parent_index == -1) {
        use_ordered_fallback = 1;
        for (mesh_index = 0; mesh_index < model->mesh_count; mesh_index++) {
            CgfxMesh *mesh = &model->meshes[mesh_index];
            int bone_index = mesh_index + 1;
            if (mesh->has_skin || !mesh->vertices || mesh->vertex_count <= 0 ||
                model->bones[bone_index].parent_index < 0 ||
                model->bones[bone_index].parent_index >= model->bone_count) {
                use_ordered_fallback = 0;
                break;
            }
        }
    }
    if (!use_named_nodes && !use_ordered_fallback) return 0;

    cgfx_update_body_skin_matrices(model);
    for (mesh_index = 0; mesh_index < model->mesh_count; mesh_index++) {
        CgfxMesh *mesh = &model->meshes[mesh_index];
        int bone_index = use_named_nodes ?
            cgfx_find_bone_index(model, mesh->mesh_node_name) : mesh_index + 1;
        int i;
        const double *matrix;
        if (mesh->has_skin || !mesh->vertices || mesh->vertex_count <= 0 ||
            bone_index < 0 || bone_index >= model->bone_count) {
            continue;
        }
        matrix = model->bones[bone_index].scaled_world;
        if (mtx34_is_identity_near(matrix)) continue;
        bounds_reset(&mesh->min, &mesh->max);
        for (i = 0; i < mesh->vertex_count; i++) {
            mesh->vertices[i] = mtx34_transform_point(matrix, mesh->vertices[i]);
            if (mesh->has_normals && mesh->normals) {
                mesh->normals[i] = vec3_normalize(mtx34_transform_vector(matrix, mesh->normals[i]));
            }
            if (mesh->has_tangents && mesh->tangents) {
                mesh->tangents[i] = vec3_normalize(mtx34_transform_vector(matrix, mesh->tangents[i]));
            }
            bounds_include(&mesh->min, &mesh->max, mesh->vertices[i]);
        }
        any = 1;
    }
    if (any) cgfx_model_update_bounds(model);
    return any;
}

static void cgfx_model_free(CgfxModel *model) {
    int i;
    for (i = 0; i < model->mesh_count; i++) cgfx_mesh_free(&model->meshes[i]);
    free(model->meshes);
    free(model->bones);
    free(model->materials);
    image_free(&model->texture);
    image_free(&model->mask_texture);
    image_free(&model->normal_texture);
    memset(model, 0, sizeof(*model));
}

typedef struct {
    char name[128];
    size_t object;
    uint32_t format;
} CgfxTextureEntry;

static void texture_prefix(const char *name, char *out, size_t out_size) {
    const char *last = strrchr(name, '_');
    size_t length = last ? (size_t)(last - name) : strlen(name);
    if (out_size == 0) return;
    if (length >= out_size) length = out_size - 1u;
    memcpy(out, name, length);
    out[length] = '\0';
}

static int texture_names_share_prefix(const char *a, const char *b) {
    char pa[128];
    char pb[128];
    texture_prefix(a, pa, sizeof(pa));
    texture_prefix(b, pb, sizeof(pb));
    return pa[0] && strcmp(pa, pb) == 0;
}

static int texture_name_is_dummy(const char *name) {
    return strstr(name, "Dummy") != NULL || strstr(name, "dummy") != NULL;
}

static int texture_format_is_alpha_like(uint32_t format) {
    return format == 0x05u || format == 0x08u || format == 0x09u || format == 0x0au;
}

static int texture_name_ends_with_slot(const char *name, const char *slot) {
    char suffix[16];
    snprintf(suffix, sizeof(suffix), "_%s", slot);
    return ends_with_ci(name, suffix);
}

static int texture_name_is_normal(const char *name) {
    return texture_name_ends_with_slot(name, "NRM");
}

static int cgfx_load_first_texture(const uint8_t *bytes, size_t size, CgfxModel *model, uint32_t fallback_color) {
    size_t dict;
    uint32_t count;
    uint32_t i;
    CgfxTextureEntry entries[128];
    int entry_count = 0;
    int selected = -1;
    int aux_prefix = -1;
    if (!cgfx_data_dict(bytes, size, 1, &dict)) return 0;
    count = cgfx_dict_count(bytes, size, dict);
    for (i = 0; i < count && entry_count < (int)(sizeof(entries) / sizeof(entries[0])); i++) {
        size_t object;
        char name[128];
        if (!cgfx_dict_entry(bytes, size, dict, i, &object, name, sizeof(name))) continue;
        if (!cgfx_magic(bytes, size, object + 4u, "TXOB")) continue;
        entries[entry_count].object = object;
        entries[entry_count].format = checked_range(size, object + 0x34u, 4) ? rd_u32(bytes + object + 0x34u) : 0xffffffffu;
        strncpy(entries[entry_count].name, name, sizeof(entries[entry_count].name) - 1u);
        entries[entry_count].name[sizeof(entries[entry_count].name) - 1u] = '\0';
        entry_count++;
    }

    for (i = 0; i < (uint32_t)entry_count; i++) {
        if (texture_name_is_dummy(entries[i].name)) continue;
        if (texture_name_is_normal(entries[i].name)) continue;
        if (!texture_name_ends_with_slot(entries[i].name, "0")) continue;
        if (texture_format_is_alpha_like(entries[i].format)) continue;
        selected = (int)i;
        break;
    }
    for (i = 0; selected < 0 && i < (uint32_t)entry_count; i++) {
        if (texture_name_is_dummy(entries[i].name)) continue;
        if (texture_name_is_normal(entries[i].name)) continue;
        if (texture_name_ends_with_slot(entries[i].name, "1")) continue;
        if (texture_format_is_alpha_like(entries[i].format)) continue;
        selected = (int)i;
        break;
    }
    for (i = 0; selected < 0 && i < (uint32_t)entry_count; i++) {
        if (!texture_name_is_dummy(entries[i].name)) continue;
        if (texture_name_is_normal(entries[i].name)) continue;
        if (!texture_name_ends_with_slot(entries[i].name, "0")) continue;
        if (texture_format_is_alpha_like(entries[i].format)) continue;
        selected = (int)i;
        break;
    }
    if (selected < 0) {
        for (i = 0; i < (uint32_t)entry_count; i++) {
            if (texture_name_is_dummy(entries[i].name)) continue;
            if (texture_name_is_normal(entries[i].name)) continue;
            selected = (int)i;
            break;
        }
    }
    if (selected < 0 && entry_count > 0) selected = 0;
    if (selected < 0) return 0;

    if (cgfx_decode_texture(bytes, size, entries[selected].object,
        &model->texture, &model->average_color, fallback_color, NULL)) {
        Image alpha;
        uint32_t alpha_average;
        int selected_dummy = texture_name_is_dummy(entries[selected].name);
        memset(&alpha, 0, sizeof(alpha));
        if (selected_dummy) {
            for (i = 0; i < (uint32_t)entry_count; i++) {
                if ((int)i == selected) continue;
                if (texture_name_is_dummy(entries[i].name)) continue;
                if (texture_name_is_normal(entries[i].name)) continue;
                if (texture_format_is_alpha_like(entries[i].format)) continue;
                if (texture_name_ends_with_slot(entries[i].name, "1") ||
                    texture_name_ends_with_slot(entries[i].name, "0")) {
                    aux_prefix = (int)i;
                    break;
                }
            }
        } else {
            aux_prefix = selected;
        }
        if (selected_dummy) {
            image_fill(&model->texture, 0xffffff);
            model->average_color = 0xffffff;
        }
        for (i = 0; i < (uint32_t)entry_count; i++) {
            if ((int)i == selected) continue;
            if (aux_prefix >= 0 && !texture_names_share_prefix(entries[aux_prefix].name, entries[i].name)) continue;
            if (texture_name_is_normal(entries[i].name)) {
                uint32_t normal_average;
                if (cgfx_decode_texture(bytes, size, entries[i].object,
                    &model->normal_texture, &normal_average, 0x8080ff, NULL)) {
                    model->has_normal_texture = 1;
                }
                continue;
            }
            if (texture_name_ends_with_slot(entries[i].name, "1") && !texture_format_is_alpha_like(entries[i].format)) {
                uint32_t mask_average;
                if (cgfx_decode_texture(bytes, size, entries[i].object,
                    &model->mask_texture, &mask_average, 0xffffff, NULL)) {
                    model->has_mask_texture = 1;
                }
                continue;
            }
            if (!texture_format_is_alpha_like(entries[i].format)) continue;
            if (cgfx_decode_texture(bytes, size, entries[i].object,
                &alpha, &alpha_average, 0xffffff, NULL)) {
                cgfx_apply_alpha_image(&model->texture, &alpha);
                image_free(&alpha);
                model->average_color = cgfx_average_color(&model->texture, fallback_color);
                break;
            }
        }
        model->has_texture = 1;
        return 1;
    }
    return 0;
}

static void cgfx_color_param_to_vec(uint32_t value, double out[4]) {
    out[0] = (double)(value & 0xffu) / 255.0;
    out[1] = (double)((value >> 8) & 0xffu) / 255.0;
    out[2] = (double)((value >> 16) & 0xffu) / 255.0;
    out[3] = (double)((value >> 24) & 0xffu) / 255.0;
}

static void cgfx_texenv_stage_default(CgfxTexEnvStage *stage) {
    int i;
    memset(stage, 0, sizeof(*stage));
    for (i = 0; i < 3; i++) {
        stage->source_color[i] = 15;
        stage->source_alpha[i] = 15;
        stage->operand_color[i] = 0;
        stage->operand_alpha[i] = 0;
    }
    stage->combiner_color = 0;
    stage->combiner_alpha = 0;
    stage->constant_selector = 0;
    stage->constant[3] = 1.0;
}

static void cgfx_material_default(CgfxMaterial *material) {
    int i;
    memset(material, 0, sizeof(*material));
    material->buffer_color[3] = 1.0;
    material->ambient[0] = material->ambient[1] = material->ambient[2] = 1.0;
    material->ambient[3] = 1.0;
    material->diffuse[0] = material->diffuse[1] = material->diffuse[2] = 1.0;
    material->diffuse[3] = 1.0;
    for (i = 0; i < 6; i++) {
        material->constant_colors[i][0] = 1.0;
        material->constant_colors[i][1] = 1.0;
        material->constant_colors[i][2] = 1.0;
        material->constant_colors[i][3] = 1.0;
    }
    for (i = 0; i < 6; i++) cgfx_texenv_stage_default(&material->stages[i]);
    for (i = 0; i < 3; i++) {
        material->tex_scale[i][0] = 1.0;
        material->tex_scale[i][1] = 1.0;
        material->tex_transform_type[i] = 0;
    }
}

static int cgfx_texenv_stage_index_from_register(uint32_t reg) {
    switch (reg) {
        case 0x00c0u: return 0;
        case 0x00c8u: return 1;
        case 0x00d0u: return 2;
        case 0x00d8u: return 3;
        case 0x00f0u: return 4;
        case 0x00f8u: return 5;
        default: return -1;
    }
}

static void cgfx_texenv_stage_from_params(CgfxTexEnvStage *stage, const uint32_t params[5]) {
    int i;
    for (i = 0; i < 3; i++) {
        stage->source_color[i] = (int)((params[0] >> (i * 4)) & 0x0fu);
        stage->source_alpha[i] = (int)((params[0] >> (16 + i * 4)) & 0x0fu);
        stage->operand_color[i] = (int)((params[1] >> (i * 4)) & 0x0fu);
        stage->operand_alpha[i] = (int)((params[1] >> (12 + i * 4)) & 0x07u);
    }
    stage->combiner_color = (int)(params[2] & 0x0fu);
    stage->combiner_alpha = (int)((params[2] >> 16) & 0x0fu);
    cgfx_color_param_to_vec(params[3], stage->constant);
    stage->scale_color = (int)(params[4] & 0x03u);
    stage->scale_alpha = (int)((params[4] >> 16) & 0x03u);
}

static void cgfx_parse_material_color_slots(const uint8_t *bytes, size_t size,
    size_t mtob, CgfxMaterial *material) {
    size_t packed = mtob + 0xd4u;
    int i;
    if (!checked_range(size, packed, 44u)) return;

    /* GfxMaterialColor stores packed RGBA after the float color block:
       emission, ambient, diffuse, specular0/1, then Constant0..5. */
    cgfx_color_param_to_vec(rd_u32(bytes + packed + 0u), material->emission);
    cgfx_color_param_to_vec(rd_u32(bytes + packed + 4u), material->ambient);
    cgfx_color_param_to_vec(rd_u32(bytes + packed + 8u), material->diffuse);
    cgfx_color_param_to_vec(rd_u32(bytes + packed + 12u), material->specular0);
    cgfx_color_param_to_vec(rd_u32(bytes + packed + 16u), material->specular1);
    for (i = 0; i < 6; i++) {
        cgfx_color_param_to_vec(rd_u32(bytes + packed + 20u + (size_t)i * 4u),
            material->constant_colors[i]);
    }
    material->ambient[3] = 1.0;
    material->diffuse[3] = 1.0;
    material->specular0[3] = 1.0;
    material->specular1[3] = 1.0;
}

static void cgfx_texenv_set_update_buffer(CgfxMaterial *material, uint32_t value) {
    material->stages[1].update_color_buffer = (value & 0x0100u) != 0;
    material->stages[2].update_color_buffer = (value & 0x0200u) != 0;
    material->stages[3].update_color_buffer = (value & 0x0400u) != 0;
    material->stages[4].update_color_buffer = (value & 0x0800u) != 0;
    material->stages[1].update_alpha_buffer = (value & 0x1000u) != 0;
    material->stages[2].update_alpha_buffer = (value & 0x2000u) != 0;
    material->stages[3].update_alpha_buffer = (value & 0x4000u) != 0;
    material->stages[4].update_alpha_buffer = (value & 0x8000u) != 0;
}

static void cgfx_parse_material_texcoords(const uint8_t *bytes, size_t size,
    size_t mtob, CgfxMaterial *material) {
    size_t base = mtob + 0x16cu;
    int i;
    for (i = 0; i < 3; i++) {
        size_t coord = base + (size_t)i * 0x58u;
        float sx, sy, tx, ty, rot;
        uint32_t source_coord;
        uint32_t mapping;
        uint32_t reference_camera;
        uint32_t transform_type;
        if (!checked_range(size, coord, 0x28u)) continue;
        source_coord = rd_u32(bytes + coord + 0x00u);
        mapping = rd_u32(bytes + coord + 0x04u);
        reference_camera = rd_u32(bytes + coord + 0x08u);
        transform_type = rd_u32(bytes + coord + 0x0cu);
        sx = rd_f32(bytes + coord + 0x10u);
        sy = rd_f32(bytes + coord + 0x14u);
        rot = rd_f32(bytes + coord + 0x18u);
        tx = rd_f32(bytes + coord + 0x1cu);
        ty = rd_f32(bytes + coord + 0x20u);
        if (source_coord > 3u || mapping > 3u || reference_camera > 32u ||
            transform_type > 2u ||
            fabs(sx) < 0.000001f || fabs(sy) < 0.000001f ||
            fabs(sx) > 16.0f || fabs(sy) > 16.0f ||
            fabs(tx) > 64.0f || fabs(ty) > 64.0f) {
            continue;
        }
        material->tex_scale[i][0] = sx;
        material->tex_scale[i][1] = sy;
        material->tex_rotation[i] = rot;
        material->tex_translate[i][0] = tx;
        material->tex_translate[i][1] = ty;
        material->tex_transform_type[i] = (int)transform_type;
        material->tex_source_coord[i] = (int)source_coord;
        material->tex_mapping_type[i] = (int)mapping;
        material->has_texcoord[i] = 1;
    }
}

static int cgfx_parse_material_texenv_at(const uint8_t *bytes, size_t size, size_t mtob,
    CgfxMaterial *material) {
    size_t pos;
    size_t end;
    int stage_hits = 0;
    cgfx_material_default(material);
    if (!mtob || !checked_range(size, mtob + 8u, 4) ||
        !cgfx_magic(bytes, size, mtob + 4u, "MTOB")) return 0;
    cgfx_parse_material_color_slots(bytes, size, mtob, material);
    cgfx_parse_material_texcoords(bytes, size, mtob, material);
    end = mtob + 0x900u;
    if (end > size) end = size;

    for (pos = mtob; pos + 24u <= end; pos += 4u) {
        uint32_t command = rd_u32(bytes + pos + 4u);
        uint32_t reg = command & 0xffffu;
        int stage_index = cgfx_texenv_stage_index_from_register(reg);
        if ((command & 0x80000000u) != 0 && stage_index >= 0 &&
            ((command >> 20) & 0x7ffu) >= 4u) {
            uint32_t params[5];
            params[0] = rd_u32(bytes + pos);
            params[1] = rd_u32(bytes + pos + 8u);
            params[2] = rd_u32(bytes + pos + 12u);
            params[3] = rd_u32(bytes + pos + 16u);
            params[4] = rd_u32(bytes + pos + 20u);
            cgfx_texenv_stage_from_params(&material->stages[stage_index], params);
            if (checked_range(size, pos - 4u, 4)) {
                uint32_t selector = rd_u32(bytes + pos - 4u);
                if (selector <= 10u) material->stages[stage_index].constant_selector = (int)selector;
            }
            stage_hits++;
        } else if (reg == 0x00fdu) {
            cgfx_color_param_to_vec(rd_u32(bytes + pos), material->buffer_color);
        } else if (reg == 0x00e0u) {
            cgfx_texenv_set_update_buffer(material, rd_u32(bytes + pos));
        }
    }

    material->has_texenv = stage_hits >= 6;
    return material->has_texenv;
}

static int cgfx_parse_material_texenv(const uint8_t *bytes, size_t size, CgfxMaterial *material) {
    size_t pos;
    for (pos = 4; pos + 4u <= size; pos++) {
        if (memcmp(bytes + pos, "MTOB", 4) == 0) {
            return cgfx_parse_material_texenv_at(bytes, size, pos - 4u, material);
        }
    }
    return 0;
}

static int cgfx_model_add_material(CgfxModel *model, const CgfxMaterial *material) {
    CgfxMaterial *next;
    if (!model || !material) return 0;
    next = (CgfxMaterial *)realloc(model->materials,
        (size_t)(model->material_count + 1) * sizeof(CgfxMaterial));
    if (!next) return 0;
    model->materials = next;
    model->materials[model->material_count] = *material;
    model->material_count++;
    return 1;
}

static int cgfx_load_materials(const uint8_t *bytes, size_t size, CgfxModel *model) {
    size_t pos;
    int loaded = 0;
    if (!model) return 0;
    for (pos = 4; pos + 4u <= size; pos++) {
        if (memcmp(bytes + pos, "MTOB", 4) == 0) {
            CgfxMaterial material;
            if (cgfx_parse_material_texenv_at(bytes, size, pos - 4u, &material) &&
                cgfx_model_add_material(model, &material)) {
                if (loaded == 0) model->material = material;
                loaded++;
            }
        }
    }
    return loaded;
}

static int cgfx_parse_skeleton(const uint8_t *bytes, size_t size, size_t skeleton_offset,
    CgfxModel *model) {
    size_t dict;
    uint32_t count;
    uint32_t i;
    CgfxBone *bones;
    if (!skeleton_offset ||
        !checked_range(size, skeleton_offset + 0x20u, 4) ||
        rd_u32(bytes + skeleton_offset) != 0x02000000u ||
        !cgfx_magic(bytes, size, skeleton_offset + 4u, "SOBJ")) {
        return 0;
    }
    count = rd_u32(bytes + skeleton_offset + 0x18u);
    dict = cgfx_rel(bytes, size, skeleton_offset + 0x1cu);
    if (!dict || !cgfx_magic(bytes, size, dict, "DICT") || count == 0 || count > 512u) return 0;

    bones = (CgfxBone *)calloc((size_t)count, sizeof(CgfxBone));
    if (!bones) return 0;
    for (i = 0; i < count; i++) {
        size_t object;
        char name[64];
        CgfxBone *bone = &bones[i];
        if (!cgfx_dict_entry(bytes, size, dict, i, &object, name, sizeof(name)) ||
            !checked_range(size, object + 0xd8u, 4)) {
            free(bones);
            return 0;
        }
        strncpy(bone->name, name, sizeof(bone->name) - 1u);
        bone->name[sizeof(bone->name) - 1u] = '\0';
        bone->index = rd_i32(bytes + object + 0x08u);
        bone->parent_index = rd_i32(bytes + object + 0x0cu);
        bone->flags = rd_u32(bytes + object + 0x14u);
        bone->base_scale.x = rd_f32(bytes + object + 0x20u);
        bone->base_scale.y = rd_f32(bytes + object + 0x24u);
        bone->base_scale.z = rd_f32(bytes + object + 0x28u);
        bone->base_rotation.x = rd_f32(bytes + object + 0x2cu);
        bone->base_rotation.y = rd_f32(bytes + object + 0x30u);
        bone->base_rotation.z = rd_f32(bytes + object + 0x34u);
        bone->base_translation.x = rd_f32(bytes + object + 0x38u);
        bone->base_translation.y = rd_f32(bytes + object + 0x3cu);
        bone->base_translation.z = rd_f32(bytes + object + 0x40u);
        mtx34_read(bytes, object + 0x44u, bone->local);
        mtx34_read(bytes, object + 0xa4u, bone->inv_world);
        mtx34_identity(bone->scaled_world);
        mtx34_identity(bone->skin_matrix);
    }

    model->bones = bones;
    model->bone_count = (int)count;
    model->has_skeleton = 1;
    return 1;
}

static int cgfx_find_bone_index(const CgfxModel *model, const char *name) {
    int i;
    if (!model || !name) return -1;
    for (i = 0; i < model->bone_count; i++) {
        if (strcmp(model->bones[i].name, name) == 0) return i;
    }
    return -1;
}

static int cgfx_bone_world_translation(const CgfxModel *model, const char *name, Vec3 *out) {
    int index = cgfx_find_bone_index(model, name);
    if (index < 0 || !out) return 0;
    mtx34_get_translation(model->bones[index].scaled_world, out);
    return 1;
}

typedef struct {
    double frame;
    double value;
    double in_slope;
    double out_slope;
} CgfxAnimKey;

static int32_t sign_extend_u32(uint32_t value, int bits) {
    uint32_t mask = 1u << (bits - 1);
    return (int32_t)((value ^ mask) - mask);
}

static uint32_t rd_u24(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

static size_t cgfx_anim_key_size(uint32_t quantization) {
    switch (quantization) {
        case 0: return 16u;
        case 1: return 8u;
        case 2: return 6u;
        case 3: return 12u;
        case 4: return 6u;
        case 5: return 4u;
        case 6: return 8u;
        case 7: return 4u;
        default: return 0u;
    }
}

static int cgfx_anim_read_key(const uint8_t *bytes, size_t size, size_t offset,
    uint32_t quantization, double frame_scale, double value_scale,
    double value_offset, CgfxAnimKey *out) {
    uint32_t packed;
    uint32_t slopes;
    if (!out) return 0;
    memset(out, 0, sizeof(*out));

    switch (quantization) {
        case 0:
            if (!checked_range(size, offset, 16u)) return 0;
            out->frame = rd_f32(bytes + offset + 0x00u);
            out->value = rd_f32(bytes + offset + 0x04u);
            out->in_slope = rd_f32(bytes + offset + 0x08u);
            out->out_slope = rd_f32(bytes + offset + 0x0cu);
            break;

        case 1:
            if (!checked_range(size, offset, 8u)) return 0;
            packed = rd_u32(bytes + offset);
            out->frame = (double)(packed & 0xfffu);
            out->value = (double)((packed >> 12) & 0xfffffu);
            out->in_slope = (double)rd_i16(bytes + offset + 4u) / 256.0;
            out->out_slope = (double)rd_i16(bytes + offset + 6u) / 256.0;
            break;

        case 2:
            if (!checked_range(size, offset, 6u)) return 0;
            out->frame = (double)bytes[offset];
            out->value = (double)rd_u16(bytes + offset + 1u);
            slopes = rd_u24(bytes + offset + 3u);
            out->in_slope = (double)sign_extend_u32(slopes & 0xfffu, 12) / 32.0;
            out->out_slope = (double)sign_extend_u32((slopes >> 12) & 0xfffu, 12) / 32.0;
            break;

        case 3:
            if (!checked_range(size, offset, 12u)) return 0;
            out->frame = rd_f32(bytes + offset + 0x00u);
            out->value = rd_f32(bytes + offset + 0x04u);
            out->in_slope = rd_f32(bytes + offset + 0x08u);
            out->out_slope = out->in_slope;
            break;

        case 4:
            if (!checked_range(size, offset, 6u)) return 0;
            out->frame = (double)rd_u16(bytes + offset + 0u) / 32.0;
            out->value = (double)rd_u16(bytes + offset + 2u);
            out->in_slope = (double)rd_i16(bytes + offset + 4u) / 256.0;
            out->out_slope = out->in_slope;
            break;

        case 5:
            if (!checked_range(size, offset, 4u)) return 0;
            out->frame = (double)bytes[offset];
            packed = rd_u24(bytes + offset + 1u);
            out->value = (double)(packed & 0xfffu);
            out->in_slope = (double)sign_extend_u32((packed >> 12) & 0xfffu, 12) / 32.0;
            out->out_slope = out->in_slope;
            break;

        case 6:
            if (!checked_range(size, offset, 8u)) return 0;
            out->frame = rd_f32(bytes + offset + 0x00u);
            out->value = rd_f32(bytes + offset + 0x04u);
            break;

        case 7:
            if (!checked_range(size, offset, 4u)) return 0;
            packed = rd_u32(bytes + offset);
            out->frame = (double)(packed & 0xfffu);
            out->value = (double)((packed >> 12) & 0xfffffu);
            break;

        default:
            return 0;
    }

    out->frame *= frame_scale;
    out->value = out->value * value_scale + value_offset;
    return isfinite(out->frame) && isfinite(out->value) &&
        isfinite(out->in_slope) && isfinite(out->out_slope);
}

static double cgfx_hermite(double lhs, double rhs, double lhs_slope,
    double rhs_slope, double frame_diff, double weight) {
    double result = lhs + (lhs - rhs) * (2.0 * weight - 3.0) * weight * weight;
    result += (frame_diff * (weight - 1.0)) *
        (lhs_slope * (weight - 1.0) + rhs_slope * weight);
    return result;
}

static int cgfx_anim_curve_value(const uint8_t *bytes, size_t size, size_t group,
    double frame, double *value) {
    uint32_t curve_flags;
    uint32_t curve_count;
    size_t curve;
    uint32_t format_flags;
    uint32_t quantization;
    uint32_t key_count;
    float inv_duration;
    double value_scale = 1.0;
    double value_offset = 0.0;
    double frame_scale = 1.0;
    size_t key_base;
    size_t key_size;
    uint32_t i;
    CgfxAnimKey lhs;
    CgfxAnimKey rhs;

    if (!checked_range(size, group + 0x14u, 4) || !value) return 0;
    curve_flags = rd_u32(bytes + group + 0x0cu);
    if ((curve_flags & 0x02u) != 0) {
        if (!checked_range(size, group + 0x10u, 4)) return 0;
        *value = rd_f32(bytes + group + 0x10u);
        return isfinite(*value);
    }
    if ((curve_flags & 0x04u) == 0) return 0;

    curve_count = rd_u32(bytes + group + 0x10u);
    if (curve_count == 0 || curve_count > 16u) return 0;
    curve = cgfx_rel(bytes, size, group + 0x14u);
    if (!curve || !checked_range(size, curve + 0x14u, 4)) return 0;

    format_flags = rd_u32(bytes + curve + 0x08u);
    key_count = rd_u32(bytes + curve + 0x0cu);
    inv_duration = rd_f32(bytes + curve + 0x10u);
    quantization = format_flags >> 5;
    if (key_count == 0 || key_count > 4096u || quantization > 7u ||
        !isfinite(inv_duration)) {
        return 0;
    }

    key_base = curve + 0x14u;
    if (quantization != 0u && quantization != 3u && quantization != 6u) {
        if (!checked_range(size, curve + 0x20u, 4)) return 0;
        value_scale = rd_f32(bytes + curve + 0x14u);
        value_offset = rd_f32(bytes + curve + 0x18u);
        frame_scale = rd_f32(bytes + curve + 0x1cu);
        key_base = curve + 0x20u;
        if (!isfinite(value_scale) || !isfinite(value_offset) || !isfinite(frame_scale)) return 0;
    }

    key_size = cgfx_anim_key_size(quantization);
    if (key_size == 0 || !checked_range(size, key_base, (size_t)key_count * key_size)) return 0;

    if (!cgfx_anim_read_key(bytes, size, key_base, quantization,
            frame_scale, value_scale, value_offset, &lhs)) {
        return 0;
    }
    rhs = lhs;
    if (key_count > 1u &&
        !cgfx_anim_read_key(bytes, size, key_base + (size_t)(key_count - 1u) * key_size,
            quantization, frame_scale, value_scale, value_offset, &rhs)) {
        return 0;
    }

    for (i = 0; i < key_count; i++) {
        CgfxAnimKey key;
        if (!cgfx_anim_read_key(bytes, size, key_base + (size_t)i * key_size,
                quantization, frame_scale, value_scale, value_offset, &key)) {
            return 0;
        }
        if (key.frame <= frame) lhs = key;
        if (key.frame >= frame && key.frame < rhs.frame) rhs = key;
    }

    if (fabs(lhs.frame - rhs.frame) <= 0.000001) {
        *value = lhs.value;
    } else {
        double frame_diff = frame - lhs.frame;
        double weight = frame_diff / (rhs.frame - lhs.frame);
        if (weight < 0.0) weight = 0.0;
        if (weight > 1.0) weight = 1.0;
        if (quantization >= 6u) {
            *value = (format_flags & 0x04u) != 0
                ? lhs.value * (1.0 - weight) + rhs.value * weight
                : lhs.value;
        } else {
            *value = cgfx_hermite(lhs.value, rhs.value, lhs.out_slope,
                rhs.in_slope, frame_diff, weight);
        }
    }
    return isfinite(*value) && fabs(*value) <= 100000.0;
}

static int cgfx_anim_transform_channel_value(const uint8_t *bytes, size_t size,
    size_t object, int channel, double frame, double *value) {
    uint32_t flags;
    uint32_t constant_mask;
    uint32_t inexistent_mask;
    size_t field;
    size_t group;

    if (!checked_range(size, object + 0x30u, 4) || channel < 0 || channel > 9 || !value) return 0;
    flags = rd_u32(bytes + object);
    constant_mask = 1u << (6 + channel);
    inexistent_mask = 1u << (16 + channel);
    if ((flags & inexistent_mask) != 0) return 0;

    field = object + 0x0cu + (size_t)channel * 4u;
    if (!checked_range(size, field, 4)) return 0;
    if ((flags & constant_mask) != 0) {
        *value = rd_f32(bytes + field);
        return isfinite(*value) && fabs(*value) <= 100000.0;
    }

    group = cgfx_rel(bytes, size, field);
    if (!group) return 0;
    return cgfx_anim_curve_value(bytes, size, group, frame, value);
}

static size_t cgfx_next_dict_object_after(const uint8_t *bytes, size_t size, size_t dict,
    size_t object, size_t fallback_end) {
    uint32_t count = cgfx_dict_count(bytes, size, dict);
    uint32_t i;
    size_t next = fallback_end;
    for (i = 0; i < count; i++) {
        size_t candidate;
        if (!cgfx_dict_entry(bytes, size, dict, i, &candidate, NULL, 0)) continue;
        if (candidate > object && candidate < next) next = candidate;
    }
    return next;
}

static int cgfx_find_animation_object(const uint8_t *bytes, size_t size, const char *name,
    size_t *object, size_t *object_end) {
    size_t dict;
    uint32_t count;
    uint32_t i;
    if (!cgfx_data_dict(bytes, size, 9, &dict)) return 0;
    count = cgfx_dict_count(bytes, size, dict);
    for (i = 0; i < count; i++) {
        size_t candidate;
        char candidate_name[128];
        if (!cgfx_dict_entry(bytes, size, dict, i, &candidate, candidate_name, sizeof(candidate_name))) continue;
        if (strcmp(candidate_name, name) != 0) continue;
        *object = candidate;
        *object_end = cgfx_next_dict_object_after(bytes, size, dict, candidate, size);
        return 1;
    }
    return 0;
}

static int cgfx_apply_canm_pose(CgfxModel *model, const uint8_t *bytes, size_t size,
    size_t canm, size_t canm_end, double frame) {
    size_t dict;
    uint32_t count;
    uint32_t i;
    int applied = 0;
    (void)canm_end;
    if (!model || !model->has_skeleton || !cgfx_magic(bytes, size, canm, "CANM")) return 0;
    dict = canm + 0x28u;
    if (!checked_range(size, dict + 0x0cu, 4) || !cgfx_magic(bytes, size, dict, "DICT")) return 0;
    count = cgfx_dict_count(bytes, size, dict);
    for (i = 0; i < count; i++) {
        char bone_name[64];
        size_t object;
        int bone_index;
        Vec3 translation;
        Vec3 rotation;
        Vec3 scale;
        double value;
        int has_channel = 0;
        if (!cgfx_dict_entry(bytes, size, dict, i, &object, bone_name, sizeof(bone_name))) continue;
        if (!checked_range(size, object + 0x30u, 4) || rd_u32(bytes + object + 0x08u) != 5u) continue;
        bone_index = cgfx_find_bone_index(model, bone_name);
        if (bone_index < 0) continue;

        scale = model->bones[bone_index].base_scale;
        rotation = model->bones[bone_index].base_rotation;
        translation = model->bones[bone_index].base_translation;

        if (cgfx_anim_transform_channel_value(bytes, size, object, 0, frame, &value)) {
            scale.x = value;
            has_channel = 1;
        }
        if (cgfx_anim_transform_channel_value(bytes, size, object, 1, frame, &value)) {
            scale.y = value;
            has_channel = 1;
        }
        if (cgfx_anim_transform_channel_value(bytes, size, object, 2, frame, &value)) {
            scale.z = value;
            has_channel = 1;
        }
        if (cgfx_anim_transform_channel_value(bytes, size, object, 3, frame, &value)) {
            rotation.x = value;
            has_channel = 1;
        }
        if (cgfx_anim_transform_channel_value(bytes, size, object, 4, frame, &value)) {
            rotation.y = value;
            has_channel = 1;
        }
        if (cgfx_anim_transform_channel_value(bytes, size, object, 5, frame, &value)) {
            rotation.z = value;
            has_channel = 1;
        }
        if (cgfx_anim_transform_channel_value(bytes, size, object, 7, frame, &value)) {
            translation.x = value;
            has_channel = 1;
        }
        if (cgfx_anim_transform_channel_value(bytes, size, object, 8, frame, &value)) {
            translation.y = value;
            has_channel = 1;
        }
        if (cgfx_anim_transform_channel_value(bytes, size, object, 9, frame, &value)) {
            translation.z = value;
            has_channel = 1;
        }
        if (!has_channel) continue;

        mtx34_make_srt(model->bones[bone_index].local, scale.x, scale.y, scale.z,
            rotation, translation);
        applied++;
    }
    return applied > 0;
}

static int cgfx_apply_skeletal_animation_file(CgfxModel *model, const char *path,
    const char *animation_name, double frame) {
    Buffer buffer;
    size_t animation;
    size_t animation_end;
    int ok;
    memset(&buffer, 0, sizeof(buffer));
    if (!model || !path || !animation_name || !read_file(path, &buffer)) return 0;
    ok = cgfx_find_animation_object(buffer.data, buffer.size, animation_name, &animation, &animation_end) &&
        cgfx_apply_canm_pose(model, buffer.data, buffer.size, animation, animation_end, frame);
    free(buffer.data);
    return ok;
}

static int apply_tomodachi_body_wait_pose(CgfxModel *model, const char *body_dir) {
    char path[1024];
    if (!body_dir || !body_dir[0]) return 0;
    snprintf(path, sizeof(path), "%s/body_common_animCm.bin.dat", body_dir);
    if (!file_exists(path)) return 0;
    /* Local source queues bodyCmWait00 and attaches the face through P_DummyFace. */
    return cgfx_apply_skeletal_animation_file(model, path, "bodyCmWait00", 0.0);
}

static void cgfx_update_body_skin_matrices(CgfxModel *model) {
    int i;
    if (!model || !model->has_skeleton || model->bone_count <= 0) return;

    for (i = 0; i < model->bone_count; i++) {
        CgfxBone *bone = &model->bones[i];
        if (bone->parent_index >= 0 && bone->parent_index < model->bone_count) {
            mtx34_mul(bone->scaled_world, model->bones[bone->parent_index].scaled_world, bone->local);
        } else {
            mtx34_copy(bone->scaled_world, bone->local);
        }
    }

    for (i = 0; i < model->bone_count; i++) {
        mtx34_mul(model->bones[i].skin_matrix, model->bones[i].scaled_world, model->bones[i].inv_world);
    }
}

static int cgfx_apply_body_skinning(CgfxModel *model) {
    int mesh_index;
    int any = 0;
    if (!model || !model->has_skeleton || model->bone_count <= 0) return 0;
    cgfx_update_body_skin_matrices(model);
    for (mesh_index = 0; mesh_index < model->mesh_count; mesh_index++) {
        CgfxMesh *mesh = &model->meshes[mesh_index];
        int i;
        if (!mesh->has_skin || !mesh->bone_indices || !mesh->bone_weights) continue;
        bounds_reset(&mesh->min, &mesh->max);
        for (i = 0; i < mesh->vertex_count; i++) {
            Vec3 source_pos = mesh->vertices[i];
            Vec3 source_normal = mesh->has_normals && mesh->normals ? mesh->normals[i] : (Vec3){ 0.0, 0.0, 1.0 };
            Vec3 source_tangent = mesh->has_tangents && mesh->tangents ? mesh->tangents[i] : (Vec3){ 1.0, 0.0, 0.0 };
            Vec3 skinned_pos = { 0.0, 0.0, 0.0 };
            Vec3 skinned_normal = { 0.0, 0.0, 0.0 };
            Vec3 skinned_tangent = { 0.0, 0.0, 0.0 };
            double weight_sum = 0.0;
            int influence;
            for (influence = 0; influence < CGFX_MAX_BONE_INFLUENCES; influence++) {
                size_t idx = (size_t)i * CGFX_MAX_BONE_INFLUENCES + (size_t)influence;
                int bone_index = mesh->bone_indices[idx];
                double weight = mesh->bone_weights[idx];
                Vec3 p;
                Vec3 n;
                Vec3 t;
                if (weight <= 0.000001 || bone_index < 0 || bone_index >= model->bone_count) continue;
                p = mtx34_transform_point(model->bones[bone_index].skin_matrix, source_pos);
                n = mtx34_transform_vector(model->bones[bone_index].skin_matrix, source_normal);
                t = mtx34_transform_vector(model->bones[bone_index].skin_matrix, source_tangent);
                skinned_pos.x += p.x * weight;
                skinned_pos.y += p.y * weight;
                skinned_pos.z += p.z * weight;
                skinned_normal.x += n.x * weight;
                skinned_normal.y += n.y * weight;
                skinned_normal.z += n.z * weight;
                skinned_tangent.x += t.x * weight;
                skinned_tangent.y += t.y * weight;
                skinned_tangent.z += t.z * weight;
                weight_sum += weight;
            }
            if (weight_sum > 0.000001) {
                mesh->vertices[i] = skinned_pos;
                if (mesh->has_normals && mesh->normals) mesh->normals[i] = vec3_normalize(skinned_normal);
                if (mesh->has_tangents && mesh->tangents) mesh->tangents[i] = vec3_normalize(skinned_tangent);
            }
            bounds_include(&mesh->min, &mesh->max, mesh->vertices[i]);
        }
        any = 1;
    }
    if (any) cgfx_model_update_bounds(model);
    return any;
}

static int cgfx_load_model_from_buffer(const uint8_t *bytes, size_t size,
    uint32_t fallback_color, CgfxModel *model) {
    size_t model_dict;
    size_t cmdl = 0;
    uint32_t dict_count;
    uint32_t i;

    memset(model, 0, sizeof(*model));
    model->average_color = fallback_color;
    if (!cgfx_data_dict(bytes, size, 0, &model_dict)) return 0;
    dict_count = cgfx_dict_count(bytes, size, model_dict);
    for (i = 0; i < dict_count; i++) {
        size_t object;
        if (!cgfx_dict_entry(bytes, size, model_dict, i, &object, NULL, 0)) continue;
        if (cgfx_magic(bytes, size, object + 4u, "CMDL")) {
            cmdl = object;
            break;
        }
    }
    if (!cmdl) return 0;

    if (rd_u32(bytes + cmdl) == 0x40000092u && checked_range(size, cmdl + 0xe4u, 4)) {
        cgfx_parse_skeleton(bytes, size, cgfx_rel(bytes, size, cmdl + 0xe0u), model);
    }
    cgfx_load_first_texture(bytes, size, model, fallback_color);
    if (!cgfx_load_materials(bytes, size, model)) {
        cgfx_parse_material_texenv(bytes, size, &model->material);
    }

    {
        uint32_t shape_count;
        size_t shape_list;
        uint32_t mesh_count = 0;
        size_t mesh_list = 0;
        uint32_t mesh_index;
        if (!checked_range(size, cmdl + 0xb4u, 4) ||
            !checked_range(size, cmdl + 0xb8u, 4) ||
            !checked_range(size, cmdl + 0xc4u, 4) ||
            !checked_range(size, cmdl + 0xc8u, 4)) {
            cgfx_model_free(model);
            return 0;
        }
        mesh_count = rd_u32(bytes + cmdl + 0xb4u);
        mesh_list = cgfx_rel(bytes, size, cmdl + 0xb8u);
        shape_count = rd_u32(bytes + cmdl + 0xc4u);
        shape_list = cgfx_rel(bytes, size, cmdl + 0xc8u);
        if (!shape_list || shape_count > 4096u) {
            cgfx_model_free(model);
            return 0;
        }
        if (mesh_list && mesh_count <= 4096u) {
            for (mesh_index = 0; mesh_index < mesh_count; mesh_index++) {
                size_t mesh_field = mesh_list + (size_t)mesh_index * 4u;
                size_t mesh_object;
                int32_t shape_index;
                int material_index;
                int visible;
                size_t shape_field;
                size_t shape_object;
                CgfxMesh mesh;
                memset(&mesh, 0, sizeof(mesh));
                if (!checked_range(size, mesh_field, 4)) break;
                mesh_object = (size_t)((int64_t)mesh_field + (int64_t)rd_i32(bytes + mesh_field));
                if (!checked_range(size, mesh_object + 0x28u, 4) ||
                    !cgfx_magic(bytes, size, mesh_object + 4u, "SOBJ")) {
                    continue;
                }
                shape_index = rd_i32(bytes + mesh_object + 0x18u);
                material_index = rd_i32(bytes + mesh_object + 0x1cu);
                visible = bytes[mesh_object + 0x24u] != 0;
                if (!visible || shape_index < 0 || (uint32_t)shape_index >= shape_count) continue;
                shape_field = shape_list + (size_t)shape_index * 4u;
                if (!checked_range(size, shape_field, 4)) continue;
                shape_object = (size_t)((int64_t)shape_field + (int64_t)rd_i32(bytes + shape_field));
                if (!cgfx_parse_sobj_mesh(bytes, size, shape_object, &mesh)) continue;
                mesh.material_index = material_index;
                cgfx_string(bytes, size,
                    cgfx_rel(bytes, size, mesh_object + 0x70u),
                    mesh.mesh_node_name, sizeof(mesh.mesh_node_name));
                if (!cgfx_model_add_mesh(model, &mesh)) {
                    cgfx_mesh_free(&mesh);
                    cgfx_model_free(model);
                    return 0;
                }
            }
        }
        if (model->mesh_count <= 0) {
            for (mesh_index = 0; mesh_index < shape_count; mesh_index++) {
                size_t field = shape_list + (size_t)mesh_index * 4u;
                size_t sobj;
                CgfxMesh mesh;
                memset(&mesh, 0, sizeof(mesh));
                if (!checked_range(size, field, 4)) break;
                sobj = (size_t)((int64_t)field + (int64_t)rd_i32(bytes + field));
                if (!cgfx_parse_sobj_mesh(bytes, size, sobj, &mesh)) continue;
                mesh.material_index = -1;
                if (!cgfx_model_add_mesh(model, &mesh)) {
                    cgfx_mesh_free(&mesh);
                    cgfx_model_free(model);
                    return 0;
                }
            }
        }
    }

    if (model->mesh_count <= 0) {
        cgfx_model_free(model);
        return 0;
    }
    cgfx_model_update_bounds(model);
    cgfx_apply_single_bone_unskinned_transform(model);
    cgfx_apply_rigid_node_unskinned_transforms(model);
    return bounds_are_valid(model->min, model->max);
}

static int cgfx_load_model_file(const char *path, uint32_t fallback_color, CgfxModel *model) {
    Buffer buffer;
    int ok;
    memset(&buffer, 0, sizeof(buffer));
    if (!read_file(path, &buffer)) return 0;
    ok = cgfx_load_model_from_buffer(buffer.data, buffer.size, fallback_color, model);
    free(buffer.data);
    return ok;
}

static ShapeTransform shape_transform_identity(void) {
    ShapeTransform t;
    memset(&t, 0, sizeof(t));
    t.scale_x = 1.0;
    t.scale_y = 1.0;
    t.scale_z = 1.0;
    return t;
}

static Vec3 transform_point(Vec3 p, const ShapeTransform *transform) {
    if (transform) {
        if (transform->mirror_x) p.x = -p.x;
        if (transform->has_matrix) return mtx34_transform_point(transform->matrix, p);
        p.x = p.x * transform->scale_x + transform->translate_x;
        p.y = p.y * transform->scale_y + transform->translate_y;
        p.z = p.z * transform->scale_z + transform->translate_z;
    }
    return p;
}

static Vec3 transform_normal(Vec3 n, const ShapeTransform *transform) {
    if (transform && transform->has_matrix) {
        n = mtx34_transform_vector(transform->matrix, n);
    } else if (transform && transform->mirror_x) {
        n.x = -n.x;
    }
    return vec3_normalize(n);
}

static Vec3 shape_normal_at(const CflShape *shape, int index) {
    Vec3 normal = { 0.0, 0.0, 1.0 };
    if (!shape->normals || shape->normal_count == 0) return normal;
    if (shape->normal_count == 1) return shape->normals[0];
    if (index >= 0 && index < shape->normal_count) return shape->normals[index];
    return normal;
}

static Vec2 shape_uv_at(const CflShape *shape, int index) {
    Vec2 uv = { 0.5, 0.5 };
    if (!shape->texcoords || shape->texcoord_count == 0) return uv;
    if (shape->texcoord_count == 1) return shape->texcoords[0];
    if (index >= 0 && index < shape->texcoord_count) return shape->texcoords[index];
    return uv;
}

static void sample_image_uv(const Image *texture, double u, double v, int mirrored, uint8_t out[4]) {
    double fx;
    double fy;
    double wx;
    double wy;
    int x0;
    int y0;
    int x1;
    int y1;
    int c;
    if (!texture || !texture->rgba || texture->width <= 0 || texture->height <= 0) {
        out[0] = out[1] = out[2] = 255;
        out[3] = 0;
        return;
    }
    u = wrap_texture_coord(u, mirrored);
    v = wrap_texture_coord(v, mirrored);
    fx = u * (texture->width - 1);
    fy = v * (texture->height - 1);
    x0 = clamp_int((int)floor(fx), 0, texture->width - 1);
    y0 = clamp_int((int)floor(fy), 0, texture->height - 1);
    x1 = clamp_int(x0 + 1, 0, texture->width - 1);
    y1 = clamp_int(y0 + 1, 0, texture->height - 1);
    wx = fx - floor(fx);
    wy = fy - floor(fy);
    for (c = 0; c < 4; c++) {
        double p00 = texture->rgba[((size_t)y0 * (size_t)texture->width + (size_t)x0) * 4u + (size_t)c];
        double p10 = texture->rgba[((size_t)y0 * (size_t)texture->width + (size_t)x1) * 4u + (size_t)c];
        double p01 = texture->rgba[((size_t)y1 * (size_t)texture->width + (size_t)x0) * 4u + (size_t)c];
        double p11 = texture->rgba[((size_t)y1 * (size_t)texture->width + (size_t)x1) * 4u + (size_t)c];
        double p0 = p00 * (1.0 - wx) + p10 * wx;
        double p1 = p01 * (1.0 - wx) + p11 * wx;
        out[c] = (uint8_t)lrint(clamp_int((int)lrint(p0 * (1.0 - wy) + p1 * wy), 0, 255));
    }
}

static void color_to_pixel(uint32_t color, uint8_t out[4]) {
    out[0] = (uint8_t)((color >> 16) & 0xffu);
    out[1] = (uint8_t)((color >> 8) & 0xffu);
    out[2] = (uint8_t)(color & 0xffu);
    out[3] = 255;
}

static void tint_pixel_by_luma(const uint8_t source[4], uint32_t color, uint8_t out[4]) {
    uint8_t base[4];
    double luma = (0.299 * source[0] + 0.587 * source[1] + 0.114 * source[2]) / 255.0;
    color_to_pixel(color, base);
    out[0] = (uint8_t)lrint(clamp_unit((base[0] / 255.0) * luma) * 255.0);
    out[1] = (uint8_t)lrint(clamp_unit((base[1] / 255.0) * luma) * 255.0);
    out[2] = (uint8_t)lrint(clamp_unit((base[2] / 255.0) * luma) * 255.0);
    out[3] = source[3];
}

static void apply_body_material_mask(uint8_t pixel[4], const uint8_t mask[4],
    uint32_t body_color, uint32_t skin_color) {
    uint8_t target[4];
    double amount;
    int red = mask[0];
    int green = mask[1];
    int blue = mask[2];
    int color_weight = red > green ? red : green;
    int skin_weight = blue;

    if (mask[3] <= 0) return;
    if (color_weight > 16 && color_weight >= skin_weight - 16) {
        tint_pixel_by_luma(pixel, body_color, target);
        amount = color_weight / 255.0;
    } else if (skin_weight > 16) {
        tint_pixel_by_luma(pixel, skin_color, target);
        amount = skin_weight / 255.0;
    } else if (red <= 16 && green <= 16 && blue <= 16) {
        tint_pixel_by_luma(pixel, 0x202020, target);
        amount = mask[3] / 255.0;
    } else {
        return;
    }

    amount *= mask[3] / 255.0;
    pixel[0] = (uint8_t)lrint(pixel[0] * (1.0 - amount) + target[0] * amount);
    pixel[1] = (uint8_t)lrint(pixel[1] * (1.0 - amount) + target[1] * amount);
    pixel[2] = (uint8_t)lrint(pixel[2] * (1.0 - amount) + target[2] * amount);
    pixel[3] = target[3];
}

static void apply_headwear_material_mask(uint8_t pixel[4], const uint8_t mask[4],
    uint32_t headwear_color) {
    uint8_t base[4];
    double luma;
    double texture_luma;
    double detail;
    double alpha;
    int i;

    if (mask[3] <= 0) return;
    color_to_pixel(headwear_color, base);

    luma = (0.299 * mask[0] + 0.587 * mask[1] + 0.114 * mask[2]) / 255.0;
    texture_luma = (0.299 * pixel[0] + 0.587 * pixel[1] + 0.114 * pixel[2]) / 255.0;
    if (texture_luma < 0.05) texture_luma = 1.0;

    detail = 0.88 + luma * 0.24;
    detail *= 0.95 + texture_luma * 0.05;
    alpha = 1.0;

    for (i = 0; i < 3; i++) {
        pixel[i] = (uint8_t)lrint(clamp_unit((base[i] / 255.0) * detail) * 255.0);
    }
    pixel[3] = 255;
}

static void rgb_color_to_vec(uint32_t color, double out[4]) {
    out[0] = (double)((color >> 16) & 0xffu) / 255.0;
    out[1] = (double)((color >> 8) & 0xffu) / 255.0;
    out[2] = (double)(color & 0xffu) / 255.0;
    out[3] = 1.0;
}

static void pixel_to_vec4(const uint8_t pixel[4], double out[4]) {
    out[0] = (double)pixel[0] / 255.0;
    out[1] = (double)pixel[1] / 255.0;
    out[2] = (double)pixel[2] / 255.0;
    out[3] = (double)pixel[3] / 255.0;
}

static void vec4_to_pixel(const double color[4], uint8_t pixel[4]) {
    pixel[0] = (uint8_t)lrint(clamp_unit(color[0]) * 255.0);
    pixel[1] = (uint8_t)lrint(clamp_unit(color[1]) * 255.0);
    pixel[2] = (uint8_t)lrint(clamp_unit(color[2]) * 255.0);
    pixel[3] = (uint8_t)lrint(clamp_unit(color[3]) * 255.0);
}

static void cgfx_texenv_source_vec(int source, const CgfxTexEnvStage *stage,
    const double primary[4], const double fragment_primary[4], const double fragment_secondary[4],
    const double texture0[4], const double texture1[4], const double texture2[4],
    const double previous[4], const double buffer[4], double out[4]) {
    const double zero[4] = { 0.0, 0.0, 0.0, 1.0 };
    const double *selected = zero;
    switch (source) {
        case 0: selected = primary; break;
        case 1: selected = fragment_primary; break;
        case 2: selected = fragment_secondary; break;
        case 3: selected = texture0; break;
        case 4: selected = texture1; break;
        case 5: selected = texture2; break;
        case 13: selected = buffer; break;
        case 14: selected = stage->constant; break;
        case 15: selected = previous; break;
        default: selected = zero; break;
    }
    out[0] = selected[0];
    out[1] = selected[1];
    out[2] = selected[2];
    out[3] = selected[3];
}

static void cgfx_material_texcoord(const CgfxMaterial *material, int unit,
    double u, double v, double *out_u, double *out_v) {
    if (material && unit >= 0 && unit < 3 && material->has_texcoord[unit]) {
        double sx = material->tex_scale[unit][0];
        double sy = material->tex_scale[unit][1];
        double tx = material->tex_translate[unit][0];
        double ty = material->tex_translate[unit][1];
        double ca = cos(material->tex_rotation[unit]);
        double sa = sin(material->tex_rotation[unit]);
        double m11 = sx * ca;
        double m12 = sy * sa;
        double m21 = sx * -sa;
        double m22 = sy * ca;
        double m41 = 0.0;
        double m42 = 0.0;
        switch (material->tex_transform_type[unit]) {
            case 1:
                m41 = sx * (-ca * tx - sa * ty);
                m42 = sy * ( sa * tx - ca * ty);
                break;
            case 2:
                m41 = sx * ca * (-tx - 0.5) - sx * sa * ( ty - 0.5) + 0.5;
                m42 = sy * sa * (-tx - 0.5) + sy * ca * ( ty - 0.5) + 0.5;
                break;
            case 0:
            default:
                m41 = sx * ((0.5 *  sa - 0.5 * ca) + 0.5 - tx);
                m42 = sy * ((0.5 * -sa - 0.5 * ca) + 0.5 - ty);
                break;
        }
        *out_u = m11 * u + m21 * v + m41;
        *out_v = m12 * u + m22 * v + m42;
    } else {
        *out_u = u;
        *out_v = v;
    }
}

static void cgfx_texenv_color_operand(const double source[4], int operand, double out[3]) {
    int invert = operand & 1;
    int base = operand & ~1;
    int i;
    if (base == 2) {
        out[0] = out[1] = out[2] = source[3];
    } else if (base == 4) {
        out[0] = out[1] = out[2] = source[0];
    } else if (base == 8) {
        out[0] = out[1] = out[2] = source[1];
    } else if (base == 12) {
        out[0] = out[1] = out[2] = source[2];
    } else {
        out[0] = source[0];
        out[1] = source[1];
        out[2] = source[2];
    }
    if (invert) {
        for (i = 0; i < 3; i++) out[i] = 1.0 - out[i];
    }
}

static double cgfx_texenv_alpha_operand(const double source[4], int operand) {
    int invert = operand & 1;
    int base = operand & ~1;
    double value;
    if (base == 2) value = source[0];
    else if (base == 4) value = source[1];
    else if (base == 6) value = source[2];
    else value = source[3];
    return invert ? 1.0 - value : value;
}

static void cgfx_texenv_combine_rgb(int mode, const double a[3], const double b[3],
    const double c[3], double out[3]) {
    int i;
    for (i = 0; i < 3; i++) {
        switch (mode) {
            case 0: out[i] = a[i]; break;
            case 1: out[i] = a[i] * b[i]; break;
            case 2: out[i] = fmin(a[i] + b[i], 1.0); break;
            case 3: out[i] = clamp_unit(a[i] + b[i] - 0.5); break;
            case 4: out[i] = b[i] * (1.0 - c[i]) + a[i] * c[i]; break;
            case 5: out[i] = fmax(a[i] - b[i], 0.0); break;
            case 8: out[i] = fmin(a[i] * b[i] + c[i], 1.0); break;
            case 9: out[i] = fmin(a[i] + b[i], 1.0) * c[i]; break;
            default: out[i] = a[i]; break;
        }
    }
    if (mode == 6 || mode == 7) {
        double dot = fmin(a[0] * b[0] + a[1] * b[1] + a[2] * b[2], 1.0);
        out[0] = out[1] = out[2] = dot;
    }
}

static double cgfx_texenv_combine_alpha(int mode, double a, double b, double c) {
    switch (mode) {
        case 0: return a;
        case 1: return a * b;
        case 2: return fmin(a + b, 1.0);
        case 3: return clamp_unit(a + b - 0.5);
        case 4: return b * (1.0 - c) + a * c;
        case 5: return fmax(a - b, 0.0);
        case 6:
        case 7: return fmin(a * b * 3.0, 1.0);
        case 8: return fmin(a * b + c, 1.0);
        case 9: return fmin(a + b, 1.0) * c;
        default: return a;
    }
}

static double cgfx_texenv_scale_value(double value, int scale) {
    double multiplier = 1.0;
    if (scale == 1) multiplier = 2.0;
    else if (scale == 2) multiplier = 4.0;
    return clamp_unit(value * multiplier);
}

static void cgfx_material_runtime_constant(const CgfxMaterial *material, int selector,
    uint32_t body_color, uint32_t skin_color, const double fallback[4], double out[4]) {
    const double *selected = fallback;
    switch (selector) {
        case 0:
            /* UsesString_mtSkin writes the Mii skin material to Constant0 (+0xe8). */
            rgb_color_to_vec(skin_color, out);
            return;
        case 1:
            /* UsesString_mtOpa writes clothing/headwear color to Constant1 (+0xec). */
            rgb_color_to_vec(body_color, out);
            return;
        case 2:
        case 3:
        case 4:
        case 5:
            selected = material->constant_colors[selector];
            break;
        case 6:
            selected = material->emission;
            break;
        case 7:
            selected = material->ambient;
            break;
        case 8:
            selected = material->diffuse;
            break;
        case 9:
            selected = material->specular0;
            break;
        case 10:
            selected = material->specular1;
            break;
        default:
            selected = fallback;
            break;
    }
    out[0] = selected[0];
    out[1] = selected[1];
    out[2] = selected[2];
    out[3] = selected[3];
}

static int apply_cgfx_texenv_body_material(uint8_t pixel[4], const uint8_t mask[4],
    const uint8_t normal[4], const CgfxMaterial *material, uint32_t body_color, uint32_t skin_color) {
    double primary[4];
    double fragment_primary[4] = { 1.0, 1.0, 1.0, 1.0 };
    double fragment_secondary[4] = { 0.0, 0.0, 0.0, 1.0 };
    double texture0[4];
    double texture1[4];
    double texture2[4];
    double previous[4];
    double buffer[4];
    int i;

    if (!material || !material->has_texenv || pixel[3] == 0) return 0;

    memcpy(primary, material->diffuse, sizeof(primary));
    pixel_to_vec4(pixel, texture0);
    pixel_to_vec4(mask, texture1);
    pixel_to_vec4(normal, texture2);
    memcpy(previous, primary, sizeof(previous));
    memcpy(buffer, material->buffer_color, sizeof(buffer));

    for (i = 0; i < 6; i++) {
        const CgfxTexEnvStage *stage = &material->stages[i];
        double fallback_constant[4];
        double source_color[3][4];
        double source_alpha[3][4];
        double rgb_operand[3][3];
        double alpha_operand[3];
        double rgb[3];
        double alpha;
        int j;

        cgfx_material_runtime_constant(material, stage->constant_selector,
            body_color, skin_color, stage->constant, fallback_constant);

        for (j = 0; j < 3; j++) {
            cgfx_texenv_source_vec(stage->source_color[j], stage, primary,
                fragment_primary, fragment_secondary, texture0, texture1, texture2,
                previous, buffer, source_color[j]);
            cgfx_texenv_source_vec(stage->source_alpha[j], stage, primary,
                fragment_primary, fragment_secondary, texture0, texture1, texture2,
                previous, buffer, source_alpha[j]);
        }
        for (j = 0; j < 3; j++) {
            if (stage->source_color[j] == 14) memcpy(source_color[j], fallback_constant, sizeof(fallback_constant));
            if (stage->source_alpha[j] == 14) memcpy(source_alpha[j], fallback_constant, sizeof(fallback_constant));
            cgfx_texenv_color_operand(source_color[j], stage->operand_color[j], rgb_operand[j]);
            alpha_operand[j] = cgfx_texenv_alpha_operand(source_alpha[j], stage->operand_alpha[j]);
        }

        cgfx_texenv_combine_rgb(stage->combiner_color,
            rgb_operand[0], rgb_operand[1], rgb_operand[2], rgb);
        alpha = cgfx_texenv_combine_alpha(stage->combiner_alpha,
            alpha_operand[0], alpha_operand[1], alpha_operand[2]);

        previous[0] = cgfx_texenv_scale_value(rgb[0], stage->scale_color);
        previous[1] = cgfx_texenv_scale_value(rgb[1], stage->scale_color);
        previous[2] = cgfx_texenv_scale_value(rgb[2], stage->scale_color);
        previous[3] = cgfx_texenv_scale_value(alpha, stage->scale_alpha);

        if (stage->update_color_buffer) {
            buffer[0] = previous[0];
            buffer[1] = previous[1];
            buffer[2] = previous[2];
        }
        if (stage->update_alpha_buffer) buffer[3] = previous[3];
    }

    vec4_to_pixel(previous, pixel);
    return 1;
}

static void shader_shade_pixel(uint8_t pixel[4], Vec3 position, Vec3 normal, int material_type) {
    const ShaderMaterial *material;
    Vec3 norm;
    Vec3 eye;
    Vec3 incoming_light;
    Vec3 reflected;
    double f_dot;
    double specular_blinn;
    double reflection;
    double rim_width = 1.0;
    const double *rim_color = shader_rim_color;
    int i;

    if (pixel[3] == 0 || material_type < 0 || material_type >= SHADER_MAT_COUNT) return;
    material = &shader_materials[material_type];
    if (material_type == SHADER_MAT_BODY || material_type == SHADER_MAT_PANTS) {
        rim_color = shader_rim_color_body;
    }
    norm = vec3_normalize(normal);
    eye.x = -position.x;
    eye.y = -position.y;
    eye.z = -position.z;
    eye = vec3_normalize(eye);
    incoming_light.x = -shader_light_dir.x;
    incoming_light.y = -shader_light_dir.y;
    incoming_light.z = -shader_light_dir.z;
    reflected = vec3_reflect(incoming_light, norm);
    f_dot = fmax(vec3_dot(shader_light_dir, norm), 0.1);
    specular_blinn = pow(fmax(vec3_dot(reflected, eye), 0.0), material->specular_power);
    reflection = specular_blinn;

    for (i = 0; i < 3; i++) {
        double base = pixel[i] / 255.0;
        double ambient = shader_light_ambient[i] * material->ambient[i];
        double diffuse = shader_light_diffuse[i] * material->diffuse[i] * f_dot;
        double specular = shader_light_specular[i] * material->specular[i] * reflection;
        double rim = rim_color[i] * pow(rim_width * (1.0 - fabs(norm.z)), shader_rim_power);
        double shaded = (ambient + diffuse) * base + specular + rim;
        pixel[i] = (uint8_t)lrint(clamp_unit(shaded) * 255.0);
    }
}

static double edge_function(double ax, double ay, double bx, double by, double cx, double cy) {
    return (cx - ax) * (by - ay) - (cy - ay) * (bx - ax);
}

static void draw_mesh_triangle(MeshCanvas *canvas,
    Vec3 world0, Vec3 world1, Vec3 world2,
    Vec3 normal0, Vec3 normal1, Vec3 normal2,
    Vec2 uv0, Vec2 uv1, Vec2 uv2,
    uint32_t vertex_color0,
    uint32_t vertex_color1,
    uint32_t vertex_color2,
    int use_vertex_color,
    const Image *image_texture,
    const Image *mask_texture,
    const Image *normal_texture,
    const CgfxMaterial *cgfx_material,
    const CflTexture *cfl_texture,
    const OverlayOptions *texture_options,
    uint32_t color,
    uint32_t skin_color,
    int use_texture,
    int use_depth,
    int write_depth,
    int blend_mode,
    int cull_back,
    int image_mode,
    int material_type) {
    double x0;
    double y0;
    double z0 = world0.z;
    double reciprocal_w0;
    double x1;
    double y1;
    double z1 = world1.z;
    double reciprocal_w1;
    double x2;
    double y2;
    double z2 = world2.z;
    double reciprocal_w2;
    double area;
    int min_x, max_x, min_y, max_y;
    int x, y;

    if (!mesh_canvas_project(canvas, world0, &x0, &y0, &reciprocal_w0) ||
        !mesh_canvas_project(canvas, world1, &x1, &y1, &reciprocal_w1) ||
        !mesh_canvas_project(canvas, world2, &x2, &y2, &reciprocal_w2)) return;
    area = edge_function(x0, y0, x1, y1, x2, y2);
    if (fabs(area) < 0.0001) return;
    if (cull_back == 1 && area < 0.0) return;
    if (cull_back == 2 && area > 0.0) return;
    min_x = clamp_int((int)floor(fmin(x0, fmin(x1, x2))), 0, canvas->image->width - 1);
    max_x = clamp_int((int)ceil(fmax(x0, fmax(x1, x2))), 0, canvas->image->width - 1);
    min_y = clamp_int((int)floor(fmin(y0, fmin(y1, y2))), 0, canvas->image->height - 1);
    max_y = clamp_int((int)ceil(fmax(y0, fmax(y1, y2))), 0, canvas->image->height - 1);

    for (y = min_y; y <= max_y; y++) {
        for (x = min_x; x <= max_x; x++) {
            double px = x + 0.5;
            double py = y + 0.5;
            double w0 = edge_function(x1, y1, x2, y2, px, py) / area;
            double w1 = edge_function(x2, y2, x0, y0, px, py) / area;
            double w2 = edge_function(x0, y0, x1, y1, px, py) / area;
            double z;
            size_t dst;
            uint8_t pixel[4];

            if (w0 < -0.0001 || w1 < -0.0001 || w2 < -0.0001) continue;
            if (!mesh_canvas_correct_barycentrics(canvas,
                    reciprocal_w0, reciprocal_w1, reciprocal_w2,
                    &w0, &w1, &w2)) continue;
            z = z0 * w0 + z1 * w1 + z2 * w2;
            dst = ((size_t)y * (size_t)canvas->image->width + (size_t)x);
            if (use_depth && canvas->depth && z < canvas->depth[dst]) continue;

            if (use_texture && image_texture) {
                double u = uv0.x * w0 + uv1.x * w1 + uv2.x * w2;
                double v = uv0.y * w0 + uv1.y * w1 + uv2.y * w2;
                double tex_u = u;
                double tex_v = v;
                uint8_t sampled_alpha;
                if (image_mode == 0) v = 1.0 - v;
                if (image_mode == CGFX_IMAGE_DIRECT_MODULATE && cgfx_material) {
                    cgfx_material_texcoord(cgfx_material, 0, u, v, &tex_u, &tex_v);
                } else {
                    tex_u = u;
                    tex_v = v;
                }
                sample_image_uv(image_texture, tex_u, tex_v, image_mode == 0, pixel);
                sampled_alpha = pixel[3];
                if (image_mode == CGFX_IMAGE_ALPHA_MASK) {
                    uint8_t alpha = pixel[3];
                    if (alpha < 64) {
                        pixel[3] = 0;
                    } else {
                        color_to_pixel(color, pixel);
                        pixel[3] = 255;
                    }
                } else if (image_mode == CGFX_IMAGE_RED_OPAQUE) {
                    uint8_t base[4];
                    uint32_t texture_red = pixel[0];
                    color_to_pixel(color, base);
                    pixel[0] = (uint8_t)((base[0] * texture_red) / 255u);
                    pixel[1] = (uint8_t)((base[1] * texture_red) / 255u);
                    pixel[2] = (uint8_t)((base[2] * texture_red) / 255u);
                    pixel[3] = 255;
                } else if (image_mode == CGFX_IMAGE_DIRECT_MODULATE) {
                    if (mask_texture || (material_type == SHADER_MAT_CAP && cgfx_material)) {
                        uint8_t mask[4] = { 255, 255, 255, 255 };
                        uint8_t normal_sample[4] = { 128, 128, 255, 255 };
                        double mask_u = u;
                        double mask_v = v;
                        double normal_u = u;
                        double normal_v = v;
                        cgfx_material_texcoord(cgfx_material, 1, u, v, &mask_u, &mask_v);
                        cgfx_material_texcoord(cgfx_material, 2, u, v, &normal_u, &normal_v);
                        if (mask_texture) sample_image_uv(mask_texture, mask_u, mask_v, 1, mask);
                        if (normal_texture) sample_image_uv(normal_texture, normal_u, normal_v, 1, normal_sample);
                        if (material_type == SHADER_MAT_CAP && mask_texture) {
                            apply_headwear_material_mask(pixel, mask, color);
                        } else if (material_type == SHADER_MAT_CAP && cgfx_material) {
                            if (!apply_cgfx_texenv_body_material(pixel, mask, normal_sample, cgfx_material,
                                    color, skin_color)) {
                                apply_headwear_material_mask(pixel, mask, color);
                            }
                        } else if (material_type == SHADER_MAT_CAP) {
                            apply_headwear_material_mask(pixel, mask, color);
                        } else if (material_type == SHADER_MAT_BODY) {
                            apply_body_material_mask(pixel, mask, color, skin_color);
                        } else if (!apply_cgfx_texenv_body_material(pixel, mask, normal_sample, cgfx_material,
                                color, skin_color)) {
                            apply_body_material_mask(pixel, mask, color, skin_color);
                        }
                    } else {
                        uint8_t base[4];
                        color_to_pixel(color, base);
                        pixel[0] = (uint8_t)((pixel[0] * base[0]) / 255u);
                        pixel[1] = (uint8_t)((pixel[1] * base[1]) / 255u);
                        pixel[2] = (uint8_t)((pixel[2] * base[2]) / 255u);
                    }
                }
                if (material_type == SHADER_MAT_CAP && image_mode == CGFX_IMAGE_DIRECT_MODULATE && !cgfx_material) {
                    pixel[3] = sampled_alpha < 16 ? 0 : 255;
                }
            } else if (use_texture && cfl_texture) {
                double u = uv0.x * w0 + uv1.x * w1 + uv2.x * w2;
                double v = uv0.y * w0 + uv1.y * w1 + uv2.y * w2;
                v = 1.0 - v;
                u = wrap_texture_coord(u, texture_options && texture_options->mirror_repeat_x);
                v = wrap_texture_coord(v, 0);
                int tx = clamp_int((int)floor(u * (cfl_texture->width - 1) + 0.5), 0, cfl_texture->width - 1);
                int ty = clamp_int((int)floor(v * (cfl_texture->height - 1) + 0.5), 0, cfl_texture->height - 1);
                size_t src = ((size_t)ty * (size_t)cfl_texture->width + (size_t)tx) * 4u;
                sample_modulated_pixel(cfl_texture, src, color, texture_options, pixel);
            } else {
                color_to_pixel(color, pixel);
            }

            if (pixel[3] > 0 && use_vertex_color) {
                double cr = (((vertex_color0 >> 24) & 0xffu) * w0 +
                    ((vertex_color1 >> 24) & 0xffu) * w1 +
                    ((vertex_color2 >> 24) & 0xffu) * w2) / 255.0;
                double cg = (((vertex_color0 >> 16) & 0xffu) * w0 +
                    ((vertex_color1 >> 16) & 0xffu) * w1 +
                    ((vertex_color2 >> 16) & 0xffu) * w2) / 255.0;
                double cb = (((vertex_color0 >> 8) & 0xffu) * w0 +
                    ((vertex_color1 >> 8) & 0xffu) * w1 +
                    ((vertex_color2 >> 8) & 0xffu) * w2) / 255.0;
                double ca = ((vertex_color0 & 0xffu) * w0 +
                    (vertex_color1 & 0xffu) * w1 +
                    (vertex_color2 & 0xffu) * w2) / 255.0;
                pixel[0] = (uint8_t)lrint(pixel[0] * clamp_unit(cr));
                pixel[1] = (uint8_t)lrint(pixel[1] * clamp_unit(cg));
                pixel[2] = (uint8_t)lrint(pixel[2] * clamp_unit(cb));
                pixel[3] = (uint8_t)lrint(pixel[3] * clamp_unit(ca));
            }

            if (pixel[3] > 0 && material_type != SHADER_MAT_NONE) {
                Vec3 normal;
                Vec3 position;
                normal.x = normal0.x * w0 + normal1.x * w1 + normal2.x * w2;
                normal.y = normal0.y * w0 + normal1.y * w1 + normal2.y * w2;
                normal.z = normal0.z * w0 + normal1.z * w1 + normal2.z * w2;
                position.x = world0.x * w0 + world1.x * w1 + world2.x * w2;
                position.y = world0.y * w0 + world1.y * w1 + world2.y * w2;
                position.z = world0.z * w0 + world1.z * w1 + world2.z * w2;
                shader_shade_pixel(pixel, position, normal, material_type);
            }

            blend_pixel(canvas->image->rgba + dst * 4u, pixel, blend_mode);
            if (write_depth && canvas->depth && pixel[3] > 16) canvas->depth[dst] = z;
        }
    }
}

static void draw_shape_mesh(MeshCanvas *canvas, const CflShape *shape,
    const ShapeTransform *transform,
    const Image *image_texture,
    const CflTexture *cfl_texture,
    const OverlayOptions *texture_options,
    uint32_t color,
    int use_depth,
    int write_depth,
    int blend_mode,
    int material_type) {
    int i;
    int use_texture = (image_texture || cfl_texture) && shape->texcoord_count != 0;
    if (!shape || !shape->vertices || !shape->indices || shape->index_count < 3) return;

    for (i = 0; i + 2 < shape->index_count; i += 3) {
        int i0 = shape->indices[i + 0];
        int i1 = shape->indices[i + 1];
        int i2 = shape->indices[i + 2];
        if (i0 < 0 || i0 >= shape->vertex_count ||
            i1 < 0 || i1 >= shape->vertex_count ||
            i2 < 0 || i2 >= shape->vertex_count) {
            continue;
        }
        draw_mesh_triangle(canvas,
            transform_point(shape->vertices[i0], transform),
            transform_point(shape->vertices[i1], transform),
            transform_point(shape->vertices[i2], transform),
            transform_normal(shape_normal_at(shape, i0), transform),
            transform_normal(shape_normal_at(shape, i1), transform),
            transform_normal(shape_normal_at(shape, i2), transform),
            shape_uv_at(shape, i0),
            shape_uv_at(shape, i1),
            shape_uv_at(shape, i2),
            0xffffffffu,
            0xffffffffu,
            0xffffffffu,
            0,
            image_texture,
            NULL,
            NULL,
            NULL,
            cfl_texture,
            texture_options,
            color,
            0,
            use_texture,
            use_depth,
            write_depth,
            blend_mode,
            0,
            0,
            material_type);
    }
}

static Vec3 cgfx_normal_at(const CgfxMesh *mesh, int index) {
    Vec3 normal = { 0.0, 0.0, 1.0 };
    if (!mesh->normals || !mesh->has_normals) return normal;
    if (index >= 0 && index < mesh->vertex_count) return mesh->normals[index];
    return normal;
}

static Vec3 cgfx_tangent_at(const CgfxMesh *mesh, int index) {
    Vec3 tangent = { 1.0, 0.0, 0.0 };
    if (!mesh->tangents || !mesh->has_tangents) return tangent;
    if (index >= 0 && index < mesh->vertex_count) return mesh->tangents[index];
    return tangent;
}

static Vec2 cgfx_uv_at(const CgfxMesh *mesh, int index) {
    Vec2 uv = { 0.5, 0.5 };
    if (!mesh->uvs || !mesh->has_uvs) return uv;
    if (index >= 0 && index < mesh->vertex_count) return mesh->uvs[index];
    return uv;
}

static Vec2 cgfx_uv_at_set(const CgfxMesh *mesh, int index, int set) {
    Vec2 uv = { 0.5, 0.5 };
    const Vec2 *values = NULL;
    int available = 0;
    if (!mesh) return uv;
    if (set == 1) {
        values = mesh->uv1s;
        available = mesh->has_uv1s;
    } else if (set == 2) {
        values = mesh->uv2s;
        available = mesh->has_uv2s;
    } else {
        values = mesh->uvs;
        available = mesh->has_uvs;
    }
    if (!values || !available) return uv;
    if (index >= 0 && index < mesh->vertex_count) return values[index];
    return uv;
}

static uint32_t cgfx_color_at(const CgfxMesh *mesh, int index) {
    if (!mesh->colors || !mesh->has_colors) return 0xffffffffu;
    if (index >= 0 && index < mesh->vertex_count) return mesh->colors[index];
    return 0xffffffffu;
}

static void draw_cgfx_model(MeshCanvas *canvas, const CgfxModel *model,
    const ShapeTransform *transform, uint32_t fallback_color,
    int use_depth, int write_depth, int blend_mode, int image_mode, int cull_back,
    int material_type, uint32_t skin_color) {
    int mesh_index;
    if (!model || !model->meshes || model->mesh_count <= 0) return;
    for (mesh_index = 0; mesh_index < model->mesh_count; mesh_index++) {
        const CgfxMesh *mesh = &model->meshes[mesh_index];
        const CgfxMaterial *material = NULL;
        const CgfxMaterial *draw_material = NULL;
        int i;
        int use_texture = image_mode != CGFX_IMAGE_SOLID && model->has_texture && mesh->has_uvs;
        uint32_t color = (image_mode == CGFX_IMAGE_DIRECT && model->has_texture) ?
            model->average_color : fallback_color;
        if (!mesh->vertices || !mesh->indices) continue;
        if (mesh->material_index >= 0 && mesh->material_index < model->material_count) {
            material = &model->materials[mesh->material_index];
        } else if (model->material.has_texenv) {
            material = &model->material;
        }
        draw_material = material;
        for (i = 0; i + 2 < mesh->index_count; i += 3) {
            uint32_t i0 = mesh->indices[i + 0];
            uint32_t i1 = mesh->indices[i + 1];
            uint32_t i2 = mesh->indices[i + 2];
            if (i0 >= (uint32_t)mesh->vertex_count ||
                i1 >= (uint32_t)mesh->vertex_count ||
                i2 >= (uint32_t)mesh->vertex_count) {
                continue;
            }
            draw_mesh_triangle(canvas,
                transform_point(mesh->vertices[i0], transform),
                transform_point(mesh->vertices[i1], transform),
                transform_point(mesh->vertices[i2], transform),
                transform_normal(cgfx_normal_at(mesh, (int)i0), transform),
                transform_normal(cgfx_normal_at(mesh, (int)i1), transform),
                transform_normal(cgfx_normal_at(mesh, (int)i2), transform),
                cgfx_uv_at(mesh, (int)i0),
                cgfx_uv_at(mesh, (int)i1),
                cgfx_uv_at(mesh, (int)i2),
                cgfx_color_at(mesh, (int)i0),
                cgfx_color_at(mesh, (int)i1),
                cgfx_color_at(mesh, (int)i2),
                mesh->has_colors,
                use_texture ? &model->texture : NULL,
                (use_texture && model->has_mask_texture) ? &model->mask_texture : NULL,
                (use_texture && model->has_normal_texture) ? &model->normal_texture : NULL,
                (use_texture && draw_material && draw_material->has_texenv) ? draw_material : NULL,
                NULL,
                NULL,
                color,
                skin_color,
                use_texture,
                use_depth,
                write_depth,
                blend_mode,
                cull_back,
                image_mode,
                material_type);
        }
    }
}

static int cfl_shape_bounds(const CflShape *shape, const ShapeTransform *transform,
    Vec3 *min, Vec3 *max) {
    int i;
    if (!shape || !shape->vertices || shape->vertex_count <= 0) return 0;
    bounds_reset(min, max);
    for (i = 0; i < shape->vertex_count; i++) {
        bounds_include(min, max, transform_point(shape->vertices[i], transform));
    }
    return bounds_are_valid(*min, *max);
}

static void body_scales(const MiiFaceParams *params, double *scale_x, double *scale_y) {
    double height = clamp_int(params->height, 0, 127);
    double build = clamp_int(params->weight, 0, 127);
    /* source/src/render/render_resource_layout_pipeline.c FUN_007327f0 */
    *scale_y = (height * 0.006015625 + 0.5) * 0.75;
    *scale_x = ((build * (height * 0.003671875 + 0.4)) / 128.0
        + height * 0.001796875 + 0.4) * 0.75;
}

static double body_default_scale_y(void) {
    return (64.0 * 0.006015625 + 0.5) * 0.75;
}

static double tomodachi_cgfx_head_min_y(void) {
    /* obj_mHead.bin.dat visible-head bounds, used as the unit bridge. */
    return 0.002305;
}

static double tomodachi_cgfx_head_max_y(void) {
    return 0.679150;
}

static double tomodachi_cgfx_head_height(void) {
    return tomodachi_cgfx_head_max_y() - tomodachi_cgfx_head_min_y();
}

static size_t align16_size(size_t value) {
    return (value + 15u) & ~(size_t)15u;
}

static int build_clothes_message_path(char *out, size_t out_size, const char *body_dir) {
    if (!out || out_size == 0 || !body_dir || !body_dir[0]) return 0;
    snprintf(out, out_size, "%s/../../message/Clothes/Clothes_US_English.bin.dat", body_dir);
    return file_exists(out);
}

typedef struct {
    int item_id;
    int model_id;
    uint8_t color_ids[16];
    int color_count;
    int color_index;
    uint32_t primary_color;
    int has_primary_color;
} TomodachiBodyItemInfo;

typedef struct {
    int item_id;
    int model_id;
    int body_type;
    int headwear_type;
    uint8_t color_ids[16];
    int color_count;
    int color_index;
    uint32_t primary_color;
    int has_primary_color;
} TomodachiHeadwearItemInfo;

static void tomodachi_body_item_info_init(TomodachiBodyItemInfo *info, int body_index) {
    if (!info) return;
    memset(info, 0, sizeof(*info));
    info->item_id = body_index < 0 ? 0 : body_index;
    info->model_id = info->item_id;
    info->color_index = 0;
}

static void tomodachi_headwear_item_info_init(TomodachiHeadwearItemInfo *info, int headwear_index) {
    if (!info) return;
    memset(info, 0, sizeof(*info));
    info->item_id = headwear_index < 0 ? 0 : headwear_index;
    info->model_id = info->item_id;
    info->body_type = 2;
    info->headwear_type = 0;
    info->color_index = 0;
}

static int msbt_atr1_records_from_offset(const uint8_t *bytes, size_t size, size_t msbt_offset,
    uint32_t expected_count, uint32_t expected_attr_size, const uint8_t **records) {
    size_t cursor;
    int section_guard = 0;
    if (!checked_range(size, msbt_offset, 0x20u) ||
        memcmp(bytes + msbt_offset, "MsgStdBn", 8) != 0 ||
        !records) {
        return 0;
    }

    cursor = msbt_offset + 0x20u;
    while (checked_range(size, cursor, 0x10u) && section_guard++ < 32) {
        uint32_t section_size = rd_u32(bytes + cursor + 4u);
        size_t body = cursor + 0x10u;
        size_t next;
        if (!checked_range(size, body, section_size)) return 0;
        if (memcmp(bytes + cursor, "ATR1", 4) == 0 && section_size >= 8u) {
            uint32_t count = rd_u32(bytes + body);
            uint32_t attr_size = rd_u32(bytes + body + 4u);
            size_t record_bytes = (size_t)section_size - 8u;
            if (count == expected_count && attr_size == expected_attr_size &&
                record_bytes >= (size_t)count * attr_size) {
                *records = bytes + body + 8u;
                return 1;
            }
        }
        next = align16_size(body + (size_t)section_size);
        if (next <= cursor || next > size) return 0;
        cursor = next;
    }
    return 0;
}

static int msbt_body_item_info_from_offset(const uint8_t *bytes, size_t size, size_t msbt_offset,
    int body_index, TomodachiBodyItemInfo *info) {
    const uint8_t *records;
    const uint8_t *record;
    int i;
    int candidate;
    if (!info || body_index < 0 ||
        !msbt_atr1_records_from_offset(bytes, size, msbt_offset, 492u, 71u, &records) ||
        body_index >= 492) {
        return 0;
    }

    record = records + (size_t)body_index * 71u;
    /*
     * Body_Name.msbt, ATR1 FileID column. This is the same table reached by
     * INT_0h_00acb5b4 + 4 during global body item init.
     */
    candidate = (int)rd_u16(record);
    if (candidate < 0 || candidate > 999) return 0;
    info->item_id = body_index;
    info->model_id = candidate;
    info->color_count = 0;
    for (i = 0; i < 16; i++) {
        uint8_t color_id = record[44 + i];
        info->color_ids[i] = color_id;
        if (color_id != 0) info->color_count = i + 1;
    }
    return 1;
}

static int msbt_headwear_item_info_from_offset(const uint8_t *bytes, size_t size, size_t msbt_offset,
    int headwear_index, TomodachiHeadwearItemInfo *info) {
    const uint8_t *records;
    const uint8_t *record;
    int i;
    int candidate;
    if (!info || headwear_index < 0 ||
        !msbt_atr1_records_from_offset(bytes, size, msbt_offset, 267u, 71u, &records) ||
        headwear_index >= 267) {
        return 0;
    }

    record = records + (size_t)headwear_index * 71u;
    candidate = (int)rd_u16(record);
    if (candidate < 0 || candidate > 999) return 0;
    info->item_id = headwear_index;
    info->model_id = candidate;
    info->body_type = record[10];
    info->headwear_type = record[11];
    info->color_count = 0;
    for (i = 0; i < 16; i++) {
        uint8_t color_id = record[44 + i];
        info->color_ids[i] = color_id;
        if (color_id != 0) info->color_count = i + 1;
    }
    return 1;
}

static int msbt_clothes_color_from_offset(const uint8_t *bytes, size_t size, size_t msbt_offset,
    uint8_t color_id, uint32_t *rgb) {
    const uint8_t *records;
    const uint8_t *record;
    if (!rgb ||
        !msbt_atr1_records_from_offset(bytes, size, msbt_offset, 98u, 71u, &records) ||
        color_id >= 98) {
        return 0;
    }
    record = records + (size_t)color_id * 71u;
    *rgb = ((uint32_t)record[59] << 16) | ((uint32_t)record[58] << 8) | (uint32_t)record[57];
    return 1;
}

static int tomodachi_body_item_info_from_item(const char *body_dir, int body_index, int body_color,
    TomodachiBodyItemInfo *info) {
    char clothes_path[1024];
    Buffer buffer;
    size_t offset;
    int found_body = 0;

    if (!info) return 0;
    tomodachi_body_item_info_init(info, body_index);
    if (!build_clothes_message_path(clothes_path, sizeof(clothes_path), body_dir)) return 0;
    memset(&buffer, 0, sizeof(buffer));
    if (!read_file(clothes_path, &buffer)) return 0;

    for (offset = 0; offset + 8u <= buffer.size; offset++) {
        if (memcmp(buffer.data + offset, "MsgStdBn", 8) != 0) continue;
        if (!found_body &&
            msbt_body_item_info_from_offset(buffer.data, buffer.size, offset, info->item_id, info)) {
            found_body = 1;
            continue;
        }
        if (found_body && info->color_count > 0) {
            int selected = body_color;
            if (selected < 0 || selected >= info->color_count || info->color_ids[selected] == 0) selected = 0;
            uint8_t color_id = info->color_ids[selected];
            uint32_t rgb;
            if (msbt_clothes_color_from_offset(buffer.data, buffer.size, offset, color_id, &rgb)) {
                info->color_index = selected;
                info->primary_color = rgb;
                info->has_primary_color = 1;
                free(buffer.data);
                return 1;
            }
        }
    }

    free(buffer.data);
    return found_body;
}

static int tomodachi_headwear_item_info_from_item(const char *headwear_dir, int headwear_index,
    int headwear_color, TomodachiHeadwearItemInfo *info) {
    char clothes_path[1024];
    Buffer buffer;
    size_t offset;
    int found_headwear = 0;

    if (!info) return 0;
    tomodachi_headwear_item_info_init(info, headwear_index);
    if (!headwear_dir || !headwear_dir[0]) return 0;
    snprintf(clothes_path, sizeof(clothes_path), "%s/../../message/Clothes/Clothes_US_English.bin.dat",
        headwear_dir);
    if (!file_exists(clothes_path)) return 0;
    memset(&buffer, 0, sizeof(buffer));
    if (!read_file(clothes_path, &buffer)) return 0;

    for (offset = 0; offset + 8u <= buffer.size; offset++) {
        if (memcmp(buffer.data + offset, "MsgStdBn", 8) != 0) continue;
        if (!found_headwear &&
            msbt_headwear_item_info_from_offset(buffer.data, buffer.size, offset, info->item_id, info)) {
            found_headwear = 1;
            continue;
        }
        if (found_headwear && info->color_count > 0) {
            int selected = headwear_color;
            uint8_t color_id;
            uint32_t rgb;
            if (selected < 0 || selected >= info->color_count || info->color_ids[selected] == 0) selected = 0;
            color_id = info->color_ids[selected];
            if (msbt_clothes_color_from_offset(buffer.data, buffer.size, offset, color_id, &rgb)) {
                info->color_index = selected;
                info->primary_color = rgb;
                info->has_primary_color = 1;
                free(buffer.data);
                return 1;
            }
        }
    }

    free(buffer.data);
    return found_headwear;
}

static int resolve_body_path_for_model(char *out, size_t out_size, const char *body_dir,
    int model_id, int gender) {
    const char *suffix = gender == 1 ? "F" : "";
    int id = model_id < 0 ? 0 : model_id;
    if (!body_dir || !body_dir[0]) return 0;
    if (id == 999) id = 0;
    if (suffix[0]) {
        snprintf(out, out_size, "%s/body_body%03d%s.bin.dat", body_dir, id, suffix);
        if (file_exists(out)) return 1;
    }
    snprintf(out, out_size, "%s/body_body%03d.bin.dat", body_dir, id);
    return file_exists(out);
}

static int resolve_body_path(char *out, size_t out_size, const char *body_dir,
    int body_index, int body_color, int gender, TomodachiBodyItemInfo *info) {
    int raw_id = body_index < 0 ? 0 : body_index;
    int model_id = raw_id;
    TomodachiBodyItemInfo local_info;
    if (!body_dir || !body_dir[0]) return 0;
    tomodachi_body_item_info_init(&local_info, raw_id);
    if (tomodachi_body_item_info_from_item(body_dir, raw_id, body_color, &local_info)) {
        model_id = local_info.model_id;
    }
    if (info) *info = local_info;
    if (model_id != raw_id &&
        resolve_body_path_for_model(out, out_size, body_dir, model_id, gender)) {
        return 1;
    }
    if (resolve_body_path_for_model(out, out_size, body_dir, raw_id, gender)) return 1;
    return resolve_body_path_for_model(out, out_size, body_dir, 0, gender);
}

static int resolve_headwear_path_for_model(char *out, size_t out_size, const char *headwear_dir,
    int model_id) {
    int id = model_id < 0 ? 0 : model_id;
    if (!headwear_dir || !headwear_dir[0] || id <= 0 || id == 999) return 0;
    snprintf(out, out_size, "%s/headwear_headwear%03d.bin.dat", headwear_dir, id);
    return file_exists(out);
}

static int resolve_headwear_path(char *out, size_t out_size, const char *headwear_dir,
    int headwear_index, int headwear_color, TomodachiHeadwearItemInfo *info) {
    int raw_id = headwear_index;
    int model_id = raw_id;
    TomodachiHeadwearItemInfo local_info;
    if (!headwear_dir || !headwear_dir[0] || headwear_index <= 0 || headwear_index == 0xffff) return 0;
    tomodachi_headwear_item_info_init(&local_info, raw_id);
    if (tomodachi_headwear_item_info_from_item(headwear_dir, raw_id, headwear_color, &local_info)) {
        model_id = local_info.model_id;
    }
    if (info) *info = local_info;
    if (model_id != raw_id && resolve_headwear_path_for_model(out, out_size, headwear_dir, model_id)) return 1;
    return resolve_headwear_path_for_model(out, out_size, headwear_dir, raw_id);
}

static int headwear_model_replaces_hair(const char *headwear_path, const char *head_model_path) {
    CgfxModel headwear;
    CgfxModel head;
    double head_width;
    double head_height;
    double head_depth;
    double wear_width;
    double wear_height;
    double wear_depth;
    int replaces;

    memset(&headwear, 0, sizeof(headwear));
    memset(&head, 0, sizeof(head));
    if (!headwear_path || !head_model_path) return 0;
    if (!cgfx_load_model_file(headwear_path, 0xffffff, &headwear)) return 0;
    if (!cgfx_load_model_file(head_model_path, 0xffffff, &head)) {
        cgfx_model_free(&headwear);
        return 0;
    }

    head_width = head.max.x - head.min.x;
    head_height = head.max.y - head.min.y;
    head_depth = head.max.z - head.min.z;
    wear_width = headwear.max.x - headwear.min.x;
    wear_height = headwear.max.y - headwear.min.y;
    wear_depth = headwear.max.z - headwear.min.z;
    replaces = headwear.min.y < head.min.y - head_height * 0.05 &&
        wear_width > head_width * 0.8 &&
        wear_height > head_height * 0.8 &&
        wear_depth > head_depth * 0.8;

    cgfx_model_free(&head);
    cgfx_model_free(&headwear);
    return replaces;
}

static int vec3_has_value(Vec3 value) {
    return fabs(value.x) > 0.000001 || fabs(value.y) > 0.000001 || fabs(value.z) > 0.000001;
}

static int draw_tomodachi_body_model(MeshCanvas *canvas, const MiiFaceParams *params,
    const char *body_dir, const CflShape *faceline_shape) {
    char path[1024];
    CgfxModel model;
    ShapeTransform transform;
    Vec3 head_min;
    Vec3 head_max;
    Vec3 attach;
    Vec3 target;
    double scale_x;
    double scale_y;
    double model_width;
    double model_height;
    double model_depth;
    double base_model_height;
    double draw_scale_y;
    int has_head_bounds;
    TomodachiBodyItemInfo body_info;
    uint32_t fallback = palette_color(mii_favorite_colors, 12, params->favorite_color, 6);
    uint32_t skin = mii_skin_color(params->face_color);

    memset(&model, 0, sizeof(model));
    tomodachi_body_item_info_init(&body_info, params->body_index);
    if (!resolve_body_path(path, sizeof(path), body_dir,
            params->body_index, params->body_color, params->gender, &body_info)) {
        return 0;
    }
    if (body_info.has_primary_color) fallback = body_info.primary_color;
    if (!cgfx_load_model_file(path, fallback, &model)) return 0;
    apply_tomodachi_body_wait_pose(&model, body_dir);
    has_head_bounds = cfl_shape_bounds(faceline_shape, NULL, &head_min, &head_max);

    model_width = model.max.x - model.min.x;
    model_height = model.max.y - model.min.y;
    model_depth = model.max.z - model.min.z;
    if (model_width <= 0.000001 || model_height <= 0.000001 || model_depth <= 0.000001) {
        cgfx_model_free(&model);
        return 0;
    }

    body_scales(params, &scale_x, &scale_y);
    cgfx_apply_body_skinning(&model);
    model_width = model.max.x - model.min.x;
    model_height = model.max.y - model.min.y;
    model_depth = model.max.z - model.min.z;
    if (model_width <= 0.000001 || model_height <= 0.000001 || model_depth <= 0.000001) {
        cgfx_model_free(&model);
        return 0;
    }
    base_model_height = model_height;
    if (has_head_bounds && head_max.y > head_min.y) {
        const double default_scale_y = body_default_scale_y();
        const double head_height = head_max.y - head_min.y;
        draw_scale_y = (head_height / tomodachi_cgfx_head_height()) / default_scale_y;
    } else {
        draw_scale_y = (250.0 / canvas->scale) /
            (base_model_height * body_default_scale_y());
    }

    transform = shape_transform_identity();
    transform.scale_x = draw_scale_y * scale_x;
    transform.scale_y = draw_scale_y * scale_y;
    transform.scale_z = transform.scale_x;

    if (!cgfx_bone_world_translation(&model, "neck", &attach) &&
        !cgfx_bone_world_translation(&model, "head", &attach)) {
        attach.x = (model.min.x + model.max.x) * 0.5;
        attach.y = model.max.y;
        attach.z = (model.min.z + model.max.z) * 0.5;
    }

    if (has_head_bounds) {
        target.x = (head_min.x + head_max.x) * 0.5;
        target.y = head_min.y + (head_max.y - head_min.y) * 0.02;
        target.z = (head_min.z + head_max.z) * 0.5;
        transform.translate_x = target.x - attach.x * transform.scale_x;
        transform.translate_y = target.y - attach.y * transform.scale_y;
        transform.translate_z = target.z - attach.z * transform.scale_z;
    } else {
        transform.translate_x = -((model.min.x + model.max.x) * 0.5) * transform.scale_x;
        transform.translate_y = -7.0 - model.max.y * transform.scale_y;
        transform.translate_z = -64.0 - ((model.min.z + model.max.z) * 0.5) * transform.scale_z;
    }

    draw_cgfx_model(canvas, &model, &transform, fallback, 1, 1, BLEND_SOURCE_OVER, CGFX_IMAGE_DIRECT_MODULATE, 1,
        SHADER_MAT_BODY, skin);
    cgfx_model_free(&model);
    return 1;
}

#if 0
/* Superseded bounds-fitting implementation retained only as provenance for
   why the exact authored-origin path below was introduced. */
static int draw_tomodachi_headwear_model_bounds_fit(MeshCanvas *canvas, const MiiFaceParams *params,
    const char *headwear_dir, const char *head_model_path, const CflShape *faceline_shape,
    const CflPartsTransform *parts, const HeadwearMetadata *metadata, int metadata_variant,
    const TomodachiHeadwearItemInfo *headwear_info) {
    char path[1024];
    CgfxModel model;
    CgfxModel head_model;
    ShapeTransform transform;
    Vec3 head_min;
    Vec3 head_max;
    double head_center_x;
    double head_center_z;
    double head_height;
    double cgfx_head_height;
    double cgfx_head_min_y;
    double cgfx_reference_height;
    double cgfx_head_center_x;
    double cgfx_head_center_z;
    double model_center_x;
    double model_center_z;
    double scale;
    Vec3 rotation = { 0.0, 0.0, 0.0 };
    Vec3 anchor = { 0.0, 0.0, 0.0 };
    Vec3 pivot = { 0.0, 0.0, 0.0 };
    Vec3 variant_translation = { 0.0, 0.0, 0.0 };
    int animation_index;
    int anchor_index = 0;
    int has_anchor = 0;
    int use_face_attachment = metadata && metadata->head_type == 1;
    int use_front_origin_attachment = metadata &&
        (metadata->head_type == 2 || metadata->head_type == 10);
    int use_head_space_alignment = metadata &&
        (metadata->head_type == 6 || metadata->head_type == 7 ||
         metadata->head_type == 8 || metadata->head_type == 9);
    uint32_t fallback = palette_color(mii_favorite_colors, 12,
        params->headwear_color >= 0 ? params->headwear_color : params->favorite_color, 6);
    const double *variant_offset = NULL;

    memset(&model, 0, sizeof(model));
    memset(&head_model, 0, sizeof(head_model));
    if (!resolve_headwear_path(path, sizeof(path), headwear_dir,
            params->headwear_index, params->headwear_color, NULL)) return 0;
    if (!cfl_shape_bounds(faceline_shape, NULL, &head_min, &head_max)) return 0;
    if (headwear_info && headwear_info->has_primary_color) fallback = headwear_info->primary_color;
    if (!cgfx_load_model_file(path, fallback, &model)) return 0;
    cgfx_apply_body_skinning(&model);
    if (!head_model_path || !cgfx_load_model_file(head_model_path, 0xf0c0a0, &head_model)) {
        cgfx_model_free(&model);
        return 0;
    }

    head_center_x = (head_min.x + head_max.x) * 0.5;
    head_center_z = (head_min.z + head_max.z) * 0.5;
    head_height = head_max.y - head_min.y;
    cgfx_head_min_y = tomodachi_cgfx_head_min_y();
    cgfx_head_height = tomodachi_cgfx_head_height();
    cgfx_reference_height = cgfx_head_height;
    cgfx_head_center_x = (head_model.min.x + head_model.max.x) * 0.5;
    cgfx_head_center_z = (head_model.min.z + head_model.max.z) * 0.5;
    model_center_x = (model.min.x + model.max.x) * 0.5;
    model_center_z = (model.min.z + model.max.z) * 0.5;
    if (head_height <= 0.000001 || cgfx_head_height <= 0.000001 ||
        cgfx_reference_height <= 0.000001 || !bounds_are_valid(head_model.min, head_model.max)) {
        cgfx_model_free(&head_model);
        cgfx_model_free(&model);
        return 0;
    }

    scale = head_height / cgfx_reference_height;
    if (metadata && metadata_variant >= 0 && metadata_variant < 16 &&
        metadata->variant_has_offset[metadata_variant]) {
        variant_offset = metadata->variant_offset[metadata_variant];
    }

    animation_index = tomodachi_headwear_visibility_animation_index(metadata ? metadata->head_type : -1);
    if (animation_index < 0 || animation_index > 2) animation_index = 0;
    if (headwear_info) {
        anchor_index = tomodachi_headwear_anchor_index_from_metadata(metadata, headwear_info->headwear_type);
    }
    if (!use_head_space_alignment && !use_front_origin_attachment &&
        anchor_index >= 0 && parts &&
        vec3_has_value(parts->hat_position[anchor_index])) {
        Vec3 anchor_rotation;
        anchor = parts->hat_position[anchor_index];
        if (params->hair_flipped) anchor.x = -anchor.x;
        anchor_rotation = tomodachi_cfl_headwear_rotation_to_render(parts->hat_angle[anchor_index]);
        if (params->hair_flipped) anchor_rotation.z = -anchor_rotation.z;
        rotation.x += anchor_rotation.x;
        rotation.y += anchor_rotation.y;
        rotation.z += anchor_rotation.z;
        has_anchor = 1;
    }

    transform = shape_transform_identity();
    transform.scale_x = scale;
    transform.scale_y = scale;
    transform.scale_z = scale;
    if (has_anchor) {
        /*
         * The source attaches headwear through obj_mHeadwear's mHeadwear node.
         * Individual headwear CGFX files are authored around headwearRoot, so
         * the CFL hat anchor should receive the model origin, not a bounds
         * center/top derived pivot. Bounds anchoring pushes shallow pieces
         * behind the head and makes small accessories disappear.
         */
        pivot.x = 0.0;
        pivot.y = 0.0;
        pivot.z = 0.0;
        transform.translate_x = anchor.x;
        transform.translate_y = anchor.y;
        transform.translate_z = anchor.z;
    } else if (use_face_attachment) {
        transform.translate_x = head_center_x - model_center_x * scale;
        transform.translate_y = head_max.y - model.max.y * scale;
        transform.translate_z = (parts ? parts->nose.z : head_max.z) - model.max.z * scale;
    } else if (use_front_origin_attachment) {
        transform.translate_x = head_center_x;
        transform.translate_y = head_max.y;
        transform.translate_z = (parts ? parts->nose.z : head_max.z) - model.max.z * scale;
    } else {
        transform.translate_x = head_center_x - cgfx_head_center_x * scale;
        transform.translate_y = head_min.y - cgfx_head_min_y * scale;
        transform.translate_z = head_center_z - cgfx_head_center_z * scale;
        if (use_head_space_alignment) {
            transform.translate_y += head_height * 0.18;
        }
    }
    if (variant_offset) {
        variant_translation.x = variant_offset[0] * 0.01 * scale;
        variant_translation.y = variant_offset[1] * 0.01 * scale;
        variant_translation.z = variant_offset[2] * 0.01 * scale;
        transform.translate_x += variant_translation.x;
        transform.translate_y += variant_translation.y;
        transform.translate_z += variant_translation.z;
        rotation.x += variant_offset[3];
        rotation.y += variant_offset[4];
        rotation.z += variant_offset[5];
    }
    if (fabs(rotation.x) > 0.000001 ||
        fabs(rotation.y) > 0.000001 ||
        fabs(rotation.z) > 0.000001) {
        Vec3 translation = { transform.translate_x, transform.translate_y, transform.translate_z };
        if (has_anchor) {
            Vec3 rotated_pivot;
            mtx34_make_srt(transform.matrix, scale, scale, scale, rotation, (Vec3){ 0.0, 0.0, 0.0 });
            rotated_pivot = mtx34_transform_point(transform.matrix, pivot);
            translation.x = anchor.x + variant_translation.x - rotated_pivot.x;
            translation.y = anchor.y + variant_translation.y - rotated_pivot.y;
            translation.z = anchor.z + variant_translation.z - rotated_pivot.z;
        }
        mtx34_make_srt(transform.matrix, scale, scale, scale, rotation, translation);
        transform.has_matrix = 1;
    }
    if (!use_head_space_alignment) {
        canvas_clear_depth_above_world_y(canvas,
            head_min.y + (tomodachi_cgfx_cut_head_max_y() - cgfx_head_min_y) * scale);
    }
    draw_cgfx_model(canvas, &model, &transform, fallback, 1, 0, BLEND_SOURCE_OVER,
        CGFX_IMAGE_DIRECT_MODULATE, 0, SHADER_MAT_CAP, fallback);
    cgfx_model_free(&head_model);
    cgfx_model_free(&model);
    return 1;
}
#endif

static int draw_tomodachi_headwear_model(MeshCanvas *canvas, const MiiFaceParams *params,
    const char *headwear_dir, const char *head_model_path, const CflShape *faceline_shape,
    const CflPartsTransform *parts, const HeadwearMetadata *metadata, int metadata_variant,
    const TomodachiHeadwearItemInfo *headwear_info) {
    char path[1024];
    CgfxModel model;
    ShapeTransform transform;
    ShapeTransform mirror_transform;
    const double scale = 100.0;
    Vec3 anchor_rotation = { 0.0, 0.0, 0.0 };
    Vec3 anchor_translation = { 0.0, 0.0, 0.0 };
    Vec3 variant_rotation = { 0.0, 0.0, 0.0 };
    Vec3 variant_translation = { 0.0, 0.0, 0.0 };
    double anchor_matrix[12];
    double local_matrix[12];
    int animation_index;
    int anchor_index = -1;
    int draw_mirrored_pair = 0;
    uint32_t fallback = palette_color(mii_favorite_colors, 12,
        params->headwear_color >= 0 ? params->headwear_color : params->favorite_color, 6);

    (void)head_model_path;
    (void)faceline_shape;
    memset(&model, 0, sizeof(model));
    if (!resolve_headwear_path(path, sizeof(path), headwear_dir,
            params->headwear_index, params->headwear_color, NULL)) return 0;
    if (headwear_info && headwear_info->has_primary_color) fallback = headwear_info->primary_color;
    if (!cgfx_load_model_file(path, fallback, &model)) return 0;
    cgfx_apply_body_skinning(&model);

    animation_index = tomodachi_headwear_visibility_animation_index(
        metadata ? metadata->head_type : -1);
    if (animation_index < 0 || animation_index > 2) animation_index = 0;
    (void)animation_index;

    if (metadata) {
        switch (metadata->head_type) {
            case 1:
            case 10:
                anchor_index = 0; /* headFront */
                break;
            case 2:
                anchor_index = 1; /* paired headSide */
                draw_mirrored_pair = 1;
                break;
            case 3:
                anchor_index = 1; /* headSide */
                break;
            case 5:
            case 9:
                anchor_index = 2; /* headTop */
                break;
            default:
                break;
        }
    }
    if (anchor_index >= 0 && parts && vec3_has_value(parts->hat_position[anchor_index])) {
        anchor_translation = parts->hat_position[anchor_index];
        anchor_rotation = tomodachi_cfl_headwear_rotation_to_render(
            parts->hat_angle[anchor_index]);
        if (metadata && metadata->head_type == 10) anchor_rotation.x = -anchor_rotation.x;
        if (params->hair_flipped) {
            anchor_translation.x = -anchor_translation.x;
            anchor_rotation.y = -anchor_rotation.y;
            anchor_rotation.z = -anchor_rotation.z;
        }
    } else if (parts) {
        anchor_translation = parts->hair;
    }

    if (metadata && metadata_variant >= 0 && metadata_variant < 16 &&
        metadata->variant_has_offset[metadata_variant]) {
        const double *offset = metadata->variant_offset[metadata_variant];
        variant_translation.x = offset[0];
        variant_translation.y = offset[1];
        variant_translation.z = offset[2];
        variant_rotation.x = offset[3];
        variant_rotation.y = offset[4];
        variant_rotation.z = offset[5];
    }

    /* Preserve the source transform hierarchy: CFL anchor, then the optional
       hair-specific local fit, then the exact 100x CGFX-to-CFL unit bridge. */
    mtx34_make_srt(anchor_matrix, 1.0, 1.0, 1.0,
        anchor_rotation, anchor_translation);
    mtx34_make_srt(local_matrix, scale, scale, scale,
        variant_rotation, variant_translation);
    transform = shape_transform_identity();
    mtx34_mul(transform.matrix, anchor_matrix, local_matrix);
    transform.has_matrix = 1;
    draw_cgfx_model(canvas, &model, &transform, fallback, 1, 0,
        BLEND_SOURCE_OVER, CGFX_IMAGE_DIRECT_MODULATE, 0, SHADER_MAT_CAP, fallback);

    if (draw_mirrored_pair) {
        anchor_translation.x = -anchor_translation.x;
        anchor_rotation.y = -anchor_rotation.y;
        anchor_rotation.z = -anchor_rotation.z;
        variant_translation.x = -variant_translation.x;
        variant_rotation.y = -variant_rotation.y;
        variant_rotation.z = -variant_rotation.z;
        mtx34_make_srt(anchor_matrix, 1.0, 1.0, 1.0,
            anchor_rotation, anchor_translation);
        mtx34_make_srt(local_matrix, -scale, scale, scale,
            variant_rotation, variant_translation);
        mirror_transform = shape_transform_identity();
        mtx34_mul(mirror_transform.matrix, anchor_matrix, local_matrix);
        mirror_transform.has_matrix = 1;
        /* This legacy preview rasterizer has culling disabled for CGFX caps;
           the native PICA exporter separately reverses mirrored winding. */
        draw_cgfx_model(canvas, &model, &mirror_transform, fallback, 1, 0,
            BLEND_SOURCE_OVER, CGFX_IMAGE_DIRECT_MODULATE, 0, SHADER_MAT_CAP, fallback);
    }

    cgfx_model_free(&model);
    return 1;
}

static int decode_texture_or_warn(const CflResource *resource, int section, int item, CflTexture *texture) {
    static const int high_section_for_cfl[] = {
        FFL_HIGH_TEX_CAP,
        FFL_HIGH_TEX_EYE,
        FFL_HIGH_TEX_EYEBROW,
        FFL_HIGH_TEX_BEARD,
        FFL_HIGH_TEX_FACELINE,
        FFL_HIGH_TEX_FACE_MAKEUP,
        FFL_HIGH_TEX_GLASS,
        FFL_HIGH_TEX_MOLE,
        FFL_HIGH_TEX_MOUTH,
        FFL_HIGH_TEX_MUSTACHE,
        FFL_HIGH_TEX_NOSELINE
    };
    int mapping_index = section - CFL_TEX_CAP;
    if (resource && resource->high_textures &&
        mapping_index >= 0 &&
        mapping_index < (int)(sizeof(high_section_for_cfl) / sizeof(high_section_for_cfl[0]))) {
        FflHighTexture high_texture;
        if (ffl_high_decode_texture(resource->high_textures,
                high_section_for_cfl[mapping_index], item, &high_texture)) {
            texture->width = high_texture.width;
            texture->height = high_texture.height;
            texture->format = high_texture.format;
            texture->rgba = high_texture.rgba;
            high_texture.rgba = NULL;
            return 1;
        }
    }
    if (cfl_decode_texture(resource, section, item, texture)) return 1;
    memset(texture, 0, sizeof(*texture));
    return 0;
}

static void raw_mask_clear_alpha(Image *image) {
    int i;
    for (i = 0; i < image->width * image->height; i++) {
        image->rgba[i * 4 + 3] = 0;
    }
}

static void draw_raw_mask_parts(const CflResource *resource, const MiiFaceParams *params,
    Image *out, int blend_mode) {
    const int size = out->width;
    const double y_add = 4.629278;
    const double y_mul = 1.0760943;
    const double spacing_mul = 0.88961464;
    const double x_mul = 1.7792293;
    const double eye_y_add = y_add + 13.822246;
    const double eyebrow_y_add = y_add + 11.920528;
    const double mouth_y_add = y_add + 24.629572;
    const double mustache_y_add = y_add + 27.134275;
    const double mole_x_add = 3.5323312 + 14.233834;
    const double mole_y_add = y_add + 11.178394 + 2.0 * y_mul;
    CflTexture texture;
    OverlayOptions options;
    uint32_t eye_color = mii_eye_color(params->eye_color, 8);
    uint32_t eyebrow_color = mii_render_eyebrow_color(params,
        params->eyebrow_color >= 0 ? params->eyebrow_color : params->hair_color, 1);
    uint32_t facial_hair_color = mii_render_facial_hair_color(params,
        params->beard_color >= 0 ? params->beard_color : params->hair_color, 1);
    int side;

    if (params->mustache_type > 0 &&
        decode_texture_or_warn(resource, CFL_TEX_MUSTACHE, clamp_int(params->mustache_type, 0, 5), &texture)) {
        double scale = 0.4 * clamp_int(params->mustache_size, 0, 8) + 1.0;
        double pos_y = clamp_int(params->mustache_y, 0, 16) * y_mul + mustache_y_add;
        memset(&options, 0, sizeof(options));
        options.mode = MOD_MODE3;
        for (side = -1; side <= 1; side += 2) {
            RawMaskDesc desc = raw_mask_desc(size, 32.0, pos_y, 4.5 * scale, 9.0 * scale,
                side < 0 ? RAW_MASK_ORIGIN_LEFT : RAW_MASK_ORIGIN_RIGHT, 0.0, 0.0);
            overlay_raw_mask_desc_blend(out, &texture, &desc, facial_hair_color, &options, blend_mode);
        }
        cfl_texture_free(&texture);
    }

    if (decode_texture_or_warn(resource, CFL_TEX_MOUTH, clamp_int(params->mouth_type, 0, 36), &texture)) {
        uint32_t mouth_lower;
        uint32_t mouth_upper;
        double scale = 0.4 * clamp_int(params->mouth_size, 0, 8) + 1.0;
        double scale_y = 0.12 * clamp_int(params->mouth_squash, 0, 6) + 0.64;
        double width = 6.1875 * scale;
        double height = 4.5 * scale * scale_y;
        double pos_y = clamp_int(params->mouth_y, 0, 18) * y_mul + mouth_y_add;
        RawMaskDesc desc = raw_mask_desc(size, 32.0, pos_y, width, height, RAW_MASK_ORIGIN_CENTER, 0.0,
            adjusted_mouth_height(height * raw_mask_unit(size), params->mouth_type));
        memset(&options, 0, sizeof(options));
        options.mode = MOD_MODE2;
        mouth_colors(params->mouth_color, &mouth_lower, &mouth_upper);
        options.colors[0] = mouth_lower;
        options.colors[1] = mouth_upper;
        options.colors[2] = 0xffffff;
        overlay_raw_mask_desc_blend(out, &texture, &desc, 0, &options, blend_mode);
        cfl_texture_free(&texture);
    }

    if (decode_texture_or_warn(resource, CFL_TEX_EYEBROWS, clamp_int(params->eyebrow_type, 0, 23), &texture)) {
        double scale = 0.4 * clamp_int(params->eyebrow_size, 0, 8) + 1.0;
        double scale_y = 0.12 * clamp_int(params->eyebrow_squash, 0, 6) + 0.64;
        double width = 5.0625 * scale;
        double height = 4.5 * scale * scale_y;
        double pos_y = clamp_int(params->eyebrow_y + 3, 0, 18) * y_mul + eyebrow_y_add;
        double spacing = clamp_int(params->eyebrow_distance, 0, 12) * spacing_mul;
        double angle = raw_mask_rotation(clamp_int(params->eyebrow_rotation, 0, 11),
            eyebrow_rotation_neutral, (int)(sizeof(eyebrow_rotation_neutral) / sizeof(eyebrow_rotation_neutral[0])),
            clamp_int(params->eyebrow_type, 0, 23), 6);

        memset(&options, 0, sizeof(options));
        options.mode = MOD_MODE3;
        for (side = -1; side <= 1; side += 2) {
            RawMaskDesc desc = raw_mask_desc(size, 32.0 + side * spacing, pos_y,
                width, height, side < 0 ? RAW_MASK_ORIGIN_LEFT : RAW_MASK_ORIGIN_RIGHT,
                side < 0 ? angle : -angle, 0.0);
            overlay_raw_mask_desc_blend(out, &texture, &desc, eyebrow_color, &options, blend_mode);
        }
        cfl_texture_free(&texture);
    }

    if (decode_texture_or_warn(resource, CFL_TEX_EYES, clamp_int(params->eye_type, 0, 61), &texture)) {
        double eye_scale = 0.4 * clamp_int(params->eye_size, 0, 7) + 1.0;
        double eye_scale_y = 0.12 * clamp_int(params->eye_squash, 0, 6) + 0.64;
        double eye_width = 5.34375 * eye_scale;
        double eye_height = 4.5 * eye_scale * eye_scale_y;
        double eye_y = clamp_int(params->eye_y, 0, 18) * y_mul + eye_y_add;
        double eye_spacing = clamp_int(params->eye_distance, 0, 12) * spacing_mul;
        double angle = raw_mask_rotation(clamp_int(params->eye_rotation, 0, 7),
            eye_rotation_neutral, (int)(sizeof(eye_rotation_neutral) / sizeof(eye_rotation_neutral[0])),
            clamp_int(params->eye_type, 0, 61), 4);

        memset(&options, 0, sizeof(options));
        options.mode = MOD_MODE2;
        options.colors[0] = 0x00ffff;
        options.colors[1] = 0xffffff;
        options.colors[2] = eye_color;
        for (side = -1; side <= 1; side += 2) {
            RawMaskDesc desc = raw_mask_desc(size, 32.0 + side * eye_spacing, eye_y,
                eye_width, eye_height, side < 0 ? RAW_MASK_ORIGIN_LEFT : RAW_MASK_ORIGIN_RIGHT,
                side < 0 ? angle : -angle,
                adjusted_eye_height(eye_height * raw_mask_unit(size), params->eye_type));
            overlay_raw_mask_desc_blend(out, &texture, &desc, eye_color, &options, blend_mode);
        }
        cfl_texture_free(&texture);
    }

    if (params->mole_on &&
        decode_texture_or_warn(resource, CFL_TEX_MOLE, 1, &texture)) {
        double scale = 0.4 * clamp_int(params->mole_size, 0, 8) + 1.0;
        double pos_x = clamp_int(params->mole_x, 0, 16) * x_mul + mole_x_add;
        double pos_y = clamp_int(params->mole_y, 0, 30) * y_mul + mole_y_add;
        RawMaskDesc desc = raw_mask_desc(size, pos_x, pos_y, scale, scale,
            RAW_MASK_ORIGIN_CENTER, 0.0, 0.0);
        memset(&options, 0, sizeof(options));
        options.mode = MOD_MODE3;
        overlay_raw_mask_desc_blend(out, &texture, &desc, 0x120f0f, &options, blend_mode);
        cfl_texture_free(&texture);
    }
}

static void overlay_image_source_over(Image *target, const Image *source) {
    int x, y;
    int width = target->width < source->width ? target->width : source->width;
    int height = target->height < source->height ? target->height : source->height;
    for (y = 0; y < height; y++) {
        for (x = 0; x < width; x++) {
            size_t offset = ((size_t)y * (size_t)target->width + (size_t)x) * 4u;
            size_t src = ((size_t)y * (size_t)source->width + (size_t)x) * 4u;
            blend_source_over(target->rgba + offset, source->rgba + src);
        }
    }
}

static void blit_faceline_to_portrait(Image *target, const Image *faceline) {
    int x, y;
    for (y = 0; y < target->height; y++) {
        int src_y = y * faceline->height / target->height;
        for (x = 0; x < target->width; x++) {
            int src_x = x * faceline->width / target->width;
            size_t dst = ((size_t)y * (size_t)target->width + (size_t)x) * 4u;
            size_t src = ((size_t)src_y * (size_t)faceline->width + (size_t)src_x) * 4u;
            target->rgba[dst + 0] = faceline->rgba[src + 0];
            target->rgba[dst + 1] = faceline->rgba[src + 1];
            target->rgba[dst + 2] = faceline->rgba[src + 2];
            target->rgba[dst + 3] = faceline->rgba[src + 3];
        }
    }
}

static void draw_portrait_accessory_overlays(const CflResource *resource, const MiiFaceParams *params, Image *out) {
    const int size = out->width;
    const double y_add = 4.629278;
    const double y_mul = 1.0760943;
    const double eye_y_add = y_add + 13.822246;
    CflTexture texture;
    OverlayOptions options;

    if (decode_texture_or_warn(resource, CFL_TEX_NOSELINE, clamp_int(params->nose_type, 0, 17), &texture)) {
        double scale = clamp_int(params->nose_size, 0, 8) * 0.175 + 0.4;
        double pos_y = clamp_int(params->nose_y, 0, 18) * y_mul + y_add + 20.2;
        RawMaskPart part = raw_mask_part(size, 32.0, pos_y, 16.0 * scale, 16.0 * scale, 0, 0.0);
        memset(&options, 0, sizeof(options));
        options.mode = MOD_MODE3;
        overlay_texture(out, &texture, part.x, part.y, part.width, part.height, 0x221817, &options);
        cfl_texture_free(&texture);
    }

    if (params->glasses_type > 0 &&
        decode_texture_or_warn(resource, CFL_TEX_GLASSES, clamp_int(params->glasses_type, 0, 8), &texture)) {
        double scale = clamp_int(params->glasses_size, 0, 7) * 0.15 + 0.4;
        double eye_y = clamp_int(params->eye_y, 0, 18) * y_mul + eye_y_add;
        double raw_y = eye_y + 1.25 + (clamp_int(params->glasses_y, 0, 20) - 10) * 0.5;
        RawMaskPart part = raw_mask_part(size, 32.0, raw_y, 18.0 * scale, 6.0 * scale, 0, 0.0);
        double height = texture.width ? part.width * ((double)texture.height / (double)texture.width) : part.height;
        uint32_t color = mii_glasses_color(params->glasses_color, 8);
        memset(&options, 0, sizeof(options));
        options.mode = MOD_MODE4;
        overlay_texture(out, &texture, part.x, part.y, part.width, height, color, &options);
        cfl_texture_free(&texture);
    }
}

static int render_face_texture(const CflResource *resource, const MiiFaceParams *params,
    int mask_only, Image *out) {
    (void)mask_only;
    if (!image_create(out, 512, 512)) return 0;

    draw_raw_mask_parts(resource, params, out, BLEND_RAW_MASK_FIRST_PASS);
    /* The fill quad in FFLiDrawRawMask writes transparent black to the alpha
       channel only; the second part pass restores feature coverage. */
    raw_mask_clear_alpha(out);
    draw_raw_mask_parts(resource, params, out, BLEND_RAW_MASK_SECOND_PASS);
    return 1;
}

static int render_faceline_texture(const CflResource *resource, const MiiFaceParams *params, Image *out) {
    const int width = 256;
    const int height = 512;
    CflTexture texture;
    OverlayOptions options;
    uint32_t skin = mii_skin_color(params->face_color);

    if (!image_create(out, width, height)) return 0;
    image_fill(out, skin);

    memset(&options, 0, sizeof(options));
    options.target_width = width;
    options.target_height = height;

    if (decode_texture_or_warn(resource, CFL_TEX_FACE_MAKEUP, clamp_int(params->face_makeup, 0, 11), &texture)) {
        options.mode = MOD_TEXTURE;
        overlay_texture(out, &texture, width / 2.0, height / 2.0, width, height, 0, &options);
        cfl_texture_free(&texture);
    }

    if (decode_texture_or_warn(resource, CFL_TEX_FACELINE, clamp_int(params->face_feature, 0, 11), &texture)) {
        options.mode = MOD_MODE3;
        overlay_texture(out, &texture, width / 2.0, height / 2.0, width, height, 0x000000, &options);
        cfl_texture_free(&texture);
    }

    if (params->beard_type >= 4 &&
        decode_texture_or_warn(resource, CFL_TEX_BEARD, params->beard_type - 3, &texture)) {
        uint32_t beard_color = mii_render_facial_hair_color(params,
            params->beard_color >= 0 ? params->beard_color : params->hair_color, 1);
        options.mode = MOD_MODE3;
        overlay_texture(out, &texture, width / 2.0, height / 2.0, width, height, beard_color, &options);
        cfl_texture_free(&texture);
    }

    return 1;
}

/* Standalone archive tools may supply an already-resolved physical body.
   The hook is invoked at the normal body insertion point so the physical
   CGFX body, CFL head/hair, and physical headwear all share one depth buffer. */
typedef int (*TomodachiDirectBodyDrawHook)(MeshCanvas *canvas,
    const MiiFaceParams *params, const CflShape *faceline_shape);
static TomodachiDirectBodyDrawHook tomodachi_direct_body_draw_hook = NULL;

/* Standalone archive tools may supply an already-resolved physical headwear
   asset.  Keeping the hook at the portrait insertion point preserves the
   source draw order and shared head/hair depth buffer without routing a real
   FileID (notably ID 000) through the catalog's legacy "none" sentinel. */
typedef int (*TomodachiDirectHeadwearDrawHook)(MeshCanvas *canvas,
    const MiiFaceParams *params, const CflShape *faceline_shape,
    const CflPartsTransform *parts, const HeadwearMetadata *metadata,
    int metadata_variant, const TomodachiHeadwearItemInfo *headwear_info);
static TomodachiDirectHeadwearDrawHook tomodachi_direct_headwear_draw_hook = NULL;
static int tomodachi_direct_headwear_enabled = 0;
static HeadwearMetadata tomodachi_direct_headwear_metadata;
static TomodachiHeadwearItemInfo tomodachi_direct_headwear_info;
static int tomodachi_direct_headwear_variant = 0;

static int render_portrait_sized(const CflResource *resource, const MiiFaceParams *params,
    const char *body_dir, const char *headwear_dir, const char *head_model_path,
    int width, int height, Image *out) {
    const double head_scale = 4.45;
    const double head_base_y = 464.0;
    Image faceline_texture;
    Image mask_texture;
    CflShape faceline_shape;
    CflShape forehead_shape;
    CflShape hair_shape;
    CflShape cap_shape;
    CflShape anchor_hair_shape;
    CflShape beard_shape;
    CflShape nose_shape;
    CflShape noseline_shape;
    CflShape mask_shape;
    CflShape glass_shape;
    CflTexture noseline_texture;
    CflTexture glass_texture;
    CflTexture cap_texture;
    CflPartsTransform parts;
    HeadwearMetadata headwear_metadata;
    TomodachiHeadwearItemInfo headwear_info;
    MeshCanvas canvas;
    ShapeTransform transform;
    OverlayOptions options;
    char headwear_path[1024];
    double *depth = NULL;
    uint32_t skin = mii_skin_color(params->face_color);
    uint32_t hair_color = mii_render_hair_color(params, params->hair_color, 1);
    uint32_t cap_color = palette_color(mii_favorite_colors, 12, params->favorite_color, 0);
    uint32_t beard_color = mii_render_facial_hair_color(params,
        params->beard_color >= 0 ? params->beard_color : params->hair_color, 1);
    int base_hair_index = clamp_int(params->hair_type, 0, 131) * 2;
    int hair_index = base_hair_index;
    int headwear_variant = 0;
    int head_model_type = 0;
    int has_headwear = 0;
    int ok = 0;

    memset(&faceline_texture, 0, sizeof(faceline_texture));
    memset(&mask_texture, 0, sizeof(mask_texture));
    memset(&faceline_shape, 0, sizeof(faceline_shape));
    memset(&forehead_shape, 0, sizeof(forehead_shape));
    memset(&hair_shape, 0, sizeof(hair_shape));
    memset(&cap_shape, 0, sizeof(cap_shape));
    memset(&anchor_hair_shape, 0, sizeof(anchor_hair_shape));
    memset(&beard_shape, 0, sizeof(beard_shape));
    memset(&nose_shape, 0, sizeof(nose_shape));
    memset(&noseline_shape, 0, sizeof(noseline_shape));
    memset(&mask_shape, 0, sizeof(mask_shape));
    memset(&glass_shape, 0, sizeof(glass_shape));
    memset(&noseline_texture, 0, sizeof(noseline_texture));
    memset(&glass_texture, 0, sizeof(glass_texture));
    memset(&cap_texture, 0, sizeof(cap_texture));
    memset(&parts, 0, sizeof(parts));
    headwear_metadata_init(&headwear_metadata);
    tomodachi_headwear_item_info_init(&headwear_info, params->headwear_index);
    headwear_path[0] = '\0';

    if (params->draw_headwear && tomodachi_direct_headwear_enabled) {
        headwear_metadata = tomodachi_direct_headwear_metadata;
        headwear_info = tomodachi_direct_headwear_info;
        headwear_variant = tomodachi_direct_headwear_variant;
        headwear_path[0] = '@';
        headwear_path[1] = '\0';
    } else if (params->draw_headwear &&
        resolve_headwear_path(headwear_path, sizeof(headwear_path), headwear_dir,
            params->headwear_index, params->headwear_color, &headwear_info) &&
        cgfx_read_headwear_metadata_file(headwear_path, &headwear_metadata)) {
        headwear_variant = headwear_metadata_select_variant(&headwear_metadata, params->hair_type);
    }
    has_headwear = params->draw_headwear &&
        (tomodachi_direct_headwear_enabled || params->headwear_index > 0) && headwear_path[0];
    if (has_headwear) {
        /* HeadType selects the same default/forCap/forHeadgear mode for both
           the CFL head parts and obj_mHeadwear.  Keep the selected Mii hair;
           catalog HeadwearType is not a replacement-hair selector. */
        head_model_type = tomodachi_headwear_visibility_animation_index(headwear_metadata.head_type);
        if (head_model_type == 1) hair_index = base_hair_index + 1;
        fprintf(stderr,
            "cfl-head-model=%s effective-hair=%d shape-index=%d headwear-type=%d head-type=%d\n",
            head_model_type == 2 ? "headgear" : (head_model_type == 1 ? "cap" : "normal"),
            params->hair_type, head_model_type == 2 ? -1 : hair_index,
            headwear_info.headwear_type, headwear_metadata.head_type);
    }
    if (width < 64 || height < 64) goto cleanup;
    if (!image_create(out, width, height)) goto cleanup;
    image_fill(out, 0xf7f8fb);
    depth = (double *)malloc((size_t)width * (size_t)height * sizeof(double));
    if (!depth) goto cleanup;
    fill_depth(depth, width * height, -1.0e30);

    if (!render_faceline_texture(resource, params, &faceline_texture)) goto cleanup;
    if (!render_face_texture(resource, params, 1, &mask_texture)) goto cleanup;
    if (!cfl_decode_shape(resource, CFL_SHAPE_FACELINE, params->face_type, &faceline_shape)) goto cleanup;
    if (!cfl_decode_shape(resource, CFL_SHAPE_MASK, params->face_type, &mask_shape)) goto cleanup;
    if (head_model_type != 2) {
        if (!cfl_decode_shape(resource, CFL_SHAPE_HAIR, hair_index, &hair_shape)) goto cleanup;
        if (!cfl_decode_shape(resource, CFL_SHAPE_FOREHEAD, hair_index, &forehead_shape)) goto cleanup;
        /* FFL selects hair, cap, and forehead from one authored model family;
           valid empty records must not fall back across families. */
        if (!cfl_decode_shape(resource, CFL_SHAPE_HAT, hair_index, &cap_shape)) goto cleanup;
        if (cap_shape.vertices &&
            !decode_texture_or_warn(resource, CFL_TEX_CAP, params->hair_type, &cap_texture)) {
            goto cleanup;
        }
    } else if (!cfl_decode_shape(resource, CFL_SHAPE_HAIR, base_hair_index, &anchor_hair_shape)) {
        goto cleanup;
    }
    cfl_decode_shape(resource, CFL_SHAPE_NOSE, params->nose_type, &nose_shape);
    cfl_decode_shape(resource, CFL_SHAPE_NOSELINE, params->nose_type, &noseline_shape);
    if (params->beard_type > 0 && params->beard_type < 4) {
        cfl_decode_shape(resource, CFL_SHAPE_BEARD, params->beard_type, &beard_shape);
    }
    if (params->glasses_type > 0) {
        cfl_decode_shape(resource, CFL_SHAPE_GLASSES, 0, &glass_shape);
        decode_texture_or_warn(resource, CFL_TEX_GLASSES, clamp_int(params->glasses_type, 0, 8), &glass_texture);
    }
    decode_texture_or_warn(resource, CFL_TEX_NOSELINE, clamp_int(params->nose_type, 0, 17), &noseline_texture);

    if (faceline_shape.extra_count >= 3) {
        parts.hair = faceline_shape.extra[0];
        parts.nose = faceline_shape.extra[1];
        parts.beard = faceline_shape.extra[2];
    }
    {
        const CflShape *parts_shape = head_model_type == 2 ? &anchor_hair_shape : &hair_shape;
        int has_hair_anchor = hair_shape.extra_count >= 6 &&
            (vec3_has_value(hair_shape.extra[1]) ||
             vec3_has_value(hair_shape.extra[3]) ||
             vec3_has_value(hair_shape.extra[5]));
        if (!has_hair_anchor) {
            int anchor_hair_index = hair_index & ~1;
            if (anchor_hair_index != hair_index &&
                cfl_decode_shape(resource, CFL_SHAPE_HAIR, anchor_hair_index, &anchor_hair_shape)) {
                parts_shape = &anchor_hair_shape;
            } else if (hair_index != base_hair_index &&
                cfl_decode_shape(resource, CFL_SHAPE_HAIR, base_hair_index, &anchor_hair_shape)) {
                parts_shape = &anchor_hair_shape;
            }
        }
    if (parts_shape->extra_count >= 6) {
        parts.hat_angle[0] = parts_shape->extra[0];
        parts.hat_position[0] = parts_shape->extra[1];
        parts.hat_angle[1] = parts_shape->extra[2];
        parts.hat_position[1] = parts_shape->extra[3];
        parts.hat_angle[2] = parts_shape->extra[4];
        parts.hat_position[2] = parts_shape->extra[5];
        parts.hat_position[0].x += parts.hair.x;
        parts.hat_position[0].y += parts.hair.y;
        parts.hat_position[0].z += parts.hair.z;
        parts.hat_position[1].x += parts.hair.x;
        parts.hat_position[1].y += parts.hair.y;
        parts.hat_position[1].z += parts.hair.z;
        parts.hat_position[2].x += parts.hair.x;
        parts.hat_position[2].y += parts.hair.y;
        parts.hat_position[2].z += parts.hair.z;
    }
    }

    canvas.image = out;
    canvas.depth = depth;
    if (params->full_body) {
        mesh_canvas_set_whole_body_camera(&canvas, width, height, params->height);
    } else {
        mesh_canvas_set_orthographic(&canvas, width * 0.5, head_base_y, head_scale);
    }

    if (params->draw_body) {
        if (tomodachi_direct_body_draw_hook) {
            if (!tomodachi_direct_body_draw_hook(
                    &canvas, params, &faceline_shape)) goto cleanup;
        } else {
            draw_tomodachi_body_model(&canvas, params, body_dir, &faceline_shape);
        }
    }

    transform = shape_transform_identity();
    draw_shape_mesh(&canvas, &faceline_shape, &transform, &faceline_texture, NULL, NULL,
        skin, 1, 1, BLEND_SOURCE_OVER, SHADER_MAT_FACELINE);

    if (beard_shape.vertices) {
        transform = shape_transform_identity();
        transform.translate_x = parts.beard.x;
        transform.translate_y = parts.beard.y;
        transform.translate_z = parts.beard.z;
        draw_shape_mesh(&canvas, &beard_shape, &transform, NULL, NULL, NULL,
            beard_color, 1, 1, BLEND_SOURCE_OVER, SHADER_MAT_BEARD);
    }

    transform = shape_transform_identity();
    transform.translate_x = parts.hair.x;
    transform.translate_y = parts.hair.y;
    transform.translate_z = parts.hair.z;
    transform.mirror_x = params->hair_flipped;
    if (forehead_shape.vertices) {
        draw_shape_mesh(&canvas, &forehead_shape, &transform, NULL, NULL, NULL,
            skin, 1, 1, BLEND_SOURCE_OVER, SHADER_MAT_FOREHEAD);
    }
    if (hair_shape.vertices) {
        draw_shape_mesh(&canvas, &hair_shape, &transform, NULL, NULL, NULL,
            hair_color, 1, 1, BLEND_SOURCE_OVER, SHADER_MAT_HAIR);
    }
    if (cap_shape.vertices && cap_texture.rgba) {
        memset(&options, 0, sizeof(options));
        options.mode = MOD_MODE5;
        draw_shape_mesh(&canvas, &cap_shape, &transform, NULL, &cap_texture, &options,
            cap_color, 1, 1, BLEND_SOURCE_OVER, SHADER_MAT_CAP);
    }

    if (params->draw_headwear) {
        if (tomodachi_direct_headwear_enabled && tomodachi_direct_headwear_draw_hook) {
            tomodachi_direct_headwear_draw_hook(&canvas, params, &faceline_shape,
                &parts, &headwear_metadata, headwear_variant, &headwear_info);
        } else {
            draw_tomodachi_headwear_model(&canvas, params, headwear_dir, head_model_path, &faceline_shape,
                &parts, &headwear_metadata, headwear_variant, &headwear_info);
        }
    }

    transform = shape_transform_identity();
    {
        double nose_scale = clamp_int(params->nose_size, 0, 8) * 0.175 + 0.4;
        transform.scale_x = nose_scale;
        transform.scale_y = nose_scale;
        transform.scale_z = has_headwear &&
            (headwear_metadata.head_type == 7 ||
             headwear_metadata.head_type == 9 ||
             headwear_metadata.head_type == 10) &&
            nose_scale > 1.1 ? 1.1 : nose_scale;
        transform.translate_x = parts.nose.x;
        transform.translate_y = parts.nose.y + (clamp_int(params->nose_y, 0, 18) - 8) * -1.5;
        transform.translate_z = parts.nose.z;
    }
    if (nose_shape.vertices) {
        draw_shape_mesh(&canvas, &nose_shape, &transform, NULL, NULL, NULL,
            skin, 1, 1, BLEND_SOURCE_OVER, SHADER_MAT_NOSE);
    }

    draw_shape_mesh(&canvas, &mask_shape, NULL, &mask_texture, NULL, NULL,
        0xffffff, 1, 0, BLEND_SOURCE_OVER, SHADER_MAT_MASK);

    if (noseline_shape.vertices && noseline_texture.rgba) {
        memset(&options, 0, sizeof(options));
        options.mode = MOD_MODE3;
        draw_shape_mesh(&canvas, &noseline_shape, &transform, NULL, &noseline_texture, &options,
            0x221817, 1, 0, BLEND_SOURCE_OVER, SHADER_MAT_NOSELINE);
    }

    if (glass_shape.vertices && glass_texture.rgba) {
        double glass_scale = clamp_int(params->glasses_size, 0, 7) * 0.15 + 0.4;
        uint32_t color = mii_glasses_color(params->glasses_color, 8);
        transform = shape_transform_identity();
        transform.scale_x = glass_scale;
        transform.scale_y = glass_scale;
        transform.scale_z = glass_scale;
        transform.translate_x = parts.nose.x;
        transform.translate_y = parts.nose.y + (clamp_int(params->glasses_y, 0, 20) - 11) * -1.5 + 5.0;
        transform.translate_z = parts.nose.z + 2.0;
        memset(&options, 0, sizeof(options));
        options.mode = MOD_MODE4;
        options.mirror_repeat_x = 1;
        draw_shape_mesh(&canvas, &glass_shape, &transform, NULL, &glass_texture, &options,
            color, 1, 0, BLEND_SOURCE_OVER, SHADER_MAT_GLASS);
    }

    ok = 1;

cleanup:
    cfl_texture_free(&cap_texture);
    cfl_texture_free(&noseline_texture);
    cfl_texture_free(&glass_texture);
    cfl_shape_free(&faceline_shape);
    cfl_shape_free(&forehead_shape);
    cfl_shape_free(&hair_shape);
    cfl_shape_free(&cap_shape);
    cfl_shape_free(&anchor_hair_shape);
    cfl_shape_free(&beard_shape);
    cfl_shape_free(&nose_shape);
    cfl_shape_free(&noseline_shape);
    cfl_shape_free(&mask_shape);
    cfl_shape_free(&glass_shape);
    image_free(&faceline_texture);
    image_free(&mask_texture);
    free(depth);
    if (!ok) image_free(out);
    return ok;
}

static int render_portrait(const CflResource *resource, const MiiFaceParams *params,
    const char *body_dir, const char *headwear_dir, const char *head_model_path, Image *out) {
    return render_portrait_sized(resource, params, body_dir, headwear_dir,
        head_model_path, 512, 832, out);
}

static void init_default_params(MiiFaceParams *params) {
    memset(params, 0, sizeof(*params));
    params->gender = 0;
    params->favorite_color = 0;
    params->height = 64;
    params->weight = 64;
    params->face_color = 0;
    params->face_type = 0;
    params->face_feature = 0;
    params->face_makeup = 0;
    params->hair_type = 0;
    params->hair_flipped = 0;
    params->hair_color = 1;
    params->hair_dye_color = 0;
    params->hair_dye_mode = 0;
    params->eye_type = 2;
    params->eye_color = 0;
    params->eye_size = 4;
    params->eye_squash = 3;
    params->eye_rotation = 4;
    params->eye_distance = 2;
    params->eye_y = 12;
    params->eyebrow_type = 6;
    params->eyebrow_color = 1;
    params->eyebrow_size = 4;
    params->eyebrow_squash = 3;
    params->eyebrow_rotation = 6;
    params->eyebrow_distance = 2;
    params->eyebrow_y = 7;
    params->nose_type = 1;
    params->nose_size = 4;
    params->nose_y = 9;
    params->mouth_type = 14;
    params->mouth_color = 0;
    params->mouth_size = 4;
    params->mouth_squash = 3;
    params->mouth_y = 13;
    params->mustache_type = 0;
    params->mustache_size = 4;
    params->mustache_y = 10;
    params->beard_type = 0;
    params->beard_color = 1;
    params->glasses_type = 0;
    params->glasses_color = 0;
    params->glasses_size = 4;
    params->glasses_y = 10;
    params->mole_on = 0;
    params->mole_size = 4;
    params->mole_x = 2;
    params->mole_y = 20;
    params->body_index = 0;
    params->body_color = 0;
    params->headwear_index = 0;
    params->headwear_color = 0;
    params->draw_body = 1;
    params->draw_headwear = 1;
    params->full_body = 0;
}

static const char *arg_value(const char *text, const char *prefix) {
    size_t length = strlen(prefix);
    return strncmp(text, prefix, length) == 0 ? text + length : NULL;
}

static int parse_int_arg(const char *arg) {
    return (int)strtol(arg, NULL, 0);
}

/*
 * The archive renderers include this translation unit and also use --height
 * and --width for their output canvas.  Keep imported Mii data in a distinct
 * namespace so a complete face/body profile cannot collide with driver
 * options.  The field names deliberately mirror render_inputs.js/MiiJS.
 */
static int mii_face_params_parse_prefixed_arg(MiiFaceParams *params, const char *arg) {
    const char *value;
    if (!params || !arg) return 0;
    if ((value = arg_value(arg, "--mii-gender="))) params->gender = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-favorite-color="))) params->favorite_color = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-height="))) params->height = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-weight="))) params->weight = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-face-color="))) params->face_color = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-face-type="))) params->face_type = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-face-feature="))) params->face_feature = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-face-makeup="))) params->face_makeup = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-hair-type="))) params->hair_type = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-hair-flipped="))) params->hair_flipped = parse_int_arg(value) != 0;
    else if ((value = arg_value(arg, "--mii-hair-color="))) params->hair_color = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-hair-dye-color="))) params->hair_dye_color = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-hair-dye-mode="))) params->hair_dye_mode = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eye-type="))) params->eye_type = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eye-color="))) params->eye_color = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eye-size="))) params->eye_size = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eye-squash="))) params->eye_squash = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eye-rotation="))) params->eye_rotation = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eye-distance="))) params->eye_distance = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eye-y="))) params->eye_y = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eyebrow-type="))) params->eyebrow_type = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eyebrow-color="))) params->eyebrow_color = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eyebrow-size="))) params->eyebrow_size = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eyebrow-squash="))) params->eyebrow_squash = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eyebrow-rotation="))) params->eyebrow_rotation = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eyebrow-distance="))) params->eyebrow_distance = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-eyebrow-y="))) params->eyebrow_y = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-nose-type="))) params->nose_type = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-nose-size="))) params->nose_size = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-nose-y="))) params->nose_y = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-mouth-type="))) params->mouth_type = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-mouth-color="))) params->mouth_color = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-mouth-size="))) params->mouth_size = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-mouth-squash="))) params->mouth_squash = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-mouth-y="))) params->mouth_y = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-mustache-type="))) params->mustache_type = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-mustache-size="))) params->mustache_size = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-mustache-y="))) params->mustache_y = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-beard-type="))) params->beard_type = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-beard-color="))) params->beard_color = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-glasses-type="))) params->glasses_type = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-glasses-color="))) params->glasses_color = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-glasses-size="))) params->glasses_size = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-glasses-y="))) params->glasses_y = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-mole-on="))) params->mole_on = parse_int_arg(value) != 0;
    else if ((value = arg_value(arg, "--mii-mole-size="))) params->mole_size = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-mole-x="))) params->mole_x = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-mole-y="))) params->mole_y = parse_int_arg(value);
    else if ((value = arg_value(arg, "--mii-full-body="))) params->full_body = parse_int_arg(value) != 0;
    else return 0;
    return 1;
}

static int parse_pair_arg(const char *arg, int *a, int *b) {
    char *endptr;
    long first = strtol(arg, &endptr, 0);
    if (*endptr != ',' && *endptr != ':') return 0;
    *a = (int)first;
    *b = (int)strtol(endptr + 1, NULL, 0);
    return 1;
}

static int write_cfl_texture_debug(const CflResource *resource, const char *spec, const char *path) {
    int section;
    int item;
    CflTexture texture;
    Image image;
    int ok;
    memset(&texture, 0, sizeof(texture));
    memset(&image, 0, sizeof(image));
    if (!spec || !path || !parse_pair_arg(spec, &section, &item)) return 0;
    if (!cfl_decode_texture(resource, section, item, &texture)) return 0;
    image.width = texture.width;
    image.height = texture.height;
    image.rgba = texture.rgba;
    ok = write_image(path, &image);
    texture.rgba = NULL;
    cfl_texture_free(&texture);
    return ok;
}

static int print_cfl_shape_info(const CflResource *resource, const char *spec) {
    int section;
    int item;
    CflShape shape;
    Vec3 min;
    Vec3 max;
    int i;
    memset(&shape, 0, sizeof(shape));
    if (!resource || !spec || !parse_pair_arg(spec, &section, &item)) return 0;
    if (!cfl_decode_shape(resource, section, item, &shape)) return 0;
    printf("cfl_shape section=%d item=%d vertices=%d indices=%d normals=%d texcoords=%d extras=%d\n",
        section, item, shape.vertex_count, shape.index_count, shape.normal_count,
        shape.texcoord_count, shape.extra_count);
    if (cfl_shape_bounds(&shape, NULL, &min, &max)) {
        printf("bounds min=(%.6f, %.6f, %.6f) max=(%.6f, %.6f, %.6f)\n",
            min.x, min.y, min.z, max.x, max.y, max.z);
    }
    for (i = 0; i < shape.extra_count && i < 6; i++) {
        printf("extra[%d]=(%.6f, %.6f, %.6f)\n", i,
            shape.extra[i].x, shape.extra[i].y, shape.extra[i].z);
    }
    cfl_shape_free(&shape);
    return 1;
}

static int print_model_info(const char *path, const char *animation_name, const char *texture_out,
    const char *mask_out, const char *normal_out) {
    CgfxModel model;
    HeadwearMetadata metadata;
    int i;
    memset(&model, 0, sizeof(model));
    headwear_metadata_init(&metadata);
    if (!cgfx_load_model_file(path, 0xffffff, &model)) {
        fprintf(stderr, "Could not load CGFX model %s\n", path);
        return 0;
    }
    if (animation_name && animation_name[0]) {
        cgfx_apply_skeletal_animation_file(&model, path, animation_name, 0.0);
        cgfx_update_body_skin_matrices(&model);
    }
    printf("model=%s\n", path);
    printf("bounds min=(%.6f, %.6f, %.6f) max=(%.6f, %.6f, %.6f)\n",
        model.min.x, model.min.y, model.min.z, model.max.x, model.max.y, model.max.z);
    printf("meshes=%d bones=%d texture=%d mask=%d normal=%d materials=%d texenv=%d\n",
        model.mesh_count, model.bone_count, model.has_texture,
        model.has_mask_texture, model.has_normal_texture, model.material_count, model.material.has_texenv);
    for (i = 0; i < 3; i++) {
        if (model.material.has_texcoord[i]) {
            printf("texcoord[%d] scale=(%.6f, %.6f) rotation=%.6f translate=(%.6f, %.6f) type=%d\n",
                i, model.material.tex_scale[i][0], model.material.tex_scale[i][1],
                model.material.tex_rotation[i], model.material.tex_translate[i][0],
                model.material.tex_translate[i][1], model.material.tex_transform_type[i]);
        }
    }
    if (model.material.has_texenv) {
        for (i = 0; i < 6; i++) {
            const CgfxTexEnvStage *stage = &model.material.stages[i];
            printf("stage[%d] srcRgb=(%d,%d,%d) srcA=(%d,%d,%d) opRgb=(%d,%d,%d) opA=(%d,%d,%d) comb=(%d,%d) scale=(%d,%d) constSel=%d const=(%.3f,%.3f,%.3f,%.3f) update=(%d,%d)\n",
                i,
                stage->source_color[0], stage->source_color[1], stage->source_color[2],
                stage->source_alpha[0], stage->source_alpha[1], stage->source_alpha[2],
                stage->operand_color[0], stage->operand_color[1], stage->operand_color[2],
                stage->operand_alpha[0], stage->operand_alpha[1], stage->operand_alpha[2],
                stage->combiner_color, stage->combiner_alpha,
                stage->scale_color, stage->scale_alpha,
                stage->constant_selector,
                stage->constant[0], stage->constant[1], stage->constant[2], stage->constant[3],
                stage->update_color_buffer, stage->update_alpha_buffer);
        }
    }
    for (i = 0; i < model.mesh_count; i++) {
        const CgfxMesh *mesh = &model.meshes[i];
        int v;
        double uv_min_x = 1e30;
        double uv_min_y = 1e30;
        double uv_max_x = -1e30;
        double uv_max_y = -1e30;
        double low_uv_min_x = 1e30;
        double low_uv_min_y = 1e30;
        double low_uv_max_x = -1e30;
        double low_uv_max_y = -1e30;
        double low_y = mesh->min.y + (mesh->max.y - mesh->min.y) * 0.35;
        printf("mesh[%d] vertices=%d indices=%d material=%d skin=%d min=(%.6f, %.6f, %.6f) max=(%.6f, %.6f, %.6f)\n",
            i, mesh->vertex_count, mesh->index_count, mesh->material_index, mesh->has_skin,
            mesh->min.x, mesh->min.y, mesh->min.z, mesh->max.x, mesh->max.y, mesh->max.z);
        if (mesh->has_uvs && mesh->uvs) {
            for (v = 0; v < mesh->vertex_count; v++) {
                Vec2 uv = mesh->uvs[v];
                if (uv.x < uv_min_x) uv_min_x = uv.x;
                if (uv.y < uv_min_y) uv_min_y = uv.y;
                if (uv.x > uv_max_x) uv_max_x = uv.x;
                if (uv.y > uv_max_y) uv_max_y = uv.y;
                if (mesh->vertices[v].y <= low_y) {
                    if (uv.x < low_uv_min_x) low_uv_min_x = uv.x;
                    if (uv.y < low_uv_min_y) low_uv_min_y = uv.y;
                    if (uv.x > low_uv_max_x) low_uv_max_x = uv.x;
                    if (uv.y > low_uv_max_y) low_uv_max_y = uv.y;
                }
            }
            printf("mesh[%d] uv=(%.6f, %.6f)..(%.6f, %.6f) low_y<=%.6f uv=(%.6f, %.6f)..(%.6f, %.6f)\n",
                i, uv_min_x, uv_min_y, uv_max_x, uv_max_y, low_y,
                low_uv_min_x, low_uv_min_y, low_uv_max_x, low_uv_max_y);
        }
    }
    for (i = 0; i < model.bone_count; i++) {
        const CgfxBone *bone = &model.bones[i];
        printf("bone[%d] name=%s parent=%d scale=(%.6f, %.6f, %.6f) rotation=(%.6f, %.6f, %.6f) translation=(%.6f, %.6f, %.6f) localT=(%.6f, %.6f, %.6f) invT=(%.6f, %.6f, %.6f)\n",
            i, bone->name, bone->parent_index,
            bone->base_scale.x, bone->base_scale.y, bone->base_scale.z,
            bone->base_rotation.x, bone->base_rotation.y, bone->base_rotation.z,
            bone->base_translation.x, bone->base_translation.y, bone->base_translation.z,
            bone->local[3], bone->local[7], bone->local[11],
            bone->inv_world[3], bone->inv_world[7], bone->inv_world[11]);
    }
    if (cgfx_read_headwear_metadata_file(path, &metadata)) {
        printf("metadata HeadType=%d defaultHair=%d hasOffset=%d Offset=(%.6f, %.6f, %.6f, %.6f, %.6f, %.6f) variants=%d\n",
            metadata.head_type, metadata.hair_index, metadata.has_offset,
            metadata.offset[0], metadata.offset[1], metadata.offset[2],
            metadata.offset[3], metadata.offset[4], metadata.offset[5], metadata.variant_count);
        for (i = 0; i < metadata.variant_count && i < 16; i++) {
            if (metadata.variant_hair_index[i] >= 0 || metadata.variant_has_offset[i]) {
                printf("metadata[%d] Hair=%d hasOffset=%d Offset=(%.6f, %.6f, %.6f, %.6f, %.6f, %.6f)\n",
                    i, metadata.variant_hair_index[i], metadata.variant_has_offset[i],
                    metadata.variant_offset[i][0], metadata.variant_offset[i][1],
                    metadata.variant_offset[i][2], metadata.variant_offset[i][3],
                    metadata.variant_offset[i][4], metadata.variant_offset[i][5]);
            }
        }
    }
    if (texture_out && model.has_texture) {
        write_image(texture_out, &model.texture);
    }
    if (mask_out && model.has_mask_texture) {
        write_image(mask_out, &model.mask_texture);
    }
    if (normal_out && model.has_normal_texture) {
        write_image(normal_out, &model.normal_texture);
    }
    cgfx_model_free(&model);
    return 1;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s --cfl=CFL_Res.dat --ffl=FFLResHigh.dat [--render-out=render.bmp] [--face-out=face.tga] [--faceline-out=faceline.tga] [fields]\n"
        "Common fields: --face-color=N --face-type=N --face-feature=N --face-makeup=N\n"
        "               --eye-type=N --eye-color=N --eye-size=N --eye-squash=N --eye-rotation=N --eye-distance=N --eye-y=N\n"
        "               --eyebrow-type=N --eyebrow-color=N --mouth-type=N --mouth-color=N --glasses-type=N\n",
        argv0);
}

int main(int argc, char **argv) {
    const char *cfl_path = "CFL_Res.dat";
    const char *ffl_path = "FFLResHigh.dat";
    const char *body_dir = "romFS/model/body";
    const char *headwear_dir = "romFS/model/headwear";
    const char *head_model_path = "romFS/model/obj/obj_mHead.bin.dat";
    const char *render_out = NULL;
    const char *face_out = NULL;
    const char *faceline_out = NULL;
    const char *model_info_path = NULL;
    const char *model_animation = NULL;
    const char *model_texture_out = NULL;
    const char *model_mask_out = NULL;
    const char *model_normal_out = NULL;
    const char *cfl_texture_spec = NULL;
    const char *cfl_texture_out = NULL;
    const char *cfl_shape_info = NULL;
    int mask_only = 0;
    Buffer cfl_bytes;
    Buffer ffl_bytes;
    CflResource resource;
    FflHighResource high_resource;
    MiiFaceParams params;
    Image render;
    Image face;
    Image faceline;
    int i;
    int ok = 1;

    init_default_params(&params);
    memset(&render, 0, sizeof(render));
    memset(&face, 0, sizeof(face));
    memset(&faceline, 0, sizeof(faceline));
    memset(&ffl_bytes, 0, sizeof(ffl_bytes));
    memset(&high_resource, 0, sizeof(high_resource));

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *value;
        if ((value = arg_value(arg, "--cfl="))) cfl_path = value;
        else if ((value = arg_value(arg, "--ffl="))) ffl_path = value;
        else if ((value = arg_value(arg, "--body-dir="))) body_dir = value;
        else if ((value = arg_value(arg, "--headwear-dir="))) headwear_dir = value;
        else if ((value = arg_value(arg, "--head-model="))) head_model_path = value;
        else if ((value = arg_value(arg, "--render-out="))) render_out = value;
        else if ((value = arg_value(arg, "--face-out="))) face_out = value;
        else if ((value = arg_value(arg, "--faceline-out="))) faceline_out = value;
        else if ((value = arg_value(arg, "--model-info="))) model_info_path = value;
        else if ((value = arg_value(arg, "--model-animation="))) model_animation = value;
        else if ((value = arg_value(arg, "--model-texture-out="))) model_texture_out = value;
        else if ((value = arg_value(arg, "--model-mask-out="))) model_mask_out = value;
        else if ((value = arg_value(arg, "--model-normal-out="))) model_normal_out = value;
        else if ((value = arg_value(arg, "--cfl-texture="))) cfl_texture_spec = value;
        else if ((value = arg_value(arg, "--cfl-texture-out="))) cfl_texture_out = value;
        else if ((value = arg_value(arg, "--cfl-shape-info="))) cfl_shape_info = value;
        else if ((value = arg_value(arg, "--mask-only="))) mask_only = parse_int_arg(value) != 0;
        else if ((value = arg_value(arg, "--gender="))) params.gender = parse_int_arg(value);
        else if ((value = arg_value(arg, "--favorite-color="))) params.favorite_color = parse_int_arg(value);
        else if ((value = arg_value(arg, "--height="))) params.height = parse_int_arg(value);
        else if ((value = arg_value(arg, "--weight="))) params.weight = parse_int_arg(value);
        else if ((value = arg_value(arg, "--face-color="))) params.face_color = parse_int_arg(value);
        else if ((value = arg_value(arg, "--face-type="))) params.face_type = parse_int_arg(value);
        else if ((value = arg_value(arg, "--face-feature="))) params.face_feature = parse_int_arg(value);
        else if ((value = arg_value(arg, "--face-makeup="))) params.face_makeup = parse_int_arg(value);
        else if ((value = arg_value(arg, "--hair-type="))) params.hair_type = parse_int_arg(value);
        else if ((value = arg_value(arg, "--hair-flipped="))) params.hair_flipped = parse_int_arg(value) != 0;
        else if ((value = arg_value(arg, "--hair-color="))) params.hair_color = parse_int_arg(value);
        else if ((value = arg_value(arg, "--hair-dye-color="))) params.hair_dye_color = parse_int_arg(value);
        else if ((value = arg_value(arg, "--hair-dye-mode="))) params.hair_dye_mode = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eye-type="))) params.eye_type = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eye-color="))) params.eye_color = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eye-size="))) params.eye_size = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eye-squash="))) params.eye_squash = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eye-rotation="))) params.eye_rotation = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eye-distance="))) params.eye_distance = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eye-y="))) params.eye_y = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eyebrow-type="))) params.eyebrow_type = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eyebrow-color="))) params.eyebrow_color = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eyebrow-size="))) params.eyebrow_size = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eyebrow-squash="))) params.eyebrow_squash = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eyebrow-rotation="))) params.eyebrow_rotation = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eyebrow-distance="))) params.eyebrow_distance = parse_int_arg(value);
        else if ((value = arg_value(arg, "--eyebrow-y="))) params.eyebrow_y = parse_int_arg(value);
        else if ((value = arg_value(arg, "--nose-type="))) params.nose_type = parse_int_arg(value);
        else if ((value = arg_value(arg, "--nose-size="))) params.nose_size = parse_int_arg(value);
        else if ((value = arg_value(arg, "--nose-y="))) params.nose_y = parse_int_arg(value);
        else if ((value = arg_value(arg, "--mouth-type="))) params.mouth_type = parse_int_arg(value);
        else if ((value = arg_value(arg, "--mouth-color="))) params.mouth_color = parse_int_arg(value);
        else if ((value = arg_value(arg, "--mouth-size="))) params.mouth_size = parse_int_arg(value);
        else if ((value = arg_value(arg, "--mouth-squash="))) params.mouth_squash = parse_int_arg(value);
        else if ((value = arg_value(arg, "--mouth-y="))) params.mouth_y = parse_int_arg(value);
        else if ((value = arg_value(arg, "--mustache-type="))) params.mustache_type = parse_int_arg(value);
        else if ((value = arg_value(arg, "--mustache-size="))) params.mustache_size = parse_int_arg(value);
        else if ((value = arg_value(arg, "--mustache-y="))) params.mustache_y = parse_int_arg(value);
        else if ((value = arg_value(arg, "--beard-type="))) params.beard_type = parse_int_arg(value);
        else if ((value = arg_value(arg, "--beard-color="))) params.beard_color = parse_int_arg(value);
        else if ((value = arg_value(arg, "--glasses-type="))) params.glasses_type = parse_int_arg(value);
        else if ((value = arg_value(arg, "--glasses-color="))) params.glasses_color = parse_int_arg(value);
        else if ((value = arg_value(arg, "--glasses-size="))) params.glasses_size = parse_int_arg(value);
        else if ((value = arg_value(arg, "--glasses-y="))) params.glasses_y = parse_int_arg(value);
        else if ((value = arg_value(arg, "--mole-on="))) params.mole_on = parse_int_arg(value) != 0;
        else if ((value = arg_value(arg, "--mole-size="))) params.mole_size = parse_int_arg(value);
        else if ((value = arg_value(arg, "--mole-x="))) params.mole_x = parse_int_arg(value);
        else if ((value = arg_value(arg, "--mole-y="))) params.mole_y = parse_int_arg(value);
        else if ((value = arg_value(arg, "--body-index="))) params.body_index = parse_int_arg(value);
        else if ((value = arg_value(arg, "--body-color="))) params.body_color = parse_int_arg(value);
        else if ((value = arg_value(arg, "--headwear-index="))) params.headwear_index = parse_int_arg(value);
        else if ((value = arg_value(arg, "--headwear-color="))) params.headwear_color = parse_int_arg(value);
        else if ((value = arg_value(arg, "--draw-body="))) params.draw_body = parse_int_arg(value) != 0;
        else if ((value = arg_value(arg, "--draw-headwear="))) params.draw_headwear = parse_int_arg(value) != 0;
        else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!render_out && !face_out && !faceline_out) {
        render_out = "render.bmp";
    }

    if (model_info_path) {
        return print_model_info(model_info_path, model_animation, model_texture_out, model_mask_out, model_normal_out) ? 0 : 1;
    }

    if (!read_file(cfl_path, &cfl_bytes)) return 1;
    if (!cfl_parse(&resource, cfl_bytes.data, cfl_bytes.size)) {
        fprintf(stderr, "Could not parse CFL resource %s\n", cfl_path);
        free(cfl_bytes.data);
        return 1;
    }
    if (!read_file(ffl_path, &ffl_bytes) ||
        !ffl_high_parse(&high_resource, ffl_bytes.data, ffl_bytes.size)) {
        fprintf(stderr, "Could not parse FFL high resource %s\n", ffl_path);
        cfl_free(&resource);
        free(cfl_bytes.data);
        free(ffl_bytes.data);
        return 1;
    }
    resource.high_textures = &high_resource;

    if (cfl_texture_spec && cfl_texture_out) {
        ok = write_cfl_texture_debug(&resource, cfl_texture_spec, cfl_texture_out);
        cfl_free(&resource);
        free(cfl_bytes.data);
        free(ffl_bytes.data);
        return ok ? 0 : 1;
    }
    if (cfl_shape_info) {
        ok = print_cfl_shape_info(&resource, cfl_shape_info);
        cfl_free(&resource);
        free(cfl_bytes.data);
        free(ffl_bytes.data);
        return ok ? 0 : 1;
    }

    if (render_out) {
        ok = render_portrait(&resource, &params, body_dir, headwear_dir, head_model_path, &render) && write_image(render_out, &render) && ok;
    }
    if (face_out) {
        ok = render_face_texture(&resource, &params, mask_only, &face) && write_image(face_out, &face) && ok;
    }
    if (faceline_out) {
        ok = render_faceline_texture(&resource, &params, &faceline) && write_image(faceline_out, &faceline) && ok;
    }

    image_free(&render);
    image_free(&face);
    image_free(&faceline);
    cfl_free(&resource);
    free(cfl_bytes.data);
    free(ffl_bytes.data);
    return ok ? 0 : 1;
}
