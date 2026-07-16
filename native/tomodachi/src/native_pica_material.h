#ifndef TOMODACHI_NATIVE_PICA_MATERIAL_H
#define TOMODACHI_NATIVE_PICA_MATERIAL_H

/*
 * CPU implementation of the CGFX/PICA material path used by Tomodachi Life.
 *
 * The loader consumes the fixed-width, little-endian sidecars emitted by
 * material_sidecar/HeadwearMaterialSidecar.  It deliberately does not infer
 * texture roles from filenames: every texture, coordinate set, sampler and
 * TEXENV source is selected by the serialized MTOB state.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NPM_MAX_TEXTURE_UNITS 3
#define NPM_TEXENV_STAGE_COUNT 6
#define NPM_MATERIAL_LUT_COUNT 6
#define NPM_MAX_FRAGMENT_LIGHTS 4

typedef struct NpmMaterialSet NpmMaterialSet;
typedef struct NpmMaterial NpmMaterial;

typedef struct {
    double x, y;
} NpmVec2;

typedef struct {
    double x, y, z;
} NpmVec3;

typedef struct {
    double r, g, b, a;
} NpmColor;

typedef struct {
    int width;
    int height;
    const uint8_t *rgba;
} NpmImageView;

typedef struct {
    /*
     * Position and the context's camera/lights must share one space.  The
     * shop presets use the original CGFX scene/model space (before the CFL
     * attachment scale); rasterizers should interpolate that local position
     * separately from screen/world placement.
     */
    NpmVec3 position;
    NpmVec3 normal;
    NpmVec3 tangent;
    NpmVec2 uv[3];
    NpmColor vertex_color;
    NpmColor primary_color;
    int has_tangent;
    int has_vertex_color;
    int has_primary_color; /* interpolated result of npm_vertex_primary_color */
    int has_lod;
    double lod;
} NpmFragmentInput;

typedef struct {
    int directional;
    int two_sided_diffuse;
    NpmVec3 position;
    NpmVec3 direction;
    NpmColor ambient;
    NpmColor diffuse;
    NpmColor specular0;
    NpmColor specular1;
} NpmFragmentLight;

typedef struct {
    uint32_t catalog_color; /* 0xRRGGBB, runtime Constant1 / mtOpa. */
    uint32_t skin_color;    /* 0xRRGGBB, runtime Constant0 / mtSkin. */
    NpmVec3 camera_position;

    NpmColor scene_ambient;
    NpmColor hemi_ground;
    NpmColor hemi_sky;
    NpmVec3 hemi_direction;
    double hemi_lerp;
    int hemisphere_enabled;

    int light_count;
    NpmFragmentLight lights[NPM_MAX_FRAGMENT_LIGHTS];
} NpmShaderContext;

typedef struct {
    NpmColor color;
    NpmColor primary_color;
    NpmColor fragment_primary;
    NpmColor fragment_secondary;
    NpmColor texture_color[NPM_MAX_TEXTURE_UNITS];
    NpmVec2 transformed_uv[NPM_MAX_TEXTURE_UNITS];
    int discarded;
} NpmFragmentOutput;

typedef struct {
    uint32_t model_count;
    uint32_t texture_count;
    uint32_t material_count;
    uint32_t mesh_count;
    uint32_t bound_texture_units;
    uint32_t decoded_textures;
    uint32_t missing_textures;
    uint32_t lut_count;
    uint32_t lut_sampler_count;
    uint32_t unresolved_lut_references;
    uint32_t invalid_material_references;
    uint32_t shade_calls;
    uint32_t discarded_fragments;
} NpmDiagnostics;

/* Lifecycle and deterministic sidecar loading. */
void npm_material_set_init(NpmMaterialSet *set);
void npm_material_set_free(NpmMaterialSet *set);
NpmMaterialSet *npm_material_set_create(void);
void npm_material_set_destroy(NpmMaterialSet *set);

int npm_load_material_sidecar(
    NpmMaterialSet *set, const char *path, char *error, size_t error_size);
int npm_load_lut_sidecar(
    NpmMaterialSet *set, const char *path, char *error, size_t error_size);
int npm_verify_lut_source(
    const NpmMaterialSet *set, const uint8_t *cgfx, size_t cgfx_size,
    char *error, size_t error_size);

/*
 * Decode all TXOBs from the matching CGFX source.  When this module is
 * included after tomodachi_renderer_c/renderer.c, define
 * NPM_HAVE_TOMODACHI_RENDERER before including native_pica_material.c to use
 * its format-complete CGFX decoder.  Source length and SHA-256 are verified.
 */
int npm_bind_cgfx_textures(
    NpmMaterialSet *set, const uint8_t *cgfx, size_t cgfx_size,
    char *error, size_t error_size);

/* An adapter may instead attach already-decoded texture pixels by index. */
int npm_set_texture_image(
    NpmMaterialSet *set, uint32_t texture_index, NpmImageView image,
    int copy_pixels, char *error, size_t error_size);

/* Ordered CMDL lookups; material_index is local to model_index. */
const NpmMaterial *npm_material_for_index(
    const NpmMaterialSet *set, uint32_t model_index, uint32_t material_index);
const NpmMaterial *npm_material_for_mesh(
    const NpmMaterialSet *set, uint32_t model_index, uint32_t mesh_index);
const char *npm_material_name(const NpmMaterial *material);
int npm_material_cull_mode(const NpmMaterial *material);
uint32_t npm_material_depth_state(const NpmMaterial *material);
uint32_t npm_material_blend_state(const NpmMaterial *material);
int npm_material_depth_write_enabled(const NpmMaterial *material);
int npm_material_cull_triangle(const NpmMaterial *material, double signed_area);

/* Source preview-scene presets (obj_sHeadwear / obj_sCostume). */
void npm_shader_context_shop_headwear(
    NpmShaderContext *context, uint32_t catalog_color, uint32_t skin_color);
void npm_shader_context_shop_body(
    NpmShaderContext *context, uint32_t catalog_color, uint32_t skin_color);

/* Vertex primary color and full fragment/TEXENV evaluation. */
NpmColor npm_vertex_primary_color(
    const NpmMaterial *material, const NpmShaderContext *context,
    NpmVec3 normal, NpmColor vertex_color, int has_vertex_color);
int npm_shade_fragment(
    NpmMaterialSet *set, const NpmMaterial *material,
    const NpmShaderContext *context, const NpmFragmentInput *input,
    NpmFragmentOutput *output);

/* Render-state helpers used by a software rasterizer. */
int npm_alpha_test_pass(const NpmMaterial *material, double alpha);
int npm_depth_test_pass(const NpmMaterial *material, double incoming, double stored);
void npm_blend_pixel(
    const NpmMaterial *material, NpmColor source, NpmColor destination,
    NpmColor *result);

const NpmDiagnostics *npm_get_diagnostics(const NpmMaterialSet *set);
void npm_reset_runtime_diagnostics(NpmMaterialSet *set);
void npm_print_diagnostics(const NpmMaterialSet *set, FILE *stream);
const char *npm_shader_contract_id(void);

#ifdef __cplusplus
}
#endif

#endif /* TOMODACHI_NATIVE_PICA_MATERIAL_H */
