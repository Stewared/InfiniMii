/*
 * Deterministic physical-headwear renderer.
 *
 * CMake generates render_body_model_embedded.c from the already-audited body
 * driver.  That gives this executable the same CFL portrait parser, body wait
 * pose/attachment, and software depth buffer without maintaining a second
 * copy.  The generated include only renames its command-line entry point and
 * adds a narrowly scoped body draw callback; the source body driver is never
 * modified.
 *
 * Headwear and the fixed preview body are shaded through native_pica_material:
 * ordered CMDL material assignment, all three serialized texture units and UV
 * sets, PICA samplers, fragment lighting/LUTs, TEXENV, alpha/depth/cull, and
 * blend state all come from the emitted SPICA sidecars.  A missing sidecar or
 * unresolved texture is a hard error -- an exhaustive export must never fall
 * back to filename heuristics or the reference renderer's preview shader.
 */

#include "render_body_model_embedded.c"

#define NPM_HAVE_TOMODACHI_RENDERER 1
#include "native_pica_material.c"

typedef struct {
    const char *headwear_model_path;
    const char *head_model_path;
    uint32_t catalog_color;
    uint32_t skin_color;
    Buffer headwear_bytes;
    CgfxModel headwear_model;
    CgfxModel head_model;
    NpmMaterialSet *materials;
    NpmShaderContext shader;
    Image object_mask;
    int hook_called;
    int hook_ok;
    unsigned long long submitted_triangles;
    unsigned long long shaded_fragments;
    unsigned long long discarded_fragments;
} HeadwearDriverState;

typedef struct {
    NpmMaterialSet *materials;
    NpmShaderContext shader;
    int draw_ok;
    unsigned long long submitted_triangles;
    unsigned long long shaded_fragments;
    unsigned long long discarded_fragments;
} BodyDriverState;

static HeadwearDriverState headwear_driver;
static BodyDriverState body_driver;

static const char *headwear_arg_value(const char *text, const char *prefix) {
    size_t length = strlen(prefix);
    return strncmp(text, prefix, length) == 0 ? text + length : NULL;
}

static int headwear_parse_rgb24(const char *text, uint32_t *out) {
    char *end = NULL;
    unsigned long value;
    if (!text || !out) return 0;
    if (*text == '#') text++;
    if (strlen(text) != 6u) return 0;
    errno = 0;
    value = strtoul(text, &end, 16);
    if (errno != 0 || !end || *end != '\0' || value > 0xfffffful) return 0;
    *out = (uint32_t)value;
    return 1;
}

static NpmVec3 headwear_npm_vec3(Vec3 value) {
    NpmVec3 result;
    result.x = value.x;
    result.y = value.y;
    result.z = value.z;
    return result;
}

static NpmVec2 headwear_npm_vec2(Vec2 value) {
    NpmVec2 result;
    result.x = value.x;
    result.y = value.y;
    return result;
}

static NpmVec3 headwear_npm_normalize(NpmVec3 value) {
    double length = sqrt(value.x * value.x + value.y * value.y + value.z * value.z);
    if (length <= 1.0e-20) {
        value.x = 0.0;
        value.y = 0.0;
        value.z = 1.0;
    } else {
        value.x /= length;
        value.y /= length;
        value.z /= length;
    }
    return value;
}

static NpmColor headwear_vertex_color(uint32_t packed) {
    NpmColor result;
    result.r = ((packed >> 24) & 0xffu) / 255.0;
    result.g = ((packed >> 16) & 0xffu) / 255.0;
    result.b = ((packed >> 8) & 0xffu) / 255.0;
    result.a = (packed & 0xffu) / 255.0;
    return result;
}

static NpmColor headwear_lerp_color(
    NpmColor a, NpmColor b, NpmColor c, double wa, double wb, double wc) {
    NpmColor result;
    result.r = a.r * wa + b.r * wb + c.r * wc;
    result.g = a.g * wa + b.g * wb + c.g * wc;
    result.b = a.b * wa + b.b * wb + c.b * wc;
    result.a = a.a * wa + b.a * wb + c.a * wc;
    return result;
}

static NpmVec3 headwear_lerp_vec3(
    NpmVec3 a, NpmVec3 b, NpmVec3 c, double wa, double wb, double wc) {
    NpmVec3 result;
    result.x = a.x * wa + b.x * wb + c.x * wc;
    result.y = a.y * wa + b.y * wb + c.y * wc;
    result.z = a.z * wa + b.z * wb + c.z * wc;
    return result;
}

static NpmVec2 headwear_lerp_vec2(
    NpmVec2 a, NpmVec2 b, NpmVec2 c, double wa, double wb, double wc) {
    NpmVec2 result;
    result.x = a.x * wa + b.x * wb + c.x * wc;
    result.y = a.y * wa + b.y * wb + c.y * wc;
    return result;
}

static NpmColor headwear_pixel_to_color(const uint8_t pixel[4]) {
    NpmColor result;
    result.r = pixel[0] / 255.0;
    result.g = pixel[1] / 255.0;
    result.b = pixel[2] / 255.0;
    result.a = pixel[3] / 255.0;
    return result;
}

static uint8_t headwear_color_channel(double value) {
    return (uint8_t)clamp_int((int)lrint(clamp_unit(value) * 255.0), 0, 255);
}

static void headwear_color_to_pixel(NpmColor color, uint8_t pixel[4]) {
    pixel[0] = headwear_color_channel(color.r);
    pixel[1] = headwear_color_channel(color.g);
    pixel[2] = headwear_color_channel(color.b);
    pixel[3] = headwear_color_channel(color.a);
}

static void headwear_draw_native_triangle(
    MeshCanvas *canvas,
    NpmMaterialSet *set,
    const NpmMaterial *material,
    const NpmShaderContext *context,
    Vec3 world[3],
    NpmVec3 local[3],
    NpmVec3 normal[3],
    NpmVec3 tangent[3],
    NpmVec2 uv[3][3],
    NpmColor vertex_color[3],
    NpmColor primary_color[3],
    int has_tangent,
    int has_vertex_color,
    unsigned long long *shaded_fragments,
    unsigned long long *discarded_fragments) {
    double sx[3];
    double sy[3];
    double reciprocal_w[3];
    double area;
    int min_x;
    int max_x;
    int min_y;
    int max_y;
    int x;
    int y;
    int i;

    for (i = 0; i < 3; i++) {
        if (!mesh_canvas_project(canvas, world[i],
                &sx[i], &sy[i], &reciprocal_w[i])) return;
    }
    area = edge_function(sx[0], sy[0], sx[1], sy[1], sx[2], sy[2]);
    if (fabs(area) < 0.0001 || npm_material_cull_triangle(material, area)) return;

    min_x = clamp_int((int)floor(fmin(sx[0], fmin(sx[1], sx[2]))),
        0, canvas->image->width - 1);
    max_x = clamp_int((int)ceil(fmax(sx[0], fmax(sx[1], sx[2]))),
        0, canvas->image->width - 1);
    min_y = clamp_int((int)floor(fmin(sy[0], fmin(sy[1], sy[2]))),
        0, canvas->image->height - 1);
    max_y = clamp_int((int)ceil(fmax(sy[0], fmax(sy[1], sy[2]))),
        0, canvas->image->height - 1);

    for (y = min_y; y <= max_y; y++) {
        for (x = min_x; x <= max_x; x++) {
            double px = x + 0.5;
            double py = y + 0.5;
            double w0 = edge_function(sx[1], sy[1], sx[2], sy[2], px, py) / area;
            double w1 = edge_function(sx[2], sy[2], sx[0], sy[0], px, py) / area;
            double w2 = edge_function(sx[0], sy[0], sx[1], sy[1], px, py) / area;
            double z;
            double stored;
            size_t dst;
            NpmFragmentInput input;
            NpmFragmentOutput output;
            NpmColor destination;
            NpmColor blended;
            uint8_t result_pixel[4];

            if (w0 < -0.0001 || w1 < -0.0001 || w2 < -0.0001) continue;
            if (!mesh_canvas_correct_barycentrics(canvas,
                    reciprocal_w[0], reciprocal_w[1], reciprocal_w[2],
                    &w0, &w1, &w2)) continue;
            z = world[0].z * w0 + world[1].z * w1 + world[2].z * w2;
            dst = (size_t)y * (size_t)canvas->image->width + (size_t)x;

            /* The shared CFL rasterizer stores the greatest world Z as the
               frontmost sample.  Negating both values maps that convention
               onto PICA's ordinary Less/LessEqual depth functions. */
            stored = canvas->depth ? canvas->depth[dst] : -1.0e30;
            if (canvas->depth && !npm_depth_test_pass(material, -z, -stored)) continue;

            memset(&input, 0, sizeof(input));
            memset(&output, 0, sizeof(output));
            input.position = headwear_lerp_vec3(local[0], local[1], local[2], w0, w1, w2);
            input.normal = headwear_npm_normalize(
                headwear_lerp_vec3(normal[0], normal[1], normal[2], w0, w1, w2));
            input.tangent = headwear_npm_normalize(
                headwear_lerp_vec3(tangent[0], tangent[1], tangent[2], w0, w1, w2));
            for (i = 0; i < 3; i++) {
                input.uv[i] = headwear_lerp_vec2(uv[0][i], uv[1][i], uv[2][i], w0, w1, w2);
            }
            input.vertex_color = headwear_lerp_color(
                vertex_color[0], vertex_color[1], vertex_color[2], w0, w1, w2);
            input.primary_color = headwear_lerp_color(
                primary_color[0], primary_color[1], primary_color[2], w0, w1, w2);
            input.has_tangent = has_tangent;
            input.has_vertex_color = has_vertex_color;
            input.has_primary_color = 1;

            if (shaded_fragments) (*shaded_fragments)++;
            if (!npm_shade_fragment(set, material, context, &input, &output) ||
                output.discarded || !npm_alpha_test_pass(material, output.color.a)) {
                if (discarded_fragments) (*discarded_fragments)++;
                continue;
            }

            destination = headwear_pixel_to_color(canvas->image->rgba + dst * 4u);
            npm_blend_pixel(material, output.color, destination, &blended);
            headwear_color_to_pixel(blended, result_pixel);
            memcpy(canvas->image->rgba + dst * 4u, result_pixel, 4u);
            if (set == headwear_driver.materials && headwear_driver.object_mask.rgba &&
                x < headwear_driver.object_mask.width && y < headwear_driver.object_mask.height) {
                uint8_t *mask = headwear_driver.object_mask.rgba + dst * 4u;
                mask[0] = mask[1] = mask[2] = mask[3] = 255;
            }
            if (canvas->depth && npm_material_depth_write_enabled(material)) {
                canvas->depth[dst] = z;
            }
        }
    }
}

static int headwear_draw_native_model(
    MeshCanvas *canvas,
    const CgfxModel *model,
    const ShapeTransform *transform,
    int reverse_winding,
    NpmMaterialSet *set,
    const NpmShaderContext *context,
    unsigned long long *submitted_triangles,
    unsigned long long *shaded_fragments,
    unsigned long long *discarded_fragments) {
    int mesh_index;
    if (!canvas || !canvas->image || !model || !set || !context ||
        !model->meshes || model->mesh_count <= 0) {
        return 0;
    }

    for (mesh_index = 0; mesh_index < model->mesh_count; mesh_index++) {
        const CgfxMesh *mesh = &model->meshes[mesh_index];
        const NpmMaterial *material = npm_material_for_mesh(set, 0u, (uint32_t)mesh_index);
        int triangle;
        if (!material) {
            fprintf(stderr, "No serialized material for mesh %d.\n", mesh_index);
            return 0;
        }
        if (!mesh->vertices || !mesh->indices || mesh->vertex_count <= 0) continue;

        for (triangle = 0; triangle + 2 < mesh->index_count; triangle += 3) {
            uint32_t index[3];
            Vec3 world[3];
            NpmVec3 local[3];
            NpmVec3 normal[3];
            NpmVec3 tangent[3];
            NpmVec2 uv[3][3];
            NpmColor vertex[3];
            NpmColor primary[3];
            int corner;
            int set_index;
            index[0] = mesh->indices[triangle + 0];
            index[1] = mesh->indices[triangle + 1];
            index[2] = mesh->indices[triangle + 2];
            if (reverse_winding) {
                uint32_t swap = index[1];
                index[1] = index[2];
                index[2] = swap;
            }
            if (index[0] >= (uint32_t)mesh->vertex_count ||
                index[1] >= (uint32_t)mesh->vertex_count ||
                index[2] >= (uint32_t)mesh->vertex_count) {
                continue;
            }

            for (corner = 0; corner < 3; corner++) {
                Vec3 local_position = mesh->vertices[index[corner]];
                Vec3 transformed_normal = transform_normal(
                    cgfx_normal_at(mesh, (int)index[corner]), transform);
                Vec3 transformed_tangent = transform_normal(
                    cgfx_tangent_at(mesh, (int)index[corner]), transform);
                world[corner] = transform_point(local_position, transform);
                local[corner] = headwear_npm_vec3(local_position);
                normal[corner] = headwear_npm_normalize(headwear_npm_vec3(transformed_normal));
                tangent[corner] = headwear_npm_normalize(headwear_npm_vec3(transformed_tangent));
                for (set_index = 0; set_index < 3; set_index++) {
                    uv[corner][set_index] = headwear_npm_vec2(
                        cgfx_uv_at_set(mesh, (int)index[corner], set_index));
                }
                vertex[corner] = headwear_vertex_color(cgfx_color_at(mesh, (int)index[corner]));
                primary[corner] = npm_vertex_primary_color(material, context,
                    normal[corner], vertex[corner], mesh->has_colors);
            }

            if (submitted_triangles) (*submitted_triangles)++;
            headwear_draw_native_triangle(canvas, set, material, context,
                world, local, normal, tangent, uv, vertex, primary,
                mesh->has_tangents, mesh->has_colors,
                shaded_fragments, discarded_fragments);
        }
    }
    return 1;
}

/* This callback is injected into the generated body wrapper's existing
   draw_attached_physical_body path.  The wrapper still owns model loading,
   bodyCmWait00 skinning, neck attachment, and ShapeTransform calculation. */
static void headwear_native_body_draw_callback(
    MeshCanvas *canvas, const CgfxModel *model, const ShapeTransform *transform,
    uint32_t fallback_color, int use_depth, int write_depth, int blend_mode,
    int image_mode, int cull_back, int material_type, uint32_t skin_color) {
    (void)fallback_color;
    (void)use_depth;
    (void)write_depth;
    (void)blend_mode;
    (void)image_mode;
    (void)cull_back;
    (void)material_type;
    (void)skin_color;
    body_driver.draw_ok = headwear_draw_native_model(canvas, model, transform, 0,
        body_driver.materials, &body_driver.shader,
        &body_driver.submitted_triangles,
        &body_driver.shaded_fragments,
        &body_driver.discarded_fragments);
}

static int headwear_direct_draw_hook(
    MeshCanvas *canvas, const MiiFaceParams *params,
    const CflShape *faceline_shape, const CflPartsTransform *parts,
    const HeadwearMetadata *metadata, int metadata_variant,
    const TomodachiHeadwearItemInfo *headwear_info) {
    const CgfxModel *model = &headwear_driver.headwear_model;
    ShapeTransform transform;
    ShapeTransform mirror_transform;
    const double scale = 100.0;
    Vec3 anchor_rotation = { 0.0, 0.0, 0.0 };
    Vec3 variant_rotation = { 0.0, 0.0, 0.0 };
    Vec3 variant_translation = { 0.0, 0.0, 0.0 };
    Vec3 attachment_translation = { 0.0, 0.0, 0.0 };
    double anchor_matrix[12];
    double local_matrix[12];
    int animation_index;
    int anchor_index = -1;
    int draw_mirrored_pair = 0;
    const double *variant_offset = NULL;

    (void)faceline_shape;
    (void)headwear_info;
    headwear_driver.hook_called = 1;
    headwear_driver.hook_ok = 0;
    if (!bounds_are_valid(model->min, model->max)) return 0;
    if (metadata && metadata_variant >= 0 && metadata_variant < 16 &&
        metadata->variant_has_offset[metadata_variant]) {
        variant_offset = metadata->variant_offset[metadata_variant];
    }

    /* HeadType selects only one of obj_mHeadwear's three visibility
       animations.  It does not select a spatial attachment branch. */
    animation_index = tomodachi_headwear_visibility_animation_index(
        metadata ? metadata->head_type : -1);
    if (animation_index < 0 || animation_index > 2) animation_index = 0;
    (void)animation_index;

    /* The accessory HeadType classes select the corresponding FFL hair-part
       transform.  Full hats, masks, and wigs are already authored in head
       space and use hatTranslate at their shared origin. */
    if (metadata) {
        switch (metadata->head_type) {
            case 1:
            case 10:
                anchor_index = 0; /* headFront */
                break;
            case 3:
                anchor_index = 1; /* headSide */
                break;
            case 2:
                anchor_index = 1; /* paired headSide */
                draw_mirrored_pair = 1;
                break;
            case 5:
            case 9:
                anchor_index = 2; /* headTop */
                break;
            default:
                break;
        }
    }
    if (anchor_index >= 0 && parts &&
        vec3_has_value(parts->hat_position[anchor_index])) {
        attachment_translation = parts->hat_position[anchor_index];
        anchor_rotation = tomodachi_cfl_headwear_rotation_to_render(
            parts->hat_angle[anchor_index]);
        /* HeadType 10 face pieces use the front anchor in the opposite local
           X-rotation convention from HeadType 1 forehead accessories. */
        if (metadata && metadata->head_type == 10) anchor_rotation.x = -anchor_rotation.x;
        if (params->hair_flipped) {
            attachment_translation.x = -attachment_translation.x;
            anchor_rotation.y = -anchor_rotation.y;
            anchor_rotation.z = -anchor_rotation.z;
        }
    } else if (parts) {
        attachment_translation = parts->hair;
    }

    /* The physical CGFX uses centimetre-like 0.01 units while CFL shape
       coordinates use the corresponding whole unit.  All headwear types
       share the head coordinate system; the attachment translation above is
       either hatTranslate or one of FFL's authored hair-part anchors. */
    if (variant_offset) {
        variant_translation.x = variant_offset[0];
        variant_translation.y = variant_offset[1];
        variant_translation.z = variant_offset[2];
        variant_rotation.x = variant_offset[3];
        variant_rotation.y = variant_offset[4];
        variant_rotation.z = variant_offset[5];
    }

    mtx34_make_srt(anchor_matrix, 1.0, 1.0, 1.0,
        anchor_rotation, attachment_translation);
    mtx34_make_srt(local_matrix, scale, scale, scale,
        variant_rotation, variant_translation);
    transform = shape_transform_identity();
    mtx34_mul(transform.matrix, anchor_matrix, local_matrix);
    transform.has_matrix = 1;

    headwear_driver.hook_ok = headwear_draw_native_model(canvas, model, &transform, 0,
        headwear_driver.materials, &headwear_driver.shader,
        &headwear_driver.submitted_triangles,
        &headwear_driver.shaded_fragments,
        &headwear_driver.discarded_fragments);
    if (headwear_driver.hook_ok && draw_mirrored_pair) {
        Vec3 mirror_anchor_rotation = {
            anchor_rotation.x, -anchor_rotation.y, -anchor_rotation.z
        };
        Vec3 mirror_attachment_translation = {
            -attachment_translation.x,
            attachment_translation.y,
            attachment_translation.z
        };
        Vec3 mirror_variant_rotation = {
            variant_rotation.x, -variant_rotation.y, -variant_rotation.z
        };
        Vec3 mirror_variant_translation = {
            -variant_translation.x,
            variant_translation.y,
            variant_translation.z
        };
        mirror_transform = shape_transform_identity();
        mtx34_make_srt(anchor_matrix, 1.0, 1.0, 1.0,
            mirror_anchor_rotation, mirror_attachment_translation);
        mtx34_make_srt(local_matrix, -scale, scale, scale,
            mirror_variant_rotation, mirror_variant_translation);
        mtx34_mul(mirror_transform.matrix, anchor_matrix, local_matrix);
        mirror_transform.has_matrix = 1;
        headwear_driver.hook_ok = headwear_draw_native_model(canvas, model,
            &mirror_transform, 1, headwear_driver.materials, &headwear_driver.shader,
            &headwear_driver.submitted_triangles,
            &headwear_driver.shaded_fragments,
            &headwear_driver.discarded_fragments);
    }
    return headwear_driver.hook_ok;
}

static int headwear_load_material_set(
    NpmMaterialSet **out, const char *material_path, const char *lut_path,
    const uint8_t *cgfx, size_t cgfx_size,
    const uint8_t *lut_cgfx, size_t lut_cgfx_size, const char *label) {
    NpmMaterialSet *set;
    const NpmDiagnostics *diagnostics;
    char error[1024];
    if (!out || !material_path || !lut_path || !cgfx || cgfx_size == 0) return 0;
    *out = NULL;
    set = npm_material_set_create();
    if (!set) {
        fprintf(stderr, "%s: could not allocate native material set.\n", label);
        return 0;
    }
    error[0] = '\0';
    if (!npm_load_material_sidecar(set, material_path, error, sizeof(error))) {
        fprintf(stderr, "%s material sidecar: %s\n", label, error[0] ? error : "load failed");
        npm_material_set_destroy(set);
        return 0;
    }
    error[0] = '\0';
    if (!npm_load_lut_sidecar(set, lut_path, error, sizeof(error))) {
        fprintf(stderr, "%s LUT sidecar: %s\n", label, error[0] ? error : "load failed");
        npm_material_set_destroy(set);
        return 0;
    }
    error[0] = '\0';
    if (!npm_verify_lut_source(set, lut_cgfx, lut_cgfx_size, error, sizeof(error))) {
        fprintf(stderr, "%s LUT source: %s\n", label, error[0] ? error : "hash check failed");
        npm_material_set_destroy(set);
        return 0;
    }
    error[0] = '\0';
    if (!npm_bind_cgfx_textures(set, cgfx, cgfx_size, error, sizeof(error))) {
        fprintf(stderr, "%s texture binding: %s\n", label, error[0] ? error : "bind failed");
        npm_material_set_destroy(set);
        return 0;
    }
    diagnostics = npm_get_diagnostics(set);
    if (!diagnostics || diagnostics->missing_textures != 0u ||
        diagnostics->unresolved_lut_references != 0u ||
        diagnostics->invalid_material_references != 0u) {
        fprintf(stderr, "%s sidecar is incomplete.\n", label);
        npm_print_diagnostics(set, stderr);
        npm_material_set_destroy(set);
        return 0;
    }
    *out = set;
    return 1;
}

static int headwear_load_cgfx_model(
    const char *path, uint32_t fallback, Buffer *bytes, CgfxModel *model) {
    if (!path || !bytes || !model) return 0;
    memset(bytes, 0, sizeof(*bytes));
    memset(model, 0, sizeof(*model));
    if (!read_file(path, bytes)) return 0;
    if (!cgfx_load_model_from_buffer(bytes->data, bytes->size, fallback, model)) {
        free(bytes->data);
        memset(bytes, 0, sizeof(*bytes));
        return 0;
    }
    return 1;
}

static int headwear_render(
    const char *headwear_model_path,
    int headwear_item,
    uint32_t headwear_rgb,
    int metadata_variant,
    int headwear_type,
    const char *fixed_body_model_path,
    uint32_t fixed_body_rgb,
    const char *body_dir,
    const char *headwear_dir,
    const char *head_model_path,
    const char *headwear_wrapper_path,
    const char *cfl_path,
    const char *ffl_path,
    const char *material_sidecar_path,
    const char *body_material_sidecar_path,
    const char *lut_sidecar_path,
    const char *lut_source_path,
    const char *object_mask_out_path,
    const char *out_path,
    int width,
    int height,
    const MiiFaceParams *mii_params) {
    Buffer cfl_bytes;
    Buffer ffl_bytes;
    Buffer body_bytes;
    Buffer lut_bytes;
    CflResource resource;
    FflHighResource high_resource;
    MiiFaceParams params;
    HeadwearMetadata metadata;
    TomodachiHeadwearItemInfo item_info;
    Image portrait;
    int subject_hair_type;
    int resolved_metadata_variant;
    int ok = 0;

    memset(&cfl_bytes, 0, sizeof(cfl_bytes));
    memset(&ffl_bytes, 0, sizeof(ffl_bytes));
    memset(&body_bytes, 0, sizeof(body_bytes));
    memset(&lut_bytes, 0, sizeof(lut_bytes));
    memset(&resource, 0, sizeof(resource));
    memset(&high_resource, 0, sizeof(high_resource));
    memset(&portrait, 0, sizeof(portrait));
    memset(&headwear_driver, 0, sizeof(headwear_driver));
    memset(&body_driver, 0, sizeof(body_driver));
    headwear_metadata_init(&metadata);
    tomodachi_headwear_item_info_init(&item_info, headwear_item);

    if (!mii_params) goto cleanup;
    params = *mii_params;
    subject_hair_type = params.hair_type;
    if (width != 512 || (params.full_body ? height != 512 : height != 1088)) {
        fprintf(stderr, "The audited headwear viewport is fixed at 512x%s.\n",
            params.full_body ? "512 in full-body mode" : "1088 in portrait mode");
        goto cleanup;
    }
    if (!file_exists(headwear_wrapper_path)) {
        fprintf(stderr, "Missing obj_mHeadwear wrapper: %s\n", headwear_wrapper_path);
        goto cleanup;
    }
    if (!headwear_load_cgfx_model(headwear_model_path, headwear_rgb,
            &headwear_driver.headwear_bytes, &headwear_driver.headwear_model)) {
        fprintf(stderr, "Could not load physical headwear CGFX: %s\n", headwear_model_path);
        goto cleanup;
    }
    cgfx_apply_body_skinning(&headwear_driver.headwear_model);
    if (!cgfx_load_model_file(head_model_path, 0xf0c0a0u, &headwear_driver.head_model)) {
        fprintf(stderr, "Could not load obj_mHead reference: %s\n", head_model_path);
        goto cleanup;
    }
    if (!read_file(fixed_body_model_path, &body_bytes)) {
        fprintf(stderr, "Could not read fixed body CGFX: %s\n", fixed_body_model_path);
        goto cleanup;
    }
    if (!read_file(lut_source_path, &lut_bytes)) {
        fprintf(stderr, "Could not read common LUT CGFX: %s\n", lut_source_path);
        goto cleanup;
    }
    if (!headwear_load_material_set(&headwear_driver.materials,
            material_sidecar_path, lut_sidecar_path,
            headwear_driver.headwear_bytes.data, headwear_driver.headwear_bytes.size,
            lut_bytes.data, lut_bytes.size,
            "headwear")) {
        goto cleanup;
    }
    if (!headwear_load_material_set(&body_driver.materials,
            body_material_sidecar_path, lut_sidecar_path,
            body_bytes.data, body_bytes.size,
            lut_bytes.data, lut_bytes.size, "fixed body")) {
        goto cleanup;
    }

    params.draw_body = 1;
    params.draw_headwear = 1;
    params.headwear_index = headwear_item;
    params.headwear_color = 0;
    headwear_driver.catalog_color = headwear_rgb;
    headwear_driver.skin_color = mii_skin_color(params.face_color);
    npm_shader_context_shop_headwear(&headwear_driver.shader,
        headwear_rgb, headwear_driver.skin_color);
    npm_shader_context_shop_body(&body_driver.shader,
        fixed_body_rgb, headwear_driver.skin_color);

    if (!cgfx_read_named_metadata(headwear_driver.headwear_bytes.data,
            headwear_driver.headwear_bytes.size, &metadata)) {
        fprintf(stderr, "Physical headwear has no readable HeadType metadata: %s\n",
            headwear_model_path);
        goto cleanup;
    }
    if (metadata_variant >= 16 || metadata_variant < -1) {
        fprintf(stderr, "Invalid metadata variant: %d\n", metadata_variant);
        goto cleanup;
    }
    resolved_metadata_variant = headwear_metadata_select_variant(
        &metadata, subject_hair_type);
    if (metadata_variant != resolved_metadata_variant) {
        fprintf(stderr,
            "Metadata variant mismatch for subject hair %d: requested %d, resolved %d.\n",
            subject_hair_type, metadata_variant, resolved_metadata_variant);
        goto cleanup;
    }
    item_info.item_id = headwear_item;
    item_info.model_id = headwear_item;
    item_info.headwear_type = headwear_type;
    item_info.primary_color = headwear_rgb;
    item_info.has_primary_color = 1;

    if (!read_file(cfl_path, &cfl_bytes) ||
        !cfl_parse(&resource, cfl_bytes.data, cfl_bytes.size)) {
        fprintf(stderr, "Could not parse CFL resource: %s\n", cfl_path);
        goto cleanup;
    }
    if (!read_file(ffl_path, &ffl_bytes) ||
        !ffl_high_parse(&high_resource, ffl_bytes.data, ffl_bytes.size)) {
        fprintf(stderr, "Could not parse FFL high resource: %s\n", ffl_path);
        goto cleanup;
    }
    resource.high_textures = &high_resource;
    if (object_mask_out_path && !image_create(&headwear_driver.object_mask, width, height)) {
        goto cleanup;
    }

    /* Insert the native physical body at render_portrait's normal body draw
       point.  Its CGFX meshes, CFL face/hair, and physical headwear then use
       the same canvas and depth buffer instead of flattened layer compositing. */
    memset(&contextual_body_draw, 0, sizeof(contextual_body_draw));
    contextual_body_draw.model_path = fixed_body_model_path;
    contextual_body_draw.body_dir = body_dir;
    contextual_body_draw.requested_color = fixed_body_rgb;
    contextual_body_draw.skin_color = headwear_driver.skin_color;
    contextual_body_draw.use_authored_color = 0;
    tomodachi_direct_body_draw_hook = contextual_body_draw_hook;
    tomodachi_body_native_draw_hook = headwear_native_body_draw_callback;
    body_driver.draw_ok = 0;

    headwear_driver.headwear_model_path = headwear_model_path;
    headwear_driver.head_model_path = head_model_path;
    tomodachi_direct_headwear_metadata = metadata;
    tomodachi_direct_headwear_info = item_info;
    tomodachi_direct_headwear_variant = resolved_metadata_variant;
    tomodachi_direct_headwear_draw_hook = headwear_direct_draw_hook;
    tomodachi_direct_headwear_enabled = 1;
    /* Mask-class headwear replaces ordinary hair.  Variant selection above
       must use the subject's true hair, while the portrait draw uses FFL's
       empty-hair part (30) to prevent covered geometry poking through. */
    if (headwear_type == 2) params.hair_type = 30;
    if (!render_portrait_sized(&resource, &params, body_dir, headwear_dir,
            head_model_path, width, height, &portrait)) {
        fprintf(stderr, "Could not render fixed Mii portrait.\n");
        goto cleanup;
    }
    tomodachi_direct_body_draw_hook = NULL;
    tomodachi_body_native_draw_hook = NULL;
    if (!contextual_body_draw.called || !body_driver.draw_ok) {
        fprintf(stderr, "Native fixed-body material draw did not complete.\n");
        goto cleanup;
    }
    if (!headwear_driver.hook_called || !headwear_driver.hook_ok) {
        fprintf(stderr, "Direct physical headwear hook did not complete.\n");
        goto cleanup;
    }
    if (!write_image(out_path, &portrait)) {
        fprintf(stderr, "Could not write BMP: %s\n", out_path);
        goto cleanup;
    }
    if (object_mask_out_path &&
        !write_image(object_mask_out_path, &headwear_driver.object_mask)) {
        fprintf(stderr, "Could not write headwear object mask: %s\n", object_mask_out_path);
        goto cleanup;
    }

    fprintf(stderr,
        "native-pica=%s headwear-triangles=%llu body-triangles=%llu "
        "headwear-fragments=%llu body-fragments=%llu\n",
        npm_shader_contract_id(),
        headwear_driver.submitted_triangles,
        body_driver.submitted_triangles,
        headwear_driver.shaded_fragments,
        body_driver.shaded_fragments);
    fprintf(stderr, "composition=tomodachi-shared-body-head-depth-ffl-high-v3\n");
    fprintf(stderr, "projection=%s\n", params.full_body
        ? "ffl-whole-body-camera-fov15-height-v1"
        : "tomodachi-portrait-orthographic-v1");
    ok = 1;

cleanup:
    tomodachi_direct_body_draw_hook = NULL;
    tomodachi_body_native_draw_hook = NULL;
    tomodachi_direct_headwear_enabled = 0;
    tomodachi_direct_headwear_draw_hook = NULL;
    npm_material_set_destroy(body_driver.materials);
    npm_material_set_destroy(headwear_driver.materials);
    free(body_bytes.data);
    free(lut_bytes.data);
    cgfx_model_free(&headwear_driver.head_model);
    cgfx_model_free(&headwear_driver.headwear_model);
    free(headwear_driver.headwear_bytes.data);
    image_free(&portrait);
    image_free(&headwear_driver.object_mask);
    cfl_free(&resource);
    free(cfl_bytes.data);
    free(ffl_bytes.data);
    return ok;
}

static void headwear_usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s --headwear-model=headwear.cgfx --headwear-item=N "
        "--headwear-rgb=RRGGBB --headwear-metadata-variant=N "
        "--headwear-type=0|1|2 --fixed-body-model=body.cgfx "
        "--fixed-body-rgb=RRGGBB --body-dir=DIR --headwear-dir=DIR "
        "--head-model=obj_mHead.bin.dat --headwear-wrapper=obj_mHeadwear.bin.dat "
        "--cfl=CFL_Res.dat --ffl=FFLResHigh.dat --material-sidecar=headwear.materials.bin "
        "--body-material-sidecar=body.materials.bin "
        "--lut-sidecar=lutCommon.luts.bin --lut-source=env_lut_common.bin.dat "
        "[--object-mask-out=mask.bmp] --out=render.bmp "
        "--width=512 --height=1088 [--full-body --height=512] [--mii-*=N ...]\n",
        argv0);
}

int main(int argc, char **argv) {
    const char *headwear_model_path = NULL;
    const char *fixed_body_model_path = NULL;
    const char *body_dir = NULL;
    const char *headwear_dir = NULL;
    const char *head_model_path = NULL;
    const char *headwear_wrapper_path = NULL;
    const char *cfl_path = NULL;
    const char *ffl_path = NULL;
    const char *material_sidecar_path = NULL;
    const char *body_material_sidecar_path = NULL;
    const char *lut_sidecar_path = NULL;
    const char *lut_source_path = NULL;
    const char *object_mask_out_path = NULL;
    const char *out_path = NULL;
    uint32_t headwear_rgb = 0;
    uint32_t fixed_body_rgb = 0;
    int headwear_item = -1;
    int metadata_variant = -2;
    int headwear_type = -1;
    int width = 0;
    int height = 0;
    MiiFaceParams mii_params;
    int i;

    init_default_params(&mii_params);

    for (i = 1; i < argc; i++) {
        const char *value;
        if ((value = headwear_arg_value(argv[i], "--headwear-model="))) {
            headwear_model_path = value;
        } else if ((value = headwear_arg_value(argv[i], "--headwear-item="))) {
            headwear_item = atoi(value);
        } else if ((value = headwear_arg_value(argv[i], "--headwear-rgb="))) {
            if (!headwear_parse_rgb24(value, &headwear_rgb)) {
                fprintf(stderr, "Invalid headwear RGB: %s\n", value);
                return 2;
            }
        } else if ((value = headwear_arg_value(argv[i], "--headwear-metadata-variant="))) {
            metadata_variant = atoi(value);
        } else if ((value = headwear_arg_value(argv[i], "--headwear-type="))) {
            headwear_type = atoi(value);
        } else if ((value = headwear_arg_value(argv[i], "--fixed-body-model="))) {
            fixed_body_model_path = value;
        } else if ((value = headwear_arg_value(argv[i], "--fixed-body-rgb="))) {
            if (!headwear_parse_rgb24(value, &fixed_body_rgb)) {
                fprintf(stderr, "Invalid fixed body RGB: %s\n", value);
                return 2;
            }
        } else if ((value = headwear_arg_value(argv[i], "--body-dir="))) {
            body_dir = value;
        } else if ((value = headwear_arg_value(argv[i], "--headwear-dir="))) {
            headwear_dir = value;
        } else if ((value = headwear_arg_value(argv[i], "--head-model="))) {
            head_model_path = value;
        } else if ((value = headwear_arg_value(argv[i], "--headwear-wrapper="))) {
            headwear_wrapper_path = value;
        } else if ((value = headwear_arg_value(argv[i], "--cfl="))) {
            cfl_path = value;
        } else if ((value = headwear_arg_value(argv[i], "--ffl="))) {
            ffl_path = value;
        } else if ((value = headwear_arg_value(argv[i], "--material-sidecar="))) {
            material_sidecar_path = value;
        } else if ((value = headwear_arg_value(argv[i], "--body-material-sidecar="))) {
            body_material_sidecar_path = value;
        } else if ((value = headwear_arg_value(argv[i], "--lut-sidecar="))) {
            lut_sidecar_path = value;
        } else if ((value = headwear_arg_value(argv[i], "--lut-source="))) {
            lut_source_path = value;
        } else if ((value = headwear_arg_value(argv[i], "--object-mask-out="))) {
            object_mask_out_path = value;
        } else if ((value = headwear_arg_value(argv[i], "--out="))) {
            out_path = value;
        } else if ((value = headwear_arg_value(argv[i], "--width="))) {
            width = atoi(value);
        } else if ((value = headwear_arg_value(argv[i], "--height="))) {
            height = atoi(value);
        } else if (strcmp(argv[i], "--full-body") == 0) {
            mii_params.full_body = 1;
        } else if (mii_face_params_parse_prefixed_arg(&mii_params, argv[i])) {
            /* Parsed by the shared decomp-backed Mii profile parser. */
        } else {
            headwear_usage(argv[0]);
            return 2;
        }
    }

    if (!headwear_model_path || headwear_item < 0 || metadata_variant < -1 ||
        headwear_type < 0 || headwear_type > 2 || !fixed_body_model_path ||
        !body_dir || !headwear_dir || !head_model_path || !headwear_wrapper_path ||
        !cfl_path || !ffl_path || !material_sidecar_path || !body_material_sidecar_path ||
        !lut_sidecar_path || !lut_source_path || !out_path || width != 512 ||
        (mii_params.full_body ? height != 512 : height != 1088)) {
        headwear_usage(argv[0]);
        return 2;
    }

    return headwear_render(headwear_model_path, headwear_item, headwear_rgb,
        metadata_variant, headwear_type, fixed_body_model_path, fixed_body_rgb,
        body_dir, headwear_dir, head_model_path, headwear_wrapper_path, cfl_path, ffl_path,
        material_sidecar_path, body_material_sidecar_path, lut_sidecar_path,
        lut_source_path, object_mask_out_path, out_path, width, height,
        &mii_params) ? 0 : 1;
}
