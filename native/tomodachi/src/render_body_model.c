/*
 * Standalone, deterministic body-archive renderer.
 *
 * The base parser, CANM wait-pose sampler, skinning path, and rasterizer come
 * from the decomp-backed reference renderer.  Ordered materials, all texture
 * units and coordinate sets, samplers, fragment lights/LUTs, six PICA TEXENV
 * stages, and render state come from the same SPICA-derived sidecars and native
 * CPU shader used by the physical-headwear renderer.  Sidecar/source hashes
 * are mandatory so an exhaustive archive audit can never fall back to a
 * guessed binding or the reference preview's generic post-shader.
 */
#define main tomodachi_reference_renderer_main
#define draw_cgfx_model tomodachi_reference_draw_cgfx_model
#include "renderer.c"
#undef draw_cgfx_model
#undef main

#ifdef TOMODACHI_BODY_STANDALONE_NATIVE
#define NPM_HAVE_TOMODACHI_RENDERER 1
#include "native_pica_material.c"

typedef struct {
    const CgfxModel *active_model;
    NpmMaterialSet *materials;
    NpmShaderContext shader;
    int draw_ok;
    int disable_material_culling;
    unsigned long long submitted_triangles;
    unsigned long long shaded_fragments;
    unsigned long long discarded_fragments;
} BodyNativeDriverState;

static BodyNativeDriverState driver_native;
static const char *driver_material_sidecar_path;
static const char *driver_lut_sidecar_path;
static const char *driver_lut_source_path;

static NpmVec3 driver_npm_vec3(Vec3 value) {
    NpmVec3 result = { value.x, value.y, value.z };
    return result;
}

static NpmVec2 driver_npm_vec2(Vec2 value) {
    NpmVec2 result = { value.x, value.y };
    return result;
}

static NpmVec3 driver_npm_normalize(NpmVec3 value) {
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

static NpmColor driver_vertex_color(uint32_t packed) {
    NpmColor result;
    result.r = ((packed >> 24) & 0xffu) / 255.0;
    result.g = ((packed >> 16) & 0xffu) / 255.0;
    result.b = ((packed >> 8) & 0xffu) / 255.0;
    result.a = (packed & 0xffu) / 255.0;
    return result;
}

static NpmColor driver_lerp_color(
    NpmColor a, NpmColor b, NpmColor c, double wa, double wb, double wc) {
    NpmColor result;
    result.r = a.r * wa + b.r * wb + c.r * wc;
    result.g = a.g * wa + b.g * wb + c.g * wc;
    result.b = a.b * wa + b.b * wb + c.b * wc;
    result.a = a.a * wa + b.a * wb + c.a * wc;
    return result;
}

static NpmVec3 driver_lerp_vec3(
    NpmVec3 a, NpmVec3 b, NpmVec3 c, double wa, double wb, double wc) {
    NpmVec3 result;
    result.x = a.x * wa + b.x * wb + c.x * wc;
    result.y = a.y * wa + b.y * wb + c.y * wc;
    result.z = a.z * wa + b.z * wb + c.z * wc;
    return result;
}

static NpmVec2 driver_lerp_vec2(
    NpmVec2 a, NpmVec2 b, NpmVec2 c, double wa, double wb, double wc) {
    NpmVec2 result;
    result.x = a.x * wa + b.x * wb + c.x * wc;
    result.y = a.y * wa + b.y * wb + c.y * wc;
    return result;
}

static NpmColor driver_pixel_to_color(const uint8_t pixel[4]) {
    NpmColor result;
    result.r = pixel[0] / 255.0;
    result.g = pixel[1] / 255.0;
    result.b = pixel[2] / 255.0;
    result.a = pixel[3] / 255.0;
    return result;
}

static uint8_t driver_color_channel(double value) {
    return (uint8_t)clamp_int((int)lrint(clamp_unit(value) * 255.0), 0, 255);
}

static void driver_color_to_pixel(NpmColor color, uint8_t pixel[4]) {
    pixel[0] = driver_color_channel(color.r);
    pixel[1] = driver_color_channel(color.g);
    pixel[2] = driver_color_channel(color.b);
    pixel[3] = driver_color_channel(color.a);
}

static void driver_draw_native_triangle(
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
    if (fabs(area) < 0.0001 ||
        (!driver_native.disable_material_culling &&
         npm_material_cull_triangle(material, area))) {
        return;
    }

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
            stored = canvas->depth ? canvas->depth[dst] : -1.0e30;
            if (canvas->depth && !npm_depth_test_pass(material, -z, -stored)) continue;

            memset(&input, 0, sizeof(input));
            memset(&output, 0, sizeof(output));
            input.position = driver_lerp_vec3(local[0], local[1], local[2], w0, w1, w2);
            input.normal = driver_npm_normalize(
                driver_lerp_vec3(normal[0], normal[1], normal[2], w0, w1, w2));
            input.tangent = driver_npm_normalize(
                driver_lerp_vec3(tangent[0], tangent[1], tangent[2], w0, w1, w2));
            for (i = 0; i < 3; i++) {
                input.uv[i] = driver_lerp_vec2(uv[0][i], uv[1][i], uv[2][i],
                    w0, w1, w2);
            }
            input.vertex_color = driver_lerp_color(
                vertex_color[0], vertex_color[1], vertex_color[2], w0, w1, w2);
            input.primary_color = driver_lerp_color(
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

            destination = driver_pixel_to_color(canvas->image->rgba + dst * 4u);
            npm_blend_pixel(material, output.color, destination, &blended);
            driver_color_to_pixel(blended, result_pixel);
            memcpy(canvas->image->rgba + dst * 4u, result_pixel, 4u);
            if (canvas->depth && npm_material_depth_write_enabled(material)) {
                canvas->depth[dst] = z;
            }
        }
    }
}

static int driver_draw_native_model(
    MeshCanvas *canvas, const CgfxModel *model, const ShapeTransform *transform,
    NpmMaterialSet *set, const NpmShaderContext *context,
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
        const NpmMaterial *material = npm_material_for_mesh(
            set, 0u, (uint32_t)mesh_index);
        int triangle;
        if (!material) {
            fprintf(stderr, "No serialized material for body mesh %d.\n", mesh_index);
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
                local[corner] = driver_npm_vec3(local_position);
                normal[corner] = driver_npm_normalize(driver_npm_vec3(transformed_normal));
                tangent[corner] = driver_npm_normalize(driver_npm_vec3(transformed_tangent));
                for (set_index = 0; set_index < 3; set_index++) {
                    uv[corner][set_index] = driver_npm_vec2(
                        cgfx_uv_at_set(mesh, (int)index[corner], set_index));
                }
                vertex[corner] = driver_vertex_color(
                    cgfx_color_at(mesh, (int)index[corner]));
                primary[corner] = npm_vertex_primary_color(material, context,
                    normal[corner], vertex[corner], mesh->has_colors);
            }

            if (submitted_triangles) (*submitted_triangles)++;
            driver_draw_native_triangle(canvas, set, material, context,
                world, local, normal, tangent, uv, vertex, primary,
                mesh->has_tangents, mesh->has_colors,
                shaded_fragments, discarded_fragments);
        }
    }
    return 1;
}
#endif

/* Keep this signature and first local declaration stable.  The headwear build
   injects its fixed-body callback at this exact boundary while compiling this
   file without TOMODACHI_BODY_STANDALONE_NATIVE. */
static void draw_cgfx_model(MeshCanvas *canvas, const CgfxModel *model,
    const ShapeTransform *transform, uint32_t fallback_color,
    int use_depth, int write_depth, int blend_mode, int image_mode, int cull_back,
    int material_type, uint32_t skin_color) {
    int mesh_index;
#ifdef TOMODACHI_BODY_STANDALONE_NATIVE
    const NpmMaterial *first_material;
    uint32_t shader_skin_color = skin_color;
    (void)mesh_index;
    (void)use_depth;
    (void)write_depth;
    (void)blend_mode;
    (void)image_mode;
    (void)material_type;
    if (!model || model != driver_native.active_model || !driver_native.materials) {
        fprintf(stderr, "Native body material set does not match the requested model.\n");
        driver_native.draw_ok = 0;
        return;
    }
    /* The standalone diagnostic top camera is outside the authored shop
       scene.  Its existing contract explicitly disables culling so the
       horizontal bodyShadow helper remains visible from above. */
    driver_native.disable_material_culling = cull_back == 0;
    first_material = npm_material_for_mesh(driver_native.materials, 0u, 0u);
    if (first_material && strcmp(npm_material_name(first_material), "mtBodyShadow") == 0) {
        /* mtBodyShadow's Constant0 is authored black; unlike wearable mtBd
           materials it is not a Mii-skin runtime uniform. */
        shader_skin_color = 0x000000u;
    }
    npm_shader_context_shop_body(&driver_native.shader,
        fallback_color, shader_skin_color);
    driver_native.draw_ok = driver_draw_native_model(canvas, model, transform,
        driver_native.materials, &driver_native.shader,
        &driver_native.submitted_triangles,
        &driver_native.shaded_fragments,
        &driver_native.discarded_fragments);
#else
    (void)mesh_index;
    tomodachi_reference_draw_cgfx_model(canvas, model, transform, fallback_color,
        use_depth, write_depth, blend_mode, image_mode, cull_back,
        material_type, skin_color);
#endif
}

#ifdef TOMODACHI_BODY_STANDALONE_NATIVE
static void driver_release_native_materials(void) {
    npm_material_set_destroy(driver_native.materials);
    driver_native.materials = NULL;
    driver_native.active_model = NULL;
    driver_native.draw_ok = 0;
}

static int driver_load_model_file(const char *path, uint32_t fallback_color,
    CgfxModel *model) {
    Buffer model_bytes;
    Buffer lut_bytes;
    NpmMaterialSet *materials = NULL;
    const NpmDiagnostics *diagnostics;
    char error[1024];
    int ok = 0;

    memset(&model_bytes, 0, sizeof(model_bytes));
    memset(&lut_bytes, 0, sizeof(lut_bytes));
    driver_release_native_materials();
    memset(model, 0, sizeof(*model));
    if (!driver_material_sidecar_path || !driver_lut_sidecar_path ||
        !driver_lut_source_path) {
        fprintf(stderr, "Native material, LUT sidecar, and LUT source are required.\n");
        goto cleanup;
    }
    if (!read_file(path, &model_bytes)) {
        fprintf(stderr, "Could not read body CGFX: %s\n", path);
        goto cleanup;
    }
    if (!cgfx_load_model_from_buffer(model_bytes.data, model_bytes.size,
            fallback_color, model)) {
        fprintf(stderr, "Could not parse body CGFX: %s\n", path);
        goto cleanup;
    }

    materials = npm_material_set_create();
    if (!materials) {
        fprintf(stderr, "Could not allocate native body material set.\n");
        goto cleanup;
    }
    error[0] = '\0';
    if (!npm_load_material_sidecar(materials, driver_material_sidecar_path,
            error, sizeof(error))) {
        fprintf(stderr, "Body material sidecar: %s\n",
            error[0] ? error : "load failed");
        goto cleanup;
    }
    error[0] = '\0';
    if (!npm_load_lut_sidecar(materials, driver_lut_sidecar_path,
            error, sizeof(error))) {
        fprintf(stderr, "Body LUT sidecar: %s\n",
            error[0] ? error : "load failed");
        goto cleanup;
    }
    if (!read_file(driver_lut_source_path, &lut_bytes)) {
        fprintf(stderr, "Could not read LUT source CGFX: %s\n", driver_lut_source_path);
        goto cleanup;
    }
    error[0] = '\0';
    if (!npm_verify_lut_source(materials, lut_bytes.data, lut_bytes.size,
            error, sizeof(error))) {
        fprintf(stderr, "Body LUT source: %s\n",
            error[0] ? error : "verification failed");
        goto cleanup;
    }
    error[0] = '\0';
    if (!npm_bind_cgfx_textures(materials, model_bytes.data, model_bytes.size,
            error, sizeof(error))) {
        fprintf(stderr, "Body texture binding: %s\n",
            error[0] ? error : "bind failed");
        goto cleanup;
    }
    diagnostics = npm_get_diagnostics(materials);
    if (!diagnostics || diagnostics->missing_textures != 0u ||
        diagnostics->unresolved_lut_references != 0u ||
        diagnostics->invalid_material_references != 0u) {
        fprintf(stderr, "Body native material sidecar is incomplete.\n");
        npm_print_diagnostics(materials, stderr);
        goto cleanup;
    }

    driver_native.materials = materials;
    driver_native.active_model = model;
    driver_native.draw_ok = 0;
    driver_native.submitted_triangles = 0;
    driver_native.shaded_fragments = 0;
    driver_native.discarded_fragments = 0;
    materials = NULL;
    ok = 1;

cleanup:
    npm_material_set_destroy(materials);
    free(lut_bytes.data);
    free(model_bytes.data);
    if (!ok) {
        cgfx_model_free(model);
        memset(model, 0, sizeof(*model));
    }
    return ok;
}
#else
static int driver_load_model_file(const char *path, uint32_t fallback_color,
    CgfxModel *model) {
    return cgfx_load_model_file(path, fallback_color, model);
}
#endif

static const char *driver_arg_value(const char *text, const char *prefix) {
    size_t length = strlen(prefix);
    return strncmp(text, prefix, length) == 0 ? text + length : NULL;
}

static int parse_rgb24(const char *text, uint32_t *out) {
    char *end = NULL;
    unsigned long value;
    if (!text || !out) return 0;
    if (text[0] == '#') text++;
    value = strtoul(text, &end, 16);
    if (!end || *end != '\0' || value > 0xfffffful) return 0;
    *out = (uint32_t)value;
    return 1;
}

static uint32_t material_constant1_rgb(const CgfxModel *model, uint32_t fallback) {
    const CgfxMaterial *material;
    double r;
    double g;
    double b;
    if (!model) return fallback;
    material = model->material_count > 0 && model->materials ?
        &model->materials[0] : &model->material;
    r = clamp_unit(material->constant_colors[1][0]);
    g = clamp_unit(material->constant_colors[1][1]);
    b = clamp_unit(material->constant_colors[1][2]);
    return ((uint32_t)lrint(r * 255.0) << 16) |
        ((uint32_t)lrint(g * 255.0) << 8) |
        (uint32_t)lrint(b * 255.0);
}

static void model_view_bounds(const CgfxModel *model, int top_view, Vec3 *out_min, Vec3 *out_max) {
    int mesh_index;
    bounds_reset(out_min, out_max);
    for (mesh_index = 0; mesh_index < model->mesh_count; mesh_index++) {
        const CgfxMesh *mesh = &model->meshes[mesh_index];
        int vertex_index;
        for (vertex_index = 0; vertex_index < mesh->vertex_count; vertex_index++) {
            Vec3 p = mesh->vertices[vertex_index];
            if (top_view) {
                double old_y = p.y;
                p.y = p.z;
                p.z = -old_y;
            }
            bounds_include(out_min, out_max, p);
        }
    }
}

static int render_physical_body(const char *model_path, const char *body_dir,
    const char *out_path, uint32_t requested_color, int use_authored_color,
    uint32_t skin_color, int top_view, int width, int height) {
    CgfxModel model;
    Image image;
    MeshCanvas canvas;
    ShapeTransform transform;
    Vec3 view_min;
    Vec3 view_max;
    double model_width;
    double model_height;
    double scale;
    double scale_x;
    double scale_y;
    double margin_x;
    double margin_y;
    double *depth = NULL;
    uint32_t color = requested_color;
    int ok = 0;

    memset(&model, 0, sizeof(model));
    memset(&image, 0, sizeof(image));
    if (!driver_load_model_file(model_path, requested_color, &model)) {
        fprintf(stderr, "Could not parse body CGFX: %s\n", model_path);
        goto cleanup;
    }
    if (use_authored_color) color = material_constant1_rgb(&model, requested_color);

    if (!top_view && model.has_skeleton) {
        apply_tomodachi_body_wait_pose(&model, body_dir);
        cgfx_apply_body_skinning(&model);
    }
    model_view_bounds(&model, top_view, &view_min, &view_max);
    if (!bounds_are_valid(view_min, view_max)) goto cleanup;

    model_width = view_max.x - view_min.x;
    model_height = view_max.y - view_min.y;
    if (model_width <= 0.000001 || model_height <= 0.000001) {
        fprintf(stderr, "Degenerate projected body bounds: %s\n", model_path);
        goto cleanup;
    }

    if (!image_create(&image, width, height)) goto cleanup;
    image_fill(&image, 0xf7f8fb);
    depth = (double *)malloc((size_t)width * (size_t)height * sizeof(double));
    if (!depth) goto cleanup;
    fill_depth(depth, width * height, -1.0e30);

    margin_x = width * 0.06;
    margin_y = height * 0.04;
    scale_x = (width - margin_x * 2.0) / model_width;
    scale_y = (height - margin_y * 2.0) / model_height;
    scale = scale_x < scale_y ? scale_x : scale_y;

    transform = shape_transform_identity();
    if (top_view) {
        mtx34_identity(transform.matrix);
        transform.has_matrix = 1;
        transform.matrix[0] = scale;
        transform.matrix[1] = 0.0;
        transform.matrix[2] = 0.0;
        transform.matrix[3] = -((view_min.x + view_max.x) * 0.5) * scale;
        transform.matrix[4] = 0.0;
        transform.matrix[5] = 0.0;
        transform.matrix[6] = scale;
        transform.matrix[7] = -((view_min.y + view_max.y) * 0.5) * scale;
        transform.matrix[8] = 0.0;
        transform.matrix[9] = -scale;
        transform.matrix[10] = 0.0;
        transform.matrix[11] = 0.0;
    } else {
        transform.scale_x = scale;
        transform.scale_y = scale;
        transform.scale_z = scale;
        transform.translate_x = -((view_min.x + view_max.x) * 0.5) * scale;
        transform.translate_y = -((view_min.y + view_max.y) * 0.5) * scale;
        transform.translate_z = -((view_min.z + view_max.z) * 0.5) * scale;
    }

    canvas.image = &image;
    canvas.depth = depth;
    mesh_canvas_set_orthographic(&canvas, width * 0.5, height * 0.5, 1.0);
    draw_cgfx_model(&canvas, &model, &transform, color, 1, 1,
        BLEND_SOURCE_OVER, CGFX_IMAGE_DIRECT_MODULATE, top_view ? 0 : 1,
        SHADER_MAT_BODY, skin_color);
#ifdef TOMODACHI_BODY_STANDALONE_NATIVE
    if (!driver_native.draw_ok) {
        fprintf(stderr, "Native PICA body draw did not complete.\n");
        goto cleanup;
    }
    fprintf(stderr,
        "native-pica=%s body-triangles=%llu body-fragments=%llu "
        "discarded-fragments=%llu\n",
        npm_shader_contract_id(),
        driver_native.submitted_triangles,
        driver_native.shaded_fragments,
        driver_native.discarded_fragments);
#endif

    if (!write_image(out_path, &image)) {
        fprintf(stderr, "Could not write render: %s\n", out_path);
        goto cleanup;
    }
    ok = 1;

cleanup:
#ifdef TOMODACHI_BODY_STANDALONE_NATIVE
    driver_release_native_materials();
#endif
    free(depth);
    image_free(&image);
    cgfx_model_free(&model);
    return ok;
}

static int draw_attached_physical_body(MeshCanvas *canvas, const MiiFaceParams *params,
    const char *model_path, const char *body_dir, const CflShape *faceline_shape,
    uint32_t requested_color, int use_authored_color, uint32_t skin_color) {
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
    uint32_t color = requested_color;
    int has_head_bounds;

    memset(&model, 0, sizeof(model));
    if (!driver_load_model_file(model_path, requested_color, &model)) return 0;
    if (use_authored_color) color = material_constant1_rgb(&model, requested_color);
    apply_tomodachi_body_wait_pose(&model, body_dir);
    has_head_bounds = cfl_shape_bounds(faceline_shape, NULL, &head_min, &head_max);

    model_width = model.max.x - model.min.x;
    model_height = model.max.y - model.min.y;
    model_depth = model.max.z - model.min.z;
    if (model_width <= 0.000001 || model_height <= 0.000001 || model_depth <= 0.000001) {
#ifdef TOMODACHI_BODY_STANDALONE_NATIVE
        driver_release_native_materials();
#endif
        cgfx_model_free(&model);
        return 0;
    }

    body_scales(params, &scale_x, &scale_y);
    cgfx_apply_body_skinning(&model);
    model_width = model.max.x - model.min.x;
    model_height = model.max.y - model.min.y;
    model_depth = model.max.z - model.min.z;
    if (model_width <= 0.000001 || model_height <= 0.000001 || model_depth <= 0.000001) {
#ifdef TOMODACHI_BODY_STANDALONE_NATIVE
        driver_release_native_materials();
#endif
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

    if (canvas->perspective) {
        Vec3 body_root;
        body_root.x = transform.translate_x;
        body_root.y = transform.translate_y;
        body_root.z = transform.translate_z;
        mesh_canvas_set_world_origin(canvas, body_root);
    }

    draw_cgfx_model(canvas, &model, &transform, color, 1, 1,
        BLEND_SOURCE_OVER, CGFX_IMAGE_DIRECT_MODULATE, 1, SHADER_MAT_BODY, skin_color);
#ifdef TOMODACHI_BODY_STANDALONE_NATIVE
    if (!driver_native.draw_ok) {
        fprintf(stderr, "Native PICA contextual body draw did not complete.\n");
        driver_release_native_materials();
        cgfx_model_free(&model);
        return 0;
    }
    fprintf(stderr,
        "native-pica=%s body-triangles=%llu body-fragments=%llu "
        "discarded-fragments=%llu\n",
        npm_shader_contract_id(),
        driver_native.submitted_triangles,
        driver_native.shaded_fragments,
        driver_native.discarded_fragments);
    driver_release_native_materials();
#endif
    cgfx_model_free(&model);
    return 1;
}

typedef struct {
    const char *model_path;
    const char *body_dir;
    uint32_t requested_color;
    uint32_t skin_color;
    int use_authored_color;
    int called;
} ContextualBodyDrawState;

static ContextualBodyDrawState contextual_body_draw;

static int contextual_body_draw_hook(MeshCanvas *canvas,
    const MiiFaceParams *params, const CflShape *faceline_shape) {
    contextual_body_draw.called = 1;
    return draw_attached_physical_body(canvas, params,
        contextual_body_draw.model_path, contextual_body_draw.body_dir,
        faceline_shape, contextual_body_draw.requested_color,
        contextual_body_draw.use_authored_color, contextual_body_draw.skin_color);
}

static int render_contextual_body(const char *cfl_path, const char *ffl_path, const char *model_path,
    const char *body_dir, const char *out_path, uint32_t requested_color,
    int use_authored_color, uint32_t skin_color,
    const MiiFaceParams *mii_params, int width, int height) {
    Buffer cfl_bytes;
    Buffer ffl_bytes;
    CflResource resource;
    FflHighResource high_resource;
    MiiFaceParams params;
    Image output;
    int render_ok;
    int ok = 0;

    memset(&cfl_bytes, 0, sizeof(cfl_bytes));
    memset(&ffl_bytes, 0, sizeof(ffl_bytes));
    memset(&resource, 0, sizeof(resource));
    memset(&high_resource, 0, sizeof(high_resource));
    memset(&output, 0, sizeof(output));
    memset(&contextual_body_draw, 0, sizeof(contextual_body_draw));
    if (!mii_params || width != 512 ||
        (mii_params->full_body ? height != 512 : height < 832)) return 0;
    params = *mii_params;
    params.draw_body = 1;
    params.draw_headwear = 0;

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

    contextual_body_draw.model_path = model_path;
    contextual_body_draw.body_dir = body_dir;
    contextual_body_draw.requested_color = requested_color;
    contextual_body_draw.skin_color = skin_color;
    contextual_body_draw.use_authored_color = use_authored_color;
    tomodachi_direct_body_draw_hook = contextual_body_draw_hook;
    render_ok = render_portrait_sized(
        &resource, &params, body_dir, "", "", width, height, &output);
    tomodachi_direct_body_draw_hook = NULL;
    if (!render_ok || !contextual_body_draw.called) goto cleanup;
    fprintf(stderr, "composition=tomodachi-shared-body-head-depth-ffl-high-v3\n");
    fprintf(stderr, "projection=%s\n", params.full_body
        ? "ffl-whole-body-camera-fov15-height-v1"
        : "tomodachi-portrait-orthographic-v1");
    if (!write_image(out_path, &output)) goto cleanup;
    ok = 1;

cleanup:
    tomodachi_direct_body_draw_hook = NULL;
    image_free(&output);
    cfl_free(&resource);
    free(cfl_bytes.data);
    free(ffl_bytes.data);
    return ok;
}

static void driver_usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s --model=body.cgfx --body-dir=romFS/model/body --out=render.bmp "
        "--material-sidecar=body.materials.bin --lut-sidecar=lutCommon.luts.bin "
        "--lut-source=env_lut_common.bin.dat "
        "[--color=RRGGBB|authored] [--skin=RRGGBB] [--view=front|top] "
        "[--cfl=CFL_Res.dat --ffl=FFLResHigh.dat] [--mii-*=N ...] "
        "[--full-body] [--width=N] [--height=N]\n", argv0);
}

int main(int argc, char **argv) {
    const char *model_path = NULL;
    const char *body_dir = NULL;
    const char *out_path = NULL;
    const char *cfl_path = NULL;
    const char *ffl_path = NULL;
    uint32_t color = 0x808080u;
    uint32_t skin = mii_skin_color(0);
    int use_authored_color = 0;
    int top_view = 0;
    int width = 512;
    int height = 768;
    MiiFaceParams mii_params;
    int i;

    init_default_params(&mii_params);

    for (i = 1; i < argc; i++) {
        const char *value;
        if ((value = driver_arg_value(argv[i], "--model="))) model_path = value;
        else if ((value = driver_arg_value(argv[i], "--body-dir="))) body_dir = value;
        else if ((value = driver_arg_value(argv[i], "--out="))) out_path = value;
        else if ((value = driver_arg_value(argv[i], "--cfl="))) cfl_path = value;
        else if ((value = driver_arg_value(argv[i], "--ffl="))) ffl_path = value;
#ifdef TOMODACHI_BODY_STANDALONE_NATIVE
        else if ((value = driver_arg_value(argv[i], "--material-sidecar="))) {
            driver_material_sidecar_path = value;
        } else if ((value = driver_arg_value(argv[i], "--lut-sidecar="))) {
            driver_lut_sidecar_path = value;
        } else if ((value = driver_arg_value(argv[i], "--lut-source="))) {
            driver_lut_source_path = value;
        }
#endif
        else if ((value = driver_arg_value(argv[i], "--color="))) {
            if (strcmp(value, "authored") == 0) use_authored_color = 1;
            else if (!parse_rgb24(value, &color)) {
                fprintf(stderr, "Invalid RGB color: %s\n", value);
                return 2;
            }
        } else if ((value = driver_arg_value(argv[i], "--skin="))) {
            if (!parse_rgb24(value, &skin)) {
                fprintf(stderr, "Invalid skin RGB color: %s\n", value);
                return 2;
            }
        } else if ((value = driver_arg_value(argv[i], "--view="))) {
            if (strcmp(value, "top") == 0) top_view = 1;
            else if (strcmp(value, "front") == 0) top_view = 0;
            else {
                fprintf(stderr, "Invalid view: %s\n", value);
                return 2;
            }
        } else if ((value = driver_arg_value(argv[i], "--width="))) width = atoi(value);
        else if ((value = driver_arg_value(argv[i], "--height="))) height = atoi(value);
        else if (strcmp(argv[i], "--full-body") == 0) mii_params.full_body = 1;
        else if (mii_face_params_parse_prefixed_arg(&mii_params, argv[i])) {
            /* Parsed by the shared decomp-backed Mii profile parser. */
        }
        else {
            driver_usage(argv[0]);
            return 2;
        }
    }

    if (!model_path || !body_dir || !out_path || width < 64 || height < 64 ||
        width > 4096 || height > 4096) {
        driver_usage(argv[0]);
        return 2;
    }
#ifdef TOMODACHI_BODY_STANDALONE_NATIVE
    if (!driver_material_sidecar_path || !driver_lut_sidecar_path ||
        !driver_lut_source_path) {
        driver_usage(argv[0]);
        return 2;
    }
#endif
    if (cfl_path && ffl_path && !top_view) {
        skin = mii_skin_color(mii_params.face_color);
        return render_contextual_body(cfl_path, ffl_path, model_path, body_dir, out_path,
            color, use_authored_color, skin, &mii_params, width, height) ? 0 : 1;
    }
    if ((cfl_path || ffl_path) && !top_view) {
        driver_usage(argv[0]);
        return 2;
    }
    return render_physical_body(model_path, body_dir, out_path, color,
        use_authored_color, skin, top_view, width, height) ? 0 : 1;
}
