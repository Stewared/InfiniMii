#include "native_draw_runtime_v2.h"

/* ABI 2 is a strict superset. Compile the frozen ABI-1 implementation unchanged. */
#include "native_draw_runtime.c"

#if defined(_MSC_VER)
#pragma float_control(precise, on, push)
#pragma fp_contract(off)
#endif

enum HairParameter {
    HAIR_BASE_R = 0, HAIR_BASE_G = 1, HAIR_BASE_B = 2,
    HAIR_LIGHT_X = 3, HAIR_LIGHT_Y = 4, HAIR_LIGHT_Z = 5,
    HAIR_AMBIENT_R = 6, HAIR_AMBIENT_G = 7, HAIR_AMBIENT_B = 8,
    HAIR_KEY_R = 9, HAIR_KEY_G = 10, HAIR_KEY_B = 11,
    HAIR_FRONT_R = 12, HAIR_FRONT_G = 13, HAIR_FRONT_B = 14,
    HAIR_CAMERA_X = 15, HAIR_CAMERA_Y = 16, HAIR_CAMERA_Z = 17,
    HAIR_ANISO_R = 18, HAIR_ANISO_G = 19, HAIR_ANISO_B = 20,
    HAIR_INVERSE_R2 = 21, HAIR_KERNEL_FACTOR = 22,
    HAIR_SHIFT_SCALE = 23, HAIR_SHIFT_OFFSET = 24, HAIR_FLIP_SIGN = 25,
    HAIR_HAS_CAMERA = 26, HAIR_PERSPECTIVE_CORRECT = 27,
    HAIR_TITLE_VIEW_SCALE = 28,
    HAIR_ANISO_LIGHT_X = 29, HAIR_ANISO_LIGHT_Y = 30, HAIR_ANISO_LIGHT_Z = 31,
    HAIR_EXECUTE_ANISOTROPY = 32
};

static ltd_draw_runtime_status validate_u8(
    const ltd_draw_const_u8_buffer *buffer, size_t expected
) {
    if (buffer == NULL || buffer->element_count != expected) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    if (expected != 0 && buffer->data == NULL) return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    return LTD_DRAW_RUNTIME_OK;
}

static ltd_draw_runtime_status validate_mesh_arrays(
    uint32_t triangle_count,
    const ltd_draw_const_f64_buffer *vertices,
    const ltd_draw_const_f64_buffer *normals,
    const ltd_draw_const_f64_buffer *uv
) {
    size_t nine = 0, six = 0;
    ltd_draw_runtime_status status;
    if (!expected_elements((size_t)triangle_count, 9, &nine) ||
        !expected_elements((size_t)triangle_count, 6, &six)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    status = validate_f64(vertices, nine);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_f64(normals, nine);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    return validate_f64(uv, six);
}

static ltd_draw_runtime_status validate_level_indices(
    const ltd_draw_const_i64_buffer *indices,
    uint32_t triangle_count,
    uint32_t level_count
) {
    ltd_draw_runtime_status status = validate_i64(indices, triangle_count);
    uint32_t triangle;
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    for (triangle = 0; triangle < triangle_count; ++triangle) {
        if (indices->data[triangle] < 0 || indices->data[triangle] >= level_count) {
            return LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE;
        }
    }
    return LTD_DRAW_RUNTIME_OK;
}

static int normalize3_v2(double value[3]) {
    double length = norm3(value);
    if (!(length > 1e-12)) return 0;
    value[0] /= length;
    value[1] /= length;
    value[2] /= length;
    return 1;
}

uint32_t LTD_DRAW_RUNTIME_CALL ltd_draw_runtime_v2_abi_version(void) {
    return LTD_DRAW_RUNTIME_V2_ABI_VERSION;
}

const char *LTD_DRAW_RUNTIME_CALL ltd_draw_runtime_v2_contract_sha256(void) {
    return LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256;
}

const char *LTD_DRAW_RUNTIME_CALL ltd_draw_runtime_v2_wrapper_sha256(void) {
    return LTD_DRAW_RUNTIME_V2_WRAPPER_SHA256;
}

ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL ltd_draw_runtime_v2_require(
    uint32_t expected_abi, const char *expected_contract_sha256
) {
    if (expected_abi != LTD_DRAW_RUNTIME_V2_ABI_VERSION) {
        return LTD_DRAW_RUNTIME_ABI_MISMATCH;
    }
    if (expected_contract_sha256 == NULL ||
        strcmp(expected_contract_sha256, LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256) != 0) {
        return LTD_DRAW_RUNTIME_CONTRACT_MISMATCH;
    }
    return LTD_DRAW_RUNTIME_OK;
}

static ltd_draw_runtime_status validate_head(
    const ltd_draw_attachments *attachments,
    const ltd_draw_head816_input *input
) {
    ltd_draw_runtime_status status;
    size_t count;
    size_t nine = 0, six = 0;
    uint32_t triangle;
    if (input == NULL) return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    count = input->triangles.triangle_count;
    if (!expected_elements(count, 9, &nine) || !expected_elements(count, 6, &six)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    status = validate_triangles(&input->triangles, attachments->width, attachments->height);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_f64(&input->world_vertices, nine);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_f64(&input->vertex_normals, nine);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_u8(&input->vertex_normal_valid, count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_f64(&input->albedo_uv, six);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_f64(&input->normal_uv, six);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_texture2d(&input->albedo_texture);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_mip_bank(&input->normal);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_level_indices(
        &input->normal_level_indices, input->triangles.triangle_count,
        input->normal.level_count
    );
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->base_color_linear);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->light_direction);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->light_color);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->ambient_color);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    if (!isfinite(input->light_intensity) || !isfinite(input->ambient_intensity) ||
        !isfinite(input->alpha_scalar) || !isfinite(input->alpha_cutoff)) {
        return LTD_DRAW_RUNTIME_NONFINITE;
    }
    if ((input->perspective_correct != 0 && input->perspective_correct != 1) ||
        (input->has_albedo != 0 && input->has_albedo != 1)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    for (triangle = 0; triangle < input->triangles.triangle_count; ++triangle) {
        if (input->vertex_normal_valid.data[triangle] > 1) {
            return LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE;
        }
    }
    return LTD_DRAW_RUNTIME_OK;
}

ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL ltd_draw_head816(
    ltd_draw_attachments *attachments,
    const ltd_draw_head816_input *input,
    uint64_t *written_fragments
) {
    ltd_draw_runtime_status status = require_rounding();
    size_t spans[3];
    double ambient[3], key[3], front[3];
    uint64_t written = 0;
    uint32_t triangle;
    if (written_fragments == NULL) return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    *written_fragments = 0;
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_attachments(attachments, spans);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_head(attachments, input);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    lighting_constants(
        input->light_direction, input->light_color, input->ambient_color,
        input->light_intensity, input->ambient_intensity, ambient, key, front
    );
    for (triangle = 0; triangle < input->triangles.triangle_count; ++triangle) {
        const double *screen = input->triangles.screen.data + (size_t)triangle * 9;
        const double *vertices = input->world_vertices.data + (size_t)triangle * 9;
        const double *normals = input->vertex_normals.data + (size_t)triangle * 9;
        const double *albedo_uv = input->albedo_uv.data + (size_t)triangle * 6;
        const double *normal_uv = input->normal_uv.data + (size_t)triangle * 6;
        const int64_t *bounds = input->triangles.bounds.data + (size_t)triangle * 4;
        double edge1[3], edge2[3], geometric_normal[3];
        double tangent[3] = {0.0, 0.0, 0.0};
        double handedness = 1.0;
        int tangent_valid = 0;
        double delta1_u, delta1_v, delta2_u, delta2_v, determinant;
        int64_t level_index;
        const double *normal_texture;
        int64_t normal_height, normal_width;
        int component, y;
        for (component = 0; component < 3; ++component) {
            edge1[component] = vertices[3 + component] - vertices[component];
            edge2[component] = vertices[6 + component] - vertices[component];
        }
        cross3(edge1, edge2, geometric_normal);
        {
            double length = norm3(geometric_normal);
            if (length != 0.0) {
                for (component = 0; component < 3; ++component) geometric_normal[component] /= length;
            }
        }
        delta1_u = normal_uv[2] - normal_uv[0];
        delta1_v = normal_uv[3] - normal_uv[1];
        delta2_u = normal_uv[4] - normal_uv[0];
        delta2_v = normal_uv[5] - normal_uv[1];
        determinant = delta1_u * delta2_v - delta2_u * delta1_v;
        if (fabs(determinant) > 1e-12) {
            double raw_bitangent[3], tangent_length;
            for (component = 0; component < 3; ++component) {
                tangent[component] =
                    (edge1[component] * delta2_v - edge2[component] * delta1_v) / determinant;
                raw_bitangent[component] =
                    (-edge1[component] * delta2_u + edge2[component] * delta1_u) / determinant;
            }
            tangent_length = norm3(tangent);
            if (tangent_length > 1e-12) {
                double cross_value[3], handedness_value;
                for (component = 0; component < 3; ++component) tangent[component] /= tangent_length;
                cross3(geometric_normal, tangent, cross_value);
                handedness_value = dot3(cross_value, raw_bitangent);
                handedness = handedness_value < 0.0 ? -1.0 :
                    (handedness_value > 0.0 ? 1.0 : 0.0);
                if (handedness == 0.0) handedness = 1.0;
                tangent_valid = 1;
            }
        }
        level_index = input->normal_level_indices.data[triangle];
        normal_texture = input->normal.texels +
            (size_t)input->normal.levels[(size_t)level_index * 3] * 4;
        normal_height = input->normal.levels[(size_t)level_index * 3 + 1];
        normal_width = input->normal.levels[(size_t)level_index * 3 + 2];
        for (y = (int)bounds[2]; y <= (int)bounds[3]; ++y) {
            int x;
            for (x = (int)bounds[0]; x <= (int)bounds[1]; ++x) {
                double affine0, affine1, affine2, z;
                double weight0, weight1, weight2;
                double source[3], fragment_alpha;
                double shading_normal[3], shading_length;
                double normal_u01, normal_u, normal_v01, normal_v, normal_sample[4];
                double normal_x, normal_y, xy_length, xy_denominator, xy_scale, z_squared, normal_z;
                int channel;
                if (!visible_lane(
                    screen, attachments, x, y, input->triangles.denominators.data[triangle],
                    &affine0, &affine1, &affine2, &z
                )) continue;
                weight0 = affine0; weight1 = affine1; weight2 = affine2;
                if (input->perspective_correct) {
                    double safe = fabs(z) < 1e-20 ? 1.0 : z;
                    weight0 = (affine0 * screen[2]) / safe;
                    weight1 = (affine1 * screen[5]) / safe;
                    weight2 = (affine2 * screen[8]) / safe;
                }
                source[0] = input->base_color_linear[0];
                source[1] = input->base_color_linear[1];
                source[2] = input->base_color_linear[2];
                fragment_alpha = input->alpha_scalar;
                if (input->has_albedo) {
                    double u01 = weight0 * albedo_uv[0] + weight1 * albedo_uv[2];
                    double u = u01 + weight2 * albedo_uv[4];
                    double v01 = weight0 * albedo_uv[1] + weight1 * albedo_uv[3];
                    double v = v01 + weight2 * albedo_uv[5];
                    double sample[4];
                    sample_rgba(
                        input->albedo_texture.texels, input->albedo_texture.height,
                        input->albedo_texture.width, u, v, 2, 1, sample
                    );
                    for (channel = 0; channel < 3; ++channel) source[channel] *= sample[channel];
                    fragment_alpha *= sample[3];
                }
                if (!(fragment_alpha >= input->alpha_cutoff)) continue;
                if (input->vertex_normal_valid.data[triangle]) {
                    for (component = 0; component < 3; ++component) {
                        double first_two = weight0 * normals[component] + weight1 * normals[3 + component];
                        shading_normal[component] = first_two + weight2 * normals[6 + component];
                    }
                    shading_length = norm3(shading_normal);
                    if (shading_length == 0.0) shading_length = 1.0;
                    for (component = 0; component < 3; ++component) shading_normal[component] /= shading_length;
                } else {
                    for (component = 0; component < 3; ++component) shading_normal[component] = geometric_normal[component];
                }
                normal_u01 = weight0 * normal_uv[0] + weight1 * normal_uv[2];
                normal_u = normal_u01 + weight2 * normal_uv[4];
                normal_v01 = weight0 * normal_uv[1] + weight1 * normal_uv[3];
                normal_v = normal_v01 + weight2 * normal_uv[5];
                sample_rgba(normal_texture, normal_height, normal_width, normal_u, normal_v, 1, 1, normal_sample);
                normal_x = (normal_sample[0] * 2.0 - 1.0) * 1.0;
                normal_y = (normal_sample[3] * 2.0 - 1.0) * 1.0;
                xy_length = sqrt(normal_x * normal_x + normal_y * normal_y);
                xy_denominator = xy_length > 1e-12 ? xy_length : 1e-12;
                xy_scale = 0.999999 / xy_denominator;
                if (xy_scale > 1.0) xy_scale = 1.0;
                normal_x *= xy_scale; normal_y *= xy_scale;
                z_squared = (1.0 - normal_x * normal_x) - normal_y * normal_y;
                if (z_squared < 0.0) z_squared = 0.0;
                normal_z = sqrt(z_squared);
                if (tangent_valid) {
                    double tangent_dot_normal = dot3(shading_normal, tangent);
                    double tangent_field[3], bitangent_field[3];
                    double tangent_field_length, final_length;
                    for (component = 0; component < 3; ++component) {
                        tangent_field[component] = tangent[component] -
                            shading_normal[component] * tangent_dot_normal;
                    }
                    tangent_field_length = norm3(tangent_field);
                    if (tangent_field_length == 0.0) tangent_field_length = 1.0;
                    for (component = 0; component < 3; ++component) tangent_field[component] /= tangent_field_length;
                    cross3(shading_normal, tangent_field, bitangent_field);
                    for (component = 0; component < 3; ++component) {
                        double first_two;
                        bitangent_field[component] *= handedness;
                        first_two = tangent_field[component] * normal_x + bitangent_field[component] * normal_y;
                        shading_normal[component] = first_two + shading_normal[component] * normal_z;
                    }
                    final_length = norm3(shading_normal);
                    if (final_length == 0.0) final_length = 1.0;
                    for (component = 0; component < 3; ++component) shading_normal[component] /= final_length;
                }
                shade_plain(source, shading_normal, input->light_direction, ambient, key, front);
                write_fragment(attachments, x, y, source, z);
                ++written;
            }
        }
    }
    *written_fragments = written;
    return LTD_DRAW_RUNTIME_OK;
}

static int valid_outfit_profile(int32_t profile) {
    return profile == LTD_DRAW_OUTFIT_TOPS984 ||
        profile == LTD_DRAW_OUTFIT_BOTTOMS936 ||
        profile == LTD_DRAW_OUTFIT_SHOES912;
}

static ltd_draw_runtime_status validate_outfit(
    const ltd_draw_attachments *attachments,
    const ltd_draw_outfit_input *input
) {
    ltd_draw_runtime_status status;
    uint32_t count, triangle;
    if (input == NULL || !valid_outfit_profile(input->profile) ||
        input->perspective_correct != 1 ||
        !isfinite(input->light_intensity) || !isfinite(input->ambient_intensity)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    count = input->triangles.triangle_count;
    status = validate_triangles(&input->triangles, attachments->width, attachments->height);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_mesh_arrays(
        count, &input->world_vertices, &input->vertex_normals, &input->material_uv
    );
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_mip_bank(&input->albedo);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_mip_bank(&input->normal);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_i64(&input->albedo_lower_indices, count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_i64(&input->albedo_upper_indices, count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_f64(&input->albedo_mip_amounts, count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_level_indices(
        &input->normal_level_indices, count, input->normal.level_count
    );
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->light_direction);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->light_color);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->ambient_color);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    for (triangle = 0; triangle < count; ++triangle) {
        int64_t lower = input->albedo_lower_indices.data[triangle];
        int64_t upper = input->albedo_upper_indices.data[triangle];
        double amount = input->albedo_mip_amounts.data[triangle];
        if (lower < 0 || lower >= input->albedo.level_count ||
            upper < 0 || upper >= input->albedo.level_count ||
            !isfinite(amount) || amount < 0.0 || amount > 1.0) {
            return LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE;
        }
    }
    return LTD_DRAW_RUNTIME_OK;
}

ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL ltd_draw_outfit(
    ltd_draw_attachments *attachments,
    const ltd_draw_outfit_input *input,
    uint64_t *written_fragments
) {
    ltd_draw_runtime_status status = require_rounding();
    size_t spans[3];
    double ambient[3], key[3], front[3];
    uint64_t written = 0;
    uint32_t triangle;
    if (written_fragments == NULL) return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    *written_fragments = 0;
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_attachments(attachments, spans);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_outfit(attachments, input);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    lighting_constants(
        input->light_direction, input->light_color, input->ambient_color,
        input->light_intensity, input->ambient_intensity, ambient, key, front
    );
    for (triangle = 0; triangle < input->triangles.triangle_count; ++triangle) {
        const double *screen = input->triangles.screen.data + (size_t)triangle * 9;
        const double *vertices = input->world_vertices.data + (size_t)triangle * 9;
        const double *normals = input->vertex_normals.data + (size_t)triangle * 9;
        const double *uv = input->material_uv.data + (size_t)triangle * 6;
        const int64_t *bounds = input->triangles.bounds.data + (size_t)triangle * 4;
        double edge1[3], edge2[3], geometric_normal[3];
        double tangent[3] = {0.0, 0.0, 0.0};
        double handedness = 1.0;
        int tangent_valid = 0;
        double delta1_u, delta1_v, delta2_u, delta2_v, determinant;
        int64_t albedo_lower_index, albedo_upper_index, normal_index;
        const double *albedo_lower_texture, *albedo_upper_texture, *normal_texture;
        int64_t albedo_lower_height, albedo_lower_width, albedo_upper_height, albedo_upper_width;
        int64_t normal_height, normal_width;
        double albedo_amount, albedo_inverse;
        int component, y;
        for (component = 0; component < 3; ++component) {
            edge1[component] = vertices[3 + component] - vertices[component];
            edge2[component] = vertices[6 + component] - vertices[component];
        }
        cross3(edge1, edge2, geometric_normal);
        {
            double length = norm3(geometric_normal);
            if (length != 0.0) {
                for (component = 0; component < 3; ++component) geometric_normal[component] /= length;
            }
        }
        delta1_u = uv[2] - uv[0]; delta1_v = uv[3] - uv[1];
        delta2_u = uv[4] - uv[0]; delta2_v = uv[5] - uv[1];
        determinant = delta1_u * delta2_v - delta2_u * delta1_v;
        if (fabs(determinant) > 1e-12) {
            double raw_bitangent[3], tangent_length;
            for (component = 0; component < 3; ++component) {
                tangent[component] =
                    (edge1[component] * delta2_v - edge2[component] * delta1_v) / determinant;
                raw_bitangent[component] =
                    (-edge1[component] * delta2_u + edge2[component] * delta1_u) / determinant;
            }
            tangent_length = norm3(tangent);
            if (tangent_length > 1e-12) {
                double cross_value[3], sign_value;
                for (component = 0; component < 3; ++component) tangent[component] /= tangent_length;
                cross3(geometric_normal, tangent, cross_value);
                sign_value = dot3(cross_value, raw_bitangent);
                handedness = sign_value < 0.0 ? -1.0 : (sign_value > 0.0 ? 1.0 : 0.0);
                if (handedness == 0.0) handedness = 1.0;
                tangent_valid = 1;
            }
        }
        albedo_lower_index = input->albedo_lower_indices.data[triangle];
        albedo_upper_index = input->albedo_upper_indices.data[triangle];
        normal_index = input->normal_level_indices.data[triangle];
        albedo_lower_texture = input->albedo.texels +
            (size_t)input->albedo.levels[(size_t)albedo_lower_index * 3] * 4;
        albedo_upper_texture = input->albedo.texels +
            (size_t)input->albedo.levels[(size_t)albedo_upper_index * 3] * 4;
        albedo_lower_height = input->albedo.levels[(size_t)albedo_lower_index * 3 + 1];
        albedo_lower_width = input->albedo.levels[(size_t)albedo_lower_index * 3 + 2];
        albedo_upper_height = input->albedo.levels[(size_t)albedo_upper_index * 3 + 1];
        albedo_upper_width = input->albedo.levels[(size_t)albedo_upper_index * 3 + 2];
        albedo_amount = input->albedo_mip_amounts.data[triangle];
        albedo_inverse = 1.0 - albedo_amount;
        normal_texture = input->normal.texels +
            (size_t)input->normal.levels[(size_t)normal_index * 3] * 4;
        normal_height = input->normal.levels[(size_t)normal_index * 3 + 1];
        normal_width = input->normal.levels[(size_t)normal_index * 3 + 2];
        for (y = (int)bounds[2]; y <= (int)bounds[3]; ++y) {
            int x;
            for (x = (int)bounds[0]; x <= (int)bounds[1]; ++x) {
                double affine0, affine1, affine2, z, safe, weight0, weight1, weight2;
                double u01, u, v01, v;
                double lower_sample[4], upper_sample[4], source[3], fragment_alpha;
                double shading_normal[3], shading_length, normal_sample[4];
                double normal_x, normal_y, xy_length, xy_denominator, xy_scale, z_squared, normal_z;
                int channel;
                if (!visible_lane(
                    screen, attachments, x, y, input->triangles.denominators.data[triangle],
                    &affine0, &affine1, &affine2, &z
                )) continue;
                safe = fabs(z) < 1e-20 ? 1.0 : z;
                weight0 = (affine0 * screen[2]) / safe;
                weight1 = (affine1 * screen[5]) / safe;
                weight2 = (affine2 * screen[8]) / safe;
                u01 = weight0 * uv[0] + weight1 * uv[2];
                u = u01 + weight2 * uv[4];
                v01 = weight0 * uv[1] + weight1 * uv[3];
                v = v01 + weight2 * uv[5];
                sample_rgba(albedo_lower_texture, albedo_lower_height, albedo_lower_width, u, v, 0, 0, lower_sample);
                sample_rgba(albedo_upper_texture, albedo_upper_height, albedo_upper_width, u, v, 0, 0, upper_sample);
                for (channel = 0; channel < 3; ++channel) {
                    source[channel] = lower_sample[channel] * albedo_inverse +
                        upper_sample[channel] * albedo_amount;
                }
                fragment_alpha = lower_sample[3] * albedo_inverse + upper_sample[3] * albedo_amount;
                if (!(fragment_alpha >= 0.0)) continue;
                for (component = 0; component < 3; ++component) {
                    double first_two = weight0 * normals[component] + weight1 * normals[3 + component];
                    shading_normal[component] = first_two + weight2 * normals[6 + component];
                }
                shading_length = norm3(shading_normal);
                if (shading_length == 0.0) shading_length = 1.0;
                for (component = 0; component < 3; ++component) shading_normal[component] /= shading_length;
                sample_rgba(normal_texture, normal_height, normal_width, u, v, 0, 0, normal_sample);
                normal_x = (normal_sample[0] * 2.0 - 1.0) * 1.0;
                normal_y = (normal_sample[1] * 2.0 - 1.0) * 1.0;
                xy_length = sqrt(normal_x * normal_x + normal_y * normal_y);
                xy_denominator = xy_length > 1e-12 ? xy_length : 1e-12;
                xy_scale = 0.999999 / xy_denominator;
                if (xy_scale > 1.0) xy_scale = 1.0;
                normal_x *= xy_scale; normal_y *= xy_scale;
                z_squared = (1.0 - normal_x * normal_x) - normal_y * normal_y;
                if (z_squared < 0.0) z_squared = 0.0;
                normal_z = sqrt(z_squared);
                if (tangent_valid) {
                    double tangent_dot_normal = dot3(shading_normal, tangent);
                    double tangent_field[3], bitangent_field[3];
                    double tangent_field_length, final_length;
                    for (component = 0; component < 3; ++component) {
                        tangent_field[component] = tangent[component] -
                            shading_normal[component] * tangent_dot_normal;
                    }
                    tangent_field_length = norm3(tangent_field);
                    if (tangent_field_length == 0.0) tangent_field_length = 1.0;
                    for (component = 0; component < 3; ++component) tangent_field[component] /= tangent_field_length;
                    cross3(shading_normal, tangent_field, bitangent_field);
                    for (component = 0; component < 3; ++component) {
                        double first_two;
                        bitangent_field[component] *= handedness;
                        first_two = tangent_field[component] * normal_x + bitangent_field[component] * normal_y;
                        shading_normal[component] = first_two + shading_normal[component] * normal_z;
                    }
                    final_length = norm3(shading_normal);
                    if (final_length == 0.0) final_length = 1.0;
                    for (component = 0; component < 3; ++component) shading_normal[component] /= final_length;
                }
                shade_plain(source, shading_normal, input->light_direction, ambient, key, front);
                write_fragment(attachments, x, y, source, z);
                ++written;
            }
        }
    }
    *written_fragments = written;
    return LTD_DRAW_RUNTIME_OK;
}

static int valid_hair_profile(int32_t profile) {
    return profile == LTD_DRAW_HAIR612 ||
        profile == LTD_DRAW_HAIR564_EQUAL_ENDPOINT ||
        profile == LTD_DRAW_BEARD468;
}

static ltd_draw_runtime_status validate_hair(
    const ltd_draw_attachments *attachments,
    const ltd_draw_hair_input *input
) {
    ltd_draw_runtime_status status;
    uint32_t count;
    int index;
    if (input == NULL || input->reserved != 0 || !valid_hair_profile(input->profile)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    count = input->triangles.triangle_count;
    status = validate_triangles(&input->triangles, attachments->width, attachments->height);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_mesh_arrays(
        count, &input->world_vertices, &input->vertex_normals, &input->material_uv
    );
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_mip_bank(&input->mim);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_level_indices(
        &input->mim_level_indices, count, input->mim.level_count
    );
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    for (index = 0; index < 33; ++index) {
        if (!isfinite(input->parameters[index])) return LTD_DRAW_RUNTIME_NONFINITE;
    }
    if ((input->parameters[HAIR_HAS_CAMERA] != 0.0 &&
         input->parameters[HAIR_HAS_CAMERA] != 1.0) ||
        (input->parameters[HAIR_PERSPECTIVE_CORRECT] != 0.0 &&
         input->parameters[HAIR_PERSPECTIVE_CORRECT] != 1.0) ||
        (input->parameters[HAIR_EXECUTE_ANISOTROPY] != 0.0 &&
         input->parameters[HAIR_EXECUTE_ANISOTROPY] != 1.0) ||
        (input->parameters[HAIR_FLIP_SIGN] != -1.0 &&
         input->parameters[HAIR_FLIP_SIGN] != 1.0)) {
        return LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE;
    }
    if ((input->profile == LTD_DRAW_HAIR564_EQUAL_ENDPOINT) !=
        (input->parameters[HAIR_EXECUTE_ANISOTROPY] == 0.0)) {
        return LTD_DRAW_RUNTIME_CONTRACT_MISMATCH;
    }
    return LTD_DRAW_RUNTIME_OK;
}

ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL ltd_draw_hair(
    ltd_draw_attachments *attachments,
    const ltd_draw_hair_input *input,
    uint64_t *written_fragments
) {
    ltd_draw_runtime_status status = require_rounding();
    size_t spans[3];
    uint64_t written = 0;
    uint32_t triangle;
    const double *parameters;
    double light[3], anisotropic_light[3];
    if (written_fragments == NULL) return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    *written_fragments = 0;
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_attachments(attachments, spans);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_hair(attachments, input);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    parameters = input->parameters;
    light[0] = parameters[HAIR_LIGHT_X];
    light[1] = parameters[HAIR_LIGHT_Y];
    light[2] = parameters[HAIR_LIGHT_Z];
    anisotropic_light[0] = parameters[HAIR_ANISO_LIGHT_X];
    anisotropic_light[1] = parameters[HAIR_ANISO_LIGHT_Y];
    anisotropic_light[2] = parameters[HAIR_ANISO_LIGHT_Z];
    for (triangle = 0; triangle < input->triangles.triangle_count; ++triangle) {
        const double *screen = input->triangles.screen.data + (size_t)triangle * 9;
        const double *vertices = input->world_vertices.data + (size_t)triangle * 9;
        const double *normals = input->vertex_normals.data + (size_t)triangle * 9;
        const double *uv = input->material_uv.data + (size_t)triangle * 6;
        const int64_t *bounds = input->triangles.bounds.data + (size_t)triangle * 4;
        double edge1[3], edge2[3], geometric_normal[3];
        double tangent[3] = {0.0, 0.0, 0.0};
        double handedness = 1.0;
        int tangent_valid = 0;
        double delta1_u, delta1_v, delta2_u, delta2_v, determinant;
        int64_t level;
        const double *mim;
        int64_t mip_height, mip_width;
        int component, y;
        for (component = 0; component < 3; ++component) {
            edge1[component] = vertices[3 + component] - vertices[component];
            edge2[component] = vertices[6 + component] - vertices[component];
        }
        cross3(edge1, edge2, geometric_normal);
        {
            double length = norm3(geometric_normal);
            if (length != 0.0) {
                geometric_normal[0] /= length;
                geometric_normal[1] /= length;
                geometric_normal[2] /= length;
            }
        }
        delta1_u = uv[2] - uv[0]; delta1_v = uv[3] - uv[1];
        delta2_u = uv[4] - uv[0]; delta2_v = uv[5] - uv[1];
        determinant = delta1_u * delta2_v - delta2_u * delta1_v;
        if (fabs(determinant) > 1e-12) {
            double raw_bitangent[3], tangent_length;
            for (component = 0; component < 3; ++component) {
                tangent[component] =
                    (edge1[component] * delta2_v - edge2[component] * delta1_v) / determinant;
                raw_bitangent[component] =
                    (-edge1[component] * delta2_u + edge2[component] * delta1_u) / determinant;
            }
            tangent_length = norm3(tangent);
            if (tangent_length > 1e-12) {
                double cross_value[3], sign;
                tangent[0] /= tangent_length;
                tangent[1] /= tangent_length;
                tangent[2] /= tangent_length;
                cross3(geometric_normal, tangent, cross_value);
                sign = dot3(cross_value, raw_bitangent);
                handedness = (sign < 0.0 ? -1.0 : 1.0) * parameters[HAIR_FLIP_SIGN];
                tangent_valid = 1;
            }
        }
        level = input->mim_level_indices.data[triangle];
        mim = input->mim.texels + (size_t)input->mim.levels[(size_t)level * 3] * 4;
        mip_height = input->mim.levels[(size_t)level * 3 + 1];
        mip_width = input->mim.levels[(size_t)level * 3 + 2];
        for (y = (int)bounds[2]; y <= (int)bounds[3]; ++y) {
            int x;
            for (x = (int)bounds[0]; x <= (int)bounds[1]; ++x) {
                double affine0, affine1, affine2, z;
                double weight0, weight1, weight2;
                double shading_normal[3], shading_length, hemisphere, source[3];
                int channel;
                if (!visible_lane(
                    screen, attachments, x, y, input->triangles.denominators.data[triangle],
                    &affine0, &affine1, &affine2, &z
                )) continue;
                weight0 = affine0; weight1 = affine1; weight2 = affine2;
                if (parameters[HAIR_PERSPECTIVE_CORRECT] != 0.0) {
                    double safe = fabs(z) < 1e-20 ? 1.0 : z;
                    weight0 = affine0 * screen[2] / safe;
                    weight1 = affine1 * screen[5] / safe;
                    weight2 = affine2 * screen[8] / safe;
                }
                for (component = 0; component < 3; ++component) {
                    double first_two = weight0 * normals[component] + weight1 * normals[3 + component];
                    shading_normal[component] = first_two + weight2 * normals[6 + component];
                }
                shading_length = norm3(shading_normal);
                if (shading_length == 0.0) shading_length = 1.0;
                shading_normal[0] /= shading_length;
                shading_normal[1] /= shading_length;
                shading_normal[2] /= shading_length;
                hemisphere = 0.5 + 0.5 * dot3(shading_normal, light);
                if (hemisphere < 0.0) hemisphere = 0.0;
                if (hemisphere > 1.0) hemisphere = 1.0;
                for (channel = 0; channel < 3; ++channel) {
                    double radiance = parameters[HAIR_AMBIENT_R + channel] +
                        parameters[HAIR_KEY_R + channel] * hemisphere;
                    double light_scale = parameters[HAIR_FRONT_R + channel] > 1e-12
                        ? radiance / parameters[HAIR_FRONT_R + channel] : 1.0;
                    source[channel] = parameters[HAIR_BASE_R + channel] * light_scale;
                }
                if (parameters[HAIR_EXECUTE_ANISOTROPY] != 0.0 && tangent_valid) {
                    double frame_normal[3] = {shading_normal[0], shading_normal[1], shading_normal[2]};
                    double normal_dot_tangent = dot3(frame_normal, tangent);
                    double tangent_field[3] = {
                        tangent[0] - frame_normal[0] * normal_dot_tangent,
                        tangent[1] - frame_normal[1] * normal_dot_tangent,
                        tangent[2] - frame_normal[2] * normal_dot_tangent
                    };
                    double bitangent[3], u01, v01, u, v, mim_sample[4], shift;
                    double shifted_axis[3], anisotangent[3], view_direction[3] = {0.0, 0.0, 1.0};
                    double half_vector[3], nh, sh, ah, scaled_sh, numerator, nh_squared, q, kernel, ndotl, lobe;
                    if (!normalize3_v2(tangent_field) || !normalize3_v2(frame_normal) ||
                        !normalize3_v2(tangent_field)) {
                        return LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE;
                    }
                    cross3(frame_normal, tangent_field, bitangent);
                    bitangent[0] *= handedness;
                    bitangent[1] *= handedness;
                    bitangent[2] *= handedness;
                    if (!normalize3_v2(bitangent)) return LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE;
                    u01 = weight0 * uv[0] + weight1 * uv[2];
                    v01 = weight0 * uv[1] + weight1 * uv[3];
                    u = u01 + weight2 * uv[4];
                    v = v01 + weight2 * uv[5];
                    sample_rgba(mim, mip_height, mip_width, u, v, 1, 1, mim_sample);
                    shift = (2.0 * mim_sample[2] - 1.0) *
                        parameters[HAIR_SHIFT_SCALE] + parameters[HAIR_SHIFT_OFFSET];
                    shifted_axis[0] = bitangent[0] + shift * frame_normal[0];
                    shifted_axis[1] = bitangent[1] + shift * frame_normal[1];
                    shifted_axis[2] = bitangent[2] + shift * frame_normal[2];
                    cross3(frame_normal, bitangent, anisotangent);
                    anisotangent[0] *= handedness;
                    anisotangent[1] *= handedness;
                    anisotangent[2] *= handedness;
                    if (!normalize3_v2(shifted_axis) || !normalize3_v2(anisotangent)) {
                        return LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE;
                    }
                    if (parameters[HAIR_HAS_CAMERA] != 0.0) {
                        for (component = 0; component < 3; ++component) {
                            double first_two = weight0 * vertices[component] +
                                weight1 * vertices[3 + component];
                            double fragment_position = first_two + weight2 * vertices[6 + component];
                            view_direction[component] = parameters[HAIR_CAMERA_X + component] - fragment_position;
                        }
                        {
                            double view_length = norm3(view_direction);
                            if (view_length != 0.0) {
                                view_direction[0] /= view_length;
                                view_direction[1] /= view_length;
                                view_direction[2] /= view_length;
                            }
                        }
                    }
                    half_vector[0] = parameters[HAIR_TITLE_VIEW_SCALE] * view_direction[0] + anisotropic_light[0];
                    half_vector[1] = parameters[HAIR_TITLE_VIEW_SCALE] * view_direction[1] + anisotropic_light[1];
                    half_vector[2] = parameters[HAIR_TITLE_VIEW_SCALE] * view_direction[2] + anisotropic_light[2];
                    if (!normalize3_v2(half_vector)) return LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE;
                    nh = dot3(frame_normal, half_vector);
                    sh = dot3(shifted_axis, half_vector);
                    ah = dot3(anisotangent, half_vector);
                    scaled_sh = sh * parameters[HAIR_INVERSE_R2];
                    numerator = ah * ah + scaled_sh * scaled_sh;
                    nh_squared = nh * nh;
                    q = nh_squared > 0.0 ? numerator / nh_squared : INFINITY;
                    kernel = exp(-q) * parameters[HAIR_KERNEL_FACTOR];
                    ndotl = dot3(frame_normal, anisotropic_light);
                    if (ndotl < 0.0) ndotl = 0.0;
                    lobe = kernel * mim_sample[1] * ndotl;
                    for (channel = 0; channel < 3; ++channel) {
                        source[channel] += parameters[HAIR_ANISO_R + channel] * lobe;
                    }
                }
                for (channel = 0; channel < 3; ++channel) {
                    if (!isfinite(source[channel])) return LTD_DRAW_RUNTIME_NONFINITE;
                    if (source[channel] < 0.0) source[channel] = 0.0;
                }
                write_fragment(attachments, x, y, source, z);
                ++written;
            }
        }
    }
    *written_fragments = written;
    return LTD_DRAW_RUNTIME_OK;
}

#if defined(_MSC_VER)
#pragma float_control(pop)
#endif
