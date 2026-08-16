#include "native_draw_runtime.h"

#include <fenv.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
#pragma float_control(precise, on, push)
#pragma fp_contract(off)
#endif

static int checked_mul(size_t left, size_t right, size_t *result) {
    if (left != 0 && right > SIZE_MAX / left) return 0;
    *result = left * right;
    return 1;
}

static int checked_add(size_t left, size_t right, size_t *result) {
    if (right > SIZE_MAX - left) return 0;
    *result = left + right;
    return 1;
}

static int aligned_double(const void *pointer) {
    return ((uintptr_t)pointer % (uintptr_t)sizeof(double)) == 0;
}

static int ranges_overlap(const void *a_pointer, size_t a_size, const void *b_pointer, size_t b_size) {
    uintptr_t a = (uintptr_t)a_pointer;
    uintptr_t b = (uintptr_t)b_pointer;
    if (a_size == 0 || b_size == 0) return 0;
    if (a > UINTPTR_MAX - a_size || b > UINTPTR_MAX - b_size) return 1;
    return a < b + b_size && b < a + a_size;
}

static ltd_draw_runtime_status require_rounding(void) {
    return fegetround() == FE_TONEAREST
        ? LTD_DRAW_RUNTIME_OK : LTD_DRAW_RUNTIME_ROUNDING_MODE;
}

static int expected_elements(size_t count, size_t per_item, size_t *result) {
    return checked_mul(count, per_item, result);
}

static ltd_draw_runtime_status validate_f64(
    const ltd_draw_const_f64_buffer *buffer, size_t expected
) {
    if (buffer == NULL || buffer->element_count != expected) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    if (expected == 0) return LTD_DRAW_RUNTIME_OK;
    if (buffer->data == NULL || !aligned_double(buffer->data)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    return LTD_DRAW_RUNTIME_OK;
}

static ltd_draw_runtime_status validate_i64(
    const ltd_draw_const_i64_buffer *buffer, size_t expected
) {
    if (buffer == NULL || buffer->element_count != expected) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    if (expected == 0) return LTD_DRAW_RUNTIME_OK;
    if (buffer->data == NULL || ((uintptr_t)buffer->data % sizeof(int64_t)) != 0) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    return LTD_DRAW_RUNTIME_OK;
}

static ltd_draw_runtime_status attachment_span(
    uint32_t width, uint32_t height, size_t channels, size_t stride,
    size_t capacity, const double *pointer, size_t *span
) {
    size_t row_elements = 0;
    size_t row_bytes = 0;
    size_t preceding = 0;
    if (pointer == NULL || !aligned_double(pointer) || stride % sizeof(double) != 0) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    if (!checked_mul((size_t)width, channels, &row_elements) ||
        !checked_mul(row_elements, sizeof(double), &row_bytes) || stride < row_bytes ||
        !checked_mul((size_t)(height - 1), stride, &preceding) ||
        !checked_add(preceding, row_bytes, span)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    return capacity < *span ? LTD_DRAW_RUNTIME_BUFFER_TOO_SMALL : LTD_DRAW_RUNTIME_OK;
}

static ltd_draw_runtime_status validate_attachments(
    const ltd_draw_attachments *attachments, size_t spans[3]
) {
    ltd_draw_runtime_status status;
    if (attachments == NULL || attachments->width == 0 || attachments->height == 0 ||
        attachments->width > LTD_DRAW_RUNTIME_MAX_DIMENSION ||
        attachments->height > LTD_DRAW_RUNTIME_MAX_DIMENSION) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    status = attachment_span(
        attachments->width, attachments->height, 3, attachments->color_row_stride_bytes,
        attachments->color_capacity_bytes, attachments->color, &spans[0]
    );
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = attachment_span(
        attachments->width, attachments->height, 1, attachments->depth_row_stride_bytes,
        attachments->depth_capacity_bytes, attachments->depth, &spans[1]
    );
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    if (attachments->alpha == NULL) {
        if (attachments->alpha_capacity_bytes != 0 || attachments->alpha_row_stride_bytes != 0) {
            return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
        }
        spans[2] = 0;
    } else {
        status = attachment_span(
            attachments->width, attachments->height, 1, attachments->alpha_row_stride_bytes,
            attachments->alpha_capacity_bytes, attachments->alpha, &spans[2]
        );
        if (status != LTD_DRAW_RUNTIME_OK) return status;
    }
    if (ranges_overlap(attachments->color, spans[0], attachments->depth, spans[1]) ||
        ranges_overlap(attachments->color, spans[0], attachments->alpha, spans[2]) ||
        ranges_overlap(attachments->depth, spans[1], attachments->alpha, spans[2])) {
        return LTD_DRAW_RUNTIME_BUFFER_ALIAS;
    }
    return LTD_DRAW_RUNTIME_OK;
}

static ltd_draw_runtime_status validate_triangles(
    const ltd_draw_triangle_batch *triangles, uint32_t width, uint32_t height
) {
    size_t count = 0;
    size_t screen_elements = 0;
    size_t bound_elements = 0;
    ltd_draw_runtime_status status;
    uint32_t triangle;
    if (triangles == NULL) return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    count = (size_t)triangles->triangle_count;
    if (!expected_elements(count, 9, &screen_elements) ||
        !expected_elements(count, 4, &bound_elements)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    status = validate_f64(&triangles->screen, screen_elements);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_i64(&triangles->bounds, bound_elements);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_f64(&triangles->denominators, count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    for (triangle = 0; triangle < triangles->triangle_count; ++triangle) {
        const int64_t *row = triangles->bounds.data + (size_t)triangle * 4;
        if (row[0] < 0 || row[2] < 0 || row[1] < row[0] || row[3] < row[2] ||
            row[1] >= (int64_t)width || row[3] >= (int64_t)height) {
            return LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE;
        }
    }
    return LTD_DRAW_RUNTIME_OK;
}

static ltd_draw_runtime_status validate_vec3(const double value[3]) {
    int component;
    if (value == NULL) return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    for (component = 0; component < 3; ++component) {
        if (!isfinite(value[component])) return LTD_DRAW_RUNTIME_NONFINITE;
    }
    return LTD_DRAW_RUNTIME_OK;
}

static ltd_draw_runtime_status validate_texture2d(const ltd_draw_texture2d *texture) {
    size_t count;
    if (texture == NULL || texture->width == 0 || texture->height == 0 ||
        texture->width > LTD_DRAW_RUNTIME_MAX_DIMENSION ||
        texture->height > LTD_DRAW_RUNTIME_MAX_DIMENSION ||
        texture->texels == NULL || !aligned_double(texture->texels) ||
        !checked_mul((size_t)texture->width, (size_t)texture->height, &count) ||
        texture->texel_count != count) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    return LTD_DRAW_RUNTIME_OK;
}

static ltd_draw_runtime_status validate_mip_bank(const ltd_draw_mip_bank *bank) {
    uint32_t level;
    if (bank == NULL || bank->texel_count == 0 || bank->level_count == 0 ||
        bank->texels == NULL || bank->levels == NULL ||
        !aligned_double(bank->texels) ||
        ((uintptr_t)bank->levels % sizeof(int64_t)) != 0) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    for (level = 0; level < bank->level_count; ++level) {
        int64_t offset = bank->levels[(size_t)level * 3];
        int64_t height = bank->levels[(size_t)level * 3 + 1];
        int64_t width = bank->levels[(size_t)level * 3 + 2];
        size_t area;
        if (offset < 0 || height <= 0 || width <= 0 ||
            (uint64_t)offset > (uint64_t)bank->texel_count ||
            !checked_mul((size_t)height, (size_t)width, &area) ||
            area > bank->texel_count - (size_t)offset) {
            return LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE;
        }
    }
    return LTD_DRAW_RUNTIME_OK;
}

static int64_t clamp_index(int64_t index, int64_t size) {
    if (index < 0) return 0;
    return index >= size ? size - 1 : index;
}

static int64_t wrapped_index(int64_t index, int64_t size, int mode) {
    if (mode == 0) return clamp_index(index, size);
    if (mode == 1) {
        int64_t repeated = index % size;
        return repeated < 0 ? repeated + size : repeated;
    }
    {
        int64_t period = size * 2;
        int64_t mirrored = index % period;
        if (mirrored < 0) mirrored += period;
        return mirrored < size ? mirrored : period - 1 - mirrored;
    }
}

static void sample_rgba(
    const double *source, int64_t height, int64_t width,
    double u, double v, int wrap_x, int wrap_y, double output[4]
) {
    double tex_x = u * (double)width - 0.5;
    double tex_y = (1.0 - v) * (double)height - 0.5;
    double floor_x = floor(tex_x);
    double floor_y = floor(tex_y);
    int64_t x0 = wrapped_index((int64_t)floor_x, width, wrap_x);
    int64_t x1 = wrapped_index((int64_t)floor_x + 1, width, wrap_x);
    int64_t y0 = wrapped_index((int64_t)floor_y, height, wrap_y);
    int64_t y1 = wrapped_index((int64_t)floor_y + 1, height, wrap_y);
    double x_amount = tex_x - floor_x;
    double y_amount = tex_y - floor_y;
    double inverse_x = 1.0 - x_amount;
    double inverse_y = 1.0 - y_amount;
    int channel;
    for (channel = 0; channel < 4; ++channel) {
        double top = source[((size_t)y0 * (size_t)width + (size_t)x0) * 4 + (size_t)channel] * inverse_x +
            source[((size_t)y0 * (size_t)width + (size_t)x1) * 4 + (size_t)channel] * x_amount;
        double bottom = source[((size_t)y1 * (size_t)width + (size_t)x0) * 4 + (size_t)channel] * inverse_x +
            source[((size_t)y1 * (size_t)width + (size_t)x1) * 4 + (size_t)channel] * x_amount;
        output[channel] = top * inverse_y + bottom * y_amount;
    }
}

static double dot3(const double left[3], const double right[3]) {
    double first_two = left[0] * right[0] + left[1] * right[1];
    return first_two + left[2] * right[2];
}

static void cross3(const double left[3], const double right[3], double output[3]) {
    output[0] = left[1] * right[2] - left[2] * right[1];
    output[1] = left[2] * right[0] - left[0] * right[2];
    output[2] = left[0] * right[1] - left[1] * right[0];
}

static double norm3(const double value[3]) {
    double first_two = value[0] * value[0] + value[1] * value[1];
    return sqrt(first_two + value[2] * value[2]);
}

static const double *depth_row(const ltd_draw_attachments *attachments, int y) {
    return (const double *)((const uint8_t *)attachments->depth +
        (size_t)y * attachments->depth_row_stride_bytes);
}

static int visible_lane(
    const double *screen, const ltd_draw_attachments *attachments,
    int x, int y, double denominator,
    double *weight0, double *weight1, double *weight2, double *z
) {
    double sample_x = (double)x + 0.5;
    double sample_y = (double)y + 0.5;
    double edge0_left = (sample_x - screen[3]) * (screen[7] - screen[4]);
    double edge0_right = (sample_y - screen[4]) * (screen[6] - screen[3]);
    double edge1_left;
    double edge1_right;
    double z01;
    *weight0 = (edge0_left - edge0_right) / denominator;
    edge1_left = (sample_x - screen[6]) * (screen[1] - screen[7]);
    edge1_right = (sample_y - screen[7]) * (screen[0] - screen[6]);
    *weight1 = (edge1_left - edge1_right) / denominator;
    *weight2 = (1.0 - *weight0) - *weight1;
    if (*weight0 < -1e-7 || *weight1 < -1e-7 || *weight2 < -1e-7) return 0;
    z01 = *weight0 * screen[2] + *weight1 * screen[5];
    *z = z01 + *weight2 * screen[8];
    return *z >= depth_row(attachments, y)[x];
}

static void lighting_constants(
    const double direction[3], const double light_color[3], const double ambient_color[3],
    double light_intensity, double ambient_intensity,
    double ambient[3], double key[3], double front[3]
) {
    double front_hemisphere = 0.5 + 0.5 * direction[2];
    int channel;
    if (front_hemisphere < 0.0) front_hemisphere = 0.0;
    else if (front_hemisphere > 1.0) front_hemisphere = 1.0;
    for (channel = 0; channel < 3; ++channel) {
        ambient[channel] = ambient_color[channel] * ambient_intensity;
        key[channel] = light_color[channel] * light_intensity;
        front[channel] = ambient[channel] + key[channel] * front_hemisphere;
    }
}

static void shade_plain(
    double source[3], const double normal[3], const double direction[3],
    const double ambient[3], const double key[3], const double front[3]
) {
    double hemisphere = 0.5 + 0.5 * dot3(normal, direction);
    int channel;
    if (hemisphere < 0.0) hemisphere = 0.0;
    else if (hemisphere > 1.0) hemisphere = 1.0;
    for (channel = 0; channel < 3; ++channel) {
        double light = 1.0;
        if (front[channel] > 1e-12) {
            double normal_radiance = ambient[channel] + key[channel] * hemisphere;
            light = normal_radiance / front[channel];
        }
        source[channel] *= light;
        if (source[channel] < 0.0) source[channel] = 0.0;
    }
}

static void write_fragment(
    ltd_draw_attachments *attachments, int x, int y,
    const double source[3], double z
) {
    double *color = (double *)((uint8_t *)attachments->color +
        (size_t)y * attachments->color_row_stride_bytes);
    double *depth = (double *)((uint8_t *)attachments->depth +
        (size_t)y * attachments->depth_row_stride_bytes);
    color[(size_t)x * 3] = source[0];
    color[(size_t)x * 3 + 1] = source[1];
    color[(size_t)x * 3 + 2] = source[2];
    if (attachments->alpha != NULL) {
        double *alpha = (double *)((uint8_t *)attachments->alpha +
            (size_t)y * attachments->alpha_row_stride_bytes);
        alpha[x] = 1.0;
    }
    depth[x] = z;
}

uint32_t LTD_DRAW_RUNTIME_CALL ltd_draw_runtime_abi_version(void) {
    return LTD_DRAW_RUNTIME_ABI_VERSION;
}

const char *LTD_DRAW_RUNTIME_CALL ltd_draw_runtime_contract_sha256(void) {
    return LTD_DRAW_RUNTIME_CONTRACT_SHA256;
}

const char *LTD_DRAW_RUNTIME_CALL ltd_draw_runtime_current_source_sha256(void) {
    return LTD_DRAW_RUNTIME_CURRENT_SOURCE_SHA256;
}

const char *LTD_DRAW_RUNTIME_CALL ltd_draw_runtime_opaque_source_sha256(void) {
    return LTD_DRAW_RUNTIME_OPAQUE_SOURCE_SHA256;
}

const char *LTD_DRAW_RUNTIME_CALL ltd_draw_runtime_status_name(ltd_draw_runtime_status status) {
    switch (status) {
        case LTD_DRAW_RUNTIME_OK: return "ok";
        case LTD_DRAW_RUNTIME_INVALID_ARGUMENT: return "invalid_argument";
        case LTD_DRAW_RUNTIME_BUFFER_TOO_SMALL: return "buffer_too_small";
        case LTD_DRAW_RUNTIME_NONFINITE: return "nonfinite";
        case LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE: return "value_out_of_range";
        case LTD_DRAW_RUNTIME_ROUNDING_MODE: return "rounding_mode";
        case LTD_DRAW_RUNTIME_ABI_MISMATCH: return "abi_mismatch";
        case LTD_DRAW_RUNTIME_CONTRACT_MISMATCH: return "contract_mismatch";
        case LTD_DRAW_RUNTIME_BUFFER_ALIAS: return "buffer_alias";
        default: return "unknown";
    }
}

ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL ltd_draw_runtime_require(
    uint32_t expected_abi, const char *expected_contract_sha256
) {
    if (expected_abi != LTD_DRAW_RUNTIME_ABI_VERSION) return LTD_DRAW_RUNTIME_ABI_MISMATCH;
    if (expected_contract_sha256 == NULL ||
        strcmp(expected_contract_sha256, LTD_DRAW_RUNTIME_CONTRACT_SHA256) != 0) {
        return LTD_DRAW_RUNTIME_CONTRACT_MISMATCH;
    }
    return LTD_DRAW_RUNTIME_OK;
}

ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL ltd_draw_plain_skin(
    ltd_draw_attachments *attachments,
    const ltd_draw_plain_skin_input *input,
    uint64_t *written_fragments
) {
    ltd_draw_runtime_status status = require_rounding();
    size_t spans[3];
    size_t normal_elements;
    double ambient[3], key[3], front[3];
    uint64_t written = 0;
    uint32_t triangle;
    if (written_fragments == NULL) return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    *written_fragments = 0;
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    if (input == NULL || input->reserved != 0 || input->perspective_correct != 1 ||
        !isfinite(input->light_intensity) || !isfinite(input->ambient_intensity)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    status = validate_attachments(attachments, spans);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_triangles(&input->triangles, attachments->width, attachments->height);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    if (!expected_elements((size_t)input->triangles.triangle_count, 9, &normal_elements)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    status = validate_f64(&input->vertex_normals, normal_elements);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->base_color_linear);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->light_direction);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->light_color);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->ambient_color);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    lighting_constants(
        input->light_direction, input->light_color, input->ambient_color,
        input->light_intensity, input->ambient_intensity, ambient, key, front
    );
    for (triangle = 0; triangle < input->triangles.triangle_count; ++triangle) {
        const double *screen = input->triangles.screen.data + (size_t)triangle * 9;
        const double *normals = input->vertex_normals.data + (size_t)triangle * 9;
        const int64_t *bounds = input->triangles.bounds.data + (size_t)triangle * 4;
        int x0 = (int)bounds[0], x1 = (int)bounds[1];
        int y0 = (int)bounds[2], y1 = (int)bounds[3];
        int y;
        for (y = y0; y <= y1; ++y) {
            int x;
            for (x = x0; x <= x1; ++x) {
                double affine0, affine1, affine2, z;
                double safe, weight0, weight1, weight2;
                double normal[3];
                double length;
                double source[3];
                int component;
                if (!visible_lane(
                    screen, attachments, x, y, input->triangles.denominators.data[triangle],
                    &affine0, &affine1, &affine2, &z
                )) continue;
                safe = fabs(z) < 1e-20 ? 1.0 : z;
                weight0 = affine0 * screen[2] / safe;
                weight1 = affine1 * screen[5] / safe;
                weight2 = affine2 * screen[8] / safe;
                for (component = 0; component < 3; ++component) {
                    double first_two = weight0 * normals[component] +
                        weight1 * normals[3 + component];
                    normal[component] = first_two + weight2 * normals[6 + component];
                }
                length = norm3(normal);
                if (length == 0.0) length = 1.0;
                for (component = 0; component < 3; ++component) normal[component] /= length;
                source[0] = input->base_color_linear[0];
                source[1] = input->base_color_linear[1];
                source[2] = input->base_color_linear[2];
                shade_plain(source, normal, input->light_direction, ambient, key, front);
                write_fragment(attachments, x, y, source, z);
                ++written;
            }
        }
    }
    *written_fragments = written;
    return LTD_DRAW_RUNTIME_OK;
}

static ltd_draw_runtime_status validate_body(const ltd_draw_body_input *input) {
    size_t count = (size_t)input->triangles.triangle_count;
    size_t nine, six;
    ltd_draw_runtime_status status;
    uint32_t triangle;
    if (!expected_elements(count, 9, &nine) || !expected_elements(count, 6, &six)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    status = validate_f64(&input->world_vertices, nine);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_f64(&input->vertex_normals, nine);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_f64(&input->material_uv, six);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_mip_bank(&input->albedo);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_mip_bank(&input->skin);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_mip_bank(&input->normal);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_i64(&input->albedo_lower_indices, count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_i64(&input->albedo_upper_indices, count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_f64(&input->albedo_mip_amounts, count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_i64(&input->skin_lower_indices, count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_i64(&input->skin_upper_indices, count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_f64(&input->skin_mip_amounts, count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_i64(&input->normal_level_indices, count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->face_color_linear);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->light_direction);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->light_color);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->ambient_color);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    for (triangle = 0; triangle < input->triangles.triangle_count; ++triangle) {
        int64_t al = input->albedo_lower_indices.data[triangle];
        int64_t au = input->albedo_upper_indices.data[triangle];
        int64_t sl = input->skin_lower_indices.data[triangle];
        int64_t su = input->skin_upper_indices.data[triangle];
        int64_t ni = input->normal_level_indices.data[triangle];
        double aa = input->albedo_mip_amounts.data[triangle];
        double sa = input->skin_mip_amounts.data[triangle];
        if (al < 0 || al >= input->albedo.level_count || au < 0 || au >= input->albedo.level_count ||
            sl < 0 || sl >= input->skin.level_count || su < 0 || su >= input->skin.level_count ||
            ni < 0 || ni >= input->normal.level_count ||
            !isfinite(aa) || aa < 0.0 || aa > 1.0 ||
            !isfinite(sa) || sa < 0.0 || sa > 1.0) {
            return LTD_DRAW_RUNTIME_VALUE_OUT_OF_RANGE;
        }
    }
    return LTD_DRAW_RUNTIME_OK;
}

ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL ltd_draw_body(
    ltd_draw_attachments *attachments,
    const ltd_draw_body_input *input,
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
    if (input == NULL || input->reserved != 0 || input->perspective_correct != 1 ||
        !isfinite(input->light_intensity) || !isfinite(input->ambient_intensity)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    status = validate_attachments(attachments, spans);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_triangles(&input->triangles, attachments->width, attachments->height);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_body(input);
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
        int x0 = (int)bounds[0], x1 = (int)bounds[1];
        int y0 = (int)bounds[2], y1 = (int)bounds[3];
        double edge1[3], edge2[3], geometric_normal[3];
        double tangent[3] = {0.0, 0.0, 0.0};
        double handedness = 1.0;
        int tangent_valid = 0;
        double delta1_u, delta1_v, delta2_u, delta2_v, tangent_determinant;
        int component;
        int64_t albedo_lower_index, albedo_upper_index, skin_lower_index, skin_upper_index, normal_index;
        const double *albedo_lower_texture, *albedo_upper_texture, *skin_lower_texture, *skin_upper_texture, *normal_texture;
        int64_t albedo_lower_height, albedo_lower_width, albedo_upper_height, albedo_upper_width;
        int64_t skin_lower_height, skin_lower_width, skin_upper_height, skin_upper_width, normal_height, normal_width;
        double albedo_amount, skin_amount;
        int y;
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
        tangent_determinant = delta1_u * delta2_v - delta2_u * delta1_v;
        if (fabs(tangent_determinant) > 1e-12) {
            double raw_bitangent[3];
            double tangent_length;
            for (component = 0; component < 3; ++component) {
                tangent[component] =
                    (edge1[component] * delta2_v - edge2[component] * delta1_v) / tangent_determinant;
                raw_bitangent[component] =
                    (-edge1[component] * delta2_u + edge2[component] * delta1_u) / tangent_determinant;
            }
            tangent_length = norm3(tangent);
            if (tangent_length > 1e-12) {
                double cross_value[3];
                double sign_value;
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
        skin_lower_index = input->skin_lower_indices.data[triangle];
        skin_upper_index = input->skin_upper_indices.data[triangle];
        normal_index = input->normal_level_indices.data[triangle];
        albedo_lower_texture = input->albedo.texels + (size_t)input->albedo.levels[(size_t)albedo_lower_index * 3] * 4;
        albedo_upper_texture = input->albedo.texels + (size_t)input->albedo.levels[(size_t)albedo_upper_index * 3] * 4;
        skin_lower_texture = input->skin.texels + (size_t)input->skin.levels[(size_t)skin_lower_index * 3] * 4;
        skin_upper_texture = input->skin.texels + (size_t)input->skin.levels[(size_t)skin_upper_index * 3] * 4;
        normal_texture = input->normal.texels + (size_t)input->normal.levels[(size_t)normal_index * 3] * 4;
        albedo_lower_height = input->albedo.levels[(size_t)albedo_lower_index * 3 + 1];
        albedo_lower_width = input->albedo.levels[(size_t)albedo_lower_index * 3 + 2];
        albedo_upper_height = input->albedo.levels[(size_t)albedo_upper_index * 3 + 1];
        albedo_upper_width = input->albedo.levels[(size_t)albedo_upper_index * 3 + 2];
        skin_lower_height = input->skin.levels[(size_t)skin_lower_index * 3 + 1];
        skin_lower_width = input->skin.levels[(size_t)skin_lower_index * 3 + 2];
        skin_upper_height = input->skin.levels[(size_t)skin_upper_index * 3 + 1];
        skin_upper_width = input->skin.levels[(size_t)skin_upper_index * 3 + 2];
        normal_height = input->normal.levels[(size_t)normal_index * 3 + 1];
        normal_width = input->normal.levels[(size_t)normal_index * 3 + 2];
        albedo_amount = input->albedo_mip_amounts.data[triangle];
        skin_amount = input->skin_mip_amounts.data[triangle];
        for (y = y0; y <= y1; ++y) {
            int x;
            for (x = x0; x <= x1; ++x) {
                double affine0, affine1, affine2, z, safe, weight0, weight1, weight2;
                double u01, u, v01, v;
                double albedo_lower_sample[4], albedo_upper_sample[4];
                double skin_lower_sample[4], skin_upper_sample[4], normal_sample[4];
                double albedo_inverse, skin_inverse, skin_g;
                double source[3], shading_normal[3];
                double normal_x, normal_y, xy_length, xy_denominator, xy_scale, z_squared, normal_z;
                double shading_length;
                int channel;
                if (!visible_lane(
                    screen, attachments, x, y, input->triangles.denominators.data[triangle],
                    &affine0, &affine1, &affine2, &z
                )) continue;
                safe = fabs(z) < 1e-20 ? 1.0 : z;
                weight0 = affine0 * screen[2] / safe;
                weight1 = affine1 * screen[5] / safe;
                weight2 = affine2 * screen[8] / safe;
                u01 = weight0 * uv[0] + weight1 * uv[2];
                u = u01 + weight2 * uv[4];
                v01 = weight0 * uv[1] + weight1 * uv[3];
                v = v01 + weight2 * uv[5];
                sample_rgba(albedo_lower_texture, albedo_lower_height, albedo_lower_width, u, v, 0, 0, albedo_lower_sample);
                sample_rgba(albedo_upper_texture, albedo_upper_height, albedo_upper_width, u, v, 0, 0, albedo_upper_sample);
                sample_rgba(skin_lower_texture, skin_lower_height, skin_lower_width, u, v, 0, 0, skin_lower_sample);
                sample_rgba(skin_upper_texture, skin_upper_height, skin_upper_width, u, v, 0, 0, skin_upper_sample);
                sample_rgba(normal_texture, normal_height, normal_width, u, v, 0, 0, normal_sample);
                albedo_inverse = 1.0 - albedo_amount;
                skin_inverse = 1.0 - skin_amount;
                skin_g = skin_lower_sample[1] * skin_inverse + skin_upper_sample[1] * skin_amount;
                for (channel = 0; channel < 3; ++channel) {
                    double albedo = albedo_lower_sample[channel] * albedo_inverse +
                        albedo_upper_sample[channel] * albedo_amount;
                    source[channel] = input->face_color_linear[channel] +
                        (albedo - input->face_color_linear[channel]) * skin_g;
                }
                for (component = 0; component < 3; ++component) {
                    double first_two = weight0 * normals[component] + weight1 * normals[3 + component];
                    shading_normal[component] = first_two + weight2 * normals[6 + component];
                }
                shading_length = norm3(shading_normal);
                if (shading_length == 0.0) shading_length = 1.0;
                for (component = 0; component < 3; ++component) shading_normal[component] /= shading_length;
                normal_x = normal_sample[0] * 2.0 - 1.0;
                normal_y = normal_sample[1] * 2.0 - 1.0;
                xy_length = sqrt(normal_x * normal_x + normal_y * normal_y);
                xy_denominator = xy_length > 1e-12 ? xy_length : 1e-12;
                xy_scale = 0.999999 / xy_denominator;
                if (xy_scale > 1.0) xy_scale = 1.0;
                normal_x *= xy_scale;
                normal_y *= xy_scale;
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
                        first_two = tangent_field[component] * normal_x +
                            bitangent_field[component] * normal_y;
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

ltd_draw_runtime_status LTD_DRAW_RUNTIME_CALL ltd_draw_mask0(
    ltd_draw_attachments *attachments,
    const ltd_draw_mask0_input *input,
    uint64_t *written_fragments
) {
    ltd_draw_runtime_status status = require_rounding();
    size_t spans[3], normals_count, uv_count;
    int perspective, mode;
    double ambient[3], key[3], front[3];
    uint64_t written = 0;
    uint32_t triangle;
    int parameter;
    if (written_fragments == NULL) return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    *written_fragments = 0;
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    if (input == NULL) return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    status = validate_attachments(attachments, spans);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_triangles(&input->triangles, attachments->width, attachments->height);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    if (!expected_elements((size_t)input->triangles.triangle_count, 9, &normals_count) ||
        !expected_elements((size_t)input->triangles.triangle_count, 6, &uv_count)) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    status = validate_f64(&input->vertex_normals, normals_count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_f64(&input->material_uv, uv_count);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_texture2d(&input->generated_texture);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_texture2d(&input->user_texture);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->light_direction);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->light_color);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    status = validate_vec3(input->ambient_color);
    if (status != LTD_DRAW_RUNTIME_OK) return status;
    for (parameter = 0; parameter < 10; ++parameter) {
        if (!isfinite(input->parameters[parameter])) return LTD_DRAW_RUNTIME_NONFINITE;
    }
    perspective = (int)input->parameters[2];
    mode = (int)input->parameters[3];
    if ((perspective != 0 && perspective != 1) || (mode != 0 && mode != 1) ||
        input->parameters[2] != (double)perspective || input->parameters[3] != (double)mode) {
        return LTD_DRAW_RUNTIME_INVALID_ARGUMENT;
    }
    lighting_constants(
        input->light_direction, input->light_color, input->ambient_color,
        input->parameters[0], input->parameters[1], ambient, key, front
    );
    for (triangle = 0; triangle < input->triangles.triangle_count; ++triangle) {
        const double *screen = input->triangles.screen.data + (size_t)triangle * 9;
        const double *normals = input->vertex_normals.data + (size_t)triangle * 9;
        const double *uv = input->material_uv.data + (size_t)triangle * 6;
        const int64_t *bounds = input->triangles.bounds.data + (size_t)triangle * 4;
        int x0 = (int)bounds[0], x1 = (int)bounds[1];
        int y0 = (int)bounds[2], y1 = (int)bounds[3];
        int y;
        for (y = y0; y <= y1; ++y) {
            int x;
            for (x = x0; x <= x1; ++x) {
                double affine0, affine1, affine2, z;
                double weight0, weight1, weight2;
                double u01, u, v01, v;
                double generated_sample[4], user_sample[4];
                double k, source[3], emission[3], shading_normal[3], normal_length;
                int channel, component;
                if (!visible_lane(
                    screen, attachments, x, y, input->triangles.denominators.data[triangle],
                    &affine0, &affine1, &affine2, &z
                )) continue;
                weight0 = affine0; weight1 = affine1; weight2 = affine2;
                if (perspective) {
                    double safe = fabs(z) < 1e-20 ? 1.0 : z;
                    weight0 = affine0 * screen[2] / safe;
                    weight1 = affine1 * screen[5] / safe;
                    weight2 = affine2 * screen[8] / safe;
                }
                u01 = weight0 * uv[0] + weight1 * uv[2];
                u = u01 + weight2 * uv[4];
                v01 = weight0 * uv[1] + weight1 * uv[3];
                v = v01 + weight2 * uv[5];
                sample_rgba(
                    input->generated_texture.texels, input->generated_texture.height,
                    input->generated_texture.width, u, v, mode, mode, generated_sample
                );
                if (mode) {
                    double bfres_v = 1.0 - v;
                    double mapped_u = input->parameters[4] * u +
                        input->parameters[5] * bfres_v + input->parameters[6];
                    double mapped_bfres_v = input->parameters[7] * u +
                        input->parameters[8] * bfres_v + input->parameters[9];
                    sample_rgba(
                        input->user_texture.texels, input->user_texture.height,
                        input->user_texture.width, mapped_u, 1.0 - mapped_bfres_v,
                        0, 0, user_sample
                    );
                    if (!(generated_sample[3] >= 0.5 || user_sample[3] >= 0.5)) continue;
                } else {
                    user_sample[0] = 0.21586050011389926;
                    user_sample[1] = 0.21586050011389926;
                    user_sample[2] = 0.21586050011389926;
                    user_sample[3] = 1.0;
                    if (!(generated_sample[3] >= 0.5)) continue;
                }
                k = input->triangles.denominators.data[triangle] > 0.0
                    ? (generated_sample[3] > 0.0 ? generated_sample[3] : 0.0) : 0.0;
                for (channel = 0; channel < 3; ++channel) {
                    source[channel] = user_sample[channel] +
                        (generated_sample[channel] - user_sample[channel]) * k;
                    emission[channel] = generated_sample[channel] * generated_sample[3] * 0.1;
                }
                for (component = 0; component < 3; ++component) {
                    double first_two = weight0 * normals[component] + weight1 * normals[3 + component];
                    shading_normal[component] = first_two + weight2 * normals[6 + component];
                }
                normal_length = sqrt(
                    (shading_normal[0] * shading_normal[0] + shading_normal[1] * shading_normal[1]) +
                    shading_normal[2] * shading_normal[2]
                );
                if (normal_length == 0.0) normal_length = 1.0;
                for (component = 0; component < 3; ++component) shading_normal[component] /= normal_length;
                {
                    double hemisphere = 0.5 + 0.5 * dot3(shading_normal, input->light_direction);
                    if (hemisphere < 0.0) hemisphere = 0.0;
                    else if (hemisphere > 1.0) hemisphere = 1.0;
                    for (channel = 0; channel < 3; ++channel) {
                        double light = 1.0;
                        if (front[channel] > 1e-12) {
                            double normal_radiance = ambient[channel] + key[channel] * hemisphere;
                            light = normal_radiance / front[channel];
                        }
                        source[channel] *= light;
                        source[channel] += emission[channel];
                        if (source[channel] < 0.0) source[channel] = 0.0;
                    }
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
