#include "native_face_runtime.h"

#include <fenv.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
#pragma float_control(precise, on, push)
#pragma fp_contract(off)
#endif

static int checked_mul_size(size_t left, size_t right, size_t *result) {
    if (left != 0 && right > SIZE_MAX / left) return 0;
    *result = left * right;
    return 1;
}

static int checked_add_size(size_t left, size_t right, size_t *result) {
    if (right > SIZE_MAX - left) return 0;
    *result = left + right;
    return 1;
}

static int image_span(
    uint32_t width,
    uint32_t height,
    size_t bytes_per_pixel,
    size_t row_stride,
    size_t *span
) {
    size_t row_bytes = 0;
    size_t preceding_rows = 0;
    if (width == 0 || height == 0) return 0;
    if (!checked_mul_size((size_t)width, bytes_per_pixel, &row_bytes)) return 0;
    if (row_stride < row_bytes) return 0;
    if (!checked_mul_size((size_t)(height - 1), row_stride, &preceding_rows)) return 0;
    return checked_add_size(preceding_rows, row_bytes, span);
}

static int stack_span(
    uint32_t layer_count,
    uint32_t width,
    uint32_t height,
    size_t row_stride,
    size_t layer_stride,
    size_t *span
) {
    size_t one_layer = 0;
    size_t preceding_layers = 0;
    if (layer_count == 0) {
        *span = 0;
        return 1;
    }
    if (!image_span(width, height, 4, row_stride, &one_layer)) return 0;
    if (layer_stride < one_layer) return 0;
    if (!checked_mul_size((size_t)(layer_count - 1), layer_stride, &preceding_layers)) {
        return 0;
    }
    return checked_add_size(preceding_layers, one_layer, span);
}

static int pointer_aligned_for_double(const void *pointer) {
    return ((uintptr_t)pointer % (uintptr_t)sizeof(double)) == 0;
}

static int ranges_overlap(
    const void *left_pointer,
    size_t left_size,
    const void *right_pointer,
    size_t right_size
) {
    uintptr_t left = (uintptr_t)left_pointer;
    uintptr_t right = (uintptr_t)right_pointer;
    if (left_size == 0 || right_size == 0) return 0;
    if (left > UINTPTR_MAX - left_size || right > UINTPTR_MAX - right_size) return 1;
    return left < right + right_size && right < left + left_size;
}

static ltd_face_runtime_status require_round_to_nearest(void) {
    return fegetround() == FE_TONEAREST
        ? LTD_FACE_RUNTIME_OK
        : LTD_FACE_RUNTIME_ROUNDING_MODE;
}

static ltd_face_runtime_status validate_dimensions(uint32_t width, uint32_t height) {
    if (
        width == 0 || height == 0 ||
        width > LTD_FACE_RUNTIME_MAX_DIMENSION ||
        height > LTD_FACE_RUNTIME_MAX_DIMENSION
    ) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    return LTD_FACE_RUNTIME_OK;
}

static ltd_face_runtime_status validate_const_rgba8(
    const ltd_face_const_rgba8_image *image,
    uint32_t expected_width,
    uint32_t expected_height,
    size_t *span
) {
    if (
        image == NULL || image->pixels == NULL ||
        image->width != expected_width || image->height != expected_height
    ) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    if (!image_span(
        image->width, image->height, 4, image->row_stride_bytes, span
    )) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    if (image->buffer_size_bytes < *span) return LTD_FACE_RUNTIME_BUFFER_TOO_SMALL;
    return LTD_FACE_RUNTIME_OK;
}

static ltd_face_runtime_status validate_rgba8(
    const ltd_face_rgba8_image *image,
    uint32_t expected_width,
    uint32_t expected_height,
    size_t *span
) {
    if (
        image == NULL || image->pixels == NULL ||
        image->width != expected_width || image->height != expected_height
    ) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    if (!image_span(
        image->width, image->height, 4, image->row_stride_bytes, span
    )) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    if (image->buffer_size_bytes < *span) return LTD_FACE_RUNTIME_BUFFER_TOO_SMALL;
    return LTD_FACE_RUNTIME_OK;
}

static ltd_face_runtime_status validate_const_rgba64(
    const ltd_face_const_rgba64_image *image,
    uint32_t expected_width,
    uint32_t expected_height,
    size_t *span
) {
    size_t pixel_bytes = 0;
    if (
        image == NULL || image->pixels == NULL ||
        image->width != expected_width || image->height != expected_height ||
        !pointer_aligned_for_double(image->pixels) ||
        image->row_stride_bytes % sizeof(double) != 0
    ) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    if (!checked_mul_size(4, sizeof(double), &pixel_bytes)) {
        return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    }
    if (!image_span(
        image->width, image->height, pixel_bytes, image->row_stride_bytes, span
    )) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    if (image->buffer_size_bytes < *span) return LTD_FACE_RUNTIME_BUFFER_TOO_SMALL;
    return LTD_FACE_RUNTIME_OK;
}

static ltd_face_runtime_status validate_rgba64(
    const ltd_face_rgba64_image *image,
    size_t *span
) {
    size_t pixel_bytes = 0;
    ltd_face_runtime_status status = validate_dimensions(image == NULL ? 0 : image->width,
                                                         image == NULL ? 0 : image->height);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    if (
        image->pixels == NULL || !pointer_aligned_for_double(image->pixels) ||
        image->row_stride_bytes % sizeof(double) != 0
    ) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    if (!checked_mul_size(4, sizeof(double), &pixel_bytes)) {
        return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    }
    if (!image_span(
        image->width, image->height, pixel_bytes, image->row_stride_bytes, span
    )) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    if (image->buffer_size_bytes < *span) return LTD_FACE_RUNTIME_BUFFER_TOO_SMALL;
    return LTD_FACE_RUNTIME_OK;
}

static ltd_face_runtime_status validate_stack(
    const ltd_face_rgba8_stack *stack,
    uint32_t layer_count,
    uint32_t width,
    uint32_t height,
    size_t *span
) {
    if (stack == NULL) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    if (layer_count == 0) {
        if (stack->pixels != NULL || stack->buffer_size_bytes != 0) {
            return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
        }
        *span = 0;
        return LTD_FACE_RUNTIME_OK;
    }
    if (stack->pixels == NULL) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    if (!stack_span(
        layer_count, width, height, stack->row_stride_bytes,
        stack->layer_stride_bytes, span
    )) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    if (stack->buffer_size_bytes < *span) return LTD_FACE_RUNTIME_BUFFER_TOO_SMALL;
    return LTD_FACE_RUNTIME_OK;
}

static unsigned char store_unorm8(double value) {
    if (value <= 0.0) return 0;
    if (value >= 1.0) return 255;
    return (unsigned char)nearbyint(value * 255.0);
}

static void zero_rgba8_rows(ltd_face_rgba8_image *image) {
    size_t row_bytes = (size_t)image->width * 4;
    uint32_t y = 0;
    for (y = 0; y < image->height; ++y) {
        memset(image->pixels + (size_t)y * image->row_stride_bytes, 0, row_bytes);
    }
}

static void zero_rgba64_rows(ltd_face_rgba64_image *image) {
    size_t row_bytes = (size_t)image->width * 4 * sizeof(double);
    uint32_t y = 0;
    for (y = 0; y < image->height; ++y) {
        memset((uint8_t *)image->pixels + (size_t)y * image->row_stride_bytes, 0, row_bytes);
    }
}

static void copy_rgba8_rows(
    ltd_face_rgba8_image *destination,
    const ltd_face_rgba8_image *source
) {
    size_t row_bytes = (size_t)source->width * 4;
    uint32_t y = 0;
    for (y = 0; y < source->height; ++y) {
        memcpy(
            destination->pixels + (size_t)y * destination->row_stride_bytes,
            source->pixels + (size_t)y * source->row_stride_bytes,
            row_bytes
        );
    }
}

static void copy_image_to_stack_layer(
    ltd_face_rgba8_stack *destination,
    uint32_t layer,
    const ltd_face_rgba8_image *source
) {
    size_t row_bytes = (size_t)source->width * 4;
    uint8_t *layer_base = destination->pixels + (size_t)layer * destination->layer_stride_bytes;
    uint32_t y = 0;
    for (y = 0; y < source->height; ++y) {
        memcpy(
            layer_base + (size_t)y * destination->row_stride_bytes,
            source->pixels + (size_t)y * source->row_stride_bytes,
            row_bytes
        );
    }
}

uint32_t LTD_FACE_RUNTIME_CALL ltd_face_runtime_abi_version(void) {
    return LTD_FACE_RUNTIME_ABI_VERSION;
}

const char *LTD_FACE_RUNTIME_CALL ltd_face_runtime_contract_sha256(void) {
    return LTD_FACE_RUNTIME_CONTRACT_SHA256;
}

const char *LTD_FACE_RUNTIME_CALL ltd_face_runtime_oracle_source_sha256(void) {
    return LTD_FACE_RUNTIME_ORACLE_SOURCE_SHA256;
}

const char *LTD_FACE_RUNTIME_CALL ltd_face_runtime_status_name(
    ltd_face_runtime_status status
) {
    switch (status) {
        case LTD_FACE_RUNTIME_OK: return "ok";
        case LTD_FACE_RUNTIME_INVALID_ARGUMENT: return "invalid_argument";
        case LTD_FACE_RUNTIME_BUFFER_TOO_SMALL: return "buffer_too_small";
        case LTD_FACE_RUNTIME_NONFINITE: return "nonfinite";
        case LTD_FACE_RUNTIME_VALUE_OUT_OF_RANGE: return "value_out_of_range";
        case LTD_FACE_RUNTIME_ROUNDING_MODE: return "rounding_mode";
        case LTD_FACE_RUNTIME_ABI_MISMATCH: return "abi_mismatch";
        case LTD_FACE_RUNTIME_CONTRACT_MISMATCH: return "contract_mismatch";
        case LTD_FACE_RUNTIME_BUFFER_ALIAS: return "buffer_alias";
        default: return "unknown";
    }
}

ltd_face_runtime_status LTD_FACE_RUNTIME_CALL ltd_face_runtime_require(
    uint32_t expected_abi_version,
    const char *expected_contract_sha256
) {
    if (expected_abi_version != LTD_FACE_RUNTIME_ABI_VERSION) {
        return LTD_FACE_RUNTIME_ABI_MISMATCH;
    }
    if (
        expected_contract_sha256 == NULL ||
        strcmp(expected_contract_sha256, LTD_FACE_RUNTIME_CONTRACT_SHA256) != 0
    ) return LTD_FACE_RUNTIME_CONTRACT_MISMATCH;
    return LTD_FACE_RUNTIME_OK;
}

ltd_face_runtime_status LTD_FACE_RUNTIME_CALL ltd_face_mask_pipeline(
    const ltd_face_mask_layer *layers,
    uint32_t layer_count,
    uint32_t width,
    uint32_t height,
    ltd_face_rgba8_image *pass0,
    ltd_face_rgba8_image *case21,
    ltd_face_rgba8_image *final_target,
    ltd_face_rgba8_image *mesh_input,
    ltd_face_rgba8_stack *pass0_audit,
    ltd_face_rgba8_stack *pass1_audit
) {
    ltd_face_runtime_status status = require_round_to_nearest();
    size_t layer_spans[LTD_FACE_RUNTIME_MAX_MASK_LAYERS];
    size_t output_spans[6];
    const void *output_pointers[6];
    uint32_t index = 0;
    uint32_t other = 0;
    int32_t previous_case = -1;
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_dimensions(width, height);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    if (layer_count > LTD_FACE_RUNTIME_MAX_MASK_LAYERS) {
        return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    }
    if (layer_count != 0 && layers == NULL) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;

    status = validate_rgba8(pass0, width, height, &output_spans[0]);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_rgba8(case21, width, height, &output_spans[1]);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_rgba8(final_target, width, height, &output_spans[2]);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_rgba8(mesh_input, width, height, &output_spans[3]);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_stack(pass0_audit, layer_count, width, height, &output_spans[4]);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_stack(pass1_audit, layer_count, width, height, &output_spans[5]);
    if (status != LTD_FACE_RUNTIME_OK) return status;

    output_pointers[0] = pass0->pixels;
    output_pointers[1] = case21->pixels;
    output_pointers[2] = final_target->pixels;
    output_pointers[3] = mesh_input->pixels;
    output_pointers[4] = pass0_audit->pixels;
    output_pointers[5] = pass1_audit->pixels;
    for (index = 0; index < 6; ++index) {
        for (other = index + 1; other < 6; ++other) {
            if (ranges_overlap(
                output_pointers[index], output_spans[index],
                output_pointers[other], output_spans[other]
            )) return LTD_FACE_RUNTIME_BUFFER_ALIAS;
        }
    }

    for (index = 0; index < layer_count; ++index) {
        if (
            layers[index].reserved != 0 ||
            layers[index].dispatcher_case <= previous_case ||
            layers[index].dispatcher_case > 20
        ) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
        previous_case = layers[index].dispatcher_case;
        status = validate_const_rgba64(
            &layers[index].image, width, height, &layer_spans[index]
        );
        if (status != LTD_FACE_RUNTIME_OK) return status;
        for (other = 0; other < 6; ++other) {
            if (ranges_overlap(
                layers[index].image.pixels, layer_spans[index],
                output_pointers[other], output_spans[other]
            )) return LTD_FACE_RUNTIME_BUFFER_ALIAS;
        }
    }

    zero_rgba8_rows(pass0);
    zero_rgba8_rows(case21);
    zero_rgba8_rows(final_target);
    zero_rgba8_rows(mesh_input);

    /* Pass 0: RGB ONE/ZERO, alpha ONE/ONE, store after every draw. */
    for (index = 0; index < layer_count; ++index) {
        uint32_t y = 0;
        for (y = 0; y < height; ++y) {
            const double *source_row = (const double *)(
                (const uint8_t *)layers[index].image.pixels +
                (size_t)y * layers[index].image.row_stride_bytes
            );
            uint8_t *target_row = pass0->pixels + (size_t)y * pass0->row_stride_bytes;
            uint32_t x = 0;
            for (x = 0; x < width; ++x) {
                size_t offset = (size_t)x * 4;
                double r = source_row[offset + 0];
                double g = source_row[offset + 1];
                double b = source_row[offset + 2];
                double a = source_row[offset + 3];
                if (!isfinite(r) || !isfinite(g) || !isfinite(b) || !isfinite(a)) {
                    return LTD_FACE_RUNTIME_NONFINITE;
                }
                if (a < 0.0 || a > 1.0) return LTD_FACE_RUNTIME_VALUE_OUT_OF_RANGE;
                if (a != 0.0) {
                    double destination_alpha = 0.0;
                    target_row[offset + 0] = store_unorm8(r);
                    target_row[offset + 1] = store_unorm8(g);
                    target_row[offset + 2] = store_unorm8(b);
                    destination_alpha = (double)target_row[offset + 3] / 255.0;
                    target_row[offset + 3] = store_unorm8(a + destination_alpha);
                }
            }
        }
        copy_image_to_stack_layer(pass0_audit, index, pass0);
    }

    {
        uint32_t y = 0;
        for (y = 0; y < height; ++y) {
            uint8_t *row = case21->pixels + (size_t)y * case21->row_stride_bytes;
            uint32_t x = 0;
            for (x = 0; x < width; ++x) row[(size_t)x * 4 + 3] = 255;
        }
    }
    copy_rgba8_rows(final_target, case21);

    /* Pass 1: RGB ONE/ONE_MINUS_SRC_ALPHA, alpha ONE/ONE. */
    for (index = 0; index < layer_count; ++index) {
        uint32_t y = 0;
        for (y = 0; y < height; ++y) {
            const double *source_row = (const double *)(
                (const uint8_t *)layers[index].image.pixels +
                (size_t)y * layers[index].image.row_stride_bytes
            );
            uint8_t *target_row = final_target->pixels +
                (size_t)y * final_target->row_stride_bytes;
            uint32_t x = 0;
            for (x = 0; x < width; ++x) {
                size_t offset = (size_t)x * 4;
                double a = source_row[offset + 3];
                if (a != 0.0) {
                    double inverse_alpha = 1.0 - a;
                    double destination_r = (double)target_row[offset + 0] / 255.0;
                    double destination_g = (double)target_row[offset + 1] / 255.0;
                    double destination_b = (double)target_row[offset + 2] / 255.0;
                    double destination_a = (double)target_row[offset + 3] / 255.0;
                    target_row[offset + 0] = store_unorm8(
                        source_row[offset + 0] + destination_r * inverse_alpha
                    );
                    target_row[offset + 1] = store_unorm8(
                        source_row[offset + 1] + destination_g * inverse_alpha
                    );
                    target_row[offset + 2] = store_unorm8(
                        source_row[offset + 2] + destination_b * inverse_alpha
                    );
                    target_row[offset + 3] = store_unorm8(a + destination_a);
                }
            }
        }
        copy_image_to_stack_layer(pass1_audit, index, final_target);
    }

    copy_rgba8_rows(mesh_input, final_target);
    {
        uint32_t y = 0;
        for (y = 0; y < height; ++y) {
            uint8_t *mesh_row = mesh_input->pixels +
                (size_t)y * mesh_input->row_stride_bytes;
            const uint8_t *pass0_row = pass0->pixels +
                (size_t)y * pass0->row_stride_bytes;
            uint32_t x = 0;
            for (x = 0; x < width; ++x) {
                size_t offset = (size_t)x * 4;
                mesh_row[offset + 3] = pass0_row[offset + 3];
                if (mesh_row[offset + 3] == 0) {
                    mesh_row[offset + 0] = 0;
                    mesh_row[offset + 1] = 0;
                    mesh_row[offset + 2] = 0;
                }
            }
        }
    }
    return LTD_FACE_RUNTIME_OK;
}

static double source_float_plane_value(
    const ltd_face_const_rgba8_image *source,
    int x,
    int y,
    int channel,
    int mirrored
) {
    int source_x = mirrored ? (int)source->width - 1 - x : x;
    const uint8_t *row = source->pixels + (size_t)y * source->row_stride_bytes;
    uint8_t value = row[(size_t)source_x * 4 + (size_t)channel];
    float normalized = (float)value / 255.0f;
    return (double)normalized;
}

static double source_byte_value(
    const ltd_face_const_rgba8_image *source,
    int x,
    int y,
    int channel,
    int mirrored
) {
    int source_x = mirrored ? (int)source->width - 1 - x : x;
    const uint8_t *row = source->pixels + (size_t)y * source->row_stride_bytes;
    return (double)row[(size_t)source_x * 4 + (size_t)channel];
}

ltd_face_runtime_status LTD_FACE_RUNTIME_CALL ltd_face_mask_sample_affine(
    const ltd_face_const_rgba8_image *source,
    const double affine[6],
    int32_t mirrored,
    int32_t float_planes,
    ltd_face_rgba64_image *output
) {
    ltd_face_runtime_status status = require_round_to_nearest();
    size_t source_span = 0;
    size_t output_span = 0;
    uint32_t coefficient = 0;
    uint32_t y = 0;
    if (status != LTD_FACE_RUNTIME_OK) return status;
    if (source == NULL) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    status = validate_dimensions(source->width, source->height);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_const_rgba8(source, source->width, source->height, &source_span);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_rgba64(output, &output_span);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    if (
        affine == NULL || (mirrored != 0 && mirrored != 1) ||
        (float_planes != 0 && float_planes != 1)
    ) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    for (coefficient = 0; coefficient < 6; ++coefficient) {
        if (!isfinite(affine[coefficient])) return LTD_FACE_RUNTIME_NONFINITE;
    }
    if (ranges_overlap(source->pixels, source_span, output->pixels, output_span)) {
        return LTD_FACE_RUNTIME_BUFFER_ALIAS;
    }
    zero_rgba64_rows(output);
    for (y = 0; y < output->height; ++y) {
        double destination_y = (double)y + 0.5;
        double *output_row = (double *)(
            (uint8_t *)output->pixels + (size_t)y * output->row_stride_bytes
        );
        uint32_t x = 0;
        for (x = 0; x < output->width; ++x) {
            double destination_x = (double)x + 0.5;
            double source_x = affine[0] * destination_x +
                affine[1] * destination_y + affine[2];
            double source_y = affine[3] * destination_x +
                affine[4] * destination_y + affine[5];
            int x0 = 0;
            int y0 = 0;
            double dx = 0.0;
            double dy = 0.0;
            int xa = 0;
            int xb0 = 0;
            int xb = 0;
            int ya = 0;
            int yb0 = 0;
            int yb = 0;
            int channel = 0;
            size_t output_offset = (size_t)x * 4;
            if (
                source_x < 0.0 || source_x >= (double)source->width ||
                source_y < 0.0 || source_y >= (double)source->height
            ) continue;
            source_x -= 0.5;
            source_y -= 0.5;
            x0 = source_x < 0.0 ? (int)floor(source_x) : (int)source_x;
            y0 = source_y < 0.0 ? (int)floor(source_y) : (int)source_y;
            dx = source_x - (double)x0;
            dy = source_y - (double)y0;
            xa = x0 < 0 ? 0 : (x0 < (int)source->width ? x0 : (int)source->width - 1);
            xb0 = x0 + 1;
            xb = xb0 < 0 ? 0 : (xb0 < (int)source->width ? xb0 : (int)source->width - 1);
            ya = y0 < 0 ? 0 : (y0 < (int)source->height ? y0 : (int)source->height - 1);
            yb0 = y0 + 1;
            yb = yb0 < 0 ? 0 : (yb0 < (int)source->height ? yb0 : (int)source->height - 1);
            for (channel = 0; channel < 4; ++channel) {
                double top_left = 0.0;
                double top_right = 0.0;
                double bottom_left = 0.0;
                double bottom_right = 0.0;
                double value_top = 0.0;
                double value_bottom = 0.0;
                double value = 0.0;
                if (float_planes) {
                    top_left = source_float_plane_value(source, xa, ya, channel, mirrored);
                    top_right = source_float_plane_value(source, xb, ya, channel, mirrored);
                    bottom_left = source_float_plane_value(source, xa, yb, channel, mirrored);
                    bottom_right = source_float_plane_value(source, xb, yb, channel, mirrored);
                } else {
                    top_left = source_byte_value(source, xa, ya, channel, mirrored);
                    top_right = source_byte_value(source, xb, ya, channel, mirrored);
                    bottom_left = source_byte_value(source, xa, yb, channel, mirrored);
                    bottom_right = source_byte_value(source, xb, yb, channel, mirrored);
                }
                value_top = top_left + (top_right - top_left) * dx;
                value_bottom = bottom_left + (bottom_right - bottom_left) * dx;
                value = value_top + (value_bottom - value_top) * dy;
                if (float_planes) {
                    float stored = (float)value;
                    output_row[output_offset + (size_t)channel] = (double)stored;
                } else {
                    unsigned char stored = (unsigned char)value;
                    output_row[output_offset + (size_t)channel] = (double)stored / 255.0;
                }
            }
        }
    }
    return LTD_FACE_RUNTIME_OK;
}

static void pillow_float_sample_pixel(
    const ltd_face_const_rgba8_image *source,
    double source_x,
    double source_y,
    int mirrored,
    double sample[4]
) {
    int channel = 0;
    int x0 = 0;
    int y0 = 0;
    double dx = 0.0;
    double dy = 0.0;
    int xa = 0;
    int xb0 = 0;
    int xb = 0;
    int ya = 0;
    int yb0 = 0;
    int yb = 0;
    for (channel = 0; channel < 4; ++channel) sample[channel] = 0.0;
    if (
        source_x < 0.0 || source_x >= (double)source->width ||
        source_y < 0.0 || source_y >= (double)source->height
    ) return;
    source_x -= 0.5;
    source_y -= 0.5;
    x0 = source_x < 0.0 ? (int)floor(source_x) : (int)source_x;
    y0 = source_y < 0.0 ? (int)floor(source_y) : (int)source_y;
    dx = source_x - (double)x0;
    dy = source_y - (double)y0;
    xa = x0 < 0 ? 0 : (x0 < (int)source->width ? x0 : (int)source->width - 1);
    xb0 = x0 + 1;
    xb = xb0 < 0 ? 0 : (xb0 < (int)source->width ? xb0 : (int)source->width - 1);
    ya = y0 < 0 ? 0 : (y0 < (int)source->height ? y0 : (int)source->height - 1);
    yb0 = y0 + 1;
    yb = yb0 < 0 ? 0 : (yb0 < (int)source->height ? yb0 : (int)source->height - 1);
    for (channel = 0; channel < 4; ++channel) {
        double top_left = source_float_plane_value(source, xa, ya, channel, mirrored);
        double top_right = source_float_plane_value(source, xb, ya, channel, mirrored);
        double bottom_left = source_float_plane_value(source, xa, yb, channel, mirrored);
        double bottom_right = source_float_plane_value(source, xb, yb, channel, mirrored);
        double value_top = top_left + (top_right - top_left) * dx;
        double value_bottom = bottom_left + (bottom_right - bottom_left) * dx;
        double value = value_top + (value_bottom - value_top) * dy;
        float stored = (float)value;
        sample[channel] = (double)stored;
    }
}

ltd_face_runtime_status LTD_FACE_RUNTIME_CALL ltd_face_mask_sample_shade_affine(
    const ltd_face_const_rgba8_image *source,
    const double affine[6],
    int32_t mirrored,
    int32_t shader_kind,
    const double c1_rgb[3],
    const double c2_rgb[3],
    ltd_face_rgba64_image *output
) {
    ltd_face_runtime_status status = require_round_to_nearest();
    size_t source_span = 0;
    size_t output_span = 0;
    uint32_t index = 0;
    uint32_t y = 0;
    if (status != LTD_FACE_RUNTIME_OK) return status;
    if (source == NULL) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    status = validate_dimensions(source->width, source->height);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_const_rgba8(source, source->width, source->height, &source_span);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_rgba64(output, &output_span);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    if (
        affine == NULL || c1_rgb == NULL || c2_rgb == NULL ||
        (mirrored != 0 && mirrored != 1) || shader_kind < 1 || shader_kind > 5
    ) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    for (index = 0; index < 6; ++index) {
        if (!isfinite(affine[index])) return LTD_FACE_RUNTIME_NONFINITE;
    }
    for (index = 0; index < 3; ++index) {
        if (!isfinite(c1_rgb[index]) || !isfinite(c2_rgb[index])) {
            return LTD_FACE_RUNTIME_NONFINITE;
        }
    }
    if (ranges_overlap(source->pixels, source_span, output->pixels, output_span)) {
        return LTD_FACE_RUNTIME_BUFFER_ALIAS;
    }
    for (y = 0; y < output->height; ++y) {
        double destination_y = (double)y + 0.5;
        double *output_row = (double *)(
            (uint8_t *)output->pixels + (size_t)y * output->row_stride_bytes
        );
        uint32_t x = 0;
        for (x = 0; x < output->width; ++x) {
            double destination_x = (double)x + 0.5;
            double source_x = affine[0] * destination_x +
                affine[1] * destination_y + affine[2];
            double source_y = affine[3] * destination_x +
                affine[4] * destination_y + affine[5];
            double sample[4];
            size_t offset = (size_t)x * 4;
            int channel = 0;
            pillow_float_sample_pixel(
                source, source_x, source_y, mirrored, sample
            );
            if (shader_kind == 1) {
                output_row[offset + 0] = c1_rgb[0];
                output_row[offset + 1] = c1_rgb[1];
                output_row[offset + 2] = c1_rgb[2];
                output_row[offset + 3] = sample[0];
            } else if (shader_kind == 2) {
                double red_green = sample[0] + sample[1];
                for (channel = 0; channel < 3; ++channel) {
                    output_row[offset + (size_t)channel] =
                        red_green * c1_rgb[channel] + sample[2];
                }
                output_row[offset + 3] = sample[3];
            } else if (shader_kind == 3) {
                for (channel = 0; channel < 3; ++channel) {
                    output_row[offset + (size_t)channel] =
                        (sample[0] * c1_rgb[channel] + sample[1]) +
                        sample[2] * c2_rgb[channel];
                }
                output_row[offset + 3] = sample[3];
            } else if (shader_kind == 4) {
                double alpha = sample[3] - sample[0];
                for (channel = 0; channel < 3; ++channel) {
                    output_row[offset + (size_t)channel] =
                        sample[1] + sample[2] * c1_rgb[channel];
                }
                if (alpha < 0.0) alpha = 0.0;
                if (alpha > 1.0) alpha = 1.0;
                output_row[offset + 3] = alpha;
            } else {
                double alpha = (sample[3] - sample[0]) - sample[1];
                output_row[offset + 0] = sample[2];
                output_row[offset + 1] = sample[2];
                output_row[offset + 2] = sample[2];
                if (alpha < 0.0) alpha = 0.0;
                if (alpha > 1.0) alpha = 1.0;
                output_row[offset + 3] = alpha;
            }
        }
    }
    return LTD_FACE_RUNTIME_OK;
}

static double sample_channel(
    const ltd_face_const_rgba8_image *source,
    double u,
    double v,
    int channel
) {
    double x = u * (double)source->width - 0.5;
    double y = v * (double)source->height - 0.5;
    int x0 = (int)floor(x);
    int y0 = (int)floor(y);
    double fraction_x = x - (double)x0;
    double fraction_y = y - (double)y0;
    int ax = x0 < 0 ? 0 : (x0 >= (int)source->width ? (int)source->width - 1 : x0);
    int bx0 = x0 + 1;
    int bx = bx0 < 0 ? 0 : (bx0 >= (int)source->width ? (int)source->width - 1 : bx0);
    int ay = y0 < 0 ? 0 : (y0 >= (int)source->height ? (int)source->height - 1 : y0);
    int by0 = y0 + 1;
    int by = by0 < 0 ? 0 : (by0 >= (int)source->height ? (int)source->height - 1 : by0);
    double one_minus_x = 1.0 - fraction_x;
    double one_minus_y = 1.0 - fraction_y;
    const uint8_t *row_a = source->pixels + (size_t)ay * source->row_stride_bytes;
    const uint8_t *row_b = source->pixels + (size_t)by * source->row_stride_bytes;
    double a = (double)row_a[(size_t)ax * 4 + (size_t)channel] / 255.0;
    double b = (double)row_a[(size_t)bx * 4 + (size_t)channel] / 255.0;
    double c = (double)row_b[(size_t)ax * 4 + (size_t)channel] / 255.0;
    double d = (double)row_b[(size_t)bx * 4 + (size_t)channel] / 255.0;
    return a * one_minus_x * one_minus_y
        + b * fraction_x * one_minus_y
        + c * one_minus_x * fraction_y
        + d * fraction_x * fraction_y;
}

ltd_face_runtime_status LTD_FACE_RUNTIME_CALL ltd_face_faceline_wrinkle(
    const ltd_face_const_rgba8_image *source,
    const uint8_t skin_rgba8[4],
    double left,
    double right,
    double bottom,
    double top,
    ltd_face_rgba8_image *output,
    ltd_face_faceline_raster_report *report
) {
    ltd_face_runtime_status status = require_round_to_nearest();
    size_t source_span = 0;
    size_t output_span = 0;
    int count = 0;
    int row_min = 256;
    int row_max = -1;
    int column_min = 128;
    int column_max = -1;
    int y = 0;
    if (status != LTD_FACE_RUNTIME_OK) return status;
    if (source == NULL) return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    status = validate_dimensions(source->width, source->height);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_const_rgba8(source, source->width, source->height, &source_span);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_rgba8(
        output, LTD_FACE_RUNTIME_FACELINE_WIDTH,
        LTD_FACE_RUNTIME_FACELINE_HEIGHT, &output_span
    );
    if (status != LTD_FACE_RUNTIME_OK) return status;
    if (skin_rgba8 == NULL || report == NULL) {
        return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    }
    if (
        !isfinite(left) || !isfinite(right) ||
        !isfinite(bottom) || !isfinite(top)
    ) return LTD_FACE_RUNTIME_NONFINITE;
    if (!(left < right) || !(bottom < top)) {
        return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    }
    if (ranges_overlap(source->pixels, source_span, output->pixels, output_span)) {
        return LTD_FACE_RUNTIME_BUFFER_ALIAS;
    }
    for (y = 0; y < 256; ++y) {
        double pixel_y = (double)y + 0.5;
        double ndc_y = 1.0 - 2.0 * pixel_y / 256.0;
        double v = (top - ndc_y) / (top - bottom);
        uint8_t *output_row = output->pixels + (size_t)y * output->row_stride_bytes;
        int x = 0;
        for (x = 0; x < 128; ++x) {
            size_t offset = (size_t)x * 4;
            double pixel_x = 0.0;
            double ndc_x = 0.0;
            double u = 0.0;
            double alpha = 0.0;
            double inverse_alpha = 0.0;
            int channel = 0;
            output_row[offset + 0] = skin_rgba8[0];
            output_row[offset + 1] = skin_rgba8[1];
            output_row[offset + 2] = skin_rgba8[2];
            output_row[offset + 3] = skin_rgba8[3];
            pixel_x = (double)x + 0.5;
            ndc_x = 2.0 * pixel_x / 128.0 - 1.0;
            u = (ndc_x - left) / (right - left);
            if (u < 0.0 || u > 1.0 || v < 0.0 || v > 1.0) continue;
            alpha = sample_channel(source, u, v, 0);
            inverse_alpha = 1.0 - alpha;
            for (channel = 0; channel < 3; ++channel) {
                double destination = (double)skin_rgba8[channel] / 255.0;
                output_row[offset + (size_t)channel] = store_unorm8(
                    destination * inverse_alpha
                );
            }
            {
                double destination_alpha = (double)skin_rgba8[3] / 255.0;
                output_row[offset + 3] = store_unorm8(
                    alpha + destination_alpha * inverse_alpha
                );
            }
            ++count;
            if (y < row_min) row_min = y;
            if (y > row_max) row_max = y;
            if (x < column_min) column_min = x;
            if (x > column_max) column_max = x;
        }
    }
    report->row_min_inclusive = row_min;
    report->row_max_inclusive = row_max;
    report->column_min_inclusive = column_min;
    report->column_max_inclusive = column_max;
    report->covered_pixel_count = (uint32_t)count;
    return LTD_FACE_RUNTIME_OK;
}

ltd_face_runtime_status LTD_FACE_RUNTIME_CALL ltd_face_faceline_johnny(
    const ltd_face_const_rgba8_image *source,
    const uint8_t skin_rgba8[4],
    const double c1_rgba[4],
    const double c2_rgba[4],
    ltd_face_rgba8_image *output
) {
    ltd_face_runtime_status status = require_round_to_nearest();
    size_t source_span = 0;
    size_t output_span = 0;
    int channel = 0;
    int y = 0;
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_const_rgba8(source, 256, 512, &source_span);
    if (status != LTD_FACE_RUNTIME_OK) return status;
    status = validate_rgba8(
        output, LTD_FACE_RUNTIME_FACELINE_WIDTH,
        LTD_FACE_RUNTIME_FACELINE_HEIGHT, &output_span
    );
    if (status != LTD_FACE_RUNTIME_OK) return status;
    if (skin_rgba8 == NULL || c1_rgba == NULL || c2_rgba == NULL) {
        return LTD_FACE_RUNTIME_INVALID_ARGUMENT;
    }
    for (channel = 0; channel < 4; ++channel) {
        if (!isfinite(c1_rgba[channel]) || !isfinite(c2_rgba[channel])) {
            return LTD_FACE_RUNTIME_NONFINITE;
        }
    }
    if (ranges_overlap(source->pixels, source_span, output->pixels, output_span)) {
        return LTD_FACE_RUNTIME_BUFFER_ALIAS;
    }
    for (y = 0; y < 256; ++y) {
        uint8_t *output_row = output->pixels + (size_t)y * output->row_stride_bytes;
        int x = 0;
        for (x = 0; x < 128; ++x) {
            double sample[4] = {0.0, 0.0, 0.0, 0.0};
            double shaded[4];
            double inverse_alpha = 0.0;
            int sy = 0;
            size_t output_offset = (size_t)x * 4;
            for (sy = 0; sy < 2; ++sy) {
                const uint8_t *source_row = source->pixels +
                    (size_t)(y * 2 + sy) * source->row_stride_bytes;
                int sx = 0;
                for (sx = 0; sx < 2; ++sx) {
                    size_t source_offset = (size_t)(x * 2 + sx) * 4;
                    for (channel = 0; channel < 4; ++channel) {
                        sample[channel] += (double)source_row[
                            source_offset + (size_t)channel
                        ];
                    }
                }
            }
            for (channel = 0; channel < 4; ++channel) {
                sample[channel] = sample[channel] / 4.0 / 255.0;
            }
            for (channel = 0; channel < 4; ++channel) {
                double rc1 = sample[0] * c1_rgba[channel];
                shaded[channel] = rc1 + sample[1] * (c2_rgba[channel] - rc1);
            }
            inverse_alpha = 1.0 - shaded[3];
            for (channel = 0; channel < 4; ++channel) {
                double destination = (double)skin_rgba8[channel] / 255.0;
                output_row[output_offset + (size_t)channel] = store_unorm8(
                    shaded[channel] + destination * inverse_alpha
                );
            }
        }
    }
    return LTD_FACE_RUNTIME_OK;
}

#if defined(_MSC_VER)
#pragma float_control(pop)
#endif
