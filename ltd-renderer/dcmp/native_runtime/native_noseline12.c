#include "native_noseline12.h"

#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
#pragma float_control(precise, on, push)
#pragma fp_contract(off)
#pragma fenv_access(on)
#endif

typedef struct sha256_state {
    uint32_t words[8];
    uint64_t byte_count;
    uint8_t block[64];
    size_t block_size;
} sha256_state;

static const uint32_t sha256_round_constants[64] = {
    UINT32_C(0x428a2f98), UINT32_C(0x71374491), UINT32_C(0xb5c0fbcf), UINT32_C(0xe9b5dba5),
    UINT32_C(0x3956c25b), UINT32_C(0x59f111f1), UINT32_C(0x923f82a4), UINT32_C(0xab1c5ed5),
    UINT32_C(0xd807aa98), UINT32_C(0x12835b01), UINT32_C(0x243185be), UINT32_C(0x550c7dc3),
    UINT32_C(0x72be5d74), UINT32_C(0x80deb1fe), UINT32_C(0x9bdc06a7), UINT32_C(0xc19bf174),
    UINT32_C(0xe49b69c1), UINT32_C(0xefbe4786), UINT32_C(0x0fc19dc6), UINT32_C(0x240ca1cc),
    UINT32_C(0x2de92c6f), UINT32_C(0x4a7484aa), UINT32_C(0x5cb0a9dc), UINT32_C(0x76f988da),
    UINT32_C(0x983e5152), UINT32_C(0xa831c66d), UINT32_C(0xb00327c8), UINT32_C(0xbf597fc7),
    UINT32_C(0xc6e00bf3), UINT32_C(0xd5a79147), UINT32_C(0x06ca6351), UINT32_C(0x14292967),
    UINT32_C(0x27b70a85), UINT32_C(0x2e1b2138), UINT32_C(0x4d2c6dfc), UINT32_C(0x53380d13),
    UINT32_C(0x650a7354), UINT32_C(0x766a0abb), UINT32_C(0x81c2c92e), UINT32_C(0x92722c85),
    UINT32_C(0xa2bfe8a1), UINT32_C(0xa81a664b), UINT32_C(0xc24b8b70), UINT32_C(0xc76c51a3),
    UINT32_C(0xd192e819), UINT32_C(0xd6990624), UINT32_C(0xf40e3585), UINT32_C(0x106aa070),
    UINT32_C(0x19a4c116), UINT32_C(0x1e376c08), UINT32_C(0x2748774c), UINT32_C(0x34b0bcb5),
    UINT32_C(0x391c0cb3), UINT32_C(0x4ed8aa4a), UINT32_C(0x5b9cca4f), UINT32_C(0x682e6ff3),
    UINT32_C(0x748f82ee), UINT32_C(0x78a5636f), UINT32_C(0x84c87814), UINT32_C(0x8cc70208),
    UINT32_C(0x90befffa), UINT32_C(0xa4506ceb), UINT32_C(0xbef9a3f7), UINT32_C(0xc67178f2)
};

static uint32_t rotate_right(uint32_t value, unsigned amount) {
    return (value >> amount) | (value << (32U - amount));
}

static void sha256_transform(sha256_state *state, const uint8_t block[64]) {
    uint32_t schedule[64];
    uint32_t a, b, c, d, e, f, g, h;
    size_t index;
    for (index = 0; index < 16; ++index) {
        size_t offset = index * 4;
        schedule[index] = ((uint32_t)block[offset] << 24) |
            ((uint32_t)block[offset + 1] << 16) |
            ((uint32_t)block[offset + 2] << 8) | (uint32_t)block[offset + 3];
    }
    for (index = 16; index < 64; ++index) {
        uint32_t first = rotate_right(schedule[index - 15], 7) ^
            rotate_right(schedule[index - 15], 18) ^ (schedule[index - 15] >> 3);
        uint32_t second = rotate_right(schedule[index - 2], 17) ^
            rotate_right(schedule[index - 2], 19) ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16] + first + schedule[index - 7] + second;
    }
    a = state->words[0]; b = state->words[1]; c = state->words[2]; d = state->words[3];
    e = state->words[4]; f = state->words[5]; g = state->words[6]; h = state->words[7];
    for (index = 0; index < 64; ++index) {
        uint32_t sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + sum1 + choose + sha256_round_constants[index] + schedule[index];
        uint32_t sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = sum0 + majority;
        h = g; g = f; f = e; e = d + temporary1;
        d = c; c = b; b = a; a = temporary1 + temporary2;
    }
    state->words[0] += a; state->words[1] += b; state->words[2] += c; state->words[3] += d;
    state->words[4] += e; state->words[5] += f; state->words[6] += g; state->words[7] += h;
}

static void sha256_initialize(sha256_state *state) {
    static const uint32_t initial[8] = {
        UINT32_C(0x6a09e667), UINT32_C(0xbb67ae85), UINT32_C(0x3c6ef372), UINT32_C(0xa54ff53a),
        UINT32_C(0x510e527f), UINT32_C(0x9b05688c), UINT32_C(0x1f83d9ab), UINT32_C(0x5be0cd19)
    };
    memcpy(state->words, initial, sizeof(initial));
    state->byte_count = 0;
    state->block_size = 0;
}

static void sha256_update(sha256_state *state, const void *raw, size_t size) {
    const uint8_t *bytes = (const uint8_t *)raw;
    state->byte_count += (uint64_t)size;
    while (size != 0) {
        size_t available = sizeof(state->block) - state->block_size;
        size_t amount = size < available ? size : available;
        memcpy(state->block + state->block_size, bytes, amount);
        state->block_size += amount;
        bytes += amount;
        size -= amount;
        if (state->block_size == sizeof(state->block)) {
            sha256_transform(state, state->block);
            state->block_size = 0;
        }
    }
}

static void sha256_u32le(sha256_state *state, uint32_t value) {
    uint8_t bytes[4];
    bytes[0] = (uint8_t)value; bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16); bytes[3] = (uint8_t)(value >> 24);
    sha256_update(state, bytes, sizeof(bytes));
}

static void sha256_finish(sha256_state *state, uint8_t digest[32]) {
    uint64_t bit_count = state->byte_count * UINT64_C(8);
    uint8_t marker = UINT8_C(0x80);
    uint8_t zero = 0;
    uint8_t length[8];
    size_t index;
    sha256_update(state, &marker, 1);
    while (state->block_size != 56) sha256_update(state, &zero, 1);
    for (index = 0; index < 8; ++index) {
        length[7 - index] = (uint8_t)(bit_count >> (index * 8));
    }
    sha256_update(state, length, sizeof(length));
    for (index = 0; index < 8; ++index) {
        digest[index * 4] = (uint8_t)(state->words[index] >> 24);
        digest[index * 4 + 1] = (uint8_t)(state->words[index] >> 16);
        digest[index * 4 + 2] = (uint8_t)(state->words[index] >> 8);
        digest[index * 4 + 3] = (uint8_t)state->words[index];
    }
}

static void digest_hex(const uint8_t digest[32], char output[65]) {
    static const char characters[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32; ++index) {
        output[index * 2] = characters[digest[index] >> 4];
        output[index * 2 + 1] = characters[digest[index] & 15];
    }
    output[64] = '\0';
}

static int checked_mul(size_t left, size_t right, size_t *output) {
    if (left != 0 && right > SIZE_MAX / left) return 0;
    *output = left * right;
    return 1;
}

static int checked_add(size_t left, size_t right, size_t *output) {
    if (right > SIZE_MAX - left) return 0;
    *output = left + right;
    return 1;
}

static int aligned_double(const void *pointer) {
    return ((uintptr_t)pointer % (uintptr_t)sizeof(double)) == 0;
}

static int ranges_overlap(const void *left_pointer, size_t left_size,
                          const void *right_pointer, size_t right_size) {
    uintptr_t left = (uintptr_t)left_pointer;
    uintptr_t right = (uintptr_t)right_pointer;
    if (left_size == 0 || right_size == 0) return 0;
    if (left_pointer == NULL || right_pointer == NULL) return 0;
    if (left > UINTPTR_MAX - left_size || right > UINTPTR_MAX - right_size) return 1;
    return left < right + right_size && right < left + left_size;
}

static ltd_noseline12_status attachment_span(
    uint32_t width, uint32_t height, size_t channels, size_t stride,
    size_t capacity, const double *pointer, size_t *span
) {
    size_t row_elements, row_bytes, preceding;
    if (pointer == NULL || !aligned_double(pointer) || stride % sizeof(double) != 0) {
        return LTD_NOSELINE12_INVALID_ARGUMENT;
    }
    if (!checked_mul((size_t)width, channels, &row_elements) ||
        !checked_mul(row_elements, sizeof(double), &row_bytes) || stride < row_bytes ||
        !checked_mul((size_t)(height - 1), stride, &preceding) ||
        !checked_add(preceding, row_bytes, span)) {
        return LTD_NOSELINE12_INVALID_ARGUMENT;
    }
    return capacity < *span ? LTD_NOSELINE12_BUFFER_TOO_SMALL : LTD_NOSELINE12_OK;
}

static ltd_noseline12_status validate_attachments(
    const ltd_noseline12_attachments *attachments, size_t spans[3]
) {
    ltd_noseline12_status status;
    uint32_t y;
    if (attachments == NULL || attachments->width == 0 || attachments->height == 0 ||
        attachments->width > LTD_NOSELINE12_MAX_DIMENSION ||
        attachments->height > LTD_NOSELINE12_MAX_DIMENSION) {
        return LTD_NOSELINE12_INVALID_ARGUMENT;
    }
    status = attachment_span(
        attachments->width, attachments->height, 3, attachments->color_row_stride_bytes,
        attachments->color_capacity_bytes, attachments->color, &spans[0]);
    if (status != LTD_NOSELINE12_OK) return status;
    status = attachment_span(
        attachments->width, attachments->height, 1, attachments->depth_row_stride_bytes,
        attachments->depth_capacity_bytes, attachments->depth, &spans[1]);
    if (status != LTD_NOSELINE12_OK) return status;
    if (attachments->alpha == NULL) {
        if (attachments->alpha_capacity_bytes != 0 || attachments->alpha_row_stride_bytes != 0) {
            return LTD_NOSELINE12_INVALID_ARGUMENT;
        }
        spans[2] = 0;
    } else {
        status = attachment_span(
            attachments->width, attachments->height, 1, attachments->alpha_row_stride_bytes,
            attachments->alpha_capacity_bytes, attachments->alpha, &spans[2]);
        if (status != LTD_NOSELINE12_OK) return status;
    }
    if (ranges_overlap(attachments->color, spans[0], attachments->depth, spans[1]) ||
        ranges_overlap(attachments->color, spans[0], attachments->alpha, spans[2]) ||
        ranges_overlap(attachments->depth, spans[1], attachments->alpha, spans[2])) {
        return LTD_NOSELINE12_BUFFER_ALIAS;
    }
    for (y = 0; y < attachments->height; ++y) {
        const double *color = (const double *)((const uint8_t *)attachments->color +
            (size_t)y * attachments->color_row_stride_bytes);
        const double *depth = (const double *)((const uint8_t *)attachments->depth +
            (size_t)y * attachments->depth_row_stride_bytes);
        const double *alpha = attachments->alpha == NULL ? NULL :
            (const double *)((const uint8_t *)attachments->alpha +
                (size_t)y * attachments->alpha_row_stride_bytes);
        uint32_t x;
        for (x = 0; x < attachments->width; ++x) {
            size_t color_offset = (size_t)x * 3;
            if (!isfinite(color[color_offset]) || !isfinite(color[color_offset + 1]) ||
                !isfinite(color[color_offset + 2])) return LTD_NOSELINE12_NONFINITE;
            if (isnan(depth[x]) || depth[x] == INFINITY) return LTD_NOSELINE12_NONFINITE;
            if (alpha != NULL && (!isfinite(alpha[x]) || alpha[x] < 0.0 || alpha[x] > 1.0)) {
                return !isfinite(alpha[x]) ? LTD_NOSELINE12_NONFINITE :
                    LTD_NOSELINE12_VALUE_OUT_OF_RANGE;
            }
        }
    }
    return LTD_NOSELINE12_OK;
}

static int exact_seal(const char value[65], const char *expected) {
    size_t index;
    for (index = 0; index < 64; ++index) {
        char byte = value[index];
        if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f')) ||
            byte != expected[index]) return 0;
    }
    return value[64] == '\0' && expected[64] == '\0';
}

static ltd_noseline12_status validate_input(
    const ltd_noseline12_input *input, size_t *mip_span
) {
    static const uint32_t widths[LTD_NOSELINE12_MIP_LEVEL_COUNT] =
        {256, 128, 64, 32, 16, 8, 4, 2, 1};
    static const uint32_t heights[LTD_NOSELINE12_MIP_LEVEL_COUNT] =
        {256, 128, 64, 32, 16, 8, 4, 2, 1};
    static const char domain[] = "ltd.noseline12.mips.v1";
    sha256_state hash;
    uint8_t digest[32];
    char hexadecimal[65];
    size_t expected_offset = 0;
    uint32_t level;
    if (input == NULL || input->perspective_correct != 1 || input->reserved != 0 ||
        input->mip_rgba == NULL || !aligned_double(input->mip_rgba)) {
        return LTD_NOSELINE12_INVALID_ARGUMENT;
    }
    if (!exact_seal(input->obj_source_sha256, LTD_NOSELINE12_OBJ_SOURCE_SHA256) ||
        !exact_seal(input->texture_manifest_sha256,
                    LTD_NOSELINE12_TEXTURE_MANIFEST_SHA256) ||
        !exact_seal(input->decoded_mips_sha256,
                    LTD_NOSELINE12_DECODED_MIPS_SHA256)) {
        return LTD_NOSELINE12_SOURCE_FINGERPRINT_MISMATCH;
    }
    for (level = 0; level < 12; ++level) {
        if (!isfinite(input->screen[level])) return LTD_NOSELINE12_NONFINITE;
    }
    sha256_initialize(&hash);
    sha256_update(&hash, domain, sizeof(domain));
    sha256_u32le(&hash, LTD_NOSELINE12_MIP_LEVEL_COUNT);
    for (level = 0; level < LTD_NOSELINE12_MIP_LEVEL_COUNT; ++level) {
        const ltd_noseline12_mip_level *descriptor = &input->levels[level];
        size_t area, scalars, scalar;
        if (descriptor->width != widths[level] || descriptor->height != heights[level] ||
            descriptor->rgba_element_offset != expected_offset ||
            !checked_mul((size_t)descriptor->width, (size_t)descriptor->height, &area) ||
            !checked_mul(area, 4, &scalars) ||
            !checked_add(expected_offset, scalars, &expected_offset) ||
            expected_offset > input->mip_rgba_element_count) {
            return LTD_NOSELINE12_VALUE_OUT_OF_RANGE;
        }
        sha256_u32le(&hash, descriptor->width);
        sha256_u32le(&hash, descriptor->height);
        for (scalar = descriptor->rgba_element_offset;
             scalar < descriptor->rgba_element_offset + scalars; ++scalar) {
            double value = input->mip_rgba[scalar];
            if (!isfinite(value)) return LTD_NOSELINE12_NONFINITE;
            if (value < 0.0 || value > 1.0) return LTD_NOSELINE12_VALUE_OUT_OF_RANGE;
        }
        sha256_update(
            &hash, input->mip_rgba + descriptor->rgba_element_offset,
            scalars * sizeof(double));
    }
    if (expected_offset != input->mip_rgba_element_count ||
        !checked_mul(expected_offset, sizeof(double), mip_span)) {
        return LTD_NOSELINE12_VALUE_OUT_OF_RANGE;
    }
    sha256_finish(&hash, digest);
    digest_hex(digest, hexadecimal);
    if (strcmp(hexadecimal, LTD_NOSELINE12_DECODED_MIPS_SHA256) != 0) {
        return LTD_NOSELINE12_SOURCE_CONTENT_MISMATCH;
    }
    return LTD_NOSELINE12_OK;
}

static int64_t repeated_index(int64_t index, int64_t size) {
    int64_t value = index % size;
    return value < 0 ? value + size : value;
}

static double sample_red(
    const double *source, int64_t width, int64_t height, double u, double v
) {
    double tex_x = u * (double)width - 0.5;
    double tex_y = (1.0 - v) * (double)height - 0.5;
    double floor_x = floor(tex_x);
    double floor_y = floor(tex_y);
    int64_t x0 = repeated_index((int64_t)floor_x, width);
    int64_t x1 = repeated_index((int64_t)floor_x + 1, width);
    int64_t y0 = repeated_index((int64_t)floor_y, height);
    int64_t y1 = repeated_index((int64_t)floor_y + 1, height);
    double x_amount = tex_x - floor_x;
    double y_amount = tex_y - floor_y;
    double inverse_x = 1.0 - x_amount;
    double inverse_y = 1.0 - y_amount;
    double top = source[((size_t)y0 * (size_t)width + (size_t)x0) * 4] * inverse_x +
        source[((size_t)y0 * (size_t)width + (size_t)x1) * 4] * x_amount;
    double bottom = source[((size_t)y1 * (size_t)width + (size_t)x0) * 4] * inverse_x +
        source[((size_t)y1 * (size_t)width + (size_t)x1) * 4] * x_amount;
    return top * inverse_y + bottom * y_amount;
}

static uint32_t select_mip(const double screen[9], const double uv[6]) {
    double a = screen[3] - screen[0];
    double b = screen[4] - screen[1];
    double c = screen[6] - screen[0];
    double d = screen[7] - screen[1];
    double determinant = a * d - b * c;
    double bu = uv[2] - uv[0];
    double bv = uv[3] - uv[1];
    double cu = uv[4] - uv[0];
    double cv = uv[5] - uv[1];
    double gradient00 = (d * bu - b * cu) / determinant;
    double gradient01 = (d * bv - b * cv) / determinant;
    double gradient10 = (-c * bu + a * cu) / determinant;
    double gradient11 = (-c * bv + a * cv) / determinant;
    double rho_x = hypot(gradient00 * 256.0, gradient01 * 256.0);
    double rho_y = hypot(gradient10 * 256.0, gradient11 * 256.0);
    double rho = rho_x > rho_y ? rho_x : rho_y;
    double lod;
    uint32_t selected;
    if (rho < 1.0) rho = 1.0;
    lod = log2(rho);
    if (lod < 0.0) lod = 0.0;
    if (lod > 8.0) lod = 8.0;
    selected = (uint32_t)floor(lod + 0.5);
    return selected > 8 ? 8 : selected;
}

static void derive_triangle(
    const ltd_noseline12_input *input, uint32_t triangle,
    double screen[9], double uv[6]
) {
    static const uint32_t indices[2][3] = {{0, 1, 2}, {2, 1, 3}};
    static const double source_uv[4][2] = {
        {0x1.7f7f7f3c2041cp-1, 0x1.9191900acf91dp-4},
        {0x1.7f7f7f3c2041cp-1, 0x1.cbcbcb450d505p-1},
        {0x1.01010187bf7c8p-2, 0x1.9191900acf91dp-4},
        {0x1.01010187bf7c8p-2, 0x1.cbcbcb450d505p-1}
    };
    uint32_t corner;
    for (corner = 0; corner < 3; ++corner) {
        uint32_t vertex = indices[triangle][corner];
        memcpy(screen + corner * 3, input->screen + vertex * 3, 3 * sizeof(double));
        memcpy(uv + corner * 2, source_uv[vertex], 2 * sizeof(double));
    }
}

static double *color_row(ltd_noseline12_attachments *attachments, int y) {
    return (double *)((uint8_t *)attachments->color +
        (size_t)y * attachments->color_row_stride_bytes);
}

static double *depth_row(ltd_noseline12_attachments *attachments, int y) {
    return (double *)((uint8_t *)attachments->depth +
        (size_t)y * attachments->depth_row_stride_bytes);
}

static double *alpha_row(ltd_noseline12_attachments *attachments, int y) {
    return attachments->alpha == NULL ? NULL :
        (double *)((uint8_t *)attachments->alpha +
            (size_t)y * attachments->alpha_row_stride_bytes);
}

uint32_t LTD_NOSELINE12_CALL ltd_noseline12_abi_version(void) {
    return LTD_NOSELINE12_ABI_VERSION;
}

const char *LTD_NOSELINE12_CALL ltd_noseline12_contract_sha256(void) {
    return LTD_NOSELINE12_CONTRACT_SHA256;
}

const char *LTD_NOSELINE12_CALL ltd_noseline12_software_renderer_sha256(void) {
    return LTD_NOSELINE12_SOFTWARE_RENDERER_SHA256;
}

const char *LTD_NOSELINE12_CALL ltd_noseline12_render_mii_sha256(void) {
    return LTD_NOSELINE12_RENDER_MII_SHA256;
}

const char *LTD_NOSELINE12_CALL ltd_noseline12_obj_source_sha256(void) {
    return LTD_NOSELINE12_OBJ_SOURCE_SHA256;
}

const char *LTD_NOSELINE12_CALL ltd_noseline12_texture_manifest_sha256(void) {
    return LTD_NOSELINE12_TEXTURE_MANIFEST_SHA256;
}

const char *LTD_NOSELINE12_CALL ltd_noseline12_decoded_mips_sha256(void) {
    return LTD_NOSELINE12_DECODED_MIPS_SHA256;
}

const char *LTD_NOSELINE12_CALL ltd_noseline12_status_name(ltd_noseline12_status status) {
    switch (status) {
        case LTD_NOSELINE12_OK: return "ok";
        case LTD_NOSELINE12_INVALID_ARGUMENT: return "invalid_argument";
        case LTD_NOSELINE12_BUFFER_TOO_SMALL: return "buffer_too_small";
        case LTD_NOSELINE12_NONFINITE: return "nonfinite";
        case LTD_NOSELINE12_VALUE_OUT_OF_RANGE: return "value_out_of_range";
        case LTD_NOSELINE12_ROUNDING_MODE: return "rounding_mode";
        case LTD_NOSELINE12_ABI_MISMATCH: return "abi_mismatch";
        case LTD_NOSELINE12_CONTRACT_MISMATCH: return "contract_mismatch";
        case LTD_NOSELINE12_SOURCE_FINGERPRINT_MISMATCH: return "source_fingerprint_mismatch";
        case LTD_NOSELINE12_SOURCE_CONTENT_MISMATCH: return "source_content_mismatch";
        case LTD_NOSELINE12_BUFFER_ALIAS: return "buffer_alias";
        case LTD_NOSELINE12_FENV_FAILURE: return "fenv_failure";
        default: return "unknown";
    }
}

ltd_noseline12_status LTD_NOSELINE12_CALL ltd_noseline12_require(
    uint32_t expected_abi, const char *expected_contract_sha256
) {
    if (expected_abi != LTD_NOSELINE12_ABI_VERSION) return LTD_NOSELINE12_ABI_MISMATCH;
    if (expected_contract_sha256 == NULL ||
        strcmp(expected_contract_sha256, LTD_NOSELINE12_CONTRACT_SHA256) != 0) {
        return LTD_NOSELINE12_CONTRACT_MISMATCH;
    }
    return LTD_NOSELINE12_OK;
}

ltd_noseline12_status LTD_NOSELINE12_CALL ltd_noseline12_draw(
    ltd_noseline12_attachments *attachments,
    const ltd_noseline12_input *input,
    ltd_noseline12_report *report
) {
    static const double output_color[3] = {
        0x1.061551372c694p-6, 0x1.2b4e09b3f0ae3p-7, 0x1.18c2a5a8a8044p-7
    };
    ltd_noseline12_status status;
    ltd_noseline12_report result;
    size_t attachment_spans[3];
    size_t mip_span;
    fenv_t saved_environment;
    uint32_t triangle;
    memset(&result, 0, sizeof(result));
    result.submitted_triangles = LTD_NOSELINE12_TRIANGLE_COUNT;
    if (report == NULL) return LTD_NOSELINE12_INVALID_ARGUMENT;
    if (fegetround() != FE_TONEAREST) return LTD_NOSELINE12_ROUNDING_MODE;
    status = validate_attachments(attachments, attachment_spans);
    if (status != LTD_NOSELINE12_OK) return status;
    status = validate_input(input, &mip_span);
    if (status != LTD_NOSELINE12_OK) return status;
    if (ranges_overlap(attachments->color, attachment_spans[0], input, sizeof(*input)) ||
        ranges_overlap(attachments->depth, attachment_spans[1], input, sizeof(*input)) ||
        ranges_overlap(attachments->alpha, attachment_spans[2], input, sizeof(*input)) ||
        ranges_overlap(attachments->color, attachment_spans[0], input->mip_rgba, mip_span) ||
        ranges_overlap(attachments->depth, attachment_spans[1], input->mip_rgba, mip_span) ||
        ranges_overlap(attachments->alpha, attachment_spans[2], input->mip_rgba, mip_span) ||
        ranges_overlap(attachments->color, attachment_spans[0], report, sizeof(*report)) ||
        ranges_overlap(attachments->depth, attachment_spans[1], report, sizeof(*report)) ||
        ranges_overlap(attachments->alpha, attachment_spans[2], report, sizeof(*report)) ||
        ranges_overlap(input->mip_rgba, mip_span, report, sizeof(*report)) ||
        ranges_overlap(input, sizeof(*input), report, sizeof(*report))) {
        return LTD_NOSELINE12_BUFFER_ALIAS;
    }
    if (feholdexcept(&saved_environment) != 0) return LTD_NOSELINE12_FENV_FAILURE;
    for (triangle = 0; triangle < LTD_NOSELINE12_TRIANGLE_COUNT; ++triangle) {
        double screen[9], uv[6];
        double minimum_x, maximum_x, minimum_y, maximum_y;
        double denominator;
        int x0, x1, y0, y1, y;
        uint32_t mip_level;
        const ltd_noseline12_mip_level *level;
        const double *texture;
        derive_triangle(input, triangle, screen, uv);
        minimum_x = fmin(screen[0], fmin(screen[3], screen[6]));
        maximum_x = fmax(screen[0], fmax(screen[3], screen[6]));
        minimum_y = fmin(screen[1], fmin(screen[4], screen[7]));
        maximum_y = fmax(screen[1], fmax(screen[4], screen[7]));
        if (maximum_x < 0.0 || maximum_y < 0.0 ||
            minimum_x > (double)(attachments->width - 1) ||
            minimum_y > (double)(attachments->height - 1)) {
            continue;
        }
        x0 = minimum_x <= 0.0 ? 0 : (int)floor(minimum_x);
        x1 = maximum_x >= (double)(attachments->width - 1) ?
            (int)attachments->width - 1 : (int)ceil(maximum_x);
        y0 = minimum_y <= 0.0 ? 0 : (int)floor(minimum_y);
        y1 = maximum_y >= (double)(attachments->height - 1) ?
            (int)attachments->height - 1 : (int)ceil(maximum_y);
        denominator = (screen[0] - screen[3]) * (screen[7] - screen[4]) -
            (screen[1] - screen[4]) * (screen[6] - screen[3]);
        if (fabs(denominator) < 1e-10 || denominator <= 0.0) continue;
        mip_level = select_mip(screen, uv);
        result.selected_mip_levels[triangle] = mip_level;
        level = &input->levels[mip_level];
        texture = input->mip_rgba + level->rgba_element_offset;
        for (y = y0; y <= y1; ++y) {
            int x;
            for (x = x0; x <= x1; ++x) {
                double sample_x = (double)x + 0.5;
                double sample_y = (double)y + 0.5;
                double edge0_left = (sample_x - screen[3]) * (screen[7] - screen[4]);
                double edge0_right = (sample_y - screen[4]) * (screen[6] - screen[3]);
                double affine0 = (edge0_left - edge0_right) / denominator;
                double edge1_left = (sample_x - screen[6]) * (screen[1] - screen[7]);
                double edge1_right = (sample_y - screen[7]) * (screen[0] - screen[6]);
                double affine1 = (edge1_left - edge1_right) / denominator;
                double affine2 = (1.0 - affine0) - affine1;
                double z01, z, safe, weight0, weight1, weight2, u, v, alpha;
                double *depth;
                if (affine0 < -1e-7 || affine1 < -1e-7 || affine2 < -1e-7) continue;
                z01 = affine0 * screen[2] + affine1 * screen[5];
                z = z01 + affine2 * screen[8];
                depth = depth_row(attachments, y);
                if (z < depth[x]) continue;
                ++result.candidate_fragments;
                safe = fabs(z) < 1e-20 ? 1.0 : z;
                weight0 = affine0 * screen[2] / safe;
                weight1 = affine1 * screen[5] / safe;
                weight2 = affine2 * screen[8] / safe;
                u = weight0 * uv[0] + weight1 * uv[2] + weight2 * uv[4];
                v = weight0 * uv[1] + weight1 * uv[3] + weight2 * uv[5];
                alpha = sample_red(texture, (int64_t)level->width,
                                   (int64_t)level->height, u, v);
                if (alpha < 0.5) continue;
                ++result.alpha_selected_fragments;
                {
                    double *color = color_row(attachments, y);
                    double *target_alpha = alpha_row(attachments, y);
                    size_t offset = (size_t)x * 3;
                    color[offset] = output_color[0];
                    color[offset + 1] = output_color[1];
                    color[offset + 2] = output_color[2];
                    depth[x] = z;
                    if (target_alpha != NULL) target_alpha[x] = 1.0;
                }
                ++result.written_fragments;
            }
        }
    }
    if (fesetenv(&saved_environment) != 0) return LTD_NOSELINE12_FENV_FAILURE;
    *report = result;
    return LTD_NOSELINE12_OK;
}

#if defined(_MSC_VER)
#pragma float_control(pop)
#endif
