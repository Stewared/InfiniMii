#include "ffl_high_texture.h"

#include <stdlib.h>
#include <string.h>

#include "miniz_tinfl.h"

#define FFL_HIGH_HEADER_SIZE 0x4a00u
#define FFL_HIGH_TEXTURE_HEADER_OFFSET 0x14u
#define FFL_HIGH_PARTS_MAX_SIZE_BYTES (FFL_HIGH_TEX_COUNT * 4u)
#define FFL_HIGH_PART_INFO_SIZE 0x10u
#define FFL_HIGH_TEXTURE_FOOTER_SIZE 0x0cu
#define FFL_HIGH_VERSION 0x00070000u
#define FFL_HIGH_EXPANDED_SIZE_AFL 0x0239d5e0u
#define FFL_HIGH_EXPANDED_SIZE_AFL_2_3 0x02502de0u

static const uint16_t ffl_high_texture_counts_default[FFL_HIGH_TEX_COUNT] = {
    3, 132, 62, 24, 12, 12, 9, 2, 37, 6, 18
};

static const uint16_t ffl_high_texture_counts_afl[FFL_HIGH_TEX_COUNT] = {
    3, 132, 80, 28, 12, 12, 9, 2, 52, 6, 18
};

static const uint16_t ffl_high_texture_counts_afl_2_3[FFL_HIGH_TEX_COUNT] = {
    3, 132, 80, 28, 12, 12, 20, 2, 52, 6, 18
};

static int ffl_high_range(size_t size, size_t offset, size_t length) {
    return offset <= size && length <= size - offset;
}

static uint16_t ffl_high_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t ffl_high_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int ffl_high_part_info_offset(const FflHighResource *resource,
    int section_index, int item_index,
    size_t *offset) {
    size_t cursor = FFL_HIGH_TEXTURE_HEADER_OFFSET +
        FFL_HIGH_PARTS_MAX_SIZE_BYTES;
    int i;

    if (!resource || !offset || section_index < 0 ||
        section_index >= FFL_HIGH_TEX_COUNT || item_index < 0 ||
        item_index >= resource->texture_counts[section_index]) {
        return 0;
    }
    for (i = 0; i < section_index; i++) {
        cursor += (size_t)resource->texture_counts[i] * FFL_HIGH_PART_INFO_SIZE;
    }
    *offset = cursor + (size_t)item_index * FFL_HIGH_PART_INFO_SIZE;
    return 1;
}

int ffl_high_parse(FflHighResource *resource, const uint8_t *bytes, size_t size) {
    uint32_t expanded_buffer_size;
    uint32_t type_hint;
    uint32_t unhinted_size;
    const uint16_t *counts;
    if (!resource) return 0;
    memset(resource, 0, sizeof(*resource));
    if (!bytes || size < FFL_HIGH_HEADER_SIZE ||
        memcmp(bytes, "FFRA", 4) != 0 ||
        ffl_high_be32(bytes + 4) != FFL_HIGH_VERSION ||
        ffl_high_be32(bytes + 8) == 0 ||
        ffl_high_be32(bytes + 16) != 0) {
        return 0;
    }
    /* Original FFL leaves +0x0c unused. The supported FFL-Testing extension
       names it m_ExpandedBufferSize and uses either its high three bits or
       the exact AFL expanded sizes to select extended linear layouts. The
       bundled resource has the source-defined AFL value 0x0239d5e0. */
    expanded_buffer_size = ffl_high_be32(bytes + 12);
    type_hint = expanded_buffer_size >> 29;
    unhinted_size = expanded_buffer_size & 0x1fffffffu;
    counts = ffl_high_texture_counts_default;
    resource->textures_are_linear = 0;
    if (type_hint == 3) {
        counts = ffl_high_texture_counts_afl_2_3;
        resource->textures_are_linear = 1;
    } else if (type_hint == 2) {
        counts = ffl_high_texture_counts_afl;
        resource->textures_are_linear = 1;
    } else if (unhinted_size == FFL_HIGH_EXPANDED_SIZE_AFL_2_3) {
        counts = ffl_high_texture_counts_afl_2_3;
        resource->textures_are_linear = 1;
    } else if (unhinted_size == FFL_HIGH_EXPANDED_SIZE_AFL) {
        counts = ffl_high_texture_counts_afl;
        resource->textures_are_linear = 1;
    }
    memcpy(resource->texture_counts, counts, sizeof(resource->texture_counts));
    resource->bytes = bytes;
    resource->size = size;
    return 1;
}

int ffl_high_decode_texture(const FflHighResource *resource, int section_index,
    int item_index, FflHighTexture *out) {
    size_t info_offset;
    uint32_t data_offset;
    uint32_t data_size;
    uint32_t compressed_size;
    uint8_t window_bits;
    uint8_t strategy;
    uint8_t *expanded = NULL;
    const uint8_t *texture_data;
    const uint8_t *footer;
    int channels;
    size_t linear_size;
    uint8_t *linear = NULL;
    size_t pixel_count;
    size_t i;

    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!resource || !resource->bytes ||
        !ffl_high_part_info_offset(resource, section_index, item_index, &info_offset) ||
        !ffl_high_range(resource->size, info_offset, FFL_HIGH_PART_INFO_SIZE)) {
        return 0;
    }

    data_offset = ffl_high_be32(resource->bytes + info_offset);
    data_size = ffl_high_be32(resource->bytes + info_offset + 4);
    compressed_size = ffl_high_be32(resource->bytes + info_offset + 8);
    window_bits = resource->bytes[info_offset + 13];
    strategy = resource->bytes[info_offset + 15];
    if (data_size < FFL_HIGH_TEXTURE_FOOTER_SIZE) return 0;

    if (strategy == 5) {
        if (!ffl_high_range(resource->size, data_offset, data_size)) return 0;
        texture_data = resource->bytes + data_offset;
    } else {
        size_t written;
        /* FFLResHigh.dat uses zlib streams (windowBits 8..15 encoded as
           values 0..7). Gzip/autodetect resource variants are deliberately
           rejected instead of being decoded with guessed framing. */
        if (window_bits > 7 || compressed_size == 0 ||
            !ffl_high_range(resource->size, data_offset, compressed_size)) {
            return 0;
        }
        expanded = (uint8_t *)malloc(data_size);
        if (!expanded) return 0;
        written = tinfl_decompress_mem_to_mem(expanded, data_size,
            resource->bytes + data_offset, compressed_size,
            TINFL_FLAG_PARSE_ZLIB_HEADER);
        if (written != data_size) {
            free(expanded);
            return 0;
        }
        texture_data = expanded;
    }

    footer = texture_data + data_size - FFL_HIGH_TEXTURE_FOOTER_SIZE;
    out->width = (int)ffl_high_be16(footer + 4);
    out->height = (int)ffl_high_be16(footer + 6);
    switch (footer[9]) {
        case 0: channels = 1; out->format = 0x07; break; /* R8 */
        case 1: channels = 2; out->format = 0x05; break; /* RG8 */
        case 2: channels = 4; out->format = 0x0a; break; /* RGBA8 */
        default: free(expanded); return 0;
    }
    if (out->width <= 0 || out->height <= 0 ||
        (size_t)out->width > SIZE_MAX / (size_t)out->height) {
        free(expanded);
        return 0;
    }
    pixel_count = (size_t)out->width * (size_t)out->height;
    if (pixel_count > SIZE_MAX / (size_t)channels ||
        pixel_count > SIZE_MAX / 4u) {
        free(expanded);
        return 0;
    }
    linear_size = pixel_count * (size_t)channels;
    linear = (uint8_t *)malloc(linear_size);
    out->rgba = (uint8_t *)malloc(pixel_count * 4u);
    if (!linear || !out->rgba) {
        free(linear);
        free(expanded);
        ffl_high_texture_free(out);
        return 0;
    }
    if (resource->textures_are_linear) {
        if (linear_size > data_size - FFL_HIGH_TEXTURE_FOOTER_SIZE) {
            free(linear);
            free(expanded);
            ffl_high_texture_free(out);
            return 0;
        }
        memcpy(linear, texture_data, linear_size);
    } else if (!ffl_gx2_deswizzle_base_level(texture_data,
            data_size - FFL_HIGH_TEXTURE_FOOTER_SIZE,
            out->width, out->height, footer[9], linear, linear_size)) {
        free(linear);
        free(expanded);
        ffl_high_texture_free(out);
        return 0;
    }

    for (i = 0; i < pixel_count; i++) {
        if (channels == 1) {
            out->rgba[i * 4u + 0] = linear[i];
            out->rgba[i * 4u + 1] = linear[i];
            out->rgba[i * 4u + 2] = linear[i];
            out->rgba[i * 4u + 3] = 255;
        } else if (channels == 2) {
            out->rgba[i * 4u + 0] = linear[i * 2u + 0];
            out->rgba[i * 4u + 1] = linear[i * 2u + 1];
            out->rgba[i * 4u + 2] = 0;
            out->rgba[i * 4u + 3] = 255;
        } else {
            memcpy(out->rgba + i * 4u, linear + i * 4u, 4u);
        }
    }

    free(linear);
    free(expanded);
    return 1;
}

void ffl_high_texture_free(FflHighTexture *texture) {
    if (!texture) return;
    free(texture->rgba);
    memset(texture, 0, sizeof(*texture));
}
