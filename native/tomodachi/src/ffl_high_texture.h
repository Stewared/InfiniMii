#ifndef INFINIMII_FFL_HIGH_TEXTURE_H
#define INFINIMII_FFL_HIGH_TEXTURE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    FFL_HIGH_TEX_BEARD = 0,
    FFL_HIGH_TEX_CAP = 1,
    FFL_HIGH_TEX_EYE = 2,
    FFL_HIGH_TEX_EYEBROW = 3,
    FFL_HIGH_TEX_FACELINE = 4,
    FFL_HIGH_TEX_FACE_MAKEUP = 5,
    FFL_HIGH_TEX_GLASS = 6,
    FFL_HIGH_TEX_MOLE = 7,
    FFL_HIGH_TEX_MOUTH = 8,
    FFL_HIGH_TEX_MUSTACHE = 9,
    FFL_HIGH_TEX_NOSELINE = 10,
    FFL_HIGH_TEX_COUNT = 11
};

typedef struct {
    const uint8_t *bytes;
    size_t size;
    uint16_t texture_counts[FFL_HIGH_TEX_COUNT];
    int textures_are_linear;
} FflHighResource;

typedef struct {
    int width;
    int height;
    int format;
    uint8_t *rgba;
} FflHighTexture;

int ffl_high_parse(FflHighResource *resource, const uint8_t *bytes, size_t size);
int ffl_high_decode_texture(const FflHighResource *resource, int section_index,
    int item_index, FflHighTexture *out);
void ffl_high_texture_free(FflHighTexture *texture);

/* Implemented by the vendored ninTexUtils GX2 address library. */
int ffl_gx2_deswizzle_base_level(const uint8_t *source, size_t source_size,
    int width, int height, int format, uint8_t *linear, size_t linear_size);

#ifdef __cplusplus
}
#endif

#endif
