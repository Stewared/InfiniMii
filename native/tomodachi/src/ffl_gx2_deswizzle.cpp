#include "ffl_high_texture.h"

#include <cstring>

#include <ninTexUtils/gx2/gx2Surface.h>

extern "C" int ffl_gx2_deswizzle_base_level(const uint8_t *source,
    size_t source_size, int width, int height, int format,
    uint8_t *linear, size_t linear_size) {
    GX2Surface source_surface;
    GX2Surface linear_surface;
    GX2SurfaceFormat surface_format;

    if (!source || !linear || width <= 0 || height <= 0) return 0;
    switch (format) {
        case 0: surface_format = GX2_SURFACE_FORMAT_UNORM_R8; break;
        case 1: surface_format = GX2_SURFACE_FORMAT_UNORM_RG8; break;
        case 2: surface_format = GX2_SURFACE_FORMAT_UNORM_RGBA8; break;
        default: return 0;
    }

    std::memset(&source_surface, 0, sizeof(source_surface));
    source_surface.dim = GX2_SURFACE_DIM_2D;
    source_surface.width = static_cast<u32>(width);
    source_surface.height = static_cast<u32>(height);
    source_surface.depth = 1;
    source_surface.numMips = 1;
    source_surface.format = surface_format;
    source_surface.aa = GX2_AA_MODE_1X;
    source_surface.use = GX2_SURFACE_USE_TEXTURE;
    source_surface.tileMode = GX2_TILE_MODE_DEFAULT;
    GX2CalcSurfaceSizeAndAlignment(&source_surface);
    if (source_surface.imageSize > source_size) return 0;
    source_surface.imagePtr = const_cast<uint8_t *>(source);

    linear_surface = source_surface;
    linear_surface.tileMode = GX2_TILE_MODE_LINEAR_SPECIAL;
    linear_surface.imagePtr = nullptr;
    linear_surface.mipPtr = nullptr;
    GX2CalcSurfaceSizeAndAlignment(&linear_surface);
    if (linear_surface.imageSize > linear_size) return 0;
    std::memset(linear, 0, linear_size);
    linear_surface.imagePtr = linear;

    GX2CopySurface(&source_surface, 0, 0, &linear_surface, 0, 0);
    return 1;
}
