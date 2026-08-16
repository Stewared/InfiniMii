#define main tomodachi_renderer_cli_main
#include "renderer.c"
#undef main

static int failures = 0;

static void expect_color(const char *label, uint32_t actual, uint32_t expected) {
    if (actual == expected) return;
    fprintf(stderr, "%s: got %06x, expected %06x\n",
        label, (unsigned int)actual, (unsigned int)expected);
    failures++;
}

static void expect_count(const char *label, size_t actual, size_t expected) {
    if (actual == expected) return;
    fprintf(stderr, "%s: got %zu entries, expected %zu\n", label, actual, expected);
    failures++;
}

static void expect_byte(const char *label, uint8_t actual, uint8_t expected) {
    if (actual == expected) return;
    fprintf(stderr, "%s: got %u, expected %u\n",
        label, (unsigned int)actual, (unsigned int)expected);
    failures++;
}

static void expect_int(const char *label, int actual, int expected) {
    if (actual == expected) return;
    fprintf(stderr, "%s: got %d, expected %d\n", label, actual, expected);
    failures++;
}

static void expect_near(const char *label, double actual, double expected, double tolerance) {
    if (fabs(actual - expected) <= tolerance) return;
    fprintf(stderr, "%s: got %.12f, expected %.12f (+/- %.12f)\n",
        label, actual, expected, tolerance);
    failures++;
}

static void test_whole_body_camera(void) {
    static const int heights[3] = { 0, 64, 127 };
    static const double expected_y[3] = {
        9.2225, 10.85, 12.4520703125
    };
    static const double expected_z[3] = {
        76.5, 90.16700973401946, 118.8
    };
    static const double expected_origin_screen_y[3] = {
        490.42185137228205, 489.9876489831652, 459.8149264120989
    };
    MeshCanvas canvas;
    Vec3 origin = { 0.0, 0.0, 0.0 };
    int index;

    memset(&canvas, 0, sizeof(canvas));
    for (index = 0; index < 3; index++) {
        double screen_x;
        double screen_y;
        double reciprocal_w;
        mesh_canvas_set_whole_body_camera(&canvas, 512, 512, heights[index]);
        expect_near("whole-body camera FOV focal length", canvas.focal_length,
            1944.5130528576387, 1.0e-9);
        expect_near("whole-body camera Y", canvas.camera_y,
            expected_y[index], 1.0e-12);
        expect_near("whole-body camera Z", canvas.camera_z,
            expected_z[index], 1.0e-10);
        expect_near("whole-body FFL-to-body unit bridge", canvas.world_scale,
            1.0 / 7.0, 1.0e-15);
        expect_int("whole-body origin projects", mesh_canvas_project(&canvas,
            origin, &screen_x, &screen_y, &reciprocal_w), 1);
        expect_near("whole-body origin screen X", screen_x, 256.0, 1.0e-12);
        expect_near("whole-body origin screen Y", screen_y,
            expected_origin_screen_y[index], 1.0e-9);
        expect_near("whole-body reciprocal W", reciprocal_w,
            1.0 / expected_z[index], 1.0e-15);
    }
}

static uint32_t fnv1a_rgba(const uint8_t *bytes, size_t size) {
    uint32_t hash = 0x811c9dc5u;
    size_t i;
    for (i = 0; i < size; i++) {
        hash ^= bytes[i];
        hash *= 0x01000193u;
    }
    return hash;
}

static void expect_high_texture(const FflHighResource *resource, int section, int item,
    int width, int height, uint32_t expected_hash) {
    FflHighTexture texture;
    char label[96];
    int decoded = ffl_high_decode_texture(resource, section, item, &texture);
    snprintf(label, sizeof(label), "FFL high section %d item %d decodes", section, item);
    expect_int(label, decoded, 1);
    if (!decoded) return;
    snprintf(label, sizeof(label), "FFL high section %d item %d width", section, item);
    expect_int(label, texture.width, width);
    snprintf(label, sizeof(label), "FFL high section %d item %d height", section, item);
    expect_int(label, texture.height, height);
    snprintf(label, sizeof(label), "FFL high section %d item %d pixels", section, item);
    expect_color(label,
        fnv1a_rgba(texture.rgba, (size_t)texture.width * (size_t)texture.height * 4u),
        expected_hash);
    ffl_high_texture_free(&texture);
}

static void test_high_resource_textures(const char *ffl_path, const char *cfl_path) {
    static const int expected_counts[FFL_HIGH_TEX_COUNT] = {
        3, 132, 80, 28, 12, 12, 9, 2, 52, 6, 18
    };
    static const int expected_present[FFL_HIGH_TEX_COUNT] = {
        3, 14, 80, 28, 12, 12, 9, 2, 52, 6, 18
    };
    Buffer ffl_bytes;
    Buffer cfl_bytes;
    FflHighResource high_resource;
    FflHighResource truncated_high;
    CflResource cfl_resource;
    int section;

    memset(&ffl_bytes, 0, sizeof(ffl_bytes));
    memset(&cfl_bytes, 0, sizeof(cfl_bytes));
    memset(&high_resource, 0, sizeof(high_resource));
    memset(&cfl_resource, 0, sizeof(cfl_resource));
    if (!ffl_path || !cfl_path || !read_file(ffl_path, &ffl_bytes) ||
        !ffl_high_parse(&high_resource, ffl_bytes.data, ffl_bytes.size) ||
        !read_file(cfl_path, &cfl_bytes) ||
        !cfl_parse(&cfl_resource, cfl_bytes.data, cfl_bytes.size)) {
        fprintf(stderr, "Could not open renderer texture fixtures.\n");
        failures++;
        goto cleanup;
    }

    expect_int("FFL high fixture is detected as linear AFL layout",
        high_resource.textures_are_linear, 1);

    for (section = 0; section < FFL_HIGH_TEX_COUNT; section++) {
        int item;
        int present = 0;
        char label[64];
        snprintf(label, sizeof(label), "FFL high section %d declared records", section);
        expect_int(label, high_resource.texture_counts[section],
            expected_counts[section]);
        for (item = 0; item < high_resource.texture_counts[section]; item++) {
            FflHighTexture texture;
            if (ffl_high_decode_texture(&high_resource, section, item, &texture)) {
                present++;
                ffl_high_texture_free(&texture);
            }
        }
        snprintf(label, sizeof(label), "FFL high section %d decoded records", section);
        expect_int(label, present, expected_present[section]);
    }

    /* These fingerprints were independently decoded by the local authoritative
       FFL.js/WASM path from the same FFLResHigh.dat. Together they exercise
       all three resource formats (RGBA8, R8, and RG8). */
    expect_high_texture(&high_resource, FFL_HIGH_TEX_EYE, 33,
        152, 128, 0x2543b732u);
    expect_high_texture(&high_resource, FFL_HIGH_TEX_MOUTH, 30,
        176, 128, 0x47c96953u);
    expect_high_texture(&high_resource, FFL_HIGH_TEX_EYEBROW, 13,
        144, 128, 0xfe230b68u);
    expect_high_texture(&high_resource, FFL_HIGH_TEX_FACE_MAKEUP, 1,
        256, 512, 0xa9d11ce0u);
    expect_high_texture(&high_resource, FFL_HIGH_TEX_GLASS, 3,
        256, 256, 0x3add4d55u);
    expect_high_texture(&high_resource, FFL_HIGH_TEX_NOSELINE, 0,
        256, 256, 0xd737507cu);

    {
        FflHighTexture high_glass;
        CflTexture glass;
        OverlayOptions options;
        uint8_t sampled[4];
        uint8_t composited[4] = { 0, 0, 0, 0 };
        uint8_t raw_mask_pixel[4] = { 0, 0, 0, 0 };
        uint8_t *white_mode4 = NULL;
        size_t sample_offset = ((size_t)48 * 256u + 154u) * 4u;
        size_t pixel_count;
        size_t i;

        memset(&high_glass, 0, sizeof(high_glass));
        memset(&glass, 0, sizeof(glass));
        memset(&options, 0, sizeof(options));
        expect_int("FFL high glass 3 decodes for MODE4",
            ffl_high_decode_texture(&high_resource, FFL_HIGH_TEX_GLASS, 3,
                &high_glass), 1);
        if (high_glass.rgba) {
            /* Independently sampled from FFL.js/WASM's raw RG8 texture:
               glass 3 at (154,48) is R=36 coverage, G=255 intensity. */
            expect_byte("FFL glass preserves raw R", high_glass.rgba[sample_offset], 36);
            expect_byte("FFL glass preserves raw G", high_glass.rgba[sample_offset + 1], 255);
            expect_byte("FFL glass neutral B", high_glass.rgba[sample_offset + 2], 0);
            expect_byte("FFL glass storage alpha", high_glass.rgba[sample_offset + 3], 255);

            glass.width = high_glass.width;
            glass.height = high_glass.height;
            glass.format = high_glass.format;
            glass.rgba = high_glass.rgba;
            options.mode = MOD_MODE4;
            sample_modulated_pixel(&glass, sample_offset, 0x804020u,
                &options, sampled);
            expect_byte("MODE4 glass red uses G", sampled[0], 128);
            expect_byte("MODE4 glass green uses G", sampled[1], 64);
            expect_byte("MODE4 glass blue uses G", sampled[2], 32);
            expect_byte("MODE4 glass alpha uses R", sampled[3], 36);
            blend_source_over(composited, sampled);
            expect_byte("MODE4 composite keeps red", composited[0], 128);
            expect_byte("MODE4 composite keeps green", composited[1], 64);
            expect_byte("MODE4 composite keeps blue", composited[2], 32);
            expect_byte("MODE4 composite is non-opaque", composited[3], 36);

            options.mode = MOD_MODE3;
            sample_modulated_pixel(&glass, sample_offset, 0x804020u,
                &options, sampled);
            expect_byte("MODE3 partial red is premultiplied", sampled[0], 18);
            expect_byte("MODE3 partial green is premultiplied", sampled[1], 9);
            expect_byte("MODE3 partial blue is premultiplied", sampled[2], 5);
            expect_byte("MODE3 partial alpha uses R", sampled[3], 36);
            blend_raw_mask_first_pass(raw_mask_pixel, sampled);
            expect_byte("MODE3 raw-mask red stays premultiplied", raw_mask_pixel[0], 18);
            expect_byte("MODE3 raw-mask green stays premultiplied", raw_mask_pixel[1], 9);
            expect_byte("MODE3 raw-mask blue stays premultiplied", raw_mask_pixel[2], 5);
            expect_byte("MODE3 raw-mask keeps partial alpha", raw_mask_pixel[3], 36);

            pixel_count = (size_t)glass.width * (size_t)glass.height;
            white_mode4 = (uint8_t *)malloc(pixel_count * 4u);
            if (!white_mode4) {
                fprintf(stderr, "Could not allocate MODE4 glass test output.\n");
                failures++;
            } else {
                options.mode = MOD_MODE4;
                for (i = 0; i < pixel_count; i++) {
                    sample_modulated_pixel(&glass, i * 4u, 0xffffffu,
                        &options, white_mode4 + i * 4u);
                }
                expect_color("FFL glass 3 MODE4 white pixels",
                    fnv1a_rgba(white_mode4, pixel_count * 4u), 0x4104f445u);
            }
        }
        free(white_mode4);
        ffl_high_texture_free(&high_glass);
    }

    {
        FflHighTexture expected_high;
        CflTexture preferred;
        CflTexture expected_fallback;
        CflTexture fallback;
        uint32_t preferred_hash;
        uint32_t expected_high_hash;
        uint32_t fallback_hash;
        uint32_t expected_fallback_hash;

        memset(&expected_high, 0, sizeof(expected_high));
        memset(&preferred, 0, sizeof(preferred));
        memset(&expected_fallback, 0, sizeof(expected_fallback));
        memset(&fallback, 0, sizeof(fallback));
        cfl_resource.high_textures = &high_resource;
        expect_int("cap 9 high texture available",
            ffl_high_decode_texture(&high_resource, FFL_HIGH_TEX_CAP, 9,
                &expected_high), 1);
        expect_int("cap 9 prefers FFL high",
            decode_texture_or_warn(&cfl_resource, CFL_TEX_CAP, 9, &preferred), 1);
        if (preferred.rgba && expected_high.rgba) {
            preferred_hash = fnv1a_rgba(preferred.rgba,
                (size_t)preferred.width * (size_t)preferred.height * 4u);
            expected_high_hash = fnv1a_rgba(expected_high.rgba,
                (size_t)expected_high.width * (size_t)expected_high.height * 4u);
            expect_color("cap 9 preferred pixels", preferred_hash, expected_high_hash);
        }

        truncated_high = high_resource;
        truncated_high.size = 0x4a00u;
        cfl_resource.high_textures = &truncated_high;
        expect_int("cap 9 CFL fixture decodes",
            cfl_decode_texture(&cfl_resource, CFL_TEX_CAP, 9, &expected_fallback), 1);
        expect_int("cap 9 falls back per record",
            decode_texture_or_warn(&cfl_resource, CFL_TEX_CAP, 9, &fallback), 1);
        if (fallback.rgba && expected_fallback.rgba) {
            fallback_hash = fnv1a_rgba(fallback.rgba,
                (size_t)fallback.width * (size_t)fallback.height * 4u);
            expected_fallback_hash = fnv1a_rgba(expected_fallback.rgba,
                (size_t)expected_fallback.width * (size_t)expected_fallback.height * 4u);
            expect_color("cap 9 fallback pixels", fallback_hash, expected_fallback_hash);
        }
        ffl_high_texture_free(&expected_high);
        cfl_texture_free(&preferred);
        cfl_texture_free(&expected_fallback);
        cfl_texture_free(&fallback);
    }

    {
        FflHighTexture high_cap;
        CflTexture cfl_cap;
        CflTexture preferred_cap;
        uint32_t cfl_hash;
        uint32_t preferred_hash;

        memset(&high_cap, 0, sizeof(high_cap));
        memset(&cfl_cap, 0, sizeof(cfl_cap));
        memset(&preferred_cap, 0, sizeof(preferred_cap));
        cfl_resource.high_textures = &high_resource;
        expect_int("cap 0 is genuinely absent from FFL high",
            ffl_high_decode_texture(&high_resource, FFL_HIGH_TEX_CAP, 0,
                &high_cap), 0);
        expect_int("cap 0 CFL fallback exists",
            cfl_decode_texture(&cfl_resource, CFL_TEX_CAP, 0, &cfl_cap), 1);
        expect_int("cap 0 uses genuine CFL fallback",
            decode_texture_or_warn(&cfl_resource, CFL_TEX_CAP, 0,
                &preferred_cap), 1);
        if (cfl_cap.rgba && preferred_cap.rgba) {
            expect_int("cap 0 fallback width", preferred_cap.width, cfl_cap.width);
            expect_int("cap 0 fallback height", preferred_cap.height, cfl_cap.height);
            cfl_hash = fnv1a_rgba(cfl_cap.rgba,
                (size_t)cfl_cap.width * (size_t)cfl_cap.height * 4u);
            preferred_hash = fnv1a_rgba(preferred_cap.rgba,
                (size_t)preferred_cap.width * (size_t)preferred_cap.height * 4u);
            expect_color("cap 0 fallback pixels", preferred_hash, cfl_hash);
        }
        ffl_high_texture_free(&high_cap);
        cfl_texture_free(&cfl_cap);
        cfl_texture_free(&preferred_cap);
    }

cleanup:
    cfl_free(&cfl_resource);
    free(cfl_bytes.data);
    free(ffl_bytes.data);
}

int main(int argc, char **argv) {
    MiiFaceParams params;
    uint32_t lower;
    uint32_t upper;
    uint8_t mask_pixel[4] = { 0, 0, 0, 0 };
    const uint8_t eyebrow_pixel[4] = { 120, 110, 100, 255 };
    const uint8_t eye_pixel[4] = { 10, 20, 30, 255 };

    expect_count("faceline palette",
        sizeof(mii_skin_colors) / sizeof(mii_skin_colors[0]), 10u);
    expect_count("common palette",
        sizeof(mii_common_colors) / sizeof(mii_common_colors[0]), 100u);
    expect_count("upper-lip palette",
        sizeof(mii_upper_lip_colors) / sizeof(mii_upper_lip_colors[0]), 100u);

    test_whole_body_camera();

    /* Switch-only faceline colors must not collapse to the Ver3 fallback. */
    expect_color("faceline 6", mii_skin_color(6), 0xffbea5u);
    expect_color("faceline 9", mii_skin_color(9), 0x3c2d23u);
    expect_color("faceline legacy 5", mii_skin_color(5), 0x632c18u);

    /* Every MiiJS feature color is a Switch common-color index, even 0..7. */
    expect_color("hair common 0", mii_hair_color(0, 1), 0x2d2828u);
    expect_color("eye common 0", mii_eye_color(0, 8), 0x2d2828u);
    expect_color("glasses common 4", mii_glasses_color(4, 8), 0x787880u);
    expect_color("common 71", mii_hair_color(71, 1), 0x63c788u);

    /* MiiJS forward-port values retain the appearance of older formats. */
    expect_color("Ver3 hair 1", mii_hair_color(1, 1), 0x402010u);
    expect_color("Ver3 eye 0 forward-port", mii_eye_color(8, 8), 0x000000u);
    expect_color("Ver3 glasses 1 forward-port", mii_glasses_color(14, 8), 0x603810u);
    mouth_colors(19, &lower, &upper);
    expect_color("Ver3 mouth 0 forward-port lower", lower, 0xd85208u);
    expect_color("Ver3 mouth 0 forward-port upper", upper, 0x823018u);

    mouth_colors(0, &lower, &upper);
    expect_color("modern mouth 0 lower", lower, 0x2d2828u);
    expect_color("modern mouth 0 upper", upper, 0x171414u);
    mouth_colors(71, &lower, &upper);
    expect_color("modern mouth 71 lower", lower, 0x63c788u);
    expect_color("modern mouth 71 upper", upper, 0x47b36fu);

    memset(&params, 0, sizeof(params));
    params.hair_dye_color = 19;
    params.hair_dye_mode = 1;
    expect_color("mode 1 dyes hair",
        mii_render_hair_color(&params, 71, 1), tomodachi_hair_dye_colors[19]);
    expect_color("mode 1 keeps eyebrows",
        mii_render_eyebrow_color(&params, 71, 1), mii_common_colors[71]);
    expect_color("mode 1 keeps facial hair",
        mii_render_facial_hair_color(&params, 71, 1), mii_common_colors[71]);

    params.hair_dye_mode = 2;
    expect_color("mode 2 dyes hair",
        mii_render_hair_color(&params, 71, 1), tomodachi_hair_dye_colors[19]);
    expect_color("mode 2 dyes eyebrows",
        mii_render_eyebrow_color(&params, 71, 1), tomodachi_hair_dye_colors[19]);
    expect_color("mode 2 dyes facial hair",
        mii_render_facial_hair_color(&params, 71, 1), tomodachi_hair_dye_colors[19]);

    params.hair_dye_mode = 3;
    expect_color("reserved mode keeps hair",
        mii_render_hair_color(&params, 71, 1), mii_common_colors[71]);
    expect_color("reserved mode keeps eyebrows",
        mii_render_eyebrow_color(&params, 71, 1), mii_common_colors[71]);
    expect_color("reserved mode keeps facial hair",
        mii_render_facial_hair_color(&params, 71, 1), mii_common_colors[71]);

    /* Physical HeadType is the native default/forCap/forHeadgear selector. */
    expect_int("HeadType 5 uses normal model",
        tomodachi_headwear_visibility_animation_index(5), 0);
    expect_int("HeadType 6 uses cap model",
        tomodachi_headwear_visibility_animation_index(6), 1);
    expect_int("HeadType 7 uses headgear model",
        tomodachi_headwear_visibility_animation_index(7), 2);
    expect_int("HeadType 8 uses headgear model",
        tomodachi_headwear_visibility_animation_index(8), 2);
    expect_int("HeadType 10 uses normal model",
        tomodachi_headwear_visibility_animation_index(10), 0);

    /* FFL draws eyebrows before eyes with a destination-alpha blend, so an
       opaque eyebrow must retain its RGB when a later eye overlaps it. The
       alpha-only second pass must not disturb that established front layer. */
    blend_raw_mask_first_pass(mask_pixel, eyebrow_pixel);
    blend_raw_mask_first_pass(mask_pixel, eye_pixel);
    expect_byte("overlap keeps eyebrow red", mask_pixel[0], eyebrow_pixel[0]);
    expect_byte("overlap keeps eyebrow green", mask_pixel[1], eyebrow_pixel[1]);
    expect_byte("overlap keeps eyebrow blue", mask_pixel[2], eyebrow_pixel[2]);
    mask_pixel[3] = 0;
    blend_raw_mask_second_pass(mask_pixel, eyebrow_pixel);
    blend_raw_mask_second_pass(mask_pixel, eye_pixel);
    expect_byte("second pass restores alpha", mask_pixel[3], 255);
    expect_byte("second pass preserves eyebrow red", mask_pixel[0], eyebrow_pixel[0]);
    expect_byte("second pass preserves eyebrow green", mask_pixel[1], eyebrow_pixel[1]);
    expect_byte("second pass preserves eyebrow blue", mask_pixel[2], eyebrow_pixel[2]);

    if (argc >= 3) test_high_resource_textures(argv[1], argv[2]);
    else {
        fprintf(stderr, "FFLResHigh.dat and CFL_Res.dat test paths are required.\n");
        failures++;
    }

    if (failures != 0) return 1;
    puts("Mii canonical color and raw-mask tests passed");
    return 0;
}
