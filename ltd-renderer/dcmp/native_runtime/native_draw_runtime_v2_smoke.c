#include "native_draw_runtime_v2.h"

#include <stdint.h>
#include <string.h>

static void initialize_attachments(
    ltd_draw_attachments *attachments,
    double color[3],
    double depth[1],
    double alpha[1]
) {
    memset(attachments, 0, sizeof(*attachments));
    attachments->color = color;
    attachments->color_capacity_bytes = sizeof(double) * 3;
    attachments->color_row_stride_bytes = sizeof(double) * 3;
    attachments->depth = depth;
    attachments->depth_capacity_bytes = sizeof(double);
    attachments->depth_row_stride_bytes = sizeof(double);
    attachments->alpha = alpha;
    attachments->alpha_capacity_bytes = sizeof(double);
    attachments->alpha_row_stride_bytes = sizeof(double);
    attachments->width = 1;
    attachments->height = 1;
}

int main(void) {
    static const double rgba[4] = {1.0, 1.0, 1.0, 1.0};
    static const int64_t levels[3] = {0, 1, 1};
    double color[3] = {0.0, 0.0, 0.0};
    double depth[1] = {1.0};
    double alpha[1] = {0.0};
    ltd_draw_attachments attachments;
    ltd_draw_head816_input head;
    ltd_draw_hair_input hair;
    ltd_draw_outfit_input outfit;
    uint64_t written = UINT64_C(99);

    if (ltd_draw_runtime_v2_abi_version() != LTD_DRAW_RUNTIME_V2_ABI_VERSION) return 1;
    if (strcmp(ltd_draw_runtime_v2_contract_sha256(), LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256) != 0) return 2;
    if (strcmp(ltd_draw_runtime_v2_wrapper_sha256(), LTD_DRAW_RUNTIME_V2_WRAPPER_SHA256) != 0) return 3;
    if (ltd_draw_runtime_v2_require(
            LTD_DRAW_RUNTIME_V2_ABI_VERSION,
            LTD_DRAW_RUNTIME_V2_CONTRACT_SHA256
        ) != LTD_DRAW_RUNTIME_OK) return 4;

    initialize_attachments(&attachments, color, depth, alpha);
    memset(&head, 0, sizeof(head));
    head.albedo_texture.texels = rgba;
    head.albedo_texture.texel_count = 1;
    head.albedo_texture.width = 1;
    head.albedo_texture.height = 1;
    head.normal.texels = rgba;
    head.normal.texel_count = 1;
    head.normal.levels = levels;
    head.normal.level_count = 1;
    head.light_direction[2] = 1.0;
    head.light_color[0] = head.light_color[1] = head.light_color[2] = 1.0;
    head.ambient_color[0] = head.ambient_color[1] = head.ambient_color[2] = 1.0;
    head.alpha_scalar = 1.0;
    head.alpha_cutoff = 1.0 / 255.0;
    head.perspective_correct = 1;
    if (ltd_draw_head816(&attachments, &head, &written) != LTD_DRAW_RUNTIME_OK || written != 0) return 5;

    memset(&hair, 0, sizeof(hair));
    hair.mim.texels = rgba;
    hair.mim.texel_count = 1;
    hair.mim.levels = levels;
    hair.mim.level_count = 1;
    hair.parameters[25] = 1.0;
    hair.profile = LTD_DRAW_HAIR564_EQUAL_ENDPOINT;
    if (ltd_draw_hair(&attachments, &hair, &written) != LTD_DRAW_RUNTIME_OK || written != 0) return 6;

    memset(&outfit, 0, sizeof(outfit));
    outfit.albedo.texels = rgba;
    outfit.albedo.texel_count = 1;
    outfit.albedo.levels = levels;
    outfit.albedo.level_count = 1;
    outfit.normal.texels = rgba;
    outfit.normal.texel_count = 1;
    outfit.normal.levels = levels;
    outfit.normal.level_count = 1;
    outfit.light_direction[2] = 1.0;
    outfit.light_color[0] = outfit.light_color[1] = outfit.light_color[2] = 1.0;
    outfit.ambient_color[0] = outfit.ambient_color[1] = outfit.ambient_color[2] = 1.0;
    outfit.perspective_correct = 1;
    outfit.profile = LTD_DRAW_OUTFIT_TOPS984;
    if (ltd_draw_outfit(&attachments, &outfit, &written) != LTD_DRAW_RUNTIME_OK || written != 0) return 7;
    return 0;
}
