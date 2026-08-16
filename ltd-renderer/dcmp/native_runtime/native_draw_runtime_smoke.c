#include "native_draw_runtime.h"

#include <string.h>

int main(void) {
    double color[3] = {0.0, 0.0, 0.0};
    double depth[1] = {-1.0};
    uint64_t written = UINT64_C(99);
    ltd_draw_attachments attachments = {
        color, sizeof(color), sizeof(color),
        depth, sizeof(depth), sizeof(depth),
        NULL, 0, 0,
        1, 1
    };
    ltd_draw_plain_skin_input input;
    memset(&input, 0, sizeof(input));
    input.base_color_linear[0] = 1.0;
    input.base_color_linear[1] = 1.0;
    input.base_color_linear[2] = 1.0;
    input.light_direction[2] = 1.0;
    input.light_color[0] = 1.0;
    input.light_color[1] = 1.0;
    input.light_color[2] = 1.0;
    input.ambient_color[0] = 1.0;
    input.ambient_color[1] = 1.0;
    input.ambient_color[2] = 1.0;
    input.light_intensity = 1.0;
    input.ambient_intensity = 1.0;
    input.perspective_correct = 1;
    if (ltd_draw_runtime_abi_version() != LTD_DRAW_RUNTIME_ABI_VERSION) return 10;
    if (strcmp(ltd_draw_runtime_contract_sha256(), LTD_DRAW_RUNTIME_CONTRACT_SHA256) != 0) return 11;
    if (ltd_draw_runtime_require(
        LTD_DRAW_RUNTIME_ABI_VERSION, LTD_DRAW_RUNTIME_CONTRACT_SHA256
    ) != LTD_DRAW_RUNTIME_OK) return 12;
    if (ltd_draw_runtime_require(
        LTD_DRAW_RUNTIME_ABI_VERSION + 1, LTD_DRAW_RUNTIME_CONTRACT_SHA256
    ) != LTD_DRAW_RUNTIME_ABI_MISMATCH) return 13;
    if (ltd_draw_plain_skin(&attachments, &input, &written) != LTD_DRAW_RUNTIME_OK) return 14;
    if (written != 0 || color[0] != 0.0 || depth[0] != -1.0) return 15;
    return 0;
}
