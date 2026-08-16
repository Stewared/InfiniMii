#include "native_facepaint_decode.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <string_view>
#include <vector>

namespace {

constexpr std::size_t kCanvasBlockLinearBytes = 0x40000;
constexpr std::size_t kUgcBlockLinearBytes = 0x20000;
constexpr std::size_t kUgcBlocksX = 128;
constexpr std::size_t kUgcBlocksY = 128;
constexpr std::size_t kMaximumEncodedBytes = 16U * 1024U * 1024U;
constexpr std::size_t kBlockHeightGobs = 16;
constexpr std::array<std::uint8_t, 4> kZstdMagic{{0x28, 0xb5, 0x2f, 0xfd}};
constexpr unsigned long long kZstdContentSizeUnknown =
    std::numeric_limits<unsigned long long>::max();
constexpr unsigned long long kZstdContentSizeError = kZstdContentSizeUnknown - 1;

void set_error(char* output, std::size_t capacity, std::string_view message) {
    if (output == nullptr || capacity == 0) return;
    const std::size_t count = std::min(capacity - 1, message.size());
    std::memcpy(output, message.data(), count);
    output[count] = '\0';
}

void clear_summary(ltd_native_facepaint_decode_summary* summary) {
    if (summary != nullptr) *summary = {};
}

bool begins_with_zstd(const std::uint8_t* source, std::size_t size) {
    return source != nullptr && size >= kZstdMagic.size() &&
           std::equal(kZstdMagic.begin(), kZstdMagic.end(), source);
}

bool ranges_overlap(
    const void* left_pointer, std::size_t left_size,
    const void* right_pointer, std::size_t right_size) {
    if (left_size == 0 || right_size == 0 || left_pointer == nullptr ||
        right_pointer == nullptr) {
        return false;
    }
    const auto left = reinterpret_cast<std::uintptr_t>(left_pointer);
    const auto right = reinterpret_cast<std::uintptr_t>(right_pointer);
    if (left > std::numeric_limits<std::uintptr_t>::max() - left_size ||
        right > std::numeric_limits<std::uintptr_t>::max() - right_size) {
        return true;
    }
    return left < right + right_size && right < left + left_size;
}

std::size_t block_linear_address(
    std::size_t x_element, std::size_t y_element,
    std::size_t width_elements, std::size_t bytes_per_element) {
    const std::size_t width_gobs =
        (width_elements * bytes_per_element + 63U) / 64U;
    const std::size_t x_bytes = x_element * bytes_per_element;
    return
        (y_element / (8U * kBlockHeightGobs)) *
            512U * kBlockHeightGobs * width_gobs +
        (x_bytes / 64U) * 512U * kBlockHeightGobs +
        ((y_element % (8U * kBlockHeightGobs)) / 8U) * 512U +
        ((x_bytes % 64U) / 32U) * 256U +
        ((y_element % 8U) / 2U) * 64U +
        ((x_bytes % 32U) / 16U) * 32U +
        (y_element % 2U) * 16U +
        (x_bytes % 16U);
}

ltd_native_facepaint_status decompress_exact(
    const ltd_native_facepaint_zstd_api& zstd,
    const std::uint8_t* encoded,
    std::size_t encoded_size,
    std::size_t decoded_size,
    std::vector<std::uint8_t>& decoded,
    std::string_view label,
    char* error,
    std::size_t error_capacity) {
    if (!begins_with_zstd(encoded, encoded_size)) {
        set_error(error, error_capacity,
                  label == "Canvas" ? "Canvas is not a Zstandard frame"
                                    : "UGC is not a Zstandard frame");
        return LTD_NATIVE_FACEPAINT_NOT_ZSTD;
    }
    const std::size_t frame_size =
        zstd.find_frame_compressed_size(encoded, encoded_size);
    if (zstd.is_error(frame_size) != 0 || frame_size == 0 ||
        frame_size > encoded_size) {
        set_error(error, error_capacity,
                  label == "Canvas" ? "Canvas has an invalid or truncated Zstandard frame"
                                    : "UGC has an invalid or truncated Zstandard frame");
        return LTD_NATIVE_FACEPAINT_ZSTD_INVALID;
    }
    if (frame_size != encoded_size) {
        set_error(error, error_capacity,
                  label == "Canvas" ? "Canvas contains trailing or concatenated frame data"
                                    : "UGC contains trailing or concatenated frame data");
        return LTD_NATIVE_FACEPAINT_ZSTD_TRAILING_DATA;
    }
    const unsigned long long content_size =
        zstd.get_frame_content_size(encoded, encoded_size);
    if (content_size == kZstdContentSizeError) {
        set_error(error, error_capacity,
                  label == "Canvas" ? "Canvas has an invalid Zstandard content size"
                                    : "UGC has an invalid Zstandard content size");
        return LTD_NATIVE_FACEPAINT_ZSTD_INVALID;
    }
    if (content_size == kZstdContentSizeUnknown) {
        set_error(error, error_capacity,
                  label == "Canvas" ? "Canvas Zstandard frame omits its decoded size"
                                    : "UGC Zstandard frame omits its decoded size");
        return LTD_NATIVE_FACEPAINT_ZSTD_UNKNOWN_SIZE;
    }
    if (content_size != decoded_size) {
        set_error(error, error_capacity,
                  label == "Canvas" ? "Canvas Zstandard decoded size differs from RGBA8 surface"
                                    : "UGC Zstandard decoded size differs from BC1 surface");
        return LTD_NATIVE_FACEPAINT_ZSTD_SIZE_MISMATCH;
    }
    decoded.resize(decoded_size);
    const std::size_t actual = zstd.decompress(
        decoded.data(), decoded.size(), encoded, encoded_size);
    if (zstd.is_error(actual) != 0) {
        set_error(error, error_capacity,
                  label == "Canvas" ? "Canvas Zstandard decompression failed"
                                    : "UGC Zstandard decompression failed");
        return LTD_NATIVE_FACEPAINT_ZSTD_INVALID;
    }
    if (actual != decoded_size) {
        set_error(error, error_capacity,
                  label == "Canvas" ? "Canvas decompressed byte count changed"
                                    : "UGC decompressed byte count changed");
        return LTD_NATIVE_FACEPAINT_ZSTD_SIZE_MISMATCH;
    }
    return LTD_NATIVE_FACEPAINT_OK;
}

ltd_native_facepaint_status deswizzle_canvas(
    const std::vector<std::uint8_t>& source,
    std::uint8_t* output,
    char* error,
    std::size_t error_capacity) {
    for (std::size_t y = 0; y < LTD_NATIVE_FACEPAINT_CANVAS_HEIGHT; ++y) {
        for (std::size_t x = 0; x < LTD_NATIVE_FACEPAINT_CANVAS_WIDTH; ++x) {
            const std::size_t source_offset =
                block_linear_address(x, y, LTD_NATIVE_FACEPAINT_CANVAS_WIDTH, 4);
            if (source_offset > source.size() || source.size() - source_offset < 4) {
                set_error(error, error_capacity,
                          "Canvas block-linear address exceeds its payload");
                return LTD_NATIVE_FACEPAINT_BLOCK_LINEAR_INVALID;
            }
            const std::size_t output_offset =
                (y * LTD_NATIVE_FACEPAINT_CANVAS_WIDTH + x) * 4U;
            std::memcpy(output + output_offset, source.data() + source_offset, 4);
        }
    }
    return LTD_NATIVE_FACEPAINT_OK;
}

std::array<std::uint16_t, 4> rgb565(std::uint16_t value) {
    const std::uint16_t red = static_cast<std::uint16_t>((value >> 11U) & 0x1fU);
    const std::uint16_t green = static_cast<std::uint16_t>((value >> 5U) & 0x3fU);
    const std::uint16_t blue = static_cast<std::uint16_t>(value & 0x1fU);
    return {{
        static_cast<std::uint16_t>((red << 3U) | (red >> 2U)),
        static_cast<std::uint16_t>((green << 2U) | (green >> 4U)),
        static_cast<std::uint16_t>((blue << 3U) | (blue >> 2U)),
        255U,
    }};
}

void write_palette_pixel(
    std::uint8_t* output,
    const std::array<std::uint16_t, 4>& value) {
    output[0] = static_cast<std::uint8_t>(value[0]);
    output[1] = static_cast<std::uint8_t>(value[1]);
    output[2] = static_cast<std::uint8_t>(value[2]);
    output[3] = static_cast<std::uint8_t>(value[3]);
}

ltd_native_facepaint_status decode_ugc(
    const std::vector<std::uint8_t>& source,
    std::uint8_t* output,
    char* error,
    std::size_t error_capacity) {
    for (std::size_t block_y = 0; block_y < kUgcBlocksY; ++block_y) {
        for (std::size_t block_x = 0; block_x < kUgcBlocksX; ++block_x) {
            const std::size_t source_offset =
                block_linear_address(block_x, block_y, kUgcBlocksX, 8);
            if (source_offset > source.size() || source.size() - source_offset < 8) {
                set_error(error, error_capacity,
                          "UGC block-linear address exceeds its payload");
                return LTD_NATIVE_FACEPAINT_BLOCK_LINEAR_INVALID;
            }
            const auto* block = source.data() + source_offset;
            const std::uint16_t color0 = static_cast<std::uint16_t>(
                block[0] | (static_cast<std::uint16_t>(block[1]) << 8U));
            const std::uint16_t color1 = static_cast<std::uint16_t>(
                block[2] | (static_cast<std::uint16_t>(block[3]) << 8U));
            const std::uint32_t selectors =
                static_cast<std::uint32_t>(block[4]) |
                (static_cast<std::uint32_t>(block[5]) << 8U) |
                (static_cast<std::uint32_t>(block[6]) << 16U) |
                (static_cast<std::uint32_t>(block[7]) << 24U);
            std::array<std::array<std::uint16_t, 4>, 4> palette{};
            palette[0] = rgb565(color0);
            palette[1] = rgb565(color1);
            if (color0 > color1) {
                for (std::size_t channel = 0; channel < 4; ++channel) {
                    palette[2][channel] = static_cast<std::uint16_t>(
                        (2U * palette[0][channel] + palette[1][channel]) / 3U);
                    palette[3][channel] = static_cast<std::uint16_t>(
                        (palette[0][channel] + 2U * palette[1][channel]) / 3U);
                }
            } else {
                for (std::size_t channel = 0; channel < 4; ++channel) {
                    palette[2][channel] = static_cast<std::uint16_t>(
                        (palette[0][channel] + palette[1][channel]) / 2U);
                }
                palette[3] = {{0, 0, 0, 0}};
            }
            for (std::size_t pixel_y = 0; pixel_y < 4; ++pixel_y) {
                for (std::size_t pixel_x = 0; pixel_x < 4; ++pixel_x) {
                    const std::size_t selector_index =
                        2U * (pixel_y * 4U + pixel_x);
                    const std::size_t palette_index =
                        (selectors >> selector_index) & 3U;
                    const std::size_t x = block_x * 4U + pixel_x;
                    const std::size_t y = block_y * 4U + pixel_y;
                    const std::size_t output_offset =
                        (y * LTD_NATIVE_FACEPAINT_UGC_WIDTH + x) * 4U;
                    write_palette_pixel(output + output_offset, palette[palette_index]);
                }
            }
        }
    }
    return LTD_NATIVE_FACEPAINT_OK;
}

bool valid_zstd_api(const ltd_native_facepaint_zstd_api* zstd) {
    return zstd != nullptr &&
           zstd->abi_version == LTD_NATIVE_FACEPAINT_ZSTD_ABI_VERSION &&
           zstd->reserved == 0 &&
           zstd->find_frame_compressed_size != nullptr &&
           zstd->get_frame_content_size != nullptr &&
           zstd->decompress != nullptr && zstd->is_error != nullptr;
}

}  // namespace

extern "C" {

std::uint32_t LTD_NATIVE_FACEPAINT_DECODE_CALL
ltd_native_facepaint_decode_abi_version(void) {
    return LTD_NATIVE_FACEPAINT_DECODE_ABI_VERSION;
}

const char* LTD_NATIVE_FACEPAINT_DECODE_CALL
ltd_native_facepaint_decode_contract_sha256(void) {
    return LTD_NATIVE_FACEPAINT_CONTRACT_SHA256;
}

const char* LTD_NATIVE_FACEPAINT_DECODE_CALL
ltd_native_facepaint_status_name(ltd_native_facepaint_status status) {
    switch (status) {
        case LTD_NATIVE_FACEPAINT_OK: return "OK";
        case LTD_NATIVE_FACEPAINT_ABSENT: return "ABSENT";
        case LTD_NATIVE_FACEPAINT_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
        case LTD_NATIVE_FACEPAINT_UNSUPPORTED_VERSION: return "UNSUPPORTED_VERSION";
        case LTD_NATIVE_FACEPAINT_INCOMPLETE_PAIR: return "INCOMPLETE_PAIR";
        case LTD_NATIVE_FACEPAINT_OUTPUT_TOO_SMALL: return "OUTPUT_TOO_SMALL";
        case LTD_NATIVE_FACEPAINT_ZSTD_UNAVAILABLE: return "ZSTD_UNAVAILABLE";
        case LTD_NATIVE_FACEPAINT_NOT_ZSTD: return "NOT_ZSTD";
        case LTD_NATIVE_FACEPAINT_ZSTD_INVALID: return "ZSTD_INVALID";
        case LTD_NATIVE_FACEPAINT_ZSTD_TRAILING_DATA: return "ZSTD_TRAILING_DATA";
        case LTD_NATIVE_FACEPAINT_ZSTD_UNKNOWN_SIZE: return "ZSTD_UNKNOWN_SIZE";
        case LTD_NATIVE_FACEPAINT_ZSTD_SIZE_MISMATCH: return "ZSTD_SIZE_MISMATCH";
        case LTD_NATIVE_FACEPAINT_BLOCK_LINEAR_INVALID: return "BLOCK_LINEAR_INVALID";
        case LTD_NATIVE_FACEPAINT_ALLOCATION_FAILED: return "ALLOCATION_FAILED";
        default: return "UNKNOWN";
    }
}

void LTD_NATIVE_FACEPAINT_DECODE_CALL
ltd_native_facepaint_get_tex_srt(ltd_native_facepaint_tex_srt* output) {
    if (output == nullptr) return;
    *output = {};
    const float size_x = 0.75f;
    const float size_y = 0.75f;
    const float offset_x = 0.0f;
    const float offset_y = 0.03f;
    float scale_x = 1.0f / size_x;
    float scale_y = 1.0f / size_y;
    float translation_x = size_x * 0.5f;
    translation_x = 0.5f - translation_x;
    translation_x = translation_x + offset_x;
    float translation_y = size_y * 0.5f;
    translation_y = 0.5f - translation_y;
    translation_y = translation_y + offset_y;
    float matrix_tx = scale_x * translation_x;
    matrix_tx = -matrix_tx;
    float matrix_ty = translation_y - 1.0f;
    matrix_ty = scale_y * matrix_ty;
    matrix_ty = matrix_ty + 1.0f;
    output->size[0] = size_x;
    output->size[1] = size_y;
    output->offset[0] = offset_x;
    output->offset[1] = offset_y;
    output->scaling[0] = scale_x;
    output->scaling[1] = scale_y;
    output->translation[0] = translation_x;
    output->translation[1] = translation_y;
    output->affine_rows[0] = scale_x;
    output->affine_rows[1] = 0.0f;
    output->affine_rows[2] = matrix_tx;
    output->affine_rows[3] = 0.0f;
    output->affine_rows[4] = scale_y;
    output->affine_rows[5] = matrix_ty;
    output->mode = 0;
    output->rotation = 0.0f;
}

ltd_native_facepaint_status LTD_NATIVE_FACEPAINT_DECODE_CALL
ltd_native_facepaint_decode(
    const ltd_native_facepaint_decode_request* request,
    ltd_native_facepaint_decode_summary* summary,
    char* error,
    std::size_t error_capacity) {
    clear_summary(summary);
    set_error(error, error_capacity, "");
    if (request == nullptr || summary == nullptr ||
        request->reserved[0] != 0 || request->reserved[1] != 0 ||
        request->has_canvas > 1 || request->has_ugc_texture > 1) {
        set_error(error, error_capacity, "invalid facepaint decode request");
        return LTD_NATIVE_FACEPAINT_INVALID_ARGUMENT;
    }
    const bool any_flag = request->has_canvas != 0 || request->has_ugc_texture != 0;
    const bool any_bytes = request->canvas_encoded_byte_count != 0 ||
                           request->ugc_encoded_byte_count != 0;
    if (request->container_version != 3) {
        if (any_flag || any_bytes) {
            set_error(error, error_capacity,
                      "embedded facepaint is supported only for ShareMii v3");
            return LTD_NATIVE_FACEPAINT_UNSUPPORTED_VERSION;
        }
        summary->abi_version = LTD_NATIVE_FACEPAINT_DECODE_ABI_VERSION;
        summary->container_version = request->container_version;
        return LTD_NATIVE_FACEPAINT_ABSENT;
    }
    if (!any_flag) {
        if (any_bytes) {
            set_error(error, error_capacity,
                      "undeclared ShareMii v3 facepaint payload bytes are present");
            return LTD_NATIVE_FACEPAINT_INCOMPLETE_PAIR;
        }
        summary->abi_version = LTD_NATIVE_FACEPAINT_DECODE_ABI_VERSION;
        summary->container_version = 3;
        return LTD_NATIVE_FACEPAINT_ABSENT;
    }
    if (request->has_canvas == 0 || request->has_ugc_texture == 0 ||
        request->canvas_encoded == nullptr || request->ugc_encoded == nullptr ||
        request->canvas_encoded_byte_count == 0 ||
        request->ugc_encoded_byte_count == 0) {
        set_error(error, error_capacity,
                  "ShareMii v3 facepaint requires both Canvas and UGC payloads");
        return LTD_NATIVE_FACEPAINT_INCOMPLETE_PAIR;
    }
    if (request->canvas_encoded_byte_count > kMaximumEncodedBytes ||
        request->ugc_encoded_byte_count > kMaximumEncodedBytes) {
        set_error(error, error_capacity, "facepaint encoded payload exceeds safety limit");
        return LTD_NATIVE_FACEPAINT_INVALID_ARGUMENT;
    }
    if (request->canvas_rgba8 == nullptr || request->ugc_rgba8 == nullptr ||
        request->canvas_rgba8_capacity < LTD_NATIVE_FACEPAINT_CANVAS_RGBA8_BYTES ||
        request->ugc_rgba8_capacity < LTD_NATIVE_FACEPAINT_UGC_RGBA8_BYTES) {
        set_error(error, error_capacity, "caller-owned facepaint output is too small");
        return LTD_NATIVE_FACEPAINT_OUTPUT_TOO_SMALL;
    }
    if (!valid_zstd_api(request->zstd)) {
        set_error(error, error_capacity, "native zstd adapter is unavailable or invalid");
        return LTD_NATIVE_FACEPAINT_ZSTD_UNAVAILABLE;
    }
    if (ranges_overlap(request->canvas_rgba8, LTD_NATIVE_FACEPAINT_CANVAS_RGBA8_BYTES,
                       request->ugc_rgba8, LTD_NATIVE_FACEPAINT_UGC_RGBA8_BYTES) ||
        ranges_overlap(request->canvas_rgba8, LTD_NATIVE_FACEPAINT_CANVAS_RGBA8_BYTES,
                       request->canvas_encoded, request->canvas_encoded_byte_count) ||
        ranges_overlap(request->canvas_rgba8, LTD_NATIVE_FACEPAINT_CANVAS_RGBA8_BYTES,
                       request->ugc_encoded, request->ugc_encoded_byte_count) ||
        ranges_overlap(request->ugc_rgba8, LTD_NATIVE_FACEPAINT_UGC_RGBA8_BYTES,
                       request->canvas_encoded, request->canvas_encoded_byte_count) ||
        ranges_overlap(request->ugc_rgba8, LTD_NATIVE_FACEPAINT_UGC_RGBA8_BYTES,
                       request->ugc_encoded, request->ugc_encoded_byte_count)) {
        set_error(error, error_capacity, "facepaint input and output buffers overlap");
        return LTD_NATIVE_FACEPAINT_INVALID_ARGUMENT;
    }
    try {
        /* Decompress and validate both frames before touching caller output. */
        std::vector<std::uint8_t> canvas_decoded;
        std::vector<std::uint8_t> ugc_decoded;
        auto status = decompress_exact(
            *request->zstd, request->canvas_encoded,
            request->canvas_encoded_byte_count, kCanvasBlockLinearBytes,
            canvas_decoded, "Canvas", error, error_capacity);
        if (status != LTD_NATIVE_FACEPAINT_OK) return status;
        status = decompress_exact(
            *request->zstd, request->ugc_encoded,
            request->ugc_encoded_byte_count, kUgcBlockLinearBytes,
            ugc_decoded, "UGC", error, error_capacity);
        if (status != LTD_NATIVE_FACEPAINT_OK) return status;
        status = deswizzle_canvas(
            canvas_decoded, request->canvas_rgba8, error, error_capacity);
        if (status != LTD_NATIVE_FACEPAINT_OK) return status;
        status = decode_ugc(
            ugc_decoded, request->ugc_rgba8, error, error_capacity);
        if (status != LTD_NATIVE_FACEPAINT_OK) return status;
    } catch (const std::bad_alloc&) {
        set_error(error, error_capacity, "facepaint decode allocation failed");
        return LTD_NATIVE_FACEPAINT_ALLOCATION_FAILED;
    }
    summary->abi_version = LTD_NATIVE_FACEPAINT_DECODE_ABI_VERSION;
    summary->container_version = 3;
    summary->canvas_width = LTD_NATIVE_FACEPAINT_CANVAS_WIDTH;
    summary->canvas_height = LTD_NATIVE_FACEPAINT_CANVAS_HEIGHT;
    summary->ugc_width = LTD_NATIVE_FACEPAINT_UGC_WIDTH;
    summary->ugc_height = LTD_NATIVE_FACEPAINT_UGC_HEIGHT;
    summary->canvas_encoded_byte_count = request->canvas_encoded_byte_count;
    summary->ugc_encoded_byte_count = request->ugc_encoded_byte_count;
    summary->canvas_rgba8_byte_count = LTD_NATIVE_FACEPAINT_CANVAS_RGBA8_BYTES;
    summary->ugc_rgba8_byte_count = LTD_NATIVE_FACEPAINT_UGC_RGBA8_BYTES;
    summary->decoded = 1;
    return LTD_NATIVE_FACEPAINT_OK;
}

}  // extern "C"
