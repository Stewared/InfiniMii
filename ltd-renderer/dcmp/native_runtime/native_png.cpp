#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "native_png.h"

#include <algorithm>
#include <cfenv>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <iterator>
#include <new>
#include <string>
#include <utility>
#include <vector>

#if !defined(_WIN32) || !defined(_WIN64)
#error This exact native PNG backend currently targets the Windows x64 runtime.
#endif

namespace {

constexpr char kAcceptedZlibVersion[] = "1.3.1.zlib-ng";
constexpr std::uint32_t kProbeStreamSize = 887;
constexpr std::uint32_t kProbeStreamCrc32 = 0xd3cdd49bU;
constexpr std::uint32_t kMaximumDimension = 16384;
constexpr std::size_t kPillowEncoderBlock = 65536;

constexpr int kZNoFlush = 0;
constexpr int kZFinish = 4;
constexpr int kZOk = 0;
constexpr int kZStreamEnd = 1;
constexpr int kZDeflated = 8;
constexpr int kZFiltered = 1;
constexpr int kZBestCompression = 9;

using z_byte = unsigned char;
using z_uint = unsigned int;
using z_ulong = unsigned long;
using z_alloc_func = void*(__cdecl*)(void*, z_uint, z_uint);
using z_free_func = void(__cdecl*)(void*, void*);

struct z_stream_compat {
    z_byte* next_in;
    z_uint avail_in;
    z_ulong total_in;
    z_byte* next_out;
    z_uint avail_out;
    z_ulong total_out;
    char* msg;
    void* state;
    z_alloc_func zalloc;
    z_free_func zfree;
    void* opaque;
    int data_type;
    z_ulong adler;
    z_ulong reserved;
};

static_assert(sizeof(unsigned long) == 4, "zlib compatibility ABI requires 32-bit uLong");

using zlib_version_function = const char*(__cdecl*)(void);
using deflate_init2_function = int(__cdecl*)(
    z_stream_compat*, int, int, int, int, int, const char*, int
);
using deflate_function = int(__cdecl*)(z_stream_compat*, int);
using deflate_end_function = int(__cdecl*)(z_stream_compat*);

struct zlib_api {
    HMODULE module = nullptr;
    zlib_version_function version = nullptr;
    deflate_init2_function deflate_init2 = nullptr;
    deflate_function deflate = nullptr;
    deflate_end_function deflate_end = nullptr;
    std::string version_text;
};

}  // namespace

struct infinimii_native_png_encoder {
    zlib_api zlib;
};

namespace {

struct compressed_stream {
    std::vector<std::vector<std::uint8_t>> chunks;
    std::size_t byte_count = 0;
};

void set_error(char* output, std::size_t capacity, const std::string& message) {
    if (output == nullptr || capacity == 0) {
        return;
    }
    const std::size_t count = std::min(capacity - 1, message.size());
    std::memcpy(output, message.data(), count);
    output[count] = '\0';
}

void clear_error(char* output, std::size_t capacity) {
    if (output != nullptr && capacity != 0) {
        output[0] = '\0';
    }
}

std::string windows_error_message(const char* operation, DWORD code) {
    return std::string(operation) + " failed with Windows error " +
           std::to_string(static_cast<unsigned long>(code));
}

bool checked_multiply(std::size_t left, std::size_t right, std::size_t& output) {
    if (left != 0 && right > std::numeric_limits<std::size_t>::max() / left) {
        return false;
    }
    output = left * right;
    return true;
}

bool valid_dimensions(std::uint32_t width, std::uint32_t height) {
    return width > 0 && height > 0 && width <= kMaximumDimension &&
           height <= kMaximumDimension;
}

std::uint32_t crc32_bytes(const std::uint8_t* bytes, std::size_t size) {
    std::uint32_t crc = 0xffffffffU;
    for (std::size_t index = 0; index < size; ++index) {
        crc ^= bytes[index];
        for (unsigned bit = 0; bit < 8; ++bit) {
            const std::uint32_t mask = 0U - (crc & 1U);
            crc = (crc >> 1U) ^ (0xedb88320U & mask);
        }
    }
    return crc ^ 0xffffffffU;
}

std::uint64_t filter_score(const std::vector<std::uint8_t>& values) {
    std::uint64_t score = 0;
    for (std::uint8_t value : values) {
        score += value < 128 ? value : 256U - value;
    }
    return score;
}

std::uint8_t paeth_predictor(std::uint8_t left, std::uint8_t up, std::uint8_t upper_left) {
    const int a = left;
    const int b = up;
    const int c = upper_left;
    const int pa = std::abs(b - c);
    const int pb = std::abs(a - c);
    const int pc = std::abs(a + b - 2 * c);
    return static_cast<std::uint8_t>(
        (pa <= pb && pa <= pc) ? a : (pb <= pc) ? b : c
    );
}

std::vector<std::vector<std::uint8_t>> pillow_optimized_filter_rows(
    const std::uint8_t* pixels,
    std::uint32_t width,
    std::uint32_t height,
    std::size_t stride,
    std::uint32_t channels
) {
    const std::size_t row_bytes = static_cast<std::size_t>(width) * channels;
    std::vector<std::uint8_t> previous(row_bytes, 0);
    std::vector<std::uint8_t> none(row_bytes);
    std::vector<std::uint8_t> up(row_bytes);
    std::vector<std::uint8_t> prior(row_bytes);
    std::vector<std::uint8_t> average(row_bytes);
    std::vector<std::uint8_t> paeth(row_bytes);
    std::vector<std::vector<std::uint8_t>> rows;
    rows.reserve(height);

    for (std::uint32_t y = 0; y < height; ++y) {
        const std::uint8_t* source = pixels + static_cast<std::size_t>(y) * stride;
        std::memcpy(none.data(), source, row_bytes);

        std::uint64_t best_score = filter_score(none);
        const std::vector<std::uint8_t>* best = &none;
        std::uint8_t selector = 0;

        if (best_score > 0) {
            for (std::size_t index = 0; index < row_bytes; ++index) {
                up[index] = static_cast<std::uint8_t>(source[index] - previous[index]);
            }
            const std::uint64_t score = filter_score(up);
            if (score < best_score) {
                best_score = score;
                best = &up;
                selector = 2;
            }
        }

        if (best_score > 0) {
            for (std::size_t index = 0; index < row_bytes; ++index) {
                const std::uint8_t left = index < channels ? 0 : source[index - channels];
                prior[index] = static_cast<std::uint8_t>(source[index] - left);
            }
            const std::uint64_t score = filter_score(prior);
            if (score < best_score) {
                best_score = score;
                best = &prior;
                selector = 1;
            }
        }

        /* optimize=True enables Pillow's otherwise-skipped average filter. */
        if (best_score > 0) {
            for (std::size_t index = 0; index < row_bytes; ++index) {
                const unsigned left = index < channels ? 0 : source[index - channels];
                const unsigned predictor = (left + previous[index]) / 2U;
                average[index] = static_cast<std::uint8_t>(source[index] - predictor);
            }
            const std::uint64_t score = filter_score(average);
            if (score < best_score) {
                best_score = score;
                best = &average;
                selector = 3;
            }
        }

        if (best_score > 0) {
            for (std::size_t index = 0; index < row_bytes; ++index) {
                const std::uint8_t left = index < channels ? 0 : source[index - channels];
                const std::uint8_t upper_left =
                    index < channels ? 0 : previous[index - channels];
                paeth[index] = static_cast<std::uint8_t>(
                    source[index] - paeth_predictor(left, previous[index], upper_left)
                );
            }
            const std::uint64_t score = filter_score(paeth);
            if (score < best_score) {
                best = &paeth;
                selector = 4;
            }
        }

        std::vector<std::uint8_t> filtered(row_bytes + 1);
        filtered[0] = selector;
        std::memcpy(filtered.data() + 1, best->data(), row_bytes);
        rows.emplace_back(std::move(filtered));
        std::memcpy(previous.data(), source, row_bytes);
    }
    return rows;
}

bool append_full_output_chunk(
    compressed_stream& output,
    const std::vector<std::uint8_t>& block,
    std::size_t used
) {
    if (used == 0) {
        return true;
    }
    output.chunks.emplace_back(block.begin(), block.begin() + used);
    output.byte_count += used;
    return true;
}

infinimii_native_png_status compress_rows(
    const zlib_api& api,
    const std::vector<std::vector<std::uint8_t>>& rows,
    std::size_t output_block_size,
    compressed_stream& output,
    std::string& error
) {
    if (output_block_size == 0 || output_block_size > std::numeric_limits<z_uint>::max()) {
        error = "Pillow encoder block size is outside the zlib ABI";
        return INFINIMII_NATIVE_PNG_INVALID_ARGUMENT;
    }
    z_stream_compat stream{};
    const int initialized = api.deflate_init2(
        &stream,
        kZBestCompression,
        kZDeflated,
        15,
        9,
        kZFiltered,
        api.version_text.c_str(),
        static_cast<int>(sizeof(stream))
    );
    if (initialized != kZOk) {
        error = "zlib-ng rejected Pillow's level-9/mem-9/Z_FILTERED profile";
        return INFINIMII_NATIVE_PNG_COMPRESSION_FAILED;
    }

    std::vector<std::uint8_t> block(output_block_size);
    stream.next_out = block.data();
    stream.avail_out = static_cast<z_uint>(block.size());
    bool ended = false;

    auto reset_full_block = [&]() {
        append_full_output_chunk(output, block, block.size());
        stream.next_out = block.data();
        stream.avail_out = static_cast<z_uint>(block.size());
    };

    for (const std::vector<std::uint8_t>& row : rows) {
        if (row.size() > std::numeric_limits<z_uint>::max()) {
            error = "filtered row is outside the zlib ABI";
            api.deflate_end(&stream);
            return INFINIMII_NATIVE_PNG_INVALID_ARGUMENT;
        }
        stream.next_in = const_cast<z_byte*>(row.data());
        stream.avail_in = static_cast<z_uint>(row.size());
        while (stream.avail_in != 0) {
            const int result = api.deflate(&stream, kZNoFlush);
            if (result != kZOk) {
                error = "zlib-ng failed while consuming a filtered PNG row";
                api.deflate_end(&stream);
                return INFINIMII_NATIVE_PNG_COMPRESSION_FAILED;
            }
            if (stream.avail_out == 0) {
                reset_full_block();
            }
        }
    }

    while (!ended) {
        const int result = api.deflate(&stream, kZFinish);
        if (result == kZStreamEnd) {
            ended = true;
        } else if (result != kZOk) {
            error = "zlib-ng failed while finishing the PNG stream";
            api.deflate_end(&stream);
            return INFINIMII_NATIVE_PNG_COMPRESSION_FAILED;
        }
        if (stream.avail_out == 0) {
            reset_full_block();
        }
    }
    const std::size_t final_used = block.size() - stream.avail_out;
    append_full_output_chunk(output, block, final_used);
    const int ended_result = api.deflate_end(&stream);
    if (ended_result != kZOk) {
        error = "zlib-ng rejected deflateEnd after a complete stream";
        return INFINIMII_NATIVE_PNG_COMPRESSION_FAILED;
    }
    return INFINIMII_NATIVE_PNG_OK;
}

void append_u32_be(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append_png_chunk(
    std::vector<std::uint8_t>& output,
    const char type[4],
    const std::uint8_t* payload,
    std::size_t payload_size
) {
    append_u32_be(output, static_cast<std::uint32_t>(payload_size));
    const std::size_t crc_start = output.size();
    output.insert(output.end(), type, type + 4);
    if (payload_size != 0) {
        output.insert(output.end(), payload, payload + payload_size);
    }
    append_u32_be(
        output,
        crc32_bytes(output.data() + crc_start, output.size() - crc_start)
    );
}

infinimii_native_png_status encode_png(
    infinimii_native_png_encoder* encoder,
    const std::uint8_t* pixels,
    std::uint32_t width,
    std::uint32_t height,
    std::size_t stride,
    std::uint32_t channels,
    infinimii_native_png_bytes* output,
    std::string& error
) {
    if (encoder == nullptr || pixels == nullptr || output == nullptr) {
        error = "encoder, pixels, and output are required";
        return INFINIMII_NATIVE_PNG_INVALID_ARGUMENT;
    }
    output->data = nullptr;
    output->size = 0;
    if (!valid_dimensions(width, height) || (channels != 3 && channels != 4)) {
        error = "PNG dimensions or channel count are outside the admitted profile";
        return INFINIMII_NATIVE_PNG_INVALID_ARGUMENT;
    }
    std::size_t row_bytes = 0;
    if (!checked_multiply(width, channels, row_bytes) || stride < row_bytes) {
        error = "PNG row stride is smaller than its packed pixel width";
        return INFINIMII_NATIVE_PNG_INVALID_ARGUMENT;
    }

    const auto rows = pillow_optimized_filter_rows(
        pixels, width, height, stride, channels
    );
    const std::size_t block_size = std::max(
        kPillowEncoderBlock, static_cast<std::size_t>(width) * 4U
    );
    compressed_stream compressed;
    infinimii_native_png_status status = compress_rows(
        encoder->zlib, rows, block_size, compressed, error
    );
    if (status != INFINIMII_NATIVE_PNG_OK) {
        return status;
    }

    std::vector<std::uint8_t> png;
    png.reserve(57U + compressed.byte_count + compressed.chunks.size() * 12U);
    constexpr std::uint8_t signature[] = {
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
    };
    png.insert(png.end(), std::begin(signature), std::end(signature));

    std::uint8_t ihdr[13]{};
    ihdr[0] = static_cast<std::uint8_t>(width >> 24U);
    ihdr[1] = static_cast<std::uint8_t>(width >> 16U);
    ihdr[2] = static_cast<std::uint8_t>(width >> 8U);
    ihdr[3] = static_cast<std::uint8_t>(width);
    ihdr[4] = static_cast<std::uint8_t>(height >> 24U);
    ihdr[5] = static_cast<std::uint8_t>(height >> 16U);
    ihdr[6] = static_cast<std::uint8_t>(height >> 8U);
    ihdr[7] = static_cast<std::uint8_t>(height);
    ihdr[8] = 8;
    ihdr[9] = channels == 4 ? 6 : 2;
    append_png_chunk(png, "IHDR", ihdr, sizeof(ihdr));
    for (const std::vector<std::uint8_t>& chunk : compressed.chunks) {
        append_png_chunk(png, "IDAT", chunk.data(), chunk.size());
    }
    append_png_chunk(png, "IEND", nullptr, 0);

    auto* allocation = static_cast<std::uint8_t*>(std::malloc(png.size()));
    if (allocation == nullptr) {
        error = "PNG output allocation failed";
        return INFINIMII_NATIVE_PNG_ALLOCATION_FAILED;
    }
    std::memcpy(allocation, png.data(), png.size());
    output->data = allocation;
    output->size = png.size();
    return INFINIMII_NATIVE_PNG_OK;
}

std::vector<std::uint8_t> compression_probe_pixels() {
    constexpr std::uint32_t width = 128;
    constexpr std::uint32_t height = 128;
    std::vector<std::uint8_t> pixels(width * height * 4U);
    for (std::uint32_t y = 0; y < height; ++y) {
        for (std::uint32_t x = 0; x < width; ++x) {
            const int dx0 = static_cast<int>(x) - 64;
            const int dy0 = static_cast<int>(y) - 64;
            const int dx1 = static_cast<int>(x) - 50;
            const int dy1 = static_cast<int>(y) - 53;
            const int dx2 = static_cast<int>(x) - 75;
            const int dy2 = static_cast<int>(y) - 62;
            const std::size_t offset =
                (static_cast<std::size_t>(y) * width + x) * 4U;
            pixels[offset + 0] = dx0 * dx0 + dy0 * dy0 < 2600 ? 30 : 230;
            pixels[offset + 1] = dx1 * dx1 + dy1 * dy1 < 1200 ? 90 : 210;
            pixels[offset + 2] = dx2 * dx2 + dy2 * dy2 < 1800 ? 180 : 245;
            pixels[offset + 3] = 255;
        }
    }
    return pixels;
}

infinimii_native_png_status validate_backend_probe(zlib_api& api, std::string& error) {
    const auto pixels = compression_probe_pixels();
    const auto rows = pillow_optimized_filter_rows(pixels.data(), 128, 128, 512, 4);
    compressed_stream compressed;
    const infinimii_native_png_status status = compress_rows(
        api, rows, kPillowEncoderBlock, compressed, error
    );
    if (status != INFINIMII_NATIVE_PNG_OK) {
        return status;
    }
    std::vector<std::uint8_t> stream;
    stream.reserve(compressed.byte_count);
    for (const auto& chunk : compressed.chunks) {
        stream.insert(stream.end(), chunk.begin(), chunk.end());
    }
    if (stream.size() != kProbeStreamSize ||
        crc32_bytes(stream.data(), stream.size()) != kProbeStreamCrc32) {
        error = "zlib-ng output differs from the Pillow 12.2.0 compression identity";
        return INFINIMII_NATIVE_PNG_BACKEND_IDENTITY_MISMATCH;
    }
    return INFINIMII_NATIVE_PNG_OK;
}

template <typename Function>
bool resolve_function(HMODULE module, const char* name, Function& output) {
    output = reinterpret_cast<Function>(GetProcAddress(module, name));
    return output != nullptr;
}

std::wstring absolute_windows_path(const wchar_t* input) {
    if (input == nullptr || input[0] == L'\0') {
        return {};
    }
    const DWORD required = GetFullPathNameW(input, 0, nullptr, nullptr);
    if (required == 0) {
        return {};
    }
    std::wstring result(required, L'\0');
    const DWORD written = GetFullPathNameW(input, required, result.data(), nullptr);
    if (written == 0 || written >= required) {
        return {};
    }
    result.resize(written);
    return result;
}

bool caller_supplied_absolute_path(const wchar_t* input) {
    if (input == nullptr) {
        return false;
    }
    const std::wstring path(input);
    return (path.size() >= 3 && path[1] == L':' &&
            (path[2] == L'\\' || path[2] == L'/')) ||
           (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\');
}

std::uint8_t quantize_unorm8(double value) {
    const double rounded = std::nearbyint(value * 255.0);
    if (rounded <= 0.0) {
        return 0;
    }
    if (rounded >= 255.0) {
        return 255;
    }
    return static_cast<std::uint8_t>(rounded);
}

double linear_to_srgb(double value) {
    const double nonnegative = std::max(value, 0.0);
    if (nonnegative <= 0.0031308) {
        return nonnegative * 12.92;
    }
    return 1.055 * std::pow(nonnegative, 1.0 / 2.4) - 0.055;
}

infinimii_native_png_status validate_transfer_buffers(
    const double* input,
    std::uint32_t width,
    std::uint32_t height,
    std::size_t input_stride,
    std::uint8_t* output,
    std::size_t output_stride,
    std::uint32_t channels,
    std::string& error
) {
    if (input == nullptr || output == nullptr || !valid_dimensions(width, height)) {
        error = "transfer buffers and admitted dimensions are required";
        return INFINIMII_NATIVE_PNG_INVALID_ARGUMENT;
    }
    if ((reinterpret_cast<std::uintptr_t>(input) % alignof(double)) != 0 ||
        input_stride % alignof(double) != 0) {
        error = "linear input rows must preserve double alignment";
        return INFINIMII_NATIVE_PNG_INVALID_ARGUMENT;
    }
    std::size_t input_row = 0;
    std::size_t output_row = 0;
    if (!checked_multiply(
            static_cast<std::size_t>(width) * channels, sizeof(double), input_row
        ) ||
        !checked_multiply(width, channels, output_row) || input_stride < input_row ||
        output_stride < output_row) {
        error = "transfer stride is smaller than its packed row";
        return INFINIMII_NATIVE_PNG_INVALID_ARGUMENT;
    }
    if (std::fegetround() != FE_TONEAREST) {
        error = "output transfer requires round-to-nearest-even";
        return INFINIMII_NATIVE_PNG_NUMERIC_CONTRACT_FAILED;
    }
    return INFINIMII_NATIVE_PNG_OK;
}

}  // namespace

extern "C" {

std::uint32_t infinimii_native_png_abi_version(void) {
    return INFINIMII_NATIVE_PNG_ABI_VERSION;
}

infinimii_native_png_status infinimii_native_png_encoder_open(
    const wchar_t* zlib_ng_compat_dll,
    infinimii_native_png_encoder** output,
    char* error,
    std::size_t error_capacity
) {
    clear_error(error, error_capacity);
    if (output == nullptr) {
        set_error(error, error_capacity, "encoder output pointer is required");
        return INFINIMII_NATIVE_PNG_INVALID_ARGUMENT;
    }
    *output = nullptr;
    if (!caller_supplied_absolute_path(zlib_ng_compat_dll)) {
        set_error(error, error_capacity, "zlib-ng DLL path must be explicit and absolute");
        return INFINIMII_NATIVE_PNG_INVALID_ARGUMENT;
    }
    const std::wstring path = absolute_windows_path(zlib_ng_compat_dll);
    if (path.empty()) {
        set_error(error, error_capacity, "zlib-ng DLL path could not be normalized");
        return INFINIMII_NATIVE_PNG_INVALID_ARGUMENT;
    }
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        set_error(error, error_capacity, "zlib-ng DLL path is not a regular file");
        return INFINIMII_NATIVE_PNG_BACKEND_LOAD_FAILED;
    }

    HMODULE module = LoadLibraryExW(
        path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32
    );
    if (module == nullptr) {
        set_error(
            error,
            error_capacity,
            windows_error_message("LoadLibraryExW", GetLastError())
        );
        return INFINIMII_NATIVE_PNG_BACKEND_LOAD_FAILED;
    }

    auto* encoder = new (std::nothrow) infinimii_native_png_encoder{};
    if (encoder == nullptr) {
        FreeLibrary(module);
        set_error(error, error_capacity, "encoder allocation failed");
        return INFINIMII_NATIVE_PNG_ALLOCATION_FAILED;
    }
    encoder->zlib.module = module;
    if (!resolve_function(module, "zlibVersion", encoder->zlib.version) ||
        !resolve_function(module, "deflateInit2_", encoder->zlib.deflate_init2) ||
        !resolve_function(module, "deflate", encoder->zlib.deflate) ||
        !resolve_function(module, "deflateEnd", encoder->zlib.deflate_end)) {
        infinimii_native_png_encoder_close(encoder);
        set_error(error, error_capacity, "zlib-ng DLL lacks the required compatibility ABI");
        return INFINIMII_NATIVE_PNG_BACKEND_LOAD_FAILED;
    }
    const char* version = encoder->zlib.version();
    if (version == nullptr || std::strcmp(version, kAcceptedZlibVersion) != 0) {
        infinimii_native_png_encoder_close(encoder);
        set_error(error, error_capacity, "zlib backend is not the accepted zlib-ng profile");
        return INFINIMII_NATIVE_PNG_BACKEND_IDENTITY_MISMATCH;
    }
    encoder->zlib.version_text = version;
    std::string probe_error;
    const infinimii_native_png_status probe =
        validate_backend_probe(encoder->zlib, probe_error);
    if (probe != INFINIMII_NATIVE_PNG_OK) {
        infinimii_native_png_encoder_close(encoder);
        set_error(error, error_capacity, probe_error);
        return probe;
    }
    *output = encoder;
    return INFINIMII_NATIVE_PNG_OK;
}

void infinimii_native_png_encoder_close(infinimii_native_png_encoder* encoder) {
    if (encoder == nullptr) {
        return;
    }
    if (encoder->zlib.module != nullptr) {
        FreeLibrary(encoder->zlib.module);
        encoder->zlib.module = nullptr;
    }
    delete encoder;
}

infinimii_native_png_status infinimii_native_png_backend_identity(
    const infinimii_native_png_encoder* encoder,
    char* version,
    std::size_t version_capacity,
    std::uint32_t* probe_stream_size,
    std::uint32_t* probe_stream_crc32
) {
    if (encoder == nullptr || version == nullptr || version_capacity == 0 ||
        probe_stream_size == nullptr || probe_stream_crc32 == nullptr) {
        return INFINIMII_NATIVE_PNG_INVALID_ARGUMENT;
    }
    const std::size_t count = std::min(
        version_capacity - 1, encoder->zlib.version_text.size()
    );
    std::memcpy(version, encoder->zlib.version_text.data(), count);
    version[count] = '\0';
    *probe_stream_size = kProbeStreamSize;
    *probe_stream_crc32 = kProbeStreamCrc32;
    return INFINIMII_NATIVE_PNG_OK;
}

infinimii_native_png_status infinimii_native_png_encode_rgb8(
    infinimii_native_png_encoder* encoder,
    const std::uint8_t* pixels,
    std::uint32_t width,
    std::uint32_t height,
    std::size_t stride,
    infinimii_native_png_bytes* output,
    char* error,
    std::size_t error_capacity
) {
    clear_error(error, error_capacity);
    try {
        std::string detail;
        const auto status = encode_png(
            encoder, pixels, width, height, stride, 3, output, detail
        );
        if (status != INFINIMII_NATIVE_PNG_OK) {
            set_error(error, error_capacity, detail);
        }
        return status;
    } catch (const std::bad_alloc&) {
        set_error(error, error_capacity, "PNG working allocation failed");
        return INFINIMII_NATIVE_PNG_ALLOCATION_FAILED;
    } catch (...) {
        set_error(error, error_capacity, "unexpected native PNG failure");
        return INFINIMII_NATIVE_PNG_COMPRESSION_FAILED;
    }
}

infinimii_native_png_status infinimii_native_png_encode_rgba8(
    infinimii_native_png_encoder* encoder,
    const std::uint8_t* pixels,
    std::uint32_t width,
    std::uint32_t height,
    std::size_t stride,
    infinimii_native_png_bytes* output,
    char* error,
    std::size_t error_capacity
) {
    clear_error(error, error_capacity);
    try {
        std::string detail;
        const auto status = encode_png(
            encoder, pixels, width, height, stride, 4, output, detail
        );
        if (status != INFINIMII_NATIVE_PNG_OK) {
            set_error(error, error_capacity, detail);
        }
        return status;
    } catch (const std::bad_alloc&) {
        set_error(error, error_capacity, "PNG working allocation failed");
        return INFINIMII_NATIVE_PNG_ALLOCATION_FAILED;
    } catch (...) {
        set_error(error, error_capacity, "unexpected native PNG failure");
        return INFINIMII_NATIVE_PNG_COMPRESSION_FAILED;
    }
}

void infinimii_native_png_bytes_free(infinimii_native_png_bytes* bytes) {
    if (bytes == nullptr) {
        return;
    }
    std::free(bytes->data);
    bytes->data = nullptr;
    bytes->size = 0;
}

infinimii_native_png_status infinimii_native_png_transfer_linear_rgb64_to_rgb8(
    const double* linear_rgb,
    std::uint32_t width,
    std::uint32_t height,
    std::size_t input_stride,
    std::uint8_t* rgb8,
    std::size_t output_stride,
    char* error,
    std::size_t error_capacity
) {
    clear_error(error, error_capacity);
    std::string detail;
    const auto validation = validate_transfer_buffers(
        linear_rgb,
        width,
        height,
        input_stride,
        rgb8,
        output_stride,
        3,
        detail
    );
    if (validation != INFINIMII_NATIVE_PNG_OK) {
        set_error(error, error_capacity, detail);
        return validation;
    }
    for (std::uint32_t y = 0; y < height; ++y) {
        const auto* source = reinterpret_cast<const double*>(
            reinterpret_cast<const std::uint8_t*>(linear_rgb) +
            static_cast<std::size_t>(y) * input_stride
        );
        auto* target = rgb8 + static_cast<std::size_t>(y) * output_stride;
        for (std::size_t index = 0; index < static_cast<std::size_t>(width) * 3U;
             ++index) {
            if (!std::isfinite(source[index])) {
                set_error(error, error_capacity, "linear RGB contains a non-finite value");
                return INFINIMII_NATIVE_PNG_NUMERIC_CONTRACT_FAILED;
            }
            target[index] = quantize_unorm8(linear_to_srgb(source[index]));
        }
    }
    return INFINIMII_NATIVE_PNG_OK;
}

infinimii_native_png_status
infinimii_native_png_transfer_premultiplied_linear_rgba64_to_rgba8(
    const double* premultiplied_linear_rgba,
    std::uint32_t width,
    std::uint32_t height,
    std::size_t input_stride,
    std::uint8_t* rgba8,
    std::size_t output_stride,
    char* error,
    std::size_t error_capacity
) {
    clear_error(error, error_capacity);
    std::string detail;
    const auto validation = validate_transfer_buffers(
        premultiplied_linear_rgba,
        width,
        height,
        input_stride,
        rgba8,
        output_stride,
        4,
        detail
    );
    if (validation != INFINIMII_NATIVE_PNG_OK) {
        set_error(error, error_capacity, detail);
        return validation;
    }
    for (std::uint32_t y = 0; y < height; ++y) {
        const auto* source = reinterpret_cast<const double*>(
            reinterpret_cast<const std::uint8_t*>(premultiplied_linear_rgba) +
            static_cast<std::size_t>(y) * input_stride
        );
        auto* target = rgba8 + static_cast<std::size_t>(y) * output_stride;
        for (std::uint32_t x = 0; x < width; ++x) {
            const std::size_t offset = static_cast<std::size_t>(x) * 4U;
            if (!std::isfinite(source[offset + 0]) ||
                !std::isfinite(source[offset + 1]) ||
                !std::isfinite(source[offset + 2]) ||
                !std::isfinite(source[offset + 3])) {
                set_error(error, error_capacity, "linear RGBA contains a non-finite value");
                return INFINIMII_NATIVE_PNG_NUMERIC_CONTRACT_FAILED;
            }
            const double alpha = std::clamp(source[offset + 3], 0.0, 1.0);
            for (std::size_t channel = 0; channel < 3; ++channel) {
                const double straight =
                    alpha > 1.0e-12 ? source[offset + channel] / alpha : 0.0;
                target[offset + channel] = quantize_unorm8(linear_to_srgb(straight));
            }
            target[offset + 3] = quantize_unorm8(alpha);
        }
    }
    return INFINIMII_NATIVE_PNG_OK;
}

}  // extern "C"
