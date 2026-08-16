#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "native_png.h"

#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <system_error>
#include <vector>

namespace {

bool parse_dimension(const wchar_t* text, std::uint32_t& output) {
    if (text == nullptr || *text == L'\0') {
        return false;
    }
    std::string narrow;
    for (const wchar_t* cursor = text; *cursor != L'\0'; ++cursor) {
        if (*cursor < L'0' || *cursor > L'9') {
            return false;
        }
        narrow.push_back(static_cast<char>(*cursor));
    }
    const char* begin = narrow.data();
    const char* end = begin + narrow.size();
    const auto parsed = std::from_chars(begin, end, output);
    return parsed.ec == std::errc{} && parsed.ptr == end && output != 0;
}

bool checked_size(
    std::uint32_t width,
    std::uint32_t height,
    std::size_t channels,
    std::size_t component_size,
    std::size_t& output
) {
    if (width > std::numeric_limits<std::size_t>::max() / height) {
        return false;
    }
    std::size_t value = static_cast<std::size_t>(width) * height;
    if (value > std::numeric_limits<std::size_t>::max() / channels) {
        return false;
    }
    value *= channels;
    if (value > std::numeric_limits<std::size_t>::max() / component_size) {
        return false;
    }
    output = value * component_size;
    return true;
}

bool read_exact_file(
    const std::filesystem::path& path,
    std::size_t expected_size,
    std::vector<std::uint8_t>& output,
    std::string& error
) {
    std::error_code file_error;
    const std::uintmax_t actual_size = std::filesystem::file_size(path, file_error);
    if (file_error || actual_size != expected_size) {
        error = "input byte length differs from width, height, mode, and component size";
        return false;
    }
    output.resize(expected_size);
    std::ifstream stream(path, std::ios::binary);
    if (!stream || (expected_size != 0 &&
                    !stream.read(
                        reinterpret_cast<char*>(output.data()),
                        static_cast<std::streamsize>(expected_size)
                    ))) {
        error = "failed to read the complete input file";
        return false;
    }
    return true;
}

bool write_exact_file(
    const std::filesystem::path& path,
    const std::uint8_t* data,
    std::size_t size,
    std::string& error
) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream || (size != 0 &&
                    !stream.write(
                        reinterpret_cast<const char*>(data),
                        static_cast<std::streamsize>(size)
                    ))) {
        error = "failed to write the complete output file";
        return false;
    }
    stream.flush();
    if (!stream) {
        error = "failed to flush the output file";
        return false;
    }
    return true;
}

int print_usage() {
    std::cerr
        << "usage:\n"
        << "  native_png_tool --probe <absolute-zlib-ng-dll>\n"
        << "  native_png_tool --encode-rgb8 <dll> <width> <height> <raw> <png>\n"
        << "  native_png_tool --encode-rgba8 <dll> <width> <height> <raw> <png>\n"
        << "  native_png_tool --transfer-linear-rgb64 <width> <height> <raw-f64> <raw-rgb8>\n"
        << "  native_png_tool --transfer-premultiplied-linear-rgba64 "
           "<width> <height> <raw-f64> <raw-rgba8>\n";
    return 2;
}

int probe_backend(const wchar_t* dll) {
    char error[512]{};
    infinimii_native_png_encoder* encoder = nullptr;
    const auto status = infinimii_native_png_encoder_open(
        dll, &encoder, error, sizeof(error)
    );
    if (status != INFINIMII_NATIVE_PNG_OK) {
        std::cerr << "native PNG backend rejected: " << error << '\n';
        return static_cast<int>(status) + 10;
    }
    char version[64]{};
    std::uint32_t probe_size = 0;
    std::uint32_t probe_crc = 0;
    const auto identity = infinimii_native_png_backend_identity(
        encoder, version, sizeof(version), &probe_size, &probe_crc
    );
    infinimii_native_png_encoder_close(encoder);
    if (identity != INFINIMII_NATIVE_PNG_OK) {
        std::cerr << "native PNG backend identity query failed\n";
        return static_cast<int>(identity) + 10;
    }
    std::cout << "{\"abi_version\":" << infinimii_native_png_abi_version()
              << ",\"zlib_version\":\"" << version
              << "\",\"probe_stream_size\":" << probe_size
              << ",\"probe_stream_crc32\":\"" << std::hex << probe_crc
              << "\"}\n";
    return 0;
}

int encode_image(
    bool rgba,
    const wchar_t* dll,
    const wchar_t* width_text,
    const wchar_t* height_text,
    const wchar_t* input_path,
    const wchar_t* output_path
) {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    if (!parse_dimension(width_text, width) || !parse_dimension(height_text, height)) {
        std::cerr << "invalid dimensions\n";
        return 2;
    }
    const std::size_t channels = rgba ? 4U : 3U;
    std::size_t input_size = 0;
    if (!checked_size(width, height, channels, 1, input_size)) {
        std::cerr << "input dimensions overflow size_t\n";
        return 2;
    }
    std::vector<std::uint8_t> pixels;
    std::string file_error;
    if (!read_exact_file(input_path, input_size, pixels, file_error)) {
        std::cerr << file_error << '\n';
        return 3;
    }
    char error[512]{};
    infinimii_native_png_encoder* encoder = nullptr;
    auto status = infinimii_native_png_encoder_open(
        dll, &encoder, error, sizeof(error)
    );
    if (status != INFINIMII_NATIVE_PNG_OK) {
        std::cerr << error << '\n';
        return static_cast<int>(status) + 10;
    }
    infinimii_native_png_bytes png{};
    status = rgba
                 ? infinimii_native_png_encode_rgba8(
                       encoder,
                       pixels.data(),
                       width,
                       height,
                       static_cast<std::size_t>(width) * 4U,
                       &png,
                       error,
                       sizeof(error)
                   )
                 : infinimii_native_png_encode_rgb8(
                       encoder,
                       pixels.data(),
                       width,
                       height,
                       static_cast<std::size_t>(width) * 3U,
                       &png,
                       error,
                       sizeof(error)
                   );
    infinimii_native_png_encoder_close(encoder);
    if (status != INFINIMII_NATIVE_PNG_OK) {
        std::cerr << error << '\n';
        return static_cast<int>(status) + 10;
    }
    const bool wrote = write_exact_file(output_path, png.data, png.size, file_error);
    infinimii_native_png_bytes_free(&png);
    if (!wrote) {
        std::cerr << file_error << '\n';
        return 4;
    }
    return 0;
}

int transfer_image(
    bool rgba,
    const wchar_t* width_text,
    const wchar_t* height_text,
    const wchar_t* input_path,
    const wchar_t* output_path
) {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    if (!parse_dimension(width_text, width) || !parse_dimension(height_text, height)) {
        std::cerr << "invalid dimensions\n";
        return 2;
    }
    const std::size_t channels = rgba ? 4U : 3U;
    std::size_t input_size = 0;
    std::size_t output_size = 0;
    if (!checked_size(width, height, channels, sizeof(double), input_size) ||
        !checked_size(width, height, channels, 1, output_size)) {
        std::cerr << "transfer dimensions overflow size_t\n";
        return 2;
    }
    std::vector<std::uint8_t> input;
    std::string file_error;
    if (!read_exact_file(input_path, input_size, input, file_error)) {
        std::cerr << file_error << '\n';
        return 3;
    }
    std::vector<std::uint8_t> output(output_size);
    char error[512]{};
    const auto status = rgba
        ? infinimii_native_png_transfer_premultiplied_linear_rgba64_to_rgba8(
              reinterpret_cast<const double*>(input.data()),
              width,
              height,
              static_cast<std::size_t>(width) * 4U * sizeof(double),
              output.data(),
              static_cast<std::size_t>(width) * 4U,
              error,
              sizeof(error)
          )
        : infinimii_native_png_transfer_linear_rgb64_to_rgb8(
              reinterpret_cast<const double*>(input.data()),
              width,
              height,
              static_cast<std::size_t>(width) * 3U * sizeof(double),
              output.data(),
              static_cast<std::size_t>(width) * 3U,
              error,
              sizeof(error)
          );
    if (status != INFINIMII_NATIVE_PNG_OK) {
        std::cerr << error << '\n';
        return static_cast<int>(status) + 10;
    }
    if (!write_exact_file(output_path, output.data(), output.size(), file_error)) {
        std::cerr << file_error << '\n';
        return 4;
    }
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wstring(argv[1]) == L"--probe") {
        return probe_backend(argv[2]);
    }
    if (argc == 7 && std::wstring(argv[1]) == L"--encode-rgb8") {
        return encode_image(false, argv[2], argv[3], argv[4], argv[5], argv[6]);
    }
    if (argc == 7 && std::wstring(argv[1]) == L"--encode-rgba8") {
        return encode_image(true, argv[2], argv[3], argv[4], argv[5], argv[6]);
    }
    if (argc == 6 && std::wstring(argv[1]) == L"--transfer-linear-rgb64") {
        return transfer_image(false, argv[2], argv[3], argv[4], argv[5]);
    }
    if (argc == 6 &&
        std::wstring(argv[1]) == L"--transfer-premultiplied-linear-rgba64") {
        return transfer_image(true, argv[2], argv[3], argv[4], argv[5]);
    }
    return print_usage();
}
