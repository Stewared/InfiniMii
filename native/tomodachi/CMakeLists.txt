cmake_minimum_required(VERSION 3.16)

project(infinimii_tomodachi_renderer C CXX)

include(CTest)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(RENDERER_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(BODY_DRIVER "${RENDERER_SOURCE_DIR}/render_body_model.c")
set(REFERENCE_RENDERER "${RENDERER_SOURCE_DIR}/renderer.c")
set(MINIZ_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/miniz")
set(NINTEXUTILS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/nintexutils")

add_library(ffl_high_texture_runtime STATIC
    "${RENDERER_SOURCE_DIR}/ffl_high_texture.c"
    "${RENDERER_SOURCE_DIR}/ffl_gx2_deswizzle.cpp"
    "${MINIZ_DIR}/miniz_tinfl.c"
    "${NINTEXUTILS_DIR}/src/ninTexUtils/gx2/gx2Surface.cpp"
    "${NINTEXUTILS_DIR}/src/ninTexUtils/gx2/tcl/addrlib.cpp")
target_include_directories(ffl_high_texture_runtime PUBLIC
    "${RENDERER_SOURCE_DIR}"
    "${MINIZ_DIR}"
    "${NINTEXUTILS_DIR}/include")

foreach(REQUIRED_SOURCE
    "${BODY_DRIVER}"
    "${REFERENCE_RENDERER}"
    "${RENDERER_SOURCE_DIR}/ffl_high_texture.c"
    "${RENDERER_SOURCE_DIR}/ffl_high_texture.h"
    "${RENDERER_SOURCE_DIR}/ffl_gx2_deswizzle.cpp"
    "${RENDERER_SOURCE_DIR}/native_pica_material.c"
    "${RENDERER_SOURCE_DIR}/native_pica_material.h"
    "${RENDERER_SOURCE_DIR}/render_headwear_model.c")
    if(NOT EXISTS "${REQUIRED_SOURCE}")
        message(FATAL_ERROR "Missing bundled renderer source: ${REQUIRED_SOURCE}")
    endif()
endforeach()

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/assets/FFLResHigh.dat")
    message(FATAL_ERROR "Missing bundled renderer resource: assets/FFLResHigh.dat")
endif()

add_executable(render_body_model "${BODY_DRIVER}")
target_include_directories(render_body_model PRIVATE "${RENDERER_SOURCE_DIR}")
target_link_libraries(render_body_model PRIVATE ffl_high_texture_runtime)
target_compile_definitions(render_body_model PRIVATE
    TOMODACHI_BODY_STANDALONE_NATIVE=1)

# The headwear driver embeds the body driver so both physical models share the
# exact portrait/depth path. Generate that adapted translation unit from the
# bundled audited source instead of maintaining a divergent copy.
file(READ "${BODY_DRIVER}" BODY_SOURCE)
string(REPLACE
    "int main(int argc, char **argv) {"
    "static int tomodachi_body_renderer_main(int argc, char **argv) {"
    BODY_SOURCE "${BODY_SOURCE}")

set(BODY_DRAW_NEEDLE [=[static void draw_cgfx_model(MeshCanvas *canvas, const CgfxModel *model,
    const ShapeTransform *transform, uint32_t fallback_color,
    int use_depth, int write_depth, int blend_mode, int image_mode, int cull_back,
    int material_type, uint32_t skin_color) {
    int mesh_index;]=])
set(BODY_DRAW_REPLACEMENT [=[typedef void (*TomodachiBodyNativeDrawHook)(
    MeshCanvas *canvas, const CgfxModel *model, const ShapeTransform *transform,
    uint32_t fallback_color, int use_depth, int write_depth, int blend_mode,
    int image_mode, int cull_back, int material_type, uint32_t skin_color);
static TomodachiBodyNativeDrawHook tomodachi_body_native_draw_hook = NULL;

static void draw_cgfx_model(MeshCanvas *canvas, const CgfxModel *model,
    const ShapeTransform *transform, uint32_t fallback_color,
    int use_depth, int write_depth, int blend_mode, int image_mode, int cull_back,
    int material_type, uint32_t skin_color) {
    int mesh_index;
    if (tomodachi_body_native_draw_hook) {
        tomodachi_body_native_draw_hook(canvas, model, transform, fallback_color,
            use_depth, write_depth, blend_mode, image_mode, cull_back,
            material_type, skin_color);
        return;
    }]=])
string(FIND "${BODY_SOURCE}" "${BODY_DRAW_NEEDLE}" BODY_DRAW_OFFSET)
if(BODY_DRAW_OFFSET EQUAL -1)
    message(FATAL_ERROR "Could not locate body draw adapter insertion point")
endif()
string(REPLACE "${BODY_DRAW_NEEDLE}" "${BODY_DRAW_REPLACEMENT}"
    BODY_SOURCE "${BODY_SOURCE}")

set(EMBEDDED_BODY "${CMAKE_CURRENT_BINARY_DIR}/render_body_model_embedded.c")
file(WRITE "${EMBEDDED_BODY}" "${BODY_SOURCE}")

add_executable(render_headwear_model
    "${RENDERER_SOURCE_DIR}/render_headwear_model.c")
target_include_directories(render_headwear_model PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}"
    "${RENDERER_SOURCE_DIR}")
target_link_libraries(render_headwear_model PRIVATE ffl_high_texture_runtime)

if(BUILD_TESTING)
    add_executable(test_mii_colors "${RENDERER_SOURCE_DIR}/test_mii_colors.c")
    target_include_directories(test_mii_colors PRIVATE "${RENDERER_SOURCE_DIR}")
    target_link_libraries(test_mii_colors PRIVATE ffl_high_texture_runtime)
    add_test(NAME mii_renderer_semantics COMMAND test_mii_colors
        "${CMAKE_CURRENT_SOURCE_DIR}/assets/FFLResHigh.dat"
        "${CMAKE_CURRENT_SOURCE_DIR}/assets/CFL_Res.dat")
endif()

if(MSVC)
    target_compile_options(render_body_model PRIVATE /W4 /O2)
    target_compile_options(render_headwear_model PRIVATE /W4 /O2)
    if(BUILD_TESTING)
        target_compile_options(test_mii_colors PRIVATE /W4 /O2)
    endif()
else()
    target_compile_options(render_body_model PRIVATE -Wall -Wextra -Wpedantic -O2)
    target_compile_options(render_headwear_model PRIVATE -Wall -Wextra -Wpedantic -O2)
    target_link_libraries(render_body_model PRIVATE m)
    target_link_libraries(render_headwear_model PRIVATE m)
    if(BUILD_TESTING)
        target_compile_options(test_mii_colors PRIVATE -Wall -Wextra -Wpedantic -O2)
        target_link_libraries(test_mii_colors PRIVATE m)
    endif()
endif()
