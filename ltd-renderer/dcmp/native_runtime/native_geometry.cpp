#include "native_geometry.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace {

constexpr std::uint32_t kAbiVersion = 1;
constexpr double kPi = 3.141592653589793238462643383279502884;

bool finite_values(const double* values, std::size_t count) {
    if (values == nullptr) return false;
    for (std::size_t index = 0; index < count; ++index) {
        if (!std::isfinite(values[index])) return false;
    }
    return true;
}

double dot3(const double left[3], const double right[3]) {
    return left[0] * right[0] + left[1] * right[1] + left[2] * right[2];
}

void cross3(const double left[3], const double right[3], double out[3]) {
    out[0] = left[1] * right[2] - left[2] * right[1];
    out[1] = left[2] * right[0] - left[0] * right[2];
    out[2] = left[0] * right[1] - left[1] * right[0];
}

bool normalize3(double value[3]) {
    const double length = std::sqrt(dot3(value, value));
    if (!(length > 0.0) || !std::isfinite(length)) return false;
    value[0] /= length; value[1] /= length; value[2] /= length;
    return true;
}

bool inverse_transpose3(const double matrix[16], double out[9]) {
    const double a = matrix[0], b = matrix[1], c = matrix[2];
    const double d = matrix[4], e = matrix[5], f = matrix[6];
    const double g = matrix[8], h = matrix[9], i = matrix[10];
    const double determinant =
        a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g);
    if (!std::isfinite(determinant) || determinant == 0.0) return false;
    const double inverse = 1.0 / determinant;
    // Transpose(inverse(M)) is the cofactor matrix divided by det.
    out[0] = (e * i - f * h) * inverse;
    out[1] = (f * g - d * i) * inverse;
    out[2] = (d * h - e * g) * inverse;
    out[3] = (c * h - b * i) * inverse;
    out[4] = (a * i - c * g) * inverse;
    out[5] = (b * g - a * h) * inverse;
    out[6] = (b * f - c * e) * inverse;
    out[7] = (c * d - a * f) * inverse;
    out[8] = (a * e - b * d) * inverse;
    return true;
}

}  // namespace

std::uint32_t ltd_native_geometry_abi_version() { return kAbiVersion; }

int ltd_native_transform_and_project(
    const double* positions,
    const double* normals,
    std::size_t vertex_count,
    const double transform[16],
    const LtdNativeProjection* projection,
    double* out_world_positions,
    double* out_world_normals,
    double* out_projected) {
    if (!finite_values(positions, vertex_count * 3) ||
        !finite_values(normals, vertex_count * 3) || !finite_values(transform, 16) ||
        projection == nullptr || projection->width == 0 || projection->height == 0 ||
        out_world_positions == nullptr || out_world_normals == nullptr || out_projected == nullptr) {
        return LTD_NATIVE_GEOMETRY_INVALID_ARGUMENT;
    }
    double normal_matrix[9]{};
    if (!inverse_transpose3(transform, normal_matrix)) {
        return LTD_NATIVE_GEOMETRY_SINGULAR_TRANSFORM;
    }

    double forward[3]{}, right[3]{}, up[3]{}, tangent = 0.0, aspect = 0.0;
    if (projection->kind == LTD_NATIVE_ORTHOGRAPHIC) {
        if (!finite_values(projection->world_bounds, 4) ||
            !(projection->world_bounds[1] > projection->world_bounds[0]) ||
            !(projection->world_bounds[3] > projection->world_bounds[2])) {
            return LTD_NATIVE_GEOMETRY_INVALID_CAMERA;
        }
    } else if (projection->kind == LTD_NATIVE_PERSPECTIVE) {
        if (!finite_values(projection->camera_position, 3) ||
            !finite_values(projection->camera_target, 3) ||
            !finite_values(projection->camera_up, 3) ||
            !std::isfinite(projection->vertical_fov_degrees) ||
            !std::isfinite(projection->horizontal_projection_scale) ||
            !(projection->horizontal_projection_scale > 0.0)) {
            return LTD_NATIVE_GEOMETRY_INVALID_CAMERA;
        }
        for (int axis = 0; axis < 3; ++axis) {
            forward[axis] = projection->camera_target[axis] - projection->camera_position[axis];
        }
        if (!normalize3(forward)) return LTD_NATIVE_GEOMETRY_INVALID_CAMERA;
        cross3(forward, projection->camera_up, right);
        if (!normalize3(right)) return LTD_NATIVE_GEOMETRY_INVALID_CAMERA;
        cross3(right, forward, up);
        tangent = std::tan(projection->vertical_fov_degrees * kPi / 180.0 * 0.5);
        aspect = static_cast<double>(projection->width) /
                 static_cast<double>(projection->height);
        if (!(tangent > 0.0) || !std::isfinite(tangent)) {
            return LTD_NATIVE_GEOMETRY_INVALID_CAMERA;
        }
    } else {
        return LTD_NATIVE_GEOMETRY_INVALID_CAMERA;
    }

    for (std::size_t vertex = 0; vertex < vertex_count; ++vertex) {
        const double* source_position = positions + vertex * 3;
        const double* source_normal = normals + vertex * 3;
        double* world_position = out_world_positions + vertex * 3;
        double* world_normal = out_world_normals + vertex * 3;
        double* screen = out_projected + vertex * 3;
        world_position[0] = transform[0] * source_position[0] + transform[1] * source_position[1] +
                            transform[2] * source_position[2] + transform[3];
        world_position[1] = transform[4] * source_position[0] + transform[5] * source_position[1] +
                            transform[6] * source_position[2] + transform[7];
        world_position[2] = transform[8] * source_position[0] + transform[9] * source_position[1] +
                            transform[10] * source_position[2] + transform[11];
        world_normal[0] = normal_matrix[0] * source_normal[0] + normal_matrix[1] * source_normal[1] +
                          normal_matrix[2] * source_normal[2];
        world_normal[1] = normal_matrix[3] * source_normal[0] + normal_matrix[4] * source_normal[1] +
                          normal_matrix[5] * source_normal[2];
        world_normal[2] = normal_matrix[6] * source_normal[0] + normal_matrix[7] * source_normal[1] +
                          normal_matrix[8] * source_normal[2];
        if (!normalize3(world_normal)) {
            world_normal[0] = world_normal[1] = world_normal[2] = 0.0;
        }

        if (projection->kind == LTD_NATIVE_ORTHOGRAPHIC) {
            const auto& bounds = projection->world_bounds;
            screen[0] = (world_position[0] - bounds[0]) / (bounds[1] - bounds[0]) *
                        static_cast<double>(projection->width - 1);
            screen[1] = (bounds[3] - world_position[1]) / (bounds[3] - bounds[2]) *
                        static_cast<double>(projection->height - 1);
            screen[2] = world_position[2];
        } else {
            double relative[3]{
                world_position[0] - projection->camera_position[0],
                world_position[1] - projection->camera_position[1],
                world_position[2] - projection->camera_position[2],
            };
            const double depth = dot3(relative, forward);
            if (!(depth > 1e-8)) {
                const double nan = std::numeric_limits<double>::quiet_NaN();
                screen[0] = screen[1] = screen[2] = nan;
            } else {
                screen[0] =
                    (dot3(relative, right) / (depth * tangent * aspect) *
                         projection->horizontal_projection_scale +
                     1.0) * 0.5 * static_cast<double>(projection->width - 1);
                screen[1] =
                    (1.0 - dot3(relative, up) / (depth * tangent)) * 0.5 *
                    static_cast<double>(projection->height - 1);
                screen[2] = 1.0 / depth;
            }
        }
    }
    return LTD_NATIVE_GEOMETRY_OK;
}

int ltd_native_setup_triangles(
    const double* projected,
    std::size_t vertex_count,
    const std::int32_t* triangle_indices,
    std::size_t triangle_count,
    std::size_t width,
    std::size_t height,
    std::uint8_t cull_back_faces,
    std::uint8_t clockwise_front_face,
    LtdNativeTriangleSetup* out_triangles) {
    if (projected == nullptr || (triangle_count != 0 && triangle_indices == nullptr) ||
        out_triangles == nullptr || width == 0 || height == 0) {
        return LTD_NATIVE_GEOMETRY_INVALID_ARGUMENT;
    }
    for (std::size_t triangle = 0; triangle < triangle_count; ++triangle) {
        auto& output = out_triangles[triangle];
        output.candidate = 0;
        for (int corner = 0; corner < 3; ++corner) {
            const std::int32_t index = triangle_indices[triangle * 3 + corner];
            if (index < 0 || index >= static_cast<std::int32_t>(vertex_count)) {
                return LTD_NATIVE_GEOMETRY_INVALID_INDEX;
            }
            std::copy(projected + static_cast<std::size_t>(index) * 3,
                      projected + static_cast<std::size_t>(index) * 3 + 3,
                      output.screen + corner * 3);
        }
        if (!finite_values(output.screen, 9)) continue;
        const double x_min = std::min({output.screen[0], output.screen[3], output.screen[6]});
        const double x_max = std::max({output.screen[0], output.screen[3], output.screen[6]});
        const double y_min = std::min({output.screen[1], output.screen[4], output.screen[7]});
        const double y_max = std::max({output.screen[1], output.screen[4], output.screen[7]});
        output.x0 = std::max<std::int32_t>(0, static_cast<std::int32_t>(std::floor(x_min)));
        output.x1 = std::min<std::int32_t>(static_cast<std::int32_t>(width - 1),
                                          static_cast<std::int32_t>(std::ceil(x_max)));
        output.y0 = std::max<std::int32_t>(0, static_cast<std::int32_t>(std::floor(y_min)));
        output.y1 = std::min<std::int32_t>(static_cast<std::int32_t>(height - 1),
                                          static_cast<std::int32_t>(std::ceil(y_max)));
        if (output.x0 > output.x1 || output.y0 > output.y1) continue;
        const double sx0 = output.screen[0], sy0 = output.screen[1];
        const double sx1 = output.screen[3], sy1 = output.screen[4];
        const double sx2 = output.screen[6], sy2 = output.screen[7];
        output.denominator = (sx0 - sx1) * (sy2 - sy1) - (sy0 - sy1) * (sx2 - sx1);
        if (std::abs(output.denominator) < 1e-10) continue;
        if (cull_back_faces != 0) {
            if (clockwise_front_face != 0 ? output.denominator >= 0.0
                                          : output.denominator <= 0.0) {
                continue;
            }
        }
        output.candidate = 1;
    }
    return LTD_NATIVE_GEOMETRY_OK;
}

