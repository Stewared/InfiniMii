#include "native_pose.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace {

constexpr std::uint32_t kAbiVersion = 1;

bool finite_values(const double* values, std::size_t count) {
    if (values == nullptr) return false;
    for (std::size_t index = 0; index < count; ++index) {
        if (!std::isfinite(values[index])) return false;
    }
    return true;
}

void identity(double out[16]) {
    std::fill(out, out + 16, 0.0);
    out[0] = out[5] = out[10] = out[15] = 1.0;
}

void multiply4(const double left[16], const double right[16], double out[16]) {
    double result[16]{};
    for (int row = 0; row < 4; ++row) {
        for (int column = 0; column < 4; ++column) {
            double sum = 0.0;
            for (int inner = 0; inner < 4; ++inner) {
                sum += left[row * 4 + inner] * right[inner * 4 + column];
            }
            result[row * 4 + column] = sum;
        }
    }
    std::copy(result, result + 16, out);
}

void local_matrix(const LtdNativeBoneInput& bone, double out[16]) {
    const double x = bone.rotation[0];
    const double y = bone.rotation[1];
    const double z = bone.rotation[2];
    const double cx = std::cos(x), sx = std::sin(x);
    const double cy = std::cos(y), sy = std::sin(y);
    const double cz = std::cos(z), sz = std::sin(z);

    // Rz @ Ry @ Rx with each basis column scaled, matching model_pose.py.
    identity(out);
    out[0] = (cz * cy) * bone.scale[0];
    out[1] = (cz * sy * sx - sz * cx) * bone.scale[1];
    out[2] = (cz * sy * cx + sz * sx) * bone.scale[2];
    out[4] = (sz * cy) * bone.scale[0];
    out[5] = (sz * sy * sx + cz * cx) * bone.scale[1];
    out[6] = (sz * sy * cx - cz * sx) * bone.scale[2];
    out[8] = (-sy) * bone.scale[0];
    out[9] = (cy * sx) * bone.scale[1];
    out[10] = (cy * cx) * bone.scale[2];
    out[3] = bone.translation[0];
    out[7] = bone.translation[1];
    out[11] = bone.translation[2];
}

void transform_position(const double matrix[16], const double in[3], double out[3]) {
    out[0] = matrix[0] * in[0] + matrix[1] * in[1] + matrix[2] * in[2] + matrix[3];
    out[1] = matrix[4] * in[0] + matrix[5] * in[1] + matrix[6] * in[2] + matrix[7];
    out[2] = matrix[8] * in[0] + matrix[9] * in[1] + matrix[10] * in[2] + matrix[11];
}

void transform_normal(const double matrix[16], const double in[3], double out[3]) {
    out[0] = matrix[0] * in[0] + matrix[1] * in[1] + matrix[2] * in[2];
    out[1] = matrix[4] * in[0] + matrix[5] * in[1] + matrix[6] * in[2];
    out[2] = matrix[8] * in[0] + matrix[9] * in[1] + matrix[10] * in[2];
}

}  // namespace

std::uint32_t ltd_native_pose_abi_version() { return kAbiVersion; }

int ltd_native_evaluate_world_matrices(
    const LtdNativeBoneInput* bones,
    std::size_t bone_count,
    double* out_world_matrices) {
    if ((bone_count != 0 && bones == nullptr) || out_world_matrices == nullptr) {
        return LTD_NATIVE_POSE_INVALID_ARGUMENT;
    }
    for (std::size_t index = 0; index < bone_count; ++index) {
        const auto& bone = bones[index];
        if (bone.parent_index < -1 || bone.parent_index >= static_cast<std::int32_t>(index) ||
            !finite_values(bone.scale, 3) || !finite_values(bone.rotation, 3) ||
            !finite_values(bone.translation, 3)) {
            return LTD_NATIVE_POSE_INVALID_HIERARCHY;
        }
        double local[16]{};
        local_matrix(bone, local);
        double* output = out_world_matrices + index * 16;
        if (bone.parent_index < 0) {
            std::copy(local, local + 16, output);
        } else {
            multiply4(out_world_matrices + static_cast<std::size_t>(bone.parent_index) * 16,
                      local, output);
        }
    }
    return LTD_NATIVE_POSE_OK;
}

int ltd_native_skin_mesh(
    const double* source_positions,
    const double* source_normals,
    std::size_t vertex_count,
    const LtdNativeShapeSkinInput* shapes,
    std::size_t shape_count,
    const std::int32_t* matrix_to_bone,
    std::size_t palette_count,
    const double* inverse_bind_matrices,
    std::size_t smooth_count,
    const double* posed_world_matrices,
    std::size_t bone_count,
    double* out_positions,
    double* out_normals) {
    if (!finite_values(source_positions, vertex_count * 3) ||
        !finite_values(source_normals, vertex_count * 3) ||
        (shape_count != 0 && shapes == nullptr) ||
        (palette_count != 0 && matrix_to_bone == nullptr) ||
        smooth_count > palette_count ||
        (smooth_count != 0 && !finite_values(inverse_bind_matrices, smooth_count * 16)) ||
        !finite_values(posed_world_matrices, bone_count * 16) ||
        out_positions == nullptr || out_normals == nullptr) {
        return LTD_NATIVE_POSE_INVALID_ARGUMENT;
    }
    for (std::size_t index = 0; index < palette_count; ++index) {
        if (matrix_to_bone[index] < 0 ||
            matrix_to_bone[index] >= static_cast<std::int32_t>(bone_count)) {
            return LTD_NATIVE_POSE_INVALID_PALETTE;
        }
    }
    std::copy(source_positions, source_positions + vertex_count * 3, out_positions);
    std::copy(source_normals, source_normals + vertex_count * 3, out_normals);

    for (std::size_t shape_index = 0; shape_index < shape_count; ++shape_index) {
        const auto& shape = shapes[shape_index];
        if (shape.skin_count == 0 || shape.vertex_offset > vertex_count ||
            shape.vertex_count > vertex_count - shape.vertex_offset ||
            shape.palette_indices == nullptr ||
            (shape.skin_count != 1 && shape.weights == nullptr)) {
            return LTD_NATIVE_POSE_INVALID_SKIN;
        }
        for (std::size_t vertex = 0; vertex < shape.vertex_count; ++vertex) {
            double weight_sum = 0.0;
            for (std::size_t influence = 0; influence < shape.skin_count; ++influence) {
                const std::size_t flat = vertex * shape.skin_count + influence;
                const std::int32_t palette_index = shape.palette_indices[flat];
                const double weight = shape.weights == nullptr ? 1.0 : shape.weights[flat];
                if (palette_index < 0 ||
                    palette_index >= static_cast<std::int32_t>(palette_count) ||
                    (shape.skin_count > 1 &&
                     palette_index >= static_cast<std::int32_t>(smooth_count)) ||
                    !std::isfinite(weight) || weight < 0.0) {
                    return LTD_NATIVE_POSE_INVALID_SKIN;
                }
                weight_sum += weight;
            }
            if (!(weight_sum > 0.0) || !std::isfinite(weight_sum)) {
                return LTD_NATIVE_POSE_INVALID_SKIN;
            }

            const std::size_t global = shape.vertex_offset + vertex;
            const double* source_position = source_positions + global * 3;
            const double* source_normal = source_normals + global * 3;
            double accumulated_position[3]{};
            double accumulated_normal[3]{};
            for (std::size_t influence = 0; influence < shape.skin_count; ++influence) {
                const std::size_t flat = vertex * shape.skin_count + influence;
                const std::size_t palette_index =
                    static_cast<std::size_t>(shape.palette_indices[flat]);
                const std::size_t bone_index =
                    static_cast<std::size_t>(matrix_to_bone[palette_index]);
                const double normalized =
                    (shape.weights == nullptr ? 1.0 : shape.weights[flat]) / weight_sum;
                double deform[16]{};
                if (palette_index < smooth_count) {
                    multiply4(posed_world_matrices + bone_index * 16,
                              inverse_bind_matrices + palette_index * 16, deform);
                } else {
                    std::copy(posed_world_matrices + bone_index * 16,
                              posed_world_matrices + bone_index * 16 + 16, deform);
                }
                double position[3]{}, normal[3]{};
                transform_position(deform, source_position, position);
                transform_normal(deform, source_normal, normal);
                for (int axis = 0; axis < 3; ++axis) {
                    accumulated_position[axis] += position[axis] * normalized;
                    accumulated_normal[axis] += normal[axis] * normalized;
                }
            }
            double length = std::sqrt(
                accumulated_normal[0] * accumulated_normal[0] +
                accumulated_normal[1] * accumulated_normal[1] +
                accumulated_normal[2] * accumulated_normal[2]);
            if (length == 0.0) length = 1.0;
            for (int axis = 0; axis < 3; ++axis) {
                out_positions[global * 3 + axis] = accumulated_position[axis];
                out_normals[global * 3 + axis] = accumulated_normal[axis] / length;
            }
        }
    }
    return LTD_NATIVE_POSE_OK;
}

