#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <math.h>
#include <stdint.h>

#define NPY_NO_DEPRECATED_API NPY_1_7_API_VERSION
#include <numpy/arrayobject.h>

#include "native_current_draw_build.h"

#if defined(_MSC_VER)
#pragma float_control(precise, on, push)
#pragma fp_contract(off)
#endif

/*
 * Whole-draw prototype for software_renderer.py's current portable Head816
 * branch.  This is intentionally not a title-shader implementation: the
 * title-owned environment/material/GlobalUBO/prepass buffers remain absent.
 * Python supplies already transformed, projected, front-face-filtered,
 * point-mip-selected primitive arrays.  This loop preserves the renderer's
 * float64 expression order and writes directly into shared attachments.
 */

static PyArrayObject *require_exact_array(
    PyObject *object,
    int type,
    int dimensions,
    int writable,
    const char *name
) {
    if (!PyArray_Check(object)) {
        PyErr_Format(PyExc_TypeError, "%s must be a NumPy array", name);
        return NULL;
    }
    PyArrayObject *array = (PyArrayObject *)object;
    if (PyArray_TYPE(array) != type) {
        PyErr_Format(PyExc_TypeError, "%s has the wrong dtype", name);
        return NULL;
    }
    if (PyArray_NDIM(array) != dimensions) {
        PyErr_Format(PyExc_ValueError, "%s has the wrong rank", name);
        return NULL;
    }
    if (!PyArray_IS_C_CONTIGUOUS(array) || !PyArray_ISALIGNED(array)) {
        PyErr_Format(PyExc_ValueError, "%s must be C-contiguous and aligned", name);
        return NULL;
    }
    if (writable && !PyArray_ISWRITEABLE(array)) {
        PyErr_Format(PyExc_ValueError, "%s must be writable", name);
        return NULL;
    }
    return array;
}

static npy_intp wrapped_index(npy_intp index, npy_intp size, int mode) {
    if (mode == 0) { /* clamp */
        if (index < 0) {
            return 0;
        }
        return index >= size ? size - 1 : index;
    }
    if (mode == 1) { /* repeat */
        npy_intp repeated = index % size;
        return repeated < 0 ? repeated + size : repeated;
    }
    const npy_intp period = size * 2; /* mirror */
    npy_intp mirrored = index % period;
    if (mirrored < 0) {
        mirrored += period;
    }
    return mirrored < size ? mirrored : period - 1 - mirrored;
}

static void sample_rgba(
    const double *source,
    npy_intp height,
    npy_intp width,
    double u,
    double v,
    int wrap_x,
    int wrap_y,
    double output[4]
) {
    const double tex_x = (u * (double)width) - 0.5;
    const double tex_y = ((1.0 - v) * (double)height) - 0.5;
    const double floor_x = floor(tex_x);
    const double floor_y = floor(tex_y);
    const npy_intp x0 = wrapped_index((npy_intp)floor_x, width, wrap_x);
    const npy_intp x1 = wrapped_index((npy_intp)floor_x + 1, width, wrap_x);
    const npy_intp y0 = wrapped_index((npy_intp)floor_y, height, wrap_y);
    const npy_intp y1 = wrapped_index((npy_intp)floor_y + 1, height, wrap_y);
    const double x_amount = tex_x - floor_x;
    const double y_amount = tex_y - floor_y;
    const double inverse_x = 1.0 - x_amount;
    const double inverse_y = 1.0 - y_amount;
    for (int channel = 0; channel < 4; ++channel) {
        const double top =
            source[(y0 * width + x0) * 4 + channel] * inverse_x +
            source[(y0 * width + x1) * 4 + channel] * x_amount;
        const double bottom =
            source[(y1 * width + x0) * 4 + channel] * inverse_x +
            source[(y1 * width + x1) * 4 + channel] * x_amount;
        output[channel] = top * inverse_y + bottom * y_amount;
    }
}

static double dot3(const double left[3], const double right[3]) {
    const double first_two = left[0] * right[0] + left[1] * right[1];
    return first_two + left[2] * right[2];
}

static void cross3(const double left[3], const double right[3], double output[3]) {
    output[0] = left[1] * right[2] - left[2] * right[1];
    output[1] = left[2] * right[0] - left[0] * right[2];
    output[2] = left[0] * right[1] - left[1] * right[0];
}

static double norm3(const double value[3]) {
    const double first_two = value[0] * value[0] + value[1] * value[1];
    return sqrt(first_two + value[2] * value[2]);
}

static int normalize3_strict(double value[3]) {
    const double length = norm3(value);
    if (!(length > 1e-12)) {
        return 0;
    }
    value[0] /= length;
    value[1] /= length;
    value[2] /= length;
    return 1;
}

static int visible_lane(
    const double *screen,
    const double *depth,
    npy_intp depth_width,
    int x,
    int y,
    double denominator,
    double *weight0,
    double *weight1,
    double *weight2,
    double *z
) {
    const double sample_x = (double)x + 0.5;
    const double sample_y = (double)y + 0.5;
    const double edge0_left = (sample_x - screen[3]) * (screen[7] - screen[4]);
    const double edge0_right = (sample_y - screen[4]) * (screen[6] - screen[3]);
    *weight0 = (edge0_left - edge0_right) / denominator;
    const double edge1_left = (sample_x - screen[6]) * (screen[1] - screen[7]);
    const double edge1_right = (sample_y - screen[7]) * (screen[0] - screen[6]);
    *weight1 = (edge1_left - edge1_right) / denominator;
    *weight2 = (1.0 - *weight0) - *weight1;
    if (*weight0 < -1e-7 || *weight1 < -1e-7 || *weight2 < -1e-7) {
        return 0;
    }
    const double z01 = *weight0 * screen[2] + *weight1 * screen[5];
    *z = z01 + *weight2 * screen[8];
    return *z >= depth[(npy_intp)y * depth_width + x];
}

static PyObject *draw_head816(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *objects[25];
    if (!PyArg_UnpackTuple(
            args,
            "draw_head816",
            25,
            25,
            &objects[0], &objects[1], &objects[2], &objects[3], &objects[4],
            &objects[5], &objects[6], &objects[7], &objects[8], &objects[9],
            &objects[10], &objects[11], &objects[12], &objects[13], &objects[14],
            &objects[15], &objects[16], &objects[17], &objects[18], &objects[19],
            &objects[20], &objects[21], &objects[22], &objects[23], &objects[24])) {
        return NULL;
    }

    PyArrayObject *color_array = require_exact_array(objects[0], NPY_FLOAT64, 3, 1, "color");
    PyArrayObject *depth_array = require_exact_array(objects[1], NPY_FLOAT64, 2, 1, "depth");
    PyArrayObject *alpha_array = NULL;
    if (objects[2] != Py_None) {
        alpha_array = require_exact_array(objects[2], NPY_FLOAT64, 2, 1, "target_alpha");
    }
    PyArrayObject *screen_array = require_exact_array(objects[3], NPY_FLOAT64, 3, 0, "screen_triangles");
    PyArrayObject *bounds_array = require_exact_array(objects[4], NPY_INT64, 2, 0, "bounds");
    PyArrayObject *denominator_array = require_exact_array(objects[5], NPY_FLOAT64, 1, 0, "denominators");
    PyArrayObject *vertices_array = require_exact_array(objects[6], NPY_FLOAT64, 3, 0, "world_vertices");
    PyArrayObject *normals_array = require_exact_array(objects[7], NPY_FLOAT64, 3, 0, "vertex_normals");
    PyArrayObject *normal_valid_array = require_exact_array(objects[8], NPY_UINT8, 1, 0, "vertex_normal_valid");
    PyArrayObject *albedo_uv_array = require_exact_array(objects[9], NPY_FLOAT64, 3, 0, "albedo_uv");
    PyArrayObject *normal_uv_array = require_exact_array(objects[10], NPY_FLOAT64, 3, 0, "normal_uv");
    PyArrayObject *albedo_array = require_exact_array(objects[11], NPY_FLOAT64, 3, 0, "albedo_texture");
    PyArrayObject *normal_texels_array = require_exact_array(objects[12], NPY_FLOAT64, 2, 0, "normal_texels");
    PyArrayObject *normal_levels_array = require_exact_array(objects[13], NPY_INT64, 2, 0, "normal_levels");
    PyArrayObject *level_indices_array = require_exact_array(objects[14], NPY_INT64, 1, 0, "normal_level_indices");
    PyArrayObject *base_color_array = require_exact_array(objects[15], NPY_FLOAT64, 1, 0, "base_color_linear");
    PyArrayObject *light_direction_array = require_exact_array(objects[16], NPY_FLOAT64, 1, 0, "light_direction");
    PyArrayObject *light_color_array = require_exact_array(objects[17], NPY_FLOAT64, 1, 0, "light_color");
    PyArrayObject *ambient_color_array = require_exact_array(objects[18], NPY_FLOAT64, 1, 0, "ambient_color");
    if (color_array == NULL || depth_array == NULL ||
        (objects[2] != Py_None && alpha_array == NULL) || screen_array == NULL ||
        bounds_array == NULL || denominator_array == NULL || vertices_array == NULL ||
        normals_array == NULL || normal_valid_array == NULL || albedo_uv_array == NULL ||
        normal_uv_array == NULL || albedo_array == NULL || normal_texels_array == NULL ||
        normal_levels_array == NULL || level_indices_array == NULL || base_color_array == NULL ||
        light_direction_array == NULL || light_color_array == NULL || ambient_color_array == NULL) {
        return NULL;
    }

    const double light_intensity = PyFloat_AsDouble(objects[19]);
    const double ambient_intensity = PyFloat_AsDouble(objects[20]);
    const double alpha_scalar = PyFloat_AsDouble(objects[21]);
    const double alpha_cutoff = PyFloat_AsDouble(objects[22]);
    const long perspective_correct = PyLong_AsLong(objects[23]);
    const long has_albedo = PyLong_AsLong(objects[24]);
    if (PyErr_Occurred()) {
        return NULL;
    }
    if ((perspective_correct != 0 && perspective_correct != 1) ||
        (has_albedo != 0 && has_albedo != 1)) {
        PyErr_SetString(PyExc_ValueError, "perspective_correct and has_albedo must be zero or one");
        return NULL;
    }

    const npy_intp framebuffer_height = PyArray_DIM(color_array, 0);
    const npy_intp framebuffer_width = PyArray_DIM(color_array, 1);
    if (framebuffer_height <= 0 || framebuffer_width <= 0 || PyArray_DIM(color_array, 2) != 3 ||
        PyArray_DIM(depth_array, 0) != framebuffer_height ||
        PyArray_DIM(depth_array, 1) != framebuffer_width ||
        (alpha_array != NULL &&
         (PyArray_DIM(alpha_array, 0) != framebuffer_height ||
          PyArray_DIM(alpha_array, 1) != framebuffer_width))) {
        PyErr_SetString(PyExc_ValueError, "attachment shapes do not match");
        return NULL;
    }

    const npy_intp triangle_count = PyArray_DIM(screen_array, 0);
#define CHECK_TRIANGLE_SHAPE(array, d1, d2, label) \
    if (PyArray_DIM((array), 0) != triangle_count || \
        PyArray_DIM((array), 1) != (d1) || PyArray_DIM((array), 2) != (d2)) { \
        PyErr_SetString(PyExc_ValueError, label " shape does not match triangle count"); \
        return NULL; \
    }
    CHECK_TRIANGLE_SHAPE(screen_array, 3, 3, "screen_triangles");
    CHECK_TRIANGLE_SHAPE(vertices_array, 3, 3, "world_vertices");
    CHECK_TRIANGLE_SHAPE(normals_array, 3, 3, "vertex_normals");
    CHECK_TRIANGLE_SHAPE(albedo_uv_array, 3, 2, "albedo_uv");
    CHECK_TRIANGLE_SHAPE(normal_uv_array, 3, 2, "normal_uv");
#undef CHECK_TRIANGLE_SHAPE
    if (PyArray_DIM(bounds_array, 0) != triangle_count || PyArray_DIM(bounds_array, 1) != 4 ||
        PyArray_DIM(denominator_array, 0) != triangle_count ||
        PyArray_DIM(normal_valid_array, 0) != triangle_count ||
        PyArray_DIM(level_indices_array, 0) != triangle_count) {
        PyErr_SetString(PyExc_ValueError, "flat per-triangle arrays have inconsistent lengths");
        return NULL;
    }
    if (PyArray_DIM(albedo_array, 0) <= 0 || PyArray_DIM(albedo_array, 1) <= 0 ||
        PyArray_DIM(albedo_array, 2) != 4 ||
        PyArray_DIM(normal_texels_array, 0) <= 0 || PyArray_DIM(normal_texels_array, 1) != 4 ||
        PyArray_DIM(normal_levels_array, 0) <= 0 || PyArray_DIM(normal_levels_array, 1) != 3 ||
        PyArray_DIM(base_color_array, 0) != 3 ||
        PyArray_DIM(light_direction_array, 0) != 3 ||
        PyArray_DIM(light_color_array, 0) != 3 ||
        PyArray_DIM(ambient_color_array, 0) != 3) {
        PyErr_SetString(PyExc_ValueError, "texture bank or three-vector shape is invalid");
        return NULL;
    }

    const int64_t *bounds = (const int64_t *)PyArray_DATA(bounds_array);
    const int64_t *normal_levels = (const int64_t *)PyArray_DATA(normal_levels_array);
    const int64_t *level_indices = (const int64_t *)PyArray_DATA(level_indices_array);
    const npy_intp normal_texel_count = PyArray_DIM(normal_texels_array, 0);
    const npy_intp normal_level_count = PyArray_DIM(normal_levels_array, 0);
    for (npy_intp level = 0; level < normal_level_count; ++level) {
        const int64_t offset = normal_levels[level * 3];
        const int64_t height = normal_levels[level * 3 + 1];
        const int64_t width = normal_levels[level * 3 + 2];
        if (offset < 0 || height <= 0 || width <= 0 ||
            offset > normal_texel_count || height > normal_texel_count ||
            width > normal_texel_count || height * width > normal_texel_count - offset) {
            PyErr_SetString(PyExc_ValueError, "normal level metadata falls outside packed texels");
            return NULL;
        }
    }
    for (npy_intp triangle = 0; triangle < triangle_count; ++triangle) {
        if (bounds[triangle * 4] < 0 || bounds[triangle * 4 + 2] < 0 ||
            bounds[triangle * 4 + 1] < bounds[triangle * 4] ||
            bounds[triangle * 4 + 3] < bounds[triangle * 4 + 2] ||
            bounds[triangle * 4 + 1] >= framebuffer_width ||
            bounds[triangle * 4 + 3] >= framebuffer_height ||
            level_indices[triangle] < 0 || level_indices[triangle] >= normal_level_count) {
            PyErr_SetString(PyExc_ValueError, "triangle bounds or normal level index is invalid");
            return NULL;
        }
    }

    double *color = (double *)PyArray_DATA(color_array);
    double *depth = (double *)PyArray_DATA(depth_array);
    double *target_alpha = alpha_array == NULL ? NULL : (double *)PyArray_DATA(alpha_array);
    const double *screens = (const double *)PyArray_DATA(screen_array);
    const double *denominators = (const double *)PyArray_DATA(denominator_array);
    const double *vertices = (const double *)PyArray_DATA(vertices_array);
    const double *vertex_normals = (const double *)PyArray_DATA(normals_array);
    const uint8_t *vertex_normal_valid = (const uint8_t *)PyArray_DATA(normal_valid_array);
    const double *albedo_uv = (const double *)PyArray_DATA(albedo_uv_array);
    const double *normal_uv = (const double *)PyArray_DATA(normal_uv_array);
    const double *albedo_texture = (const double *)PyArray_DATA(albedo_array);
    const double *normal_texels = (const double *)PyArray_DATA(normal_texels_array);
    const double *base_color = (const double *)PyArray_DATA(base_color_array);
    const double *light_direction = (const double *)PyArray_DATA(light_direction_array);
    const double *light_color = (const double *)PyArray_DATA(light_color_array);
    const double *ambient_color = (const double *)PyArray_DATA(ambient_color_array);
    const npy_intp albedo_height = PyArray_DIM(albedo_array, 0);
    const npy_intp albedo_width = PyArray_DIM(albedo_array, 1);

    double ambient_radiance[3];
    double key_radiance[3];
    double front_radiance[3];
    double front_hemisphere = 0.5 + 0.5 * light_direction[2];
    if (front_hemisphere < 0.0) {
        front_hemisphere = 0.0;
    } else if (front_hemisphere > 1.0) {
        front_hemisphere = 1.0;
    }
    for (int channel = 0; channel < 3; ++channel) {
        ambient_radiance[channel] = ambient_color[channel] * ambient_intensity;
        key_radiance[channel] = light_color[channel] * light_intensity;
        front_radiance[channel] =
            ambient_radiance[channel] + key_radiance[channel] * front_hemisphere;
    }

    npy_intp written_fragments = 0;
    Py_BEGIN_ALLOW_THREADS
    for (npy_intp triangle = 0; triangle < triangle_count; ++triangle) {
        const double *screen = screens + triangle * 9;
        const double *triangle_vertices = vertices + triangle * 9;
        const double *triangle_normals = vertex_normals + triangle * 9;
        const double *triangle_albedo_uv = albedo_uv + triangle * 6;
        const double *triangle_normal_uv = normal_uv + triangle * 6;
        const double denominator = denominators[triangle];
        const int x0 = (int)bounds[triangle * 4];
        const int x1 = (int)bounds[triangle * 4 + 1];
        const int y0 = (int)bounds[triangle * 4 + 2];
        const int y1 = (int)bounds[triangle * 4 + 3];

        double edge1[3];
        double edge2[3];
        for (int component = 0; component < 3; ++component) {
            edge1[component] = triangle_vertices[3 + component] - triangle_vertices[component];
            edge2[component] = triangle_vertices[6 + component] - triangle_vertices[component];
        }
        double geometric_normal[3];
        cross3(edge1, edge2, geometric_normal);
        const double geometric_length = norm3(geometric_normal);
        if (geometric_length != 0.0) {
            for (int component = 0; component < 3; ++component) {
                geometric_normal[component] /= geometric_length;
            }
        }

        const double delta1_u = triangle_normal_uv[2] - triangle_normal_uv[0];
        const double delta1_v = triangle_normal_uv[3] - triangle_normal_uv[1];
        const double delta2_u = triangle_normal_uv[4] - triangle_normal_uv[0];
        const double delta2_v = triangle_normal_uv[5] - triangle_normal_uv[1];
        const double tangent_determinant =
            delta1_u * delta2_v - delta2_u * delta1_v;
        int tangent_valid = 0;
        double tangent[3] = {0.0, 0.0, 0.0};
        double handedness = 1.0;
        if (fabs(tangent_determinant) > 1e-12) {
            double raw_bitangent[3];
            for (int component = 0; component < 3; ++component) {
                tangent[component] =
                    (edge1[component] * delta2_v - edge2[component] * delta1_v) /
                    tangent_determinant;
                raw_bitangent[component] =
                    (-edge1[component] * delta2_u + edge2[component] * delta1_u) /
                    tangent_determinant;
            }
            const double tangent_length = norm3(tangent);
            if (tangent_length > 1e-12) {
                for (int component = 0; component < 3; ++component) {
                    tangent[component] /= tangent_length;
                }
                double cross_value[3];
                cross3(geometric_normal, tangent, cross_value);
                const double handedness_value = dot3(cross_value, raw_bitangent);
                handedness =
                    handedness_value < 0.0 ? -1.0 :
                    (handedness_value > 0.0 ? 1.0 : 0.0);
                if (handedness == 0.0) {
                    handedness = 1.0;
                }
                tangent_valid = 1;
            }
        }

        const int64_t level_index = level_indices[triangle];
        const int64_t normal_offset = normal_levels[level_index * 3];
        const npy_intp normal_height = (npy_intp)normal_levels[level_index * 3 + 1];
        const npy_intp normal_width = (npy_intp)normal_levels[level_index * 3 + 2];
        const double *normal_texture = normal_texels + normal_offset * 4;

        for (int y = y0; y <= y1; ++y) {
            for (int x = x0; x <= x1; ++x) {
                double affine0, affine1, affine2, z;
                if (!visible_lane(
                        screen, depth, framebuffer_width, x, y, denominator,
                        &affine0, &affine1, &affine2, &z)) {
                    continue;
                }
                double weight0 = affine0;
                double weight1 = affine1;
                double weight2 = affine2;
                if (perspective_correct) {
                    const double safe = fabs(z) < 1e-20 ? 1.0 : z;
                    weight0 = (affine0 * screen[2]) / safe;
                    weight1 = (affine1 * screen[5]) / safe;
                    weight2 = (affine2 * screen[8]) / safe;
                }

                double source_color[3] = {
                    base_color[0], base_color[1], base_color[2]
                };
                double fragment_alpha = alpha_scalar;
                if (has_albedo) {
                    const double u01 =
                        weight0 * triangle_albedo_uv[0] + weight1 * triangle_albedo_uv[2];
                    const double u = u01 + weight2 * triangle_albedo_uv[4];
                    const double v01 =
                        weight0 * triangle_albedo_uv[1] + weight1 * triangle_albedo_uv[3];
                    const double v = v01 + weight2 * triangle_albedo_uv[5];
                    double sample[4];
                    sample_rgba(
                        albedo_texture, albedo_height, albedo_width,
                        u, v, 2, 1, sample
                    );
                    for (int channel = 0; channel < 3; ++channel) {
                        source_color[channel] *= sample[channel];
                    }
                    fragment_alpha *= sample[3];
                }
                if (!(fragment_alpha >= alpha_cutoff)) {
                    continue;
                }

                double shading_normal[3];
                if (vertex_normal_valid[triangle]) {
                    for (int component = 0; component < 3; ++component) {
                        const double first_two =
                            weight0 * triangle_normals[component] +
                            weight1 * triangle_normals[3 + component];
                        shading_normal[component] =
                            first_two + weight2 * triangle_normals[6 + component];
                    }
                    double shading_length = norm3(shading_normal);
                    if (shading_length == 0.0) {
                        shading_length = 1.0;
                    }
                    for (int component = 0; component < 3; ++component) {
                        shading_normal[component] /= shading_length;
                    }
                } else {
                    for (int component = 0; component < 3; ++component) {
                        shading_normal[component] = geometric_normal[component];
                    }
                }

                const double normal_u01 =
                    weight0 * triangle_normal_uv[0] + weight1 * triangle_normal_uv[2];
                const double normal_u = normal_u01 + weight2 * triangle_normal_uv[4];
                const double normal_v01 =
                    weight0 * triangle_normal_uv[1] + weight1 * triangle_normal_uv[3];
                const double normal_v = normal_v01 + weight2 * triangle_normal_uv[5];
                double normal_sample[4];
                sample_rgba(
                    normal_texture, normal_height, normal_width,
                    normal_u, normal_v, 1, 1, normal_sample
                );
                double normal_x = 0.0;
                double normal_y = 0.0;
                normal_x += (normal_sample[0] * 2.0 - 1.0) * 1.0;
                normal_y += (normal_sample[3] * 2.0 - 1.0) * 1.0;
                const double normal_xy_length =
                    sqrt(normal_x * normal_x + normal_y * normal_y);
                const double normal_xy_denominator =
                    normal_xy_length > 1e-12 ? normal_xy_length : 1e-12;
                double normal_xy_scale = 0.999999 / normal_xy_denominator;
                if (normal_xy_scale > 1.0) {
                    normal_xy_scale = 1.0;
                }
                normal_x *= normal_xy_scale;
                normal_y *= normal_xy_scale;
                double normal_z_squared =
                    (1.0 - normal_x * normal_x) - normal_y * normal_y;
                if (normal_z_squared < 0.0) {
                    normal_z_squared = 0.0;
                }
                const double normal_z = sqrt(normal_z_squared);

                if (tangent_valid) {
                    const double tangent_dot_normal = dot3(shading_normal, tangent);
                    double tangent_field[3];
                    for (int component = 0; component < 3; ++component) {
                        tangent_field[component] =
                            tangent[component] - shading_normal[component] * tangent_dot_normal;
                    }
                    double tangent_field_length = norm3(tangent_field);
                    if (tangent_field_length == 0.0) {
                        tangent_field_length = 1.0;
                    }
                    for (int component = 0; component < 3; ++component) {
                        tangent_field[component] /= tangent_field_length;
                    }
                    double bitangent_field[3];
                    cross3(shading_normal, tangent_field, bitangent_field);
                    for (int component = 0; component < 3; ++component) {
                        bitangent_field[component] *= handedness;
                        const double first_two =
                            tangent_field[component] * normal_x +
                            bitangent_field[component] * normal_y;
                        shading_normal[component] =
                            first_two + shading_normal[component] * normal_z;
                    }
                    double final_normal_length = norm3(shading_normal);
                    if (final_normal_length == 0.0) {
                        final_normal_length = 1.0;
                    }
                    for (int component = 0; component < 3; ++component) {
                        shading_normal[component] /= final_normal_length;
                    }
                }

                double hemisphere = 0.5 + 0.5 * dot3(shading_normal, light_direction);
                if (hemisphere < 0.0) {
                    hemisphere = 0.0;
                } else if (hemisphere > 1.0) {
                    hemisphere = 1.0;
                }
                for (int channel = 0; channel < 3; ++channel) {
                    double light = 1.0;
                    if (front_radiance[channel] > 1e-12) {
                        const double normal_radiance =
                            ambient_radiance[channel] + key_radiance[channel] * hemisphere;
                        light = normal_radiance / front_radiance[channel];
                    }
                    source_color[channel] *= light;
                    source_color[channel] =
                        source_color[channel] > 0.0 ? source_color[channel] : 0.0;
                }

                const npy_intp pixel = (npy_intp)y * framebuffer_width + x;
                color[pixel * 3] = source_color[0];
                color[pixel * 3 + 1] = source_color[1];
                color[pixel * 3 + 2] = source_color[2];
                if (target_alpha != NULL) {
                    target_alpha[pixel] = 1.0;
                }
                depth[pixel] = z;
                ++written_fragments;
            }
        }
    }
    Py_END_ALLOW_THREADS

    return PyLong_FromLongLong((long long)written_fragments);
}

/* Exact-current opaque outfit response. Python has already selected one strict
 * Tops984, Bottoms936, or Shoes912 fingerprint and each triangle's mips. */
static PyObject *draw_opaque_outfit(
    PyObject *self,
    PyObject *args,
    const char *argument_name
) {
    (void)self;
    PyObject *objects[23];
    if (!PyArg_UnpackTuple(
            args, argument_name, 23, 23,
            &objects[0], &objects[1], &objects[2], &objects[3],
            &objects[4], &objects[5], &objects[6], &objects[7],
            &objects[8], &objects[9], &objects[10], &objects[11],
            &objects[12], &objects[13], &objects[14], &objects[15],
            &objects[16], &objects[17], &objects[18], &objects[19],
            &objects[20], &objects[21], &objects[22])) {
        return NULL;
    }

    PyArrayObject *color_array = require_exact_array(objects[0], NPY_FLOAT64, 3, 1, "color");
    PyArrayObject *depth_array = require_exact_array(objects[1], NPY_FLOAT64, 2, 1, "depth");
    PyArrayObject *alpha_array = NULL;
    if (objects[2] != Py_None) {
        alpha_array = require_exact_array(objects[2], NPY_FLOAT64, 2, 1, "target_alpha");
    }
    PyArrayObject *screen_array = require_exact_array(objects[3], NPY_FLOAT64, 3, 0, "screen_triangles");
    PyArrayObject *bounds_array = require_exact_array(objects[4], NPY_INT64, 2, 0, "bounds");
    PyArrayObject *denominator_array = require_exact_array(objects[5], NPY_FLOAT64, 1, 0, "denominators");
    PyArrayObject *vertices_array = require_exact_array(objects[6], NPY_FLOAT64, 3, 0, "world_vertices");
    PyArrayObject *normals_array = require_exact_array(objects[7], NPY_FLOAT64, 3, 0, "vertex_normals");
    PyArrayObject *uv_array = require_exact_array(objects[8], NPY_FLOAT64, 3, 0, "material_uv");
    PyArrayObject *albedo_texels_array = require_exact_array(objects[9], NPY_FLOAT64, 2, 0, "albedo_texels");
    PyArrayObject *albedo_levels_array = require_exact_array(objects[10], NPY_INT64, 2, 0, "albedo_levels");
    PyArrayObject *albedo_lower_array = require_exact_array(objects[11], NPY_INT64, 1, 0, "albedo_lower_indices");
    PyArrayObject *albedo_upper_array = require_exact_array(objects[12], NPY_INT64, 1, 0, "albedo_upper_indices");
    PyArrayObject *albedo_amount_array = require_exact_array(objects[13], NPY_FLOAT64, 1, 0, "albedo_mip_amounts");
    PyArrayObject *normal_texels_array = require_exact_array(objects[14], NPY_FLOAT64, 2, 0, "normal_texels");
    PyArrayObject *normal_levels_array = require_exact_array(objects[15], NPY_INT64, 2, 0, "normal_levels");
    PyArrayObject *normal_index_array = require_exact_array(objects[16], NPY_INT64, 1, 0, "normal_level_indices");
    PyArrayObject *light_direction_array = require_exact_array(objects[17], NPY_FLOAT64, 1, 0, "light_direction");
    PyArrayObject *light_color_array = require_exact_array(objects[18], NPY_FLOAT64, 1, 0, "light_color");
    PyArrayObject *ambient_color_array = require_exact_array(objects[19], NPY_FLOAT64, 1, 0, "ambient_color");
    if (color_array == NULL || depth_array == NULL ||
        (objects[2] != Py_None && alpha_array == NULL) || screen_array == NULL ||
        bounds_array == NULL || denominator_array == NULL || vertices_array == NULL ||
        normals_array == NULL || uv_array == NULL || albedo_texels_array == NULL ||
        albedo_levels_array == NULL || albedo_lower_array == NULL ||
        albedo_upper_array == NULL || albedo_amount_array == NULL ||
        normal_texels_array == NULL || normal_levels_array == NULL ||
        normal_index_array == NULL || light_direction_array == NULL ||
        light_color_array == NULL || ambient_color_array == NULL) {
        return NULL;
    }
    const double light_intensity = PyFloat_AsDouble(objects[20]);
    const double ambient_intensity = PyFloat_AsDouble(objects[21]);
    const long perspective_correct = PyLong_AsLong(objects[22]);
    if (PyErr_Occurred()) {
        return NULL;
    }
    if (perspective_correct != 1) {
        PyErr_SetString(PyExc_ValueError, "opaque outfit requires perspective correction");
        return NULL;
    }

    const npy_intp framebuffer_height = PyArray_DIM(color_array, 0);
    const npy_intp framebuffer_width = PyArray_DIM(color_array, 1);
    if (framebuffer_height <= 0 || framebuffer_width <= 0 || PyArray_DIM(color_array, 2) != 3 ||
        PyArray_DIM(depth_array, 0) != framebuffer_height ||
        PyArray_DIM(depth_array, 1) != framebuffer_width ||
        (alpha_array != NULL &&
         (PyArray_DIM(alpha_array, 0) != framebuffer_height ||
          PyArray_DIM(alpha_array, 1) != framebuffer_width))) {
        PyErr_SetString(PyExc_ValueError, "attachment shapes do not match");
        return NULL;
    }
    const npy_intp triangle_count = PyArray_DIM(screen_array, 0);
#define CHECK_OUTFIT_TRIANGLE_SHAPE(array, d1, d2, label) \
    if (PyArray_DIM((array), 0) != triangle_count || \
        PyArray_DIM((array), 1) != (d1) || PyArray_DIM((array), 2) != (d2)) { \
        PyErr_SetString(PyExc_ValueError, label " shape does not match triangle count"); \
        return NULL; \
    }
    CHECK_OUTFIT_TRIANGLE_SHAPE(screen_array, 3, 3, "screen_triangles");
    CHECK_OUTFIT_TRIANGLE_SHAPE(vertices_array, 3, 3, "world_vertices");
    CHECK_OUTFIT_TRIANGLE_SHAPE(normals_array, 3, 3, "vertex_normals");
    CHECK_OUTFIT_TRIANGLE_SHAPE(uv_array, 3, 2, "material_uv");
#undef CHECK_OUTFIT_TRIANGLE_SHAPE
    if (PyArray_DIM(bounds_array, 0) != triangle_count || PyArray_DIM(bounds_array, 1) != 4 ||
        PyArray_DIM(denominator_array, 0) != triangle_count ||
        PyArray_DIM(albedo_lower_array, 0) != triangle_count ||
        PyArray_DIM(albedo_upper_array, 0) != triangle_count ||
        PyArray_DIM(albedo_amount_array, 0) != triangle_count ||
        PyArray_DIM(normal_index_array, 0) != triangle_count ||
        PyArray_DIM(albedo_texels_array, 0) <= 0 || PyArray_DIM(albedo_texels_array, 1) != 4 ||
        PyArray_DIM(normal_texels_array, 0) <= 0 || PyArray_DIM(normal_texels_array, 1) != 4 ||
        PyArray_DIM(albedo_levels_array, 0) <= 0 || PyArray_DIM(albedo_levels_array, 1) != 3 ||
        PyArray_DIM(normal_levels_array, 0) <= 0 || PyArray_DIM(normal_levels_array, 1) != 3 ||
        PyArray_DIM(light_direction_array, 0) != 3 ||
        PyArray_DIM(light_color_array, 0) != 3 || PyArray_DIM(ambient_color_array, 0) != 3) {
        PyErr_SetString(PyExc_ValueError, "opaque outfit flat ABI shapes are inconsistent");
        return NULL;
    }

    const int64_t *bounds = (const int64_t *)PyArray_DATA(bounds_array);
    const int64_t *albedo_levels = (const int64_t *)PyArray_DATA(albedo_levels_array);
    const int64_t *normal_levels = (const int64_t *)PyArray_DATA(normal_levels_array);
    const int64_t *albedo_lower = (const int64_t *)PyArray_DATA(albedo_lower_array);
    const int64_t *albedo_upper = (const int64_t *)PyArray_DATA(albedo_upper_array);
    const int64_t *normal_indices = (const int64_t *)PyArray_DATA(normal_index_array);
    const double *albedo_amounts = (const double *)PyArray_DATA(albedo_amount_array);
    const npy_intp albedo_level_count = PyArray_DIM(albedo_levels_array, 0);
    const npy_intp normal_level_count = PyArray_DIM(normal_levels_array, 0);
    const npy_intp albedo_texel_count = PyArray_DIM(albedo_texels_array, 0);
    const npy_intp normal_texel_count = PyArray_DIM(normal_texels_array, 0);
    for (npy_intp level = 0; level < albedo_level_count; ++level) {
        const int64_t offset = albedo_levels[level * 3];
        const int64_t height = albedo_levels[level * 3 + 1];
        const int64_t width = albedo_levels[level * 3 + 2];
        if (offset < 0 || height <= 0 || width <= 0 || offset > albedo_texel_count ||
            height > albedo_texel_count || width > albedo_texel_count ||
            height * width > albedo_texel_count - offset) {
            PyErr_SetString(PyExc_ValueError, "albedo level metadata falls outside packed texels");
            return NULL;
        }
    }
    for (npy_intp level = 0; level < normal_level_count; ++level) {
        const int64_t offset = normal_levels[level * 3];
        const int64_t height = normal_levels[level * 3 + 1];
        const int64_t width = normal_levels[level * 3 + 2];
        if (offset < 0 || height <= 0 || width <= 0 || offset > normal_texel_count ||
            height > normal_texel_count || width > normal_texel_count ||
            height * width > normal_texel_count - offset) {
            PyErr_SetString(PyExc_ValueError, "normal level metadata falls outside packed texels");
            return NULL;
        }
    }
    for (npy_intp triangle = 0; triangle < triangle_count; ++triangle) {
        if (bounds[triangle * 4] < 0 || bounds[triangle * 4 + 2] < 0 ||
            bounds[triangle * 4 + 1] < bounds[triangle * 4] ||
            bounds[triangle * 4 + 3] < bounds[triangle * 4 + 2] ||
            bounds[triangle * 4 + 1] >= framebuffer_width ||
            bounds[triangle * 4 + 3] >= framebuffer_height ||
            albedo_lower[triangle] < 0 || albedo_lower[triangle] >= albedo_level_count ||
            albedo_upper[triangle] < 0 || albedo_upper[triangle] >= albedo_level_count ||
            normal_indices[triangle] < 0 || normal_indices[triangle] >= normal_level_count ||
            !isfinite(albedo_amounts[triangle]) || albedo_amounts[triangle] < 0.0 ||
            albedo_amounts[triangle] > 1.0) {
            PyErr_SetString(PyExc_ValueError, "Tops984 triangle metadata is invalid");
            return NULL;
        }
    }

    double *color = (double *)PyArray_DATA(color_array);
    double *depth = (double *)PyArray_DATA(depth_array);
    double *target_alpha = alpha_array == NULL ? NULL : (double *)PyArray_DATA(alpha_array);
    const double *screens = (const double *)PyArray_DATA(screen_array);
    const double *denominators = (const double *)PyArray_DATA(denominator_array);
    const double *vertices = (const double *)PyArray_DATA(vertices_array);
    const double *vertex_normals = (const double *)PyArray_DATA(normals_array);
    const double *material_uv = (const double *)PyArray_DATA(uv_array);
    const double *albedo_texels = (const double *)PyArray_DATA(albedo_texels_array);
    const double *normal_texels = (const double *)PyArray_DATA(normal_texels_array);
    const double *light_direction = (const double *)PyArray_DATA(light_direction_array);
    const double *light_color = (const double *)PyArray_DATA(light_color_array);
    const double *ambient_color = (const double *)PyArray_DATA(ambient_color_array);
    double ambient_radiance[3];
    double key_radiance[3];
    double front_radiance[3];
    double front_hemisphere = 0.5 + 0.5 * light_direction[2];
    if (front_hemisphere < 0.0) front_hemisphere = 0.0;
    else if (front_hemisphere > 1.0) front_hemisphere = 1.0;
    for (int channel = 0; channel < 3; ++channel) {
        ambient_radiance[channel] = ambient_color[channel] * ambient_intensity;
        key_radiance[channel] = light_color[channel] * light_intensity;
        front_radiance[channel] = ambient_radiance[channel] +
            key_radiance[channel] * front_hemisphere;
    }

    npy_intp written_fragments = 0;
    Py_BEGIN_ALLOW_THREADS
    for (npy_intp triangle = 0; triangle < triangle_count; ++triangle) {
        const double *screen = screens + triangle * 9;
        const double *triangle_vertices = vertices + triangle * 9;
        const double *triangle_normals = vertex_normals + triangle * 9;
        const double *triangle_uv = material_uv + triangle * 6;
        const double denominator = denominators[triangle];
        const int x0 = (int)bounds[triangle * 4];
        const int x1 = (int)bounds[triangle * 4 + 1];
        const int y0 = (int)bounds[triangle * 4 + 2];
        const int y1 = (int)bounds[triangle * 4 + 3];

        double edge1[3];
        double edge2[3];
        for (int component = 0; component < 3; ++component) {
            edge1[component] = triangle_vertices[3 + component] - triangle_vertices[component];
            edge2[component] = triangle_vertices[6 + component] - triangle_vertices[component];
        }
        double geometric_normal[3];
        cross3(edge1, edge2, geometric_normal);
        const double geometric_length = norm3(geometric_normal);
        if (geometric_length != 0.0) {
            for (int component = 0; component < 3; ++component) {
                geometric_normal[component] /= geometric_length;
            }
        }
        const double delta1_u = triangle_uv[2] - triangle_uv[0];
        const double delta1_v = triangle_uv[3] - triangle_uv[1];
        const double delta2_u = triangle_uv[4] - triangle_uv[0];
        const double delta2_v = triangle_uv[5] - triangle_uv[1];
        const double tangent_determinant = delta1_u * delta2_v - delta2_u * delta1_v;
        int tangent_valid = 0;
        double tangent[3] = {0.0, 0.0, 0.0};
        double handedness = 1.0;
        if (fabs(tangent_determinant) > 1e-12) {
            double raw_bitangent[3];
            for (int component = 0; component < 3; ++component) {
                tangent[component] =
                    (edge1[component] * delta2_v - edge2[component] * delta1_v) /
                    tangent_determinant;
                raw_bitangent[component] =
                    (-edge1[component] * delta2_u + edge2[component] * delta1_u) /
                    tangent_determinant;
            }
            const double tangent_length = norm3(tangent);
            if (tangent_length > 1e-12) {
                for (int component = 0; component < 3; ++component) tangent[component] /= tangent_length;
                double cross_value[3];
                cross3(geometric_normal, tangent, cross_value);
                const double sign_value = dot3(cross_value, raw_bitangent);
                handedness = sign_value < 0.0 ? -1.0 : (sign_value > 0.0 ? 1.0 : 0.0);
                if (handedness == 0.0) handedness = 1.0;
                tangent_valid = 1;
            }
        }

        const int64_t albedo_lower_index = albedo_lower[triangle];
        const int64_t albedo_upper_index = albedo_upper[triangle];
        const int64_t normal_index = normal_indices[triangle];
        const double *albedo_lower_texture = albedo_texels + albedo_levels[albedo_lower_index * 3] * 4;
        const double *albedo_upper_texture = albedo_texels + albedo_levels[albedo_upper_index * 3] * 4;
        const npy_intp albedo_lower_height = (npy_intp)albedo_levels[albedo_lower_index * 3 + 1];
        const npy_intp albedo_lower_width = (npy_intp)albedo_levels[albedo_lower_index * 3 + 2];
        const npy_intp albedo_upper_height = (npy_intp)albedo_levels[albedo_upper_index * 3 + 1];
        const npy_intp albedo_upper_width = (npy_intp)albedo_levels[albedo_upper_index * 3 + 2];
        const double albedo_amount = albedo_amounts[triangle];
        const double albedo_inverse_amount = 1.0 - albedo_amount;
        const double *normal_texture = normal_texels + normal_levels[normal_index * 3] * 4;
        const npy_intp normal_height = (npy_intp)normal_levels[normal_index * 3 + 1];
        const npy_intp normal_width = (npy_intp)normal_levels[normal_index * 3 + 2];

        for (int y = y0; y <= y1; ++y) {
            for (int x = x0; x <= x1; ++x) {
                double affine0, affine1, affine2, z;
                if (!visible_lane(screen, depth, framebuffer_width, x, y, denominator,
                                  &affine0, &affine1, &affine2, &z)) {
                    continue;
                }
                const double safe = fabs(z) < 1e-20 ? 1.0 : z;
                const double weight0 = (affine0 * screen[2]) / safe;
                const double weight1 = (affine1 * screen[5]) / safe;
                const double weight2 = (affine2 * screen[8]) / safe;
                const double u01 = weight0 * triangle_uv[0] + weight1 * triangle_uv[2];
                const double u = u01 + weight2 * triangle_uv[4];
                const double v01 = weight0 * triangle_uv[1] + weight1 * triangle_uv[3];
                const double v = v01 + weight2 * triangle_uv[5];
                double albedo_lower_sample[4];
                double albedo_upper_sample[4];
                sample_rgba(albedo_lower_texture, albedo_lower_height, albedo_lower_width,
                            u, v, 0, 0, albedo_lower_sample);
                sample_rgba(albedo_upper_texture, albedo_upper_height, albedo_upper_width,
                            u, v, 0, 0, albedo_upper_sample);
                double source_color[3];
                for (int channel = 0; channel < 3; ++channel) {
                    source_color[channel] =
                        albedo_lower_sample[channel] * albedo_inverse_amount +
                        albedo_upper_sample[channel] * albedo_amount;
                }
                const double fragment_alpha =
                    albedo_lower_sample[3] * albedo_inverse_amount +
                    albedo_upper_sample[3] * albedo_amount;
                if (!(fragment_alpha >= 0.0)) continue;

                double shading_normal[3];
                for (int component = 0; component < 3; ++component) {
                    const double first_two = weight0 * triangle_normals[component] +
                        weight1 * triangle_normals[3 + component];
                    shading_normal[component] = first_two + weight2 * triangle_normals[6 + component];
                }
                double shading_length = norm3(shading_normal);
                if (shading_length == 0.0) shading_length = 1.0;
                for (int component = 0; component < 3; ++component) shading_normal[component] /= shading_length;

                double normal_sample[4];
                sample_rgba(normal_texture, normal_height, normal_width, u, v, 0, 0, normal_sample);
                double normal_x = (normal_sample[0] * 2.0 - 1.0) * 1.0;
                double normal_y = (normal_sample[1] * 2.0 - 1.0) * 1.0;
                const double xy_length = sqrt(normal_x * normal_x + normal_y * normal_y);
                const double xy_denominator = xy_length > 1e-12 ? xy_length : 1e-12;
                double xy_scale = 0.999999 / xy_denominator;
                if (xy_scale > 1.0) xy_scale = 1.0;
                normal_x *= xy_scale;
                normal_y *= xy_scale;
                double z_squared = (1.0 - normal_x * normal_x) - normal_y * normal_y;
                if (z_squared < 0.0) z_squared = 0.0;
                const double normal_z = sqrt(z_squared);
                if (tangent_valid) {
                    const double tangent_dot_normal = dot3(shading_normal, tangent);
                    double tangent_field[3];
                    for (int component = 0; component < 3; ++component) {
                        tangent_field[component] = tangent[component] -
                            shading_normal[component] * tangent_dot_normal;
                    }
                    double tangent_field_length = norm3(tangent_field);
                    if (tangent_field_length == 0.0) tangent_field_length = 1.0;
                    for (int component = 0; component < 3; ++component) tangent_field[component] /= tangent_field_length;
                    double bitangent_field[3];
                    cross3(shading_normal, tangent_field, bitangent_field);
                    for (int component = 0; component < 3; ++component) {
                        bitangent_field[component] *= handedness;
                        const double first_two = tangent_field[component] * normal_x +
                            bitangent_field[component] * normal_y;
                        shading_normal[component] = first_two + shading_normal[component] * normal_z;
                    }
                    double final_length = norm3(shading_normal);
                    if (final_length == 0.0) final_length = 1.0;
                    for (int component = 0; component < 3; ++component) shading_normal[component] /= final_length;
                }
                double hemisphere = 0.5 + 0.5 * dot3(shading_normal, light_direction);
                if (hemisphere < 0.0) hemisphere = 0.0;
                else if (hemisphere > 1.0) hemisphere = 1.0;
                for (int channel = 0; channel < 3; ++channel) {
                    double light = 1.0;
                    if (front_radiance[channel] > 1e-12) {
                        const double normal_radiance = ambient_radiance[channel] +
                            key_radiance[channel] * hemisphere;
                        light = normal_radiance / front_radiance[channel];
                    }
                    source_color[channel] *= light;
                    source_color[channel] = source_color[channel] > 0.0 ? source_color[channel] : 0.0;
                }
                const npy_intp pixel = (npy_intp)y * framebuffer_width + x;
                color[pixel * 3] = source_color[0];
                color[pixel * 3 + 1] = source_color[1];
                color[pixel * 3 + 2] = source_color[2];
                if (target_alpha != NULL) target_alpha[pixel] = 1.0;
                depth[pixel] = z;
                ++written_fragments;
            }
        }
    }
    Py_END_ALLOW_THREADS
    return PyLong_FromLongLong((long long)written_fragments);
}

static PyObject *draw_outfit984(PyObject *self, PyObject *args) {
    return draw_opaque_outfit(self, args, "draw_outfit984");
}

static PyObject *draw_outfit936(PyObject *self, PyObject *args) {
    return draw_opaque_outfit(self, args, "draw_outfit936");
}

static PyObject *draw_outfit912(PyObject *self, PyObject *args) {
    return draw_opaque_outfit(self, args, "draw_outfit912");
}

enum Hair612Parameter {
    HAIR_BASE_R = 0,
    HAIR_BASE_G = 1,
    HAIR_BASE_B = 2,
    HAIR_LIGHT_X = 3,
    HAIR_LIGHT_Y = 4,
    HAIR_LIGHT_Z = 5,
    HAIR_AMBIENT_R = 6,
    HAIR_AMBIENT_G = 7,
    HAIR_AMBIENT_B = 8,
    HAIR_KEY_R = 9,
    HAIR_KEY_G = 10,
    HAIR_KEY_B = 11,
    HAIR_FRONT_R = 12,
    HAIR_FRONT_G = 13,
    HAIR_FRONT_B = 14,
    HAIR_CAMERA_X = 15,
    HAIR_CAMERA_Y = 16,
    HAIR_CAMERA_Z = 17,
    HAIR_ANISO_R = 18,
    HAIR_ANISO_G = 19,
    HAIR_ANISO_B = 20,
    HAIR_INVERSE_R2 = 21,
    HAIR_KERNEL_FACTOR = 22,
    HAIR_SHIFT_SCALE = 23,
    HAIR_SHIFT_OFFSET = 24,
    HAIR_FLIP_SIGN = 25,
    HAIR_HAS_CAMERA = 26,
    HAIR_PERSPECTIVE_CORRECT = 27,
    HAIR_TITLE_VIEW_SCALE = 28,
    HAIR_ANISO_LIGHT_X = 29,
    HAIR_ANISO_LIGHT_Y = 30,
    HAIR_ANISO_LIGHT_Z = 31,
    HAIR_EXECUTE_ANISOTROPY = 32,
    HAIR_PARAMETER_COUNT = 33
};

/* Current portable Hair612 response, not the uncaptured title shader. */
static PyObject *draw_hair612(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *objects[13];
    if (!PyArg_UnpackTuple(
            args, "draw_hair612", 13, 13,
            &objects[0], &objects[1], &objects[2], &objects[3],
            &objects[4], &objects[5], &objects[6], &objects[7],
            &objects[8], &objects[9], &objects[10], &objects[11],
            &objects[12])) {
        return NULL;
    }

    PyArrayObject *color_array = require_exact_array(objects[0], NPY_FLOAT64, 3, 1, "color");
    PyArrayObject *depth_array = require_exact_array(objects[1], NPY_FLOAT64, 2, 1, "depth");
    PyArrayObject *alpha_array = objects[2] == Py_None ? NULL :
        require_exact_array(objects[2], NPY_FLOAT64, 2, 1, "target_alpha");
    PyArrayObject *screen_array = require_exact_array(objects[3], NPY_FLOAT64, 3, 0, "screen_triangles");
    PyArrayObject *bounds_array = require_exact_array(objects[4], NPY_INT64, 2, 0, "bounds");
    PyArrayObject *denominator_array = require_exact_array(objects[5], NPY_FLOAT64, 1, 0, "denominators");
    PyArrayObject *vertices_array = require_exact_array(objects[6], NPY_FLOAT64, 3, 0, "world_vertices");
    PyArrayObject *normals_array = require_exact_array(objects[7], NPY_FLOAT64, 3, 0, "vertex_normals");
    PyArrayObject *uv_array = require_exact_array(objects[8], NPY_FLOAT64, 3, 0, "material_uv");
    PyArrayObject *texels_array = require_exact_array(objects[9], NPY_FLOAT64, 2, 0, "mim_texels");
    PyArrayObject *levels_array = require_exact_array(objects[10], NPY_INT64, 2, 0, "mim_levels");
    PyArrayObject *level_indices_array = require_exact_array(objects[11], NPY_INT64, 1, 0, "mim_level_indices");
    PyArrayObject *parameters_array = require_exact_array(objects[12], NPY_FLOAT64, 1, 0, "parameters");
    if (color_array == NULL || depth_array == NULL ||
        (objects[2] != Py_None && alpha_array == NULL) || screen_array == NULL ||
        bounds_array == NULL || denominator_array == NULL || vertices_array == NULL ||
        normals_array == NULL || uv_array == NULL || texels_array == NULL ||
        levels_array == NULL || level_indices_array == NULL || parameters_array == NULL) {
        return NULL;
    }

    const npy_intp framebuffer_height = PyArray_DIM(color_array, 0);
    const npy_intp framebuffer_width = PyArray_DIM(color_array, 1);
    const npy_intp triangle_count = PyArray_DIM(screen_array, 0);
    if (framebuffer_height <= 0 || framebuffer_width <= 0 ||
        PyArray_DIM(color_array, 2) != 3 ||
        PyArray_DIM(depth_array, 0) != framebuffer_height ||
        PyArray_DIM(depth_array, 1) != framebuffer_width ||
        (alpha_array != NULL &&
         (PyArray_DIM(alpha_array, 0) != framebuffer_height ||
          PyArray_DIM(alpha_array, 1) != framebuffer_width)) ||
        PyArray_DIM(screen_array, 1) != 3 || PyArray_DIM(screen_array, 2) != 3 ||
        PyArray_DIM(bounds_array, 0) != triangle_count || PyArray_DIM(bounds_array, 1) != 4 ||
        PyArray_DIM(denominator_array, 0) != triangle_count ||
        PyArray_DIM(vertices_array, 0) != triangle_count ||
        PyArray_DIM(vertices_array, 1) != 3 || PyArray_DIM(vertices_array, 2) != 3 ||
        PyArray_DIM(normals_array, 0) != triangle_count ||
        PyArray_DIM(normals_array, 1) != 3 || PyArray_DIM(normals_array, 2) != 3 ||
        PyArray_DIM(uv_array, 0) != triangle_count ||
        PyArray_DIM(uv_array, 1) != 3 || PyArray_DIM(uv_array, 2) != 2 ||
        PyArray_DIM(texels_array, 0) <= 0 || PyArray_DIM(texels_array, 1) != 4 ||
        PyArray_DIM(levels_array, 0) <= 0 || PyArray_DIM(levels_array, 1) != 3 ||
        PyArray_DIM(level_indices_array, 0) != triangle_count ||
        PyArray_DIM(parameters_array, 0) != HAIR_PARAMETER_COUNT) {
        PyErr_SetString(PyExc_ValueError, "flat Hair612 ABI shapes differ");
        return NULL;
    }

    const int64_t *bounds = (const int64_t *)PyArray_DATA(bounds_array);
    const int64_t *levels = (const int64_t *)PyArray_DATA(levels_array);
    const int64_t *level_indices = (const int64_t *)PyArray_DATA(level_indices_array);
    const npy_intp texel_count = PyArray_DIM(texels_array, 0);
    const npy_intp level_count = PyArray_DIM(levels_array, 0);
    for (npy_intp level = 0; level < level_count; ++level) {
        const int64_t offset = levels[level * 3];
        const int64_t height = levels[level * 3 + 1];
        const int64_t width = levels[level * 3 + 2];
        if (offset < 0 || height <= 0 || width <= 0 ||
            offset > texel_count || height * width > texel_count - offset) {
            PyErr_SetString(PyExc_ValueError, "Hair612 mip metadata is invalid");
            return NULL;
        }
    }
    for (npy_intp triangle = 0; triangle < triangle_count; ++triangle) {
        if (bounds[triangle * 4] < 0 || bounds[triangle * 4 + 2] < 0 ||
            bounds[triangle * 4 + 1] < bounds[triangle * 4] ||
            bounds[triangle * 4 + 3] < bounds[triangle * 4 + 2] ||
            bounds[triangle * 4 + 1] >= framebuffer_width ||
            bounds[triangle * 4 + 3] >= framebuffer_height ||
            level_indices[triangle] < 0 || level_indices[triangle] >= level_count) {
            PyErr_SetString(PyExc_ValueError, "Hair612 triangle metadata is invalid");
            return NULL;
        }
    }

    const double *parameters = (const double *)PyArray_DATA(parameters_array);
    for (int index = 0; index < HAIR_PARAMETER_COUNT; ++index) {
        if (!isfinite(parameters[index])) {
            PyErr_SetString(PyExc_ValueError, "Hair612 parameters must be finite");
            return NULL;
        }
    }
    double *color = (double *)PyArray_DATA(color_array);
    double *depth = (double *)PyArray_DATA(depth_array);
    double *target_alpha = alpha_array == NULL ? NULL : (double *)PyArray_DATA(alpha_array);
    const double *screens = (const double *)PyArray_DATA(screen_array);
    const double *denominators = (const double *)PyArray_DATA(denominator_array);
    const double *vertices = (const double *)PyArray_DATA(vertices_array);
    const double *normals = (const double *)PyArray_DATA(normals_array);
    const double *uvs = (const double *)PyArray_DATA(uv_array);
    const double *texels = (const double *)PyArray_DATA(texels_array);
    const double light[3] = {
        parameters[HAIR_LIGHT_X], parameters[HAIR_LIGHT_Y], parameters[HAIR_LIGHT_Z]
    };
    const double anisotropic_light[3] = {
        parameters[HAIR_ANISO_LIGHT_X],
        parameters[HAIR_ANISO_LIGHT_Y],
        parameters[HAIR_ANISO_LIGHT_Z]
    };
    npy_intp written_fragments = 0;

    for (npy_intp triangle = 0; triangle < triangle_count; ++triangle) {
        const double *screen = screens + triangle * 9;
        const double *triangle_vertices = vertices + triangle * 9;
        const double *triangle_normals = normals + triangle * 9;
        const double *triangle_uv = uvs + triangle * 6;
        const double denominator = denominators[triangle];
        const int x0 = (int)bounds[triangle * 4];
        const int x1 = (int)bounds[triangle * 4 + 1];
        const int y0 = (int)bounds[triangle * 4 + 2];
        const int y1 = (int)bounds[triangle * 4 + 3];

        double edge1[3], edge2[3], geometric_normal[3];
        for (int component = 0; component < 3; ++component) {
            edge1[component] = triangle_vertices[3 + component] - triangle_vertices[component];
            edge2[component] = triangle_vertices[6 + component] - triangle_vertices[component];
        }
        cross3(edge1, edge2, geometric_normal);
        const double geometric_length = norm3(geometric_normal);
        if (geometric_length != 0.0) {
            geometric_normal[0] /= geometric_length;
            geometric_normal[1] /= geometric_length;
            geometric_normal[2] /= geometric_length;
        }
        const double delta1_u = triangle_uv[2] - triangle_uv[0];
        const double delta1_v = triangle_uv[3] - triangle_uv[1];
        const double delta2_u = triangle_uv[4] - triangle_uv[0];
        const double delta2_v = triangle_uv[5] - triangle_uv[1];
        const double tangent_determinant = delta1_u * delta2_v - delta2_u * delta1_v;
        int tangent_valid = 0;
        double tangent[3] = {0.0, 0.0, 0.0};
        double handedness = 1.0;
        if (fabs(tangent_determinant) > 1e-12) {
            double raw_bitangent[3];
            for (int component = 0; component < 3; ++component) {
                tangent[component] =
                    (edge1[component] * delta2_v - edge2[component] * delta1_v) /
                    tangent_determinant;
                raw_bitangent[component] =
                    (-edge1[component] * delta2_u + edge2[component] * delta1_u) /
                    tangent_determinant;
            }
            const double tangent_length = norm3(tangent);
            if (tangent_length > 1e-12) {
                tangent[0] /= tangent_length;
                tangent[1] /= tangent_length;
                tangent[2] /= tangent_length;
                double cross_value[3];
                cross3(geometric_normal, tangent, cross_value);
                const double sign = dot3(cross_value, raw_bitangent);
                handedness = (sign < 0.0 ? -1.0 : 1.0) * parameters[HAIR_FLIP_SIGN];
                tangent_valid = 1;
            }
        }
        const int64_t level = level_indices[triangle];
        const double *mim = texels + levels[level * 3] * 4;
        const npy_intp mip_height = (npy_intp)levels[level * 3 + 1];
        const npy_intp mip_width = (npy_intp)levels[level * 3 + 2];

        for (int y = y0; y <= y1; ++y) {
            for (int x = x0; x <= x1; ++x) {
                double affine0, affine1, affine2, z;
                if (!visible_lane(
                        screen, depth, framebuffer_width, x, y, denominator,
                        &affine0, &affine1, &affine2, &z)) {
                    continue;
                }
                double weight0 = affine0;
                double weight1 = affine1;
                double weight2 = affine2;
                if (parameters[HAIR_PERSPECTIVE_CORRECT] != 0.0) {
                    const double safe = fabs(z) < 1e-20 ? 1.0 : z;
                    weight0 = affine0 * screen[2] / safe;
                    weight1 = affine1 * screen[5] / safe;
                    weight2 = affine2 * screen[8] / safe;
                }
                double shading_normal[3];
                for (int component = 0; component < 3; ++component) {
                    const double first_two =
                        weight0 * triangle_normals[component] +
                        weight1 * triangle_normals[3 + component];
                    shading_normal[component] =
                        first_two + weight2 * triangle_normals[6 + component];
                }
                double shading_length = norm3(shading_normal);
                if (shading_length == 0.0) shading_length = 1.0;
                shading_normal[0] /= shading_length;
                shading_normal[1] /= shading_length;
                shading_normal[2] /= shading_length;

                double hemisphere = 0.5 + 0.5 * dot3(shading_normal, light);
                if (hemisphere < 0.0) hemisphere = 0.0;
                if (hemisphere > 1.0) hemisphere = 1.0;
                double source_color[3];
                for (int channel = 0; channel < 3; ++channel) {
                    const double radiance = parameters[HAIR_AMBIENT_R + channel] +
                        parameters[HAIR_KEY_R + channel] * hemisphere;
                    const double light_scale = parameters[HAIR_FRONT_R + channel] > 1e-12
                        ? radiance / parameters[HAIR_FRONT_R + channel] : 1.0;
                    source_color[channel] = parameters[HAIR_BASE_R + channel] * light_scale;
                }

                if (parameters[HAIR_EXECUTE_ANISOTROPY] != 0.0 && tangent_valid) {
                    double frame_normal[3] = {
                        shading_normal[0], shading_normal[1], shading_normal[2]
                    };
                    const double normal_dot_tangent = dot3(frame_normal, tangent);
                    double tangent_field[3] = {
                        tangent[0] - frame_normal[0] * normal_dot_tangent,
                        tangent[1] - frame_normal[1] * normal_dot_tangent,
                        tangent[2] - frame_normal[2] * normal_dot_tangent
                    };
                    if (!normalize3_strict(tangent_field) ||
                        !normalize3_strict(frame_normal) ||
                        !normalize3_strict(tangent_field)) {
                        PyErr_SetString(PyExc_ValueError, "Hair612 tangent frame became degenerate");
                        return NULL;
                    }
                    double bitangent[3];
                    cross3(frame_normal, tangent_field, bitangent);
                    bitangent[0] *= handedness;
                    bitangent[1] *= handedness;
                    bitangent[2] *= handedness;
                    if (!normalize3_strict(bitangent)) {
                        PyErr_SetString(PyExc_ValueError, "Hair612 bitangent became degenerate");
                        return NULL;
                    }
                    const double u01 = weight0 * triangle_uv[0] + weight1 * triangle_uv[2];
                    const double v01 = weight0 * triangle_uv[1] + weight1 * triangle_uv[3];
                    const double u = u01 + weight2 * triangle_uv[4];
                    const double v = v01 + weight2 * triangle_uv[5];
                    double mim_sample[4];
                    sample_rgba(mim, mip_height, mip_width, u, v, 1, 1, mim_sample);
                    const double shift = (2.0 * mim_sample[2] - 1.0) *
                        parameters[HAIR_SHIFT_SCALE] + parameters[HAIR_SHIFT_OFFSET];
                    double shifted_axis[3] = {
                        bitangent[0] + shift * frame_normal[0],
                        bitangent[1] + shift * frame_normal[1],
                        bitangent[2] + shift * frame_normal[2]
                    };
                    double anisotangent[3];
                    cross3(frame_normal, bitangent, anisotangent);
                    anisotangent[0] *= handedness;
                    anisotangent[1] *= handedness;
                    anisotangent[2] *= handedness;
                    if (!normalize3_strict(shifted_axis) || !normalize3_strict(anisotangent)) {
                        PyErr_SetString(PyExc_ValueError, "Hair612 anisotropic frame became degenerate");
                        return NULL;
                    }
                    double view_direction[3] = {0.0, 0.0, 1.0};
                    if (parameters[HAIR_HAS_CAMERA] != 0.0) {
                        for (int component = 0; component < 3; ++component) {
                            const double first_two =
                                weight0 * triangle_vertices[component] +
                                weight1 * triangle_vertices[3 + component];
                            const double fragment_position =
                                first_two + weight2 * triangle_vertices[6 + component];
                            view_direction[component] =
                                parameters[HAIR_CAMERA_X + component] - fragment_position;
                        }
                        const double view_length = norm3(view_direction);
                        if (view_length != 0.0) {
                            view_direction[0] /= view_length;
                            view_direction[1] /= view_length;
                            view_direction[2] /= view_length;
                        }
                    }
                    double half_vector[3] = {
                        parameters[HAIR_TITLE_VIEW_SCALE] * view_direction[0] + anisotropic_light[0],
                        parameters[HAIR_TITLE_VIEW_SCALE] * view_direction[1] + anisotropic_light[1],
                        parameters[HAIR_TITLE_VIEW_SCALE] * view_direction[2] + anisotropic_light[2]
                    };
                    if (!normalize3_strict(half_vector)) {
                        PyErr_SetString(PyExc_ValueError, "Hair612 half vector became degenerate");
                        return NULL;
                    }
                    const double nh = dot3(frame_normal, half_vector);
                    const double sh = dot3(shifted_axis, half_vector);
                    const double ah = dot3(anisotangent, half_vector);
                    const double scaled_sh = sh * parameters[HAIR_INVERSE_R2];
                    const double numerator = ah * ah + scaled_sh * scaled_sh;
                    const double nh_squared = nh * nh;
                    const double q = nh_squared > 0.0 ? numerator / nh_squared : INFINITY;
                    const double kernel = exp(-q) * parameters[HAIR_KERNEL_FACTOR];
                    double ndotl = dot3(frame_normal, anisotropic_light);
                    if (ndotl < 0.0) ndotl = 0.0;
                    const double lobe = kernel * mim_sample[1] * ndotl;
                    for (int channel = 0; channel < 3; ++channel) {
                        source_color[channel] += parameters[HAIR_ANISO_R + channel] * lobe;
                    }
                }

                const npy_intp pixel = (npy_intp)y * framebuffer_width + x;
                for (int channel = 0; channel < 3; ++channel) {
                    if (!isfinite(source_color[channel])) {
                        PyErr_SetString(PyExc_FloatingPointError, "Hair612 produced non-finite radiance");
                        return NULL;
                    }
                    if (source_color[channel] < 0.0) source_color[channel] = 0.0;
                    color[pixel * 3 + channel] = source_color[channel];
                }
                if (target_alpha != NULL) target_alpha[pixel] = 1.0;
                depth[pixel] = z;
                ++written_fragments;
            }
        }
    }
    return PyLong_FromLongLong((long long)written_fragments);
}

/* The flat ABI and fragment loop are shared; strict Python fingerprints and
 * parameter builders keep Hair612 and Beard468 semantics isolated. */
static PyObject *draw_beard468(PyObject *self, PyObject *args) {
    return draw_hair612(self, args);
}

static PyObject *draw_hair564(PyObject *self, PyObject *args) {
    return draw_hair612(self, args);
}

static PyObject *draw_mask0(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *objects[15];
    if (!PyArg_UnpackTuple(
            args, "draw_mask0", 15, 15,
            &objects[0], &objects[1], &objects[2], &objects[3], &objects[4],
            &objects[5], &objects[6], &objects[7], &objects[8], &objects[9],
            &objects[10], &objects[11], &objects[12], &objects[13], &objects[14])) {
        return NULL;
    }

    PyArrayObject *color_array = require_exact_array(objects[0], NPY_FLOAT64, 3, 1, "color");
    PyArrayObject *depth_array = require_exact_array(objects[1], NPY_FLOAT64, 2, 1, "depth");
    PyArrayObject *alpha_array = objects[2] == Py_None ? NULL :
        require_exact_array(objects[2], NPY_FLOAT64, 2, 1, "target_alpha");
    PyArrayObject *screen_array = require_exact_array(objects[3], NPY_FLOAT64, 3, 0, "screen");
    PyArrayObject *bounds_array = require_exact_array(objects[4], NPY_INT64, 2, 0, "bounds");
    PyArrayObject *denominator_array = require_exact_array(objects[5], NPY_FLOAT64, 1, 0, "denominators");
    PyArrayObject *vertices_array = require_exact_array(objects[6], NPY_FLOAT64, 3, 0, "vertices");
    PyArrayObject *normals_array = require_exact_array(objects[7], NPY_FLOAT64, 3, 0, "normals");
    PyArrayObject *uv_array = require_exact_array(objects[8], NPY_FLOAT64, 3, 0, "uv");
    PyArrayObject *generated_array = require_exact_array(objects[9], NPY_FLOAT64, 3, 0, "generated");
    PyArrayObject *user_array = require_exact_array(objects[10], NPY_FLOAT64, 3, 0, "user");
    PyArrayObject *direction_array = require_exact_array(objects[11], NPY_FLOAT64, 1, 0, "light_direction");
    PyArrayObject *light_array = require_exact_array(objects[12], NPY_FLOAT64, 1, 0, "light_color");
    PyArrayObject *ambient_array = require_exact_array(objects[13], NPY_FLOAT64, 1, 0, "ambient_color");
    PyArrayObject *parameters_array = require_exact_array(objects[14], NPY_FLOAT64, 1, 0, "parameters");
    if (color_array == NULL || depth_array == NULL ||
        (objects[2] != Py_None && alpha_array == NULL) || screen_array == NULL ||
        bounds_array == NULL || denominator_array == NULL || vertices_array == NULL ||
        normals_array == NULL || uv_array == NULL || generated_array == NULL ||
        user_array == NULL || direction_array == NULL || light_array == NULL ||
        ambient_array == NULL || parameters_array == NULL) return NULL;

    const npy_intp height = PyArray_DIM(color_array, 0);
    const npy_intp width = PyArray_DIM(color_array, 1);
    const npy_intp triangle_count = PyArray_DIM(screen_array, 0);
    if (height <= 0 || width <= 0 || PyArray_DIM(color_array, 2) != 3 ||
        PyArray_DIM(depth_array, 0) != height || PyArray_DIM(depth_array, 1) != width ||
        (alpha_array != NULL &&
         (PyArray_DIM(alpha_array, 0) != height || PyArray_DIM(alpha_array, 1) != width)) ||
        PyArray_DIM(screen_array, 1) != 3 || PyArray_DIM(screen_array, 2) != 3 ||
        PyArray_DIM(bounds_array, 0) != triangle_count || PyArray_DIM(bounds_array, 1) != 4 ||
        PyArray_DIM(denominator_array, 0) != triangle_count ||
        PyArray_DIM(vertices_array, 0) != triangle_count || PyArray_DIM(vertices_array, 1) != 3 || PyArray_DIM(vertices_array, 2) != 3 ||
        PyArray_DIM(normals_array, 0) != triangle_count || PyArray_DIM(normals_array, 1) != 3 || PyArray_DIM(normals_array, 2) != 3 ||
        PyArray_DIM(uv_array, 0) != triangle_count || PyArray_DIM(uv_array, 1) != 3 || PyArray_DIM(uv_array, 2) != 2 ||
        PyArray_DIM(generated_array, 0) <= 0 || PyArray_DIM(generated_array, 1) <= 0 || PyArray_DIM(generated_array, 2) != 4 ||
        PyArray_DIM(user_array, 0) <= 0 || PyArray_DIM(user_array, 1) <= 0 || PyArray_DIM(user_array, 2) != 4 ||
        PyArray_DIM(direction_array, 0) != 3 || PyArray_DIM(light_array, 0) != 3 ||
        PyArray_DIM(ambient_array, 0) != 3 || PyArray_DIM(parameters_array, 0) != 10) {
        PyErr_SetString(PyExc_ValueError, "Mask0 flat ABI shape mismatch");
        return NULL;
    }

    const int64_t *bounds = (const int64_t *)PyArray_DATA(bounds_array);
    for (npy_intp triangle = 0; triangle < triangle_count; ++triangle) {
        if (bounds[triangle * 4] < 0 || bounds[triangle * 4 + 2] < 0 ||
            bounds[triangle * 4 + 1] < bounds[triangle * 4] ||
            bounds[triangle * 4 + 3] < bounds[triangle * 4 + 2] ||
            bounds[triangle * 4 + 1] >= width || bounds[triangle * 4 + 3] >= height) {
            PyErr_SetString(PyExc_ValueError, "Mask0 triangle bounds are invalid");
            return NULL;
        }
    }

    const double *parameters = (const double *)PyArray_DATA(parameters_array);
    const int perspective_correct = (int)parameters[2];
    const int mode = (int)parameters[3];
    if ((perspective_correct != 0 && perspective_correct != 1) ||
        (mode != 0 && mode != 1) || parameters[2] != perspective_correct ||
        parameters[3] != mode) {
        PyErr_SetString(PyExc_ValueError, "Mask0 flags must be exact zero/one");
        return NULL;
    }

    double *color = (double *)PyArray_DATA(color_array);
    double *depth = (double *)PyArray_DATA(depth_array);
    double *target_alpha = alpha_array == NULL ? NULL : (double *)PyArray_DATA(alpha_array);
    const double *screens = (const double *)PyArray_DATA(screen_array);
    const double *denominators = (const double *)PyArray_DATA(denominator_array);
    const double *vertices = (const double *)PyArray_DATA(vertices_array);
    const double *normals = (const double *)PyArray_DATA(normals_array);
    const double *uvs = (const double *)PyArray_DATA(uv_array);
    const double *generated = (const double *)PyArray_DATA(generated_array);
    const double *user = (const double *)PyArray_DATA(user_array);
    const double *light_direction = (const double *)PyArray_DATA(direction_array);
    const double *light_color = (const double *)PyArray_DATA(light_array);
    const double *ambient_color = (const double *)PyArray_DATA(ambient_array);
    const npy_intp generated_height = PyArray_DIM(generated_array, 0);
    const npy_intp generated_width = PyArray_DIM(generated_array, 1);
    const npy_intp user_height = PyArray_DIM(user_array, 0);
    const npy_intp user_width = PyArray_DIM(user_array, 1);

    double ambient_radiance[3];
    double key_radiance[3];
    double front_radiance[3];
    double front_hemisphere = 0.5 + 0.5 * light_direction[2];
    if (front_hemisphere < 0.0) front_hemisphere = 0.0;
    else if (front_hemisphere > 1.0) front_hemisphere = 1.0;
    for (int channel = 0; channel < 3; ++channel) {
        ambient_radiance[channel] = ambient_color[channel] * parameters[1];
        key_radiance[channel] = light_color[channel] * parameters[0];
        front_radiance[channel] =
            ambient_radiance[channel] + key_radiance[channel] * front_hemisphere;
    }

    npy_intp written = 0;
    Py_BEGIN_ALLOW_THREADS
    for (npy_intp triangle = 0; triangle < triangle_count; ++triangle) {
        const double *screen = screens + triangle * 9;
        const double *triangle_normals = normals + triangle * 9;
        const double *triangle_uv = uvs + triangle * 6;
        const double denominator = denominators[triangle];
        const int x0 = (int)bounds[triangle * 4];
        const int x1 = (int)bounds[triangle * 4 + 1];
        const int y0 = (int)bounds[triangle * 4 + 2];
        const int y1 = (int)bounds[triangle * 4 + 3];
        (void)vertices;
        for (int y = y0; y <= y1; ++y) {
            for (int x = x0; x <= x1; ++x) {
                double affine0, affine1, affine2, z;
                if (!visible_lane(
                        screen, depth, width, x, y, denominator,
                        &affine0, &affine1, &affine2, &z)) continue;
                double weight0 = affine0;
                double weight1 = affine1;
                double weight2 = affine2;
                if (perspective_correct) {
                    const double safe = fabs(z) < 1e-20 ? 1.0 : z;
                    weight0 = affine0 * screen[2] / safe;
                    weight1 = affine1 * screen[5] / safe;
                    weight2 = affine2 * screen[8] / safe;
                }
                const double u01 = weight0 * triangle_uv[0] + weight1 * triangle_uv[2];
                const double u = u01 + weight2 * triangle_uv[4];
                const double v01 = weight0 * triangle_uv[1] + weight1 * triangle_uv[3];
                const double v = v01 + weight2 * triangle_uv[5];
                double generated_sample[4];
                sample_rgba(
                    generated, generated_height, generated_width, u, v,
                    mode, mode, generated_sample
                );
                double user_sample[4];
                if (mode) {
                    const double bfres_v = 1.0 - v;
                    const double mapped_u =
                        parameters[4] * u + parameters[5] * bfres_v + parameters[6];
                    const double mapped_bfres_v =
                        parameters[7] * u + parameters[8] * bfres_v + parameters[9];
                    sample_rgba(
                        user, user_height, user_width, mapped_u, 1.0 - mapped_bfres_v,
                        0, 0, user_sample
                    );
                    if (!(generated_sample[3] >= 0.5 || user_sample[3] >= 0.5)) continue;
                } else {
                    user_sample[0] = 0.21586050011389926;
                    user_sample[1] = 0.21586050011389926;
                    user_sample[2] = 0.21586050011389926;
                    user_sample[3] = 1.0;
                    if (!(generated_sample[3] >= 0.5)) continue;
                }

                const double k = denominator > 0.0 ?
                    (generated_sample[3] > 0.0 ? generated_sample[3] : 0.0) : 0.0;
                double source_color[3];
                double emission[3];
                for (int channel = 0; channel < 3; ++channel) {
                    source_color[channel] =
                        user_sample[channel] +
                        (generated_sample[channel] - user_sample[channel]) * k;
                    emission[channel] =
                        generated_sample[channel] * generated_sample[3] * 0.1;
                }

                double shading_normal[3];
                for (int component = 0; component < 3; ++component) {
                    const double first_two =
                        weight0 * triangle_normals[component] +
                        weight1 * triangle_normals[3 + component];
                    shading_normal[component] =
                        first_two + weight2 * triangle_normals[6 + component];
                }
                double normal_length = sqrt(
                    (shading_normal[0] * shading_normal[0] +
                     shading_normal[1] * shading_normal[1]) +
                    shading_normal[2] * shading_normal[2]
                );
                if (normal_length == 0.0) normal_length = 1.0;
                for (int component = 0; component < 3; ++component)
                    shading_normal[component] /= normal_length;

                double hemisphere = 0.5 + 0.5 * dot3(shading_normal, light_direction);
                if (hemisphere < 0.0) hemisphere = 0.0;
                else if (hemisphere > 1.0) hemisphere = 1.0;
                for (int channel = 0; channel < 3; ++channel) {
                    double light = 1.0;
                    if (front_radiance[channel] > 1e-12) {
                        const double normal_radiance =
                            ambient_radiance[channel] + key_radiance[channel] * hemisphere;
                        light = normal_radiance / front_radiance[channel];
                    }
                    source_color[channel] *= light;
                    source_color[channel] += emission[channel];
                    if (source_color[channel] < 0.0) source_color[channel] = 0.0;
                }
                const npy_intp pixel = (npy_intp)y * width + x;
                color[pixel * 3] = source_color[0];
                color[pixel * 3 + 1] = source_color[1];
                color[pixel * 3 + 2] = source_color[2];
                if (target_alpha != NULL) target_alpha[pixel] = 1.0;
                depth[pixel] = z;
                ++written;
            }
        }
    }
    Py_END_ALLOW_THREADS
    return PyLong_FromLongLong((long long)written);
}


/* Body324/336/348 and the texture-free Ear372/Nose756 response are kept in a
 * separately reviewable translation fragment while sharing this module and
 * source-sealed ABI. Rename its private helpers to keep the consolidated
 * translation unit collision-free. */
#define LTD_NATIVE_CURRENT_DRAW_EMBED 1
#define require_array opaque_require_array
#define clamp_index opaque_clamp_index
#define sample_clamp_rgba opaque_sample_clamp_rgba
#define dot3 opaque_dot3
#define cross3 opaque_cross3
#define norm3 opaque_norm3
#define visible_lane opaque_visible_lane
#define attachment_shapes opaque_attachment_shapes
#define triangle_metadata opaque_triangle_metadata
#define lighting_constants opaque_lighting_constants
#define shade_plain opaque_shade_plain
#define valid_mip_bank opaque_valid_mip_bank
#include "native_current_opaque_kernel.c"
#undef valid_mip_bank
#undef shade_plain
#undef lighting_constants
#undef triangle_metadata
#undef attachment_shapes
#undef visible_lane
#undef norm3
#undef cross3
#undef dot3
#undef sample_clamp_rgba
#undef clamp_index
#undef require_array
#undef LTD_NATIVE_CURRENT_DRAW_EMBED

static PyMethodDef module_methods[] = {
    {
        "draw_head816",
        draw_head816,
        METH_VARARGS,
        "Mutate shared color/depth/alpha buffers using the flat current Head816 ABI."
    },
    {
        "draw_hair612",
        draw_hair612,
        METH_VARARGS,
        "Mutate shared attachments using the flat current Hair612 ABI."
    },
    {
        "draw_beard468",
        draw_beard468,
        METH_VARARGS,
        "Mutate shared attachments using the flat current Beard468 ABI."
    },
    {
        "draw_hair564",
        draw_hair564,
        METH_VARARGS,
        "Mutate shared attachments using the equal-endpoint current Hair564 ABI."
    },
    {
        "draw_outfit984",
        draw_outfit984,
        METH_VARARGS,
        "Mutate shared attachments using the exact opaque current Tops984 ABI."
    },
    {
        "draw_outfit936",
        draw_outfit936,
        METH_VARARGS,
        "Mutate shared attachments using the exact opaque current Bottoms936 ABI."
    },
    {
        "draw_outfit912",
        draw_outfit912,
        METH_VARARGS,
        "Mutate shared attachments using the exact opaque current Shoes912 ABI."
    },
    {
        "draw_body",
        draw_body,
        METH_VARARGS,
        "Mutate shared attachments using exact current Body324/336/348."
    },
    {
        "draw_plain_skin",
        draw_plain_skin,
        METH_VARARGS,
        "Mutate shared attachments using exact current Ear372/Nose756 skin."
    },
    {
        "draw_mask0",
        draw_mask0,
        METH_VARARGS,
        "Mutate shared attachments using the generated-only or UGC current Mask0 ABI."
    },
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module_definition = {
    PyModuleDef_HEAD_INIT,
    "_native_current_draw",
    "Exact-current-output Head/Hair/Beard/outfit/Body/Ear/Nose/Mask whole-draw kernels.",
    -1,
    module_methods
};

PyMODINIT_FUNC PyInit__native_current_draw(void) {
    import_array();
    PyObject *module = PyModule_Create(&module_definition);
    if (module == NULL) {
        return NULL;
    }
    if (PyModule_AddIntConstant(
            module, "ABI_VERSION", LTD_NATIVE_CURRENT_DRAW_ABI_VERSION) < 0 ||
        PyModule_AddStringConstant(
            module, "SOURCE_SHA256", LTD_NATIVE_CURRENT_DRAW_SOURCE_SHA256) < 0 ||
        PyModule_AddStringConstant(
            module, "OPAQUE_SOURCE_SHA256", LTD_NATIVE_CURRENT_DRAW_OPAQUE_SOURCE_SHA256) < 0 ||
        PyModule_AddIntConstant(module, "HAIR612_PARAMETER_COUNT", HAIR_PARAMETER_COUNT) < 0 ||
        PyModule_AddIntConstant(module, "NUMPY_ABI_VERSION", NPY_VERSION) < 0) {
        Py_DECREF(module);
        return NULL;
    }
    return module;
}

#if defined(_MSC_VER)
#pragma float_control(pop)
#endif
