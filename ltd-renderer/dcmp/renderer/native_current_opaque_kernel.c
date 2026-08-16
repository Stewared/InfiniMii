#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <math.h>
#include <stdint.h>

#define NPY_NO_DEPRECATED_API NPY_1_7_API_VERSION
#include <numpy/arrayobject.h>

#if defined(_MSC_VER)
#pragma float_control(precise, on, push)
#pragma fp_contract(off)
#endif

static PyArrayObject *require_array(
    PyObject *object, int type, int dimensions, int writable, const char *name
) {
    if (!PyArray_Check(object)) {
        PyErr_Format(PyExc_TypeError, "%s must be a NumPy array", name);
        return NULL;
    }
    PyArrayObject *array = (PyArrayObject *)object;
    if (PyArray_TYPE(array) != type || PyArray_NDIM(array) != dimensions) {
        PyErr_Format(PyExc_TypeError, "%s has the wrong dtype or rank", name);
        return NULL;
    }
    if (!PyArray_IS_C_CONTIGUOUS(array) || !PyArray_ISALIGNED(array) ||
        (writable && !PyArray_ISWRITEABLE(array))) {
        PyErr_Format(PyExc_ValueError, "%s has an invalid memory layout", name);
        return NULL;
    }
    return array;
}

static npy_intp clamp_index(npy_intp index, npy_intp size) {
    if (index < 0) return 0;
    return index >= size ? size - 1 : index;
}

static void sample_clamp_rgba(
    const double *source, npy_intp height, npy_intp width,
    double u, double v, double output[4]
) {
    const double tex_x = u * (double)width - 0.5;
    const double tex_y = (1.0 - v) * (double)height - 0.5;
    const double floor_x = floor(tex_x);
    const double floor_y = floor(tex_y);
    const npy_intp x0 = clamp_index((npy_intp)floor_x, width);
    const npy_intp x1 = clamp_index((npy_intp)floor_x + 1, width);
    const npy_intp y0 = clamp_index((npy_intp)floor_y, height);
    const npy_intp y1 = clamp_index((npy_intp)floor_y + 1, height);
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

static int visible_lane(
    const double *screen, const double *depth, npy_intp width,
    int x, int y, double denominator,
    double *weight0, double *weight1, double *weight2, double *z
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
    if (*weight0 < -1e-7 || *weight1 < -1e-7 || *weight2 < -1e-7) return 0;
    const double z01 = *weight0 * screen[2] + *weight1 * screen[5];
    *z = z01 + *weight2 * screen[8];
    return *z >= depth[(npy_intp)y * width + x];
}

static int attachment_shapes(
    PyArrayObject *color, PyArrayObject *depth, PyArrayObject *alpha,
    npy_intp *height, npy_intp *width
) {
    *height = PyArray_DIM(color, 0);
    *width = PyArray_DIM(color, 1);
    if (*height <= 0 || *width <= 0 || PyArray_DIM(color, 2) != 3 ||
        PyArray_DIM(depth, 0) != *height || PyArray_DIM(depth, 1) != *width ||
        (alpha != NULL &&
         (PyArray_DIM(alpha, 0) != *height || PyArray_DIM(alpha, 1) != *width))) {
        PyErr_SetString(PyExc_ValueError, "attachment shapes do not match");
        return 0;
    }
    return 1;
}

static int triangle_metadata(
    PyArrayObject *screens, PyArrayObject *bounds, PyArrayObject *denominators,
    npy_intp height, npy_intp width
) {
    const npy_intp count = PyArray_DIM(screens, 0);
    if (PyArray_DIM(screens, 1) != 3 || PyArray_DIM(screens, 2) != 3 ||
        PyArray_DIM(bounds, 0) != count || PyArray_DIM(bounds, 1) != 4 ||
        PyArray_DIM(denominators, 0) != count) {
        PyErr_SetString(PyExc_ValueError, "triangle metadata shapes do not match");
        return 0;
    }
    const int64_t *rows = (const int64_t *)PyArray_DATA(bounds);
    for (npy_intp triangle = 0; triangle < count; ++triangle) {
        const int64_t *row = rows + triangle * 4;
        if (row[0] < 0 || row[2] < 0 || row[1] < row[0] || row[3] < row[2] ||
            row[1] >= width || row[3] >= height) {
            PyErr_SetString(PyExc_ValueError, "triangle bounds are invalid");
            return 0;
        }
    }
    return 1;
}

static void lighting_constants(
    const double *direction, const double *light_color, const double *ambient_color,
    double light_intensity, double ambient_intensity,
    double ambient[3], double key[3], double front[3]
) {
    double front_hemisphere = 0.5 + 0.5 * direction[2];
    if (front_hemisphere < 0.0) front_hemisphere = 0.0;
    else if (front_hemisphere > 1.0) front_hemisphere = 1.0;
    for (int channel = 0; channel < 3; ++channel) {
        ambient[channel] = ambient_color[channel] * ambient_intensity;
        key[channel] = light_color[channel] * light_intensity;
        front[channel] = ambient[channel] + key[channel] * front_hemisphere;
    }
}

static void shade_plain(
    double source[3], const double normal[3], const double *direction,
    const double ambient[3], const double key[3], const double front[3]
) {
    double hemisphere = 0.5 + 0.5 * dot3(normal, direction);
    if (hemisphere < 0.0) hemisphere = 0.0;
    else if (hemisphere > 1.0) hemisphere = 1.0;
    for (int channel = 0; channel < 3; ++channel) {
        double light = 1.0;
        if (front[channel] > 1e-12) {
            const double normal_radiance = ambient[channel] + key[channel] * hemisphere;
            light = normal_radiance / front[channel];
        }
        source[channel] *= light;
        if (source[channel] < 0.0) source[channel] = 0.0;
    }
}

static PyObject *draw_plain_skin(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *objects[14];
    if (!PyArg_UnpackTuple(
            args, "draw_plain_skin", 14, 14,
            &objects[0], &objects[1], &objects[2], &objects[3],
            &objects[4], &objects[5], &objects[6], &objects[7],
            &objects[8], &objects[9], &objects[10], &objects[11],
            &objects[12], &objects[13])) return NULL;
    PyArrayObject *color_array = require_array(objects[0], NPY_FLOAT64, 3, 1, "color");
    PyArrayObject *depth_array = require_array(objects[1], NPY_FLOAT64, 2, 1, "depth");
    PyArrayObject *alpha_array = objects[2] == Py_None ? NULL :
        require_array(objects[2], NPY_FLOAT64, 2, 1, "target_alpha");
    PyArrayObject *screens_array = require_array(objects[3], NPY_FLOAT64, 3, 0, "screen_triangles");
    PyArrayObject *bounds_array = require_array(objects[4], NPY_INT64, 2, 0, "bounds");
    PyArrayObject *denominators_array = require_array(objects[5], NPY_FLOAT64, 1, 0, "denominators");
    PyArrayObject *normals_array = require_array(objects[6], NPY_FLOAT64, 3, 0, "vertex_normals");
    PyArrayObject *base_array = require_array(objects[7], NPY_FLOAT64, 1, 0, "base_color_linear");
    PyArrayObject *direction_array = require_array(objects[8], NPY_FLOAT64, 1, 0, "light_direction");
    PyArrayObject *light_array = require_array(objects[9], NPY_FLOAT64, 1, 0, "light_color");
    PyArrayObject *ambient_array = require_array(objects[10], NPY_FLOAT64, 1, 0, "ambient_color");
    if (color_array == NULL || depth_array == NULL ||
        (objects[2] != Py_None && alpha_array == NULL) || screens_array == NULL ||
        bounds_array == NULL || denominators_array == NULL || normals_array == NULL ||
        base_array == NULL || direction_array == NULL || light_array == NULL || ambient_array == NULL) return NULL;
    const double light_intensity = PyFloat_AsDouble(objects[11]);
    const double ambient_intensity = PyFloat_AsDouble(objects[12]);
    const long perspective = PyLong_AsLong(objects[13]);
    if (PyErr_Occurred()) return NULL;
    if (perspective != 1) {
        PyErr_SetString(PyExc_ValueError, "plain skin prototype requires perspective correction");
        return NULL;
    }
    npy_intp height, width;
    if (!attachment_shapes(color_array, depth_array, alpha_array, &height, &width) ||
        !triangle_metadata(screens_array, bounds_array, denominators_array, height, width)) return NULL;
    const npy_intp count = PyArray_DIM(screens_array, 0);
    if (PyArray_DIM(normals_array, 0) != count || PyArray_DIM(normals_array, 1) != 3 ||
        PyArray_DIM(normals_array, 2) != 3 || PyArray_DIM(base_array, 0) != 3 ||
        PyArray_DIM(direction_array, 0) != 3 || PyArray_DIM(light_array, 0) != 3 ||
        PyArray_DIM(ambient_array, 0) != 3) {
        PyErr_SetString(PyExc_ValueError, "plain skin ABI shapes do not match");
        return NULL;
    }
    double *color = (double *)PyArray_DATA(color_array);
    double *depth = (double *)PyArray_DATA(depth_array);
    double *target_alpha = alpha_array == NULL ? NULL : (double *)PyArray_DATA(alpha_array);
    const double *screens = (const double *)PyArray_DATA(screens_array);
    const int64_t *bounds = (const int64_t *)PyArray_DATA(bounds_array);
    const double *denominators = (const double *)PyArray_DATA(denominators_array);
    const double *normals = (const double *)PyArray_DATA(normals_array);
    const double *base = (const double *)PyArray_DATA(base_array);
    const double *direction = (const double *)PyArray_DATA(direction_array);
    const double *light_color = (const double *)PyArray_DATA(light_array);
    const double *ambient_color = (const double *)PyArray_DATA(ambient_array);
    double ambient[3], key[3], front[3];
    lighting_constants(direction, light_color, ambient_color, light_intensity, ambient_intensity, ambient, key, front);
    npy_intp written = 0;
    Py_BEGIN_ALLOW_THREADS
    for (npy_intp triangle = 0; triangle < count; ++triangle) {
        const double *screen = screens + triangle * 9;
        const double *triangle_normals = normals + triangle * 9;
        const int x0 = (int)bounds[triangle * 4];
        const int x1 = (int)bounds[triangle * 4 + 1];
        const int y0 = (int)bounds[triangle * 4 + 2];
        const int y1 = (int)bounds[triangle * 4 + 3];
        for (int y = y0; y <= y1; ++y) {
            for (int x = x0; x <= x1; ++x) {
                double affine0, affine1, affine2, z;
                if (!visible_lane(screen, depth, width, x, y, denominators[triangle],
                                  &affine0, &affine1, &affine2, &z)) continue;
                const double safe = fabs(z) < 1e-20 ? 1.0 : z;
                const double weight0 = affine0 * screen[2] / safe;
                const double weight1 = affine1 * screen[5] / safe;
                const double weight2 = affine2 * screen[8] / safe;
                double normal[3];
                for (int component = 0; component < 3; ++component) {
                    const double first_two = weight0 * triangle_normals[component] +
                        weight1 * triangle_normals[3 + component];
                    normal[component] = first_two + weight2 * triangle_normals[6 + component];
                }
                double length = norm3(normal);
                if (length == 0.0) length = 1.0;
                for (int component = 0; component < 3; ++component) normal[component] /= length;
                double source[3] = {base[0], base[1], base[2]};
                shade_plain(source, normal, direction, ambient, key, front);
                const npy_intp pixel = (npy_intp)y * width + x;
                color[pixel * 3] = source[0];
                color[pixel * 3 + 1] = source[1];
                color[pixel * 3 + 2] = source[2];
                if (target_alpha != NULL) target_alpha[pixel] = 1.0;
                depth[pixel] = z;
                ++written;
            }
        }
    }
    Py_END_ALLOW_THREADS
    return PyLong_FromLongLong((long long)written);
}

static int valid_mip_bank(
    PyArrayObject *texels_array, PyArrayObject *levels_array, const char *label
) {
    if (PyArray_DIM(texels_array, 0) <= 0 || PyArray_DIM(texels_array, 1) != 4 ||
        PyArray_DIM(levels_array, 0) <= 0 || PyArray_DIM(levels_array, 1) != 3) {
        PyErr_Format(PyExc_ValueError, "%s mip bank shape is invalid", label);
        return 0;
    }
    const npy_intp texel_count = PyArray_DIM(texels_array, 0);
    const int64_t *levels = (const int64_t *)PyArray_DATA(levels_array);
    for (npy_intp level = 0; level < PyArray_DIM(levels_array, 0); ++level) {
        const int64_t offset = levels[level * 3];
        const int64_t height = levels[level * 3 + 1];
        const int64_t width = levels[level * 3 + 2];
        if (offset < 0 || height <= 0 || width <= 0 || offset > texel_count ||
            height > texel_count || width > texel_count ||
            height * width > texel_count - offset) {
            PyErr_Format(PyExc_ValueError, "%s mip metadata exceeds packed texels", label);
            return 0;
        }
    }
    return 1;
}

static PyObject *draw_body(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *objects[29];
    if (!PyArg_UnpackTuple(
            args, "draw_body", 29, 29,
            &objects[0], &objects[1], &objects[2], &objects[3],
            &objects[4], &objects[5], &objects[6], &objects[7],
            &objects[8], &objects[9], &objects[10], &objects[11],
            &objects[12], &objects[13], &objects[14], &objects[15],
            &objects[16], &objects[17], &objects[18], &objects[19],
            &objects[20], &objects[21], &objects[22], &objects[23],
            &objects[24], &objects[25], &objects[26], &objects[27],
            &objects[28])) return NULL;

    PyArrayObject *color_array = require_array(objects[0], NPY_FLOAT64, 3, 1, "color");
    PyArrayObject *depth_array = require_array(objects[1], NPY_FLOAT64, 2, 1, "depth");
    PyArrayObject *alpha_array = objects[2] == Py_None ? NULL :
        require_array(objects[2], NPY_FLOAT64, 2, 1, "target_alpha");
    PyArrayObject *screens_array = require_array(objects[3], NPY_FLOAT64, 3, 0, "screen_triangles");
    PyArrayObject *bounds_array = require_array(objects[4], NPY_INT64, 2, 0, "bounds");
    PyArrayObject *denominators_array = require_array(objects[5], NPY_FLOAT64, 1, 0, "denominators");
    PyArrayObject *vertices_array = require_array(objects[6], NPY_FLOAT64, 3, 0, "world_vertices");
    PyArrayObject *normals_array = require_array(objects[7], NPY_FLOAT64, 3, 0, "vertex_normals");
    PyArrayObject *uv_array = require_array(objects[8], NPY_FLOAT64, 3, 0, "material_uv");
    PyArrayObject *albedo_texels_array = require_array(objects[9], NPY_FLOAT64, 2, 0, "albedo_texels");
    PyArrayObject *albedo_levels_array = require_array(objects[10], NPY_INT64, 2, 0, "albedo_levels");
    PyArrayObject *albedo_lower_array = require_array(objects[11], NPY_INT64, 1, 0, "albedo_lower_indices");
    PyArrayObject *albedo_upper_array = require_array(objects[12], NPY_INT64, 1, 0, "albedo_upper_indices");
    PyArrayObject *albedo_amount_array = require_array(objects[13], NPY_FLOAT64, 1, 0, "albedo_mip_amounts");
    PyArrayObject *skin_texels_array = require_array(objects[14], NPY_FLOAT64, 2, 0, "skin_texels");
    PyArrayObject *skin_levels_array = require_array(objects[15], NPY_INT64, 2, 0, "skin_levels");
    PyArrayObject *skin_lower_array = require_array(objects[16], NPY_INT64, 1, 0, "skin_lower_indices");
    PyArrayObject *skin_upper_array = require_array(objects[17], NPY_INT64, 1, 0, "skin_upper_indices");
    PyArrayObject *skin_amount_array = require_array(objects[18], NPY_FLOAT64, 1, 0, "skin_mip_amounts");
    PyArrayObject *normal_texels_array = require_array(objects[19], NPY_FLOAT64, 2, 0, "normal_texels");
    PyArrayObject *normal_levels_array = require_array(objects[20], NPY_INT64, 2, 0, "normal_levels");
    PyArrayObject *normal_indices_array = require_array(objects[21], NPY_INT64, 1, 0, "normal_level_indices");
    PyArrayObject *face_array = require_array(objects[22], NPY_FLOAT64, 1, 0, "face_color_linear");
    PyArrayObject *direction_array = require_array(objects[23], NPY_FLOAT64, 1, 0, "light_direction");
    PyArrayObject *light_array = require_array(objects[24], NPY_FLOAT64, 1, 0, "light_color");
    PyArrayObject *ambient_array = require_array(objects[25], NPY_FLOAT64, 1, 0, "ambient_color");
    if (color_array == NULL || depth_array == NULL ||
        (objects[2] != Py_None && alpha_array == NULL) || screens_array == NULL ||
        bounds_array == NULL || denominators_array == NULL || vertices_array == NULL ||
        normals_array == NULL || uv_array == NULL || albedo_texels_array == NULL ||
        albedo_levels_array == NULL || albedo_lower_array == NULL ||
        albedo_upper_array == NULL || albedo_amount_array == NULL ||
        skin_texels_array == NULL || skin_levels_array == NULL || skin_lower_array == NULL ||
        skin_upper_array == NULL || skin_amount_array == NULL || normal_texels_array == NULL ||
        normal_levels_array == NULL || normal_indices_array == NULL || face_array == NULL ||
        direction_array == NULL || light_array == NULL || ambient_array == NULL) return NULL;
    const double light_intensity = PyFloat_AsDouble(objects[26]);
    const double ambient_intensity = PyFloat_AsDouble(objects[27]);
    const long perspective = PyLong_AsLong(objects[28]);
    if (PyErr_Occurred()) return NULL;
    if (perspective != 1) {
        PyErr_SetString(PyExc_ValueError, "opaque body prototype requires perspective correction");
        return NULL;
    }
    npy_intp height, width;
    if (!attachment_shapes(color_array, depth_array, alpha_array, &height, &width) ||
        !triangle_metadata(screens_array, bounds_array, denominators_array, height, width) ||
        !valid_mip_bank(albedo_texels_array, albedo_levels_array, "albedo") ||
        !valid_mip_bank(skin_texels_array, skin_levels_array, "skin") ||
        !valid_mip_bank(normal_texels_array, normal_levels_array, "normal")) return NULL;
    const npy_intp count = PyArray_DIM(screens_array, 0);
#define BODY_TRI_SHAPE(array, d1, d2) \
    (PyArray_DIM((array), 0) == count && PyArray_DIM((array), 1) == (d1) && PyArray_DIM((array), 2) == (d2))
    if (!BODY_TRI_SHAPE(vertices_array, 3, 3) || !BODY_TRI_SHAPE(normals_array, 3, 3) ||
        !BODY_TRI_SHAPE(uv_array, 3, 2) || PyArray_DIM(albedo_lower_array, 0) != count ||
        PyArray_DIM(albedo_upper_array, 0) != count || PyArray_DIM(albedo_amount_array, 0) != count ||
        PyArray_DIM(skin_lower_array, 0) != count || PyArray_DIM(skin_upper_array, 0) != count ||
        PyArray_DIM(skin_amount_array, 0) != count || PyArray_DIM(normal_indices_array, 0) != count ||
        PyArray_DIM(face_array, 0) != 3 || PyArray_DIM(direction_array, 0) != 3 ||
        PyArray_DIM(light_array, 0) != 3 || PyArray_DIM(ambient_array, 0) != 3) {
        PyErr_SetString(PyExc_ValueError, "opaque body ABI shapes do not match");
        return NULL;
    }
#undef BODY_TRI_SHAPE
    const int64_t *albedo_levels = (const int64_t *)PyArray_DATA(albedo_levels_array);
    const int64_t *skin_levels = (const int64_t *)PyArray_DATA(skin_levels_array);
    const int64_t *normal_levels = (const int64_t *)PyArray_DATA(normal_levels_array);
    const int64_t *albedo_lower = (const int64_t *)PyArray_DATA(albedo_lower_array);
    const int64_t *albedo_upper = (const int64_t *)PyArray_DATA(albedo_upper_array);
    const int64_t *skin_lower = (const int64_t *)PyArray_DATA(skin_lower_array);
    const int64_t *skin_upper = (const int64_t *)PyArray_DATA(skin_upper_array);
    const int64_t *normal_indices = (const int64_t *)PyArray_DATA(normal_indices_array);
    const double *albedo_amounts = (const double *)PyArray_DATA(albedo_amount_array);
    const double *skin_amounts = (const double *)PyArray_DATA(skin_amount_array);
    const npy_intp albedo_level_count = PyArray_DIM(albedo_levels_array, 0);
    const npy_intp skin_level_count = PyArray_DIM(skin_levels_array, 0);
    const npy_intp normal_level_count = PyArray_DIM(normal_levels_array, 0);
    for (npy_intp triangle = 0; triangle < count; ++triangle) {
        if (albedo_lower[triangle] < 0 || albedo_lower[triangle] >= albedo_level_count ||
            albedo_upper[triangle] < 0 || albedo_upper[triangle] >= albedo_level_count ||
            skin_lower[triangle] < 0 || skin_lower[triangle] >= skin_level_count ||
            skin_upper[triangle] < 0 || skin_upper[triangle] >= skin_level_count ||
            normal_indices[triangle] < 0 || normal_indices[triangle] >= normal_level_count ||
            !isfinite(albedo_amounts[triangle]) || albedo_amounts[triangle] < 0.0 ||
            albedo_amounts[triangle] > 1.0 || !isfinite(skin_amounts[triangle]) ||
            skin_amounts[triangle] < 0.0 || skin_amounts[triangle] > 1.0) {
            PyErr_SetString(PyExc_ValueError, "opaque body mip selections are invalid");
            return NULL;
        }
    }

    double *color = (double *)PyArray_DATA(color_array);
    double *depth = (double *)PyArray_DATA(depth_array);
    double *target_alpha = alpha_array == NULL ? NULL : (double *)PyArray_DATA(alpha_array);
    const double *screens = (const double *)PyArray_DATA(screens_array);
    const int64_t *bounds = (const int64_t *)PyArray_DATA(bounds_array);
    const double *denominators = (const double *)PyArray_DATA(denominators_array);
    const double *vertices = (const double *)PyArray_DATA(vertices_array);
    const double *normals = (const double *)PyArray_DATA(normals_array);
    const double *uvs = (const double *)PyArray_DATA(uv_array);
    const double *albedo_texels = (const double *)PyArray_DATA(albedo_texels_array);
    const double *skin_texels = (const double *)PyArray_DATA(skin_texels_array);
    const double *normal_texels = (const double *)PyArray_DATA(normal_texels_array);
    const double *face = (const double *)PyArray_DATA(face_array);
    const double *direction = (const double *)PyArray_DATA(direction_array);
    const double *light_color = (const double *)PyArray_DATA(light_array);
    const double *ambient_color = (const double *)PyArray_DATA(ambient_array);
    double ambient[3], key[3], front[3];
    lighting_constants(direction, light_color, ambient_color, light_intensity, ambient_intensity, ambient, key, front);

    npy_intp written = 0;
    Py_BEGIN_ALLOW_THREADS
    for (npy_intp triangle = 0; triangle < count; ++triangle) {
        const double *screen = screens + triangle * 9;
        const double *triangle_vertices = vertices + triangle * 9;
        const double *triangle_normals = normals + triangle * 9;
        const double *triangle_uv = uvs + triangle * 6;
        const int x0 = (int)bounds[triangle * 4];
        const int x1 = (int)bounds[triangle * 4 + 1];
        const int y0 = (int)bounds[triangle * 4 + 2];
        const int y1 = (int)bounds[triangle * 4 + 3];

        double edge1[3], edge2[3];
        for (int component = 0; component < 3; ++component) {
            edge1[component] = triangle_vertices[3 + component] - triangle_vertices[component];
            edge2[component] = triangle_vertices[6 + component] - triangle_vertices[component];
        }
        double geometric_normal[3];
        cross3(edge1, edge2, geometric_normal);
        const double geometric_length = norm3(geometric_normal);
        if (geometric_length != 0.0) {
            for (int component = 0; component < 3; ++component) geometric_normal[component] /= geometric_length;
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
                    (edge1[component] * delta2_v - edge2[component] * delta1_v) / tangent_determinant;
                raw_bitangent[component] =
                    (-edge1[component] * delta2_u + edge2[component] * delta1_u) / tangent_determinant;
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
        const int64_t skin_lower_index = skin_lower[triangle];
        const int64_t skin_upper_index = skin_upper[triangle];
        const int64_t normal_index = normal_indices[triangle];
        const double *albedo_lower_texture = albedo_texels + albedo_levels[albedo_lower_index * 3] * 4;
        const double *albedo_upper_texture = albedo_texels + albedo_levels[albedo_upper_index * 3] * 4;
        const double *skin_lower_texture = skin_texels + skin_levels[skin_lower_index * 3] * 4;
        const double *skin_upper_texture = skin_texels + skin_levels[skin_upper_index * 3] * 4;
        const double *normal_texture = normal_texels + normal_levels[normal_index * 3] * 4;
        const npy_intp albedo_lower_height = (npy_intp)albedo_levels[albedo_lower_index * 3 + 1];
        const npy_intp albedo_lower_width = (npy_intp)albedo_levels[albedo_lower_index * 3 + 2];
        const npy_intp albedo_upper_height = (npy_intp)albedo_levels[albedo_upper_index * 3 + 1];
        const npy_intp albedo_upper_width = (npy_intp)albedo_levels[albedo_upper_index * 3 + 2];
        const npy_intp skin_lower_height = (npy_intp)skin_levels[skin_lower_index * 3 + 1];
        const npy_intp skin_lower_width = (npy_intp)skin_levels[skin_lower_index * 3 + 2];
        const npy_intp skin_upper_height = (npy_intp)skin_levels[skin_upper_index * 3 + 1];
        const npy_intp skin_upper_width = (npy_intp)skin_levels[skin_upper_index * 3 + 2];
        const npy_intp normal_height = (npy_intp)normal_levels[normal_index * 3 + 1];
        const npy_intp normal_width = (npy_intp)normal_levels[normal_index * 3 + 2];
        const double albedo_amount = albedo_amounts[triangle];
        const double skin_amount = skin_amounts[triangle];

        for (int y = y0; y <= y1; ++y) {
            for (int x = x0; x <= x1; ++x) {
                double affine0, affine1, affine2, z;
                if (!visible_lane(screen, depth, width, x, y, denominators[triangle],
                                  &affine0, &affine1, &affine2, &z)) continue;
                const double safe = fabs(z) < 1e-20 ? 1.0 : z;
                const double weight0 = affine0 * screen[2] / safe;
                const double weight1 = affine1 * screen[5] / safe;
                const double weight2 = affine2 * screen[8] / safe;
                const double u01 = weight0 * triangle_uv[0] + weight1 * triangle_uv[2];
                const double u = u01 + weight2 * triangle_uv[4];
                const double v01 = weight0 * triangle_uv[1] + weight1 * triangle_uv[3];
                const double v = v01 + weight2 * triangle_uv[5];
                double albedo_lower_sample[4], albedo_upper_sample[4];
                double skin_lower_sample[4], skin_upper_sample[4], normal_sample[4];
                sample_clamp_rgba(albedo_lower_texture, albedo_lower_height, albedo_lower_width, u, v, albedo_lower_sample);
                sample_clamp_rgba(albedo_upper_texture, albedo_upper_height, albedo_upper_width, u, v, albedo_upper_sample);
                sample_clamp_rgba(skin_lower_texture, skin_lower_height, skin_lower_width, u, v, skin_lower_sample);
                sample_clamp_rgba(skin_upper_texture, skin_upper_height, skin_upper_width, u, v, skin_upper_sample);
                sample_clamp_rgba(normal_texture, normal_height, normal_width, u, v, normal_sample);
                const double albedo_inverse = 1.0 - albedo_amount;
                const double skin_inverse = 1.0 - skin_amount;
                double source[3];
                const double skin_g = skin_lower_sample[1] * skin_inverse + skin_upper_sample[1] * skin_amount;
                for (int channel = 0; channel < 3; ++channel) {
                    const double albedo = albedo_lower_sample[channel] * albedo_inverse +
                        albedo_upper_sample[channel] * albedo_amount;
                    source[channel] = face[channel] + (albedo - face[channel]) * skin_g;
                }

                double shading_normal[3];
                for (int component = 0; component < 3; ++component) {
                    const double first_two = weight0 * triangle_normals[component] +
                        weight1 * triangle_normals[3 + component];
                    shading_normal[component] = first_two + weight2 * triangle_normals[6 + component];
                }
                double shading_length = norm3(shading_normal);
                if (shading_length == 0.0) shading_length = 1.0;
                for (int component = 0; component < 3; ++component) shading_normal[component] /= shading_length;

                double normal_x = normal_sample[0] * 2.0 - 1.0;
                double normal_y = normal_sample[1] * 2.0 - 1.0;
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
                shade_plain(source, shading_normal, direction, ambient, key, front);
                const npy_intp pixel = (npy_intp)y * width + x;
                color[pixel * 3] = source[0];
                color[pixel * 3 + 1] = source[1];
                color[pixel * 3 + 2] = source[2];
                if (target_alpha != NULL) target_alpha[pixel] = 1.0;
                depth[pixel] = z;
                ++written;
            }
        }
    }
    Py_END_ALLOW_THREADS
    return PyLong_FromLongLong((long long)written);
}

#if defined(_MSC_VER)
#pragma float_control(pop)
#endif
