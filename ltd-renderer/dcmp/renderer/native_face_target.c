#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <fenv.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#define NPY_NO_DEPRECATED_API NPY_1_7_API_VERSION
#include <numpy/arrayobject.h>

#include "native_face_target_build.h"

#if defined(_MSC_VER)
#pragma float_control(precise, on, push)
#pragma fp_contract(off)
#endif

/*
 * Minimal kernel for the two remaining fixed-size face targets. Scene
 * selection, evidence validation, LOD selection, affine construction and
 * shader routing deliberately remain in the audited Python implementation.
 * This file only replaces its dense per-pixel loops.
 */

static unsigned char store_unorm8(double value) {
    if (value <= 0.0) return 0;
    if (value >= 1.0) return 255;
    return (unsigned char)nearbyint(value * 255.0);
}

static int require_round_to_nearest(void) {
    if (fegetround() != FE_TONEAREST) {
        PyErr_SetString(
            PyExc_RuntimeError,
            "native face target requires round-to-nearest-even"
        );
        return 0;
    }
    return 1;
}

static int exact_array(
    PyObject *object,
    int type,
    int dimensions,
    const char *name,
    PyArrayObject **result
) {
    if (!PyArray_Check(object)) {
        PyErr_Format(PyExc_TypeError, "%s must be a NumPy array", name);
        return 0;
    }
    PyArrayObject *array = (PyArrayObject *)object;
    if (
        PyArray_TYPE(array) != type ||
        PyArray_NDIM(array) != dimensions ||
        !PyArray_IS_C_CONTIGUOUS(array) ||
        !PyArray_ISALIGNED(array)
    ) {
        PyErr_Format(
            PyExc_TypeError,
            "%s has the wrong dtype, rank, alignment, or contiguity",
            name
        );
        return 0;
    }
    Py_INCREF(array);
    *result = array;
    return 1;
}

static PyObject *mask_pipeline(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *layers_object = NULL;
    PyObject *cases_object = NULL;
    int width = 0;
    int height = 0;
    if (!PyArg_ParseTuple(
        args, "OOii:mask_pipeline", &layers_object, &cases_object, &width, &height
    )) return NULL;
    if (!require_round_to_nearest()) return NULL;
    if (width <= 0 || height <= 0 || width > 4096 || height > 4096) {
        PyErr_SetString(PyExc_ValueError, "mask target dimensions are invalid");
        return NULL;
    }

    PyObject *layers = PySequence_Fast(layers_object, "layers must be a sequence");
    PyObject *cases = PySequence_Fast(cases_object, "cases must be a sequence");
    if (layers == NULL || cases == NULL) {
        Py_XDECREF(layers);
        Py_XDECREF(cases);
        return NULL;
    }
    const Py_ssize_t count = PySequence_Fast_GET_SIZE(layers);
    if (count != PySequence_Fast_GET_SIZE(cases) || count > 21) {
        PyErr_SetString(PyExc_ValueError, "mask layer/case counts differ or exceed 21");
        goto fail_sequences;
    }

    PyArrayObject *source_arrays[21] = {0};
    int previous_case = -1;
    for (Py_ssize_t index = 0; index < count; ++index) {
        long dispatcher_case = PyLong_AsLong(PySequence_Fast_GET_ITEM(cases, index));
        if (dispatcher_case == -1 && PyErr_Occurred()) goto fail_sources;
        if (dispatcher_case <= previous_case || dispatcher_case > 20) {
            PyErr_SetString(
                PyExc_ValueError,
                "mask dispatcher cases must be unique, sorted, and inside 0..20"
            );
            goto fail_sources;
        }
        previous_case = (int)dispatcher_case;
        if (!exact_array(
            PySequence_Fast_GET_ITEM(layers, index),
            NPY_FLOAT64,
            3,
            "mask layer",
            &source_arrays[index]
        )) goto fail_sources;
        if (
            PyArray_DIM(source_arrays[index], 0) != height ||
            PyArray_DIM(source_arrays[index], 1) != width ||
            PyArray_DIM(source_arrays[index], 2) != 4
        ) {
            PyErr_SetString(PyExc_ValueError, "mask layer shape differs from target");
            goto fail_sources;
        }
    }

    npy_intp target_dims[3] = {height, width, 4};
    npy_intp audit_dims[4] = {count, height, width, 4};
    PyArrayObject *pass0 = (PyArrayObject *)PyArray_ZEROS(3, target_dims, NPY_UINT8, 0);
    PyArrayObject *case21 = (PyArrayObject *)PyArray_ZEROS(3, target_dims, NPY_UINT8, 0);
    PyArrayObject *final = (PyArrayObject *)PyArray_ZEROS(3, target_dims, NPY_UINT8, 0);
    PyArrayObject *mesh = (PyArrayObject *)PyArray_ZEROS(3, target_dims, NPY_UINT8, 0);
    PyArrayObject *pass0_audit = (PyArrayObject *)PyArray_ZEROS(4, audit_dims, NPY_UINT8, 0);
    PyArrayObject *pass1_audit = (PyArrayObject *)PyArray_ZEROS(4, audit_dims, NPY_UINT8, 0);
    if (
        pass0 == NULL || case21 == NULL || final == NULL || mesh == NULL ||
        pass0_audit == NULL || pass1_audit == NULL
    ) {
        Py_XDECREF(pass0); Py_XDECREF(case21); Py_XDECREF(final);
        Py_XDECREF(mesh); Py_XDECREF(pass0_audit); Py_XDECREF(pass1_audit);
        goto fail_sources;
    }

    const npy_intp pixel_count = (npy_intp)width * height;
    const size_t target_bytes = (size_t)pixel_count * 4;
    unsigned char *pass0_data = (unsigned char *)PyArray_DATA(pass0);
    unsigned char *case21_data = (unsigned char *)PyArray_DATA(case21);
    unsigned char *final_data = (unsigned char *)PyArray_DATA(final);
    unsigned char *mesh_data = (unsigned char *)PyArray_DATA(mesh);
    unsigned char *pass0_audit_data = (unsigned char *)PyArray_DATA(pass0_audit);
    unsigned char *pass1_audit_data = (unsigned char *)PyArray_DATA(pass1_audit);

    /* Pass 0: RGB ONE/ZERO, alpha ONE/ONE, store after every draw. */
    for (Py_ssize_t layer = 0; layer < count; ++layer) {
        const double *source = (const double *)PyArray_DATA(source_arrays[layer]);
        for (npy_intp pixel = 0; pixel < pixel_count; ++pixel) {
            const npy_intp offset = pixel * 4;
            const double r = source[offset + 0];
            const double g = source[offset + 1];
            const double b = source[offset + 2];
            const double a = source[offset + 3];
            if (!isfinite(r) || !isfinite(g) || !isfinite(b) || !isfinite(a)) {
                PyErr_SetString(PyExc_ValueError, "mask layer contains a non-finite value");
                goto fail_outputs;
            }
            if (a < 0.0 || a > 1.0) {
                PyErr_SetString(PyExc_ValueError, "mask shader alpha is outside UNORM");
                goto fail_outputs;
            }
            if (a != 0.0) {
                pass0_data[offset + 0] = store_unorm8(r);
                pass0_data[offset + 1] = store_unorm8(g);
                pass0_data[offset + 2] = store_unorm8(b);
                const double destination_alpha = (double)pass0_data[offset + 3] / 255.0;
                pass0_data[offset + 3] = store_unorm8(a + destination_alpha);
            }
        }
        memcpy(pass0_audit_data + (size_t)layer * target_bytes, pass0_data, target_bytes);
    }

    for (npy_intp pixel = 0; pixel < pixel_count; ++pixel) {
        case21_data[pixel * 4 + 3] = 255;
    }
    memcpy(final_data, case21_data, target_bytes);

    /* Pass 1: RGB ONE/ONE_MINUS_SRC_ALPHA, alpha ONE/ONE. */
    for (Py_ssize_t layer = 0; layer < count; ++layer) {
        const double *source = (const double *)PyArray_DATA(source_arrays[layer]);
        for (npy_intp pixel = 0; pixel < pixel_count; ++pixel) {
            const npy_intp offset = pixel * 4;
            const double a = source[offset + 3];
            if (a != 0.0) {
                const double inverse_alpha = 1.0 - a;
                const double destination_r = (double)final_data[offset + 0] / 255.0;
                const double destination_g = (double)final_data[offset + 1] / 255.0;
                const double destination_b = (double)final_data[offset + 2] / 255.0;
                const double destination_a = (double)final_data[offset + 3] / 255.0;
                final_data[offset + 0] = store_unorm8(source[offset + 0] + destination_r * inverse_alpha);
                final_data[offset + 1] = store_unorm8(source[offset + 1] + destination_g * inverse_alpha);
                final_data[offset + 2] = store_unorm8(source[offset + 2] + destination_b * inverse_alpha);
                final_data[offset + 3] = store_unorm8(a + destination_a);
            }
        }
        memcpy(pass1_audit_data + (size_t)layer * target_bytes, final_data, target_bytes);
    }

    memcpy(mesh_data, final_data, target_bytes);
    for (npy_intp pixel = 0; pixel < pixel_count; ++pixel) {
        const npy_intp offset = pixel * 4;
        mesh_data[offset + 3] = pass0_data[offset + 3];
        if (mesh_data[offset + 3] == 0) {
            mesh_data[offset + 0] = 0;
            mesh_data[offset + 1] = 0;
            mesh_data[offset + 2] = 0;
        }
    }

    for (Py_ssize_t index = 0; index < count; ++index) Py_DECREF(source_arrays[index]);
    Py_DECREF(layers);
    Py_DECREF(cases);
    return Py_BuildValue(
        "NNNNNN",
        pass0, case21, final, mesh, pass0_audit, pass1_audit
    );

fail_outputs:
    Py_DECREF(pass0); Py_DECREF(case21); Py_DECREF(final);
    Py_DECREF(mesh); Py_DECREF(pass0_audit); Py_DECREF(pass1_audit);
fail_sources:
    for (Py_ssize_t index = 0; index < count; ++index) Py_XDECREF(source_arrays[index]);
fail_sequences:
    Py_DECREF(layers);
    Py_DECREF(cases);
    return NULL;
}

static double sample_channel(
    const unsigned char *source,
    int width,
    int height,
    double u,
    double v,
    int channel
) {
    const double x = u * (double)width - 0.5;
    const double y = v * (double)height - 0.5;
    const int x0 = (int)floor(x);
    const int y0 = (int)floor(y);
    const double fraction_x = x - (double)x0;
    const double fraction_y = y - (double)y0;
    const int ax = x0 < 0 ? 0 : (x0 >= width ? width - 1 : x0);
    const int bx0 = x0 + 1;
    const int bx = bx0 < 0 ? 0 : (bx0 >= width ? width - 1 : bx0);
    const int ay = y0 < 0 ? 0 : (y0 >= height ? height - 1 : y0);
    const int by0 = y0 + 1;
    const int by = by0 < 0 ? 0 : (by0 >= height ? height - 1 : by0);
    const double one_minus_x = 1.0 - fraction_x;
    const double one_minus_y = 1.0 - fraction_y;
    const double a = (double)source[((npy_intp)ay * width + ax) * 4 + channel] / 255.0;
    const double b = (double)source[((npy_intp)ay * width + bx) * 4 + channel] / 255.0;
    const double c = (double)source[((npy_intp)by * width + ax) * 4 + channel] / 255.0;
    const double d = (double)source[((npy_intp)by * width + bx) * 4 + channel] / 255.0;
    return a * one_minus_x * one_minus_y
        + b * fraction_x * one_minus_y
        + c * one_minus_x * fraction_y
        + d * fraction_x * fraction_y;
}

static PyObject *faceline_wrinkle(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *source_object = NULL;
    PyObject *skin_object = NULL;
    double left, right, bottom, top;
    if (!PyArg_ParseTuple(
        args, "OOdddd:faceline_wrinkle", &source_object, &skin_object,
        &left, &right, &bottom, &top
    )) return NULL;
    if (!require_round_to_nearest()) return NULL;
    if (!(left < right) || !(bottom < top)) {
        PyErr_SetString(PyExc_ValueError, "faceline clip bounds are invalid");
        return NULL;
    }
    PyArrayObject *source = NULL;
    PyArrayObject *skin = NULL;
    if (!exact_array(source_object, NPY_UINT8, 3, "wrinkle source", &source)) return NULL;
    if (!exact_array(skin_object, NPY_UINT8, 1, "skin", &skin)) {
        Py_DECREF(source);
        return NULL;
    }
    if (
        PyArray_DIM(source, 0) < 1 || PyArray_DIM(source, 1) < 1 ||
        PyArray_DIM(source, 2) != 4 || PyArray_DIM(skin, 0) != 4
    ) {
        PyErr_SetString(PyExc_ValueError, "wrinkle source or skin shape is invalid");
        Py_DECREF(source); Py_DECREF(skin);
        return NULL;
    }
    const int source_height = (int)PyArray_DIM(source, 0);
    const int source_width = (int)PyArray_DIM(source, 1);
    const unsigned char *source_data = (const unsigned char *)PyArray_DATA(source);
    const unsigned char *skin_data = (const unsigned char *)PyArray_DATA(skin);
    npy_intp output_dims[3] = {256, 128, 4};
    PyArrayObject *output = (PyArrayObject *)PyArray_SimpleNew(3, output_dims, NPY_UINT8);
    if (output == NULL) {
        Py_DECREF(source); Py_DECREF(skin);
        return NULL;
    }
    unsigned char *output_data = (unsigned char *)PyArray_DATA(output);
    int count = 0, row_min = 256, row_max = -1, column_min = 128, column_max = -1;
    for (int y = 0; y < 256; ++y) {
        const double pixel_y = (double)y + 0.5;
        const double ndc_y = 1.0 - 2.0 * pixel_y / 256.0;
        const double v = (top - ndc_y) / (top - bottom);
        for (int x = 0; x < 128; ++x) {
            const npy_intp offset = ((npy_intp)y * 128 + x) * 4;
            output_data[offset + 0] = skin_data[0];
            output_data[offset + 1] = skin_data[1];
            output_data[offset + 2] = skin_data[2];
            output_data[offset + 3] = skin_data[3];
            const double pixel_x = (double)x + 0.5;
            const double ndc_x = 2.0 * pixel_x / 128.0 - 1.0;
            const double u = (ndc_x - left) / (right - left);
            if (u < 0.0 || u > 1.0 || v < 0.0 || v > 1.0) continue;
            const double alpha = sample_channel(
                source_data, source_width, source_height, u, v, 0
            );
            const double inverse_alpha = 1.0 - alpha;
            for (int channel = 0; channel < 3; ++channel) {
                const double destination = (double)skin_data[channel] / 255.0;
                output_data[offset + channel] = store_unorm8(destination * inverse_alpha);
            }
            const double destination_alpha = (double)skin_data[3] / 255.0;
            output_data[offset + 3] = store_unorm8(
                alpha + destination_alpha * inverse_alpha
            );
            ++count;
            if (y < row_min) row_min = y;
            if (y > row_max) row_max = y;
            if (x < column_min) column_min = x;
            if (x > column_max) column_max = x;
        }
    }
    Py_DECREF(source); Py_DECREF(skin);
    return Py_BuildValue(
        "N(ii)(ii)i", output, row_min, row_max, column_min, column_max, count
    );
}

static PyObject *faceline_johnny(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *source_object = NULL;
    PyObject *skin_object = NULL;
    PyObject *c1_object = NULL;
    PyObject *c2_object = NULL;
    if (!PyArg_ParseTuple(
        args, "OOOO:faceline_johnny", &source_object, &skin_object, &c1_object, &c2_object
    )) return NULL;
    if (!require_round_to_nearest()) return NULL;
    PyArrayObject *source = NULL, *skin = NULL, *c1 = NULL, *c2 = NULL;
    if (!exact_array(source_object, NPY_UINT8, 3, "Johnny source", &source)) return NULL;
    if (!exact_array(skin_object, NPY_UINT8, 1, "skin", &skin)) goto fail_johnny;
    if (!exact_array(c1_object, NPY_FLOAT64, 1, "C1", &c1)) goto fail_johnny;
    if (!exact_array(c2_object, NPY_FLOAT64, 1, "C2", &c2)) goto fail_johnny;
    if (
        PyArray_DIM(source, 0) != 512 || PyArray_DIM(source, 1) != 256 ||
        PyArray_DIM(source, 2) != 4 || PyArray_DIM(skin, 0) != 4 ||
        PyArray_DIM(c1, 0) != 4 || PyArray_DIM(c2, 0) != 4
    ) {
        PyErr_SetString(PyExc_ValueError, "Johnny kernel inputs differ from its exact ABI");
        goto fail_johnny;
    }
    const unsigned char *source_data = (const unsigned char *)PyArray_DATA(source);
    const unsigned char *skin_data = (const unsigned char *)PyArray_DATA(skin);
    const double *c1_data = (const double *)PyArray_DATA(c1);
    const double *c2_data = (const double *)PyArray_DATA(c2);
    for (int channel = 0; channel < 4; ++channel) {
        if (!isfinite(c1_data[channel]) || !isfinite(c2_data[channel])) {
            PyErr_SetString(PyExc_ValueError, "Johnny shader constants are non-finite");
            goto fail_johnny;
        }
    }
    npy_intp output_dims[3] = {256, 128, 4};
    PyArrayObject *output = (PyArrayObject *)PyArray_SimpleNew(3, output_dims, NPY_UINT8);
    if (output == NULL) goto fail_johnny;
    unsigned char *output_data = (unsigned char *)PyArray_DATA(output);
    for (int y = 0; y < 256; ++y) {
        for (int x = 0; x < 128; ++x) {
            double sample[4] = {0.0, 0.0, 0.0, 0.0};
            for (int sy = 0; sy < 2; ++sy) {
                for (int sx = 0; sx < 2; ++sx) {
                    const npy_intp source_offset = (
                        (npy_intp)(y * 2 + sy) * 256 + (x * 2 + sx)
                    ) * 4;
                    for (int channel = 0; channel < 4; ++channel) {
                        sample[channel] += (double)source_data[source_offset + channel];
                    }
                }
            }
            for (int channel = 0; channel < 4; ++channel) sample[channel] = sample[channel] / 4.0 / 255.0;
            double shaded[4];
            for (int channel = 0; channel < 4; ++channel) {
                const double rc1 = sample[0] * c1_data[channel];
                shaded[channel] = rc1 + sample[1] * (c2_data[channel] - rc1);
            }
            const double inverse_alpha = 1.0 - shaded[3];
            const npy_intp output_offset = ((npy_intp)y * 128 + x) * 4;
            for (int channel = 0; channel < 4; ++channel) {
                const double destination = (double)skin_data[channel] / 255.0;
                output_data[output_offset + channel] = store_unorm8(
                    shaded[channel] + destination * inverse_alpha
                );
            }
        }
    }
    Py_DECREF(source); Py_DECREF(skin); Py_DECREF(c1); Py_DECREF(c2);
    return (PyObject *)output;

fail_johnny:
    Py_XDECREF(source); Py_XDECREF(skin); Py_XDECREF(c1); Py_XDECREF(c2);
    return NULL;
}

static double source_float_plane_value(
    const unsigned char *source,
    int width,
    int x,
    int y,
    int channel,
    int mirrored
) {
    const int source_x = mirrored ? width - 1 - x : x;
    const unsigned char value = source[((npy_intp)y * width + source_x) * 4 + channel];
    /* compose_face_texture explicitly creates float32 planes before Pillow. */
    const float normalized = (float)value / 255.0f;
    return (double)normalized;
}

static double source_byte_value(
    const unsigned char *source,
    int width,
    int x,
    int y,
    int channel,
    int mirrored
) {
    const int source_x = mirrored ? width - 1 - x : x;
    return (double)source[((npy_intp)y * width + source_x) * 4 + channel];
}

static PyObject *mask_sample_affine(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *source_object = NULL;
    int output_width, output_height, mirrored, float_planes;
    double a0, a1, a2, a3, a4, a5;
    if (!PyArg_ParseTuple(
        args,
        "Oiiddddddii:mask_sample_affine",
        &source_object,
        &output_width,
        &output_height,
        &a0, &a1, &a2, &a3, &a4, &a5,
        &mirrored,
        &float_planes
    )) return NULL;
    if (
        output_width <= 0 || output_height <= 0 ||
        output_width > 4096 || output_height > 4096 ||
        (mirrored != 0 && mirrored != 1) ||
        (float_planes != 0 && float_planes != 1)
    ) {
        PyErr_SetString(PyExc_ValueError, "affine sampler arguments are invalid");
        return NULL;
    }
    PyArrayObject *source = NULL;
    if (!exact_array(source_object, NPY_UINT8, 3, "affine source", &source)) return NULL;
    if (
        PyArray_DIM(source, 0) < 1 || PyArray_DIM(source, 1) < 1 ||
        PyArray_DIM(source, 2) != 4 ||
        PyArray_DIM(source, 0) > INT32_MAX || PyArray_DIM(source, 1) > INT32_MAX
    ) {
        PyErr_SetString(PyExc_ValueError, "affine source shape is invalid");
        Py_DECREF(source);
        return NULL;
    }
    const int source_height = (int)PyArray_DIM(source, 0);
    const int source_width = (int)PyArray_DIM(source, 1);
    const unsigned char *source_data = (const unsigned char *)PyArray_DATA(source);
    npy_intp output_dims[3] = {output_height, output_width, 4};
    PyArrayObject *output = (PyArrayObject *)PyArray_ZEROS(3, output_dims, NPY_FLOAT64, 0);
    if (output == NULL) {
        Py_DECREF(source);
        return NULL;
    }
    double *output_data = (double *)PyArray_DATA(output);
    for (int y = 0; y < output_height; ++y) {
        const double destination_y = (double)y + 0.5;
        for (int x = 0; x < output_width; ++x) {
            const double destination_x = (double)x + 0.5;
            /* Exact expression order from Pillow 12.2.0 affine_transform. */
            double source_x = a0 * destination_x + a1 * destination_y + a2;
            double source_y = a3 * destination_x + a4 * destination_y + a5;
            if (
                source_x < 0.0 || source_x >= (double)source_width ||
                source_y < 0.0 || source_y >= (double)source_height
            ) continue;
            source_x -= 0.5;
            source_y -= 0.5;
            const int x0 = source_x < 0.0 ? (int)floor(source_x) : (int)source_x;
            const int y0 = source_y < 0.0 ? (int)floor(source_y) : (int)source_y;
            const double dx = source_x - (double)x0;
            const double dy = source_y - (double)y0;
            const int xa = x0 < 0 ? 0 : (x0 < source_width ? x0 : source_width - 1);
            const int xb0 = x0 + 1;
            const int xb = xb0 < 0 ? 0 : (xb0 < source_width ? xb0 : source_width - 1);
            const int ya = y0 < 0 ? 0 : (y0 < source_height ? y0 : source_height - 1);
            const int yb0 = y0 + 1;
            const int yb = yb0 < 0 ? 0 : (yb0 < source_height ? yb0 : source_height - 1);
            const npy_intp output_offset = ((npy_intp)y * output_width + x) * 4;
            for (int channel = 0; channel < 4; ++channel) {
                double top_left, top_right, bottom_left, bottom_right;
                if (float_planes) {
                    top_left = source_float_plane_value(source_data, source_width, xa, ya, channel, mirrored);
                    top_right = source_float_plane_value(source_data, source_width, xb, ya, channel, mirrored);
                    bottom_left = source_float_plane_value(source_data, source_width, xa, yb, channel, mirrored);
                    bottom_right = source_float_plane_value(source_data, source_width, xb, yb, channel, mirrored);
                } else {
                    top_left = source_byte_value(source_data, source_width, xa, ya, channel, mirrored);
                    top_right = source_byte_value(source_data, source_width, xb, ya, channel, mirrored);
                    bottom_left = source_byte_value(source_data, source_width, xa, yb, channel, mirrored);
                    bottom_right = source_byte_value(source_data, source_width, xb, yb, channel, mirrored);
                }
                double value_top = top_left + (top_right - top_left) * dx;
                double value_bottom = bottom_left + (bottom_right - bottom_left) * dx;
                double value = value_top + (value_bottom - value_top) * dy;
                if (float_planes) {
                    /* Pillow's bilinear_filter32F stores through FLOAT32. */
                    const float stored = (float)value;
                    output_data[output_offset + channel] = (double)stored;
                } else {
                    /* Pillow's UINT8 bilinear path truncates instead of rounding. */
                    const unsigned char stored = (unsigned char)value;
                    output_data[output_offset + channel] = (double)stored / 255.0;
                }
            }
        }
    }
    Py_DECREF(source);
    return (PyObject *)output;
}

static void pillow_float_sample_pixel(
    const unsigned char *source,
    int source_width,
    int source_height,
    double source_x,
    double source_y,
    int mirrored,
    double sample[4]
) {
    for (int channel = 0; channel < 4; ++channel) sample[channel] = 0.0;
    if (
        source_x < 0.0 || source_x >= (double)source_width ||
        source_y < 0.0 || source_y >= (double)source_height
    ) return;
    source_x -= 0.5;
    source_y -= 0.5;
    const int x0 = source_x < 0.0 ? (int)floor(source_x) : (int)source_x;
    const int y0 = source_y < 0.0 ? (int)floor(source_y) : (int)source_y;
    const double dx = source_x - (double)x0;
    const double dy = source_y - (double)y0;
    const int xa = x0 < 0 ? 0 : (x0 < source_width ? x0 : source_width - 1);
    const int xb0 = x0 + 1;
    const int xb = xb0 < 0 ? 0 : (xb0 < source_width ? xb0 : source_width - 1);
    const int ya = y0 < 0 ? 0 : (y0 < source_height ? y0 : source_height - 1);
    const int yb0 = y0 + 1;
    const int yb = yb0 < 0 ? 0 : (yb0 < source_height ? yb0 : source_height - 1);
    for (int channel = 0; channel < 4; ++channel) {
        const double top_left = source_float_plane_value(
            source, source_width, xa, ya, channel, mirrored
        );
        const double top_right = source_float_plane_value(
            source, source_width, xb, ya, channel, mirrored
        );
        const double bottom_left = source_float_plane_value(
            source, source_width, xa, yb, channel, mirrored
        );
        const double bottom_right = source_float_plane_value(
            source, source_width, xb, yb, channel, mirrored
        );
        double value_top = top_left + (top_right - top_left) * dx;
        double value_bottom = bottom_left + (bottom_right - bottom_left) * dx;
        const double value = value_top + (value_bottom - value_top) * dy;
        const float stored = (float)value;
        sample[channel] = (double)stored;
    }
}

static PyObject *mask_sample_shade_affine(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *source_object = NULL, *c1_object = NULL, *c2_object = NULL;
    int output_width, output_height, mirrored, shader_kind;
    double a0, a1, a2, a3, a4, a5;
    if (!PyArg_ParseTuple(
        args,
        "OiiddddddiiOO:mask_sample_shade_affine",
        &source_object,
        &output_width,
        &output_height,
        &a0, &a1, &a2, &a3, &a4, &a5,
        &mirrored,
        &shader_kind,
        &c1_object,
        &c2_object
    )) return NULL;
    if (
        output_width <= 0 || output_height <= 0 ||
        output_width > 4096 || output_height > 4096 ||
        (mirrored != 0 && mirrored != 1) ||
        shader_kind < 1 || shader_kind > 5
    ) {
        PyErr_SetString(PyExc_ValueError, "affine shader arguments are invalid");
        return NULL;
    }
    PyArrayObject *source = NULL, *c1 = NULL, *c2 = NULL;
    if (!exact_array(source_object, NPY_UINT8, 3, "affine source", &source)) return NULL;
    if (!exact_array(c1_object, NPY_FLOAT64, 1, "shader C1", &c1)) goto fail_shade;
    if (!exact_array(c2_object, NPY_FLOAT64, 1, "shader C2", &c2)) goto fail_shade;
    if (
        PyArray_DIM(source, 0) < 1 || PyArray_DIM(source, 1) < 1 ||
        PyArray_DIM(source, 2) != 4 || PyArray_DIM(c1, 0) != 3 ||
        PyArray_DIM(c2, 0) != 3 ||
        PyArray_DIM(source, 0) > INT32_MAX || PyArray_DIM(source, 1) > INT32_MAX
    ) {
        PyErr_SetString(PyExc_ValueError, "affine shader input shape is invalid");
        goto fail_shade;
    }
    const int source_height = (int)PyArray_DIM(source, 0);
    const int source_width = (int)PyArray_DIM(source, 1);
    const unsigned char *source_data = (const unsigned char *)PyArray_DATA(source);
    const double *c1_data = (const double *)PyArray_DATA(c1);
    const double *c2_data = (const double *)PyArray_DATA(c2);
    for (int channel = 0; channel < 3; ++channel) {
        if (!isfinite(c1_data[channel]) || !isfinite(c2_data[channel])) {
            PyErr_SetString(PyExc_ValueError, "affine shader constant is non-finite");
            goto fail_shade;
        }
    }
    npy_intp output_dims[3] = {output_height, output_width, 4};
    PyArrayObject *output = (PyArrayObject *)PyArray_SimpleNew(3, output_dims, NPY_FLOAT64);
    if (output == NULL) goto fail_shade;
    double *output_data = (double *)PyArray_DATA(output);
    for (int y = 0; y < output_height; ++y) {
        const double destination_y = (double)y + 0.5;
        for (int x = 0; x < output_width; ++x) {
            const double destination_x = (double)x + 0.5;
            const double source_x = a0 * destination_x + a1 * destination_y + a2;
            const double source_y = a3 * destination_x + a4 * destination_y + a5;
            double sample[4];
            pillow_float_sample_pixel(
                source_data,
                source_width,
                source_height,
                source_x,
                source_y,
                mirrored,
                sample
            );
            const npy_intp offset = ((npy_intp)y * output_width + x) * 4;
            if (shader_kind == 1) { /* mode 3: constant RGB, sampled R alpha */
                output_data[offset + 0] = c1_data[0];
                output_data[offset + 1] = c1_data[1];
                output_data[offset + 2] = c1_data[2];
                output_data[offset + 3] = sample[0];
            } else if (shader_kind == 2) { /* mouth mode 2 */
                const double red_green = sample[0] + sample[1];
                for (int channel = 0; channel < 3; ++channel) {
                    output_data[offset + channel] = red_green * c1_data[channel] + sample[2];
                }
                output_data[offset + 3] = sample[3];
            } else if (shader_kind == 3) { /* eye mode 2 */
                for (int channel = 0; channel < 3; ++channel) {
                    output_data[offset + channel] = (
                        sample[0] * c1_data[channel] + sample[1]
                    ) + sample[2] * c2_data[channel];
                }
                output_data[offset + 3] = sample[3];
            } else if (shader_kind == 4) { /* eye mode 7 */
                for (int channel = 0; channel < 3; ++channel) {
                    output_data[offset + channel] = sample[1] + sample[2] * c1_data[channel];
                }
                double alpha = sample[3] - sample[0];
                if (alpha < 0.0) alpha = 0.0;
                if (alpha > 1.0) alpha = 1.0;
                output_data[offset + 3] = alpha;
            } else { /* mode 8 */
                output_data[offset + 0] = sample[2];
                output_data[offset + 1] = sample[2];
                output_data[offset + 2] = sample[2];
                double alpha = (sample[3] - sample[0]) - sample[1];
                if (alpha < 0.0) alpha = 0.0;
                if (alpha > 1.0) alpha = 1.0;
                output_data[offset + 3] = alpha;
            }
        }
    }
    Py_DECREF(source); Py_DECREF(c1); Py_DECREF(c2);
    return (PyObject *)output;

fail_shade:
    Py_XDECREF(source); Py_XDECREF(c1); Py_XDECREF(c2);
    return NULL;
}

static PyMethodDef methods[] = {
    {"mask_sample_affine", mask_sample_affine, METH_VARARGS, "Execute Pillow-compatible MiiMask affine sampling."},
    {"mask_sample_shade_affine", mask_sample_shade_affine, METH_VARARGS, "Execute exact production MiiMask affine sampling and shader modes."},
    {"mask_pipeline", mask_pipeline, METH_VARARGS, "Execute exact MiiMask blend/store passes."},
    {"faceline_wrinkle", faceline_wrinkle, METH_VARARGS, "Execute exact Noir wrinkle target pixels."},
    {"faceline_johnny", faceline_johnny, METH_VARARGS, "Execute exact Johnny faceline target pixels."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "_native_face_target",
    "Source-sealed exact-current-output native face target.",
    -1,
    methods
};

PyMODINIT_FUNC PyInit__native_face_target(void) {
    import_array();
    PyObject *result = PyModule_Create(&module);
    if (result == NULL) return NULL;
    if (
        PyModule_AddIntConstant(result, "ABI_VERSION", LTD_NATIVE_FACE_TARGET_ABI_VERSION) < 0 ||
        PyModule_AddStringConstant(result, "SOURCE_SHA256", LTD_NATIVE_FACE_TARGET_SOURCE_SHA256) < 0
    ) {
        Py_DECREF(result);
        return NULL;
    }
    return result;
}

#if defined(_MSC_VER)
#pragma float_control(pop)
#endif
