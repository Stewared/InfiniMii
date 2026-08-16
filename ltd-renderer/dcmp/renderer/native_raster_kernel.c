#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <math.h>

#define NPY_NO_DEPRECATED_API NPY_1_7_API_VERSION
#include <numpy/arrayobject.h>

#include "native_raster_kernel_build.h"

#if defined(_MSC_VER)
#pragma float_control(precise, on, push)
#pragma fp_contract(off)
#endif

/*
 * Exact scalar port of the coverage/early-depth prefix in
 * OrthographicRasterizer._draw_triangle.  This intentionally keeps the same
 * double-precision expression order as NumPy.  It does not approximate,
 * quantize, tile, or change the renderer's depth convention.
 */
static int lane_visible(
    const double *screen,
    const double *depth,
    npy_intp depth_width,
    int x0,
    int y0,
    int local_x,
    int local_y,
    double denominator,
    double *weight0_out,
    double *weight1_out,
    double *weight2_out,
    double *z_out
) {
    const double x = (double)(x0 + local_x) + 0.5;
    const double y = (double)(y0 + local_y) + 0.5;

    const double edge0_left = (x - screen[3]) * (screen[7] - screen[4]);
    const double edge0_right = (y - screen[4]) * (screen[6] - screen[3]);
    const double weight0 = (edge0_left - edge0_right) / denominator;

    const double edge1_left = (x - screen[6]) * (screen[1] - screen[7]);
    const double edge1_right = (y - screen[7]) * (screen[0] - screen[6]);
    const double weight1 = (edge1_left - edge1_right) / denominator;
    const double weight2 = (1.0 - weight0) - weight1;

    if (weight0 < -1e-7 || weight1 < -1e-7 || weight2 < -1e-7) {
        return 0;
    }

    const double z01 = weight0 * screen[2] + weight1 * screen[5];
    const double z = z01 + weight2 * screen[8];
    if (z < depth[(npy_intp)(y0 + local_y) * depth_width + (x0 + local_x)]) {
        return 0;
    }

    *weight0_out = weight0;
    *weight1_out = weight1;
    *weight2_out = weight2;
    *z_out = z;
    return 1;
}

static PyObject *coverage_fragments(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *screen_object = NULL;
    PyObject *depth_object = NULL;
    int x0, x1, y0, y1;
    double denominator;
    if (!PyArg_ParseTuple(
            args,
            "OOiiiid:coverage_fragments",
            &screen_object,
            &depth_object,
            &x0,
            &x1,
            &y0,
            &y1,
            &denominator)) {
        return NULL;
    }

    PyArrayObject *screen_array = (PyArrayObject *)PyArray_FROM_OTF(
        screen_object, NPY_FLOAT64, NPY_ARRAY_IN_ARRAY
    );
    if (screen_array == NULL) {
        return NULL;
    }
    PyArrayObject *depth_array = (PyArrayObject *)PyArray_FROM_OTF(
        depth_object, NPY_FLOAT64, NPY_ARRAY_IN_ARRAY
    );
    if (depth_array == NULL) {
        Py_DECREF(screen_array);
        return NULL;
    }

    if (PyArray_NDIM(screen_array) != 2 ||
        PyArray_DIM(screen_array, 0) != 3 ||
        PyArray_DIM(screen_array, 1) != 3) {
        PyErr_SetString(PyExc_ValueError, "screen must have shape (3, 3)");
        goto fail;
    }
    if (PyArray_NDIM(depth_array) != 2) {
        PyErr_SetString(PyExc_ValueError, "depth must be a two-dimensional float64 array");
        goto fail;
    }
    const npy_intp depth_height = PyArray_DIM(depth_array, 0);
    const npy_intp depth_width = PyArray_DIM(depth_array, 1);
    if (x0 < 0 || y0 < 0 || x1 < x0 || y1 < y0 ||
        x1 >= depth_width || y1 >= depth_height) {
        PyErr_SetString(PyExc_ValueError, "coverage bounds fall outside the depth buffer");
        goto fail;
    }

    const double *screen = (const double *)PyArray_DATA(screen_array);
    const double *depth = (const double *)PyArray_DATA(depth_array);
    const int local_width = x1 - x0 + 1;
    const int local_height = y1 - y0 + 1;
    npy_intp count = 0;
    double scratch0, scratch1, scratch2, scratch_z;
    for (int local_y = 0; local_y < local_height; ++local_y) {
        for (int local_x = 0; local_x < local_width; ++local_x) {
            count += lane_visible(
                screen, depth, depth_width, x0, y0, local_x, local_y,
                denominator, &scratch0, &scratch1, &scratch2, &scratch_z
            );
        }
    }

    if (count == 0) {
        Py_DECREF(screen_array);
        Py_DECREF(depth_array);
        Py_RETURN_NONE;
    }

    npy_intp coordinate_dims[1] = {count};
    npy_intp value_dims[2] = {1, count};
    PyArrayObject *fragment_y = (PyArrayObject *)PyArray_SimpleNew(1, coordinate_dims, NPY_INTP);
    PyArrayObject *fragment_x = (PyArrayObject *)PyArray_SimpleNew(1, coordinate_dims, NPY_INTP);
    PyArrayObject *weight0_array = (PyArrayObject *)PyArray_SimpleNew(2, value_dims, NPY_FLOAT64);
    PyArrayObject *weight1_array = (PyArrayObject *)PyArray_SimpleNew(2, value_dims, NPY_FLOAT64);
    PyArrayObject *weight2_array = (PyArrayObject *)PyArray_SimpleNew(2, value_dims, NPY_FLOAT64);
    PyArrayObject *z_array = (PyArrayObject *)PyArray_SimpleNew(2, value_dims, NPY_FLOAT64);
    if (fragment_y == NULL || fragment_x == NULL || weight0_array == NULL ||
        weight1_array == NULL || weight2_array == NULL || z_array == NULL) {
        Py_XDECREF(fragment_y);
        Py_XDECREF(fragment_x);
        Py_XDECREF(weight0_array);
        Py_XDECREF(weight1_array);
        Py_XDECREF(weight2_array);
        Py_XDECREF(z_array);
        goto fail;
    }

    npy_intp *fragment_y_data = (npy_intp *)PyArray_DATA(fragment_y);
    npy_intp *fragment_x_data = (npy_intp *)PyArray_DATA(fragment_x);
    double *weight0_data = (double *)PyArray_DATA(weight0_array);
    double *weight1_data = (double *)PyArray_DATA(weight1_array);
    double *weight2_data = (double *)PyArray_DATA(weight2_array);
    double *z_data = (double *)PyArray_DATA(z_array);
    npy_intp output_index = 0;
    for (int local_y = 0; local_y < local_height; ++local_y) {
        for (int local_x = 0; local_x < local_width; ++local_x) {
            double weight0, weight1, weight2, z;
            if (!lane_visible(
                    screen, depth, depth_width, x0, y0, local_x, local_y,
                    denominator, &weight0, &weight1, &weight2, &z)) {
                continue;
            }
            fragment_y_data[output_index] = local_y;
            fragment_x_data[output_index] = local_x;
            weight0_data[output_index] = weight0;
            weight1_data[output_index] = weight1;
            weight2_data[output_index] = weight2;
            z_data[output_index] = z;
            ++output_index;
        }
    }

    Py_DECREF(screen_array);
    Py_DECREF(depth_array);
    return Py_BuildValue(
        "NNNNNN",
        fragment_y,
        fragment_x,
        weight0_array,
        weight1_array,
        weight2_array,
        z_array
    );

fail:
    Py_DECREF(screen_array);
    Py_DECREF(depth_array);
    return NULL;
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

static PyObject *sample_bilinear(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *source_object = NULL;
    PyObject *u_object = NULL;
    PyObject *v_object = NULL;
    int x_offset, y_offset, wrap_x, wrap_y;
    if (!PyArg_ParseTuple(
            args,
            "OOOiiii:sample_bilinear",
            &source_object,
            &u_object,
            &v_object,
            &x_offset,
            &y_offset,
            &wrap_x,
            &wrap_y)) {
        return NULL;
    }
    if (wrap_x < 0 || wrap_x > 2 || wrap_y < 0 || wrap_y > 2) {
        PyErr_SetString(PyExc_ValueError, "wrap modes must be clamp=0, repeat=1, or mirror=2");
        return NULL;
    }

    PyArrayObject *source_array = (PyArrayObject *)PyArray_FROM_OTF(
        source_object, NPY_FLOAT64, NPY_ARRAY_IN_ARRAY
    );
    PyArrayObject *u_array = (PyArrayObject *)PyArray_FROM_OTF(
        u_object, NPY_FLOAT64, NPY_ARRAY_IN_ARRAY
    );
    PyArrayObject *v_array = (PyArrayObject *)PyArray_FROM_OTF(
        v_object, NPY_FLOAT64, NPY_ARRAY_IN_ARRAY
    );
    if (source_array == NULL || u_array == NULL || v_array == NULL) {
        Py_XDECREF(source_array);
        Py_XDECREF(u_array);
        Py_XDECREF(v_array);
        return NULL;
    }
    if (PyArray_NDIM(source_array) != 3 ||
        PyArray_DIM(source_array, 0) <= 0 ||
        PyArray_DIM(source_array, 1) <= 0 ||
        PyArray_DIM(source_array, 2) <= 0) {
        PyErr_SetString(PyExc_ValueError, "source must have nonempty shape (height, width, channels)");
        goto sample_fail;
    }
    if (PyArray_NDIM(u_array) != PyArray_NDIM(v_array)) {
        PyErr_SetString(PyExc_ValueError, "u and v coordinates must have identical shapes");
        goto sample_fail;
    }
    for (int dimension = 0; dimension < PyArray_NDIM(u_array); ++dimension) {
        if (PyArray_DIM(u_array, dimension) != PyArray_DIM(v_array, dimension)) {
            PyErr_SetString(PyExc_ValueError, "u and v coordinates must have identical shapes");
            goto sample_fail;
        }
    }
    if (PyArray_NDIM(u_array) + 1 > NPY_MAXDIMS) {
        PyErr_SetString(PyExc_ValueError, "coordinate rank is too large");
        goto sample_fail;
    }

    npy_intp output_dims[NPY_MAXDIMS];
    const int coordinate_ndim = PyArray_NDIM(u_array);
    for (int dimension = 0; dimension < coordinate_ndim; ++dimension) {
        output_dims[dimension] = PyArray_DIM(u_array, dimension);
    }
    const npy_intp channels = PyArray_DIM(source_array, 2);
    output_dims[coordinate_ndim] = channels;
    PyArrayObject *result_array = (PyArrayObject *)PyArray_SimpleNew(
        coordinate_ndim + 1, output_dims, NPY_FLOAT64
    );
    if (result_array == NULL) {
        goto sample_fail;
    }

    const npy_intp height = PyArray_DIM(source_array, 0);
    const npy_intp width = PyArray_DIM(source_array, 1);
    const npy_intp coordinate_count = PyArray_SIZE(u_array);
    const double *source = (const double *)PyArray_DATA(source_array);
    const double *u = (const double *)PyArray_DATA(u_array);
    const double *v = (const double *)PyArray_DATA(v_array);
    double *result = (double *)PyArray_DATA(result_array);
    for (npy_intp lane = 0; lane < coordinate_count; ++lane) {
        const double tex_x = ((u[lane] * (double)width) - 0.5) + (double)x_offset;
        const double tex_y = (((1.0 - v[lane]) * (double)height) - 0.5) + (double)y_offset;
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
        for (npy_intp channel = 0; channel < channels; ++channel) {
            const double top =
                source[(y0 * width + x0) * channels + channel] * inverse_x +
                source[(y0 * width + x1) * channels + channel] * x_amount;
            const double bottom =
                source[(y1 * width + x0) * channels + channel] * inverse_x +
                source[(y1 * width + x1) * channels + channel] * x_amount;
            result[lane * channels + channel] = top * inverse_y + bottom * y_amount;
        }
    }

    Py_DECREF(source_array);
    Py_DECREF(u_array);
    Py_DECREF(v_array);
    return (PyObject *)result_array;

sample_fail:
    Py_DECREF(source_array);
    Py_DECREF(u_array);
    Py_DECREF(v_array);
    return NULL;
}

static PyMethodDef module_methods[] = {
    {
        "coverage_fragments",
        coverage_fragments,
        METH_VARARGS,
        "Return exact covered, early-depth-visible fragment coordinates and barycentrics."
    },
    {
        "sample_bilinear",
        sample_bilinear,
        METH_VARARGS,
        "Sample one float64 texture level with the renderer's exact bilinear/wrap rules."
    },
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module_definition = {
    PyModuleDef_HEAD_INIT,
    "_native_raster_kernel",
    "Minimal exact-output compiled raster coverage kernel.",
    -1,
    module_methods
};

PyMODINIT_FUNC PyInit__native_raster_kernel(void) {
    import_array();
    PyObject *module = PyModule_Create(&module_definition);
    if (module == NULL) {
        return NULL;
    }
    if (PyModule_AddIntConstant(
            module, "ABI_VERSION", LTD_NATIVE_RASTER_KERNEL_ABI_VERSION) < 0 ||
        PyModule_AddStringConstant(
            module, "SOURCE_SHA256", LTD_NATIVE_RASTER_KERNEL_SOURCE_SHA256) < 0 ||
        PyModule_AddIntConstant(module, "NUMPY_ABI_VERSION", NPY_VERSION) < 0) {
        Py_DECREF(module);
        return NULL;
    }
    return module;
}

#if defined(_MSC_VER)
#pragma float_control(pop)
#endif
