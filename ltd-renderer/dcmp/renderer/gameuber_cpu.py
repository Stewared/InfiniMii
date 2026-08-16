"""Portable local equations recovered from active Kestron GameUber programs.

The functions in this module stop at boundaries visible in the shader binaries.
They do not invent the missing ``gsys_environment``/``gsys_context`` light
records or claim to reproduce final title radiance.  Inputs may be one vector or
NumPy arrays whose final axis is the vector component axis.

Only functions prefixed with ``proxy_`` add a conventional single key light.
That namespace distinction is intentional: proxy output is useful for the CPU
renderer, but is not an exact GameUber final-lighting equation.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from numpy.typing import ArrayLike, NDArray


FloatArray = NDArray[np.float64]
INV_FOUR_PI = np.float64(0.0795774683356285)


@dataclass(frozen=True)
class GameAllProgramIdentity:
    """Audited GameAll program family and its locally executable scope.

    This record deliberately says nothing about final radiance.  Every listed
    program still requires title-owned context/environment buffers and
    prepasses for complete fragment execution.  The booleans below authorize
    only the isolated equations recovered from the selected instruction
    streams; the portable rasterizer uses them to reject cross-program shader
    effects instead of silently applying one generic material model.
    """

    family: str
    program_index: int
    local_base_scope: str
    cheap_sss_local_curve: bool = False
    anisotropic_local_kernel: bool = False
    front_edge_local_gate: bool = False
    receives_screen_space_face_shadow: bool = False
    literal_title_final_coverage: bool = True


@dataclass(frozen=True)
class ScreenSpaceFaceShadowParameters:
    """Exact title parameters for the unavailable Mii face-shadow passes.

    The values identify ``ScreenSpaceFaceShadowMap``/``FaceShadowMap`` state;
    they are not sufficient to synthesize either buffer.  In particular, no
    world-space depth-map algorithm, bias, or PCF kernel is implied here.
    """

    enable: bool
    fade: bool
    depth_offset: float
    scale_y: float
    search_length: float
    softness: float
    fade_start: float
    fade_end: float


SCREEN_SPACE_FACE_SHADOW_PARAMETERS = ScreenSpaceFaceShadowParameters(
    enable=True,
    fade=True,
    depth_offset=0.0001,
    scale_y=0.3,
    search_length=0.03,
    softness=0.1,
    fade_start=20.0,
    fade_end=30.0,
)


def _identity(
    family: str,
    program_index: int,
    local_base_scope: str,
    *,
    cheap_sss_local_curve: bool = False,
    anisotropic_local_kernel: bool = False,
    front_edge_local_gate: bool = False,
    receives_screen_space_face_shadow: bool = False,
    literal_title_final_coverage: bool = True,
) -> GameAllProgramIdentity:
    return GameAllProgramIdentity(
        family=family,
        program_index=program_index,
        local_base_scope=local_base_scope,
        cheap_sss_local_curve=cheap_sss_local_curve,
        anisotropic_local_kernel=anisotropic_local_kernel,
        front_edge_local_gate=front_edge_local_gate,
        receives_screen_space_face_shadow=receives_screen_space_face_shadow,
        literal_title_final_coverage=literal_title_final_coverage,
    )


# Program/family pairs admitted here are backed by selected instruction hashes
# and the semantic ledgers.  A compatible resolver index alone is not enough.
_GAMEALL_PROGRAM_IDENTITIES = {
    ("head", 816): _identity(
        "head",
        816,
        "Head816 generated-faceline _a0 base and RA normal reconstruction",
        cheap_sss_local_curve=True,
        front_edge_local_gate=True,
        receives_screen_space_face_shadow=True,
    ),
    ("mask", 0): _identity(
        "mask",
        0,
        "Mask0 generated _a0/_user0 composite and ordinary emission",
        literal_title_final_coverage=False,
    ),
    **{
        ("hair_endpoint", index): _identity(
            "hair_endpoint",
            index,
            f"Hair{index} exact Hair564 fragment family: MGH.R endpoint mix followed by abs(x)^2.2",
        )
        for index in (564, 576, 588)
    },
    **{
        ("hair_anisotropic", index): _identity(
            "hair_anisotropic",
            index,
            f"Hair{index} exact Hair612 fragment family: MGH.R base plus shifted-bitangent anisotropic kernel",
            anisotropic_local_kernel=True,
            front_edge_local_gate=True,
        )
        for index in (612, 624, 636)
    },
    **{
        ("hair_endpoint", index): _identity(
            "hair_endpoint",
            index,
            f"Hair{index} exact Hair672 fragment family: MGH.R endpoint mix followed by abs(x)^2.2",
        )
        for index in (672, 696)
    },
    ("hair_anisotropic", 708): _identity(
        "hair_anisotropic",
        708,
        "Hair708 MGH.R/G face gradient plus shifted-bitangent anisotropic kernel",
        anisotropic_local_kernel=True,
        front_edge_local_gate=True,
    ),
    ("hair_endpoint", 1056): _identity(
        "hair_endpoint", 1056, "Hair1056 MGH.R endpoint mix followed by abs(x)^2.2"
    ),
    ("hair_endpoint", 1116): _identity(
        "hair_endpoint",
        1116,
        "Hair1116 MGH.R endpoint base and BC5_SNORM normal reconstruction",
    ),
    **{
        ("hair_constant", index): _identity(
            "hair_constant",
            index,
            f"Hair{index} texture-independent linear mii_hair_color0 base",
        )
        for index in (396, 408, 420, 432)
    },
    ("nose", 756): _identity(
        "nose",
        756,
        "Nose756 face-color base, Hgt parallax, and MIM.G material mask",
        cheap_sss_local_curve=True,
        receives_screen_space_face_shadow=True,
    ),
    ("nose_line", 12): _identity(
        "nose_line",
        12,
        "NoseLine12 literal constant output; authored coverage needs unresolved override",
        literal_title_final_coverage=False,
    ),
    ("ear", 372): _identity(
        "ear",
        372,
        "Ear372 linear mii_face_color base",
        cheap_sss_local_curve=True,
        front_edge_local_gate=True,
        receives_screen_space_face_shadow=True,
    ),
    **{
        ("beard_anisotropic", index): _identity(
            "beard_anisotropic",
            index,
            f"Beard{index} constant base plus shifted-bitangent anisotropic kernel",
            anisotropic_local_kernel=True,
            front_edge_local_gate=True,
        )
        for index in (456, 468)
    },
    **{
        ("body", index): _identity(
            "body",
            index,
            f"Body{index} exact shared fragment family: Alb/Skm.G base and Mic.R roughness",
            cheap_sss_local_curve=True,
        )
        for index in (324, 336, 348)
    },
    ("decoration", 480): _identity(
        "decoration",
        480,
        "Decoration480 linear mii_constant_color0 base and archive-zero specular mask",
    ),
    ("decoration", 492): _identity(
        "decoration",
        492,
        "Decoration492 skinned vertex path with the Decoration480 constant local base",
    ),
    ("headwear", 96): _identity(
        "headwear",
        96,
        "Headwear96 hardware-sRGB Alb, BC5_SNORM Nrm, and Mic.R material bindings",
    ),
    ("outfit_tops", 984): _identity(
        "outfit_tops",
        984,
        "OutfitTops984 active hardware-sRGB Alb, Nrm, Emm, and Mic.R bindings; serialized _alp0 is compiled inactive",
    ),
    ("outfit_bottoms", 936): _identity(
        "outfit_bottoms",
        936,
        "OutfitBottoms936 active hardware-sRGB Alb, Nrm, and Mic.R bindings; serialized _alp0 is compiled inactive",
    ),
    ("outfit_shoes", 912): _identity(
        "outfit_shoes",
        912,
        "OutfitShoes912 active hardware-sRGB Alb, Nrm, and Mic.R bindings; serialized _alp0 is compiled inactive",
    ),
    ("glass_frame", 360): _identity(
        "glass_frame",
        360,
        "GlassFrame360 linear mii_glass_color0 constant base",
    ),
    ("glass_lens_translucent", 60): _identity(
        "glass_lens_translucent",
        60,
        "GlassLens60 exact local color/alpha/decay uniforms, Nrm, and premultiplied blend state",
    ),
    ("glass_lens_opaque", 768): _identity(
        "glass_lens_opaque",
        768,
        "GlassLens768 exact local color/alpha/decay uniforms, Nrm, and opaque depth state",
    ),
}


def gameall_program_identity(family: str, program_index: int) -> GameAllProgramIdentity:
    """Return one hash/semantics-audited local GameAll identity.

    Unknown family/index combinations fail closed.  This prevents a resolver
    candidate from inheriting local equations merely because it has a nearby
    program number.
    """

    key = (str(family), int(program_index))
    try:
        return _GAMEALL_PROGRAM_IDENTITIES[key]
    except KeyError as error:
        raise ValueError(
            f"no audited portable GameAll local contract for {key[0]!r} program {key[1]}"
        ) from error


def validate_gameall_program_identity(
    identity: GameAllProgramIdentity,
) -> GameAllProgramIdentity:
    """Reject hand-constructed identities that differ from the audit table."""

    if not isinstance(identity, GameAllProgramIdentity):
        raise TypeError("identity must be a GameAllProgramIdentity")
    expected = gameall_program_identity(identity.family, identity.program_index)
    if identity != expected:
        raise ValueError(
            f"GameAll {identity.family}/{identity.program_index} local contract was altered"
        )
    return expected


@dataclass(frozen=True)
class AnisotropicFrame612468:
    """Hair612/Beard468 local anisotropic axes.

    ``bitangent`` is reconstructed from normal, tangent, and tangent handedness.
    ``shifted_axis`` is the shifted bitangent used by the exponential kernel;
    ``anisotangent`` is the other kernel axis.
    """

    normal: FloatArray
    tangent: FloatArray
    bitangent: FloatArray
    shifted_axis: FloatArray
    anisotangent: FloatArray
    shift: FloatArray


@dataclass(frozen=True)
class Body348LocalSurface:
    """Shared Body324/336/348 local albedo and roughness before title lighting."""

    base_linear_rgb: FloatArray
    roughness: FloatArray


@dataclass(frozen=True)
class Mask0LocalSurface:
    """Mask0 local RGB terms and its literal shader output alpha."""

    albedo_linear_rgb: FloatArray
    ordinary_emission_linear_rgb: FloatArray
    output_alpha: FloatArray


@dataclass(frozen=True)
class GlassLensRuntimeState:
    """Exact local lens uniforms produced by ``FUN_7101d7c4e0``.

    The title's environment/reflection contribution is outside this record;
    these are only the color, opacity, and decay values uploaded to GameAll.
    """

    lens_color_rgba: FloatArray
    raw_opacity: FloatArray
    effective_alpha: FloatArray
    glass_decay_rgba: FloatArray


def _vector(value: ArrayLike, components: int, name: str) -> FloatArray:
    result = np.asarray(value, dtype=np.float64)
    if result.ndim == 0 or result.shape[-1] != components:
        raise ValueError(f"{name} must have a final axis of length {components}")
    if not np.all(np.isfinite(result)):
        raise ValueError(f"{name} must contain only finite values")
    return result


def _scalar(value: ArrayLike, name: str) -> FloatArray:
    result = np.asarray(value, dtype=np.float64)
    if not np.all(np.isfinite(result)):
        raise ValueError(f"{name} must contain only finite values")
    return result


def _positive_epsilon(value: float) -> np.float64:
    epsilon = np.float64(value)
    if not np.isfinite(epsilon) or epsilon <= 0.0:
        raise ValueError("epsilon must be finite and greater than zero")
    return epsilon


def _normalize(value: FloatArray, *, epsilon: float, name: str) -> FloatArray:
    threshold = _positive_epsilon(epsilon)
    length = np.linalg.norm(value, axis=-1, keepdims=True)
    if np.any(length <= threshold):
        raise ValueError(f"{name} contains a zero/degenerate vector")
    return value / length


def anisotropic_frame_612_468(
    normal: ArrayLike,
    tangent: ArrayLike,
    tangent_handedness: ArrayLike,
    mim_b: ArrayLike,
    *,
    aniso_shift_scale: ArrayLike,
    aniso_shift_offset: ArrayLike,
    epsilon: float,
) -> AnisotropicFrame612468:
    """Build the exact local Hair612/Beard468 anisotropic frame.

    The recovered equations are::

        B = normalize(handedness * cross(N, T))
        shift = (2*MIM.b - 1)*aniso_shift_scale + aniso_shift_offset
        S = normalize(B + shift*N)
        A = normalize(handedness * cross(N, B))

    Hair612 omits its shift uniforms from BFRES, so callers must explicitly
    provide captured values or clearly labelled template/proxy defaults.
    """

    n = _normalize(_vector(normal, 3, "normal"), epsilon=epsilon, name="normal")
    t = _normalize(_vector(tangent, 3, "tangent"), epsilon=epsilon, name="tangent")
    handedness = _scalar(tangent_handedness, "tangent_handedness")
    if np.any(np.abs(np.abs(handedness) - 1.0) > _positive_epsilon(epsilon)):
        raise ValueError("tangent_handedness must be -1 or +1")
    handedness_vector = handedness[..., np.newaxis]

    bitangent = _normalize(
        handedness_vector * np.cross(n, t), epsilon=epsilon, name="reconstructed bitangent"
    )
    shift = (
        (2.0 * _scalar(mim_b, "mim_b") - 1.0)
        * _scalar(aniso_shift_scale, "aniso_shift_scale")
        + _scalar(aniso_shift_offset, "aniso_shift_offset")
    )
    shifted_axis = _normalize(
        bitangent + shift[..., np.newaxis] * n,
        epsilon=epsilon,
        name="shifted anisotropic axis",
    )
    anisotangent = _normalize(
        handedness_vector * np.cross(n, bitangent),
        epsilon=epsilon,
        name="anisotangent",
    )
    return AnisotropicFrame612468(
        normal=n,
        tangent=t,
        bitangent=bitangent,
        shifted_axis=shifted_axis,
        anisotangent=anisotangent,
        shift=np.asarray(shift, dtype=np.float64),
    )


def anisotropic_half_vector_612_468(
    view_vector: ArrayLike,
    title_light_vector: ArrayLike,
    title_view_scale: ArrayLike,
    *,
    epsilon: float,
) -> FloatArray:
    """Assemble one recovered title half vector, ``normalize(kV*V + L_i)``.

    ``title_light_vector`` and ``title_view_scale`` are explicit because their
    active values come from unresolved title light records.  The function does
    not independently normalize either input before the recovered weighted sum.
    """

    view = _vector(view_vector, 3, "view_vector")
    light = _vector(title_light_vector, 3, "title_light_vector")
    view_scale = _scalar(title_view_scale, "title_view_scale")
    return _normalize(
        view_scale[..., np.newaxis] * view + light,
        epsilon=epsilon,
        name="anisotropic half vector",
    )


def anisotropic_kernel_612_468(
    frame: AnisotropicFrame612468,
    half_vector: ArrayLike,
    roughness: ArrayLike,
    aniso_specular_size: ArrayLike,
    *,
    epsilon: float,
) -> FloatArray:
    """Evaluate the exact recovered local Hair612/Beard468 kernel ``K_i``.

    This is a dimensionless local kernel, not final radiance::

        invr2 = 1 / max(max(roughness, eps)^2, eps)
        q = (dot(A,H)^2 + (dot(S,H)*invr2)^2) / dot(N,H)^2
        K = exp(-q) * invr2 * aniso_specular_size / (4*pi)

    The shader's internal positive epsilon was not recovered as a named
    constant, so it remains an explicit API input.
    """

    threshold = _positive_epsilon(epsilon)
    h = _normalize(_vector(half_vector, 3, "half_vector"), epsilon=epsilon, name="half_vector")
    rough = np.maximum(_scalar(roughness, "roughness"), threshold)
    inverse_r2 = 1.0 / np.maximum(rough * rough, threshold)
    size = _scalar(aniso_specular_size, "aniso_specular_size")

    nh = np.sum(frame.normal * h, axis=-1)
    sh = np.sum(frame.shifted_axis * h, axis=-1)
    ah = np.sum(frame.anisotangent * h, axis=-1)
    numerator = ah * ah + np.square(sh * inverse_r2)
    nh_squared = nh * nh
    output_shape = np.broadcast_shapes(numerator.shape, nh_squared.shape)
    q = np.full(output_shape, np.inf, dtype=np.float64)
    np.divide(numerator, nh_squared, out=q, where=nh_squared > 0.0)
    return np.exp(-q) * inverse_r2 * size * INV_FOUR_PI


def anisotropic_masked_lobe_612_468(
    kernel: ArrayLike,
    mim_g: ArrayLike,
    toon_specular_intensity: ArrayLike,
) -> FloatArray:
    """Apply the exact local ``MIM.g`` and toon-specular multipliers to ``K_i``."""

    return (
        _scalar(kernel, "kernel")
        * _scalar(mim_g, "mim_g")
        * _scalar(toon_specular_intensity, "toon_specular_intensity")
    )


def proxy_single_key_light_anisotropic_specular_612_468(
    frame: AnisotropicFrame612468,
    view_to_camera: ArrayLike,
    surface_to_light: ArrayLike,
    light_radiance_linear_rgb: ArrayLike,
    *,
    title_view_scale: ArrayLike,
    roughness: ArrayLike,
    aniso_specular_size: ArrayLike,
    mim_g: ArrayLike,
    toon_specular_intensity: ArrayLike,
    epsilon: float,
) -> FloatArray:
    """Safe conventional one-key-light proxy around the exact local kernel.

    The proxy adds ``max(dot(N,L), 0) * light_radiance``.  That composition is
    deliberately *not* presented as the missing GameUber light-record/LTC
    radiance path; callers needing title fidelity must replace this function.
    """

    view = _normalize(
        _vector(view_to_camera, 3, "view_to_camera"), epsilon=epsilon, name="view_to_camera"
    )
    light = _normalize(
        _vector(surface_to_light, 3, "surface_to_light"),
        epsilon=epsilon,
        name="surface_to_light",
    )
    radiance = _vector(light_radiance_linear_rgb, 3, "light_radiance_linear_rgb")
    half_vector = anisotropic_half_vector_612_468(
        view, light, title_view_scale, epsilon=epsilon
    )
    kernel = anisotropic_kernel_612_468(
        frame,
        half_vector,
        roughness,
        aniso_specular_size,
        epsilon=epsilon,
    )
    lobe = anisotropic_masked_lobe_612_468(kernel, mim_g, toon_specular_intensity)
    ndotl = np.maximum(np.sum(frame.normal * light, axis=-1), 0.0)
    return radiance * (lobe * ndotl)[..., np.newaxis]


def hair_endpoint_gradient_base_linear(
    mii_hair_color_srgb0_rgb: ArrayLike,
    mii_hair_color_srgb1_rgb: ArrayLike,
    mgh_r: ArrayLike,
) -> FloatArray:
    """Shared hair endpoint base: mix sRGB-named colors, then ``abs(x)^2.2``.

    This local expression is source-checked for the selected Hair612, Hair564,
    and Hair1116 programs.  It is the shader's simple power operation, not
    piecewise IEC-sRGB decode and not interpolation between already-linear
    endpoints.  Program-specific anisotropic terms are deliberately separate.
    """

    primary = _vector(mii_hair_color_srgb0_rgb, 3, "mii_hair_color_srgb0_rgb")
    secondary = _vector(mii_hair_color_srgb1_rgb, 3, "mii_hair_color_srgb1_rgb")
    weight = _scalar(mgh_r, "mgh_r")[..., np.newaxis]
    mixed_srgb = primary + (secondary - primary) * weight
    return np.power(np.abs(mixed_srgb), 2.2)


def hair_constant_color_base_linear(
    mii_hair_color0_linear_rgb: ArrayLike,
) -> FloatArray:
    """Hair396/408/420/432's exact texture-independent local base.

    These fragment families bind only MIM as ``_o0``.  Their base-color path
    reads the runtime-bound linear ``mii_hair_color0.rgb`` components directly;
    there is no MGH endpoint sample and no ``abs(x)^2.2`` conversion.
    """

    return _vector(
        mii_hair_color0_linear_rgb,
        3,
        "mii_hair_color0_linear_rgb",
    ).copy()


def hair708_face_gradient_base_linear(
    mii_hair_color_srgb0_rgb: ArrayLike,
    mii_hair_color_srgb1_rgb: ArrayLike,
    mii_face_color_linear_rgb: ArrayLike,
    mgh_r: ArrayLike,
    mgh_g: ArrayLike,
) -> FloatArray:
    """Hair708's exact two-channel MGH base-color expression.

    Programs 708 first interpolate the two sRGB-named hair endpoints by MGH.R,
    then interpolate that result toward the title's linear ``mii_face_color``
    uniform by MGH.G, and finally apply the compiled ``abs(x)^2.2`` transfer::

        endpoint = mix(hair_srgb0, hair_srgb1, MGH.r)
        mixed = mix(endpoint, mii_face_color, MGH.g)
        base = pow(abs(mixed), 2.2)

    The seemingly mixed color spaces are intentional: they are the literal
    order and uniforms in the exact program-708 instruction stream.
    """

    primary = _vector(mii_hair_color_srgb0_rgb, 3, "mii_hair_color_srgb0_rgb")
    secondary = _vector(mii_hair_color_srgb1_rgb, 3, "mii_hair_color_srgb1_rgb")
    face = _vector(mii_face_color_linear_rgb, 3, "mii_face_color_linear_rgb")
    endpoint_weight = _scalar(mgh_r, "mgh_r")[..., np.newaxis]
    face_weight = _scalar(mgh_g, "mgh_g")[..., np.newaxis]
    endpoint = primary + (secondary - primary) * endpoint_weight
    mixed = endpoint + (face - endpoint) * face_weight
    return np.power(np.abs(mixed), 2.2)


def glass_lens_runtime_state(
    lens_color_rgba: ArrayLike,
    raw_opacity: ArrayLike,
    *,
    is_multiply_blend: bool,
) -> GlassLensRuntimeState:
    """Evaluate the exact local glass uniform equations.

    ``FUN_7101d7c4e0`` uploads the selected common color unchanged.  For each
    RGB channel it computes ``1-opacity**(color*1.8+0.2)``.  The alpha upload
    is the raw opacity in multiply mode; otherwise it is opacity raised to the
    same exponent built from the title's literal luminance coefficients.

    Mode selection and the checked SystemParam defaults remain caller-side so
    this equation can also be adversarially verified without hidden globals.
    """

    color = _vector(lens_color_rgba, 4, "lens_color_rgba")
    opacity = _scalar(raw_opacity, "raw_opacity")
    if np.any((opacity < 0.0) | (opacity > 1.0)):
        raise ValueError("raw_opacity must be in the inclusive range [0, 1]")
    broadcast_shape = np.broadcast_shapes(color.shape[:-1], opacity.shape)
    color = np.broadcast_to(color, (*broadcast_shape, 4))
    opacity = np.broadcast_to(opacity, broadcast_shape)
    decay_rgb = 1.0 - np.power(
        opacity[..., np.newaxis], color[..., :3] * 1.8 + 0.2
    )
    if is_multiply_blend:
        effective_alpha = opacity
    else:
        luminance = (
            color[..., 0] * 0.298912
            + color[..., 1] * 0.586611
            + color[..., 2] * 0.114478
        )
        effective_alpha = np.power(opacity, luminance * 1.8 + 0.2)
    decay = np.concatenate(
        (decay_rgb, effective_alpha[..., np.newaxis]), axis=-1
    )
    return GlassLensRuntimeState(
        lens_color_rgba=np.asarray(color, dtype=np.float64),
        raw_opacity=np.asarray(opacity, dtype=np.float64),
        effective_alpha=np.asarray(effective_alpha, dtype=np.float64),
        glass_decay_rgba=np.asarray(decay, dtype=np.float64),
    )


def decoration480_492_local_base_linear(
    mii_constant_color0_linear_rgba: ArrayLike,
) -> FloatArray:
    """Return Decoration480/492's exact texture-independent local base.

    The selected programs have ``replace_albedo`` with ``map_albedo=100`` and
    consume the runtime-bound ``mii_constant_color0``. Their inherited
    ``map_specular_mask`` resolves to the archive default zero. Lighting and
    environment records remain outside this identity local-base operation.
    """

    return _vector(
        mii_constant_color0_linear_rgba,
        4,
        "mii_constant_color0_linear_rgba",
    ).copy()


def cheap_sss_local_scatter_816_756_372_348(
    title_light_input_x: ArrayLike,
    scatter_distance: ArrayLike,
    scatter_attenuation: ArrayLike,
    scatter_color_linear_rgb: ArrayLike,
) -> FloatArray:
    """Exact local cheap-SSS response shared by Head/Nose/Ear/Body programs.

    ``title_light_input_x`` is explicit because it is reconstructed from
    light-prepass/environment terms and is *not* raw N.L or N.V::

        x_sat = saturate(x)
        wrapped = saturate(distance + (1-distance)*x)
        delta = pow(wrapped, attenuation) - x_sat
        scatter_rgb = delta * scatter_color

    The profile's global skin-emission gate and ``scatter_emission_color`` add
    are not folded into this local response because their shader-side coupling
    remains unresolved.
    """

    x = _scalar(title_light_input_x, "title_light_input_x")
    distance = _scalar(scatter_distance, "scatter_distance")
    attenuation = _scalar(scatter_attenuation, "scatter_attenuation")
    color = _vector(scatter_color_linear_rgb, 3, "scatter_color_linear_rgb")
    x_saturated = np.clip(x, 0.0, 1.0)
    wrapped = np.clip(distance + (1.0 - distance) * x, 0.0, 1.0)
    delta = np.power(wrapped, attenuation) - x_saturated
    return color * delta[..., np.newaxis]


def nose756_parallax_uv(
    uv0: ArrayLike,
    hgt_r: ArrayLike,
    view_tangent_xyz: ArrayLike,
    *,
    epsilon: float,
    parallax_height_scale: ArrayLike = 0.25,
) -> FloatArray:
    """Nose756 parallax using the exact selected material's height scale.

    The established fixtures serialize 0.25.  Other exact Nose756 materials
    may provide a different positive finite BFRES ``parallax_height_scale``;
    callers must pass that checked value instead of borrowing 0.25.
    """

    uv = _vector(uv0, 2, "uv0")
    height = _scalar(hgt_r, "hgt_r")
    view = _vector(view_tangent_xyz, 3, "view_tangent_xyz")
    threshold = _positive_epsilon(epsilon)
    view_z = view[..., 2]
    if np.any(np.abs(view_z) <= threshold):
        raise ValueError("view_tangent_xyz.z is too close to zero for Nose756 parallax")
    height_scale = _scalar(parallax_height_scale, "parallax_height_scale")
    if np.any(height_scale <= 0.0):
        raise ValueError("parallax_height_scale must be finite and greater than zero")
    depth = height_scale * (1.0 - height)
    return uv - depth[..., np.newaxis] * view[..., :2] / view_z[..., np.newaxis]


def body348_local_base_linear(
    mii_face_color_linear_rgb: ArrayLike,
    albedo_hardware_srgb_sample_linear_rgb: ArrayLike,
    skm_g: ArrayLike,
) -> FloatArray:
    """Shared Body324/336/348 base: ``mix(mii_face_color, Alb_linear, Skm.g)``.

    ``Alb`` must already be hardware-decoded from its sRGB texture view.
    """

    face = _vector(mii_face_color_linear_rgb, 3, "mii_face_color_linear_rgb")
    albedo = _vector(
        albedo_hardware_srgb_sample_linear_rgb,
        3,
        "albedo_hardware_srgb_sample_linear_rgb",
    )
    skin_mix = _scalar(skm_g, "skm_g")[..., np.newaxis]
    return face + (albedo - face) * skin_mix


def body348_local_roughness(
    skm_g: ArrayLike,
    mic_r: ArrayLike,
    const_single_roughness: ArrayLike,
) -> FloatArray:
    """Shared Body324/336/348 roughness: ``mix(Mic.r, const_roughness, 1-Skm.g)``."""

    skin_mix = _scalar(skm_g, "skm_g")
    mic = _scalar(mic_r, "mic_r")
    constant = _scalar(const_single_roughness, "const_single_roughness")
    return mic * skin_mix + constant * (1.0 - skin_mix)


def body348_local_surface(
    mii_face_color_linear_rgb: ArrayLike,
    albedo_hardware_srgb_sample_linear_rgb: ArrayLike,
    skm_g: ArrayLike,
    mic_r: ArrayLike,
    const_single_roughness: ArrayLike,
) -> Body348LocalSurface:
    """Return both recovered shared Body324/336/348 local material outputs."""

    return Body348LocalSurface(
        base_linear_rgb=body348_local_base_linear(
            mii_face_color_linear_rgb,
            albedo_hardware_srgb_sample_linear_rgb,
            skm_g,
        ),
        roughness=body348_local_roughness(skm_g, mic_r, const_single_roughness),
    )


def mask0_local_albedo_linear(
    user0_hardware_srgb_sample_linear_rgba: ArrayLike,
    generated_mask_hardware_srgb_sample_linear_rgba: ArrayLike,
    replace_albedo_color_linear_rgba: ArrayLike,
    const_single0: ArrayLike,
    *,
    front_facing: ArrayLike = True,
) -> FloatArray:
    """Evaluate GameAll0's exact local two-texture RGB composite.

    ``U`` is ``_user0`` and ``A`` is generated ``_a0``::

        k_front = max(A.a - min(U.a, const_single0), 0)
        k = k_front on front faces, otherwise 0
        under = mix(U.rgb, U.a*C.rgb, C.a)
        local = mix(under, A.rgb, k)

    Both active textures use sRGB views, so RGB inputs are linear hardware
    samples.  Alpha inputs remain untransformed.
    """

    user = _vector(
        user0_hardware_srgb_sample_linear_rgba,
        4,
        "user0_hardware_srgb_sample_linear_rgba",
    )
    mask = _vector(
        generated_mask_hardware_srgb_sample_linear_rgba,
        4,
        "generated_mask_hardware_srgb_sample_linear_rgba",
    )
    replacement = _vector(
        replace_albedo_color_linear_rgba,
        4,
        "replace_albedo_color_linear_rgba",
    )
    cutoff_source = np.minimum(user[..., 3], _scalar(const_single0, "const_single0"))
    k_front = np.maximum(mask[..., 3] - cutoff_source, 0.0)
    k = np.where(np.asarray(front_facing, dtype=bool), k_front, 0.0)[..., np.newaxis]
    under = user[..., :3] + (
        user[..., 3, np.newaxis] * replacement[..., :3] - user[..., :3]
    ) * replacement[..., 3, np.newaxis]
    return under + (mask[..., :3] - under) * k


def mask0_local_ordinary_emission_linear(
    generated_mask_hardware_srgb_sample_linear_rgba: ArrayLike,
    emission_color_linear_rgb: ArrayLike,
    emission_intensity: ArrayLike,
) -> FloatArray:
    """GameAll0 ordinary emission: ``A.rgb*A.a*color*intensity``."""

    mask = _vector(
        generated_mask_hardware_srgb_sample_linear_rgba,
        4,
        "generated_mask_hardware_srgb_sample_linear_rgba",
    )
    color = _vector(emission_color_linear_rgb, 3, "emission_color_linear_rgb")
    intensity = _scalar(emission_intensity, "emission_intensity")
    return mask[..., :3] * mask[..., 3, np.newaxis] * color * intensity[..., np.newaxis]


def mask0_local_surface(
    user0_hardware_srgb_sample_linear_rgba: ArrayLike,
    generated_mask_hardware_srgb_sample_linear_rgba: ArrayLike,
    replace_albedo_color_linear_rgba: ArrayLike,
    const_single0: ArrayLike,
    emission_color_linear_rgb: ArrayLike,
    emission_intensity: ArrayLike,
    *,
    front_facing: ArrayLike = True,
) -> Mask0LocalSurface:
    """Return the recovered Mask0 local RGB terms and literal alpha-one output."""

    albedo = mask0_local_albedo_linear(
        user0_hardware_srgb_sample_linear_rgba,
        generated_mask_hardware_srgb_sample_linear_rgba,
        replace_albedo_color_linear_rgba,
        const_single0,
        front_facing=front_facing,
    )
    emission = mask0_local_ordinary_emission_linear(
        generated_mask_hardware_srgb_sample_linear_rgba,
        emission_color_linear_rgb,
        emission_intensity,
    )
    output_shape = np.broadcast_shapes(albedo.shape[:-1], emission.shape[:-1])
    return Mask0LocalSurface(
        albedo_linear_rgb=albedo,
        ordinary_emission_linear_rgb=emission,
        output_alpha=np.ones(output_shape, dtype=np.float64),
    )


def portable_mask0_runtime_override_coverage(
    generated_mask_alpha: ArrayLike, *, threshold: float = 0.5
) -> NDArray[np.bool_]:
    """Emulate the unresolved title pass that prevents Mask0's opaque shield.

    This is intentionally outside ``mask0_local_surface``: GameAll0 itself has
    no KIL and writes alpha one.  The transparent generated atlas plus title
    output proves a missing override/pass boundary; a 0.5 cutoff is the safe
    portable behavior used by this reconstruction.
    """

    alpha = _scalar(generated_mask_alpha, "generated_mask_alpha")
    cutoff = np.float64(threshold)
    if not np.isfinite(cutoff):
        raise ValueError("threshold must be finite")
    return np.asarray(alpha >= cutoff, dtype=np.bool_)


__all__ = [
    "AnisotropicFrame612468",
    "Body348LocalSurface",
    "GameAllProgramIdentity",
    "GlassLensRuntimeState",
    "INV_FOUR_PI",
    "Mask0LocalSurface",
    "SCREEN_SPACE_FACE_SHADOW_PARAMETERS",
    "ScreenSpaceFaceShadowParameters",
    "anisotropic_frame_612_468",
    "anisotropic_half_vector_612_468",
    "anisotropic_kernel_612_468",
    "anisotropic_masked_lobe_612_468",
    "body348_local_base_linear",
    "body348_local_roughness",
    "body348_local_surface",
    "cheap_sss_local_scatter_816_756_372_348",
    "decoration480_492_local_base_linear",
    "hair708_face_gradient_base_linear",
    "hair_endpoint_gradient_base_linear",
    "hair_constant_color_base_linear",
    "glass_lens_runtime_state",
    "gameall_program_identity",
    "mask0_local_albedo_linear",
    "mask0_local_ordinary_emission_linear",
    "mask0_local_surface",
    "nose756_parallax_uv",
    "portable_mask0_runtime_override_coverage",
    "proxy_single_key_light_anisotropic_specular_612_468",
    "validate_gameall_program_identity",
]
