#include "native_scene_assembler.h"

#include "native_geometry.h"
#include "native_parts_selector.h"
#include "native_pose.h"
#include "native_scene_math.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using infinimii::native_parts::Logical;
using infinimii::native_parts::SelectedRecord;

struct AssemblyFailure final : std::runtime_error {
    ltd_native_scene_assembler_status status;
    AssemblyFailure(ltd_native_scene_assembler_status value, std::string message)
        : std::runtime_error(std::move(message)), status(value) {}
};

[[noreturn]] void fail(ltd_native_scene_assembler_status status, std::string message) {
    throw AssemblyFailure(status, std::move(message));
}

void set_error(char* output, std::size_t capacity, std::string_view message) {
    if (output == nullptr || capacity == 0) return;
    const std::size_t count = std::min(capacity - 1, message.size());
    std::memcpy(output, message.data(), count);
    output[count] = '\0';
}

bool valid_sha256(const char* value) {
    if (value == nullptr) return false;
    for (std::size_t index = 0; index < 64; ++index) {
        const char c = value[index];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return value[64] == '\0';
}

bool finite_values(const double* values, std::size_t count) {
    if (count != 0 && values == nullptr) return false;
    for (std::size_t index = 0; index < count; ++index) {
        if (!std::isfinite(values[index])) return false;
    }
    return true;
}

bool checked_mul(std::size_t left, std::size_t right, std::size_t& output) {
    if (left != 0 && right > std::numeric_limits<std::size_t>::max() / left) return false;
    output = left * right;
    return true;
}

void identity(double output[16]) {
    std::fill(output, output + 16, 0.0);
    output[0] = output[5] = output[10] = output[15] = 1.0;
}

void multiply4(const double left[16], const double right[16], double output[16]) {
    double result[16]{};
    for (int row = 0; row < 4; ++row) {
        for (int column = 0; column < 4; ++column) {
            double value = 0.0;
            for (int inner = 0; inner < 4; ++inner) {
                value += left[row * 4 + inner] * right[inner * 4 + column];
            }
            result[row * 4 + column] = value;
        }
    }
    std::copy(result, result + 16, output);
}

std::array<double, 16> multiplied(const double left[16], const double right[16]) {
    std::array<double, 16> output{};
    multiply4(left, right, output.data());
    return output;
}

std::array<double, 16> scale_matrix(double x, double y, double z) {
    std::array<double, 16> output{};
    identity(output.data());
    output[0] = x;
    output[5] = y;
    output[10] = z;
    return output;
}

std::array<double, 16> translation_matrix(double x, double y, double z) {
    std::array<double, 16> output{};
    identity(output.data());
    output[3] = x;
    output[7] = y;
    output[11] = z;
    return output;
}

struct PreparedModel final {
    ltd_native_scene_model_view source{};
    std::string resource;
    std::string model;
    std::vector<double> world_matrices;
    std::vector<double> positions;
    std::vector<double> normals;
};

struct OwnedDraw final {
    std::string resource;
    std::string model;
    std::string group;
    std::uint32_t profile = 0;
    std::uint8_t blend = 0;
    std::uint8_t depth_write = 1;
    std::uint8_t cull = 1;
    std::uint8_t clockwise = 0;
    std::array<double, 16> transform{};
    std::uint64_t submitted = 0;
    std::vector<std::uint64_t> source_triangle_indices;
    std::vector<double> world_vertices;
    std::vector<double> world_normals;
    std::vector<double> screen;
    std::vector<std::int64_t> bounds;
    std::vector<double> denominators;
    std::vector<double> material_uv;
    std::vector<double> uv0;
    std::vector<double> uv2;
};

struct AuthoredDraw final {
    PreparedModel* model = nullptr;
    const ltd_native_scene_shape_view* shape = nullptr;
    std::string group;
    std::uint32_t profile = 0;
    std::uint8_t cull = 1;
    std::uint8_t clockwise = 0;
    std::array<double, 16> transform{};
};

const ltd_native_scene_shape_view* find_shape(
    const PreparedModel& model, std::string_view group) {
    const ltd_native_scene_shape_view* found = nullptr;
    for (std::size_t index = 0; index < model.source.shape_count; ++index) {
        const auto& shape = model.source.shapes[index];
        if (shape.group != nullptr && group == shape.group) {
            if (found != nullptr) {
                fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                     model.resource + "/" + model.model + " duplicates shape " +
                         std::string(group));
            }
            found = &shape;
        }
    }
    if (found == nullptr) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
             model.resource + "/" + model.model + " lacks shape " + std::string(group));
    }
    return found;
}

std::size_t find_bone(const PreparedModel& model, std::string_view name) {
    std::size_t found = model.source.bone_count;
    for (std::size_t index = 0; index < model.source.bone_count; ++index) {
        const char* candidate = model.source.bones[index].name;
        if (candidate != nullptr && name == candidate) {
            if (found != model.source.bone_count) {
                fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                     model.resource + " duplicates bone " + std::string(name));
            }
            found = index;
        }
    }
    if (found == model.source.bone_count) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
             model.resource + " lacks bone " + std::string(name));
    }
    return found;
}

const double* bone_matrix(const PreparedModel& model, std::string_view name) {
    return model.world_matrices.data() + find_bone(model, name) * 16;
}

const double* rigid_shape_matrix(
    const PreparedModel& model, const ltd_native_scene_shape_view& shape) {
    if (shape.vertex_skin_count != 0 || shape.bone_index < 0 ||
        static_cast<std::size_t>(shape.bone_index) >= model.source.bone_count) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
             model.resource + "/" + shape.group + " is not a valid rigid shape");
    }
    return model.world_matrices.data() + static_cast<std::size_t>(shape.bone_index) * 16;
}

const ltd_native_scene_pose_bone_view* pose_bone(
    const ltd_native_scene_pose_view* pose, std::string_view name) {
    if (pose == nullptr) return nullptr;
    const ltd_native_scene_pose_bone_view* found = nullptr;
    for (std::size_t index = 0; index < pose->bone_count; ++index) {
        const auto& candidate = pose->bones[index];
        if (candidate.name != nullptr && name == candidate.name) {
            if (found != nullptr) {
                fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                     "IconPose contains a duplicate bone " + std::string(name));
            }
            found = &candidate;
        }
    }
    return found;
}

void validate_model_view(
    const ltd_native_scene_model_view& model,
    std::string_view expected_resource,
    std::string_view expected_model) {
    if (model.resource_name == nullptr || model.model_name == nullptr ||
        expected_resource != model.resource_name || expected_model != model.model_name ||
        !valid_sha256(model.obj_sha256) || !valid_sha256(model.catalog_sha256) ||
        model.position_count == 0 || model.position_count != model.normal_count ||
        model.position_count != model.texcoord_count || model.triangle_count == 0 ||
        model.bone_count == 0 || model.shape_count == 0 ||
        model.positions == nullptr || model.normals == nullptr || model.texcoords == nullptr ||
        model.triangles == nullptr || model.bones == nullptr || model.shapes == nullptr ||
        !finite_values(model.positions, model.position_count * 3) ||
        !finite_values(model.normals, model.normal_count * 3) ||
        !finite_values(model.texcoords, model.texcoord_count * 2)) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
             std::string(expected_resource) + "/" + std::string(expected_model) +
                 " has an invalid immutable model view");
    }
    if ((model.named_uv_channel_count != 0 &&
         (model.named_uv_channels == nullptr || !valid_sha256(model.named_uv_sha256))) ||
        (model.named_uv_channel_count == 0 && model.named_uv_sha256 != nullptr)) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_SOURCE_SEAL_INVALID,
             std::string(expected_resource) + " named-UV seal is inconsistent");
    }
    if ((model.palette_count != 0 &&
         (model.matrix_to_bone == nullptr || model.smooth_count > model.palette_count)) ||
        (model.smooth_count != 0 && model.inverse_bind_matrices == nullptr) ||
        !finite_values(model.inverse_bind_matrices, model.smooth_count * 16)) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
             std::string(expected_resource) + " has an invalid matrix palette");
    }
    std::set<std::string_view> bone_names;
    for (std::size_t index = 0; index < model.bone_count; ++index) {
        const auto& bone = model.bones[index];
        if (bone.name == nullptr || bone.name[0] == '\0' || bone.reserved != 0 ||
            bone.parent_index < -1 || bone.parent_index >= static_cast<std::int32_t>(index) ||
            !finite_values(bone.scale, 3) || !finite_values(bone.rotation, 3) ||
            !finite_values(bone.translation, 3) || !bone_names.insert(bone.name).second) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                 std::string(expected_resource) + " has an invalid bone hierarchy");
        }
    }
    for (std::size_t index = 0; index < model.palette_count; ++index) {
        if (model.matrix_to_bone[index] < 0 ||
            static_cast<std::size_t>(model.matrix_to_bone[index]) >= model.bone_count) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                 std::string(expected_resource) + " has an invalid matrix palette index");
        }
    }
    std::set<std::string_view> shape_names;
    for (std::size_t index = 0; index < model.shape_count; ++index) {
        const auto& shape = model.shapes[index];
        std::size_t influence_count = 0;
        if (shape.group == nullptr || shape.group[0] == '\0' ||
            shape.texcoord_attribute == nullptr ||
            !shape_names.insert(shape.group).second || shape.bone_index < 0 ||
            static_cast<std::size_t>(shape.bone_index) >= model.bone_count ||
            shape.vertex_offset > model.position_count ||
            shape.vertex_count > model.position_count - shape.vertex_offset ||
            !checked_mul(shape.vertex_count, shape.vertex_skin_count, influence_count)) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                 std::string(expected_resource) + " has invalid shape metadata");
        }
        if (shape.vertex_skin_count == 0) {
            if (shape.palette_indices != nullptr || shape.palette_index_count != 0 ||
                shape.weights != nullptr || shape.weight_count != 0) {
                fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                     std::string(expected_resource) + " rigid shape carries skin arrays");
            }
        } else if (shape.palette_indices == nullptr ||
                   shape.palette_index_count != influence_count ||
                   (shape.vertex_skin_count != 1 && shape.weights == nullptr) ||
                   (shape.weights != nullptr && shape.weight_count != influence_count)) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                 std::string(expected_resource) + " has invalid shape skin arrays");
        }
    }
    for (std::size_t index = 0; index < model.triangle_count; ++index) {
        const auto& triangle = model.triangles[index];
        if (triangle.group == nullptr || shape_names.count(triangle.group) == 0) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                 std::string(expected_resource) + " triangle names an unknown shape");
        }
        for (int corner = 0; corner < 3; ++corner) {
            if (triangle.vertex[corner] < 0 || triangle.normal[corner] < 0 ||
                triangle.texcoord[corner] < 0 ||
                static_cast<std::size_t>(triangle.vertex[corner]) >= model.position_count ||
                static_cast<std::size_t>(triangle.normal[corner]) >= model.normal_count ||
                static_cast<std::size_t>(triangle.texcoord[corner]) >= model.texcoord_count) {
                fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                     std::string(expected_resource) + " triangle index is invalid");
            }
        }
    }
    std::set<std::string_view> uv_names;
    for (std::size_t index = 0; index < model.named_uv_channel_count; ++index) {
        const auto& channel = model.named_uv_channels[index];
        if (channel.name == nullptr || channel.name[0] == '\0' ||
            channel.values == nullptr || channel.element_count != model.position_count * 2 ||
            !uv_names.insert(channel.name).second) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                 std::string(expected_resource) + " has an invalid named-UV channel");
        }
    }
}

PreparedModel prepare_model(
    const ltd_native_scene_model_view& source,
    std::string_view resource,
    std::string_view model,
    const ltd_native_scene_pose_view* pose) {
    validate_model_view(source, resource, model);
    PreparedModel output;
    output.source = source;
    output.resource = std::string(resource);
    output.model = std::string(model);
    std::vector<LtdNativeBoneInput> bones(source.bone_count);
    for (std::size_t index = 0; index < source.bone_count; ++index) {
        const auto& input = source.bones[index];
        const auto* animated = pose_bone(pose, input.name);
        bones[index].parent_index = input.parent_index;
        std::copy(animated ? animated->scale : input.scale,
                  (animated ? animated->scale : input.scale) + 3, bones[index].scale);
        std::copy(animated ? animated->rotation : input.rotation,
                  (animated ? animated->rotation : input.rotation) + 3, bones[index].rotation);
        std::copy(animated ? animated->translation : input.translation,
                  (animated ? animated->translation : input.translation) + 3,
                  bones[index].translation);
    }
    output.world_matrices.resize(source.bone_count * 16);
    if (ltd_native_evaluate_world_matrices(
            bones.data(), bones.size(), output.world_matrices.data()) != LTD_NATIVE_POSE_OK) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_POSE_FAILED,
             output.resource + "/" + output.model + " bone evaluation failed");
    }
    std::vector<LtdNativeShapeSkinInput> skins;
    for (std::size_t index = 0; index < source.shape_count; ++index) {
        const auto& shape = source.shapes[index];
        if (shape.vertex_skin_count == 0) continue;
        skins.push_back({
            shape.vertex_offset, shape.vertex_count, shape.vertex_skin_count,
            shape.palette_indices, shape.weights});
    }
    output.positions.resize(source.position_count * 3);
    output.normals.resize(source.normal_count * 3);
    if (ltd_native_skin_mesh(
            source.positions, source.normals, source.position_count,
            skins.data(), skins.size(), source.matrix_to_bone, source.palette_count,
            source.inverse_bind_matrices, source.smooth_count,
            output.world_matrices.data(), source.bone_count,
            output.positions.data(), output.normals.data()) != LTD_NATIVE_POSE_OK) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_POSE_FAILED,
             output.resource + "/" + output.model + " skinning failed");
    }
    return output;
}

class ModelStore final {
public:
    ModelStore(const ltd_native_scene_asset_provider& provider,
               const ltd_native_scene_pose_view& pose)
        : provider_(provider), pose_(pose) {}

    PreparedModel& get(std::string resource, std::string model, bool icon_pose) {
        const std::string key = resource + "\n" + model + (icon_pose ? "\npose" : "\nbind");
        const auto existing = models_.find(key);
        if (existing != models_.end()) return existing->second;
        if (models_.size() >= LTD_NATIVE_SCENE_ASSEMBLER_MAX_MODELS) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_RESOURCE_LIMIT, "scene model limit exceeded");
        }
        ltd_native_scene_model_view view{};
        char provider_error[256]{};
        const int status = provider_.get_model(
            provider_.context, resource.c_str(), model.c_str(), &view,
            provider_error, sizeof(provider_error));
        if (status == 1) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_MISSING,
                 resource + "/" + model + " is missing from the immutable provider");
        }
        if (status != 0) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_PROVIDER_FAILED,
                 provider_error[0] == '\0' ? resource + "/" + model + " provider failure"
                                            : provider_error);
        }
        auto [inserted, unused] = models_.emplace(
            key, prepare_model(view, resource, model, icon_pose ? &pose_ : nullptr));
        (void)unused;
        return inserted->second;
    }

    [[nodiscard]] std::size_t size() const noexcept { return models_.size(); }

private:
    const ltd_native_scene_asset_provider& provider_;
    const ltd_native_scene_pose_view& pose_;
    std::map<std::string, PreparedModel, std::less<>> models_;
};

const SelectedRecord& selected_record(
    const infinimii::native_parts::Selection& selection, Logical logical) {
    for (const auto& record : selection.records) {
        if (record.logical == logical) return record;
    }
    fail(LTD_NATIVE_SCENE_ASSEMBLER_PARTS_FAILED, "native Parts record inventory changed");
}

std::string selected_model_unit(
    const infinimii::native_parts::Selection& selection, Logical logical,
    bool required = false) {
    const auto& selected = selected_record(selection, logical);
    if (!selected.enabled) {
        if (required) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED,
                 std::string(infinimii::native_parts::LogicalName(logical)) +
                     " has no enabled ModelUnit");
        }
        return {};
    }
    if (!selected.resolved || selected.entry == nullptr || selected.is_nothing) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_PARTS_FAILED,
             std::string(infinimii::native_parts::LogicalName(logical)) +
                 " is enabled without a resolved Parts entry");
    }
    std::string result;
    for (const auto& model : selected.entry->model_resources) {
        if (model.role != "ModelUnit") continue;
        if (!result.empty()) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED,
                 std::string(infinimii::native_parts::LogicalName(logical)) +
                     " has multiple ModelUnit resources");
        }
        result = std::string(model.resource_name);
    }
    if (result.empty() && required) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED,
             std::string(infinimii::native_parts::LogicalName(logical)) +
                 " has no ModelUnit resource");
    }
    return result;
}

void reject_broader_model_profiles(const infinimii::native_parts::Selection& selection) {
    const std::set<Logical> admitted{
        Logical::kFaceline, Logical::kHair, Logical::kHairFront, Logical::kEar,
        Logical::kNose, Logical::kBeard, Logical::kGlassPrimary};
    for (const auto& record : selection.records) {
        if (!record.enabled || record.entry == nullptr || admitted.count(record.logical) != 0) {
            continue;
        }
        if (std::any_of(
                record.entry->model_resources.begin(), record.entry->model_resources.end(),
                [](const auto& model) { return model.role == "ModelUnit"; })) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED,
                 "selected broader ModelUnit profile is outside fixture admission: " +
                     std::string(infinimii::native_parts::LogicalName(record.logical)));
        }
    }
}

std::array<double, 16> chain(
    const std::initializer_list<const double*>& matrices) {
    std::array<double, 16> result{};
    identity(result.data());
    for (const double* matrix : matrices) result = multiplied(result.data(), matrix);
    return result;
}

void require_shape_inventory(
    const PreparedModel& model, const std::set<std::string_view>& expected,
    bool allow_softmesh = false) {
    std::set<std::string_view> actual;
    for (std::size_t index = 0; index < model.source.shape_count; ++index) {
        const std::string_view group(model.source.shapes[index].group);
        if (allow_softmesh && group.find("mt_Softmesh") != std::string_view::npos) continue;
        actual.insert(group);
    }
    if (actual != expected) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED,
             model.resource + "/" + model.model + " shape/profile inventory is not admitted");
    }
}

const ltd_native_scene_named_uv_view* named_uv(
    const PreparedModel& model, std::string_view name) {
    for (std::size_t index = 0; index < model.source.named_uv_channel_count; ++index) {
        const auto& channel = model.source.named_uv_channels[index];
        if (channel.name != nullptr && name == channel.name) return &channel;
    }
    return nullptr;
}

void append_uv(
    std::vector<double>& output,
    const PreparedModel& model,
    const ltd_native_scene_triangle_view& triangle,
    const ltd_native_scene_shape_view& shape,
    std::string_view channel_name,
    bool required) {
    const auto* channel = named_uv(model, channel_name);
    const bool default_channel = shape.texcoord_attribute != nullptr &&
                                 channel_name == shape.texcoord_attribute;
    if (channel == nullptr && !default_channel) {
        if (required) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                 model.resource + "/" + shape.group + " lacks " +
                     std::string(channel_name));
        }
        return;
    }
    for (int corner = 0; corner < 3; ++corner) {
        const std::size_t index = channel != nullptr
            ? static_cast<std::size_t>(triangle.vertex[corner])
            : static_cast<std::size_t>(triangle.texcoord[corner]);
        const double* values = channel != nullptr ? channel->values : model.source.texcoords;
        const double u = values[index * 2];
        const double v = values[index * 2 + 1];
        if (!std::isfinite(u) || !std::isfinite(v)) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
                 model.resource + "/" + shape.group + " has unauthored " +
                     std::string(channel_name) + " on a submitted vertex");
        }
        output.push_back(u);
        output.push_back(v);
    }
}

OwnedDraw compile_geometry(
    const AuthoredDraw& authored, const LtdNativeProjection& projection) {
    const PreparedModel& model = *authored.model;
    std::vector<std::size_t> triangle_indices;
    for (std::size_t index = 0; index < model.source.triangle_count; ++index) {
        if (model.source.triangles[index].group != nullptr &&
            authored.group == model.source.triangles[index].group) {
            triangle_indices.push_back(index);
        }
    }
    if (triangle_indices.empty()) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
             model.resource + "/" + authored.group + " has no triangles");
    }
    std::vector<double> world_positions(model.source.position_count * 3);
    std::vector<double> world_normals(model.source.normal_count * 3);
    std::vector<double> projected(model.source.position_count * 3);
    if (ltd_native_transform_and_project(
            model.positions.data(), model.normals.data(), model.source.position_count,
            authored.transform.data(), &projection, world_positions.data(),
            world_normals.data(), projected.data()) != LTD_NATIVE_GEOMETRY_OK) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_GEOMETRY_FAILED,
             model.resource + "/" + authored.group + " transform/projection failed");
    }
    std::vector<std::int32_t> indices;
    indices.reserve(triangle_indices.size() * 3);
    for (const std::size_t index : triangle_indices) {
        for (const std::int64_t vertex : model.source.triangles[index].vertex) {
            if (vertex > std::numeric_limits<std::int32_t>::max()) {
                fail(LTD_NATIVE_SCENE_ASSEMBLER_RESOURCE_LIMIT,
                     "triangle vertex index exceeds the geometry ABI");
            }
            indices.push_back(static_cast<std::int32_t>(vertex));
        }
    }
    std::vector<LtdNativeTriangleSetup> setup(triangle_indices.size());
    if (ltd_native_setup_triangles(
            projected.data(), model.source.position_count, indices.data(),
            triangle_indices.size(), projection.width, projection.height,
            authored.cull, authored.clockwise, setup.data()) != LTD_NATIVE_GEOMETRY_OK) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_GEOMETRY_FAILED,
             model.resource + "/" + authored.group + " triangle setup failed");
    }
    OwnedDraw output;
    output.resource = model.resource;
    output.model = model.model;
    output.group = authored.group;
    output.profile = authored.profile;
    output.cull = authored.cull;
    output.clockwise = authored.clockwise;
    output.transform = authored.transform;
    output.submitted = triangle_indices.size();
    const bool require_uv2 = authored.profile == LTD_NATIVE_SCENE_PROFILE_HEAD816;
    for (std::size_t local = 0; local < triangle_indices.size(); ++local) {
        if (setup[local].candidate == 0) continue;
        const std::size_t source_index = triangle_indices[local];
        const auto& triangle = model.source.triangles[source_index];
        output.source_triangle_indices.push_back(source_index);
        output.screen.insert(output.screen.end(), setup[local].screen, setup[local].screen + 9);
        output.bounds.insert(output.bounds.end(), {
            setup[local].x0, setup[local].x1, setup[local].y0, setup[local].y1});
        output.denominators.push_back(setup[local].denominator);
        for (int corner = 0; corner < 3; ++corner) {
            const std::size_t vertex = static_cast<std::size_t>(triangle.vertex[corner]);
            const std::size_t normal = static_cast<std::size_t>(triangle.normal[corner]);
            const std::size_t texcoord = static_cast<std::size_t>(triangle.texcoord[corner]);
            output.world_vertices.insert(
                output.world_vertices.end(), world_positions.data() + vertex * 3,
                world_positions.data() + vertex * 3 + 3);
            output.world_normals.insert(
                output.world_normals.end(), world_normals.data() + normal * 3,
                world_normals.data() + normal * 3 + 3);
            output.material_uv.push_back(model.source.texcoords[texcoord * 2]);
            output.material_uv.push_back(model.source.texcoords[texcoord * 2 + 1]);
        }
        append_uv(output.uv0, model, triangle, *authored.shape, "_u0", true);
        if (require_uv2) {
            append_uv(output.uv2, model, triangle, *authored.shape, "_u2", true);
        }
    }
    const std::size_t candidates = output.source_triangle_indices.size();
    if ((!output.uv0.empty() && output.uv0.size() != candidates * 6) ||
        (!output.uv2.empty() && output.uv2.size() != candidates * 6)) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID,
             model.resource + "/" + authored.group + " has a partial named-UV stream");
    }
    return output;
}

}  // namespace

struct ltd_native_scene_assembly {
    ltd_native_scene_assembly_summary summary{};
    ltd_native_scene_camera_view camera{};
    std::vector<OwnedDraw> draws;
};

namespace {

void add_draw(
    std::vector<AuthoredDraw>& draws, PreparedModel& model, std::string group,
    std::uint32_t profile, const std::array<double, 16>& transform,
    std::uint8_t cull = 1, std::uint8_t clockwise = 0) {
    if (draws.size() >= LTD_NATIVE_SCENE_ASSEMBLER_MAX_DRAWS) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_RESOURCE_LIMIT, "scene draw limit exceeded");
    }
    draws.push_back({&model, find_shape(model, group), std::move(group), profile,
                     cull, clockwise, transform});
}

std::unique_ptr<ltd_native_scene_assembly> assemble_internal(
    const ltd_native_scene_assemble_request& request) {
    if (ltd_native_scene_abi_version() != 1 || ltd_native_pose_abi_version() != 1 ||
        ltd_native_geometry_abi_version() != 1) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_MODULE_MISMATCH,
             "linked scene/pose/geometry ABI differs from version 1");
    }
    if (request.parts_catalog_bytes == nullptr || request.parts_catalog_sha256 == nullptr ||
        request.raw_char_info == nullptr || request.assets == nullptr ||
        request.assets->get_model == nullptr || request.icon_pose == nullptr ||
        request.parts_catalog_byte_count == 0 ||
        request.parts_catalog_byte_count > 4U * 1024U * 1024U ||
        request.raw_char_info_byte_count != infinimii::native_parts::kCharInfoSize ||
        (request.view_kind != LTD_NATIVE_SCENE_VIEW_PORTRAIT &&
         request.view_kind != LTD_NATIVE_SCENE_VIEW_FULL_BODY) ||
        (request.raster_size != 128 && request.raster_size != 512)) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_INVALID_ARGUMENT, "invalid scene assemble request");
    }
    if (request.icon_pose->name == nullptr ||
        std::strcmp(request.icon_pose->name, "IconPose") != 0 ||
        !valid_sha256(request.icon_pose->source_sha256) ||
        request.icon_pose->bones == nullptr || request.icon_pose->bone_count == 0) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_SOURCE_SEAL_INVALID,
             "IconPose identity or immutable view is invalid");
    }
    const std::span<const std::uint8_t, 32> expected(
        request.parts_catalog_sha256, 32);
    std::unique_ptr<infinimii::native_parts::Catalog> catalog;
    std::string parts_error;
    if (!infinimii::native_parts::Catalog::Open(
            std::span<const std::uint8_t>(
                request.parts_catalog_bytes, request.parts_catalog_byte_count),
            expected, &catalog, &parts_error)) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_PARTS_FAILED,
             "native Parts catalog open failed: " + parts_error);
    }
    infinimii::native_parts::Selection selection;
    if (!infinimii::native_parts::Select(
            *catalog,
            std::span<const std::uint8_t>(
                request.raw_char_info, request.raw_char_info_byte_count),
            &selection, &parts_error)) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_PARTS_FAILED,
             "native Parts selection failed: " + parts_error);
    }
    reject_broader_model_profiles(selection);
    const auto& char_info = selection.effective_char_info;
    const int height = char_info[40];
    const int build = char_info[41];
    const int ear_scale = char_info[76];
    const int ear_y = char_info[77];
    const int nose_scale = char_info[124];
    const int nose_y = char_info[125];

    ModelStore models(*request.assets, *request.icon_pose);
    auto& body = models.get("BodyBaseDefault", "BodyBaseDefault", true);
    auto& top = models.get("ClothTopsTshirtLong", "ClothTopsTshirtLong", true);
    auto& bottoms = models.get("ClothBottomsPantsLong", "ClothBottomsPantsLong", true);
    auto& shoes = models.get("ClothShoesStandard", "ClothShoesStandard", true);
    const std::string head_resource = selected_model_unit(selection, Logical::kFaceline, true);
    if (head_resource != "MiiHead00" && head_resource != "MiiHead14") {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED,
             "faceline model is outside the authoritative fixture set: " + head_resource);
    }
    auto& head = models.get(head_resource, head_resource, false);
    require_shape_inventory(head, {"Head__mt_Head", "Mask__mt_Mask"});

    static constexpr std::array<std::pair<std::string_view, std::uint32_t>, 13> body_groups{{
        {"BodyArm__mt_Tops", LTD_NATIVE_SCENE_PROFILE_BODY336},
        {"BodyChest__mt_Tops", LTD_NATIVE_SCENE_PROFILE_BODY348},
        {"BodyElbow__mt_Tops", LTD_NATIVE_SCENE_PROFILE_BODY336},
        {"BodyFoot__mt_Socks", LTD_NATIVE_SCENE_PROFILE_BODY324},
        {"BodyHand__mt_Tops", LTD_NATIVE_SCENE_PROFILE_BODY336},
        {"BodyHip__mt_Bottoms", LTD_NATIVE_SCENE_PROFILE_BODY336},
        {"BodyHip__mt_Socks", LTD_NATIVE_SCENE_PROFILE_BODY324},
        {"BodyKnee__mt_Socks", LTD_NATIVE_SCENE_PROFILE_BODY336},
        {"BodyLeg__mt_Socks", LTD_NATIVE_SCENE_PROFILE_BODY324},
        {"BodyShoulder__mt_Tops", LTD_NATIVE_SCENE_PROFILE_BODY348},
        {"BodySole__mt_Socks", LTD_NATIVE_SCENE_PROFILE_BODY324},
        {"BodyThigh__mt_Socks", LTD_NATIVE_SCENE_PROFILE_BODY336},
        {"BodyWaist__mt_Tops", LTD_NATIVE_SCENE_PROFILE_BODY336},
    }};
    std::set<std::string_view> expected_body;
    for (const auto& [group, unused] : body_groups) {
        (void)unused;
        expected_body.insert(group);
    }
    require_shape_inventory(body, expected_body);
    require_shape_inventory(top, {"Tops__mt_Body"}, true);
    require_shape_inventory(bottoms, {"Bottoms__mt_Body"}, true);
    require_shape_inventory(shoes, {"Shoes__mt_Body"});

    const std::size_t body_head_index = find_bone(body, "Head");
    LtdNativeSceneCamera native_camera{};
    const int camera_status = request.view_kind == LTD_NATIVE_SCENE_VIEW_PORTRAIT
        ? ltd_native_resolve_bust_camera(
              build, height, body.world_matrices.data() + body_head_index * 16,
              &native_camera)
        : ltd_native_resolve_full_body_camera(
              build, height, body.world_matrices.data() + body_head_index * 16,
              &native_camera);
    if (camera_status != LTD_NATIVE_SCENE_OK) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_TRANSFORM_FAILED,
             "native body/head/camera transform resolution failed");
    }
    const auto body_transform = scale_matrix(
        native_camera.body_scale[0], native_camera.body_scale[1],
        native_camera.body_scale[2]);
    const double* head_scene = native_camera.head_transform;

    std::vector<AuthoredDraw> authored;
    /* The fixed reference outfit owns these four SystemParam cutlines. */
    static const std::set<std::string_view> hidden_body_groups{
        "BodyArm__mt_Tops", "BodyChest__mt_Tops",
        "BodyHip__mt_Bottoms", "BodySole__mt_Socks"};
    for (const auto& [group, profile] : body_groups) {
        if (hidden_body_groups.count(group) != 0) continue;
        const auto* shape = find_shape(body, group);
        const std::uint32_t expected_skin = profile == LTD_NATIVE_SCENE_PROFILE_BODY324
            ? 2U : profile == LTD_NATIVE_SCENE_PROFILE_BODY336 ? 3U : 4U;
        if (shape->vertex_skin_count != expected_skin) {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED,
                 std::string(group) + " skin-count program changed");
        }
        add_draw(authored, body, std::string(group), profile, body_transform);
    }
    add_draw(authored, top, "Tops__mt_Body", LTD_NATIVE_SCENE_PROFILE_OUTFIT_TOPS984,
             body_transform, 0);
    add_draw(authored, bottoms, "Bottoms__mt_Body",
             LTD_NATIVE_SCENE_PROFILE_OUTFIT_BOTTOMS936, body_transform, 0);
    add_draw(authored, shoes, "Shoes__mt_Body",
             LTD_NATIVE_SCENE_PROFILE_OUTFIT_SHOES912, body_transform, 0);

    const auto* head_shape = find_shape(head, "Head__mt_Head");
    const auto* mask_shape = find_shape(head, "Mask__mt_Mask");
    add_draw(authored, head, "Head__mt_Head", LTD_NATIVE_SCENE_PROFILE_HEAD816,
             chain({head_scene, rigid_shape_matrix(head, *head_shape)}));

    const std::string ear_resource = selected_model_unit(selection, Logical::kEar);
    if (!ear_resource.empty()) {
        if (ear_resource != "MiiEar00") {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED,
                 "ear model is outside the authoritative fixture set: " + ear_resource);
        }
        auto& ear = models.get(ear_resource, ear_resource, false);
        require_shape_inventory(ear, {"Ear__mt_Ear"});
        const auto* shape = find_shape(ear, "Ear__mt_Ear");
        std::array<double, 16> attachment{};
        std::copy(bone_matrix(head, "set_ear"), bone_matrix(head, "set_ear") + 16,
                  attachment.begin());
        attachment[7] += (static_cast<double>(ear_y) - 4.0) * -0.015;
        const double size = (static_cast<double>(ear_scale) * 0.175 + 0.75) / 1.1;
        const auto local_scale = scale_matrix(size, size, size);
        const auto right = chain({attachment.data(), local_scale.data(),
                                  rigid_shape_matrix(ear, *shape)});
        const auto reflection = scale_matrix(-1.0, 1.0, 1.0);
        const auto left = multiplied(reflection.data(), right.data());
        add_draw(authored, ear, "Ear__mt_Ear", LTD_NATIVE_SCENE_PROFILE_EAR372,
                 chain({head_scene, right.data()}));
        add_draw(authored, ear, "Ear__mt_Ear", LTD_NATIVE_SCENE_PROFILE_EAR372,
                 chain({head_scene, left.data()}), 1, 1);
    }

    add_draw(authored, head, "Mask__mt_Mask", LTD_NATIVE_SCENE_PROFILE_MASK0,
             chain({head_scene, rigid_shape_matrix(head, *mask_shape)}), 0);

    for (const Logical logical : {Logical::kHair, Logical::kHairFront}) {
        const std::string resource = selected_model_unit(selection, logical);
        if (resource.empty()) continue;
        std::uint32_t profile = 0;
        if (resource == "MiiHairAllLegacy121") profile = LTD_NATIVE_SCENE_PROFILE_HAIR612;
        else if (resource == "MiiHairBack000" || resource == "MiiHairFront029") {
            profile = LTD_NATIVE_SCENE_PROFILE_HAIR564_EQUAL_ENDPOINT;
        } else {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED,
                 "hair model is outside the authoritative fixture set: " + resource);
        }
        auto& hair = models.get(resource, resource, false);
        require_shape_inventory(hair, {"Hair__mt_Hair"});
        const auto* shape = find_shape(hair, "Hair__mt_Hair");
        add_draw(authored, hair, "Hair__mt_Hair", profile,
                 chain({head_scene, bone_matrix(head, "set_hair"),
                        rigid_shape_matrix(hair, *shape)}));
    }

    const std::string nose_resource = selected_model_unit(selection, Logical::kNose);
    if (!nose_resource.empty()) {
        if (nose_resource != "MiiNose06") {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED,
                 "nose model is outside the authoritative fixture set: " + nose_resource);
        }
        auto& nose = models.get(nose_resource, nose_resource, false);
        require_shape_inventory(nose, {"Nose__mt_Nose", "NoseLine__mt_NoseLine"});
        const double size = (static_cast<double>(nose_scale) * 0.175 + 0.4) / 1.1;
        const double y = (static_cast<double>(nose_y) - 9.0) * -0.015;
        const auto offset = translation_matrix(0.0, y, 0.0);
        const auto local_scale = scale_matrix(size, size, size);
        const auto attachment = chain(
            {head_scene, bone_matrix(head, "set_nose"), offset.data(), local_scale.data()});
        const auto* nose_shape = find_shape(nose, "Nose__mt_Nose");
        const auto* line_shape = find_shape(nose, "NoseLine__mt_NoseLine");
        add_draw(authored, nose, "Nose__mt_Nose", LTD_NATIVE_SCENE_PROFILE_NOSE756,
                 chain({attachment.data(), rigid_shape_matrix(nose, *nose_shape)}));
        add_draw(authored, nose, "NoseLine__mt_NoseLine",
                 LTD_NATIVE_SCENE_PROFILE_NOSE_LINE12,
                 chain({attachment.data(), rigid_shape_matrix(nose, *line_shape)}));
    }

    const std::string beard_resource = selected_model_unit(selection, Logical::kBeard);
    if (!beard_resource.empty()) {
        if (beard_resource != "MiiBeard02") {
            fail(LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED,
                 "beard model is outside the authoritative fixture set: " + beard_resource);
        }
        auto& beard = models.get(beard_resource, beard_resource, false);
        require_shape_inventory(beard, {"Beard__mt_Beard"});
        const auto* shape = find_shape(beard, "Beard__mt_Beard");
        add_draw(authored, beard, "Beard__mt_Beard", LTD_NATIVE_SCENE_PROFILE_BEARD468,
                 chain({head_scene, bone_matrix(head, "set_beard"),
                        rigid_shape_matrix(beard, *shape)}));
    }

    const std::string glass_resource = selected_model_unit(selection, Logical::kGlassPrimary);
    if (!glass_resource.empty()) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED,
             "glass profiles are outside the authoritative four-fixture admission: " +
                 glass_resource);
    }

    std::vector<LtdNativeDrawRecord> records(authored.size());
    std::vector<std::size_t> order(authored.size());
    for (std::size_t index = 0; index < authored.size(); ++index) {
        records[index] = {authored[index].group.c_str(), 0, 1};
    }
    if (ltd_native_schedule_draws(
            records.data(), records.size(), order.data(), order.size()) !=
        LTD_NATIVE_SCENE_OK) {
        fail(LTD_NATIVE_SCENE_ASSEMBLER_SCHEDULE_FAILED,
             "native ModelSortKey schedule rejected the assembled draw inventory");
    }
    LtdNativeProjection projection{};
    projection.kind = LTD_NATIVE_PERSPECTIVE;
    projection.width = request.raster_size;
    projection.height = request.raster_size;
    projection.camera_position[0] = 0.0;
    projection.camera_position[1] = native_camera.camera_position_y;
    projection.camera_position[2] = native_camera.camera_distance;
    projection.camera_target[0] = 0.0;
    projection.camera_target[1] = native_camera.camera_at_y;
    projection.camera_target[2] = 0.0;
    projection.camera_up[1] = 1.0;
    projection.vertical_fov_degrees = native_camera.vertical_fov_degrees;
    projection.horizontal_projection_scale = native_camera.horizontal_projection_scale;

    auto output = std::make_unique<ltd_native_scene_assembly>();
    output->draws.reserve(authored.size());
    for (const std::size_t index : order) {
        output->draws.push_back(compile_geometry(authored[index], projection));
    }
    output->summary.abi_version = LTD_NATIVE_SCENE_ASSEMBLER_ABI_VERSION;
    output->summary.view_kind = request.view_kind;
    output->summary.raster_size = request.raster_size;
    output->summary.model_count = static_cast<std::uint32_t>(models.size());
    output->summary.draw_count = static_cast<std::uint32_t>(output->draws.size());
    output->summary.source_seals_validated = 1;
    output->summary.native_parts_selected = 1;
    output->summary.production_activation_ready = 0;
    for (const auto& draw : output->draws) {
        output->summary.submitted_triangle_count += draw.submitted;
        output->summary.candidate_triangle_count += draw.source_triangle_indices.size();
    }
    output->camera.projection_kind = 1;
    output->camera.width = request.raster_size;
    output->camera.height = request.raster_size;
    output->camera.camera_position[1] = native_camera.camera_position_y;
    output->camera.camera_position[2] = native_camera.camera_distance;
    output->camera.camera_target[1] = native_camera.camera_at_y;
    output->camera.camera_up[1] = 1.0;
    output->camera.vertical_fov_degrees = native_camera.vertical_fov_degrees;
    output->camera.horizontal_projection_scale = native_camera.horizontal_projection_scale;
    std::copy(native_camera.body_scale, native_camera.body_scale + 3,
              output->camera.body_scale);
    std::copy(native_camera.head_transform, native_camera.head_transform + 16,
              output->camera.head_transform);
    return output;
}

}  // namespace

extern "C" {

std::uint32_t LTD_NATIVE_SCENE_ASSEMBLER_CALL ltd_native_scene_assembler_abi_version(void) {
    return LTD_NATIVE_SCENE_ASSEMBLER_ABI_VERSION;
}

const char* LTD_NATIVE_SCENE_ASSEMBLER_CALL ltd_native_scene_assembler_contract_sha256(void) {
    return LTD_NATIVE_SCENE_ASSEMBLER_CONTRACT_SHA256;
}

const char* LTD_NATIVE_SCENE_ASSEMBLER_CALL ltd_native_scene_assembler_status_name(
    ltd_native_scene_assembler_status status) {
    switch (status) {
        case LTD_NATIVE_SCENE_ASSEMBLER_OK: return "OK";
        case LTD_NATIVE_SCENE_ASSEMBLER_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
        case LTD_NATIVE_SCENE_ASSEMBLER_MODULE_MISMATCH: return "MODULE_MISMATCH";
        case LTD_NATIVE_SCENE_ASSEMBLER_PARTS_FAILED: return "PARTS_FAILED";
        case LTD_NATIVE_SCENE_ASSEMBLER_ASSET_MISSING: return "ASSET_MISSING";
        case LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID: return "ASSET_INVALID";
        case LTD_NATIVE_SCENE_ASSEMBLER_SOURCE_SEAL_INVALID: return "SOURCE_SEAL_INVALID";
        case LTD_NATIVE_SCENE_ASSEMBLER_PROFILE_UNIMPLEMENTED: return "PROFILE_UNIMPLEMENTED";
        case LTD_NATIVE_SCENE_ASSEMBLER_POSE_FAILED: return "POSE_FAILED";
        case LTD_NATIVE_SCENE_ASSEMBLER_TRANSFORM_FAILED: return "TRANSFORM_FAILED";
        case LTD_NATIVE_SCENE_ASSEMBLER_GEOMETRY_FAILED: return "GEOMETRY_FAILED";
        case LTD_NATIVE_SCENE_ASSEMBLER_SCHEDULE_FAILED: return "SCHEDULE_FAILED";
        case LTD_NATIVE_SCENE_ASSEMBLER_RESOURCE_LIMIT: return "RESOURCE_LIMIT";
        case LTD_NATIVE_SCENE_ASSEMBLER_ALLOCATION_FAILED: return "ALLOCATION_FAILED";
        case LTD_NATIVE_SCENE_ASSEMBLER_PROVIDER_FAILED: return "PROVIDER_FAILED";
        default: return "UNKNOWN";
    }
}

int LTD_NATIVE_SCENE_ASSEMBLER_CALL ltd_native_scene_assembler_activation_ready(void) {
    return 0;
}

ltd_native_scene_assembler_status LTD_NATIVE_SCENE_ASSEMBLER_CALL
ltd_native_scene_assemble(
    const ltd_native_scene_assemble_request* request,
    ltd_native_scene_assembly** output,
    char* error,
    std::size_t error_capacity) {
    if (output == nullptr) return LTD_NATIVE_SCENE_ASSEMBLER_INVALID_ARGUMENT;
    *output = nullptr;
    set_error(error, error_capacity, "");
    if (request == nullptr) return LTD_NATIVE_SCENE_ASSEMBLER_INVALID_ARGUMENT;
    try {
        auto assembly = assemble_internal(*request);
        *output = assembly.release();
        return LTD_NATIVE_SCENE_ASSEMBLER_OK;
    } catch (const AssemblyFailure& failure) {
        set_error(error, error_capacity, failure.what());
        return failure.status;
    } catch (const std::bad_alloc&) {
        set_error(error, error_capacity, "scene assembly allocation failed");
        return LTD_NATIVE_SCENE_ASSEMBLER_ALLOCATION_FAILED;
    } catch (const std::exception& failure) {
        set_error(error, error_capacity, failure.what());
        return LTD_NATIVE_SCENE_ASSEMBLER_ASSET_INVALID;
    }
}

void LTD_NATIVE_SCENE_ASSEMBLER_CALL ltd_native_scene_assembly_destroy(
    ltd_native_scene_assembly* assembly) {
    delete assembly;
}

ltd_native_scene_assembler_status LTD_NATIVE_SCENE_ASSEMBLER_CALL
ltd_native_scene_assembly_get_summary(
    const ltd_native_scene_assembly* assembly,
    ltd_native_scene_assembly_summary* output) {
    if (assembly == nullptr || output == nullptr) {
        return LTD_NATIVE_SCENE_ASSEMBLER_INVALID_ARGUMENT;
    }
    *output = assembly->summary;
    return LTD_NATIVE_SCENE_ASSEMBLER_OK;
}

ltd_native_scene_assembler_status LTD_NATIVE_SCENE_ASSEMBLER_CALL
ltd_native_scene_assembly_get_camera(
    const ltd_native_scene_assembly* assembly,
    ltd_native_scene_camera_view* output) {
    if (assembly == nullptr || output == nullptr) {
        return LTD_NATIVE_SCENE_ASSEMBLER_INVALID_ARGUMENT;
    }
    *output = assembly->camera;
    return LTD_NATIVE_SCENE_ASSEMBLER_OK;
}

ltd_native_scene_assembler_status LTD_NATIVE_SCENE_ASSEMBLER_CALL
ltd_native_scene_assembly_get_draw(
    const ltd_native_scene_assembly* assembly,
    std::size_t index,
    ltd_native_scene_draw_view* output) {
    if (assembly == nullptr || output == nullptr || index >= assembly->draws.size()) {
        return LTD_NATIVE_SCENE_ASSEMBLER_INVALID_ARGUMENT;
    }
    const auto& draw = assembly->draws[index];
    *output = {};
    output->resource_name = draw.resource.c_str();
    output->model_name = draw.model.c_str();
    output->group = draw.group.c_str();
    output->profile = draw.profile;
    output->blend = draw.blend;
    output->depth_write = draw.depth_write;
    output->cull_back_faces = draw.cull;
    output->clockwise_front_face = draw.clockwise;
    std::copy(draw.transform.begin(), draw.transform.end(), output->transform);
    output->submitted_triangle_count = draw.submitted;
    output->candidate_triangle_count = draw.source_triangle_indices.size();
    output->source_triangle_indices = draw.source_triangle_indices.data();
    output->world_vertices = draw.world_vertices.data();
    output->world_normals = draw.world_normals.data();
    output->screen = draw.screen.data();
    output->bounds = draw.bounds.data();
    output->denominators = draw.denominators.data();
    output->material_uv = draw.material_uv.empty() ? nullptr : draw.material_uv.data();
    output->uv0 = draw.uv0.empty() ? nullptr : draw.uv0.data();
    output->uv2 = draw.uv2.empty() ? nullptr : draw.uv2.data();
    return LTD_NATIVE_SCENE_ASSEMBLER_OK;
}

}  // extern "C"
