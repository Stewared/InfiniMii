#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#define LTD_NATIVE_MATERIAL_PROVIDER_TRUSTED_INTERNAL
#include "native_runtime_material_adapter.h"

#include "native_facepaint_decode.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstring>
#include <fstream>
#include <limits>
#include <new>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace infinimii::native_runtime_material_adapter {
namespace {

struct Failure final {
  Status status;
  std::string message;
};

[[noreturn]] void fail(Status status, std::string message) {
  throw Failure{status, std::move(message)};
}

void assign_error(std::string* output, std::string_view message) {
  if (output != nullptr) *output = message;
}

struct FixtureRecord final {
  const char* name;
  const char* ltd_path;
  const char* ltd_sha256;
  std::uint64_t ltd_byte_count;
  const char* char_info_sha256;
  std::uint8_t has_user_facepaint;
  const char* user_facepaint_rgba8_sha256;
  std::uint32_t noseline_scene_draw_index;
  std::uint32_t noseline_chain_index;
  const char* noseline_decoded_mips_sha256;
};

struct CaseRecord final {
  std::uint32_t fixture_index;
  std::uint32_t view_kind;
  std::uint32_t raster_size;
  std::uint32_t first_material;
  std::uint32_t material_count;
  const char* publication_sha256;
};

struct ArtifactRecord final {
  std::uint32_t role;
  const char* path;
  const char* sha256;
  std::uint64_t byte_count;
};

struct LevelRecord final {
  std::uint32_t level;
  std::uint32_t width;
  std::uint32_t height;
  const char* path;
  const char* sha256;
  std::uint64_t byte_count;
};

struct ChainRecord final {
  const char* source_key;
  const char* texture_name;
  const char* source_format;
  const char* authored_path;
  const char* authored_sha256;
  std::uint64_t authored_byte_count;
  const char* manifest_path;
  const char* manifest_sha256;
  std::uint64_t manifest_byte_count;
  std::uint32_t color_space;
  std::uint32_t first_level;
  std::uint32_t level_count;
};

struct BindingRecord final {
  std::uint8_t role;
  std::uint32_t chain_index;
  std::uint8_t address_u;
  std::uint8_t address_v;
  std::uint8_t mip_filter;
  std::uint8_t hardware_srgb;
};

struct MaterialRecord final {
  std::uint32_t scene_draw_index;
  const char* source_key;
  const char* material_name;
  const char* model_key;
  const char* resource_name;
  const char* group;
  std::int32_t program;
  std::uint16_t family;
  std::int16_t priority;
  std::uint32_t flags;
  std::array<std::uint64_t, 39> double_bits;
  std::uint8_t has_camera;
  std::uint8_t perspective_correct;
  std::uint8_t mask_facepaint_mode;
  std::uint32_t first_binding;
  std::uint32_t binding_count;
  std::array<std::uint32_t, 4> evidence_indices;
};

#include "generated/native_runtime_material_catalog.inc"

static_assert(std::size(generated::kFixtures) == 4);
static_assert(std::size(generated::kCases) == 16);

bool valid_hex(std::string_view value) {
  return value.size() == 64 &&
      std::all_of(value.begin(), value.end(), [](char byte) {
        return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
      });
}

std::string hex(std::span<const std::uint8_t> bytes) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
    fail(Status::kSourceMismatch, "could not open SHA-256 provider");
  }
  const auto close = [&]() {
    if (hash != nullptr) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
  };
  if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0) {
    close();
    fail(Status::kSourceMismatch, "could not create SHA-256 hash");
  }
  std::size_t cursor = 0;
  while (cursor < bytes.size()) {
    const std::size_t count = std::min<std::size_t>(
        bytes.size() - cursor, std::numeric_limits<ULONG>::max());
    if (BCryptHashData(hash, const_cast<PUCHAR>(bytes.data() + cursor),
                       static_cast<ULONG>(count), 0) < 0) {
      close();
      fail(Status::kSourceMismatch, "could not update SHA-256 hash");
    }
    cursor += count;
  }
  std::array<std::uint8_t, 32> digest{};
  if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) {
    close();
    fail(Status::kSourceMismatch, "could not finish SHA-256 hash");
  }
  close();
  static constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(64);
  for (const std::uint8_t byte : digest) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 15]);
  }
  return result;
}

std::vector<std::uint8_t> read_authenticated(
    const std::filesystem::path& root, const char* logical_path,
    const char* expected_sha256, std::uint64_t expected_count,
    std::uint64_t* authenticated_bytes) {
  if (logical_path == nullptr || expected_sha256 == nullptr ||
      !valid_hex(expected_sha256)) {
    fail(Status::kCatalogMismatch, "catalog source record is malformed");
  }
  const std::filesystem::path path = root / std::filesystem::path(logical_path);
  std::error_code ec;
  const auto weak_root = std::filesystem::weakly_canonical(root, ec);
  if (ec || weak_root.empty())
    fail(Status::kInvalidArgument, "repository root cannot be canonicalized");
  const auto weak_path = std::filesystem::weakly_canonical(path, ec);
  if (ec || weak_path.empty()) fail(Status::kAssetMissing, std::string("source is missing: ") + logical_path);
  /* logical_path is compile-time generated and catalog-pinned.  `../` is
     required for authenticated converted assets adjacent to dcmp; no caller
     path participates in this join. */
  std::ifstream stream(weak_path, std::ios::binary);
  if (!stream) fail(Status::kAssetMissing, std::string("source is missing: ") + logical_path);
  stream.seekg(0, std::ios::end);
  const auto end = stream.tellg();
  if (end < 0 || static_cast<std::uint64_t>(end) != expected_count ||
      expected_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    fail(Status::kAssetMismatch, std::string("source byte count changed: ") + logical_path);
  }
  std::vector<std::uint8_t> result(static_cast<std::size_t>(expected_count));
  stream.seekg(0, std::ios::beg);
  if (!result.empty()) stream.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(result.size()));
  if (!stream || hex(result) != expected_sha256) {
    fail(Status::kAssetMismatch, std::string("source SHA-256 changed: ") + logical_path);
  }
  if (authenticated_bytes != nullptr) *authenticated_bytes += expected_count;
  return result;
}

double as_double(std::uint64_t bits) { return std::bit_cast<double>(bits); }

void append_u32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8)
    bytes.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append_u64(std::vector<std::uint8_t>& bytes, std::uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8)
    bytes.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append_text(std::vector<std::uint8_t>& bytes, std::string_view value) {
  if (value.size() > std::numeric_limits<std::uint32_t>::max())
    fail(Status::kCatalogMismatch, "catalog text exceeds canonical bounds");
  append_u32(bytes, static_cast<std::uint32_t>(value.size()));
  bytes.insert(bytes.end(), value.begin(), value.end());
}

std::string catalog_digest() {
  static constexpr char domain[] = "ltd.native.runtime-material-catalog.v1\0";
  std::vector<std::uint8_t> bytes(domain, domain + sizeof(domain) - 1);
  append_u32(bytes, static_cast<std::uint32_t>(std::size(generated::kFixtures)));
  append_u32(bytes, static_cast<std::uint32_t>(std::size(generated::kCases)));
  append_u32(bytes, static_cast<std::uint32_t>(std::size(generated::kArtifacts)));
  append_u32(bytes, static_cast<std::uint32_t>(std::size(generated::kLevels)));
  append_u32(bytes, static_cast<std::uint32_t>(std::size(generated::kChains)));
  append_u32(bytes, static_cast<std::uint32_t>(std::size(generated::kBindings)));
  append_u32(bytes, static_cast<std::uint32_t>(std::size(generated::kMaterials)));
  for (const auto& item : generated::kFixtures) {
    append_text(bytes, item.name); append_text(bytes, item.ltd_path);
    append_text(bytes, item.ltd_sha256); append_u64(bytes, item.ltd_byte_count);
    append_text(bytes, item.char_info_sha256);
    append_u32(bytes, item.has_user_facepaint);
    append_text(bytes, item.user_facepaint_rgba8_sha256);
    append_u32(bytes, item.noseline_scene_draw_index);
    append_u32(bytes, item.noseline_chain_index);
    append_text(bytes, item.noseline_decoded_mips_sha256);
  }
  for (const auto& item : generated::kCases) {
    append_u32(bytes, item.fixture_index); append_u32(bytes, item.view_kind);
    append_u32(bytes, item.raster_size); append_u32(bytes, item.first_material);
    append_u32(bytes, item.material_count); append_text(bytes, item.publication_sha256);
  }
  for (const auto& item : generated::kArtifacts) {
    append_u32(bytes, item.role); append_text(bytes, item.path);
    append_text(bytes, item.sha256); append_u64(bytes, item.byte_count);
  }
  for (const auto& item : generated::kLevels) {
    append_u32(bytes, item.level); append_u32(bytes, item.width);
    append_u32(bytes, item.height); append_text(bytes, item.path);
    append_text(bytes, item.sha256); append_u64(bytes, item.byte_count);
  }
  for (const auto& item : generated::kChains) {
    append_text(bytes, item.source_key); append_text(bytes, item.texture_name);
    append_text(bytes, item.source_format); append_text(bytes, item.authored_path);
    append_text(bytes, item.authored_sha256); append_u64(bytes, item.authored_byte_count);
    append_text(bytes, item.manifest_path); append_text(bytes, item.manifest_sha256);
    append_u64(bytes, item.manifest_byte_count); append_u32(bytes, item.color_space);
    append_u32(bytes, item.first_level); append_u32(bytes, item.level_count);
  }
  for (const auto& item : generated::kBindings) {
    append_u32(bytes, item.role); append_u32(bytes, item.chain_index);
    append_u32(bytes, item.address_u); append_u32(bytes, item.address_v);
    append_u32(bytes, item.mip_filter); append_u32(bytes, item.hardware_srgb);
  }
  for (const auto& item : generated::kMaterials) {
    append_u32(bytes, item.scene_draw_index); append_text(bytes, item.source_key);
    append_text(bytes, item.material_name); append_text(bytes, item.model_key);
    append_text(bytes, item.resource_name); append_text(bytes, item.group);
    append_u32(bytes, static_cast<std::uint32_t>(item.program));
    append_u32(bytes, item.family);
    append_u32(bytes, static_cast<std::uint32_t>(item.priority));
    append_u32(bytes, item.flags);
    for (const auto value : item.double_bits) append_u64(bytes, value);
    append_u32(bytes, item.has_camera); append_u32(bytes, item.perspective_correct);
    append_u32(bytes, item.mask_facepaint_mode); append_u32(bytes, item.first_binding);
    append_u32(bytes, item.binding_count);
    for (const auto value : item.evidence_indices) append_u32(bytes, value);
  }
  return hex(bytes);
}

std::string noseline_digest(const native_runtime::DecodedTextureMipChainView& view) {
  static constexpr char domain[] = "ltd.noseline12.mips.v1\0";
  std::vector<std::uint8_t> canonical(domain, domain + sizeof(domain) - 1);
  append_u32(canonical, static_cast<std::uint32_t>(view.levels.size()));
  for (const auto& level : view.levels) {
    append_u32(canonical, level.width);
    append_u32(canonical, level.height);
    const auto bytes = std::as_bytes(level.rgba64);
    const auto* begin = reinterpret_cast<const std::uint8_t*>(bytes.data());
    canonical.insert(canonical.end(), begin, begin + bytes.size());
  }
  return hex(canonical);
}

const FixtureRecord& fixture_for(const BuildRequest& request) {
  const std::string ltd_sha = hex(request.share_mii);
  const std::string char_sha = hex(request.effective_char_info);
  const FixtureRecord* found = nullptr;
  for (const auto& fixture : generated::kFixtures) {
    if (ltd_sha == fixture.ltd_sha256) {
      if (request.share_mii.size() != fixture.ltd_byte_count ||
          char_sha != fixture.char_info_sha256) {
        fail(Status::kSourceMismatch,
             "accepted LTD identity does not match its exact effective CharInfo");
      }
      found = &fixture;
      break;
    }
  }
  if (found == nullptr) fail(Status::kFixtureUnsupported, "LTD fixture is outside the accepted four-fixture authority");
  return *found;
}

std::uint32_t fixture_index(const FixtureRecord& fixture) {
  return static_cast<std::uint32_t>(&fixture - std::data(generated::kFixtures));
}

const CaseRecord& case_for(std::uint32_t index, std::uint32_t view, std::uint32_t size) {
  for (const auto& item : generated::kCases) {
    if (item.fixture_index == index && item.view_kind == view && item.raster_size == size) return item;
  }
  fail(Status::kCaseUnsupported, "view/raster size has no accepted material case");
}

std::wstring wide_key(std::string_view value) {
  if (value.empty() || value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    fail(Status::kCatalogMismatch, "catalog mip key is empty or too long");
  }
  const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                        static_cast<int>(value.size()), nullptr, 0);
  if (count <= 0) fail(Status::kCatalogMismatch, "catalog mip key is not valid UTF-8");
  std::wstring output(static_cast<std::size_t>(count), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), output.data(), count) != count) {
    fail(Status::kCatalogMismatch, "catalog mip key conversion changed length");
  }
  return output;
}

}  // namespace

struct MaterialBundle::Storage final {
  struct ArtifactOwner final {
    std::vector<std::uint8_t> bytes;
    ltd_native_material_source_document source{};
  };
  struct ChainOwner final {
    std::vector<std::uint8_t> authored;
    std::vector<std::uint8_t> manifest;
    std::vector<std::vector<std::uint8_t>> level_bytes;
    std::vector<ltd_native_material_mip_level_source> levels;
    ltd_native_material_mip_chain_source source{};
  };
  struct MaterialOwner final {
    ltd_native_normalized_material_view normalized{};
    std::array<ltd_native_material_source_document, 4> evidence{};
    ltd_native_material_normalized_source source{};
  };

  std::vector<ArtifactOwner> artifacts;
  std::vector<ChainOwner> chains;
  std::vector<MaterialOwner> materials;
  std::vector<ltd_native_material_mip_chain_source> unique_chain_sources;
  std::vector<ltd_native_material_normalized_source> trusted_material_sources;
  std::vector<std::uint32_t> trusted_scene_draw_indices;
  std::vector<MaterialPublicationView> publications;
  std::vector<std::uint8_t> user_facepaint_rgba8;
  std::vector<double> user_facepaint_rgba64;
  std::vector<double> generated_head_rgba64;
  std::vector<double> generated_mask_rgba64;
  std::vector<double> noseline_rgba64;
  ltd_native_noseline_pipeline_texture noseline_texture{};
  NoseLinePublicationView noseline{};
  std::string head_key;
  std::string mask_key;
  std::string ugc_key;
  ltd_native_material_face_views face{};
  UgcPublicationView ugc{};
  Report report{};
  native_runtime::DecodedAssetCache* decoded_assets = nullptr;
};

MaterialBundle::MaterialBundle() : storage_(std::make_shared<Storage>()) {}
MaterialBundle::~MaterialBundle() = default;
MaterialBundle::MaterialBundle(MaterialBundle&&) noexcept = default;
MaterialBundle& MaterialBundle::operator=(MaterialBundle&&) noexcept = default;

std::span<const MaterialPublicationView> MaterialBundle::publications() const {
  return storage_->publications;
}

std::span<const ltd_native_material_mip_chain_source> MaterialBundle::unique_mip_chains() const {
  return storage_->unique_chain_sources;
}

const ltd_native_material_face_views& MaterialBundle::face_views() const { return storage_->face; }
UgcPublicationView MaterialBundle::ugc() const { return storage_->ugc; }
NoseLinePublicationView MaterialBundle::noseline() const { return storage_->noseline; }
const Report& MaterialBundle::report() const { return storage_->report; }

Status MaterialBundle::Publish(ltd_native_material_provider* provider, std::string* error) const {
  if (provider == nullptr) {
    assign_error(error, "material provider is null");
    return Status::kInvalidArgument;
  }
  char detail[512]{};
  for (const auto& chain : storage_->unique_chain_sources) {
    const auto status = ltd_native_material_provider_publish_mip_chain(provider, &chain, detail, sizeof(detail));
    if (status != LTD_NATIVE_MATERIAL_PROVIDER_OK) {
      assign_error(error, detail);
      return Status::kProviderFailed;
    }
  }
  for (const auto& material : storage_->materials) {
    const auto status = ltd_native_material_provider_publish_material(provider, &material.source, detail, sizeof(detail));
    if (status != LTD_NATIVE_MATERIAL_PROVIDER_OK) {
      assign_error(error, detail);
      return Status::kProviderFailed;
    }
  }
  if (error != nullptr) error->clear();
  return Status::kOk;
}

Status MaterialBundle::PublishTrusted(ltd_native_material_provider* provider,
                                      std::string* error) const {
  if (provider == nullptr || storage_ == nullptr ||
      storage_->decoded_assets == nullptr ||
      storage_->trusted_material_sources.empty() ||
      storage_->trusted_scene_draw_indices.size() !=
          storage_->trusted_material_sources.size()) {
    assign_error(error, "trusted material bundle/provider is incomplete");
    return Status::kInvalidArgument;
  }
  ltd_native_material_trusted_bundle batch{};
  batch.abi_version = 1;
  batch.producer_contract_sha256 = kContractSha256.data();
  batch.decoded_cache = storage_->decoded_assets;
  batch.catalog_sha256 = storage_->report.catalog_sha256.data();
  batch.source_bundle_sha256 = storage_->report.source_bundle_sha256.data();
  batch.publication_sha256 = storage_->report.publication_sha256.data();
  batch.share_mii_sha256 = storage_->report.share_mii_sha256.data();
  batch.effective_char_info_sha256 =
      storage_->report.effective_char_info_sha256.data();
  batch.view_kind = storage_->report.view_kind;
  batch.raster_size = storage_->report.raster_size;
  batch.mip_chains = storage_->unique_chain_sources.data();
  batch.mip_chain_count = static_cast<std::uint32_t>(
      storage_->unique_chain_sources.size());
  batch.materials = storage_->trusted_material_sources.data();
  batch.scene_draw_indices = storage_->trusted_scene_draw_indices.data();
  batch.material_count = static_cast<std::uint32_t>(
      storage_->trusted_material_sources.size());
  batch.lease_context = const_cast<std::shared_ptr<Storage>*>(&storage_);
  batch.authenticate = +[](void* context,
                           const ltd_native_material_trusted_bundle* value)
      -> int {
    if (context == nullptr || value == nullptr) return 0;
    const auto& owner = *static_cast<const std::shared_ptr<Storage>*>(context);
    if (owner == nullptr) return 0;
    const auto same = [](const char* text, std::string_view expected) {
      return text != nullptr && std::string_view(text) == expected;
    };
    return value->abi_version == 1 && value->reserved == 0 &&
        same(value->producer_contract_sha256, kContractSha256) &&
        value->decoded_cache == owner->decoded_assets &&
        same(value->catalog_sha256, owner->report.catalog_sha256) &&
        same(value->source_bundle_sha256, owner->report.source_bundle_sha256) &&
        same(value->publication_sha256, owner->report.publication_sha256) &&
        same(value->share_mii_sha256, owner->report.share_mii_sha256) &&
        same(value->effective_char_info_sha256,
             owner->report.effective_char_info_sha256) &&
        value->view_kind == owner->report.view_kind &&
        value->raster_size == owner->report.raster_size &&
        value->mip_chains == owner->unique_chain_sources.data() &&
        value->mip_chain_count == owner->unique_chain_sources.size() &&
        value->materials == owner->trusted_material_sources.data() &&
        value->scene_draw_indices == owner->trusted_scene_draw_indices.data() &&
        value->material_count == owner->trusted_material_sources.size();
  };
  batch.retain = +[](void* context) -> void* {
    if (context == nullptr) return nullptr;
    try {
      return new std::shared_ptr<Storage>(
          *static_cast<const std::shared_ptr<Storage>*>(context));
    } catch (...) {
      return nullptr;
    }
  };
  batch.release = +[](void* lease) {
    delete static_cast<std::shared_ptr<Storage>*>(lease);
  };
  char detail[512]{};
  const auto status = ltd_native_material_provider_publish_trusted_bundle(
      provider, &batch, detail, sizeof(detail));
  if (status != LTD_NATIVE_MATERIAL_PROVIDER_OK) {
    assign_error(error, detail);
    return Status::kProviderFailed;
  }
  if (error != nullptr) error->clear();
  return Status::kOk;
}

std::string_view CatalogSha256() { return generated::kCatalogSha256; }
std::string_view SourceBundleSha256() { return generated::kSourceBundleSha256; }

std::string_view StatusName(Status status) {
  switch (status) {
    case Status::kOk: return "ok";
    case Status::kInvalidArgument: return "invalid_argument";
    case Status::kModuleMismatch: return "module_mismatch";
    case Status::kCatalogMismatch: return "catalog_mismatch";
    case Status::kFixtureUnsupported: return "fixture_unsupported";
    case Status::kSourceMismatch: return "source_mismatch";
    case Status::kCaseUnsupported: return "case_unsupported";
    case Status::kAssetMissing: return "asset_missing";
    case Status::kAssetMismatch: return "asset_mismatch";
    case Status::kCacheFailed: return "cache_failed";
    case Status::kFaceMismatch: return "face_mismatch";
    case Status::kProviderFailed: return "provider_failed";
    case Status::kAllocationFailed: return "allocation_failed";
  }
  return "unknown";
}

Status Build(const BuildRequest& request, MaterialBundle* output, std::string* error) {
  if (output == nullptr || request.repository_root.empty() || request.share_mii.empty() ||
      request.effective_char_info.size() != kCharInfoSize || request.decoded_assets == nullptr ||
      request.face_plan == nullptr || !valid_hex(request.expected_catalog_sha256) ||
      !valid_hex(request.expected_source_bundle_sha256)) {
    assign_error(error, "native material adapter request is invalid");
    return Status::kInvalidArgument;
  }
  if (request.expected_catalog_sha256 != generated::kCatalogSha256 ||
      request.expected_source_bundle_sha256 != generated::kSourceBundleSha256) {
    assign_error(error, "native material catalog/source bundle pin differs");
    return Status::kCatalogMismatch;
  }
  if (catalog_digest() != generated::kCatalogSha256) {
    assign_error(error, "compiled native material catalog records differ from their pin");
    return Status::kCatalogMismatch;
  }
  if (ltd_native_material_provider_abi_version() != LTD_NATIVE_MATERIAL_PROVIDER_ABI_VERSION ||
      std::string_view(ltd_native_material_provider_contract_sha256()) !=
          LTD_NATIVE_MATERIAL_PROVIDER_CONTRACT_SHA256 ||
      ltd_native_facepaint_decode_abi_version() != 1 ||
      std::string_view(ltd_native_facepaint_decode_contract_sha256()) !=
          LTD_NATIVE_FACEPAINT_CONTRACT_SHA256 ||
      ltd_noseline12_abi_version() != LTD_NOSELINE12_ABI_VERSION) {
    assign_error(error, "native material provider/facepaint module contract differs");
    return Status::kModuleMismatch;
  }
  try {
    MaterialBundle candidate;
    auto& storage = *candidate.storage_;
    storage.decoded_assets = request.decoded_assets;
    const FixtureRecord& fixture = fixture_for(request);
    const CaseRecord& selected = case_for(
        fixture_index(fixture), request.view_kind, request.raster_size);
    if (request.share_mii.size() != fixture.ltd_byte_count) {
      fail(Status::kSourceMismatch, "accepted LTD byte count differs");
    }
    const std::string effective_sha = hex(request.effective_char_info);
    const auto& face_report = request.face_plan->report();
    if (face_report.share_mii_sha256 != fixture.ltd_sha256 ||
        face_report.effective_char_info_sha256 != fixture.char_info_sha256) {
      fail(Status::kFaceMismatch, "FacePlan belongs to a different accepted fixture/CharInfo");
    }

    storage.report = {
        fixture.name, fixture.ltd_sha256, fixture.char_info_sha256,
        generated::kCatalogSha256, generated::kSourceBundleSha256,
        selected.publication_sha256,
        request.view_kind, request.raster_size, selected.material_count, 0, 0, 0,
        0, request.share_mii.size(), false, false, false, false, UINT32_MAX};

    storage.artifacts.resize(std::size(generated::kArtifacts));
    for (std::size_t index = 0; index < storage.artifacts.size(); ++index) {
      const auto& record = generated::kArtifacts[index];
      auto& owner = storage.artifacts[index];
      owner.bytes = read_authenticated(request.repository_root, record.path, record.sha256,
                                       record.byte_count, &storage.report.authenticated_source_bytes);
      owner.source = {record.role, 0, record.path, record.sha256,
                      owner.bytes.data(), owner.bytes.size()};
    }
    storage.report.evidence_document_count = static_cast<std::uint32_t>(storage.artifacts.size());

    std::set<std::uint32_t> needed_chains;
    for (std::uint32_t index = selected.first_material;
         index < selected.first_material + selected.material_count; ++index) {
      const auto& material = generated::kMaterials[index];
      for (std::uint32_t binding = material.first_binding;
           binding < material.first_binding + material.binding_count; ++binding) {
        needed_chains.insert(generated::kBindings[binding].chain_index);
      }
    }
    if (fixture.noseline_chain_index != UINT32_MAX)
      needed_chains.insert(fixture.noseline_chain_index);
    storage.chains.reserve(needed_chains.size());
    storage.unique_chain_sources.reserve(needed_chains.size());
    std::vector<std::optional<std::size_t>> local_chain(std::size(generated::kChains));
    for (const std::uint32_t catalog_index : needed_chains) {
      if (catalog_index >= std::size(generated::kChains)) fail(Status::kCatalogMismatch, "binding chain index is outside catalog");
      const auto& record = generated::kChains[catalog_index];
      const std::size_t local_index = storage.chains.size();
      local_chain[catalog_index] = local_index;
      storage.chains.emplace_back();
      auto& owner = storage.chains.back();
      owner.authored = read_authenticated(request.repository_root, record.authored_path,
                                           record.authored_sha256, record.authored_byte_count,
                                           &storage.report.authenticated_source_bytes);
      owner.manifest = read_authenticated(request.repository_root, record.manifest_path,
                                           record.manifest_sha256, record.manifest_byte_count,
                                           &storage.report.authenticated_source_bytes);
      owner.level_bytes.resize(record.level_count);
      owner.levels.resize(record.level_count);
      std::vector<native_runtime::DecodedTextureMipSource> cache_levels(record.level_count);
      for (std::uint32_t offset = 0; offset < record.level_count; ++offset) {
        if (record.first_level + offset >= std::size(generated::kLevels))
          fail(Status::kCatalogMismatch, "mip level range is outside catalog");
        const auto& level = generated::kLevels[record.first_level + offset];
        auto& bytes = owner.level_bytes[offset];
        bytes = read_authenticated(request.repository_root, level.path, level.sha256,
                                   level.byte_count, &storage.report.authenticated_source_bytes);
        owner.levels[offset] = {level.level, level.width, level.height, 0, level.path,
                                level.sha256, bytes.data(), bytes.size()};
        cache_levels[offset] = {level.level, level.width, level.height, wide_key(level.path),
                                level.sha256, bytes};
      }
      owner.source = {record.source_key, record.texture_name, record.source_format,
                      record.authored_sha256, owner.authored.data(), owner.authored.size(),
                      record.manifest_sha256, owner.manifest.data(), owner.manifest.size(),
                      record.color_space, record.level_count, owner.levels.data()};
      const native_runtime::DecodedTextureMipChainSource cache_source{
          record.texture_name, record.source_format, record.authored_sha256, owner.authored,
          record.manifest_sha256, owner.manifest,
          record.color_space == LTD_NATIVE_MATERIAL_TEXTURE_SRGB
              ? native_runtime::DecodedTextureColorSpace::kSrgb
              : native_runtime::DecodedTextureColorSpace::kLinear,
          cache_levels};
      request.decoded_assets->decode_texture_mip_chain(wide_key(record.source_key), cache_source);
      if (catalog_index != fixture.noseline_chain_index) {
        storage.unique_chain_sources.push_back(owner.source);
        ++storage.report.unique_mip_chain_count;
        storage.report.mip_level_count += record.level_count;
      } else {
        storage.report.noseline_mip_level_count += record.level_count;
      }
    }

    if (fixture.noseline_chain_index != UINT32_MAX) {
      if (fixture.noseline_scene_draw_index == UINT32_MAX ||
          fixture.noseline_chain_index >= local_chain.size() ||
          !local_chain[fixture.noseline_chain_index].has_value())
        fail(Status::kCatalogMismatch, "NoseLine catalog indices are inconsistent");
      const auto& chain = generated::kChains[fixture.noseline_chain_index];
      const auto view = request.decoded_assets->get_texture_mip_chain(
          wide_key(chain.source_key), chain.manifest_sha256, chain.authored_sha256);
      if (view.levels.size() != LTD_NOSELINE12_MIP_LEVEL_COUNT ||
          noseline_digest(view) != fixture.noseline_decoded_mips_sha256 ||
          std::string_view(ltd_noseline12_texture_manifest_sha256()) != chain.manifest_sha256 ||
          std::string_view(ltd_noseline12_decoded_mips_sha256()) !=
              fixture.noseline_decoded_mips_sha256)
        fail(Status::kSourceMismatch, "NoseLine manifest/decoded mip bank differs from ABI1");
      std::size_t element_count = 0;
      for (const auto& level : view.levels) element_count += level.rgba64.size();
      storage.noseline_rgba64.reserve(element_count);
      std::size_t element_offset = 0;
      for (std::size_t index = 0; index < view.levels.size(); ++index) {
        const auto& level = view.levels[index];
        storage.noseline_texture.levels[index] = {
            element_offset, level.width, level.height};
        storage.noseline_rgba64.insert(storage.noseline_rgba64.end(),
                                       level.rgba64.begin(), level.rgba64.end());
        element_offset += level.rgba64.size();
      }
      storage.noseline_texture.mip_rgba = storage.noseline_rgba64.data();
      storage.noseline_texture.mip_rgba_element_count = storage.noseline_rgba64.size();
      storage.noseline_texture.texture_manifest_sha256 = chain.manifest_sha256;
      storage.noseline_texture.decoded_mips_sha256 = fixture.noseline_decoded_mips_sha256;
      storage.noseline.source_key = chain.source_key;
      storage.noseline.mip_rgba = storage.noseline_rgba64;
      for (std::size_t index = 0; index < storage.noseline.levels.size(); ++index)
        storage.noseline.levels[index] = storage.noseline_texture.levels[index];
      storage.noseline.texture_manifest_sha256 = chain.manifest_sha256;
      storage.noseline.decoded_mips_sha256 = fixture.noseline_decoded_mips_sha256;
      storage.noseline.scene_draw_index = fixture.noseline_scene_draw_index;
      storage.report.has_noseline = true;
      storage.report.noseline_scene_draw_index = fixture.noseline_scene_draw_index;
    }

    storage.materials.resize(selected.material_count);
    storage.trusted_material_sources.resize(selected.material_count);
    storage.trusted_scene_draw_indices.resize(selected.material_count);
    storage.publications.resize(selected.material_count);
    for (std::uint32_t offset = 0; offset < selected.material_count; ++offset) {
      const auto& record = generated::kMaterials[selected.first_material + offset];
      auto& owner = storage.materials[offset];
      auto& value = owner.normalized;
      value.model_key = record.model_key;
      value.resource_name = record.resource_name;
      value.group = record.group;
      value.gameall_program = record.program;
      value.family = record.family;
      value.gsys_priority = record.priority;
      value.material_flags = record.flags;
      std::array<double*, 39> destination{};
      std::size_t cursor = 0;
      auto add = [&](double* data, std::size_t count) {
        for (std::size_t index = 0; index < count; ++index) destination[cursor++] = data + index;
      };
      add(value.color_srgb, 4);
      add(&value.alpha_multiplier, 1); add(&value.alpha_cutoff, 1); add(&value.roughness, 1);
      add(&value.anisotropic_shift_scale, 1); add(&value.anisotropic_shift_offset, 1);
      add(&value.anisotropic_specular_size, 1); add(&value.anisotropic_toon_intensity, 1);
      add(&value.anisotropic_title_view_scale, 1); add(&value.anisotropic_radiance_scale, 1);
      add(&value.parallax_scale, 1); add(value.body_face_color_linear, 3);
      add(value.hair_primary_srgb, 3); add(value.hair_secondary_srgb, 3);
      add(value.light_direction, 3); add(value.light_color, 3); add(value.ambient_color, 3);
      add(value.camera_position, 3); add(&value.light_intensity, 1);
      add(&value.ambient_intensity, 1); add(&value.light_normalization, 1);
      add(&value.flip_horizontal_sign, 1);
      if (cursor != destination.size()) fail(Status::kCatalogMismatch, "normalized double schema differs");
      for (std::size_t index = 0; index < destination.size(); ++index) {
        *destination[index] = as_double(record.double_bits[index]);
        if (!std::isfinite(*destination[index])) fail(Status::kCatalogMismatch, "catalog material contains nonfinite double");
      }
      value.has_camera_position = record.has_camera;
      value.perspective_correct = record.perspective_correct;
      value.mask_facepaint_mode = record.mask_facepaint_mode;
      for (std::uint32_t binding = record.first_binding;
           binding < record.first_binding + record.binding_count; ++binding) {
        if (binding >= std::size(generated::kBindings)) fail(Status::kCatalogMismatch, "binding range is outside catalog");
        const auto& spec = generated::kBindings[binding];
        if (spec.role == 0 || spec.role >= 10 || spec.chain_index >= std::size(generated::kChains))
          fail(Status::kCatalogMismatch, "binding role/chain is invalid");
        const auto& chain = generated::kChains[spec.chain_index];
        value.texture_keys[spec.role] = chain.source_key;
        value.texture_source_sha256[spec.role] = chain.authored_sha256;
        value.texture_manifest_sha256[spec.role] = chain.manifest_sha256;
        value.texture_address_u[spec.role] = spec.address_u;
        value.texture_address_v[spec.role] = spec.address_v;
        value.texture_mip_filter[spec.role] = spec.mip_filter;
        value.texture_hardware_srgb[spec.role] = spec.hardware_srgb;
      }
      for (std::size_t evidence = 0; evidence < record.evidence_indices.size(); ++evidence) {
        const std::uint32_t artifact = record.evidence_indices[evidence];
        if (artifact >= storage.artifacts.size()) fail(Status::kCatalogMismatch, "evidence index is outside catalog");
        owner.evidence[evidence] = storage.artifacts[artifact].source;
      }
      owner.source = {record.source_key, record.material_name, &owner.normalized,
                      owner.evidence.data(), static_cast<std::uint32_t>(owner.evidence.size())};
      storage.trusted_material_sources[offset] = owner.source;
      storage.trusted_scene_draw_indices[offset] = record.scene_draw_index;
      storage.publications[offset] = {
          record.scene_draw_index, &owner.source,
          std::span<const ltd_native_material_mip_chain_source>(
              offset == 0 ? storage.unique_chain_sources.data() : nullptr,
              offset == 0 ? storage.unique_chain_sources.size() : 0)};
    }

    storage.head_key = std::string("faceplan:") + fixture.name + ":head";
    storage.mask_key = std::string("faceplan:") + fixture.name + ":mask";
    storage.ugc_key = std::string("facepaint:") + fixture.name + ":ugc";
    const auto head = request.face_plan->generated_head_albedo_rgba64();
    const auto mask = request.face_plan->generated_mask_rgba64();
    storage.face.generated_head_albedo_source_key = storage.head_key.c_str();
    storage.face.generated_mask_source_key = storage.mask_key.c_str();
    storage.face.user_facepaint_source_key = storage.ugc_key.c_str();
    if (head.pixels != nullptr && head.element_count != 0)
      storage.generated_head_rgba64.assign(head.pixels, head.pixels + head.element_count);
    if (mask.pixels != nullptr && mask.element_count != 0)
      storage.generated_mask_rgba64.assign(mask.pixels, mask.pixels + mask.element_count);
    storage.face.generated_head_albedo = {
        storage.generated_head_rgba64.data(), storage.generated_head_rgba64.size() * sizeof(double),
        head.row_stride_bytes, head.width, head.height};
    storage.face.generated_mask = {
        storage.generated_mask_rgba64.data(), storage.generated_mask_rgba64.size() * sizeof(double),
        mask.row_stride_bytes, mask.width, mask.height};
    storage.face.has_generated_head_albedo = head.pixels != nullptr && head.element_count != 0;
    storage.face.has_generated_mask = mask.pixels != nullptr && mask.element_count != 0;
    storage.report.has_generated_head_albedo = storage.face.has_generated_head_albedo != 0;
    storage.report.has_generated_mask = storage.face.has_generated_mask != 0;
    const bool expected_ugc = fixture.has_user_facepaint != 0;
    if (expected_ugc != !request.user_facepaint_rgba8.empty())
      fail(Status::kFaceMismatch, "decoded UGC presence differs from accepted fixture");
    if (expected_ugc) {
      constexpr std::size_t width = 512;
      constexpr std::size_t height = 512;
      constexpr std::size_t bytes = width * height * 4;
      if (request.user_facepaint_rgba8.size() != bytes ||
          hex(request.user_facepaint_rgba8) != fixture.user_facepaint_rgba8_sha256)
        fail(Status::kFaceMismatch, "decoded UGC RGBA8 differs from accepted fixture");
      storage.user_facepaint_rgba64.resize(bytes);
      storage.user_facepaint_rgba8.assign(request.user_facepaint_rgba8.begin(),
                                          request.user_facepaint_rgba8.end());
      for (std::size_t index = 0; index < bytes; ++index)
        storage.user_facepaint_rgba64[index] = static_cast<double>(request.user_facepaint_rgba8[index]) / 255.0;
      storage.face.user_facepaint = {storage.user_facepaint_rgba64.data(),
                                     storage.user_facepaint_rgba64.size() * sizeof(double),
                                     width * 4 * sizeof(double), width, height};
      storage.face.has_user_facepaint = 1;
      ltd_native_facepaint_get_tex_srt(&storage.face.user_facepaint_srt);
      storage.ugc = {storage.ugc_key, storage.user_facepaint_rgba8, width, height,
                     storage.face.user_facepaint_srt};
      storage.report.has_user_facepaint = true;
    }
    *output = std::move(candidate);
    if (error != nullptr) error->clear();
    return Status::kOk;
  } catch (const native_runtime::DecodedAssetError& failure) {
    assign_error(error, failure.code() + ": " + failure.what());
    return Status::kCacheFailed;
  } catch (const Failure& failure) {
    assign_error(error, failure.message);
    return failure.status;
  } catch (const std::bad_alloc&) {
    assign_error(error, "native material adapter allocation failed");
    return Status::kAllocationFailed;
  } catch (const std::exception& failure) {
    assign_error(error, failure.what());
    return Status::kAssetMismatch;
  }
}

}  // namespace infinimii::native_runtime_material_adapter
