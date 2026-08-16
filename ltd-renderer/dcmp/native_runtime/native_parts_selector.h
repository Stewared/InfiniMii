#ifndef INFINIMII_NATIVE_PARTS_SELECTOR_H_
#define INFINIMII_NATIVE_PARTS_SELECTOR_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace infinimii::native_parts {

inline constexpr std::size_t kCharInfoSize = 152;
inline constexpr std::size_t kLogicalRecordCount = 23;
inline constexpr std::size_t kMaxActiveResources = 64;
inline constexpr std::uint32_t kCatalogFormatVersion = 1;

enum class Category : std::uint8_t {
  kFaceline = 0,
  kWrinkleLower,
  kWrinkleUpper,
  kMakeUpper,
  kMakeLower,
  kHair,
  kHairFront,
  kEar,
  kEye,
  kHighlight,
  kEyelashUpper,
  kEyelashLower,
  kEyelidUpper,
  kEyelidLower,
  kEyebrow,
  kNose,
  kMouth,
  kBeard,
  kBeardShort,
  kMustache,
  kGlass,
  kMole,
  kCount,
};

enum class Logical : std::uint8_t {
  kFaceline = 0,
  kWrinkleLower,
  kWrinkleUpper,
  kMakeupUpper,
  kMakeupLower,
  kHair,
  kHairFront,
  kHairBackEditorState,
  kEar,
  kEye,
  kEyeHighlight,
  kEyelashUpper,
  kEyelashLower,
  kEyelidUpper,
  kEyelidLower,
  kEyebrow,
  kNose,
  kMouth,
  kBeard,
  kBeardShort,
  kMustache,
  kGlassPrimary,
  kMole,
};

enum class Gate : std::uint8_t {
  kNone = 0,
  kSelectedHairAttachableFront,
  kMoleEnabled,
  kHairBackEditorState,
};

enum class InactiveProjection : std::uint8_t {
  kNone = 0,
  kExactPartsNothing,
  kGateDisabled,
  kTitleLookupEmpty,
};

enum class NormalizationAction : std::uint8_t {
  kOrdinaryNoop = 0,
  kSpecialPreservedNoRegionMove,
  kSpecialPreservedMatchingRegion,
  kReplaceWithSdkDefault,
};

struct ModelResource {
  std::string_view role;
  std::string_view resource_name;
};

struct CatalogEntry {
  Category category{};
  std::uint16_t selector = 0;
  std::string_view record_name;
  std::string_view parts_config;
  std::string_view texture_name;
  std::vector<ModelResource> model_resources;
  bool is_nothing = false;
  bool is_attachable_hair_front = false;
};

class Catalog final {
 public:
  Catalog();
  ~Catalog();
  Catalog(const Catalog&) = delete;
  Catalog& operator=(const Catalog&) = delete;
  Catalog(Catalog&&) noexcept;
  Catalog& operator=(Catalog&&) noexcept;

  static bool Open(std::span<const std::uint8_t> bytes,
                   std::span<const std::uint8_t, 32> expected_sha256,
                   std::unique_ptr<Catalog>* output, std::string* error);

  [[nodiscard]] const CatalogEntry* Find(Category category,
                                         std::uint16_t selector) const;
  [[nodiscard]] std::span<const CatalogEntry> entries() const;
  [[nodiscard]] std::array<std::uint8_t, 32> source_bundle_sha256() const;

 private:
  struct Storage;
  std::unique_ptr<Storage> storage_;

  friend bool Select(const Catalog&, std::span<const std::uint8_t>,
                     struct Selection*, std::string*);
};

struct SelectedRecord {
  Logical logical{};
  std::uint16_t selector = 0;
  bool has_category = false;
  Category category{};
  bool resolved = false;
  bool enabled = false;
  bool is_nothing = false;
  Gate gate = Gate::kNone;
  bool gate_enabled = true;
  InactiveProjection inactive_projection = InactiveProjection::kNone;
  const CatalogEntry* entry = nullptr;
};

struct Selection {
  std::array<std::uint8_t, kCharInfoSize> effective_char_info{};
  NormalizationAction normalization_action = NormalizationAction::kOrdinaryNoop;
  bool normalized = false;
  std::int8_t default_index = -1;
  std::array<SelectedRecord, kLogicalRecordCount> records{};
  std::array<std::string_view, kMaxActiveResources> active_model_resources{};
  std::size_t active_model_count = 0;
  std::array<std::string_view, kMaxActiveResources> active_texture_resources{};
  std::size_t active_texture_count = 0;
};

// Selects from a raw, exactly 152-byte CharInfoEx.  No fallback selector is
// inferred: a missing main Hair row aborts, while all other missing rows are
// represented as unresolved/title-lookup-empty exactly like the Python
// authority.
bool Select(const Catalog& catalog, std::span<const std::uint8_t> raw_char_info,
            Selection* output, std::string* error);

std::string_view CategoryName(Category value);
std::string_view LogicalName(Logical value);
std::string_view GateName(Gate value);
std::string_view InactiveProjectionName(InactiveProjection value);
std::string_view NormalizationActionName(NormalizationAction value);

}  // namespace infinimii::native_parts

#endif  // INFINIMII_NATIVE_PARTS_SELECTOR_H_
