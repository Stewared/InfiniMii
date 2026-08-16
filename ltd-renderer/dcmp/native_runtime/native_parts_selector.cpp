#include "native_parts_selector.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <sstream>
#include <utility>

namespace infinimii::native_parts {
namespace {

constexpr std::array<std::uint8_t, 8> kMagic = {'I', 'M', 'P', 'A', 'R', 'T', 'S', 0};
constexpr std::size_t kHeaderSize = 88;
constexpr std::size_t kProfileSize = 4 + 6 * kCharInfoSize;
constexpr std::size_t kEntrySize = 28;
constexpr std::size_t kModelSize = 8;
constexpr std::uint32_t kAbsentString = 0xFFFFFFFFu;
constexpr std::uint16_t kKnownFlags = 0x000Fu;

constexpr std::array<std::string_view, 22> kCategoryNames = {
    "Faceline",     "WrinkleLower", "WrinkleUpper", "MakeUpper",
    "MakeLower",    "Hair",         "HairFront",    "Ear",
    "Eye",          "Highlight",    "EyelashUpper", "EyelashLower",
    "EyelidUpper",  "EyelidLower",  "Eyebrow",      "Nose",
    "Mouth",        "Beard",        "BeardShort",   "Mustache",
    "Glass",        "Mole",
};
constexpr std::array<std::string_view, kLogicalRecordCount> kLogicalNames = {
    "faceline",       "wrinkle_lower", "wrinkle_upper", "makeup_upper",
    "makeup_lower",   "hair",          "hair_front",    "hair_back_editor_state",
    "ear",            "eye",           "eye_highlight", "eyelash_upper",
    "eyelash_lower",  "eyelid_upper",  "eyelid_lower",  "eyebrow",
    "nose",           "mouth",         "beard",         "beard_short",
    "mustache",       "glass_primary", "mole",
};

struct Sha256 final {
  std::array<std::uint32_t, 8> state = {
      0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
      0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
  };
  std::array<std::uint8_t, 64> block{};
  std::uint64_t total = 0;
  std::size_t used = 0;

  static constexpr std::array<std::uint32_t, 64> k = {
      0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
      0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
      0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
      0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
      0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
      0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
      0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
      0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
      0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
      0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
      0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
      0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
      0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
  };

  static std::uint32_t Ror(std::uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32u - bits));
  }
  void Compress(const std::uint8_t* input) {
    std::array<std::uint32_t, 64> words{};
    for (std::size_t index = 0; index < 16; ++index) {
      const std::size_t offset = index * 4;
      words[index] = (static_cast<std::uint32_t>(input[offset]) << 24u) |
                     (static_cast<std::uint32_t>(input[offset + 1]) << 16u) |
                     (static_cast<std::uint32_t>(input[offset + 2]) << 8u) |
                     static_cast<std::uint32_t>(input[offset + 3]);
    }
    for (std::size_t index = 16; index < words.size(); ++index) {
      const std::uint32_t s0 = Ror(words[index - 15], 7) ^
                               Ror(words[index - 15], 18) ^
                               (words[index - 15] >> 3u);
      const std::uint32_t s1 = Ror(words[index - 2], 17) ^
                               Ror(words[index - 2], 19) ^
                               (words[index - 2] >> 10u);
      words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    std::uint32_t a = state[0];
    std::uint32_t b = state[1];
    std::uint32_t c = state[2];
    std::uint32_t d = state[3];
    std::uint32_t e = state[4];
    std::uint32_t f = state[5];
    std::uint32_t g = state[6];
    std::uint32_t h = state[7];
    for (std::size_t index = 0; index < words.size(); ++index) {
      const std::uint32_t big1 = Ror(e, 6) ^ Ror(e, 11) ^ Ror(e, 25);
      const std::uint32_t choice = (e & f) ^ (~e & g);
      const std::uint32_t temp1 = h + big1 + choice + k[index] + words[index];
      const std::uint32_t big0 = Ror(a, 2) ^ Ror(a, 13) ^ Ror(a, 22);
      const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t temp2 = big0 + majority;
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
  }
  void Update(std::span<const std::uint8_t> input) {
    total += input.size();
    for (const std::uint8_t value : input) {
      block[used++] = value;
      if (used == block.size()) {
        Compress(block.data());
        used = 0;
      }
    }
  }
  std::array<std::uint8_t, 32> Final() {
    const std::uint64_t bit_count = total * 8u;
    block[used++] = 0x80u;
    if (used > 56) {
      std::fill(block.begin() + static_cast<std::ptrdiff_t>(used), block.end(),
                static_cast<std::uint8_t>(0));
      Compress(block.data());
      used = 0;
    }
    std::fill(block.begin() + static_cast<std::ptrdiff_t>(used), block.begin() + 56,
              static_cast<std::uint8_t>(0));
    for (std::size_t index = 0; index < 8; ++index) {
      block[63 - index] = static_cast<std::uint8_t>(bit_count >> (index * 8));
    }
    Compress(block.data());
    std::array<std::uint8_t, 32> digest{};
    for (std::size_t index = 0; index < state.size(); ++index) {
      digest[index * 4] = static_cast<std::uint8_t>(state[index] >> 24u);
      digest[index * 4 + 1] = static_cast<std::uint8_t>(state[index] >> 16u);
      digest[index * 4 + 2] = static_cast<std::uint8_t>(state[index] >> 8u);
      digest[index * 4 + 3] = static_cast<std::uint8_t>(state[index]);
    }
    return digest;
  }
};

std::array<std::uint8_t, 32> Digest(std::span<const std::uint8_t> bytes) {
  Sha256 sha;
  sha.Update(bytes);
  return sha.Final();
}

std::uint16_t Read16(const std::uint8_t* value) {
  return static_cast<std::uint16_t>(value[0]) |
         static_cast<std::uint16_t>(static_cast<std::uint16_t>(value[1]) << 8u);
}

std::uint32_t Read32(const std::uint8_t* value) {
  return static_cast<std::uint32_t>(value[0]) |
         (static_cast<std::uint32_t>(value[1]) << 8u) |
         (static_cast<std::uint32_t>(value[2]) << 16u) |
         (static_cast<std::uint32_t>(value[3]) << 24u);
}

bool Fail(std::string* error, std::string message) {
  if (error != nullptr) {
    *error = std::move(message);
  }
  return false;
}

bool HasSuffix(std::string_view value, std::string_view suffix) {
  return value.size() >= suffix.size() &&
         value.substr(value.size() - suffix.size()) == suffix;
}

struct LogicalSpec {
  Logical logical;
  Category category;
  std::uint16_t offset;
  bool wide;
  Gate gate;
  bool has_category;
};

constexpr std::array<LogicalSpec, kLogicalRecordCount> kSpecs = {{
    {Logical::kFaceline, Category::kFaceline, 44, false, Gate::kNone, true},
    {Logical::kWrinkleLower, Category::kWrinkleLower, 46, false, Gate::kNone, true},
    {Logical::kWrinkleUpper, Category::kWrinkleUpper, 51, false, Gate::kNone, true},
    {Logical::kMakeupUpper, Category::kMakeUpper, 56, false, Gate::kNone, true},
    {Logical::kMakeupLower, Category::kMakeLower, 62, false, Gate::kNone, true},
    {Logical::kHair, Category::kHair, 68, true, Gate::kNone, true},
    {Logical::kHairFront, Category::kHairFront, 72, false,
     Gate::kSelectedHairAttachableFront, true},
    {Logical::kHairBackEditorState, Category::kHair, 73, false,
     Gate::kHairBackEditorState, false},
    {Logical::kEar, Category::kEar, 75, false, Gate::kNone, true},
    {Logical::kEye, Category::kEye, 78, false, Gate::kNone, true},
    {Logical::kEyeHighlight, Category::kHighlight, 86, false, Gate::kNone, true},
    {Logical::kEyelashUpper, Category::kEyelashUpper, 92, false, Gate::kNone, true},
    {Logical::kEyelashLower, Category::kEyelashLower, 98, false, Gate::kNone, true},
    {Logical::kEyelidUpper, Category::kEyelidUpper, 104, false, Gate::kNone, true},
    {Logical::kEyelidLower, Category::kEyelidLower, 110, false, Gate::kNone, true},
    {Logical::kEyebrow, Category::kEyebrow, 116, false, Gate::kNone, true},
    {Logical::kNose, Category::kNose, 123, false, Gate::kNone, true},
    {Logical::kMouth, Category::kMouth, 126, false, Gate::kNone, true},
    {Logical::kBeard, Category::kBeard, 132, false, Gate::kNone, true},
    {Logical::kBeardShort, Category::kBeardShort, 134, false, Gate::kNone, true},
    {Logical::kMustache, Category::kMustache, 136, false, Gate::kNone, true},
    {Logical::kGlassPrimary, Category::kGlass, 141, false, Gate::kNone, true},
    {Logical::kMole, Category::kMole, 43, false, Gate::kMoleEnabled, true},
}};

template <std::size_t N>
bool AppendUnique(std::array<std::string_view, N>* values, std::size_t* count,
                  std::string_view value, std::string* error) {
  if (std::find(values->begin(), values->begin() + static_cast<std::ptrdiff_t>(*count),
                value) != values->begin() + static_cast<std::ptrdiff_t>(*count)) {
    return true;
  }
  if (*count >= values->size()) {
    return Fail(error, "active Parts resource inventory exceeds ABI capacity");
  }
  (*values)[(*count)++] = value;
  return true;
}

}  // namespace

struct Catalog::Storage {
  std::vector<std::uint8_t> bytes;
  std::vector<CatalogEntry> entries;
  std::array<std::uint8_t, 32> source_digest{};
  bool special_enabled = false;
  std::uint8_t merged_region = 0;
  std::array<std::array<std::uint8_t, kCharInfoSize>, 6> templates{};
};

Catalog::Catalog() = default;
Catalog::~Catalog() = default;
Catalog::Catalog(Catalog&&) noexcept = default;
Catalog& Catalog::operator=(Catalog&&) noexcept = default;

bool Catalog::Open(std::span<const std::uint8_t> bytes,
                   std::span<const std::uint8_t, 32> expected_sha256,
                   std::unique_ptr<Catalog>* output, std::string* error) {
  if (output == nullptr) {
    return Fail(error, "native Parts catalog output pointer is null");
  }
  output->reset();
  if (bytes.size() < kHeaderSize) {
    return Fail(error, "native Parts catalog is truncated");
  }
  const auto actual_sha256 = Digest(bytes);
  if (!std::equal(actual_sha256.begin(), actual_sha256.end(),
                  expected_sha256.begin())) {
    return Fail(error, "native Parts catalog SHA-256 differs from the admitted digest");
  }
  if (!std::equal(kMagic.begin(), kMagic.end(), bytes.begin())) {
    return Fail(error, "native Parts catalog magic changed");
  }
  const std::uint8_t* header = bytes.data();
  const std::uint32_t version = Read32(header + 8);
  const std::uint32_t total_size = Read32(header + 12);
  const std::uint32_t profile_offset = Read32(header + 16);
  const std::uint32_t profile_size = Read32(header + 20);
  const std::uint32_t entries_offset = Read32(header + 24);
  const std::uint32_t entry_count = Read32(header + 28);
  const std::uint32_t entry_size = Read32(header + 32);
  const std::uint32_t models_offset = Read32(header + 36);
  const std::uint32_t model_count = Read32(header + 40);
  const std::uint32_t model_size = Read32(header + 44);
  const std::uint32_t strings_offset = Read32(header + 48);
  const std::uint32_t strings_size = Read32(header + 52);
  if (version != kCatalogFormatVersion || total_size != bytes.size() ||
      profile_offset != kHeaderSize || profile_size != kProfileSize ||
      entry_size != kEntrySize || model_size != kModelSize || entry_count == 0 ||
      entry_count > 65536u || model_count > 1048576u || strings_size == 0) {
    return Fail(error, "native Parts catalog header is invalid");
  }
  const std::uint64_t expected_entries =
      static_cast<std::uint64_t>(profile_offset) + profile_size;
  const std::uint64_t expected_models =
      expected_entries + static_cast<std::uint64_t>(entry_count) * entry_size;
  const std::uint64_t expected_strings =
      expected_models + static_cast<std::uint64_t>(model_count) * model_size;
  const std::uint64_t expected_end = expected_strings + strings_size;
  if (entries_offset != expected_entries || models_offset != expected_models ||
      strings_offset != expected_strings || expected_end != bytes.size()) {
    return Fail(error, "native Parts catalog sections overlap or have gaps");
  }

  auto catalog = std::make_unique<Catalog>();
  catalog->storage_ = std::make_unique<Storage>();
  Storage& storage = *catalog->storage_;
  storage.bytes.assign(bytes.begin(), bytes.end());
  const std::uint8_t* owned = storage.bytes.data();
  std::copy_n(owned + 56, storage.source_digest.size(), storage.source_digest.begin());
  const std::uint8_t* profile = owned + profile_offset;
  if (profile[0] > 1 || profile[1] > 2 || profile[2] != 0 || profile[3] != 0) {
    return Fail(error, "native Parts normalization profile is invalid");
  }
  storage.special_enabled = profile[0] != 0;
  storage.merged_region = profile[1];
  for (std::size_t index = 0; index < storage.templates.size(); ++index) {
    std::copy_n(profile + 4 + index * kCharInfoSize, kCharInfoSize,
                storage.templates[index].begin());
    if (storage.templates[index][39] != (index >= 3 ? 1 : 0)) {
      return Fail(error, "native Parts SDK-default template gender changed");
    }
  }

  const std::uint8_t* strings = owned + strings_offset;
  if (strings[0] != 0) {
    return Fail(error, "native Parts string table lacks its empty sentinel");
  }
  const auto get_string = [&](std::uint32_t offset, bool absent_allowed,
                              std::string_view* value) -> bool {
    if (absent_allowed && offset == kAbsentString) {
      *value = {};
      return true;
    }
    if (offset >= strings_size || (offset != 0 && strings[offset - 1] != 0)) {
      return false;
    }
    const void* terminator = std::memchr(strings + offset, 0, strings_size - offset);
    if (terminator == nullptr) {
      return false;
    }
    const auto* end = static_cast<const std::uint8_t*>(terminator);
    *value = std::string_view(reinterpret_cast<const char*>(strings + offset),
                              static_cast<std::size_t>(end - (strings + offset)));
    return true;
  };

  std::array<bool, static_cast<std::size_t>(Category::kCount)> category_seen{};
  storage.entries.reserve(entry_count);
  std::uint32_t previous_key = 0;
  bool has_previous = false;
  for (std::uint32_t index = 0; index < entry_count; ++index) {
    const std::uint8_t* raw = owned + entries_offset + index * entry_size;
    const std::uint16_t category_value = Read16(raw);
    const std::uint16_t selector = Read16(raw + 2);
    const std::uint32_t record_offset = Read32(raw + 4);
    const std::uint32_t parts_offset = Read32(raw + 8);
    const std::uint32_t texture_offset = Read32(raw + 12);
    const std::uint32_t model_start = Read32(raw + 16);
    const std::uint32_t entry_model_count = Read32(raw + 20);
    const std::uint16_t flags = Read16(raw + 24);
    const std::uint16_t reserved = Read16(raw + 26);
    if (category_value >= static_cast<std::uint16_t>(Category::kCount) ||
        (flags & ~kKnownFlags) != 0 || reserved != 0 ||
        model_start > model_count || entry_model_count > model_count - model_start) {
      return Fail(error, "native Parts catalog entry is invalid");
    }
    const std::uint32_t key = (static_cast<std::uint32_t>(category_value) << 16u) | selector;
    if (has_previous && key <= previous_key) {
      return Fail(error, "native Parts catalog entries are not strictly ordered");
    }
    previous_key = key;
    has_previous = true;
    CatalogEntry entry;
    entry.category = static_cast<Category>(category_value);
    entry.selector = selector;
    if (!get_string(record_offset, false, &entry.record_name) ||
        !get_string(parts_offset, false, &entry.parts_config) ||
        !get_string(texture_offset, true, &entry.texture_name) ||
        entry.record_name.empty() || entry.parts_config.empty()) {
      return Fail(error, "native Parts catalog entry has an invalid string reference");
    }
    const bool texture_flag = (flags & 4u) != 0;
    const bool models_flag = (flags & 8u) != 0;
    if (texture_flag != !entry.texture_name.empty() ||
        models_flag != (entry_model_count != 0)) {
      return Fail(error, "native Parts catalog payload flags disagree");
    }
    entry.is_nothing = (flags & 1u) != 0;
    entry.is_attachable_hair_front = (flags & 2u) != 0;
    if (entry.is_nothing != HasSuffix(entry.record_name, "Nothing") ||
        (entry.is_attachable_hair_front && entry.category != Category::kHair)) {
      return Fail(error, "native Parts catalog semantic flags disagree");
    }
    entry.model_resources.reserve(entry_model_count);
    for (std::uint32_t model_index = 0; model_index < entry_model_count; ++model_index) {
      const std::uint8_t* model =
          owned + models_offset + (model_start + model_index) * model_size;
      ModelResource resource;
      if (!get_string(Read32(model), false, &resource.role) ||
          !get_string(Read32(model + 4), false, &resource.resource_name) ||
          resource.role.empty()) {
        return Fail(error, "native Parts model resource has an invalid string reference");
      }
      entry.model_resources.push_back(resource);
    }
    category_seen[category_value] = true;
    storage.entries.push_back(std::move(entry));
  }
  if (std::find(category_seen.begin(), category_seen.end(), false) != category_seen.end()) {
    return Fail(error, "native Parts catalog omits a required category");
  }
  *output = std::move(catalog);
  if (error != nullptr) {
    error->clear();
  }
  return true;
}

const CatalogEntry* Catalog::Find(Category category, std::uint16_t selector) const {
  if (!storage_) {
    return nullptr;
  }
  const auto found = std::lower_bound(
      storage_->entries.begin(), storage_->entries.end(),
      std::pair{category, selector},
      [](const CatalogEntry& entry, const std::pair<Category, std::uint16_t>& key) {
        return std::pair{entry.category, entry.selector} < key;
      });
  return found != storage_->entries.end() && found->category == category &&
                 found->selector == selector
             ? &*found
             : nullptr;
}

std::span<const CatalogEntry> Catalog::entries() const {
  return storage_ ? std::span<const CatalogEntry>(storage_->entries) :
                    std::span<const CatalogEntry>();
}

std::array<std::uint8_t, 32> Catalog::source_bundle_sha256() const {
  return storage_ ? storage_->source_digest : std::array<std::uint8_t, 32>{};
}

bool Select(const Catalog& catalog, std::span<const std::uint8_t> raw_char_info,
            Selection* output, std::string* error) {
  if (output == nullptr) {
    return Fail(error, "native Parts selection output pointer is null");
  }
  *output = {};
  if (!catalog.storage_) {
    return Fail(error, "native Parts catalog is not open");
  }
  if (raw_char_info.size() != kCharInfoSize) {
    return Fail(error, "CharInfoEx must be exactly 152 bytes");
  }
  const std::uint8_t gender = raw_char_info[39];
  const std::uint8_t region_move = raw_char_info[42];
  const bool special = (raw_char_info[43] & 1u) != 0;
  if (gender > 1) {
    return Fail(error, "unsupported CharInfoEx gender");
  }
  if (region_move > 3) {
    return Fail(error, "unexpected special-Mii region_move");
  }
  std::copy(raw_char_info.begin(), raw_char_info.end(), output->effective_char_info.begin());
  int expected_region = -1;
  if (region_move != 0) {
    expected_region = static_cast<int>(region_move) - 1;
  }
  const bool replace = special &&
      (!catalog.storage_->special_enabled ||
       (expected_region >= 0 && expected_region != catalog.storage_->merged_region));
  if (replace) {
    const std::uint8_t index = static_cast<std::uint8_t>((gender != 0 ? 3 : 0) +
                                                         raw_char_info[15] % 3);
    output->default_index = static_cast<std::int8_t>(index);
    output->effective_char_info = catalog.storage_->templates[index];
    std::copy_n(raw_char_info.begin(), 16, output->effective_char_info.begin());
    if (output->effective_char_info[39] != gender) {
      return Fail(error, "SDK default normalization did not preserve gender");
    }
    output->normalization_action = NormalizationAction::kReplaceWithSdkDefault;
    output->normalized = true;
  } else if (!special) {
    output->normalization_action = NormalizationAction::kOrdinaryNoop;
  } else if (region_move == 0) {
    output->normalization_action = NormalizationAction::kSpecialPreservedNoRegionMove;
  } else {
    output->normalization_action = NormalizationAction::kSpecialPreservedMatchingRegion;
  }

  const auto& effective = output->effective_char_info;
  const std::uint16_t hair_selector = Read16(effective.data() + 68);
  const CatalogEntry* selected_hair = catalog.Find(Category::kHair, hair_selector);
  if (selected_hair == nullptr) {
    return Fail(error, "no Hair PartsIndex record for the effective selector");
  }
  const bool hair_front_enabled = selected_hair->is_attachable_hair_front;
  const bool mole_enabled = (effective[43] & 0x80u) != 0;

  for (std::size_t index = 0; index < kSpecs.size(); ++index) {
    const LogicalSpec& spec = kSpecs[index];
    SelectedRecord& selected = output->records[index];
    selected.logical = spec.logical;
    selected.has_category = spec.has_category;
    selected.category = spec.category;
    selected.gate = spec.gate;
    if (spec.gate == Gate::kMoleEnabled) {
      selected.selector = mole_enabled ? 1 : 0;
      selected.gate_enabled = mole_enabled;
    } else {
      selected.selector = spec.wide ? Read16(effective.data() + spec.offset)
                                    : effective[spec.offset];
      selected.gate_enabled = spec.gate == Gate::kSelectedHairAttachableFront
                                  ? hair_front_enabled
                                  : true;
    }
    if (!spec.has_category) {
      selected.resolved = false;
      selected.enabled = false;
      selected.gate_enabled = true;
      continue;
    }
    selected.entry = catalog.Find(spec.category, selected.selector);
    if (selected.entry == nullptr) {
      selected.resolved = false;
      selected.enabled = false;
      selected.inactive_projection = InactiveProjection::kTitleLookupEmpty;
      continue;
    }
    selected.resolved = true;
    selected.is_nothing = selected.entry->is_nothing;
    const bool render_payload = !selected.entry->texture_name.empty() ||
                                !selected.entry->model_resources.empty();
    selected.enabled = selected.gate_enabled && !selected.is_nothing && render_payload;
    selected.inactive_projection =
        selected.is_nothing
            ? InactiveProjection::kExactPartsNothing
            : !selected.gate_enabled ? InactiveProjection::kGateDisabled
                                     : InactiveProjection::kNone;
    if (!selected.enabled) {
      continue;
    }
    for (const ModelResource& model : selected.entry->model_resources) {
      if (model.role == "ModelUnit" &&
          !AppendUnique(&output->active_model_resources, &output->active_model_count,
                        model.resource_name, error)) {
        return false;
      }
    }
    if (!selected.entry->texture_name.empty() &&
        !AppendUnique(&output->active_texture_resources,
                      &output->active_texture_count, selected.entry->texture_name,
                      error)) {
      return false;
    }
  }
  if (error != nullptr) {
    error->clear();
  }
  return true;
}

std::string_view CategoryName(Category value) {
  const auto index = static_cast<std::size_t>(value);
  return index < kCategoryNames.size() ? kCategoryNames[index] : std::string_view{};
}

std::string_view LogicalName(Logical value) {
  const auto index = static_cast<std::size_t>(value);
  return index < kLogicalNames.size() ? kLogicalNames[index] : std::string_view{};
}

std::string_view GateName(Gate value) {
  constexpr std::array<std::string_view, 4> names = {
      "none", "selected_hair_attachable_front", "mole_enabled", "hair_back_editor_state"};
  const auto index = static_cast<std::size_t>(value);
  return index < names.size() ? names[index] : std::string_view{};
}

std::string_view InactiveProjectionName(InactiveProjection value) {
  constexpr std::array<std::string_view, 4> names = {
      "none", "exact_parts_nothing", "gate_disabled", "title_lookup_empty"};
  const auto index = static_cast<std::size_t>(value);
  return index < names.size() ? names[index] : std::string_view{};
}

std::string_view NormalizationActionName(NormalizationAction value) {
  constexpr std::array<std::string_view, 4> names = {
      "ordinary_noop", "special_preserved_no_region_move",
      "special_preserved_matching_region", "replace_with_sdk_default"};
  const auto index = static_cast<std::size_t>(value);
  return index < names.size() ? names[index] : std::string_view{};
}

}  // namespace infinimii::native_parts

#ifdef NATIVE_PARTS_SELECTOR_TOOL
namespace {
using infinimii::native_parts::Catalog;
using infinimii::native_parts::Selection;

std::vector<std::uint8_t> ReadFile(const char* path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error(std::string("cannot open ") + path);
  }
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::array<std::uint8_t, 32> ParseDigest(std::string_view text) {
  if (text.size() != 64) {
    throw std::runtime_error("expected SHA-256 must contain 64 hex digits");
  }
  std::array<std::uint8_t, 32> result{};
  for (std::size_t index = 0; index < result.size(); ++index) {
    const auto digit = [](char value) -> int {
      if (value >= '0' && value <= '9') return value - '0';
      if (value >= 'a' && value <= 'f') return value - 'a' + 10;
      if (value >= 'A' && value <= 'F') return value - 'A' + 10;
      return -1;
    };
    const int high = digit(text[index * 2]);
    const int low = digit(text[index * 2 + 1]);
    if (high < 0 || low < 0) {
      throw std::runtime_error("expected SHA-256 contains a non-hex digit");
    }
    result[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return result;
}

void JsonString(std::ostream& output, std::string_view value) {
  output << '"';
  for (const unsigned char byte : value) {
    switch (byte) {
      case '"': output << "\\\""; break;
      case '\\': output << "\\\\"; break;
      case '\b': output << "\\b"; break;
      case '\f': output << "\\f"; break;
      case '\n': output << "\\n"; break;
      case '\r': output << "\\r"; break;
      case '\t': output << "\\t"; break;
      default:
        if (byte < 0x20u) {
          output << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
                 << static_cast<unsigned>(byte) << std::dec;
        } else {
          output << static_cast<char>(byte);
        }
    }
  }
  output << '"';
}

void Emit(const Selection& selection) {
  using namespace infinimii::native_parts;
  std::cout << "{\"normalization_action\":";
  JsonString(std::cout, NormalizationActionName(selection.normalization_action));
  std::cout << ",\"normalized\":" << (selection.normalized ? "true" : "false")
            << ",\"default_index\":" << static_cast<int>(selection.default_index)
            << ",\"effective_char_info_hex\":\"";
  for (const std::uint8_t value : selection.effective_char_info) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<unsigned>(value);
  }
  std::cout << std::dec << "\",\"records\":[";
  for (std::size_t index = 0; index < selection.records.size(); ++index) {
    const auto& record = selection.records[index];
    if (index != 0) std::cout << ',';
    std::cout << "{\"logical_name\":";
    JsonString(std::cout, LogicalName(record.logical));
    std::cout << ",\"selector\":" << record.selector << ",\"category\":";
    if (record.has_category) JsonString(std::cout, CategoryName(record.category));
    else std::cout << "null";
    std::cout << ",\"resolved\":" << (record.resolved ? "true" : "false")
              << ",\"enabled\":" << (record.enabled ? "true" : "false")
              << ",\"is_nothing\":" << (record.is_nothing ? "true" : "false")
              << ",\"gate\":";
    JsonString(std::cout, GateName(record.gate));
    std::cout << ",\"gate_enabled\":" << (record.gate_enabled ? "true" : "false")
              << ",\"inactive_projection\":";
    JsonString(std::cout, InactiveProjectionName(record.inactive_projection));
    std::cout << ",\"record\":";
    if (record.entry != nullptr) JsonString(std::cout, record.entry->record_name);
    else std::cout << "null";
    std::cout << ",\"texture_name\":";
    if (record.entry != nullptr && !record.entry->texture_name.empty())
      JsonString(std::cout, record.entry->texture_name);
    else std::cout << "null";
    std::cout << ",\"model_resources\":[";
    if (record.entry != nullptr) {
      for (std::size_t model_index = 0; model_index < record.entry->model_resources.size();
           ++model_index) {
        if (model_index != 0) std::cout << ',';
        std::cout << "{\"role\":";
        JsonString(std::cout, record.entry->model_resources[model_index].role);
        std::cout << ",\"resource_name\":";
        JsonString(std::cout, record.entry->model_resources[model_index].resource_name);
        std::cout << '}';
      }
    }
    std::cout << "]}";
  }
  std::cout << "],\"active_model_resources\":[";
  for (std::size_t index = 0; index < selection.active_model_count; ++index) {
    if (index != 0) std::cout << ',';
    JsonString(std::cout, selection.active_model_resources[index]);
  }
  std::cout << "],\"active_texture_resources\":[";
  for (std::size_t index = 0; index < selection.active_texture_count; ++index) {
    if (index != 0) std::cout << ',';
    JsonString(std::cout, selection.active_texture_resources[index]);
  }
  std::cout << "]}\n";
}
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc != 4) {
      std::cerr << "usage: native_parts_selector <catalog.bin> <sha256> <charinfo.bin>\n";
      return 2;
    }
    const auto catalog_bytes = ReadFile(argv[1]);
    const auto expected = ParseDigest(argv[2]);
    std::unique_ptr<Catalog> catalog;
    std::string error;
    if (!Catalog::Open(catalog_bytes, expected, &catalog, &error)) {
      std::cerr << error << '\n';
      return 3;
    }
    const auto char_info = ReadFile(argv[3]);
    Selection selection;
    if (!infinimii::native_parts::Select(*catalog, char_info, &selection, &error)) {
      std::cerr << error << '\n';
      return 4;
    }
    Emit(selection);
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
#endif
