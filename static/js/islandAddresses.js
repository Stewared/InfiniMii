const WORKGROUP_SIZE = 256;
const DISPATCH_GROUPS = 512;
const ITERATIONS_PER_THREAD = 256;
const STRIDE = WORKGROUP_SIZE * DISPATCH_GROUPS;
let CHUNK_CANDIDATES;
let MASK_128;
let UINT32_MASK;
let SHIFT_8;
let SHIFT_32;
let SHIFT_64;
let SHIFT_96;
const ISLAND_WORDS = Object.freeze([
    "Ice-Cream Cone",
    "Apple Pie",
    "Strawberry",
    "Prawn Salad",
    "Sashimi",
    "Orange Juice",
    "Chocolate Gâteau",
    "Chewing Gum",
    "Fried Chicken",
    "Mushroom",
    "Caviar",
    "Gummy Candy",
    "Gratin",
    "Creamy Stew",
    "Crepe",
    "Grapefruit",
    "Croissant",
    "Coffee",
    "Cheese",
    "Rice",
    "Cherries",
    "Salad",
    "Sandwich",
    "Buttered Potato",
    "Strawberry Shortcake",
    "Watermelon",
    "Steak",
    "Sausage",
    "Soft-Serve Ice Cream",
    "Tacos",
    "Roasted Chestnuts",
    "Red Chili Pepper",
    "Fried Tofu",
    "Corn on the Cob",
    "Doughnut",
    "Banana",
    "Cheeseburger",
    "Salisbury Steak",
    "Pizza",
    "Cracker",
    "Grapes",
    "French Fries",
    "Barbecue",
    "Blue Cheese",
    "French Toast",
    "Potato Chips",
    "Macadamia Nuts",
    "Orange",
    "Peach",
    "Hard-Boiled Egg",
    "Ramen",
    "Apple",
    "Tomato Juice",
    "Avocado",
    "Bacon",
    "Broccoli",
    "Calamari",
    "Quiche",
    "Cotton Candy",
    "Cappuccino",
    "Coconut",
    "Cornflakes",
    "Cheesecake",
    "Kiwi",
    "Lasagna",
    "Macaron",
    "Meatballs",
    "Melon",
    "Muffin",
    "Paella",
    "Peanuts",
    "Pretzel",
    "Risotto",
    "Roast Beef",
    "Salami",
    "Escargot",
    "Spaghetti Peperoncino",
    "Tiramisu",
    "Truffle",
    "Waffle",
    "Yogurt",
    "Gelatin Snack",
    "Soda",
    "Pancakes",
    "Instant Noodles",
    "Stuffed Cabbage Roll",
    "Tomato",
    "Apple Juice",
    "Mango",
    "Hot Dog",
    "Pineapple",
    "Octopus",
    "Green Pepper",
    "Sushi",
    "Pot-au-Feu",
    "Celery",
    "Popcorn",
    "Durian",
    "Garlic",
    "Fried Egg"
]);
const WORD_INDEX = new Map(ISLAND_WORDS.map((word, index) => [normalizeWord(word), index]));

const shaderSource = `
struct Params {
  ocean: u32,
  isles: u32,
  num1: u32,
  num2: u32,
  base0: u32,
  base1: u32,
  base2: u32,
  base3: u32,
  iterations: u32,
  stride: u32,
  pad0: u32,
  pad1: u32,
};

struct Result {
  found: atomic<u32>,
  id0: u32,
  id1: u32,
  id2: u32,
  id3: u32,
};

struct ShaState {
  s0: u32,
  s1: u32,
  s2: u32,
  s3: u32,
  s4: u32,
};

struct HashWords {
  lo: u32,
  hi: u32,
};

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> result: Result;

fn rotl32(x: u32, n: u32) -> u32 {
  return (x << n) | (x >> (32u - n));
}

fn bswap32(x: u32) -> u32 {
  return ((x & 0x000000ffu) << 24u) |
         ((x & 0x0000ff00u) << 8u) |
         ((x & 0x00ff0000u) >> 8u) |
         ((x & 0xff000000u) >> 24u);
}

fn sha1Compress(
  s0: u32, s1: u32, s2: u32, s3: u32, s4: u32,
  w0: u32, w1: u32, w2: u32, w3: u32,
  w4: u32, w5: u32, w6: u32, w7: u32,
  w8: u32, w9: u32, w10: u32, w11: u32,
  w12: u32, w13: u32, w14: u32, w15: u32
) -> ShaState {
  var w = array<u32, 16>(w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15);
  var a = s0;
  var b = s1;
  var c = s2;
  var d = s3;
  var e = s4;

  for (var i = 0u; i < 80u; i = i + 1u) {
    var wi: u32;
    if (i < 16u) {
      wi = w[i];
    } else {
      wi = rotl32(w[(i - 3u) & 15u] ^ w[(i - 8u) & 15u] ^ w[(i - 14u) & 15u] ^ w[i & 15u], 1u);
      w[i & 15u] = wi;
    }
    var f: u32;
    var k: u32;

    if (i < 20u) {
      f = d ^ (b & (c ^ d));
      k = 0x5A827999u;
    } else if (i < 40u) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1u;
    } else if (i < 60u) {
      f = (b & c) | (d & (b | c));
      k = 0x8F1BBCDCu;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6u;
    }

    let t = rotl32(a, 5u) + f + e + k + wi;
    e = d;
    d = c;
    c = rotl32(b, 30u);
    b = a;
    a = t;
  }

  return ShaState(s0 + a, s1 + b, s2 + c, s3 + d, s4 + e);
}

fn computeH(id0: u32, id1: u32, id2: u32, id3: u32) -> HashWords {
  let inner = sha1Compress(
    0x533fef0cu, 0xc1343d17u, 0x2d61508fu, 0xdacf4115u, 0xfc8c1f9eu,
    bswap32(id0), bswap32(id1), bswap32(id2), bswap32(id3),
    0x80000000u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u,
    0u, 0u, 0u, 640u
  );

  let outer = sha1Compress(
    0xc07a55d3u, 0x8ea667fcu, 0x51cb0b28u, 0x7a02c8c9u, 0xa8a200eeu,
    inner.s0, inner.s1, inner.s2, inner.s3, inner.s4,
    0x80000000u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u,
    0u, 0u, 672u
  );

  return HashWords(bswap32(outer.s0), bswap32(outer.s1));
}

fn mod1000Shift20(hlo: u32, hhi: u32) -> u32 {
  return (((hhi % 1000u) * 96u) + (hlo >> 20u)) % 1000u;
}

fn mod1000Shift30(hlo: u32, hhi: u32) -> u32 {
  return (((hhi % 1000u) * 4u) + (hlo >> 30u)) % 1000u;
}

fn mod100(hlo: u32, hhi: u32) -> u32 {
  return (((hhi % 100u) * 96u) + (hlo % 100u)) % 100u;
}

fn mod100Shift10(hlo: u32, hhi: u32) -> u32 {
  return (((hhi % 100u) * 4u) + ((hlo >> 10u) % 100u)) % 100u;
}

fn addCarry(a: u32, b: u32) -> vec2<u32> {
  let sum = a + b;
  return vec2<u32>(sum, select(0u, 1u, sum < a));
}

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) globalId: vec3<u32>) {
  let idx = globalId.x;

  let s0 = addCarry(params.base0, idx);
  var c0 = s0.x;
  let s1 = addCarry(params.base1, s0.y);
  var c1 = s1.x;
  let s2 = addCarry(params.base2, s1.y);
  var c2 = s2.x;
  var c3 = params.base3 + s2.y;

  for (var iter = 0u; iter < params.iterations; iter = iter + 1u) {
    if (atomicLoad(&result.found) != 0u) {
      return;
    }

    let id0 = c0 ^ 0x7F4A7C15u;
    let id1 = c1 ^ 0x9E3779B9u;
    let id2 = c2 ^ 0x07BB0142u;
    let id3 = c3 ^ 0x6C62272Eu;
    let h = computeH(id0, id1, id2, id3);

    if (mod1000Shift20(h.lo, h.hi) == params.num1 &&
        mod1000Shift30(h.lo, h.hi) == params.num2 &&
        mod100(h.lo, h.hi) == params.ocean &&
        mod100Shift10(h.lo, h.hi) == params.isles) {
      let claim = atomicCompareExchangeWeak(&result.found, 0u, 1u);
      if (claim.exchanged) {
        result.id0 = id0;
        result.id1 = id1;
        result.id2 = id2;
        result.id3 = id3;
      }
      return;
    }

    let n0 = addCarry(c0, params.stride);
    c0 = n0.x;
    let n1 = addCarry(c1, n0.y);
    c1 = n1.x;
    let n2 = addCarry(c2, n1.y);
    c2 = n2.x;
    c3 = c3 + n2.y;
  }
}
`;

const ui = {
    alerts: document.getElementById("islandCompatibilityAlerts"),
    ocean: document.getElementById("islandOcean"),
    isles: document.getElementById("islandIsles"),
    num1: document.getElementById("islandNum1"),
    num2: document.getElementById("islandNum2"),
    start: document.getElementById("islandStart"),
    stop: document.getElementById("islandStop"),
    state: document.getElementById("islandState"),
    checked: document.getElementById("islandChecked"),
    rate: document.getElementById("islandRate"),
    miiUpload: document.getElementById("islandMiiUpload"),
    uploadStatus: document.getElementById("islandUploadStatus"),
    islandNameControl: document.getElementById("islandNameControl"),
    islandNameInput: document.getElementById("islandNameInput"),
    addressResult: document.getElementById("islandAddressResult"),
    idResult: document.getElementById("islandIdResult"),
    copyId: document.getElementById("islandCopyId"),
    miiQrResult: document.getElementById("islandMiiQrResult"),
    miiQrImage: document.getElementById("islandMiiQrImage"),
    miiQrStatus: document.getElementById("islandMiiQrStatus"),
    miiQrDownload: document.getElementById("islandMiiQrDownload"),
    islesOptions: document.getElementById("islandIslesOptions"),
    oceanOptions: document.getElementById("islandOceanOptions"),
    measure: document.getElementById("islandMeasure")
};
const ISLAND_QR_EXPORTS_ENABLED = Boolean(ui.miiQrResult);

let device;
let pipeline;
let bindGroup;
let paramsBuffer;
let resultBuffer;
let readbackBuffer;
let running = false;
let stopRequested = false;
let baseCounter = null;
let checked = 0;
let startedAt = 0;
let uploadedMiiFile = null;
let uploadedMiiHasTomodachiLifeData = false;
let uploadedMiiCanGenerateQr = false;
let latestIslandId = "";
let latestAddressParts = null;
let qrGenerationSerial = 0;
let islandNameQrTimer = null;

function showCompatibilityWarning(message) {
    const alert = document.createElement("p");
    alert.className = "island-compat-alert is-error";
    alert.textContent = message;
    ui.alerts?.appendChild(alert);
}

function foldText(value) {
    return String(value || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLocaleLowerCase();
}

function normalizeWord(value) {
    return foldText(value.trim());
}

function resizeInput(input) {
    if (!input || !ui.measure) return;
    const computed = getComputedStyle(input);
    ui.measure.style.font = computed.font;
    ui.measure.style.letterSpacing = computed.letterSpacing;
    ui.measure.textContent = input.value || input.placeholder || "0";
    const textWidth = ui.measure.getBoundingClientRect().width;
    const padding = Number.parseFloat(computed.paddingLeft) + Number.parseFloat(computed.paddingRight);
    const border = Number.parseFloat(computed.borderLeftWidth) + Number.parseFloat(computed.borderRightWidth);
    input.style.width = `${Math.ceil(textWidth + padding + border + 2)}px`;
}

function resizeAddressInputs() {
    for (const input of [ui.num1, ui.num2, ui.isles, ui.ocean]) {
        resizeInput(input);
    }
}

function bindAutoWidth(input) {
    input?.addEventListener("input", () => resizeInput(input));
    input?.addEventListener("change", () => resizeInput(input));
}

function clampAddressNumberInput(input) {
    if (!input) return;
    const digits = String(input.value || "").replace(/\D+/g, "");
    const nextValue = digits ? String(Math.min(999, Number(digits))) : "";
    if (input.value !== nextValue) input.value = nextValue;
    resizeInput(input);
}

function bindAddressNumberInput(input) {
    input?.addEventListener("beforeinput", (event) => {
        if (event.data && /\D/.test(event.data)) {
            event.preventDefault();
        }
    });
    input?.addEventListener("keydown", (event) => {
        if (["e", "E", "+", "-", ".", ","].includes(event.key)) {
            event.preventDefault();
        }
    });
    input?.addEventListener("input", () => clampAddressNumberInput(input));
    input?.addEventListener("change", () => clampAddressNumberInput(input));
}

function matchRange(word, query) {
    const needle = normalizeWord(query);
    if (!needle) return null;

    let folded = "";
    const offsets = [];
    let offset = 0;
    for (const character of word) {
        const piece = foldText(character);
        for (let i = 0; i < piece.length; i++) {
            offsets.push([offset, offset + character.length]);
        }
        folded += piece;
        offset += character.length;
    }

    const start = folded.indexOf(needle);
    if (start < 0) return null;
    return [offsets[start][0], offsets[start + needle.length - 1][1]];
}

function sortedWordRows(query) {
    const needle = normalizeWord(query);
    const hasQuery = needle.length > 0;
    return ISLAND_WORDS
        .map((word, index) => ({ word, index, range: matchRange(word, query) }))
        .sort((a, b) => {
            const aExact = hasQuery && normalizeWord(a.word) === needle;
            const bExact = hasQuery && normalizeWord(b.word) === needle;
            if (aExact !== bExact) return aExact ? -1 : 1;

            const aMatches = hasQuery && a.range !== null;
            const bMatches = hasQuery && b.range !== null;
            if (aMatches !== bMatches) return aMatches ? -1 : 1;
            if (aMatches && a.range[0] !== b.range[0]) return a.range[0] - b.range[0];
            return a.index - b.index;
        });
}

function appendHighlightedWord(option, word, range) {
    if (!range) {
        option.textContent = word;
        return;
    }

    const [start, end] = range;
    option.append(document.createTextNode(word.slice(0, start)));
    const mark = document.createElement("mark");
    mark.textContent = word.slice(start, end);
    option.append(mark, document.createTextNode(word.slice(end)));
}

function setActiveOption(input, list, option) {
    for (const item of list.querySelectorAll(".island-address-option")) {
        item.setAttribute("aria-selected", "false");
    }
    option.setAttribute("aria-selected", "true");
    input.setAttribute("aria-activedescendant", option.id);
    option.scrollIntoView({ block: "nearest" });
}

function renderWordOptions(input, list) {
    const rows = sortedWordRows(input.value);
    const exactIndex = WORD_INDEX.get(normalizeWord(input.value));
    const fragment = document.createDocumentFragment();
    let activeOption = null;

    for (const row of rows) {
        const option = document.createElement("button");
        option.type = "button";
        option.id = `${list.id}-${row.index}`;
        option.className = "island-address-option";
        option.dataset.index = String(row.index);
        option.setAttribute("role", "option");
        option.setAttribute("aria-selected", "false");
        if (row.range) option.classList.add("is-match");
        appendHighlightedWord(option, row.word, row.range);
        fragment.append(option);

        if (!activeOption && (row.index === exactIndex || exactIndex === undefined)) {
            activeOption = option;
        }
    }

    list.replaceChildren(fragment);
    if (activeOption) {
        setActiveOption(input, list, activeOption);
    } else {
        input.removeAttribute("aria-activedescendant");
    }
}

function closeWordPicker(input, list) {
    if (!input || !list) return;
    list.hidden = true;
    input.setAttribute("aria-expanded", "false");
    input.removeAttribute("aria-activedescendant");
}

function closeAllWordPickers() {
    closeWordPicker(ui.isles, ui.islesOptions);
    closeWordPicker(ui.ocean, ui.oceanOptions);
}

function openWordPicker(input, list) {
    closeAllWordPickers();
    renderWordOptions(input, list);
    list.hidden = false;
    input.setAttribute("aria-expanded", "true");
}

function selectWord(input, list, index) {
    input.value = ISLAND_WORDS[index];
    resizeInput(input);
    renderWordOptions(input, list);
    closeWordPicker(input, list);
    input.focus({ preventScroll: true });
}

function moveActiveOption(input, list, delta) {
    const options = Array.from(list.querySelectorAll(".island-address-option"));
    if (options.length === 0) return;
    const current = Math.max(0, options.findIndex((option) => option.getAttribute("aria-selected") === "true"));
    const next = (current + delta + options.length) % options.length;
    setActiveOption(input, list, options[next]);
}

function bindWordPicker(input, list) {
    input.addEventListener("focus", () => openWordPicker(input, list));
    input.addEventListener("click", () => openWordPicker(input, list));
    input.addEventListener("input", () => {
        renderWordOptions(input, list);
        list.hidden = false;
        input.setAttribute("aria-expanded", "true");
    });
    input.addEventListener("keydown", (event) => {
        if (event.key === "ArrowDown" || event.key === "ArrowUp") {
            event.preventDefault();
            if (list.hidden) {
                openWordPicker(input, list);
            } else {
                moveActiveOption(input, list, event.key === "ArrowDown" ? 1 : -1);
            }
            return;
        }
        if (event.key === "Enter" && !list.hidden) {
            const active = list.querySelector('[aria-selected="true"]');
            if (active) {
                event.preventDefault();
                selectWord(input, list, Number(active.dataset.index));
            }
            return;
        }
        if (event.key === "Escape") {
            closeWordPicker(input, list);
            return;
        }
        if (event.key === "Tab") closeWordPicker(input, list);
    });
    list.addEventListener("pointerdown", (event) => {
        const target = event.target instanceof Element ? event.target : null;
        const option = target?.closest(".island-address-option");
        if (!option) return;
        event.preventDefault();
        selectWord(input, list, Number(option.dataset.index));
    });
}

function readNumber(input, min, max) {
    const value = Number(input.value);
    if (!Number.isInteger(value) || value < min || value > max) {
        throw new Error(`${input.getAttribute("aria-label")} must be ${min}..${max}.`);
    }
    return value;
}

function readWordIndex(input, fieldName) {
    const index = WORD_INDEX.get(normalizeWord(input.value));
    if (index === undefined) {
        throw new Error(`${fieldName} must be selected from the word list.`);
    }
    input.value = ISLAND_WORDS[index];
    resizeInput(input);
    return index;
}

function random128() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    let value = BigInt(0);
    for (let i = 15; i >= 0; i--) {
        value = (value << SHIFT_8) | BigInt(bytes[i]);
    }
    return value;
}

function writeParams(target) {
    const bytes = new ArrayBuffer(48);
    const view = new DataView(bytes);
    view.setUint32(0, target.ocean, true);
    view.setUint32(4, target.isles, true);
    view.setUint32(8, target.num1, true);
    view.setUint32(12, target.num2, true);
    view.setUint32(16, Number(baseCounter & UINT32_MASK), true);
    view.setUint32(20, Number((baseCounter >> SHIFT_32) & UINT32_MASK), true);
    view.setUint32(24, Number((baseCounter >> SHIFT_64) & UINT32_MASK), true);
    view.setUint32(28, Number((baseCounter >> SHIFT_96) & UINT32_MASK), true);
    view.setUint32(32, ITERATIONS_PER_THREAD, true);
    view.setUint32(36, STRIDE, true);
    device.queue.writeBuffer(paramsBuffer, 0, bytes);
}

function wordsToHex(words) {
    let hex = "";
    for (const word of words) {
        for (let shift = 0; shift < 32; shift += 8) {
            hex += ((word >>> shift) & 0xff).toString(16).padStart(2, "0").toUpperCase();
        }
    }
    return hex;
}

function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

async function verifyResult(hex) {
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode("this is a tempolary key.\0"),
        { name: "HMAC", hash: "SHA-1" },
        false,
        ["sign"]
    );
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, hexToBytes(hex)));
    const hLo = digest[0] | (digest[1] << 8) | (digest[2] << 16) | (digest[3] << 24);
    const hHi = digest[4] | (digest[5] << 8) | (digest[6] << 16) | (digest[7] << 24);
    return {
        ocean: ((((hHi >>> 0) % 100) * 96) + ((hLo >>> 0) % 100)) % 100,
        isles: ((((hHi >>> 0) % 100) * 4) + (((hLo >>> 10) >>> 0) % 100)) % 100,
        num1: ((((hHi >>> 0) % 1000) * 96) + (hLo >>> 20)) % 1000,
        num2: ((((hHi >>> 0) % 1000) * 4) + (hLo >>> 30)) % 1000
    };
}

function formatInteger(value) {
    return new Intl.NumberFormat().format(value);
}

function updateStats() {
    const seconds = Math.max((performance.now() - startedAt) / 1000, 0.001);
    const rate = Number(checked) / seconds;
    ui.checked.textContent = formatInteger(checked);
    ui.rate.textContent = `${formatInteger(Math.round(rate))}/s`;
}

function setResultDisplay({ address = "No address yet.", id = "No ID yet.", canCopyId = false } = {}) {
    ui.addressResult.textContent = address;
    ui.idResult.textContent = id;
    ui.copyId.hidden = !canCopyId;
    ui.copyId.textContent = "Copy ID";
}

function getIslandNameLine() {
    if (ui.islandNameControl?.hidden) return "";
    const islandName = String(ui.islandNameInput?.value || "").replace(/\s+/g, " ").trim();
    return islandName ? `${islandName} Island` : "";
}

function formatAddressResult(parts) {
    if (!parts) return "No address yet.";
    const lines = [
        getIslandNameLine(),
        `${parts.num1}-${parts.num2} ${ISLAND_WORDS[parts.isles]} Isles`,
        `${ISLAND_WORDS[parts.ocean]} Ocean`
    ].filter(Boolean);
    return lines.join("\n");
}

function refreshFoundAddressDisplay() {
    if (!latestIslandId || !latestAddressParts) return;
    setResultDisplay({
        address: formatAddressResult(latestAddressParts),
        id: latestIslandId,
        canCopyId: true
    });
}

function setUploadStatus(message, isError = false) {
    if (!ui.uploadStatus) return;
    ui.uploadStatus.textContent = message;
    ui.uploadStatus.classList.toggle("is-error", isError);
}

function setIslandNameControl(isVisible, value = "") {
    if (!ui.islandNameControl || !ui.islandNameInput) return;
    ui.islandNameControl.hidden = !isVisible;
    if (isVisible) ui.islandNameInput.value = value || "";
}

function setAddressInputsFromUpload(address) {
    if (!address) return;
    if (Number.isInteger(address.num1)) ui.num1.value = String(address.num1);
    if (Number.isInteger(address.num2)) ui.num2.value = String(address.num2);
    clampAddressNumberInput(ui.num1);
    clampAddressNumberInput(ui.num2);
    if (address.isles) ui.isles.value = address.isles;
    if (address.ocean) ui.ocean.value = address.ocean;
    resizeAddressInputs();
}

function clearGeneratedQr(message = "QR not generated yet.", cancelPending = true) {
    if (cancelPending) qrGenerationSerial++;
    if (ui.miiQrImage) {
        ui.miiQrImage.hidden = true;
        ui.miiQrImage.removeAttribute("src");
    }
    if (ui.miiQrDownload) {
        ui.miiQrDownload.hidden = true;
        ui.miiQrDownload.removeAttribute("href");
    }
    if (ui.miiQrStatus) ui.miiQrStatus.textContent = message;
    if (ui.miiQrResult) ui.miiQrResult.hidden = true;
}

async function readJsonResponse(response) {
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
        throw new Error(payload?.error || `Request failed with HTTP ${response.status}.`);
    }
    if (payload?.error) {
        throw new Error(payload.error);
    }
    return payload || {};
}

async function analyzeUploadedMii() {
    const file = ui.miiUpload?.files?.[0] || null;
    uploadedMiiFile = file;
    uploadedMiiHasTomodachiLifeData = false;
    uploadedMiiCanGenerateQr = false;
    setIslandNameControl(false);
    clearGeneratedQr();

    if (!file) {
        setUploadStatus("No Mii uploaded.");
        return;
    }

    setUploadStatus("Reading Mii...");

    try {
        const formData = new FormData();
        formData.append("mii", file, file.name || "mii");
        const payload = await readJsonResponse(await fetch("/islandAddresses/analyzeMii", {
            method: "POST",
            body: formData
        }));

        if (file !== uploadedMiiFile) return;

        uploadedMiiHasTomodachiLifeData = Boolean(payload.hasTomodachiLifeData);
        uploadedMiiCanGenerateQr = ISLAND_QR_EXPORTS_ENABLED;
        setIslandNameControl(ISLAND_QR_EXPORTS_ENABLED, payload.islandName || "");

        if (!uploadedMiiHasTomodachiLifeData) {
            setUploadStatus(`Loaded ${payload.miiName || "Mii"}. No Tomodachi Life data found, so the address fields were left as-is.`);
        } else if (payload.address) {
            setAddressInputsFromUpload(payload.address);
            setUploadStatus(`Loaded ${payload.miiName || "Mii"} and filled its island address.`);
        } else {
            setUploadStatus(`Loaded ${payload.miiName || "Mii"}, but no island address was found.`, true);
        }

        refreshFoundAddressDisplay();
        if (latestIslandId) {
            void generateUploadedMiiQr(latestIslandId);
        }
    } catch (error) {
        if (file !== uploadedMiiFile) return;
        uploadedMiiHasTomodachiLifeData = false;
        uploadedMiiCanGenerateQr = false;
        setIslandNameControl(false);
        setUploadStatus(error.message || "Could not read that Mii file.", true);
    }
}

async function generateUploadedMiiQr(islandId) {
    if (!ISLAND_QR_EXPORTS_ENABLED || !uploadedMiiFile || !uploadedMiiCanGenerateQr || !islandId) return;

    const serial = ++qrGenerationSerial;
    const file = uploadedMiiFile;
    const islandName = ui.islandNameInput?.value || "";

    if (ui.miiQrResult) ui.miiQrResult.hidden = false;
    if (ui.miiQrImage) ui.miiQrImage.hidden = true;
    if (ui.miiQrDownload) ui.miiQrDownload.hidden = true;
    if (ui.miiQrStatus) ui.miiQrStatus.textContent = "Generating QR...";

    try {
        const formData = new FormData();
        formData.append("mii", file, file.name || "mii");
        formData.append("islandId", islandId);
        formData.append("islandName", islandName);

        const payload = await readJsonResponse(await fetch("/islandAddresses/generateMiiQr", {
            method: "POST",
            body: formData
        }));

        if (serial !== qrGenerationSerial || file !== uploadedMiiFile) return;

        ui.miiQrImage.src = payload.qrDataUri;
        ui.miiQrImage.hidden = false;
        ui.miiQrDownload.href = payload.qrDataUri;
        ui.miiQrDownload.download = payload.fileName || "tomodachi-life-mii.png";
        ui.miiQrDownload.hidden = false;
        ui.miiQrStatus.textContent = `${payload.islandName || "Island"} Island QR generated.`;
    } catch (error) {
        if (serial !== qrGenerationSerial || file !== uploadedMiiFile) return;
        if (ui.miiQrResult) ui.miiQrResult.hidden = false;
        if (ui.miiQrStatus) ui.miiQrStatus.textContent = error.message || "Could not generate the QR.";
    }
}

function queueUploadedMiiQrRegeneration() {
    refreshFoundAddressDisplay();
    if (!latestIslandId || !uploadedMiiFile || !uploadedMiiCanGenerateQr) return;
    window.clearTimeout(islandNameQrTimer);
    if (ui.miiQrResult) ui.miiQrResult.hidden = false;
    if (ui.miiQrStatus) ui.miiQrStatus.textContent = "Island name changed. Regenerating QR...";
    islandNameQrTimer = window.setTimeout(() => {
        void generateUploadedMiiQr(latestIslandId);
    }, 500);
}

function initRuntimeConstants() {
    if (!globalThis.BigInt) {
        throw new Error("This browser does not support BigInt, which is required for the island ID search.");
    }

    CHUNK_CANDIDATES = BigInt(STRIDE) * BigInt(ITERATIONS_PER_THREAD);
    MASK_128 = (BigInt(1) << BigInt(128)) - BigInt(1);
    UINT32_MASK = BigInt(0xffffffff);
    SHIFT_8 = BigInt(8);
    SHIFT_32 = BigInt(32);
    SHIFT_64 = BigInt(64);
    SHIFT_96 = BigInt(96);
}

async function initWebGpu() {
    if (!window.isSecureContext) {
        throw new Error("This tool needs a secure browser context. Open it over HTTPS or from localhost.");
    }
    if (!globalThis.BigInt) {
        throw new Error("This browser does not support BigInt, which is required for the island ID search.");
    }
    if (!globalThis.crypto?.getRandomValues || !globalThis.crypto?.subtle) {
        throw new Error("This browser does not expose the Web Crypto APIs needed to verify island IDs.");
    }
    if (!navigator.gpu) {
        throw new Error("WebGPU is not available in this browser or OS. Try a current desktop Chrome or Edge build with hardware acceleration enabled.");
    }

    const adapter = await navigator.gpu.requestAdapter();
    if (!adapter) {
        throw new Error("No compatible WebGPU adapter was found. This can happen on unsupported operating systems, disabled hardware acceleration, or GPU drivers without WebGPU support.");
    }

    device = await adapter.requestDevice();
    device.lost.then((info) => {
        stopRequested = true;
        ui.state.textContent = "Unavailable";
        ui.start.disabled = true;
        ui.stop.disabled = true;
        showCompatibilityWarning(`The WebGPU device was lost${info?.message ? `: ${info.message}` : "."}`);
    });

    const module = device.createShaderModule({ code: shaderSource });
    pipeline = await device.createComputePipelineAsync({
        layout: "auto",
        compute: { module, entryPoint: "main" }
    });

    paramsBuffer = device.createBuffer({
        size: 48,
        usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST
    });
    resultBuffer = device.createBuffer({
        size: 32,
        usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST
    });
    readbackBuffer = device.createBuffer({
        size: 32,
        usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST
    });

    bindGroup = device.createBindGroup({
        layout: pipeline.getBindGroupLayout(0),
        entries: [
            { binding: 0, resource: { buffer: paramsBuffer } },
            { binding: 1, resource: { buffer: resultBuffer } }
        ]
    });
}

async function runChunk(target) {
    writeParams(target);

    const encoder = device.createCommandEncoder();
    const pass = encoder.beginComputePass();
    pass.setPipeline(pipeline);
    pass.setBindGroup(0, bindGroup);
    pass.dispatchWorkgroups(DISPATCH_GROUPS);
    pass.end();
    encoder.copyBufferToBuffer(resultBuffer, 0, readbackBuffer, 0, 32);
    device.queue.submit([encoder.finish()]);
    await readbackBuffer.mapAsync(GPUMapMode.READ);
    const words = new Uint32Array(readbackBuffer.getMappedRange().slice(0));
    readbackBuffer.unmap();

    baseCounter = (baseCounter + CHUNK_CANDIDATES) & MASK_128;
    checked += CHUNK_CANDIDATES;
    return words;
}

async function startSearch() {
    if (running) return;

    let target;
    try {
        target = {
            ocean: readWordIndex(ui.ocean, "Ocean"),
            isles: readWordIndex(ui.isles, "Isles"),
            num1: readNumber(ui.num1, 0, 999),
            num2: readNumber(ui.num2, 0, 999)
        };
    } catch (error) {
        ui.state.textContent = "Invalid Input";
        setResultDisplay({ address: error.message });
        return;
    }

    running = true;
    stopRequested = false;
    latestIslandId = "";
    latestAddressParts = null;
    checked = BigInt(0);
    baseCounter = random128();
    startedAt = performance.now();
    setResultDisplay({ address: "Searching..." });
    clearGeneratedQr();
    ui.state.textContent = "Running";
    ui.start.disabled = true;
    ui.stop.disabled = false;
    device.queue.writeBuffer(resultBuffer, 0, new Uint32Array(8));

    try {
        while (!stopRequested) {
            const words = await runChunk(target);
            updateStats();

            if (words[0] !== 0) {
                const hex = wordsToHex(words.slice(1, 5));
                const decoded = await verifyResult(hex);
                ui.state.textContent = "Found";
                latestIslandId = hex;
                latestAddressParts = decoded;
                setResultDisplay({
                    address: formatAddressResult(decoded),
                    id: hex,
                    canCopyId: true
                });
                void generateUploadedMiiQr(hex);
                break;
            }

            await new Promise(requestAnimationFrame);
        }

        if (stopRequested) {
            ui.state.textContent = "Stopped";
            setResultDisplay({ address: "Stopped before a result was found." });
        }
    } catch (error) {
        ui.state.textContent = "Error";
        setResultDisplay({ address: error.message || "The search failed." });
    } finally {
        running = false;
        if (device) ui.start.disabled = false;
        ui.stop.disabled = true;
    }
}

for (const input of [ui.num1, ui.num2]) {
    bindAddressNumberInput(input);
}
for (const input of [ui.isles, ui.ocean]) {
    bindAutoWidth(input);
}
bindWordPicker(ui.isles, ui.islesOptions);
bindWordPicker(ui.ocean, ui.oceanOptions);
ui.miiUpload?.addEventListener("change", analyzeUploadedMii);
ui.islandNameInput?.addEventListener("input", queueUploadedMiiQrRegeneration);
resizeAddressInputs();
window.addEventListener("resize", resizeAddressInputs);
document.addEventListener("pointerdown", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target?.closest(".island-address-combo")) {
        closeAllWordPickers();
    }
});

ui.start.addEventListener("click", startSearch);
ui.stop.addEventListener("click", () => {
    stopRequested = true;
    ui.stop.disabled = true;
});
ui.copyId.addEventListener("click", async () => {
    await navigator.clipboard.writeText(ui.idResult.textContent || "");
    ui.copyId.textContent = "Copied";
    window.setTimeout(() => {
        ui.copyId.textContent = "Copy ID";
    }, 1200);
});

async function initializeIslandAddressSearch() {
    try {
        initRuntimeConstants();
        await initWebGpu();
        ui.state.textContent = "Ready";
        ui.start.textContent = "Start Search";
        ui.start.disabled = false;
    } catch (error) {
        ui.state.textContent = "Unavailable";
        ui.start.textContent = "Unavailable";
        ui.start.disabled = true;
        ui.stop.disabled = true;
        showCompatibilityWarning(error.message || "This browser or operating system cannot run the island address search.");
    }
}

initializeIslandAddressSearch();
