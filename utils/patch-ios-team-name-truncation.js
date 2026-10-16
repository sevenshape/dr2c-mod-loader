const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath) {
    throw new Error(
        'Usage: node utils/patch-ios-team-name-truncation.js /path/to/DR2C'
    );
}

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc1000 || binary.readUInt32LE(0) !== 0xfeedfacf)
    throw new Error(`Not the expected gum-grafted 64-bit Mach-O: ${resolved}`);

const FRIDA_TEXT_RVA = 0x5e8000;
const FRIDA_TEXT_FILE_OFFSET = 0xc0000;
const HELPER_RVA = 0x5e87a0;
const HELPER_FILE_OFFSET = FRIDA_TEXT_FILE_OFFSET + HELPER_RVA - FRIDA_TEXT_RVA;
const WIDTH_RVA = 0x42730;
const CALL_RVA = 0x42734;

function encodeBl(fromRva, toRva) {
    const delta = (toRva - fromRva) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 25) || delta >= 2 ** 25)
        throw new Error(`BL target is out of range at 0x${fromRva.toString(16)}`);
    return (0x94000000 | (delta & 0x03ffffff)) >>> 0;
}

// The helper below no longer uses the native pixel-width argument: that
// routine measures the original font and disagrees with the translated font.
// Accept both values so this patch upgrades either a clean binary or beta 4.
const ORIGINAL_WIDTH_WORD = 0x52800801; // mov w1, #0x40
const REPLACEMENT_WIDTH_WORD = 0x52800f01; // mov w1, #0x78

// Beta 4 delegated to the native glyph-width routine and only repaired the
// returned UTF-8 boundary. Keep its words here solely so an installed/tested
// beta 4 build can be upgraded in place.
const LEGACY_HELPER_WORDS = [
    0xa9be4ff4, 0xa9017bfd, 0x910043fd, 0xaa0003f3,
    encodeBl(HELPER_RVA + 0x10, 0x7e124),
    0x34000140, 0x2a0003f4, 0x38744a68, 0x121a0508,
    0x7102011f, 0x54000061, 0x51000694, 0x17fffffb,
    0x38344a7f, 0x2a1403e0, 0xa9417bfd, 0xa8c24ff4,
    0xd65f03c0
];

// Deterministic Team-column measurement for the translated font:
//   ASCII code point     = 1 display unit
//   non-ASCII code point = 2 display units
// The 13-unit budget preserves six CJK characters (12 units), while 18 wide
// ASCII characters become a safe 13-character prefix plus the caller's dot.
// The helper advances by complete UTF-8 code points and therefore cannot split
// a Chinese character. It only edits the Team row's temporary stack copy.
const FIFTEEN_UNIT_HELPER_WORDS = [
    0xa9bd57f6, 0xa9014ff4, 0xa9027bfd, 0x910083fd,
    0xaa0003f3, 0x2a1f03f4, 0x2a1f03f5, 0x38744a68,
    0x34000348, 0x37380088, 0x52800029, 0x5280002a,
    0x1400000d, 0x121c0d0b, 0x7103c17f, 0x54000100,
    0x121b090b, 0x7103817f, 0x54000060, 0x52800049,
    0x14000004, 0x52800069, 0x14000002, 0x52800089,
    0x5280004a, 0x0b0a02ab, 0x71003d7f, 0x5400008c,
    0x2a0b03f5, 0x0b090294, 0x17ffffe9, 0x38344a7f,
    0x2a1403e0, 0x14000002, 0x2a1f03e0, 0xa9427bfd,
    0xa9414ff4, 0xa8c357f6, 0xd65f03c0
];
const HELPER_WORDS = FIFTEEN_UNIT_HELPER_WORDS.map((word, index) =>
    index === 26 ? 0x7100357f : word // cmp w11, #13
);

const helperMatches = HELPER_WORDS.every((word, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) ===
        (word >>> 0)
);
const helperEmpty = HELPER_WORDS.every((_, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) === 0
);
const legacyHelperMatches = LEGACY_HELPER_WORDS.every((word, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) ===
        (word >>> 0)
) && HELPER_WORDS.slice(LEGACY_HELPER_WORDS.length).every((_, index) =>
    (binary.readUInt32LE(
        HELPER_FILE_OFFSET + (LEGACY_HELPER_WORDS.length + index) * 4
    ) >>> 0) === 0
);
const fifteenUnitHelperMatches = FIFTEEN_UNIT_HELPER_WORDS.every((word, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) ===
        (word >>> 0)
);
if (
    !helperMatches &&
    !helperEmpty &&
    !legacyHelperMatches &&
    !fifteenUnitHelperMatches
) {
    throw new Error(
        `Team-name display-unit helper cave is occupied @ 0x${HELPER_FILE_OFFSET.toString(16)}`
    );
}

const originalCall = encodeBl(CALL_RVA, 0x82268);
const disabledCall = 0x52800000; // previous fix: mov w0, #0
const replacementCall = encodeBl(CALL_RVA, HELPER_RVA);
const actualCall = binary.readUInt32LE(CALL_RVA) >>> 0;
if (![originalCall, disabledCall, replacementCall].includes(actualCall)) {
    throw new Error(
        `Unexpected team-name truncation instruction @ 0x${CALL_RVA.toString(16)}: ` +
        `0x${actualCall.toString(16)}`
    );
}

const actualWidth = binary.readUInt32LE(WIDTH_RVA) >>> 0;
if (![ORIGINAL_WIDTH_WORD, REPLACEMENT_WIDTH_WORD].includes(actualWidth)) {
    throw new Error(
        `Unexpected team-name width instruction @ 0x${WIDTH_RVA.toString(16)}: ` +
        `0x${actualWidth.toString(16)}`
    );
}

let changed = false;
if (actualWidth !== REPLACEMENT_WIDTH_WORD) {
    binary.writeUInt32LE(REPLACEMENT_WIDTH_WORD, WIDTH_RVA);
    changed = true;
}
if (actualCall !== replacementCall) {
    binary.writeUInt32LE(replacementCall, CALL_RVA);
    changed = true;
}
if (!helperMatches) {
    HELPER_WORDS.forEach((word, index) => {
        binary.writeUInt32LE(
            word >>> 0,
            HELPER_FILE_OFFSET + index * 4
        );
    });
    changed = true;
}

if (changed) {
    fs.writeFileSync(resolved, binary);
    console.log(`Patched display-unit-safe iOS Team name-column truncation in ${resolved}`);
} else {
    console.log(`Verified display-unit-safe iOS Team name-column truncation in ${resolved}`);
}
