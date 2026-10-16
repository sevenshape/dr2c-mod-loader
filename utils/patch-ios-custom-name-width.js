const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath) {
    throw new Error(
        'Usage: node utils/patch-ios-custom-name-width.js /path/to/DR2C'
    );
}

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc1000 || binary.readUInt32LE(0) !== 0xfeedfacf)
    throw new Error(`Not the expected gum-grafted 64-bit Mach-O: ${resolved}`);

// The custom-character name editor is the only caller of the editable-field
// update routine at RVA 0x8216c. Its stock pixel truncator measures each UTF-8
// byte as a separate native glyph and may terminate in the middle of a Chinese
// character (for example, U+9F99 becomes the invalid byte pair E9 BE).
//
// The loader already enforces an 18-byte UTF-8-safe input limit. Eighteen ASCII
// glyphs fit the widened 144-pixel field, and any multibyte name has fewer
// rendered glyphs, so the native second truncation is both unnecessary and
// unsafe. Keep the widened field and make this one call report "no cut".
const WIDTH_RVA = 0x82200;
const TRUNCATE_CALL_RVA = 0x82204;
const ORIGINAL_WORD = 0x52800c01; // mov w1, #0x60 (96 px)
const REPLACEMENT_WORD = 0x52801201; // mov w1, #0x90 (144 px)
const ORIGINAL_TRUNCATE_CALL = 0x97ffefc8; // bl 0x7e124
const DISABLED_TRUNCATE_CALL = 0x52800000; // mov w0, #0

const actualWidth = binary.readUInt32LE(WIDTH_RVA) >>> 0;
if (![ORIGINAL_WORD, REPLACEMENT_WORD].includes(actualWidth)) {
    throw new Error(
        `Unexpected custom-name width instruction @ 0x${WIDTH_RVA.toString(16)}: ` +
        `got 0x${actualWidth.toString(16)}`
    );
}

const actualCall = binary.readUInt32LE(TRUNCATE_CALL_RVA) >>> 0;
if (![ORIGINAL_TRUNCATE_CALL, DISABLED_TRUNCATE_CALL].includes(actualCall)) {
    throw new Error(
        `Unexpected custom-name truncation instruction @ 0x${TRUNCATE_CALL_RVA.toString(16)}: ` +
        `got 0x${actualCall.toString(16)}`
    );
}

let changed = false;
if (actualWidth !== REPLACEMENT_WORD) {
    binary.writeUInt32LE(REPLACEMENT_WORD, WIDTH_RVA);
    changed = true;
}
if (actualCall !== DISABLED_TRUNCATE_CALL) {
    binary.writeUInt32LE(DISABLED_TRUNCATE_CALL, TRUNCATE_CALL_RVA);
    changed = true;
}

if (changed) {
    fs.writeFileSync(resolved, binary);
    console.log(`Patched UTF-8-safe iOS custom-name field in ${resolved}`);
} else {
    console.log(`Verified UTF-8-safe iOS custom-name field in ${resolved}`);
}
