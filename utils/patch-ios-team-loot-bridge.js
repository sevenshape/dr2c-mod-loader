const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath) {
    throw new Error(
        'Usage: node utils/patch-ios-team-loot-bridge.js /path/to/DR2C'
    );
}

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc06f0 || binary.readUInt32LE(0) !== 0xfeedfacf) {
    throw new Error(`Not the expected gum-grafted 64-bit Mach-O: ${resolved}`);
}

// team_layout_team formats the car-loot header before normal text hooks run.
// It also substitutes the native literal "nothing" when a member's loot
// buffer is empty.  One helper at the NOP following the header ADR replaces
// both arguments from a two-pointer table in writable __FRIDA_DATA0 space.
// Preserve the localized empty pointer in x23 because the following member
// loop reuses that register for each character with no collected resources.
const CALL_RVA = 0x426b4;
const ORIGINAL_CALL_WORD = 0xd503201f;
const HELPER_RVA = 0x5e86c0;
const FRIDA_TEXT_RVA = 0x5e8000;
const FRIDA_TEXT_FILE_OFFSET = 0xc0000;
const HELPER_FILE_OFFSET = FRIDA_TEXT_FILE_OFFSET + HELPER_RVA - FRIDA_TEXT_RVA;
const HELPER_WORDS = [
    0x9000002a, // adrp x10, 0x5ec000 (__FRIDA_DATA0)
    0x9125614a, // add x10, x10, #0x958
    0xf9400149, // ldr x9, [x10] (localized "nothing")
    0xf100013f, // cmp x9, #0
    0x9a971129, // csel x9, x9, x23, ne (native fallback)
    0xeb17011f, // cmp x8, x23 (did the layout select "nothing"?)
    0x9a880128, // csel x8, x9, x8, eq
    0xaa0903f7, // mov x23, x9 (reuse for empty character-loot rows)
    0xf9400549, // ldr x9, [x10, #8] (localized header format)
    0xf100013f, // cmp x9, #0
    0x9a831123, // csel x3, x9, x3, ne (native fallback)
    0xd65f03c0  // ret
];
const LEGACY_HELPER_WORDS = [
    0x9000002a, 0x9125614a, 0xf9400149, 0xf100013f,
    0x9a971129, 0xeb17011f, 0x9a880128, 0xf9400549,
    0xf100013f, 0x9a831123, 0xd65f03c0, 0
];

function encodeBl(fromRva, toRva) {
    const delta = (toRva - fromRva) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 25) || delta >= 2 ** 25) {
        throw new Error('Team-loot bridge is outside BL range');
    }
    return (0x94000000 | (delta & 0x03ffffff)) >>> 0;
}

const callWord = encodeBl(CALL_RVA, HELPER_RVA);
const actualCall = binary.readUInt32LE(CALL_RVA) >>> 0;
if (actualCall !== ORIGINAL_CALL_WORD && actualCall !== callWord) {
    throw new Error(
        `Unexpected team-loot instruction @ 0x${CALL_RVA.toString(16)}: ` +
        `0x${actualCall.toString(16)}`
    );
}

const actualHelperWords = HELPER_WORDS.map((_, index) =>
    binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0
);
const matchesHelper = words => words.every((word, index) =>
    actualHelperWords[index] === (word >>> 0)
);
const helperMatches = matchesHelper(HELPER_WORDS);
const helperEmpty = actualHelperWords.every(word => word === 0);
const helperLegacy = matchesHelper(LEGACY_HELPER_WORDS);
if (!helperMatches && !helperEmpty && !helperLegacy) {
    throw new Error(
        `Team-loot code cave is occupied @ 0x${HELPER_FILE_OFFSET.toString(16)}`
    );
}

// Two pointers: localized empty-member text and localized header format.
const DATA_TABLE_FILE_OFFSET = 0xc4958;
for (let offset = DATA_TABLE_FILE_OFFSET;
    offset < DATA_TABLE_FILE_OFFSET + 0x10; offset++) {
    if (binary[offset] !== 0) {
        throw new Error(
            `Team-loot data table is occupied @ 0x${offset.toString(16)}`
        );
    }
}

const alreadyPatched = actualCall === callWord && helperMatches;
binary.writeUInt32LE(callWord, CALL_RVA);
HELPER_WORDS.forEach((word, index) => {
    binary.writeUInt32LE(word >>> 0, HELPER_FILE_OFFSET + index * 4);
});
fs.writeFileSync(resolved, binary);
console.log(
    `${alreadyPatched ? 'Verified' : 'Patched'} strict iOS ` +
    `team-loot bridge in ${resolved}`
);
