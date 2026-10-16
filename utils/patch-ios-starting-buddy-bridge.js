const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath) {
    throw new Error(
        'Usage: node utils/patch-ios-starting-buddy-bridge.js /path/to/DR2C'
    );
}

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc0714 || binary.readUInt32LE(0) !== 0xfeedfacf) {
    throw new Error(`Not the expected gum-grafted 64-bit Mach-O: ${resolved}`);
}

// The starting-companion toggle selects native "No buddy" and "With buddy"
// pointers, then stores the chosen pointer directly into the button.  Replace
// the NOP after the second ADR with a branch to a helper that substitutes both
// localized pointers from __FRIDA_DATA0 + 0x968 before the state selection.
// This callback is a leaf function and does not save x30, so the bridge must
// use B in both directions instead of BL/RET.
const CALL_RVA = 0x554c4;
const ORIGINAL_CALL_WORD = 0xd503201f;
const HELPER_RVA = 0x5e86f0;
const FRIDA_TEXT_RVA = 0x5e8000;
const FRIDA_TEXT_FILE_OFFSET = 0xc0000;
const HELPER_FILE_OFFSET = FRIDA_TEXT_FILE_OFFSET + HELPER_RVA - FRIDA_TEXT_RVA;
const HELPER_WORDS = [
    0x9000002c, // adrp x12, 0x5ec000 (__FRIDA_DATA0)
    0x9125a18c, // add x12, x12, #0x968
    0xf940018d, // ldr x13, [x12] (No buddy)
    0xf10001bf, // cmp x13, #0
    0x9a8a11aa, // csel x10, x13, x10, ne
    0xf940058d, // ldr x13, [x12, #8] (With buddy)
    0xf10001bf, // cmp x13, #0
    0x9a8b11ab, // csel x11, x13, x11, ne
    0x17e9b36e  // b 0x554c8 (resume without touching x30)
];
const LEGACY_HELPER_WORDS = [
    0x9000002c, 0x9125a18c, 0xf940018d, 0xf10001bf,
    0x9a8a11aa, 0xf940058d, 0xf10001bf, 0x9a8b11ab,
    0xd65f03c0
];

function encodeBranch(fromRva, toRva, opcode) {
    const delta = (toRva - fromRva) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 25) || delta >= 2 ** 25) {
        throw new Error('Starting-buddy bridge is outside branch range');
    }
    return (opcode | (delta & 0x03ffffff)) >>> 0;
}

const callWord = encodeBranch(CALL_RVA, HELPER_RVA, 0x14000000);
const legacyCallWord = encodeBranch(CALL_RVA, HELPER_RVA, 0x94000000);
const actualCall = binary.readUInt32LE(CALL_RVA) >>> 0;
if (actualCall !== ORIGINAL_CALL_WORD && actualCall !== callWord &&
    actualCall !== legacyCallWord) {
    throw new Error(
        `Unexpected starting-buddy instruction @ 0x${CALL_RVA.toString(16)}: ` +
        `0x${actualCall.toString(16)}`
    );
}

const helperMatches = HELPER_WORDS.every((word, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) ===
    (word >>> 0)
);
const helperLegacy = LEGACY_HELPER_WORDS.every((word, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) ===
    (word >>> 0)
);
const helperEmpty = HELPER_WORDS.every((_, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) === 0
);
if (!helperMatches && !helperEmpty && !helperLegacy) {
    throw new Error(
        `Starting-buddy code cave is occupied @ 0x${HELPER_FILE_OFFSET.toString(16)}`
    );
}

const DATA_TABLE_FILE_OFFSET = 0xc4968;
for (let offset = DATA_TABLE_FILE_OFFSET;
    offset < DATA_TABLE_FILE_OFFSET + 0x10; offset++) {
    if (binary[offset] !== 0) {
        throw new Error(
            `Starting-buddy data table is occupied @ 0x${offset.toString(16)}`
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
    `starting-buddy bridge in ${resolved}`
);
