const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath) {
    throw new Error(
        'Usage: node utils/patch-ios-equipment-swap-none-bridge.js /path/to/DR2C'
    );
}

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc06b8 || binary.readUInt32LE(0) !== 0xfeedfacf) {
    throw new Error(`Not the expected gum-grafted 64-bit Mach-O: ${resolved}`);
}

// The pause-menu equipment swap layout stores the native literal "NONE"
// directly into the empty equipment button.  Replace its adjacent NOP with a
// strict-signing-safe helper that loads the existing localized NONE pointer
// from __FRIDA_DATA0 + 0x950.  Other uses of NONE remain unchanged.
const CALL_RVA = 0x33504;
const ORIGINAL_CALL_WORD = 0xd503201f;
const HELPER_RVA = 0x5e86a0;
const FRIDA_TEXT_RVA = 0x5e8000;
const FRIDA_TEXT_FILE_OFFSET = 0xc0000;
const HELPER_FILE_OFFSET = FRIDA_TEXT_FILE_OFFSET + HELPER_RVA - FRIDA_TEXT_RVA;
const HELPER_WORDS = [
    0x9000002a, // adrp x10, 0x5ec000 (__FRIDA_DATA0)
    0x9125414a, // add x10, x10, #0x950
    0xf9400149, // ldr x9, [x10]
    0xf100013f, // cmp x9, #0
    0x9a881128, // csel x8, x9, x8, ne (fallback to native "NONE")
    0xd65f03c0  // ret
];

function encodeBl(fromRva, toRva) {
    const delta = (toRva - fromRva) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 25) || delta >= 2 ** 25) {
        throw new Error('Equipment-swap NONE bridge is outside BL range');
    }
    return (0x94000000 | (delta & 0x03ffffff)) >>> 0;
}

const callWord = encodeBl(CALL_RVA, HELPER_RVA);
const actualCall = binary.readUInt32LE(CALL_RVA) >>> 0;
if (actualCall !== ORIGINAL_CALL_WORD && actualCall !== callWord) {
    throw new Error(
        `Unexpected equipment NONE instruction @ 0x${CALL_RVA.toString(16)}: ` +
        `0x${actualCall.toString(16)}`
    );
}

const helperMatches = HELPER_WORDS.every((word, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) ===
    (word >>> 0)
);
const helperEmpty = HELPER_WORDS.every((_, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) === 0
);
if (!helperMatches && !helperEmpty) {
    throw new Error(
        `Equipment NONE code cave is occupied @ 0x${HELPER_FILE_OFFSET.toString(16)}`
    );
}

const DATA_POINTER_FILE_OFFSET = 0xc4950;
for (let offset = DATA_POINTER_FILE_OFFSET;
    offset < DATA_POINTER_FILE_OFFSET + 8; offset++) {
    if (binary[offset] !== 0) {
        throw new Error(
            `Equipment NONE data pointer is occupied @ 0x${offset.toString(16)}`
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
    `equipment-swap NONE bridge in ${resolved}`
);
