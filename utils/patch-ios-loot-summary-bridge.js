const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath) {
    throw new Error(
        'Usage: node utils/patch-ios-loot-summary-bridge.js /path/to/DR2C'
    );
}

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc05c8 || binary.readUInt32LE(0) !== 0xfeedfacf) {
    throw new Error(`Not the expected gum-grafted 64-bit Mach-O: ${resolved}`);
}

// cyoa_loot_summary normally gives snprintf an English resource pointer and
// format string.  full.js publishes localized equivalents in unused writable
// __FRIDA_DATA0 space at RVA 0x5ec800.
// Redirect the argument setup through unused __FRIDA_TEXT0 space so this also
// works under strict self-signing, where libc interception is unavailable.
const CALL_RVA = 0x5bac0;
const ORIGINAL_CALL_WORD = 0xa90123e0; // stp x0, x8, [sp, #0x10]
const HELPER_RVA = 0x5e85a0;
const FRIDA_TEXT_RVA = 0x5e8000;
const FRIDA_TEXT_FILE_OFFSET = 0xc0000;
const HELPER_FILE_OFFSET = FRIDA_TEXT_FILE_OFFSET + HELPER_RVA - FRIDA_TEXT_RVA;
const HELPER_WORDS = [
    0x9000002a, // adrp x10, 0x5ec000 (__FRIDA_DATA0)
    0x9120014a, // add x10, x10, #0x800
    0xf873794b, // ldr x11, [x10, x19, lsl #3]
    0xf100017f, // cmp x11, #0
    0x9a80116b, // csel x11, x11, x0, ne (fallback to native name)
    0xa90123eb, // stp x11, x8, [sp, #0x10]
    0xf940214b, // ldr x11, [x10, #0x40]
    0xf100017f, // cmp x11, #0
    0x9a941174, // csel x20, x11, x20, ne (fallback to native format)
    0xd65f03c0  // ret
];
const BSS_HELPER_WORDS = [
    0xb0fff80a, 0x9105a14a, 0xf873794b, 0xf100017f, 0x9a80116b,
    0xa90123eb, 0xf940214b, 0xf100017f, 0x9a941174, 0xd65f03c0
];
const LEGACY_HELPER_WORDS = [
    0xb0fff80a, 0x9105a14a, 0xf873794b,
    0xa90123eb, 0xf9402154, 0xd65f03c0, 0, 0, 0, 0
];

function encodeBl(fromRva, toRva) {
    const delta = (toRva - fromRva) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 25) || delta >= 2 ** 25) {
        throw new Error('Loot-summary bridge is outside BL range');
    }
    return (0x94000000 | (delta & 0x03ffffff)) >>> 0;
}

const callWord = encodeBl(CALL_RVA, HELPER_RVA);
const actualCall = binary.readUInt32LE(CALL_RVA) >>> 0;
if (actualCall !== ORIGINAL_CALL_WORD && actualCall !== callWord) {
    throw new Error(
        `Unexpected cyoa_loot_summary instruction @ 0x${CALL_RVA.toString(16)}: ` +
        `0x${actualCall.toString(16)}`
    );
}

const actualHelperWords = HELPER_WORDS.map((_, index) =>
    binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0
);
const matchesHelper = words => words.every(
    (word, index) => actualHelperWords[index] === (word >>> 0)
);
const ZERO_HELPER_WORDS = HELPER_WORDS.map(() => 0);
if (![HELPER_WORDS, BSS_HELPER_WORDS, LEGACY_HELPER_WORDS, ZERO_HELPER_WORDS]
    .some(matchesHelper)) {
    throw new Error(
        `Loot-summary code cave is occupied @ 0x${HELPER_FILE_OFFSET.toString(16)}`
    );
}

const alreadyPatched = actualCall === callWord && matchesHelper(HELPER_WORDS);

// The pointer table occupies 0x48 bytes in the otherwise unused data tail.
const DATA_TABLE_FILE_OFFSET = 0xc4800;
for (let offset = DATA_TABLE_FILE_OFFSET; offset < DATA_TABLE_FILE_OFFSET + 0x48; offset++) {
    if (binary[offset] !== 0) {
        throw new Error(
            `Loot-summary data table is occupied @ 0x${offset.toString(16)}`
        );
    }
}

binary.writeUInt32LE(callWord, CALL_RVA);
for (let index = 0; index < HELPER_WORDS.length; index++) {
    binary.writeUInt32LE(HELPER_WORDS[index] >>> 0, HELPER_FILE_OFFSET + index * 4);
}
fs.writeFileSync(resolved, binary);
console.log(
    `${alreadyPatched ? 'Verified' : 'Patched'} strict iOS ` +
    `loot-summary bridge in ${resolved}`
);
