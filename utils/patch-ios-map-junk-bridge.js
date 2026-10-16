const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath) {
    throw new Error(
        'Usage: node utils/patch-ios-map-junk-bridge.js /path/to/DR2C'
    );
}

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc0678 || binary.readUInt32LE(0) !== 0xfeedfacf) {
    throw new Error(`Not the expected gum-grafted 64-bit Mach-O: ${resolved}`);
}

// Resource pickup ID 7 alone formats the literal "junk.".  Replace the NOP
// immediately after its ADR with a strict-signing-safe helper that substitutes
// the localized pointer published at __FRIDA_DATA0 + 0x940.  If full.js has not
// initialized the table yet, x8 retains the original native literal.
const CALL_RVA = 0x6b248;
const ORIGINAL_CALL_WORD = 0xd503201f;
const HELPER_RVA = 0x5e8660;
const FRIDA_TEXT_RVA = 0x5e8000;
const FRIDA_TEXT_FILE_OFFSET = 0xc0000;
const HELPER_FILE_OFFSET = FRIDA_TEXT_FILE_OFFSET + HELPER_RVA - FRIDA_TEXT_RVA;
const HELPER_WORDS = [
    0x9000002a, // adrp x10, 0x5ec000 (__FRIDA_DATA0)
    0x9125014a, // add x10, x10, #0x940
    0xf9400149, // ldr x9, [x10]
    0xf100013f, // cmp x9, #0
    0x9a881128, // csel x8, x9, x8, ne (fallback to native "junk.")
    0xd65f03c0  // ret
];

function encodeBl(fromRva, toRva) {
    const delta = (toRva - fromRva) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 25) || delta >= 2 ** 25) {
        throw new Error('Map-junk bridge is outside BL range');
    }
    return (0x94000000 | (delta & 0x03ffffff)) >>> 0;
}

const callWord = encodeBl(CALL_RVA, HELPER_RVA);
const actualCall = binary.readUInt32LE(CALL_RVA) >>> 0;
if (actualCall !== ORIGINAL_CALL_WORD && actualCall !== callWord) {
    throw new Error(
        `Unexpected map-junk instruction @ 0x${CALL_RVA.toString(16)}: ` +
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
        `Map-junk code cave is occupied @ 0x${HELPER_FILE_OFFSET.toString(16)}`
    );
}

// One runtime pointer at __FRIDA_DATA0 + 0x940.
const DATA_TABLE_FILE_OFFSET = 0xc4940;
for (let offset = DATA_TABLE_FILE_OFFSET;
    offset < DATA_TABLE_FILE_OFFSET + 8; offset++) {
    if (binary[offset] !== 0) {
        throw new Error(
            `Map-event data table is occupied @ 0x${offset.toString(16)}`
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
    `map-junk bridge in ${resolved}`
);
