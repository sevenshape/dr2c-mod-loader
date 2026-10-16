const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath) {
    throw new Error(
        'Usage: node utils/patch-ios-car-empty-bridge.js /path/to/DR2C'
    );
}

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc0698 || binary.readUInt32LE(0) !== 0xfeedfacf) {
    throw new Error(`Not the expected gum-grafted 64-bit Mach-O: ${resolved}`);
}

// The interaction code references the shared native literal "empty" twice:
// once when an approached wreck is already empty, and once after siphoning its
// final unit of gas.  Redirect only those two NOP slots through a helper that
// reads the context-specific pointer at __FRIDA_DATA0 + 0x948.  Character-slot
// empty text and every other use of the shared literal remain untouched.
const CALL_RVAS = [0x6a970, 0x6ac1c];
const ORIGINAL_CALL_WORD = 0xd503201f;
const HELPER_RVA = 0x5e8680;
const FRIDA_TEXT_RVA = 0x5e8000;
const FRIDA_TEXT_FILE_OFFSET = 0xc0000;
const HELPER_FILE_OFFSET = FRIDA_TEXT_FILE_OFFSET + HELPER_RVA - FRIDA_TEXT_RVA;
const HELPER_WORDS = [
    0x9000002a, // adrp x10, 0x5ec000 (__FRIDA_DATA0)
    0x9125214a, // add x10, x10, #0x948
    0xf9400149, // ldr x9, [x10]
    0xf100013f, // cmp x9, #0
    0x9a811121, // csel x1, x9, x1, ne (fallback to native "empty")
    0xd65f03c0  // ret
];

function encodeBl(fromRva, toRva) {
    const delta = (toRva - fromRva) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 25) || delta >= 2 ** 25) {
        throw new Error('Car-empty bridge is outside BL range');
    }
    return (0x94000000 | (delta & 0x03ffffff)) >>> 0;
}

let alreadyPatched = true;
const calls = CALL_RVAS.map(callRva => {
    const callWord = encodeBl(callRva, HELPER_RVA);
    const actualCall = binary.readUInt32LE(callRva) >>> 0;
    if (actualCall !== ORIGINAL_CALL_WORD && actualCall !== callWord) {
        throw new Error(
            `Unexpected car-empty instruction @ 0x${callRva.toString(16)}: ` +
            `0x${actualCall.toString(16)}`
        );
    }
    alreadyPatched = alreadyPatched && actualCall === callWord;
    return {callRva, callWord};
});

const helperMatches = HELPER_WORDS.every((word, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) ===
    (word >>> 0)
);
const helperEmpty = HELPER_WORDS.every((_, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) === 0
);
if (!helperMatches && !helperEmpty) {
    throw new Error(
        `Car-empty code cave is occupied @ 0x${HELPER_FILE_OFFSET.toString(16)}`
    );
}
alreadyPatched = alreadyPatched && helperMatches;

// Second pointer in the map-event table, after the "junk." pointer.
const DATA_POINTER_FILE_OFFSET = 0xc4948;
for (let offset = DATA_POINTER_FILE_OFFSET;
    offset < DATA_POINTER_FILE_OFFSET + 8; offset++) {
    if (binary[offset] !== 0) {
        throw new Error(
            `Car-empty data pointer is occupied @ 0x${offset.toString(16)}`
        );
    }
}

calls.forEach(({callRva, callWord}) => {
    binary.writeUInt32LE(callWord, callRva);
});
HELPER_WORDS.forEach((word, index) => {
    binary.writeUInt32LE(word >>> 0, HELPER_FILE_OFFSET + index * 4);
});
fs.writeFileSync(resolved, binary);
console.log(
    `${alreadyPatched ? 'Verified' : 'Patched'} strict iOS ` +
    `car-empty bridge in ${resolved}`
);
