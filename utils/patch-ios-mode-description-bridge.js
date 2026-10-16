const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath) {
    throw new Error(
        'Usage: node utils/patch-ios-mode-description-bridge.js /path/to/DR2C'
    );
}

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc0594 || binary.readUInt32LE(0) !== 0xfeedfacf) {
    throw new Error(`Not the expected gum-grafted 64-bit Mach-O: ${resolved}`);
}

// btn_gamemode_desc originally treats record+0x28 as an inline C string.  The
// compact record stores icon/lock/apply metadata there, while full.js keeps the
// description pointer table at MODE_BASE + 0x1000.  Redirect the one address
// calculation through a tiny static helper in the unused __FRIDA_TEXT0 tail.
// x20 is the selected record and x26 is MODE_BASE at this call site.
const CALL_RVA = 0x916b8;
const ORIGINAL_CALL_WORD = 0x9100a296; // add x22, x20, #0x28
const HELPER_RVA = 0x5e8580;
const FRIDA_TEXT_RVA = 0x5e8000;
const FRIDA_TEXT_FILE_OFFSET = 0xc0000;
const HELPER_FILE_OFFSET = FRIDA_TEXT_FILE_OFFSET + HELPER_RVA - FRIDA_TEXT_RVA;
const HELPER_WORDS = [
    0xcb1a0288, // sub x8, x20, x26
    0xd346fd08, // lsr x8, x8, #6
    0x91400749, // add x9, x26, #1, lsl #12
    0xf8687936, // ldr x22, [x9, x8, lsl #3]
    0xd65f03c0  // ret
];

function encodeBl(fromRva, toRva) {
    const delta = (toRva - fromRva) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 25) || delta >= 2 ** 25) {
        throw new Error('Mode-description bridge is outside BL range');
    }
    return (0x94000000 | (delta & 0x03ffffff)) >>> 0;
}

const callWord = encodeBl(CALL_RVA, HELPER_RVA);
const actualCall = binary.readUInt32LE(CALL_RVA) >>> 0;
if (actualCall !== ORIGINAL_CALL_WORD && actualCall !== callWord) {
    throw new Error(
        `Unexpected btn_gamemode_desc instruction @ 0x${CALL_RVA.toString(16)}: ` +
        `0x${actualCall.toString(16)}`
    );
}

const alreadyPatched = actualCall === callWord && HELPER_WORDS.every(
    (word, index) =>
        (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) ===
        (word >>> 0)
);

for (let index = 0; index < HELPER_WORDS.length; index++) {
    const offset = HELPER_FILE_OFFSET + index * 4;
    const actual = binary.readUInt32LE(offset) >>> 0;
    const expected = HELPER_WORDS[index] >>> 0;
    if (actual !== 0 && actual !== expected) {
        throw new Error(
            `Mode-description code cave is occupied @ 0x${offset.toString(16)}: ` +
            `0x${actual.toString(16)}`
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
    `gamemode-description bridge in ${resolved}`
);
