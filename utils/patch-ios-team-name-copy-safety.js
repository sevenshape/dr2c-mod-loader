const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath) {
    throw new Error(
        'Usage: node utils/patch-ios-team-name-copy-safety.js /path/to/DR2C'
    );
}

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc1000 || binary.readUInt32LE(0) !== 0xfeedfacf)
    throw new Error(`Not the expected gum-grafted 64-bit Mach-O: ${resolved}`);

const FRIDA_TEXT_RVA = 0x5e8000;
const FRIDA_TEXT_FILE_OFFSET = 0xc0000;
const HELPER_RVA = 0x5e8780;
const HELPER_FILE_OFFSET = FRIDA_TEXT_FILE_OFFSET + HELPER_RVA - FRIDA_TEXT_RVA;
const STRNCPY_STUB_RVA = 0xa1d4c;
const CALL_RVAS = [0x40f50, 0x413b4];

function encodeBl(fromRva, toRva) {
    const delta = (toRva - fromRva) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 25) || delta >= 2 ** 25)
        throw new Error(`BL target is out of range at 0x${fromRva.toString(16)}`);
    return (0x94000000 | (delta & 0x03ffffff)) >>> 0;
}

// Both callers provide a 19-byte stack destination. Copy at most 18 bytes and
// always terminate byte 18 so legacy overlong names cannot make strlen()/the
// suffix writer walk into the stack canary. Newly entered names are already
// limited to a valid UTF-8 prefix of at most 18 bytes by full.js.
const HELPER_WORDS = [
    0xa9bf7bfd, // stp x29, x30, [sp, #-0x10]!
    0x910003fd, // mov x29, sp
    0x52800242, // mov w2, #0x12
    encodeBl(HELPER_RVA + 0x0c, STRNCPY_STUB_RVA),
    0x3900481f, // strb wzr, [x0, #0x12]
    0xa8c17bfd, // ldp x29, x30, [sp], #0x10
    0xd65f03c0  // ret
];

const helperMatches = HELPER_WORDS.every((word, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) ===
        (word >>> 0)
);
const helperEmpty = HELPER_WORDS.every((_, index) =>
    (binary.readUInt32LE(HELPER_FILE_OFFSET + index * 4) >>> 0) === 0
);
if (!helperMatches && !helperEmpty) {
    throw new Error(
        `Team-name copy helper cave is occupied @ 0x${HELPER_FILE_OFFSET.toString(16)}`
    );
}

let changed = false;
for (const callRva of CALL_RVAS) {
    const original = encodeBl(callRva, STRNCPY_STUB_RVA);
    const replacement = encodeBl(callRva, HELPER_RVA);
    const actual = binary.readUInt32LE(callRva) >>> 0;
    if (actual === replacement) continue;
    if (actual !== original) {
        throw new Error(
            `Unexpected team-name strncpy call @ 0x${callRva.toString(16)}: ` +
            `expected 0x${original.toString(16)}, got 0x${actual.toString(16)}`
        );
    }
    binary.writeUInt32LE(replacement, callRva);
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
    console.log(`Patched safe iOS team-name stack copies in ${resolved}`);
} else {
    console.log(`Verified safe iOS team-name stack copies in ${resolved}`);
}
