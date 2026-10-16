const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath) {
    throw new Error(
        'Usage: node utils/patch-ios-character-storage-bridge.js /path/to/DR2C'
    );
}

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc0658 || binary.readUInt32LE(0) !== 0xfeedfacf) {
    throw new Error(`Not the expected gum-grafted 64-bit Mach-O: ${resolved}`);
}

const FRIDA_TEXT_RVA = 0x5e8000;
const FRIDA_TEXT_FILE_OFFSET = 0xc0000;
const TITLE_CALL_RVA = 0x59a28;
const EMPTY_CALL_RVA = 0x59e44;
const DELETE_CALL_RVA = 0x59c18;
const TITLE_HELPER_RVA = 0x5e85e0;
const EMPTY_HELPER_RVA = 0x5e8620;
const DELETE_HELPER_RVA = 0x5e8640;

const helpers = [
    {
        label: 'title',
        callRva: TITLE_CALL_RVA,
        originalCall: 0xd503201f, // nop after title-format ADR
        helperRva: TITLE_HELPER_RVA,
        words: [
            0x9000002a, 0x9124014a, 0xf94003eb, 0xf0ffd60c,
            0x9120958c, 0xeb0c017f, 0xf940054c, 0xf940094d,
            0x9a8d018c, 0xf100019f, 0x9a8b118b, 0xf90003eb,
            0xf940014c, 0xf100019f, 0x9a831183, 0xd65f03c0
        ]
    },
    {
        label: 'empty-slot',
        callRva: EMPTY_CALL_RVA,
        originalCall: 0xf9006668, // str x8, [x19, #0xc8]
        helperRva: EMPTY_HELPER_RVA,
        words: [
            0x9000002a, 0x9124014a, 0xf9400d49, 0xf100013f,
            0x9a881128, 0xf9006668, 0xd65f03c0
        ]
    },
    {
        label: 'delete-confirmation',
        callRva: DELETE_CALL_RVA,
        originalCall: 0xd503201f, // nop after delete-format ADR
        helperRva: DELETE_HELPER_RVA,
        words: [
            0x9000002a, 0x9124014a, 0xf940114a,
            0xf100015f, 0x9a831143, 0xd65f03c0
        ]
    }
];

function encodeBl(fromRva, toRva) {
    const delta = (toRva - fromRva) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 25) || delta >= 2 ** 25) {
        throw new Error('Character-storage bridge is outside BL range');
    }
    return (0x94000000 | (delta & 0x03ffffff)) >>> 0;
}

let alreadyPatched = true;
for (const helper of helpers) {
    helper.fileOffset = FRIDA_TEXT_FILE_OFFSET +
        helper.helperRva - FRIDA_TEXT_RVA;
    helper.callWord = encodeBl(helper.callRva, helper.helperRva);
    const actualCall = binary.readUInt32LE(helper.callRva) >>> 0;
    if (actualCall !== helper.originalCall && actualCall !== helper.callWord) {
        throw new Error(
            `Unexpected ${helper.label} instruction @ 0x${helper.callRva.toString(16)}: ` +
            `0x${actualCall.toString(16)}`
        );
    }
    const helperMatches = helper.words.every((word, index) =>
        (binary.readUInt32LE(helper.fileOffset + index * 4) >>> 0) ===
        (word >>> 0)
    );
    const helperEmpty = helper.words.every((_, index) =>
        (binary.readUInt32LE(helper.fileOffset + index * 4) >>> 0) === 0
    );
    if (!helperMatches && !helperEmpty) {
        throw new Error(
            `${helper.label} code cave is occupied @ 0x${helper.fileOffset.toString(16)}`
        );
    }
    alreadyPatched = alreadyPatched &&
        actualCall === helper.callWord && helperMatches;
}

// Five runtime pointers occupy 0x28 bytes at __FRIDA_DATA0 + 0x900.
for (let offset = 0xc4900; offset < 0xc4928; offset++) {
    if (binary[offset] !== 0) {
        throw new Error(
            `Character-storage data table is occupied @ 0x${offset.toString(16)}`
        );
    }
}

for (const helper of helpers) {
    binary.writeUInt32LE(helper.callWord, helper.callRva);
    helper.words.forEach((word, index) => {
        binary.writeUInt32LE(word >>> 0, helper.fileOffset + index * 4);
    });
}
fs.writeFileSync(resolved, binary);
console.log(
    `${alreadyPatched ? 'Verified' : 'Patched'} strict iOS ` +
    `character-storage bridge in ${resolved}`
);
