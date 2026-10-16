const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath) {
    throw new Error(
        'Usage: node utils/patch-ios-role-description-bridge.js /path/to/DR2C'
    );
}

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc0778 || binary.readUInt32LE(0) !== 0xfeedfacf) {
    throw new Error(`Not the expected gum-grafted 64-bit Mach-O: ${resolved}`);
}

// The role tab stores one of three complete native description strings
// directly into its text widget.  Bridge each state-specific ADR through its
// own short helper and read the existing PO translations from a three-pointer
// table at __FRIDA_DATA0 + 0x978.
const FRIDA_TEXT_RVA = 0x5e8000;
const FRIDA_TEXT_FILE_OFFSET = 0xc0000;
const ORIGINAL_CALL_WORD = 0xd503201f;
const helpers = [
    {
        label: 'lead', callRva: 0x77704, helperRva: 0x5e8720,
        words: [
            0x9000002a, 0x9125e14a, 0xf9400149,
            0xf100013f, 0x9a881128, 0xd65f03c0
        ]
    },
    {
        label: 'follow', callRva: 0x77744, helperRva: 0x5e8740,
        words: [
            0x9000002a, 0x9125e14a, 0xf9400549,
            0xf100013f, 0x9a881128, 0xd65f03c0
        ]
    },
    {
        label: 'rest', callRva: 0x77750, helperRva: 0x5e8760,
        words: [
            0x9000002a, 0x9125e14a, 0xf9400949,
            0xf100013f, 0x9a881128, 0xd65f03c0
        ]
    }
];

function encodeBl(fromRva, toRva) {
    const delta = (toRva - fromRva) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 25) || delta >= 2 ** 25) {
        throw new Error('Role-description bridge is outside BL range');
    }
    return (0x94000000 | (delta & 0x03ffffff)) >>> 0;
}

let alreadyPatched = true;
for (const helper of helpers) {
    helper.fileOffset = FRIDA_TEXT_FILE_OFFSET +
        helper.helperRva - FRIDA_TEXT_RVA;
    helper.callWord = encodeBl(helper.callRva, helper.helperRva);
    const actualCall = binary.readUInt32LE(helper.callRva) >>> 0;
    if (actualCall !== ORIGINAL_CALL_WORD && actualCall !== helper.callWord) {
        throw new Error(
            `Unexpected ${helper.label} role instruction @ ` +
            `0x${helper.callRva.toString(16)}: 0x${actualCall.toString(16)}`
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
            `${helper.label} role code cave is occupied @ ` +
            `0x${helper.fileOffset.toString(16)}`
        );
    }
    alreadyPatched = alreadyPatched &&
        actualCall === helper.callWord && helperMatches;
}

const DATA_TABLE_FILE_OFFSET = 0xc4978;
for (let offset = DATA_TABLE_FILE_OFFSET;
    offset < DATA_TABLE_FILE_OFFSET + 0x18; offset++) {
    if (binary[offset] !== 0) {
        throw new Error(
            `Role-description data table is occupied @ 0x${offset.toString(16)}`
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
    `role-description bridge in ${resolved}`
);
