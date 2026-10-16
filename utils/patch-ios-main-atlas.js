const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath)
    throw new Error('Usage: node utils/patch-ios-main-atlas.js /path/to/DR2C');

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0x84000 || binary.readUInt32LE(0) !== 0xfeedfacf)
    throw new Error(`Not the expected 64-bit Mach-O: ${resolved}`);

// OCT-03-2022 load_gfx starts at RVA 0x83128. Its first atlas allocation is:
//   mov w1, #0x800
//   mov w2, #0x800
//   bl  atlas_create_texture
// Patch only those verified immediates. This avoids grafting the hot atlas
// function and therefore does not consume another iOS code cave.
const patches = [
    [0x83140, 0x52810001, 0x52820001, 'main atlas width'],
    [0x83144, 0x52810002, 0x52820002, 'main atlas height']
];

let changed = 0;
for (const [offset, expected, replacement, label] of patches) {
    const actual = binary.readUInt32LE(offset) >>> 0;
    if (actual === replacement) continue;
    if (actual !== expected) {
        throw new Error(
            `${label} @ 0x${offset.toString(16)}: expected ` +
            `0x${expected.toString(16)}, got 0x${actual.toString(16)}`
        );
    }
    binary.writeUInt32LE(replacement, offset);
    changed++;
}

fs.writeFileSync(resolved, binary);
console.log(`Patched ${changed}/2 iOS main-atlas dimensions to 4096x4096 in ${resolved}`);
