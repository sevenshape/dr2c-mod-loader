const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
const rangeOption = process.argv[3];
if (!binaryPath)
    throw new Error(
        'Usage: node utils/patch-ios-capacity.js /path/to/DR2C ' +
        '[--range=START:END]'
    );

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0x97400 || binary.readUInt32LE(0) !== 0xfeedfacf)
    throw new Error(`Not the expected 64-bit Mach-O: ${resolved}`);

const movW = (rd, imm) => (0x52800000 | ((imm & 0xffff) << 5) | rd) >>> 0;
const addX = (rd, rn, imm) => (0x91000000 | ((imm & 0xfff) << 10) | (rn << 5) | rd) >>> 0;
const cmpW = (rn, imm) => (0x7100001f | ((imm & 0xfff) << 10) | (rn << 5)) >>> 0;
const ldrW = (rt, rn, off) => (0xb9400000 | (((off / 4) & 0xfff) << 10) | (rn << 5) | rt) >>> 0;
const strW = (rt, rn, off) => (0xb9000000 | (((off / 4) & 0xfff) << 10) | (rn << 5) | rt) >>> 0;
const ldrX = (rt, rn, off) => (0xf9400000 | (((off / 8) & 0xfff) << 10) | (rn << 5) | rt) >>> 0;
const strX = (rt, rn, off) => (0xf9000000 | (((off / 8) & 0xfff) << 10) | (rn << 5) | rt) >>> 0;

// The OCT-03-2022 arm64 Mach-O maps __TEXT at file offset zero, so each RVA
// below is also the instruction's file offset. Expected words make this fail
// closed if a different game build is supplied.
const patches = [
    [0x911F8, movW(9, 0x140), movW(9, 0x40), 'gamemode_is_locked stride'],
    [0x91208, ldrW(0, 8, 0x130), ldrW(0, 8, 0x2c), 'gamemode_is_locked field'],
    [0x91248, movW(10, 0x140), movW(10, 0x40), 'gamemode_applyword stride'],
    [0x91250, ldrX(0, 8, 0x138), ldrX(0, 8, 0x30), 'gamemode_applyword field'],
    [0x912B4, movW(24, 0x140), movW(24, 0x40), 'gamemode_layout list stride'],
    [0x91338, ldrW(8, 8, 0x12c), ldrW(8, 8, 0x28), 'gamemode_layout icon'],
    [0x91360, ldrW(8, 8, 0x130), ldrW(8, 8, 0x2c), 'gamemode_layout locked'],
    [0x914B4, movW(20, 0x140), movW(20, 0x40), 'gamemode_layout detail stride'],
    [0x914C4, ldrW(8, 8, 0x12c), ldrW(8, 8, 0x28), 'gamemode_layout detail icon'],
    [0x914F8, ldrW(9, 9, 0x130), ldrW(9, 9, 0x2c), 'gamemode_layout detail locked'],
    [0x9169C, movW(25, 0x140), movW(25, 0x40), 'btn_gamemode_desc stride'],
    [0x9170C, ldrW(8, 8, 0x130), ldrW(8, 8, 0x2c), 'btn_gamemode_desc locked'],
    [0x91B20, cmpW(8, 0x24), cmpW(8, 0x40), 'word_strmode capacity'],
    [0x91B4C, movW(9, 0x140), movW(9, 0x40), 'word_strmode stride'],
    [0x91BD8, strW(0, 8, 0x12c), strW(0, 8, 0x28), 'word_mode_icon field'],
    [0x91BF8, strW(0, 8, 0x130), strW(0, 8, 0x2c), 'word_mode_locked field'],
    [0x91C1C, strX(0, 8, 0x138), strX(0, 8, 0x30), 'word_mode_applyword field'],
    [0x91CD0, ldrW(8, 20, 0x130), ldrW(8, 20, 0x2c), 'gamemode button locked'],
    [0x91DCC, movW(9, 0x140), movW(9, 0x40), 'gamemode button stride'],

    [0x3512C, ldrW(8, 0, 0x130), ldrW(8, 0, 0x90), 'random perk locked'],
    [0x35150, ldrW(8, 0, 0x130), ldrW(8, 0, 0x90), 'random trait locked'],
    [0x91F6C, addX(20, 20, 0x140), addX(20, 20, 0xa0), 'perkntrait_find stride'],
    [0x92164, addX(20, 20, 0x140), addX(20, 20, 0xa0), 'word_strperk search stride'],
    [0x92170, cmpW(21, 0x20), cmpW(21, 0x40), 'word_strperk capacity'],
    [0x921A4, movW(8, 0x140), movW(8, 0xa0), 'word_strperk insert stride'],
    [0x92230, addX(20, 20, 0x140), addX(20, 20, 0xa0), 'word_strtrait search stride'],
    [0x9223C, cmpW(21, 0x21), cmpW(21, 0x40), 'word_strtrait capacity'],
    [0x92270, movW(8, 0x140), movW(8, 0xa0), 'word_strtrait insert stride'],
    [0x9231C, strW(9, 8, 0x128), strW(9, 8, 0x88), 'word_lvl field'],
    [0x92340, strW(0, 8, 0x130), strW(0, 8, 0x90), 'word_lock field'],
    [0x92364, strX(0, 8, 0x138), strX(0, 8, 0x98), 'word_applyword field'],
    [0x923AC, movW(10, 0x140), movW(10, 0xa0), 'perk_info stride'],
    [0x923D4, movW(10, 0x140), movW(10, 0xa0), 'trait_info stride'],
    [0x92510, movW(9, 0x140), movW(9, 0xa0), 'perkntrait layout first stride'],
    [0x92598, addX(27, 27, 0x140), addX(27, 27, 0xa0), 'perkntrait layout next stride'],
    [0x92728, movW(10, 0x140), movW(10, 0xa0), 'perk button trait stride'],
    [0x92730, ldrW(8, 8, 0x130), ldrW(8, 8, 0x90), 'perk button trait locked'],
    [0x9279C, movW(10, 0x140), movW(10, 0xa0), 'perk button perk stride'],
    [0x927CC, movW(10, 0x140), movW(10, 0xa0), 'perk button selected stride'],
    [0x927D4, ldrW(10, 10, 0x130), ldrW(10, 10, 0x90), 'perk button selected locked'],
    [0x92870, movW(10, 0x140), movW(10, 0xa0), 'perk button level stride'],
    [0x92878, ldrW(8, 8, 0x128), ldrW(8, 8, 0x88), 'perk button level'],
    [0x9295C, cmpW(8, 0x18), cmpW(8, 0x38), 'perk/trait page maximum compare'],
    [0x92960, movW(10, 0x18), movW(10, 0x38), 'perk/trait page maximum value'],
    [0x929E8, ldrW(8, 19, 0x130), ldrW(8, 19, 0x90), 'perk description locked'],
    [0x92A58, ldrW(8, 19, 0x128), ldrW(8, 19, 0x88), 'perk description level'],
    [0x973D0, ldrX(1, 0, 0x138), ldrX(1, 0, 0x98), 'perkfinder applyword']
];

let selectedPatches = patches;
let selectedStart = 0;
let selectedEnd = patches.length;
if (rangeOption !== undefined) {
    const match = /^--range=(\d+):(\d+)$/.exec(rangeOption);
    if (!match)
        throw new Error('Invalid range; expected --range=START:END');
    selectedStart = Number(match[1]);
    selectedEnd = Number(match[2]);
    if (selectedStart < 0 || selectedEnd > patches.length ||
        selectedStart >= selectedEnd)
        throw new Error(`Capacity patch range is out of bounds (0:${patches.length})`);
    selectedPatches = patches.slice(selectedStart, selectedEnd);
}

let changed = 0;
for (const [offset, expected, replacement, label] of selectedPatches) {
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
console.log(
    `Patched ${changed}/${selectedPatches.length} iOS capacity instructions ` +
    `(range ${selectedStart}:${selectedEnd}) in ${resolved}`
);
