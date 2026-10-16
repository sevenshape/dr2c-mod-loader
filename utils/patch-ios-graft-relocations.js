const fs = require('fs');
const path = require('path');

const binaryPath = process.argv[2];
if (!binaryPath)
    throw new Error('Usage: node utils/patch-ios-graft-relocations.js /path/to/DR2C');

const resolved = path.resolve(binaryPath);
const binary = fs.readFileSync(resolved);
if (binary.length < 0xc1000 || binary.readUInt32LE(0) !== 0xfeedfacf)
    throw new Error(`Not the expected grafted 64-bit Mach-O: ${resolved}`);

// gum-graft 16.6.6 copies the overwritten first instruction into each
// listener's fallback trampoline. Plain register/stack instructions remain
// valid there, but PC-relative instructions must be re-encoded for the new
// address. Derive each fallback address from the branch installed at the
// original function so this remains correct when new graft targets are added.
const FRIDA_TEXT_RVA = 0x5e8000;
const FRIDA_TEXT_SIZE = 0x4000;
const FRIDA_TEXT_FILE_OFFSET = 0xc0000;
const VM_TO_FILE_DELTA = FRIDA_TEXT_RVA - FRIDA_TEXT_FILE_OFFSET;

function signExtend(value, bits) {
    const sign = 2 ** (bits - 1);
    return value >= sign ? value - 2 ** bits : value;
}

function fileOffsetForRva(rva) {
    if (rva >= FRIDA_TEXT_RVA && rva < FRIDA_TEXT_RVA + FRIDA_TEXT_SIZE)
        return rva - VM_TO_FILE_DELTA;
    return rva;
}

function readWord(rva) {
    return binary.readUInt32LE(fileOffsetForRva(rva)) >>> 0;
}

function writeWord(rva, value) {
    binary.writeUInt32LE(value >>> 0, fileOffsetForRva(rva));
}

function decodeBranchTarget(rva, word) {
    if ((word & 0xfc000000) !== 0x14000000)
        throw new Error(`Expected B at RVA 0x${rva.toString(16)}, got 0x${word.toString(16)}`);
    return rva + signExtend(word & 0x03ffffff, 26) * 4;
}

function fallbackFor(targetRva) {
    const trampoline = decodeBranchTarget(targetRva, readWord(targetRva));
    if (trampoline < FRIDA_TEXT_RVA ||
        trampoline >= FRIDA_TEXT_RVA + FRIDA_TEXT_SIZE)
        throw new Error(`Graft trampoline for 0x${targetRva.toString(16)} is out of range`);
    return trampoline + 0x24;
}

function isGrafted(targetRva) {
    const word = readWord(targetRva);
    if ((word & 0xfc000000) !== 0x14000000) return false;
    const destination = decodeBranchTarget(targetRva, word);
    return destination >= FRIDA_TEXT_RVA &&
        destination < FRIDA_TEXT_RVA + FRIDA_TEXT_SIZE;
}

function encodeAdrp(original, instructionRva, targetPageRva) {
    const delta = (targetPageRva - (instructionRva & ~0xfff)) / 0x1000;
    if (!Number.isInteger(delta) || delta < -(2 ** 20) || delta >= 2 ** 20)
        throw new Error(`ADRP target is out of range at 0x${instructionRva.toString(16)}`);
    const imm = delta & 0x1fffff;
    return (0x90000000 |
        ((imm & 3) << 29) |
        (((imm >>> 2) & 0x7ffff) << 5) |
        (original & 0x1f)) >>> 0;
}

function patchAdrp(targetRva, original, targetPageRva, label) {
    const fallback = fallbackFor(targetRva);
    const replacement = encodeAdrp(original, fallback, targetPageRva);
    const actual = readWord(fallback);
    if (actual === replacement) return 0;
    if (actual !== original) {
        throw new Error(
            `${label} @ RVA 0x${fallback.toString(16)}: expected ` +
            `0x${original.toString(16)}, got 0x${actual.toString(16)}`
        );
    }
    writeWord(fallback, replacement);
    return 1;
}

function findVeneerRva() {
    let lastTrampoline = 0;
    // All original code precedes file offset 0xc0000. Find every direct branch
    // that gum-graft installed into __FRIDA_TEXT0 and place the veneer after
    // the final 44-byte listener plus its 16-byte shared dispatch tail.
    for (let rva = 0x4000; rva < FRIDA_TEXT_FILE_OFFSET; rva += 4) {
        // The starting-buddy translation bridge deliberately uses a plain B
        // into its helper cave. It is not a gum-graft listener and must not
        // move the shared CBZ veneer when this verifier is run a second time.
        if (rva === 0x554c4) continue;
        const word = readWord(rva);
        if ((word & 0xfc000000) !== 0x14000000) continue;
        const destination = decodeBranchTarget(rva, word);
        if (destination >= FRIDA_TEXT_RVA &&
            destination < FRIDA_TEXT_RVA + FRIDA_TEXT_SIZE)
            lastTrampoline = Math.max(lastTrampoline, destination);
    }
    if (lastTrampoline === 0) throw new Error('No gum-graft trampolines found');
    return lastTrampoline + 0x2c + 0x10;
}

function encodeB(fromRva, toRva) {
    const delta = (toRva - fromRva) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 25) || delta >= 2 ** 25)
        throw new Error(`B target is out of range at 0x${fromRva.toString(16)}`);
    return (0x14000000 | (delta & 0x03ffffff)) >>> 0;
}

function patchThingReportCbz() {
    const targetRva = 0x239f4;
    const originalTarget = 0x23abc;
    const original = 0xb4000640;
    const fallback = fallbackFor(targetRva);
    const veneer = findVeneerRva();
    const delta = (veneer - fallback) / 4;
    if (!Number.isInteger(delta) || delta < -(2 ** 18) || delta >= 2 ** 18)
        throw new Error('thing_report_ex CBZ veneer is out of range');
    const replacement = ((original & 0xff00001f) |
        ((delta & 0x7ffff) << 5)) >>> 0;
    const veneerBranch = encodeB(veneer, originalTarget);
    let changed = 0;

    const actual = readWord(fallback);
    if (actual !== replacement) {
        if (actual !== original) {
            throw new Error(
                `thing_report_ex CBZ @ RVA 0x${fallback.toString(16)}: expected ` +
                `0x${original.toString(16)}, got 0x${actual.toString(16)}`
            );
        }
        writeWord(fallback, replacement);
        changed++;
    }

    const actualVeneer = readWord(veneer);
    if (actualVeneer !== veneerBranch) {
        if (actualVeneer !== 0) {
            throw new Error(
                `thing_report_ex veneer @ RVA 0x${veneer.toString(16)} is occupied: ` +
                `0x${actualVeneer.toString(16)}`
            );
        }
        writeWord(veneer, veneerBranch);
        changed++;
    }
    return changed;
}

let changed = 0;
if (isGrafted(0x239f4))
    changed += patchThingReportCbz();
if (isGrafted(0x7cabc))
    changed += patchAdrp(0x7cabc, 0xf0002983, 0x5af000,
        'plot_text glyph descriptor ADRP');
if (isGrafted(0x92370))
    changed += patchAdrp(0x92370, 0xb00022e8, 0x4ef000,
        'perk description data ADRP');

// buttons_reset_to is grafted only in standalone builds that restore the
// persistent native console button. Its first ADRP must continue to address
// the native button-count global at page 0x15f000.
if (isGrafted(0x53d5c))
    changed += patchAdrp(0x53d5c, 0x90000868, 0x15f000,
        'buttons_reset_to button-count ADRP');

if (changed > 0) fs.writeFileSync(resolved, binary);
console.log(`Patched ${changed} iOS gum-graft relocation word(s) in ${resolved}`);
