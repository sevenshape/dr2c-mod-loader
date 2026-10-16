#!/usr/bin/env node
'use strict';

/*
 * Loads Frida Gadget at the executable entry point, after Windows has finished
 * resolving the game's ordinary DLL imports.  This is deliberately later than
 * adding Gadget to the import table: some Windows/Parallels combinations fault
 * when Gadget's worker is started while the loader lock is still active.
 *
 * The generated EXE has one executable .dr2c section and leaves the source
 * unchanged.  It calls the game's existing KERNEL32!LoadLibraryA IAT slot,
 * restores every general register/flags, and jumps to the original entry.
 */

const fs = require('fs');
const path = require('path');

function die(message) { throw new Error(message); }
function align(value, boundary) { return Math.ceil(value / boundary) * boundary; }

function option(argv, name, fallback) {
    const index = argv.indexOf(name);
    if (index === -1) return fallback;
    if (index + 1 >= argv.length) die(`Missing value after ${name}`);
    return argv[index + 1];
}

function parsePe(buffer) {
    if (buffer.toString('ascii', 0, 2) !== 'MZ') die('Input is not a PE executable');
    const pe = buffer.readUInt32LE(0x3c);
    if (buffer.toString('ascii', pe, pe + 4) !== 'PE\0\0') die('PE signature not found');
    const optional = pe + 24;
    if (buffer.readUInt16LE(optional) !== 0x10b) die('Only 32-bit PE files are supported');
    const sectionCount = buffer.readUInt16LE(pe + 6);
    const optionalSize = buffer.readUInt16LE(pe + 20);
    const sectionTable = optional + optionalSize;
    if (sectionTable + (sectionCount + 1) * 40 > buffer.readUInt32LE(optional + 60)) {
        die('No room for an additional PE section header');
    }
    const sections = [];
    for (let index = 0; index < sectionCount; index++) {
        const offset = sectionTable + index * 40;
        sections.push({
            offset,
            va: buffer.readUInt32LE(offset + 12),
            virtualSize: buffer.readUInt32LE(offset + 8),
            rawSize: buffer.readUInt32LE(offset + 16),
            rawOffset: buffer.readUInt32LE(offset + 20),
        });
    }
    const rvaToOffset = (rva) => {
        const section = sections.find(item => rva >= item.va && rva < item.va + Math.max(item.virtualSize, item.rawSize));
        if (!section) die(`RVA 0x${rva.toString(16)} is not backed by a section`);
        return section.rawOffset + rva - section.va;
    };
    return { pe, optional, sectionCount, sectionTable, sections, rvaToOffset };
}

function zeroTerminatedAscii(buffer, offset) {
    const end = buffer.indexOf(0, offset);
    if (end < 0) die(`Unterminated string at 0x${offset.toString(16)}`);
    return buffer.toString('ascii', offset, end);
}

function findIatSlot(buffer, pe, requiredDll, requiredSymbol) {
    const importRva = buffer.readUInt32LE(pe.optional + 104);
    if (!importRva) die('Import directory is missing');
    const importOffset = pe.rvaToOffset(importRva);
    for (let descriptor = importOffset; ; descriptor += 20) {
        const originalThunkRva = buffer.readUInt32LE(descriptor);
        const nameRva = buffer.readUInt32LE(descriptor + 12);
        const firstThunkRva = buffer.readUInt32LE(descriptor + 16);
        if (!originalThunkRva && !nameRva && !firstThunkRva) break;
        const dllName = zeroTerminatedAscii(buffer, pe.rvaToOffset(nameRva));
        if (dllName.toLowerCase() !== requiredDll.toLowerCase()) continue;
        const lookupRva = originalThunkRva || firstThunkRva;
        for (let index = 0; ; index++) {
            const thunk = buffer.readUInt32LE(pe.rvaToOffset(lookupRva + index * 4));
            if (!thunk) break;
            if (thunk & 0x80000000) continue;
            const name = zeroTerminatedAscii(buffer, pe.rvaToOffset(thunk) + 2);
            if (name === requiredSymbol) return firstThunkRva + index * 4;
        }
    }
    die(`Unable to locate ${requiredDll}!${requiredSymbol} in the existing IAT`);
}

function patch(input, output, dllName, waitMs) {
    if (path.resolve(input) === path.resolve(output)) die('Input and output must differ');
    if (!/^[A-Za-z0-9_.-]+\.dll$/i.test(dllName)) die('--dll must be a plain DLL filename');
    const source = fs.readFileSync(input);
    const pe = parsePe(source);
    const imageBase = source.readUInt32LE(pe.optional + 28);
    const originalEntry = source.readUInt32LE(pe.optional + 16);
    const loadLibraryIatRva = findIatSlot(source, pe, 'KERNEL32.dll', 'LoadLibraryA');
    const sleepIatRva = findIatSlot(source, pe, 'KERNEL32.dll', 'Sleep');
    const fileAlignment = source.readUInt32LE(pe.optional + 36);
    const sectionAlignment = source.readUInt32LE(pe.optional + 32);
    const rawOffset = align(Math.max(source.length, ...pe.sections.map(s => s.rawOffset + s.rawSize)), fileAlignment);
    const sectionRva = align(Math.max(...pe.sections.map(s => s.va + Math.max(s.virtualSize, s.rawSize))), sectionAlignment);

    // pushfd; pushad; push <dll>; call [LoadLibraryA IAT]; push <wait>;
    // call [Sleep IAT]; popad; popfd; jmp OEP.  Gadget starts its worker from
    // DllMain, so a short pause here prevents the game's first load_gfx pass
    // from racing the font/i18n hooks on a cold launch.
    const codeSize = 31;
    const name = Buffer.from(dllName + '\0', 'ascii');
    const payload = Buffer.alloc(codeSize + name.length);
    let at = 0;
    payload[at++] = 0x9c;
    payload[at++] = 0x60;
    payload[at++] = 0x68;
    payload.writeUInt32LE(imageBase + sectionRva + codeSize, at); at += 4;
    payload[at++] = 0xff;
    payload[at++] = 0x15;
    payload.writeUInt32LE(imageBase + loadLibraryIatRva, at); at += 4;
    payload[at++] = 0x68;
    payload.writeUInt32LE(waitMs, at); at += 4;
    payload[at++] = 0xff;
    payload[at++] = 0x15;
    payload.writeUInt32LE(imageBase + sleepIatRva, at); at += 4;
    payload[at++] = 0x61;
    payload[at++] = 0x9d;
    payload[at++] = 0xe9;
    payload.writeInt32LE(originalEntry - (sectionRva + at + 4), at); at += 4;
    name.copy(payload, at);
    if (at + name.length !== payload.length) die('Internal trampoline layout error');

    const rawSize = align(payload.length, fileAlignment);
    const result = Buffer.alloc(rawOffset + rawSize);
    source.copy(result);
    payload.copy(result, rawOffset);
    const header = pe.sectionTable + pe.sectionCount * 40;
    Buffer.from('.dr2c\0\0\0', 'ascii').copy(result, header);
    result.writeUInt32LE(payload.length, header + 8);
    result.writeUInt32LE(sectionRva, header + 12);
    result.writeUInt32LE(rawSize, header + 16);
    result.writeUInt32LE(rawOffset, header + 20);
    result.writeUInt32LE(0x60000020, header + 36); // executable/readable code
    result.writeUInt16LE(pe.sectionCount + 1, pe.pe + 6);
    result.writeUInt32LE(align(sectionRva + payload.length, sectionAlignment), pe.optional + 56);
    result.writeUInt32LE(sectionRva, pe.optional + 16);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, result);
    return { originalEntry, entry: sectionRva, loadLibraryIatRva, sleepIatRva, rawOffset, waitMs };
}

try {
    const argv = process.argv.slice(2);
    const input = option(argv, '--input');
    const output = option(argv, '--output');
    if (!input || !output) die('Usage: --input <prog.exe> --output <new.exe> [--dll dr2c-gadget.dll] [--wait-ms 350]');
    const waitMs = Number(option(argv, '--wait-ms', '350'));
    if (!Number.isInteger(waitMs) || waitMs < 0 || waitMs > 2000) {
        die('--wait-ms must be an integer between 0 and 2000');
    }
    const result = patch(input, output, option(argv, '--dll', 'dr2c-gadget.dll'), waitMs);
    console.log(`Patched ${output}`);
    console.log(`Entry 0x${result.originalEntry.toString(16)} -> 0x${result.entry.toString(16)}; LoadLibraryA IAT RVA 0x${result.loadLibraryIatRva.toString(16)}, Sleep IAT RVA 0x${result.sleepIatRva.toString(16)}; wait=${result.waitMs}ms; section raw offset 0x${result.rawOffset.toString(16)}.`);
} catch (error) {
    console.error(`patch-pc-gadget-entrypoint: ${error.message}`);
    process.exitCode = 1;
}
