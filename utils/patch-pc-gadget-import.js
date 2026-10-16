#!/usr/bin/env node
'use strict';

/*
 * Adds one normal PE import to a 32-bit Windows executable.  It is used for
 * DR2C's PC loader to start Frida Gadget from a dedicated DLL instead of
 * grafting Gadget into SDL2.dll (which breaks SDL_mixer audio on some hosts).
 *
 * This deliberately creates a new file; it never changes the input EXE.
 *
 * Usage:
 *   node patch-pc-gadget-import.js --input prog.exe --output prog.exe \
 *     --dll dr2c-gadget.dll --symbol frida_gadget_load
 */

const fs = require('fs');
const path = require('path');

function fail(message) {
    throw new Error(message);
}

function takeOption(argv, name, fallback) {
    const index = argv.indexOf(name);
    if (index === -1) return fallback;
    if (index + 1 >= argv.length) fail(`Missing value after ${name}`);
    return argv[index + 1];
}

function align(value, boundary) {
    return Math.ceil(value / boundary) * boundary;
}

function readAsciiZ(buffer, offset) {
    const end = buffer.indexOf(0, offset);
    if (end === -1) fail(`Unterminated ASCII string at 0x${offset.toString(16)}`);
    return buffer.toString('ascii', offset, end);
}

function inspectPe(buffer) {
    if (buffer.length < 0x100 || buffer.toString('ascii', 0, 2) !== 'MZ') {
        fail('Input is not a DOS/PE executable');
    }
    const pe = buffer.readUInt32LE(0x3c);
    if (pe + 24 > buffer.length || buffer.toString('ascii', pe, pe + 4) !== 'PE\0\0') {
        fail('Input has no valid PE header');
    }
    const sectionCount = buffer.readUInt16LE(pe + 6);
    const optionalSize = buffer.readUInt16LE(pe + 20);
    const optional = pe + 24;
    if (optionalSize < 104 || buffer.readUInt16LE(optional) !== 0x10b) {
        fail('Only PE32 executables are supported');
    }
    const sectionTable = optional + optionalSize;
    const sizeHeaders = buffer.readUInt32LE(optional + 60);
    if (sectionTable + (sectionCount + 1) * 40 > sizeHeaders) {
        fail('No room for one additional PE section header');
    }
    const sections = [];
    for (let index = 0; index < sectionCount; index++) {
        const offset = sectionTable + index * 40;
        sections.push({
            offset,
            name: buffer.toString('ascii', offset, offset + 8).replace(/\0+$/, ''),
            virtualSize: buffer.readUInt32LE(offset + 8),
            virtualAddress: buffer.readUInt32LE(offset + 12),
            rawSize: buffer.readUInt32LE(offset + 16),
            rawOffset: buffer.readUInt32LE(offset + 20),
        });
    }
    const rvaToOffset = (rva) => {
        for (const section of sections) {
            const span = Math.max(section.virtualSize, section.rawSize);
            if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
                return section.rawOffset + rva - section.virtualAddress;
            }
        }
        if (rva < sizeHeaders) return rva;
        fail(`RVA 0x${rva.toString(16)} is outside the file sections`);
    };
    return { pe, optional, sectionTable, sectionCount, sections, rvaToOffset };
}

function parseImports(buffer, pe) {
    const importRva = buffer.readUInt32LE(pe.optional + 96 + 8);
    const importSize = buffer.readUInt32LE(pe.optional + 96 + 12);
    if (!importRva || importSize < 20) fail('Input has no import table');
    const offset = pe.rvaToOffset(importRva);
    const descriptors = [];
    const maxCount = Math.floor(importSize / 20) + 1;
    for (let index = 0; index < maxCount; index++) {
        const at = offset + index * 20;
        if (at + 20 > buffer.length) fail('Import table runs past end of file');
        const first = buffer.readUInt32LE(at);
        const time = buffer.readUInt32LE(at + 4);
        const forwarder = buffer.readUInt32LE(at + 8);
        const name = buffer.readUInt32LE(at + 12);
        const thunk = buffer.readUInt32LE(at + 16);
        if (!first && !time && !forwarder && !name && !thunk) break;
        descriptors.push(buffer.subarray(at, at + 20));
    }
    if (descriptors.length === maxCount) fail('Import table has no terminating descriptor');
    return descriptors;
}

function buildImportSection(existingDescriptors, sectionRva, dllName, symbolName) {
    const descriptorSize = (existingDescriptors.length + 2) * 20;
    let cursor = align(descriptorSize, 4);
    const iltOffset = cursor;
    cursor += 8; // IMAGE_THUNK_DATA[2]
    const iatOffset = cursor;
    cursor += 8;
    cursor = align(cursor, 2);
    const hintNameOffset = cursor;
    const symbol = Buffer.from(symbolName + '\0', 'ascii');
    cursor += 2 + symbol.length;
    cursor = align(cursor, 2);
    const dllNameOffset = cursor;
    const dll = Buffer.from(dllName + '\0', 'ascii');
    cursor += dll.length;

    const payload = Buffer.alloc(cursor);
    for (let index = 0; index < existingDescriptors.length; index++) {
        existingDescriptors[index].copy(payload, index * 20);
    }
    const added = existingDescriptors.length * 20;
    payload.writeUInt32LE(sectionRva + iltOffset, added);
    payload.writeUInt32LE(sectionRva + dllNameOffset, added + 12);
    payload.writeUInt32LE(sectionRva + iatOffset, added + 16);
    payload.writeUInt32LE(sectionRva + hintNameOffset, iltOffset);
    payload.writeUInt32LE(sectionRva + hintNameOffset, iatOffset);
    // Hint remains zero.
    symbol.copy(payload, hintNameOffset + 2);
    dll.copy(payload, dllNameOffset);
    return { payload, importSize: descriptorSize };
}

function patch({ input, output, dllName, symbolName }) {
    if (path.resolve(input) === path.resolve(output)) {
        fail('--input and --output must differ; this tool never overwrites the source EXE');
    }
    if (!/^[A-Za-z0-9_.-]+\.dll$/i.test(dllName)) fail('--dll must be a plain DLL filename');
    if (!/^[A-Za-z0-9_@?$.-]+$/.test(symbolName)) fail('--symbol contains unsupported characters');

    const source = fs.readFileSync(input);
    const pe = inspectPe(source);
    const descriptors = parseImports(source, pe);
    const fileAlignment = source.readUInt32LE(pe.optional + 36);
    const sectionAlignment = source.readUInt32LE(pe.optional + 32);
    if (!fileAlignment || !sectionAlignment) fail('Invalid PE section alignment');

    // prog.exe carries an overlay after its final section.  It is not part of
    // the PE section map, but discarding it changes the game binary.  Put the
    // new section after both the mapped image and any such trailing data.
    const lastRawEnd = Math.max(source.length, ...pe.sections.map(s => s.rawOffset + s.rawSize));
    const lastVirtualEnd = Math.max(...pe.sections.map(s => s.virtualAddress + Math.max(s.virtualSize, s.rawSize)));
    const sectionRawOffset = align(lastRawEnd, fileAlignment);
    const sectionRva = align(lastVirtualEnd, sectionAlignment);
    const imports = buildImportSection(descriptors, sectionRva, dllName, symbolName);
    const rawSize = align(imports.payload.length, fileAlignment);
    const virtualSize = imports.payload.length;

    const outputBuffer = Buffer.alloc(sectionRawOffset + rawSize);
    source.copy(outputBuffer);
    imports.payload.copy(outputBuffer, sectionRawOffset);

    const newHeader = pe.sectionTable + pe.sectionCount * 40;
    Buffer.from('.dr2c\0\0\0', 'ascii').copy(outputBuffer, newHeader);
    outputBuffer.writeUInt32LE(virtualSize, newHeader + 8);
    outputBuffer.writeUInt32LE(sectionRva, newHeader + 12);
    outputBuffer.writeUInt32LE(rawSize, newHeader + 16);
    outputBuffer.writeUInt32LE(sectionRawOffset, newHeader + 20);
    outputBuffer.writeUInt32LE(0x40000040, newHeader + 36); // initialized, readable data

    outputBuffer.writeUInt16LE(pe.sectionCount + 1, pe.pe + 6);
    outputBuffer.writeUInt32LE(align(sectionRva + virtualSize, sectionAlignment), pe.optional + 56);
    outputBuffer.writeUInt32LE(sectionRva, pe.optional + 96 + 8);
    outputBuffer.writeUInt32LE(imports.importSize, pe.optional + 96 + 12);

    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, outputBuffer);
    return { sectionRva, sectionRawOffset, virtualSize, rawSize, originalImports: descriptors.length };
}

try {
    const argv = process.argv.slice(2);
    const input = takeOption(argv, '--input');
    const output = takeOption(argv, '--output');
    if (!input || !output) fail('Usage: --input <prog.exe> --output <new.exe> [--dll <name>] [--symbol <name>]');
    const result = patch({
        input,
        output,
        dllName: takeOption(argv, '--dll', 'dr2c-gadget.dll'),
        symbolName: takeOption(argv, '--symbol', 'frida_gadget_load'),
    });
    console.log(`Patched ${output}`);
    console.log(`Added .dr2c import section at RVA 0x${result.sectionRva.toString(16)} (raw 0x${result.sectionRawOffset.toString(16)}); copied ${result.originalImports} original import descriptors.`);
} catch (error) {
    console.error(`patch-pc-gadget-import: ${error.message}`);
    process.exitCode = 1;
}
