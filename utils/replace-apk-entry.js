const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function fail(message) {
    console.error(message);
    process.exit(1);
}

function crc32(buffer) {
    let crc = 0xffffffff;
    for (const byte of buffer) {
        crc ^= byte;
        for (let bit = 0; bit < 8; bit++)
            crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
    return (crc ^ 0xffffffff) >>> 0;
}

function findEocd(apk) {
    const signature = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
    const minimum = Math.max(0, apk.length - 0xffff - 22);
    for (let offset = apk.length - 22; offset >= minimum; offset--) {
        if (!apk.subarray(offset, offset + 4).equals(signature)) continue;
        if (offset + 22 + apk.readUInt16LE(offset + 20) === apk.length)
            return offset;
    }
    fail('ZIP end-of-central-directory record not found');
}

function readCentralEntries(apk, eocdOffset) {
    const entryCount = apk.readUInt16LE(eocdOffset + 10);
    const centralOffset = apk.readUInt32LE(eocdOffset + 16);
    const entries = [];
    let cursor = centralOffset;

    for (let index = 0; index < entryCount; index++) {
        if (apk.readUInt32LE(cursor) !== 0x02014b50)
            fail(`Invalid central-directory entry ${index}`);
        const nameLength = apk.readUInt16LE(cursor + 28);
        const extraLength = apk.readUInt16LE(cursor + 30);
        const commentLength = apk.readUInt16LE(cursor + 32);
        entries.push({
            centralOffset: cursor,
            name: apk.subarray(cursor + 46, cursor + 46 + nameLength).toString('utf8'),
            method: apk.readUInt16LE(cursor + 10),
            flags: apk.readUInt16LE(cursor + 8),
            compressedSize: apk.readUInt32LE(cursor + 20),
            uncompressedSize: apk.readUInt32LE(cursor + 24),
            localOffset: apk.readUInt32LE(cursor + 42)
        });
        cursor += 46 + nameLength + extraLength + commentLength;
    }
    return { entries, centralOffset };
}

function localDataOffset(apk, entry) {
    if (apk.readUInt32LE(entry.localOffset) !== 0x04034b50)
        fail(`Invalid local header for ${entry.name}`);
    const nameLength = apk.readUInt16LE(entry.localOffset + 26);
    const extraLength = apk.readUInt16LE(entry.localOffset + 28);
    return entry.localOffset + 30 + nameLength + extraLength;
}

function encodeEntry(uncompressed, method) {
    if (method === 0) return Buffer.from(uncompressed);
    if (method === 8) return zlib.deflateRawSync(uncompressed, { level: 9 });
    fail(`Unsupported compression method ${method}`);
}

const [inputArg, outputArg, entryName, replacementArg] = process.argv.slice(2);
if (!inputArg || !outputArg || !entryName || !replacementArg) {
    fail(
        'Usage: node replace-apk-entry.js ' +
        '<input.apk> <output.apk> <entry-name> <replacement-file>'
    );
}

const inputPath = path.resolve(inputArg);
const outputPath = path.resolve(outputArg);
const replacementPath = path.resolve(replacementArg);
const apk = fs.readFileSync(inputPath);
const replacement = fs.readFileSync(replacementPath);
const eocdOffset = findEocd(apk);
const { entries, centralOffset } = readCentralEntries(apk, eocdOffset);
const entry = entries.find(candidate => candidate.name === entryName);
if (!entry) fail(`APK entry is missing: ${entryName}`);

const signingMagic = Buffer.from('APK Sig Block 42', 'ascii');
if (centralOffset >= 24 &&
    apk.subarray(centralOffset - 16, centralOffset).equals(signingMagic)) {
    fail('APK still has an outer Signing Block; strip it before replacing entries');
}

const dataOffset = localDataOffset(apk, entry);
const compressed = encodeEntry(replacement, entry.method);
const oldDataEnd = dataOffset + entry.compressedSize;
const delta = compressed.length - entry.compressedSize;
const patched = Buffer.concat([
    apk.subarray(0, dataOffset),
    compressed,
    apk.subarray(oldDataEnd)
]);

const newCrc = crc32(replacement);
for (const candidate of entries) {
    const newCentralOffset = candidate.centralOffset +
        (candidate.centralOffset >= oldDataEnd ? delta : 0);
    const newLocalOffset = candidate.localOffset +
        (candidate.localOffset >= oldDataEnd ? delta : 0);
    patched.writeUInt32LE(newLocalOffset, newCentralOffset + 42);

    if (candidate !== entry) continue;
    patched.writeUInt32LE(newCrc, newCentralOffset + 16);
    patched.writeUInt32LE(compressed.length, newCentralOffset + 20);
    patched.writeUInt32LE(replacement.length, newCentralOffset + 24);
    patched.writeUInt32LE(newCrc, newLocalOffset + 14);
    patched.writeUInt32LE(compressed.length, newLocalOffset + 18);
    patched.writeUInt32LE(replacement.length, newLocalOffset + 22);

    if (candidate.flags & 0x0008) {
        const descriptor = dataOffset + compressed.length;
        const hasSignature = patched.readUInt32LE(descriptor) === 0x08074b50;
        const crcOffset = descriptor + (hasSignature ? 4 : 0);
        patched.writeUInt32LE(newCrc, crcOffset);
        patched.writeUInt32LE(compressed.length, crcOffset + 4);
        patched.writeUInt32LE(replacement.length, crcOffset + 8);
    }
}

const newEocdOffset = eocdOffset + (eocdOffset >= oldDataEnd ? delta : 0);
patched.writeUInt32LE(
    centralOffset + (centralOffset >= oldDataEnd ? delta : 0),
    newEocdOffset + 16
);

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, patched);
console.log(`Replaced ${entryName} (${entry.uncompressedSize} -> ${replacement.length} bytes)`);
console.log(`Compressed-size delta: ${delta >= 0 ? '+' : ''}${delta}`);
console.log(`Unsigned APK: ${outputPath}`);
