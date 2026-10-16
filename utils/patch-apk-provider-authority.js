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
    const offset = apk.lastIndexOf(signature);
    if (offset < 0 || offset + 22 > apk.length)
        fail('ZIP end-of-central-directory record not found');
    return offset;
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

function decodeEntry(apk, entry) {
    const local = entry.localOffset;
    if (apk.readUInt32LE(local) !== 0x04034b50)
        fail(`Invalid local header for ${entry.name}`);
    const nameLength = apk.readUInt16LE(local + 26);
    const extraLength = apk.readUInt16LE(local + 28);
    const dataOffset = local + 30 + nameLength + extraLength;
    const compressed = apk.subarray(dataOffset, dataOffset + entry.compressedSize);
    if (entry.method === 0)
        return { dataOffset, uncompressed: Buffer.from(compressed) };
    if (entry.method === 8)
        return { dataOffset, uncompressed: zlib.inflateRawSync(compressed) };
    fail(`Unsupported compression method ${entry.method} for ${entry.name}`);
}

function encodeEntry(uncompressed, entry) {
    if (entry.method === 0)
        return Buffer.from(uncompressed);

    // Pick the result closest to the original compressed length. Keeping the
    // delta tiny matters because NPatch APKs alias many outer ZIP entries to
    // local headers inside assets/npatch/origin.apk.
    let best = null;
    for (let level = 1; level <= 9; level++) {
        for (const strategy of [
            zlib.constants.Z_DEFAULT_STRATEGY,
            zlib.constants.Z_FILTERED,
            zlib.constants.Z_HUFFMAN_ONLY,
            zlib.constants.Z_RLE,
            zlib.constants.Z_FIXED
        ]) {
            const candidate = zlib.deflateRawSync(uncompressed, { level, strategy });
            const distance = Math.abs(candidate.length - entry.compressedSize);
            if (!best || distance < best.distance ||
                (distance === best.distance && candidate.length < best.buffer.length)) {
                best = { buffer: candidate, distance };
            }
        }
    }
    return best.buffer;
}

function replaceExactlyOnce(buffer, oldValue, newValue) {
    const oldBytes = Buffer.from(oldValue, 'utf8');
    const newBytes = Buffer.from(newValue, 'utf8');
    if (oldBytes.length !== newBytes.length)
        fail('Binary AndroidManifest replacement requires equal byte lengths');

    const first = buffer.indexOf(oldBytes);
    if (first < 0)
        fail(`AndroidManifest does not contain ${oldValue}`);
    if (buffer.indexOf(oldBytes, first + oldBytes.length) >= 0)
        fail(`AndroidManifest contains ${oldValue} more than once`);
    newBytes.copy(buffer, first);
}

const [inputArg, outputArg, oldPackage, newPackage] = process.argv.slice(2);
if (!inputArg || !outputArg || !oldPackage || !newPackage) {
    fail(
        'Usage: node patch-apk-provider-authority.js ' +
        '<input.apk> <output.apk> <old-package> <new-package>'
    );
}

const inputPath = path.resolve(inputArg);
const outputPath = path.resolve(outputArg);
if (!fs.existsSync(inputPath))
    fail(`Missing input APK: ${inputPath}`);

const apk = fs.readFileSync(inputPath);
const eocdOffset = findEocd(apk);
const { entries, centralOffset } = readCentralEntries(apk, eocdOffset);
const manifestEntry = entries.find(entry => entry.name === 'AndroidManifest.xml');
if (!manifestEntry)
    fail('AndroidManifest.xml is missing from APK');

// Refuse to silently invalidate a V2/V3 signature. V1 signature files are
// also intentionally absent from the coexistence output.
const signingMagic = Buffer.from('APK Sig Block 42', 'ascii');
if (centralOffset >= 24 &&
    apk.subarray(centralOffset - 16, centralOffset).equals(signingMagic)) {
    fail('APK still has an outer Signing Block; strip it before patching');
}

const oldAuthority = `${oldPackage}.FlurryContentProvider`;
const newAuthority = `${newPackage}.FlurryContentProvider`;
const { dataOffset, uncompressed } = decodeEntry(apk, manifestEntry);
replaceExactlyOnce(uncompressed, oldAuthority, newAuthority);

const compressed = encodeEntry(uncompressed, manifestEntry);
const oldDataEnd = dataOffset + manifestEntry.compressedSize;
const delta = compressed.length - manifestEntry.compressedSize;
const patched = Buffer.concat([
    apk.subarray(0, dataOffset),
    compressed,
    apk.subarray(oldDataEnd)
]);

const newCrc = crc32(uncompressed);
for (const entry of entries) {
    const newCentralOffset = entry.centralOffset +
        (entry.centralOffset >= oldDataEnd ? delta : 0);
    const newLocalOffset = entry.localOffset +
        (entry.localOffset >= oldDataEnd ? delta : 0);
    patched.writeUInt32LE(newLocalOffset, newCentralOffset + 42);

    if (entry !== manifestEntry)
        continue;
    patched.writeUInt32LE(newCrc, newCentralOffset + 16);
    patched.writeUInt32LE(compressed.length, newCentralOffset + 20);

    const local = newLocalOffset;
    patched.writeUInt32LE(newCrc, local + 14);
    patched.writeUInt32LE(compressed.length, local + 18);

    if (entry.flags & 0x0008) {
        const descriptor = dataOffset + compressed.length;
        const hasSignature = patched.readUInt32LE(descriptor) === 0x08074b50;
        const crcOffset = descriptor + (hasSignature ? 4 : 0);
        patched.writeUInt32LE(newCrc, crcOffset);
        patched.writeUInt32LE(compressed.length, crcOffset + 4);
        patched.writeUInt32LE(uncompressed.length, crcOffset + 8);
    }
}

const newEocdOffset = eocdOffset + (eocdOffset >= oldDataEnd ? delta : 0);
patched.writeUInt32LE(
    centralOffset + (centralOffset >= oldDataEnd ? delta : 0),
    newEocdOffset + 16
);

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, patched);
console.log(`Provider authority: ${oldAuthority} -> ${newAuthority}`);
console.log(`AndroidManifest compressed-size delta: ${delta >= 0 ? '+' : ''}${delta}`);
console.log(`Patched unsigned APK: ${outputPath}`);
