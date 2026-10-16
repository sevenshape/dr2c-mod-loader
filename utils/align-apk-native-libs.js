const fs = require('fs');
const path = require('path');

const LOCAL_FILE_HEADER = 0x04034b50;
const CENTRAL_FILE_HEADER = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY = 0x06054b50;

function findEndOfCentralDirectory(buffer) {
    const minimum = Math.max(0, buffer.length - 0xffff - 22);
    for (let offset = buffer.length - 22; offset >= minimum; offset--) {
        if (buffer.readUInt32LE(offset) !== END_OF_CENTRAL_DIRECTORY)
            continue;
        const commentLength = buffer.readUInt16LE(offset + 20);
        if (offset + 22 + commentLength === buffer.length)
            return offset;
    }
    throw new Error('ZIP end-of-central-directory record not found');
}

function parseCentralDirectory(buffer, eocdOffset) {
    const diskNumber = buffer.readUInt16LE(eocdOffset + 4);
    const centralDisk = buffer.readUInt16LE(eocdOffset + 6);
    const entryCount = buffer.readUInt16LE(eocdOffset + 10);
    const centralSize = buffer.readUInt32LE(eocdOffset + 12);
    const centralOffset = buffer.readUInt32LE(eocdOffset + 16);
    if (diskNumber !== 0 || centralDisk !== 0 || entryCount === 0xffff ||
        centralSize === 0xffffffff || centralOffset === 0xffffffff) {
        throw new Error('Multi-disk and ZIP64 APKs are not supported');
    }

    const entries = [];
    let offset = centralOffset;
    for (let index = 0; index < entryCount; index++) {
        if (buffer.readUInt32LE(offset) !== CENTRAL_FILE_HEADER)
            throw new Error(`Invalid central-directory entry at ${offset}`);
        const nameLength = buffer.readUInt16LE(offset + 28);
        const extraLength = buffer.readUInt16LE(offset + 30);
        const commentLength = buffer.readUInt16LE(offset + 32);
        const length = 46 + nameLength + extraLength + commentLength;
        entries.push({
            centralOffset: offset,
            length,
            name: buffer.toString('utf8', offset + 46, offset + 46 + nameLength),
            compressionMethod: buffer.readUInt16LE(offset + 10),
            localOffset: buffer.readUInt32LE(offset + 42)
        });
        offset += length;
    }
    if (offset !== centralOffset + centralSize)
        throw new Error('Unexpected central-directory size');
    return {entries, centralOffset, centralSize};
}

function alignApkNativeLibraries(inputPath, outputPath, alignment = 16384) {
    if (!Number.isInteger(alignment) || alignment <= 0)
        throw new Error(`Invalid alignment: ${alignment}`);

    const input = fs.readFileSync(inputPath);
    const eocdOffset = findEndOfCentralDirectory(input);
    const central = parseCentralDirectory(input, eocdOffset);
    const byLocalOffset = [...central.entries].sort((a, b) => a.localOffset - b.localOffset);
    const chunks = [];
    const newLocalOffsets = new Map();
    let inputCursor = 0;
    let outputOffset = 0;

    function append(chunk) {
        if (chunk.length === 0) return;
        chunks.push(chunk);
        outputOffset += chunk.length;
    }

    for (let index = 0; index < byLocalOffset.length; index++) {
        const entry = byLocalOffset[index];
        const nextOffset = index + 1 < byLocalOffset.length
            ? byLocalOffset[index + 1].localOffset
            : central.centralOffset;
        append(input.subarray(inputCursor, entry.localOffset));
        newLocalOffsets.set(entry.localOffset, outputOffset);

        if (input.readUInt32LE(entry.localOffset) !== LOCAL_FILE_HEADER)
            throw new Error(`Invalid local header for ${entry.name}`);
        const nameLength = input.readUInt16LE(entry.localOffset + 26);
        const extraLength = input.readUInt16LE(entry.localOffset + 28);
        const headerEnd = entry.localOffset + 30 + nameLength + extraLength;
        const header = Buffer.from(input.subarray(entry.localOffset, headerEnd));
        const isStoredNativeLibrary = entry.compressionMethod === 0 &&
            /^lib\/[^/]+\/[^/]+\.so$/.test(entry.name);
        const isStoredResourceTable = entry.compressionMethod === 0 &&
            entry.name === 'resources.arsc';
        const entryAlignment = isStoredNativeLibrary
            ? alignment
            : (isStoredResourceTable ? 4 : 1);
        const padding = (entryAlignment -
            ((outputOffset + header.length) % entryAlignment)) % entryAlignment;
        if (extraLength + padding > 0xffff)
            throw new Error(`Local extra field is too large for ${entry.name}`);
        header.writeUInt16LE(extraLength + padding, 28);
        append(header);
        append(Buffer.alloc(padding));
        append(input.subarray(headerEnd, nextOffset));
        inputCursor = nextOffset;
    }

    append(input.subarray(inputCursor, central.centralOffset));
    const newCentralOffset = outputOffset;
    const centralAndGap = Buffer.from(input.subarray(central.centralOffset, eocdOffset));
    for (const entry of central.entries) {
        const patchedOffset = newLocalOffsets.get(entry.localOffset);
        if (patchedOffset === undefined)
            throw new Error(`Missing rewritten offset for ${entry.name}`);
        centralAndGap.writeUInt32LE(
            patchedOffset,
            entry.centralOffset - central.centralOffset + 42
        );
    }
    append(centralAndGap);

    const eocd = Buffer.from(input.subarray(eocdOffset));
    eocd.writeUInt32LE(newCentralOffset, 16);
    append(eocd);

    const output = Buffer.concat(chunks);
    fs.mkdirSync(path.dirname(outputPath), {recursive: true});
    fs.writeFileSync(outputPath, output);
}

if (require.main === module) {
    const [inputPath, outputPath, alignmentArg] = process.argv.slice(2);
    if (!inputPath || !outputPath) {
        console.error('Usage: node align-apk-native-libs.js <input.apk> <output.apk> [alignment]');
        process.exit(1);
    }
    alignApkNativeLibraries(
        path.resolve(inputPath),
        path.resolve(outputPath),
        alignmentArg === undefined ? 16384 : Number(alignmentArg)
    );
}

module.exports = {alignApkNativeLibraries};
