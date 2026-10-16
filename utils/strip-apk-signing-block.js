const fs = require('fs');
const path = require('path');

function fail(message) {
    console.error(message);
    process.exit(1);
}

const [inputArg, outputArg] = process.argv.slice(2);
if (!inputArg || !outputArg)
    fail('Usage: node strip-apk-signing-block.js <signed.apk> <unsigned.apk>');

const inputPath = path.resolve(inputArg);
const outputPath = path.resolve(outputArg);
const apk = fs.readFileSync(inputPath);
const eocdMagic = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
const eocdOffset = apk.lastIndexOf(eocdMagic);
if (eocdOffset < 0 || eocdOffset + 22 > apk.length)
    fail('ZIP end-of-central-directory record not found');

const centralDirectoryOffset = apk.readUInt32LE(eocdOffset + 16);
const footerOffset = centralDirectoryOffset - 24;
const signingMagic = Buffer.from('APK Sig Block 42', 'ascii');
if (footerOffset < 0 || !apk.subarray(footerOffset + 8, footerOffset + 24).equals(signingMagic))
    fail('No outer APK Signing Block found');

const sizeInFooter = Number(apk.readBigUInt64LE(footerOffset));
const blockSize = sizeInFooter + 8;
const blockOffset = centralDirectoryOffset - blockSize;
if (blockOffset < 0 || Number(apk.readBigUInt64LE(blockOffset)) !== sizeInFooter)
    fail('APK Signing Block size fields do not agree');

const unsigned = Buffer.concat([
    apk.subarray(0, blockOffset),
    apk.subarray(centralDirectoryOffset)
]);
const newEocdOffset = eocdOffset - blockSize;
unsigned.writeUInt32LE(blockOffset, newEocdOffset + 16);

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, unsigned);
console.log(`Removed ${blockSize} byte APK Signing Block`);
console.log(`Unsigned APK: ${outputPath}`);
