const childProcess = require('child_process');
const fs = require('fs');
const path = require('path');

const loaderRoot = path.resolve(__dirname, '..');
const source = path.join(loaderRoot, 'assets', 'font_ucs2_12x12.png');
const output = path.join(loaderRoot, 'assets', 'font_ucs2_12x12_padded.png');
const ffmpeg = process.env.FFMPEG || '/opt/homebrew/bin/ffmpeg';

const cells = 256;
const cellSize = 12;
const padding = 1;
const stride = cellSize + padding * 2;
const sourceSize = cells * cellSize;
const outputSize = cells * stride;

if (!fs.existsSync(source))
    throw new Error(`Missing source font atlas: ${source}`);
if (!fs.existsSync(ffmpeg))
    throw new Error(`ffmpeg is required to generate the padded atlas: ${ffmpeg}`);

const sourcePixels = childProcess.execFileSync(ffmpeg, [
    '-v', 'error', '-i', source,
    '-f', 'rawvideo', '-pix_fmt', 'rgba', 'pipe:1'
], {maxBuffer: sourceSize * sourceSize * 4 + 1024});
const expectedBytes = sourceSize * sourceSize * 4;
if (sourcePixels.length !== expectedBytes)
    throw new Error(`Unexpected decoded atlas size: ${sourcePixels.length}`);

// Extruded gutters stop linear/half-texel sampling on some desktop GPUs from
// reading a neighbouring Unicode cell. Copying each tile's outer pixels into
// the gutter also avoids fading a glyph edge toward transparent black.
const outputPixels = Buffer.alloc(outputSize * outputSize * 4);
for (let cellY = 0; cellY < cells; cellY++) {
    for (let cellX = 0; cellX < cells; cellX++) {
        const sourceX = cellX * cellSize;
        const outputX = cellX * stride + padding;
        const outputY = cellY * stride + padding;
        for (let row = 0; row < cellSize; row++) {
            const sourceOffset = ((cellY * cellSize + row) * sourceSize + sourceX) * 4;
            const outputOffset = ((outputY + row) * outputSize + outputX) * 4;
            sourcePixels.copy(
                outputPixels, outputOffset, sourceOffset,
                sourceOffset + cellSize * 4
            );
            // Extrude the first and last pixel of this row horizontally.
            outputPixels.copy(
                outputPixels, outputOffset - 4,
                outputOffset, outputOffset + 4
            );
            outputPixels.copy(
                outputPixels, outputOffset + cellSize * 4,
                outputOffset + (cellSize - 1) * 4,
                outputOffset + cellSize * 4
            );
        }
        // Extrude the now-complete first and last rows vertically, including
        // their corner pixels.
        const rowBytes = stride * 4;
        const firstRow = (outputY * outputSize + outputX - padding) * 4;
        const lastRow = ((outputY + cellSize - 1) * outputSize +
            outputX - padding) * 4;
        outputPixels.copy(
            outputPixels, firstRow - outputSize * 4,
            firstRow, firstRow + rowBytes
        );
        outputPixels.copy(
            outputPixels, lastRow + outputSize * 4,
            lastRow, lastRow + rowBytes
        );
    }
}

childProcess.execFileSync(ffmpeg, [
    '-v', 'error',
    '-f', 'rawvideo', '-pix_fmt', 'rgba',
    '-s', `${outputSize}x${outputSize}`, '-i', 'pipe:0',
    '-frames:v', '1', '-c:v', 'png', '-compression_level', '9',
    '-y', output
], {input: outputPixels, maxBuffer: 1024 * 1024});

console.log(`Windows padded Unicode atlas: ${output} (${outputSize}x${outputSize})`);
