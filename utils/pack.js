const fs = require('fs');
const path = require('path');
const JSZip = require('jszip');
const pkg = require('../package.json');

const OUT_FILE = path.resolve(__dirname, '../', 'build/' + pkg.name + '-' + pkg.version + '.zip');
const DIST_DIR = path.resolve(__dirname, '../', 'dist');
const BUILD_DIR = path.resolve(__dirname, '../', 'build');

/** @param {string} dirPath @returns {string[]} */
function getAllFiles(dirPath) {
    const result = [];
    const items = fs.readdirSync(dirPath);

    for (const item of items) {
        const fullPath = path.join(dirPath, item);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
            result.push(...getAllFiles(fullPath));  // 递归
        } else {
            result.push(fullPath);
        }
    }

    return result;
}

(async () => {
    const zip = new JSZip();

    getAllFiles(DIST_DIR).forEach(item => {

        const stat = fs.statSync(item);
        let zipPath = path.relative(DIST_DIR, item);
        if (process.platform === 'win32') {
            zipPath = zipPath.replaceAll('\\', '/');
        }

        if (stat.isFile()) {
            zip.file(zipPath, fs.readFileSync(item));
        }
        if (stat.isDirectory()) {
            zip.folder(zipPath + '/');
        }
        console.log(item, 'to zip:', zipPath);
    });

    const buf = await zip.generateAsync({
        type: 'nodebuffer',
        compression: 'DEFLATE',
        compressionOptions: { level: 9 },
    });
    fs.mkdirSync(BUILD_DIR, { recursive: true });
    fs.writeFileSync(OUT_FILE, buf);
    console.log(`[+] done: ${OUT_FILE} (${(buf.length / 1024 / 1024).toFixed(2)} MB)`);
})();