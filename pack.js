const fs = require('fs');
const path = require('path');
const JSZip = require('jszip');
const pkg = require('./package.json');

const OUT_FILE = path.resolve(__dirname, 'dist/' + pkg.name + '-' + pkg.version + '.zip');

(async () => {
    const zip = new JSZip();
    zip.file(pkg.name + '.js', fs.readFileSync(path.resolve(__dirname, 'index.js')));
    zip.file(pkg.name + '.config', fs.readFileSync(path.resolve(__dirname, 'package.json')));
    const buf = await zip.generateAsync({
        type: 'nodebuffer',
        compression: 'DEFLATE',
        compressionOptions: { level: 9 },
    });
    fs.writeFileSync(OUT_FILE, buf);
    console.log(`[+] done: ${OUT_FILE} (${(buf.length / 1024 / 1024).toFixed(2)} MB)`);
})();