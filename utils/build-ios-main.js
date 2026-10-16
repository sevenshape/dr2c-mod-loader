const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');
const esbuild = require('esbuild');

const loaderRoot = path.resolve(__dirname, '..');
const iosRoot = path.join(loaderRoot, 'ios');
const vendorRoot = path.join(iosRoot, 'vendor');
const generatedEntry = path.join(iosRoot, 'autonomous-index.generated.js');
const generatedJSZip = path.join(vendorRoot, 'jszip.global.js');
const distRoot = path.join(loaderRoot, 'dist');

fs.mkdirSync(vendorRoot, {recursive: true});

// Frida 16's compiler only bundles ECMAScript modules. JSZip 3 is CommonJS,
// so first turn its browser bundle into a side-effect ESM module. Its UMD
// wrapper must always publish to globalThis: Frida's module wrapper exposes
// module/exports and would otherwise select JSZip's private CommonJS branch.
esbuild.buildSync({
    entryPoints: [path.join(loaderRoot, 'node_modules/jszip/dist/jszip.min.js')],
    outfile: generatedJSZip,
    format: 'esm',
    platform: 'browser',
    target: ['es2020'],
    banner: {js: 'var window=globalThis;var global=globalThis;var self=globalThis;'},
    define: {define: 'undefined'},
    minifySyntax: true,
    logLevel: 'silent'
});

const jszipUmdBranch =
    'typeof exports == "object" && typeof module < "u" ? module.exports = e() : ' +
    '(typeof window < "u" ? window : typeof global < "u" ? global : ' +
    'typeof self < "u" ? self : this).JSZip = e();';
let jszipSource = fs.readFileSync(generatedJSZip, 'utf8');
if (!jszipSource.includes(jszipUmdBranch))
    throw new Error('Unable to locate the JSZip UMD export branch');
jszipSource = jszipSource.replace(jszipUmdBranch, 'globalThis.JSZip = e();');
fs.writeFileSync(generatedJSZip, jszipSource);

const commonJsHeader = `const JSZip = require('jszip');
const fridaFS = require('frida-fs');
// The Java bridge is Android-only. Avoid initializing its Frida-17 build in
// the iOS Gadget 16.6.6 runtime before the loader entrypoint can run.
const Java = Process.platform === 'linux'
    ? require('frida-java-bridge').default
    : null;`;
const iosHeader = `import './vendor/jszip.global.js';
import fridaFS from 'frida-fs';

globalThis.__DR2C_IOS_AUTONOMOUS__ = true;
const JSZip = globalThis.JSZip;
const Java = null;`;

let entrySource = fs.readFileSync(path.join(loaderRoot, 'index.js'), 'utf8');
if (!entrySource.includes(commonJsHeader))
    throw new Error('Unable to locate the dependency header in index.js');
entrySource = entrySource.replace(commonJsHeader, iosHeader);

// The embedded COFF table is only used by the Windows build and is by far the
// largest single literal in index.js. Keeping it in the iOS script can exceed
// Gadget 16 / QuickJS's startup compiler limits before the first statement is
// executed.
const symbolTableStart = entrySource.indexOf('const SYMBOLS_JSON_STR = ');
const symbolTableEnd = entrySource.indexOf(
    '\n\nlet iosDocumentPickerResolve',
    symbolTableStart
);
if (symbolTableStart === -1 || symbolTableEnd === -1)
    throw new Error('Unable to locate the Windows COFF symbol table');
entrySource = entrySource.slice(0, symbolTableStart)
    + "const SYMBOLS_JSON_STR = '{}';"
    + entrySource.slice(symbolTableEnd);
fs.writeFileSync(generatedEntry, entrySource);

fs.rmSync(distRoot, {recursive: true, force: true});
fs.mkdirSync(distRoot, {recursive: true});
fs.cpSync(path.join(loaderRoot, 'assets'), path.join(distRoot, 'assets'), {
    recursive: true
});
for (const name of ['index.js', 'index.html', 'package.json'])
    fs.copyFileSync(path.join(loaderRoot, name), path.join(distRoot, name));

// Emit a single ordinary script instead of Frida 16's module container. This
// makes Gadget's startup path identical to the proven minimal bootstrap and
// also lets esbuild remove compile-time-unreachable platform branches.
esbuild.buildSync({
    entryPoints: [generatedEntry],
    outfile: path.join(distRoot, 'main.js'),
    bundle: true,
    format: 'iife',
    platform: 'neutral',
    mainFields: ['main'],
    target: ['es2020'],
    minifySyntax: true,
    define: {'Process.platform': '"darwin"'},
    alias: {
        assert: '@frida/assert',
        buffer: '@frida/buffer',
        events: '@frida/events',
        path: '@frida/path',
        process: '@frida/process',
        stream: '@frida/stream',
        string_decoder: '@frida/string_decoder',
        timers: '@frida/timers',
        util: '@frida/util'
    },
    logLevel: 'silent'
});

console.log(`iOS Gadget 16 main script prepared at:\n${path.join(distRoot, 'main.js')}`);
