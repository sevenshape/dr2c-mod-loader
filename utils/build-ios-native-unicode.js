const childProcess = require('child_process');
const fs = require('fs');
const path = require('path');

const loaderRoot = path.resolve(__dirname, '..');
const source = path.join(loaderRoot, 'ios', 'native-unicode-remap.c');
const outputDir = path.join(loaderRoot, 'build', 'ios');
const output = path.join(outputDir, 'MR2CUnicode.dylib');

if (!fs.existsSync(source))
    throw new Error(`Missing iOS native Unicode source: ${source}`);

const sdk = childProcess.execFileSync('xcrun', [
    '--sdk', 'iphoneos', '--show-sdk-path'
], {encoding: 'utf8'}).trim();
const clang = childProcess.execFileSync('xcrun', [
    '--sdk', 'iphoneos', '--find', 'clang'
], {encoding: 'utf8'}).trim();

fs.mkdirSync(outputDir, {recursive: true});
childProcess.execFileSync(clang, [
    '-x', 'c',
    '-arch', 'arm64',
    '-isysroot', sdk,
    '-miphoneos-version-min=12.0',
    '-dynamiclib',
    '-O3',
    '-fvisibility=hidden',
    '-fno-stack-protector',
    '-Wl,-install_name,@rpath/MR2CUnicode.dylib',
    '-Wl,-dead_strip',
    source,
    '-o', output
], {stdio: 'inherit'});

console.log(`iOS native Unicode renderer: ${output}`);
