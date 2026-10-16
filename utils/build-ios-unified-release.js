const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const loaderRoot = path.resolve(__dirname, '..');
const workspaceRoot = path.resolve(loaderRoot, '..');
const pristineIpa = path.join(workspaceRoot, 'DR2C_纯净砸壳_1.32.ipa');
const gadget = path.join(
    workspaceRoot,
    'ios-autonomous-release',
    'Payload',
    'DR2C.app',
    'Frameworks',
    'FridaGadget.dylib'
);
const gumGraft = path.resolve(
    process.argv[2] || '/private/tmp/gum-graft-16.6.6-macos-arm64'
);
const bootstrap = path.join(loaderRoot, 'ios', 'main.js');
const gadgetConfig = path.join(loaderRoot, 'ios', 'FridaGadget.unified.config');
const fullScript = path.join(loaderRoot, 'dist', 'main.js');
const nativeUnicode = path.join(loaderRoot, 'build', 'ios', 'MR2CUnicode.dylib');
const assets = path.join(loaderRoot, 'assets');
const outputRoot = path.join(workspaceRoot, 'ios-unified-release');
const payload = path.join(outputRoot, 'Payload');
const app = path.join(payload, 'DR2C.app');
const executable = path.join(app, 'DR2C');
const frameworks = path.join(app, 'Frameworks');
const infoPlist = path.join(app, 'Info.plist');
const outputIpa = path.join(
    workspaceRoot,
    'releases',
    'MR2C-1.32-unified-Frida16.6.6-unsigned.ipa'
);

const EXPECTED = Object.freeze({
    pristineIpa:
        '674e65ff3fb70c1527575f623346f5d9fc3618c4edeaad60dbafbec87322ddbd',
    gadget:
        'bf95c10663a747accce6823ae098d09ad4fc28b7dc98832521246bccdedab6a3',
    gumGraft:
        'a1ec1b378cd3eed5833cf70fe6ed45bd8c8fba3dfdc98383371ed23b7a85b7a0',
    infoPlist:
        'b169222f03feb5bf4fb9262deaac063fe6b127b28144bc373c982a6502fc522d',
    patchedExecutable:
        '875eab1ec21dcaa781de8b1c63296fc087c2a53e6f26b711f7de9d801f0ee599'
});

const GRAFT_TARGETS = Object.freeze([
    0x0a720, 0x239f4, 0x242fc, 0x33dbc, 0x36b64, 0x399dc,
    0x48318, 0x483c8, 0x53844, 0x53cdc, 0x53d5c, 0x54100,
    0x547d8, 0x556b8, 0x55714, 0x61e88, 0x73668, 0x73a80,
    0x74930, 0x7c6a0, 0x7cabc, 0x7d7f4, 0x80514, 0x81f34,
    0x82f9c, 0x83128, 0x919e0, 0x91b84, 0x91f90, 0x922c4,
    0x92370
]);

const PATCH_SCRIPTS = Object.freeze([
    'patch-ios-graft-relocations.js',
    'patch-ios-main-atlas.js',
    'patch-ios-capacity.js',
    'patch-ios-mode-description-bridge.js',
    'patch-ios-loot-summary-bridge.js',
    'patch-ios-character-storage-bridge.js',
    'patch-ios-map-junk-bridge.js',
    'patch-ios-car-empty-bridge.js',
    'patch-ios-equipment-swap-none-bridge.js',
    'patch-ios-team-loot-bridge.js',
    'patch-ios-starting-buddy-bridge.js',
    'patch-ios-role-description-bridge.js',
    'patch-ios-team-name-copy-safety.js',
    'patch-ios-team-name-truncation.js',
    'patch-ios-custom-name-width.js'
]);

function sha256(filename) {
    return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
}

function assertHash(label, filename, expected) {
    const actual = sha256(filename);
    if (actual !== expected) {
        throw new Error(
            `${label} SHA-256 mismatch:\n` +
            `expected ${expected}\n` +
            `actual   ${actual}\n` +
            `file     ${filename}`
        );
    }
}

function removePackagingJunk(root) {
    if (!fs.existsSync(root)) return;
    for (const entry of fs.readdirSync(root, {withFileTypes: true})) {
        const target = path.join(root, entry.name);
        const removeDirectory = entry.isDirectory() && [
            '_CodeSignature',
            'SC_Info',
            '__MACOSX'
        ].includes(entry.name);
        const removeFile = !entry.isDirectory() && (
            entry.name === '.DS_Store' ||
            entry.name === 'embedded.mobileprovision' ||
            entry.name === 'CodeResources' ||
            entry.name.startsWith('._')
        );
        if (removeDirectory) {
            fs.rmSync(target, {recursive: true, force: true});
        } else if (removeFile) {
            fs.rmSync(target, {force: true});
        } else if (entry.isDirectory()) {
            removePackagingJunk(target);
        }
    }
}

childProcess.execFileSync(process.execPath, [
    path.join(loaderRoot, 'utils', 'build-ios-native-unicode.js')
], {stdio: 'inherit'});

for (const required of [
    pristineIpa,
    gadget,
    gumGraft,
    bootstrap,
    gadgetConfig,
    fullScript,
    nativeUnicode,
    assets
]) {
    if (!fs.existsSync(required))
        throw new Error(`Required input is missing: ${required}`);
}

assertHash('Pristine IPA', pristineIpa, EXPECTED.pristineIpa);
assertHash('Frida Gadget 16.6.6', gadget, EXPECTED.gadget);
assertHash('gum-graft 16.6.6', gumGraft, EXPECTED.gumGraft);

fs.rmSync(outputRoot, {recursive: true, force: true});
fs.mkdirSync(outputRoot, {recursive: true});
childProcess.execFileSync('/usr/bin/unzip', [
    '-q',
    pristineIpa,
    'Payload/*',
    '-d',
    outputRoot
]);

if (!fs.existsSync(executable))
    throw new Error('Pristine IPA is missing Payload/DR2C.app/DR2C');
assertHash('Original Info.plist', infoPlist, EXPECTED.infoPlist);

removePackagingJunk(payload);
fs.mkdirSync(frameworks, {recursive: true});
fs.cpSync(assets, path.join(app, 'assets'), {recursive: true, force: true});
fs.copyFileSync(gadget, path.join(frameworks, 'FridaGadget.dylib'));
fs.copyFileSync(nativeUnicode, path.join(frameworks, 'MR2CUnicode.dylib'));
fs.copyFileSync(gadgetConfig, path.join(frameworks, 'FridaGadget.config'));
fs.copyFileSync(bootstrap, path.join(frameworks, 'mr2c-unified-bootstrap.js'));
fs.copyFileSync(fullScript, path.join(frameworks, 'full.js'));

childProcess.execFileSync('/usr/local/bin/insert_dylib', [
    '--inplace',
    '--strip-codesig',
    '--all-yes',
    '@executable_path/Frameworks/FridaGadget.dylib',
    executable
], {stdio: 'inherit'});

const graftArgs = GRAFT_TARGETS.flatMap(target => [
    '-i',
    `0x${target.toString(16)}`
]);
childProcess.execFileSync(gumGraft, [...graftArgs, executable], {
    stdio: 'inherit'
});

for (const script of PATCH_SCRIPTS) {
    childProcess.execFileSync(process.execPath, [
        path.join(loaderRoot, 'utils', script),
        executable
    ], {stdio: 'inherit'});
}

assertHash('Rebuilt patched executable', executable, EXPECTED.patchedExecutable);
assertHash('Unmodified Info.plist', infoPlist, EXPECTED.infoPlist);
removePackagingJunk(payload);

fs.rmSync(outputIpa, {force: true});
childProcess.execFileSync('/usr/bin/zip', [
    '-X',
    '-q',
    '-r',
    outputIpa,
    'Payload'
], {
    cwd: outputRoot,
    env: {...process.env, COPYFILE_DISABLE: '1'}
});

console.log(`Unified direct-install/LiveContainer app: ${app}`);
console.log(`Unsigned unified release IPA: ${outputIpa}`);
console.log(`Info.plist SHA-256: ${sha256(infoPlist)}`);
console.log(`Executable SHA-256: ${sha256(executable)}`);
console.log(`Gadget SHA-256: ${sha256(path.join(frameworks, 'FridaGadget.dylib'))}`);
console.log(`IPA SHA-256: ${sha256(outputIpa)}`);
