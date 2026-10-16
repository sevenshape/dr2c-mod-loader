const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

const loaderRoot = path.resolve(__dirname, '..');
const workspaceRoot = path.resolve(loaderRoot, '..');
const pristineIpa = path.join(
    workspaceRoot,
    'DR2C_纯净砸壳_1.32.ipa'
);
const releaseRoot = path.join(workspaceRoot, 'ios-autonomous-release');
const releasePayload = path.join(releaseRoot, 'Payload');
const releaseApp = path.join(releasePayload, 'DR2C.app');
const compiledScript = path.join(loaderRoot, 'dist', 'main.js');
const gadgetConfig = path.join(loaderRoot, 'ios', 'FridaGadget.config');

for (const required of [
    pristineIpa,
    compiledScript,
    gadgetConfig
]) {
    if (!fs.existsSync(required))
        throw new Error(`Required input is missing: ${required}`);
}

fs.rmSync(releaseRoot, {recursive: true, force: true});
fs.mkdirSync(releaseRoot, {recursive: true});
childProcess.execFileSync('/usr/bin/unzip', [
    '-q',
    pristineIpa,
    '-d',
    releaseRoot
]);

if (!fs.existsSync(releaseApp))
    throw new Error(`Pristine IPA is missing Payload/DR2C.app: ${pristineIpa}`);

// Finder metadata makes objection think Payload contains multiple apps/files.
fs.rmSync(path.join(releasePayload, '.DS_Store'), {force: true});

// These files seed a clean app container before any mod has been installed.
// Full translation resources still come from the user's installed mod.
fs.cpSync(
    path.join(loaderRoot, 'assets'),
    path.join(releaseApp, 'assets'),
    {recursive: true}
);

// Copying resources invalidates the old signature. Removing it makes the
// required re-signing step explicit and prevents accidental distribution of a
// bundle that merely looks signed.
fs.rmSync(path.join(releaseApp, '_CodeSignature'), {
    recursive: true,
    force: true
});

// objection's -C and -l options copy these two files beside Gadget using the
// exact runtime names expected by Frida.
fs.copyFileSync(gadgetConfig, path.join(releaseRoot, 'FridaGadget.config'));
fs.copyFileSync(compiledScript, path.join(releaseRoot, 'main.js'));

const sourceIpa = path.join(releaseRoot, 'DR2C-autonomous-source.ipa');
childProcess.execFileSync('/usr/bin/zip', [
    '-q',
    '-r',
    sourceIpa,
    'Payload'
], {cwd: releaseRoot});

console.log(`Clean 1.32 autonomous source app prepared at:\n${releaseApp}`);
console.log(`Source IPA prepared at:\n${sourceIpa}`);
console.log('Patch it with objection -C FridaGadget.config -l main.js.');
