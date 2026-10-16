const childProcess = require('child_process');
const fs = require('fs');
const path = require('path');

const loaderRoot = path.resolve(__dirname, '..');
const workspaceRoot = path.resolve(loaderRoot, '..');
const sourceIpa = path.join(workspaceRoot, 'releases', 'MR2C.ipa');
const bootstrap = path.join(loaderRoot, 'ios', 'main.js');
const gadgetConfig = path.join(
    loaderRoot,
    'ios',
    'FridaGadget.livecontainer.config'
);
const fullScript = path.join(loaderRoot, 'dist', 'main.js');
const outputRoot = path.join(workspaceRoot, 'ios-livecontainer-path-fix');
const app = path.join(outputRoot, 'Payload', 'DR2C.app');
const frameworks = path.join(app, 'Frameworks');
const outputIpa = path.join(
    workspaceRoot,
    'releases',
    'MR2C-LiveContainer-path-fix.ipa'
);

for (const required of [sourceIpa, bootstrap, gadgetConfig, fullScript]) {
    if (!fs.existsSync(required))
        throw new Error(`Required input is missing: ${required}`);
}

fs.rmSync(outputRoot, {recursive: true, force: true});
fs.mkdirSync(outputRoot, {recursive: true});
childProcess.execFileSync('/usr/bin/unzip', [
    '-q',
    sourceIpa,
    '-d',
    outputRoot
]);

if (!fs.existsSync(frameworks))
    throw new Error(`Source IPA is missing DR2C.app/Frameworks`);

fs.copyFileSync(
    bootstrap,
    path.join(frameworks, 'mr2c-livecontainer-bootstrap.js')
);
fs.copyFileSync(gadgetConfig, path.join(frameworks, 'FridaGadget.config'));
fs.copyFileSync(fullScript, path.join(frameworks, 'full.js'));

// Preserve the tested executable, grafts, Gadget and resources exactly. Only
// the bootstrap/config/full-script files differ. The output remains unsigned
// for the same external signing/install flow as the existing release IPA.
fs.rmSync(path.join(outputRoot, 'Payload', '.DS_Store'), {force: true});
fs.rmSync(path.join(app, '_CodeSignature'), {recursive: true, force: true});
fs.rmSync(path.join(app, 'embedded.mobileprovision'), {force: true});
fs.rmSync(outputIpa, {force: true});
childProcess.execFileSync('/usr/bin/zip', [
    '-q',
    '-r',
    outputIpa,
    'Payload'
], {cwd: outputRoot});

console.log(`LiveContainer-fixed app: ${app}`);
console.log(`Unsigned fixed IPA: ${outputIpa}`);
