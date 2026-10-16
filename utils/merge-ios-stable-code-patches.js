const fs = require('fs');
const path = require('path');

const [baselinePath, referencePath, targetPath] = process.argv.slice(2);
if (!targetPath) {
    throw new Error(
        'Usage: node utils/merge-ios-stable-code-patches.js ' +
        'BASELINE_GRAFTED REFERENCE_STABLE TARGET_GRAFTED'
    );
}

const baseline = fs.readFileSync(path.resolve(baselinePath));
const reference = fs.readFileSync(path.resolve(referencePath));
const target = fs.readFileSync(path.resolve(targetPath));
for (const [name, binary] of [
    ['baseline', baseline],
    ['reference', reference],
    ['target', target]
]) {
    if (binary.readUInt32LE(0) !== 0xfeedfacf)
        throw new Error(`${name} is not a 64-bit Mach-O`);
}

// Ignore Mach-O load-command/signature differences and the generated Frida
// segments. The interval below is the original mapped code/data content. Any
// difference between a clean 26-target graft and the current stable binary is
// an intentional native compatibility/capacity patch that must survive when
// rebuilding with additional graft targets.
const START = 0x4000;
const END = 0xc0000;
if (Math.min(baseline.length, reference.length, target.length) < END)
    throw new Error('One or more binaries are shorter than the original mapped content');

let changed = 0;
for (let offset = START; offset < END; offset++) {
    if (baseline[offset] === reference[offset]) continue;
    target[offset] = reference[offset];
    changed++;
}

if (changed > 0) fs.writeFileSync(path.resolve(targetPath), target);
console.log(`Merged ${changed} stable native patch byte(s) into ${targetPath}`);
