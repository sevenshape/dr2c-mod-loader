const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { alignApkNativeLibraries } = require('./align-apk-native-libs');

function fail(message) {
    console.error(message);
    process.exit(1);
}

function run(command, args, options = {}) {
    const result = spawnSync(command, args, { stdio: 'inherit', ...options });
    if (result.status !== 0)
        fail(`${command} failed with exit code ${result.status}`);
}

function replaceExactlyOnce(text, oldValue, newValue, label) {
    const first = text.indexOf(oldValue);
    if (first < 0)
        fail(`${label} does not contain ${oldValue}`);
    if (text.indexOf(oldValue, first + oldValue.length) >= 0)
        fail(`${label} contains ${oldValue} more than once`);
    return text.slice(0, first) + newValue + text.slice(first + oldValue.length);
}

const [
    sourceModuleArg,
    outputModuleArg,
    oldPackage,
    newPackage,
    distArg,
    apktoolArg
] = process.argv.slice(2);
if (!sourceModuleArg || !outputModuleArg || !oldPackage || !newPackage || !distArg) {
    fail(
        'Usage: node prepare-android-coexist-module.js ' +
        '<source-module.apk> <output-module.apk> <old-package> <new-package> ' +
        '<dist-dir> [apktool.jar]'
    );
}

const sourceModule = path.resolve(sourceModuleArg);
const outputModule = path.resolve(outputModuleArg);
const distDir = path.resolve(distArg);
const apktoolJar = path.resolve(
    apktoolArg || process.env.APKTOOL_JAR || '/private/tmp/apktool_3.0.3.jar'
);
if (!fs.existsSync(sourceModule)) fail(`Missing source module: ${sourceModule}`);
if (!fs.existsSync(path.join(distDir, 'main.js'))) fail(`Missing compiled loader: ${distDir}/main.js`);
if (!fs.existsSync(apktoolJar)) fail(`Missing Apktool jar: ${apktoolJar}`);

const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr2c-coexist-module-'));
try {
    const decodedDir = path.join(workDir, 'decoded');
    run('java', ['-jar', apktoolJar, 'd', '-f', '-o', decodedDir, sourceModule]);

    // Reassemble the DEX after changing the package filter. DEX string_ids
    // are lexicographically ordered; an in-place drtc -> mrtc replacement
    // leaves the table out of order and Android rejects the whole module.
    const xposedSmaliPath = path.join(
        decodedDir, 'smali', 'top', 'sevenshape', 'dr2cmodloader', 'Xposed.smali'
    );
    let xposedSmali = fs.readFileSync(xposedSmaliPath, 'utf8');
    xposedSmali = replaceExactlyOnce(
        xposedSmali,
        `const-string v1, "${oldPackage}"`,
        `const-string v1, "${newPackage}"`,
        'Xposed.smali package filter'
    );
    const oldGameActivity =
        'const-string v1, "com.noodlecake.drtc.DrtcGameActivity"';
    const splashActivity =
        'const-string v1, "com.noodlecake.drtc.SplashActivity"';
    if (xposedSmali.includes(oldGameActivity)) {
        xposedSmali = replaceExactlyOnce(
            xposedSmali,
            oldGameActivity,
            splashActivity,
            'Xposed.smali activity hook target'
        );
    } else if (!xposedSmali.includes(splashActivity)) {
        fail('Xposed.smali does not contain a supported activity hook target');
    }
    fs.writeFileSync(xposedSmaliPath, xposedSmali, 'utf8');

    // Never carry a source module signature into the rebuilt APK.
    fs.rmSync(path.join(decodedDir, 'original', 'META-INF'), {
        recursive: true,
        force: true
    });

    const gadgetConfigPath = path.join(
        decodedDir, 'lib', 'arm64-v8a', 'libfrida-gadget.config.so'
    );
    const gadgetConfig = fs.readFileSync(gadgetConfigPath, 'utf8');
    if (!gadgetConfig.includes(oldPackage))
        fail('The embedded Gadget config does not contain the expected source package');
    fs.writeFileSync(
        gadgetConfigPath,
        gadgetConfig.split(oldPackage).join(newPackage),
        'utf8'
    );

    const decodedPublicDir = path.join(decodedDir, 'assets', 'public');
    fs.rmSync(decodedPublicDir, { recursive: true, force: true });
    fs.cpSync(distDir, decodedPublicDir, { recursive: true });

    fs.mkdirSync(path.dirname(outputModule), { recursive: true });
    fs.rmSync(outputModule, { force: true });
    run('java', ['-jar', apktoolJar, 'b', '-f', '-o', outputModule, decodedDir]);

    // android:extractNativeLibs="false" makes the dynamic linker mmap native
    // libraries directly from the module APK. Apktool preserves STORED entries
    // but drops zipalign's local-header padding, which Android reports as a
    // misleading "library ... not found" error. Restore 16 KiB alignment so
    // the rebuilt module works on both 4 KiB and 16 KiB page-size devices.
    const alignedModule = `${outputModule}.aligned`;
    alignApkNativeLibraries(outputModule, alignedModule, 16384);
    fs.renameSync(alignedModule, outputModule);

    console.log(`Prepared rebuilt unsigned coexist module: ${outputModule}`);
} finally {
    fs.rmSync(workDir, { recursive: true, force: true });
}
