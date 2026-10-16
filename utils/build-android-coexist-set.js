const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { alignApkNativeLibraries } = require('./align-apk-native-libs');

function fail(message) {
    throw new Error(message);
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

function requireFile(filePath) {
    if (!fs.existsSync(filePath))
        fail(`Missing required file: ${filePath}`);
}

const [outputArg, rootLoaderArg, ...requestedPackages] = process.argv.slice(2);
if (!outputArg || !rootLoaderArg) {
    console.error(
        'Usage: node build-android-coexist-set.js <output-dir> <root-loader-dir> ' +
        '[package ...]'
    );
    process.exit(1);
}

const projectRoot = path.resolve(__dirname, '..', '..');
const outputDir = path.resolve(outputArg);
const rootLoaderDir = path.resolve(rootLoaderArg);
const packages = requestedPackages.length > 0 ? requestedPackages : [
    'com.noodlecake.mr2c',
    'com.noodlecake.mr2ca',
    'com.noodlecake.mr2cb',
    'com.noodlecake.mr2cc',
    'com.noodlecake.mr2cd',
    'com.noodlecake.mr2ce',
    'com.noodlecake.mr2cf',
    'com.noodlecake.mr2cg'
];

const oldPackage = 'com.noodlecake.mrtc';
const originalPackage = 'com.noodlecake.drtc';
const coexistKit = '/private/tmp/mr2c-coexist-kit';
const decodedOrigin = path.join(coexistKit, 'base-origin-decoded');
const sourceModule = path.join(coexistKit, 'source-module.apk');
const apktoolJar = path.join(coexistKit, 'tools', 'apktool_3.0.3.jar');
const npatchJar = path.join(coexistKit, 'tools', 'npatch-v1.0.5.jar');
const bcJar = path.join(coexistKit, 'tools', 'bcprov-jdk18on-1.83.jar');
const bcSecurity = path.join(coexistKit, 'tools', 'npatch-bc.security');
const innerJks = path.join(coexistKit, 'keys', 'coexist-temp.jks');
const outerBks = path.join(coexistKit, 'keys', 'coexist-temp.bks');
const prepareModule = path.join(__dirname, 'prepare-android-coexist-module.js');
const stripSigningBlock = path.join(__dirname, 'strip-apk-signing-block.js');

for (const required of [
    path.join(decodedOrigin, 'apktool.yml'),
    sourceModule,
    apktoolJar,
    npatchJar,
    bcJar,
    bcSecurity,
    innerJks,
    outerBks,
    path.join(rootLoaderDir, 'index.js'),
    path.join(rootLoaderDir, 'main.js')
]) requireFile(required);

fs.mkdirSync(outputDir, { recursive: true });

for (const packageName of packages) {
    if (!/^com\.noodlecake\.mr2c[a-g]?$/.test(packageName))
        fail(`Unsupported coexist package: ${packageName}`);

    console.log(`\n=== Building ${packageName} ===`);
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr2c-coexist-set-'));
    try {
        const originDir = path.join(workDir, 'origin');
        fs.cpSync(decodedOrigin, originDir, { recursive: true });

        const nativeSmali = path.join(
            originDir,
            'smali',
            'com',
            'noodlecake',
            'NoodleX',
            'NoodleXNative.smali'
        );
        let smali = fs.readFileSync(nativeSmali, 'utf8');
        smali = replaceExactlyOnce(
            smali,
            `.field public static packageName:Ljava/lang/String; = "${oldPackage}"`,
            `.field public static packageName:Ljava/lang/String; = "${packageName}"`,
            'NoodleXNative package identity'
        );
        fs.writeFileSync(nativeSmali, smali, 'utf8');

        // NPatch changes the manifest package but leaves explicit provider
        // authorities untouched. Change the authority in decoded XML before
        // rebuilding so packages of every length remain valid.
        const manifestPath = path.join(originDir, 'AndroidManifest.xml');
        let manifest = fs.readFileSync(manifestPath, 'utf8');
        manifest = replaceExactlyOnce(
            manifest,
            `${originalPackage}.FlurryContentProvider`,
            `${packageName}.FlurryContentProvider`,
            'Flurry provider authority'
        );
        fs.writeFileSync(manifestPath, manifest, 'utf8');
        fs.rmSync(path.join(originDir, 'original', 'META-INF'), {
            recursive: true,
            force: true
        });

        const innerRaw = path.join(workDir, 'origin-rebuilt.apk');
        const innerSignedUnaligned = path.join(workDir, 'origin-signed-unaligned.apk');
        const innerSigned = path.join(workDir, 'origin-signed.apk');
        run('java', ['-jar', apktoolJar, 'b', '-f', '-o', innerRaw, originDir]);
        run('jarsigner', [
            '-keystore', innerJks,
            '-storepass', 'android',
            '-keypass', 'android',
            '-signedjar', innerSignedUnaligned,
            innerRaw,
            'coexist'
        ]);
        // jarsigner rewrites ZIP entry headers. Apply alignment afterwards;
        // V1 signatures cover entry contents, not ZIP padding/header offsets.
        // NPatch embeds this APK at a 4 KiB boundary and aliases its original
        // entries, so the aligned inner resources.arsc remains aligned in the
        // final outer APK as required by Android 14.
        alignApkNativeLibraries(innerSignedUnaligned, innerSigned, 16384);

        const moduleApk = path.join(workDir, 'loader-module.apk');
        run('node', [
            prepareModule,
            sourceModule,
            moduleApk,
            oldPackage,
            packageName,
            rootLoaderDir,
            apktoolJar
        ], { cwd: projectRoot });

        const npatchOut = path.join(workDir, 'npatch');
        fs.mkdirSync(npatchOut, { recursive: true });
        run('java', [
            `-Djava.security.properties=${bcSecurity}`,
            '-cp', `${bcJar}${path.delimiter}${npatchJar}`,
            'top.nkbe.npatch.patch.NPatch',
            innerSigned,
            '-o', npatchOut,
            '-f',
            '-l', '2',
            '-k', outerBks, 'android', 'coexist', 'android',
            '-m', moduleApk,
            '-p', packageName
        ]);

        const patched = fs.readdirSync(npatchOut)
            .filter(name => name.endsWith('-npatched.apk'))
            .map(name => path.join(npatchOut, name));
        if (patched.length !== 1)
            fail(`Expected one NPatch output for ${packageName}, got ${patched.length}`);

        const finalPath = path.join(
            outputDir,
            `DRTC-${packageName}-unsigned.apk`
        );
        run('node', [stripSigningBlock, patched[0], finalPath], {
            cwd: projectRoot
        });
        console.log(`Completed ${finalPath}`);
    } finally {
        fs.rmSync(workDir, { recursive: true, force: true });
    }
}
