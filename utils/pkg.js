const { exec } = require('@yao-pkg/pkg');

const nodeMajor = process.versions.node.split('.')[0];

const platformMap = {
    win32: 'win',
    darwin: 'macos',
    linux: 'linux',
};

const archMap = {
    x64: 'x64',
    arm64: 'arm64',
    ia32: 'x86',
};

const target = `node${nodeMajor}-${platformMap[process.platform]}-${archMap[process.arch]}`;

console.log(`Building for target: ${target}`);

exec(['utils/run.js', '--targets', target, '--out-path', 'build', '--config', 'pck.json']);