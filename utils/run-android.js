#!/usr/bin/env node
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const os = require('os');
const https = require('https');
const { execFile, spawn } = require('child_process');
const { promisify } = require('util');
const { pipeline } = require('stream/promises');
const { Command } = require('commander');
const lzma = require('lzma-native');
const frida = require('frida');

const execFileAsync = promisify(execFile);

// ---------- 配置 ----------
const REMOTE_PATH = '/data/local/tmp/frida-server';
const LOCAL_CACHE_DIR = path.join(os.homedir(), '.cache', 'frida-server');
const GITHUB_API_LATEST = 'https://api.github.com/repos/frida/frida/releases/latest';
const GITHUB_DOWNLOAD = (ver, arch) =>
    `https://github.com/frida/frida/releases/download/${ver}/frida-server-${ver}-android-${arch}.xz`;

const ABI_MAP = {
    'arm64-v8a': 'arm64',
    'armeabi-v7a': 'arm',
    'armeabi': 'arm',
    'x86': 'x86',
    'x86_64': 'x86_64',
};

// ---------- 工具函数 ----------

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function run(cmd, args, { check = true } = {}) {
    try {
        const { stdout } = await execFileAsync(cmd, args, {
            encoding: 'utf8',
            maxBuffer: 10 * 1024 * 1024,
        });
        return (stdout || '').trim();
    } catch (e) {
        if (check) {
            const stderr = (e.stderr || e.stdout || e.message || '').trim();
            throw new Error(`命令执行失败: ${cmd} ${args.join(' ')}\n${stderr}`);
        }
        return (e.stdout || '').trim();
    }
}

async function adb(args, opts = {}) {
    const arr = typeof args === 'string' ? args.split(/\s+/).filter(Boolean) : args;
    return run('adb', arr, opts);
}

async function adbShell(cmd, { check = false } = {}) {
    return run('adb', ['shell', cmd], { check });
}

function httpsGetJson(url, headers = {}, timeout = 20000) {
    return new Promise((resolve, reject) => {
        const req = https.get(url, { headers }, res => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                res.resume();
                return resolve(httpsGetJson(res.headers.location, headers, timeout));
            }
            if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => {
                try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
                catch (e) { reject(e); }
            });
        });
        req.setTimeout(timeout, () => req.destroy(new Error('timeout')));
        req.on('error', reject);
    });
}

function downloadWithProgress(url, dest, headers = {}) {
    return new Promise((resolve, reject) => {
        const doGet = u => {
            https.get(u, { headers }, res => {
                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    res.resume();
                    return doGet(res.headers.location);
                }
                if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
                const total = parseInt(res.headers['content-length'] || '0', 10);
                let downloaded = 0;
                const out = fs.createWriteStream(dest);
                res.on('data', chunk => {
                    downloaded += chunk.length;
                    if (total) {
                        const pct = Math.floor(downloaded * 100 / total);
                        process.stdout.write(
                            `\r  进度: ${pct}% (${Math.floor(downloaded / 1024)} KB / ${Math.floor(total / 1024)} KB)`
                        );
                    }
                });
                res.pipe(out);
                out.on('finish', () => { process.stdout.write('\n'); resolve(); });
                out.on('error', reject);
            }).on('error', reject);
        };
        doGet(url);
    });
}

// ---------- 主逻辑 ----------

async function checkAdbDevice() {
    let out;
    try {
        out = await adb('devices');
    } catch (e) {
        if (/ENOENT/.test(e.message)) {
            console.error('✗ 未找到 adb,请先安装 Android Platform Tools 并加入 PATH');
            process.exit(1);
        }
        throw e;
    }
    const lines = out.split('\n').slice(1);
    const devices = lines.filter(l => l.trim() && /\bdevice\b/.test(l) && !/offline/.test(l));
    if (devices.length === 0) {
        console.error('✗ 没有检测到已连接的 Android 设备(adb devices 为空)');
        process.exit(1);
    }
    if (devices.length > 1) console.log(`⚠ 检测到多台设备,将使用默认设备:\n${out}`);
    console.log(`✓ 设备已连接: ${devices[0].split(/\s+/)[0]}`);
}

async function detectArch() {
    const abi = (await adbShell('getprop ro.product.cpu.abi', { check: true })).trim();
    const arch = ABI_MAP[abi];
    if (!arch) {
        console.error(`✗ 不支持的设备 ABI: ${abi}`);
        process.exit(1);
    }
    console.log(`✓ 设备架构: ${abi} -> ${arch}`);
    return arch;
}

async function detectFridaVersion() {
    // 优先用本地 frida CLI 的版本,保持 client/server 一致
    try {
        const ver = (await run('frida', ['--version'])).trim();
        if (/^\d+\.\d+\.\d+/.test(ver)) {
            console.log(`✓ 使用本地 frida 版本: ${ver}`);
            return ver;
        }
    } catch (_) { }

    console.log('→ 本地未安装 frida,查询 GitHub 最新版本...');
    const data = await httpsGetJson(GITHUB_API_LATEST, { 'User-Agent': 'frida-helper' });
    const ver = data.tag_name.replace(/^v/, '');
    console.log(`✓ 最新版本: ${ver}`);
    return ver;
}

async function ensureLocalBinary(version, arch) {
    await fsp.mkdir(LOCAL_CACHE_DIR, { recursive: true });
    const binName = `frida-server-${version}-android-${arch}`;
    const binPath = path.join(LOCAL_CACHE_DIR, binName);

    try {
        const stat = await fsp.stat(binPath);
        if (stat.size > 0) {
            console.log(`✓ 使用缓存: ${binPath}`);
            return binPath;
        }
    } catch (_) { }

    const url = GITHUB_DOWNLOAD(version, arch);
    const xzPath = path.join(LOCAL_CACHE_DIR, `${binName}.xz`);
    console.log(`→ 下载 ${url}`);
    await downloadWithProgress(url, xzPath, { 'User-Agent': 'frida-helper' });

    console.log('→ 解压 xz...');
    await pipeline(
        fs.createReadStream(xzPath),
        lzma.createDecompressor(),
        fs.createWriteStream(binPath)
    );

    await fsp.unlink(xzPath).catch(() => { });
    console.log(`✓ 已解压到: ${binPath}`);
    return binPath;
}

async function detectRoot() {
    const candidates = [
        ['su', '-c', 'id'],
        ['su', '0', 'id'],
        ['su', '-c', 'id -u'],
    ];
    for (const cmd of candidates) {
        const out = await run('adb', ['shell', ...cmd], { check: false });
        if (/uid=0/.test(out) || out.trim() === '0') {
            console.log(`✓ 已获取 root: adb shell ${cmd.slice(0, -1).join(' ')} ...`);
            return cmd.slice(0, -1); // 去掉测试用的 id
        }
    }
    return null;
}

async function isFridaListening() {
    const probes = [
        "ss -lnt 2>/dev/null | grep -E ':27042 '",
        "netstat -lnt 2>/dev/null | grep -E ':27042 '",
        "cat /proc/net/tcp 2>/dev/null | awk '{print $2}' | grep -i ':69A2'",
    ];
    for (const probe of probes) {
        if ((await adbShell(probe)).trim()) return true;
    }
    return false;
}

async function stopFrida(suPrefix) {
    for (const cmd of ['pkill -9 -f frida-server', 'killall -9 frida-server']) {
        await run('adb', ['shell', ...suPrefix, cmd], { check: false });
    }
    await sleep(500);
}

async function pushAndStart(localBin) {
    const suPrefix = await detectRoot();
    if (!suPrefix) {
        console.error([
            '✗ 设备未 root 或 su 不可用。',
            '  frida-server 必须以 root 运行。请检查:',
            '  1) 设备已 root(Magisk / SuperSU 等)',
            '  2) shell 用户已被授予 root 权限(在 Magisk 中授权)',
            '  非 root 设备只能用 Frida Gadget(需重打包 APK 注入 .so)',
        ].join('\n'));
        process.exit(1);
    }

    console.log('→ 清理已有 frida-server');
    await stopFrida(suPrefix);

    const localSize = (await fsp.stat(localBin)).size;
    const remoteSize = (await adbShell(`stat -c%s ${REMOTE_PATH} 2>/dev/null || echo 0`)).trim();

    if (remoteSize !== String(localSize)) {
        console.log(`→ 推送 ${path.basename(localBin)} 到 ${REMOTE_PATH}`);
        await adb(['push', localBin, REMOTE_PATH]);
    } else {
        console.log('✓ 设备上已存在相同二进制,跳过推送');
    }
    await run('adb', ['shell', ...suPrefix, `chmod 755 ${REMOTE_PATH}`], { check: false });

    // 启动:nohup + 后台,Node 端 detach 不等
    const logRemote = '/data/local/tmp/frida.log';
    await run('adb', ['shell', ...suPrefix, `rm -f ${logRemote}`], { check: false });
    console.log('→ 以 root 权限启动 frida-server...');
    const startCmd = `nohup ${REMOTE_PATH} > ${logRemote} 2>&1 &`;
    const child = spawn('adb', ['shell', ...suPrefix, startCmd], {
        stdio: 'ignore',
        detached: true,
    });
    child.unref();

    // 等监听(最多 10s)
    for (let i = 0; i < 20; i++) {
        await sleep(500);
        if (await isFridaListening()) {
            console.log(`✓ frida-server 启动成功并监听 27042 (耗时 ~${((i + 1) * 0.5).toFixed(1)}s)`);
            return;
        }
    }

    // 失败:把设备日志拉出来
    const log = (await adbShell(`cat ${logRemote} 2>/dev/null`)).trim();
    const msg = ['✗ frida-server 启动失败(端口 27042 未监听)'];
    if (log) msg.push(`  设备日志:\n${log}`);
    msg.push(
        '  常见原因:',
        '  • 架构不匹配 — 检查下载的二进制与设备 CPU 是否一致',
        "  • SELinux 拦截 — 试试 adb shell \"su -c 'setenforce 0'\"",
        "  • 端口被占用 — adb shell \"su -c 'lsof -i:27042'\"",
        '  • Magisk 未授权 shell — 在 Magisk 应用里把 shell 加入授权列表',
    );
    console.error(msg.join('\n'));
    process.exit(1);
}

function onMessage(message) {
    if (message.type === 'send') {
        console.log('[agent]', message.payload);
    } else if (message.type === 'error') {
        console.log('[error]', message.stack);
    } else {
        console.log('[msg]', message);
    }
}

async function spawnAndInject(pkg, scriptPath) {
    const resolved = path.resolve(scriptPath);
    if (!fs.existsSync(resolved)) {
        console.error(`✗ 找不到注入脚本: ${resolved}`);
        process.exit(1);
    }

    console.log('\n→ 连接 USB 设备...');
    let device;
    try {
        // frida-node 的 getUsbDevice 不直接接 timeout,这里包一层超时
        device = await Promise.race([
            frida.getUsbDevice(),
            new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5000)),
        ]);
    } catch (e) {
        console.error(`✗ 连接设备失败: ${e.message}`);
        process.exit(1);
    }
    console.log(`✓ 设备: ${device.name}`);

    const source = await fsp.readFile(resolved, 'utf-8');

    console.log(`→ spawn ${pkg} ...`);
    let pid;
    try {
        pid = await device.spawn([pkg]);
    } catch (e) {
        console.error(`✗ spawn 失败: ${e.message}\n  请确认包名正确且应用已安装`);
        process.exit(1);
    }
    console.log(`✓ pid = ${pid}`);

    console.log(`→ attach 并加载 ${path.basename(resolved)} ...`);
    const session = await device.attach(pid);

    const exited = new Promise(resolve => {
        session.detached.connect(reason => {
            console.log(`[!] session detached: ${reason}`);
            resolve();
        });
    });
    console.log('[*] attach 成功');

    const script = await session.createScript(source);
    script.message.connect(onMessage);
    await script.load();
    console.log('[*] agent 已注入');

    await device.resume(pid);
    console.log('✓ 已恢复进程,agent 运行中。\n');

    process.on('SIGINT', async () => {
        console.log('\n[*] 退出');
        try { await session.detach(); } catch (_) { }
        process.exit(0);
    });

    await exited;
}

async function main() {
    const program = new Command();
    program
        .description('启动 frida-server 并可选 spawn + 注入 ./dist/main.js')
        .argument('[package]', '要 spawn 的应用包名(可选)')
        .option('-s, --script <path>', '注入脚本路径', 'dist/main.js')
        .parse(process.argv);

    const opts = program.opts();
    const pkg = program.args[0];

    console.log('='.repeat(50));
    console.log('  Frida Server 自动启动脚本');
    console.log('='.repeat(50));

    await checkAdbDevice();
    const arch = await detectArch();
    const version = await detectFridaVersion();
    const localBin = await ensureLocalBinary(version, arch);
    await pushAndStart(localBin);

    if (pkg) {
        await sleep(1000);
        await spawnAndInject(pkg, opts.script);
    } else {
        console.log('\n现在可以使用: frida-ps -U');
    }
}

main().catch(err => {
    console.error(`✗ 错误: ${err.message || err}`);
    process.exit(1);
});