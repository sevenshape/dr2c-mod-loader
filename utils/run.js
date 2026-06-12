#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const os = require('os');
const { Command } = require('commander');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);


// 判断是否在 pkg 打包后的环境中运行
// @ts-ignore
const isPkg = typeof process.pkg !== 'undefined';

// 真实可执行文件所在目录(打包后 __dirname 指向虚拟路径,不能用)
const exeDir = isPkg
    ? path.dirname(process.execPath)
    : __dirname;

// snapshot 里的源路径(打包前后都用同一份代码)
const sourceRoot = isPkg
    ? path.join(path.dirname(process.argv[1]), '..', 'node_modules')
    : path.join(__dirname, '..', 'node_modules');

// 目标路径(exe 同目录下的 node_modules)
const targetRoot = path.join(exeDir, 'node_modules');

function copyDirRecursive(src, dest) {
    if (!fs.existsSync(dest)) {
        fs.mkdirSync(dest, { recursive: true });
    }

    const entries = fs.readdirSync(src, { withFileTypes: true });

    for (const entry of entries) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);

        if (entry.isDirectory()) {
            copyDirRecursive(srcPath, destPath);
        } else {
            // 已存在就跳过,避免每次启动都覆盖
            if (!fs.existsSync(destPath)) {
                fs.copyFileSync(srcPath, destPath);
            }
        }
    }
}

if (isPkg) {
    console.log('Extracting assets to:', targetRoot);
    copyDirRecursive(sourceRoot, targetRoot);
    console.log('Done.');
}

console.log('fridaPath:', path.join(exeDir, 'node_modules', 'frida'));
const frida = require(isPkg ? path.join(exeDir, 'node_modules', 'frida') : 'frida');

async function openZipFile(title = 'Install Mod From File') {
    const platform = process.platform;

    try {
        if (platform === 'win32') {
            // Windows: PowerShell + .NET OpenFileDialog,-Sta 必须加
            const escTitle = title.replace(/'/g, "''");
            const ps = `
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        Add-Type -AssemblyName System.Windows.Forms
        $f = New-Object System.Windows.Forms.OpenFileDialog
        $f.Title = '${escTitle}'
        $f.Filter = 'ZIP files (*.zip)|*.zip'
        $f.Multiselect = $false
        if ($f.ShowDialog() -eq 'OK') { Write-Output $f.FileName }
      `;
            const { stdout } = await execFileAsync(
                'powershell',
                ['-NoProfile', '-Sta', '-Command', ps],
                { encoding: 'utf8' }
            );
            return stdout.trim() || null;
        }

        if (platform === 'darwin') {
            // macOS: osascript + choose file
            const escTitle = title.replace(/"/g, '\\"');
            const script = `try
  set f to choose file with prompt "${escTitle}" of type {"zip", "public.zip-archive"}
  return POSIX path of f
on error
  return ""
end try`;
            const { stdout } = await execFileAsync('osascript', ['-e', script]);
            return stdout.trim() || null;
        }

        // Linux: zenity(用户需预装)
        const { stdout } = await execFileAsync('zenity', [
            '--file-selection',
            `--title=${title}`,
            '--file-filter=ZIP files | *.zip',
        ]);
        return stdout.trim() || null;
    } catch (e) {
        // 用户取消 / zenity 没装 / 用户没选文件 → 一律当作 null
        return null;
    }
}

let Registry;
if (process.platform === 'win32') {
    Registry = require('winreg');
}

function expanduser(p) {
    if (!p) return p;
    if (p.startsWith('~')) return path.join(os.homedir(), p.slice(1));
    return p;
}

async function findGameExe() {
    if (process.platform === 'win32') {
        const regKey = new Registry({
            hive: Registry.HKCU,
            key: '\\Software\\Valve\\Steam',
        });

        const steamPath = await new Promise((resolve, reject) => {
            regKey.get('SteamPath', (err, item) => {
                if (err) reject(err);
                else resolve(item.value);
            });
        });

        const vdf = path.join(steamPath, 'steamapps', 'libraryfolders.vdf');
        const content = fs.readFileSync(vdf, 'utf-8');

        const match = content.match(/"path"\s+"(.+?)"/);
        if (match) {
            return path.join(
                match[1].replace(/\\\\/g, '\\'),
                'steamapps', 'common', 'DeathRoadToCanada', 'prog.exe'
            );
        }
        return null;
    }

    if (process.platform === 'linux') {
        return path.join(
            os.homedir(),
            '.steam/steam/steamapps/common/DeathRoadToCanada/prog-linux'
        );
    }

    if (process.platform === 'darwin') {
        return path.join(
            os.homedir(),
            'Library/Application Support/Steam/steamapps/common/DeathRoadToCanada/DR2C.app/Contents/MacOS/DR2C'
        );
    }

    return null;
}

let script; // 全局 script,供 onMessage 里 post 回消息

async function onMessage(message, data) {
    if (message.type === 'send') {
        const payload = message.payload;

        if (payload.type === 'mkdir') {
            fs.mkdirSync(payload.data.path, { recursive: true });
            script.post({
                type: 'mkdir',
                success: true,
            });
        } else if (payload.type === 'filedialog') {
            const result = await openZipFile('Install Mod From File');

            script.post({
                type: 'filedialog',
                success: true,
                result: result,   // 选中:字符串路径;取消/失败:null
            });
        } else {
            console.log('[agent]', payload);
        }
    } else if (message.type === 'error') {
        console.log('[error]', message.stack);
    } else {
        console.log('[msg]', message);
    }
}

async function main() {
    const program = new Command();
    program
        .description('启动 frida-server 并可选 spawn + 注入 main.js')
        .option('-t, --target <path>', '注入的对象exe')
        .option('-s, --script <path>', '注入脚本路径', './dist/main.js')
        .parse(process.argv);

    const args = program.opts();

    if (!args.target) {
        const gameExe = await findGameExe();
        if (!gameExe) throw new Error('Fail to find game directory');
        args.target = gameExe;
    }

    const targetPath = expanduser(args.target);

    const agentSource = fs.readFileSync(args.script, 'utf-8');

    const device = await frida.getLocalDevice();
    console.log(`[*] 已连接: ${device.name}`);
    console.log(`[*] script: ${args.script}`);

    console.log(`[*] spawn ${targetPath} ...`);
    const pid = await device.spawn(targetPath, {
        cwd: path.dirname(targetPath),
    });
    console.log(`[*] PID = ${pid}(已暂停)`);

    const session = await device.attach(pid);
    console.log('[*] attach 成功');

    const exited = new Promise((resolve) => {
        session.detached.connect((reason) => {
            console.log(`[!] session detached: ${reason}`);
            resolve();
        });
    });

    script = await session.createScript(agentSource, {
        name: path.basename(args.script, '.js'),
    });
    script.message.connect(onMessage);
    await script.load();
    console.log('[*] agent 已注入');
    console.log('[*] agent 初始化完成');

    await device.resume(pid);
    console.log('[*] 进程已 resume\n');

    process.on('SIGINT', async () => {
        console.log('\n[*] 退出');
        try {
            await session.detach();
        } catch (_) { }
        process.exit(0);
    });

    await exited;
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});