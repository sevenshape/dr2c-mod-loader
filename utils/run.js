#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const os = require('os');
const { Command } = require('commander');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

const frida = require('frida');

async function openGameExeFile(title = 'Select Game File') {
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
        $f.Filter = 'prog.exe|prog.exe'
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
    } catch (e) {
        // 用户取消 / zenity 没装 / 用户没选文件 → 一律当作 null
        return null;
    }
}

function expanduser(p) {
    if (!p) return p;
    if (p.startsWith('~')) return path.join(os.homedir(), p.slice(1));
    return p;
}

async function findGameExe() {
    if (process.platform === 'win32') {
        const { stdout } = await execFileAsync('powershell.exe', [
            '-NoProfile',
            '-Command',
            '(Get-ItemProperty -Path "HKLM:\\SOFTWARE\\WOW6432Node\\Valve\\Steam" -Name "InstallPath" -ErrorAction SilentlyContinue).InstallPath'
        ]);

        const steamPath = stdout.trim();

        if (!steamPath) {
            return '';
        }
        if (!fs.existsSync(path.join(steamPath, 'steamapps', 'common', 'DeathRoadToCanada', 'prog.exe'))) {
            return '';
        }
        return path.join(steamPath, 'steamapps', 'common', 'DeathRoadToCanada', 'prog.exe');
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

let script;

async function main() {
    const program = new Command();
    program
        .description('启动 frida-server 并可选 spawn + 注入 main.js')
        .option('-t, --target <path>', '注入的对象exe')
        .option('-s, --script <path>', '注入脚本路径', './dist/main.js')
        .parse(process.argv);

    const args = program.opts();

    const isCompiled = __filename.includes("deno-compile-");

    if (!args.target) {
        let gameExe = await findGameExe();
        if (!gameExe && !(gameExe = await openGameExeFile())) {
            throw new Error('Fail to find game exe')
        };
        args.target = gameExe;
    }

    const targetPath = expanduser(args.target);

    if (isCompiled) {
        const targetDir = path.join(path.dirname(args.target), 'mods', 'dr2c-mod-loader');
        const sourceDir = path.join(__dirname, '..', 'dist');

        if (!fs.existsSync(path.join(targetDir, 'main.js'))) {
            fs.cpSync(sourceDir, targetDir, { recursive: true });

            const chmodRecursive = (dir) => {
                fs.chmodSync(dir, 0o755);
                for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
                    const fullPath = path.join(dir, entry.name);
                    if (entry.isDirectory()) {
                        chmodRecursive(fullPath);
                    } else {
                        fs.chmodSync(fullPath, 0o644);
                    }
                }
            };
            chmodRecursive(targetDir);

            console.log(`Copied ${sourceDir} to ${targetDir}`);
        } else {
            console.log(`${targetDir} already exists, skipping copy`);
        }


        args.script = path.join(targetDir, 'main.js');
    }

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