#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动启动 Android 设备上的 frida-server,并 spawn 目标应用注入 agent.js
- 自动检测设备 CPU 架构
- 自动匹配本地 frida 版本(若未安装则使用最新版)
- 自动下载对应架构的 frida-server
- 通过 adb 推送并以 root 权限后台启动
- 可选:spawn 指定包名,注入当前目录下的 agent.js 并保持运行

用法:
    python3 start_frida.py                       # 仅启动 frida-server
    python3 start_frida.py com.example.app       # 启动 server 并 spawn + 注入 agent.js
    python3 start_frida.py com.example.app -s my_agent.js  # 指定脚本路径
"""

import argparse
import lzma
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
import threading
import json

# ---------- 配置 ----------
REMOTE_PATH = "/data/local/tmp/frida-server"
LOCAL_CACHE_DIR = Path.home() / ".cache" / "frida-server"
GITHUB_API_LATEST = "https://api.github.com/repos/frida/frida/releases/latest"
GITHUB_DOWNLOAD = "https://github.com/frida/frida/releases/download/{ver}/frida-server-{ver}-android-{arch}.xz"

# Android ABI -> frida arch
ABI_MAP = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "x86": "x86",
    "x86_64": "x86_64",
}

def on_message(message, data):
    if message["type"] == "send":
        print("[agent]", message["payload"])
    elif message["type"] == "error":
        print("[error]", message["stack"])
    else:
        print("[msg]", message)

# ---------- 工具函数 ----------
def run(cmd, check=True, capture=True):
    """执行 shell 命令"""
    if isinstance(cmd, str):
        cmd = cmd.split()
    result = subprocess.run(cmd, capture_output=capture, text=True)
    if check and result.returncode != 0:
        stderr = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"命令执行失败: {' '.join(cmd)}\n{stderr}")
    return (result.stdout or "").strip()


def adb(args, check=True):
    """执行 adb 命令"""
    return run(["adb", *args.split()] if isinstance(args, str) else ["adb", *args], check=check)


def adb_shell(cmd, root=False, check=False):
    """在设备上执行 shell 命令"""
    if root:
        # 用 su -c 提权;部分设备使用 'su 0'
        full = ["adb", "shell", "su", "-c", cmd]
    else:
        full = ["adb", "shell", cmd]
    return run(full, check=check)


# ---------- 主逻辑 ----------
def check_adb_device():
    """确认 adb 已连接到至少一台设备"""
    try:
        out = adb("devices")
    except FileNotFoundError:
        sys.exit("✗ 未找到 adb,请先安装 Android Platform Tools 并加入 PATH")
    devices = [l for l in out.splitlines()[1:] if l.strip() and "device" in l and "offline" not in l]
    if not devices:
        sys.exit("✗ 没有检测到已连接的 Android 设备(adb devices 为空)")
    if len(devices) > 1:
        print(f"⚠ 检测到多台设备,将使用默认设备:\n{out}")
    print(f"✓ 设备已连接: {devices[0].split()[0]}")


def detect_arch():
    """检测设备 CPU 架构,返回 frida 使用的 arch 名称"""
    abi = adb_shell("getprop ro.product.cpu.abi", check=True)
    arch = ABI_MAP.get(abi)
    if not arch:
        sys.exit(f"✗ 不支持的设备 ABI: {abi}")
    print(f"✓ 设备架构: {abi} -> {arch}")
    return arch


def detect_frida_version():
    """优先使用本地已安装的 frida 版本,以保证 client/server 版本一致"""
    frida_bin = shutil.which("frida")
    if frida_bin:
        try:
            ver = run([frida_bin, "--version"]).strip()
            if re.match(r"^\d+\.\d+\.\d+", ver):
                print(f"✓ 使用本地 frida 版本: {ver}")
                return ver
        except Exception:
            pass

    # 退回到 GitHub 最新版本
    print("→ 本地未安装 frida,查询 GitHub 最新版本...")
    req = urllib.request.Request(GITHUB_API_LATEST, headers={"User-Agent": "frida-helper"})
    with urllib.request.urlopen(req, timeout=20) as r:
        import json
        data = json.loads(r.read())
    ver = data["tag_name"].lstrip("v")
    print(f"✓ 最新版本: {ver}")
    return ver


def ensure_local_binary(version, arch):
    """确保本地缓存中存在解压后的 frida-server 二进制"""
    LOCAL_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    bin_name = f"frida-server-{version}-android-{arch}"
    bin_path = LOCAL_CACHE_DIR / bin_name
    if bin_path.exists() and bin_path.stat().st_size > 0:
        print(f"✓ 使用缓存: {bin_path}")
        return bin_path

    url = GITHUB_DOWNLOAD.format(ver=version, arch=arch)
    xz_path = LOCAL_CACHE_DIR / f"{bin_name}.xz"
    print(f"→ 下载 {url}")

    req = urllib.request.Request(url, headers={"User-Agent": "frida-helper"})
    with urllib.request.urlopen(req, timeout=60) as r, open(xz_path, "wb") as f:
        total = int(r.headers.get("Content-Length", 0))
        downloaded = 0
        while chunk := r.read(64 * 1024):
            f.write(chunk)
            downloaded += len(chunk)
            if total:
                pct = downloaded * 100 // total
                print(f"\r  进度: {pct}% ({downloaded // 1024} KB / {total // 1024} KB)", end="")
        print()

    print("→ 解压 xz...")
    with lzma.open(xz_path, "rb") as src, open(bin_path, "wb") as dst:
        shutil.copyfileobj(src, dst)
    xz_path.unlink(missing_ok=True)
    print(f"✓ 已解压到: {bin_path}")
    return bin_path


def detect_root():
    """检测设备的 root 方式,返回可用的 su 调用前缀(列表)。无 root 返回 None"""
    candidates = [
        ["su", "-c", "id"],          # 主流: su -c '<cmd>'
        ["su", "0", "id"],           # Magisk 部分版本
        ["su", "-c", "id -u"],       # 兜底
    ]
    for cmd in candidates:
        out = run(["adb", "shell", *cmd], check=False)
        if "uid=0" in out or out.strip() == "0":
            print(f"✓ 已获取 root: adb shell {' '.join(cmd[:-1])} ...")
            # 返回 su 前缀(去掉测试用的 id)
            return cmd[:-1]
    return None


def is_frida_listening():
    """检测 frida-server 是否在 27042 端口监听(比 pgrep 可靠)"""
    # ss 在新 Android 上更通用;netstat 兜底
    for probe in (
        "ss -lnt 2>/dev/null | grep -E ':27042 '",
        "netstat -lnt 2>/dev/null | grep -E ':27042 '",
        "cat /proc/net/tcp 2>/dev/null | awk '{print $2}' | grep -i ':69A2'",  # 27042 = 0x69A2
    ):
        if adb_shell(probe).strip():
            return True
    return False


def stop_frida(su_prefix):
    """停止设备上残留的 frida-server,避免端口占用"""
    for cmd in ("pkill -9 -f frida-server", "killall -9 frida-server"):
        run(["adb", "shell", *su_prefix, cmd], check=False)
    time.sleep(0.5)


def push_and_start(local_bin):
    """推送 frida-server 到设备并启动"""
    su_prefix = detect_root()
    if not su_prefix:
        sys.exit(
            "✗ 设备未 root 或 su 不可用。\n"
            "  frida-server 必须以 root 运行。请检查:\n"
            "  1) 设备已 root(Magisk / SuperSU 等)\n"
            "  2) shell 用户已被授予 root 权限(在 Magisk 中授权)\n"
            "  非 root 设备只能用 Frida Gadget(需重打包 APK 注入 .so)"
        )

    # 清掉残留实例
    print("→ 清理已有 frida-server")
    stop_frida(su_prefix)

    # 推送(尺寸一致就跳过)
    remote_size = adb_shell(f"stat -c%s {REMOTE_PATH} 2>/dev/null || echo 0").strip()
    if remote_size != str(local_bin.stat().st_size):
        print(f"→ 推送 {local_bin.name} 到 {REMOTE_PATH}")
        adb(["push", str(local_bin), REMOTE_PATH])
    else:
        print("✓ 设备上已存在相同二进制,跳过推送")
    run(["adb", "shell", *su_prefix, f"chmod 755 {REMOTE_PATH}"], check=False)

    # 启动 — 输出重定向到日志方便排查
    log_remote = "/data/local/tmp/frida.log"
    run(["adb", "shell", *su_prefix, f"rm -f {log_remote}"], check=False)
    print("→ 以 root 权限启动 frida-server...")
    start_cmd = f"nohup {REMOTE_PATH} > {log_remote} 2>&1 &"
    subprocess.Popen(
        ["adb", "shell", *su_prefix, start_cmd],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # 等待端口监听(最多 10 秒)
    for i in range(20):
        time.sleep(0.5)
        if is_frida_listening():
            print(f"✓ frida-server 启动成功并监听 27042 (耗时 ~{(i+1)*0.5:.1f}s)")
            return

    # 失败 — 读取日志帮助定位
    log = adb_shell(f"cat {log_remote} 2>/dev/null").strip()
    msg = ["✗ frida-server 启动失败(端口 27042 未监听)"]
    if log:
        msg.append(f"  设备日志:\n{log}")
    msg += [
        "  常见原因:",
        "  • 架构不匹配 — 检查下载的二进制与设备 CPU 是否一致",
        "  • SELinux 拦截 — 试试 adb shell \"su -c 'setenforce 0'\"",
        "  • 端口被占用 — adb shell \"su -c 'lsof -i:27042'\"",
        "  • Magisk 未授权 shell — 在 Magisk 应用里把 shell 加入授权列表",
    ]
    sys.exit("\n".join(msg))


def spawn_and_inject(package, script_path):
    """spawn 目标应用,注入 agent.js,并保持脚本运行"""
    try:
        import frida
    except ImportError:
        sys.exit("✗ 需要安装 frida 的 Python 绑定: pip install frida-tools")

    script_path = Path(script_path).resolve()
    if not script_path.exists():
        sys.exit(f"✗ 找不到注入脚本: {script_path}")

    print(f"\n→ 连接 USB 设备...")
    try:
        device = frida.get_usb_device(timeout=5)
    except Exception as e:
        sys.exit(f"✗ 连接设备失败: {e}")
    print(f"✓ 设备: {device.name}")

    with open(script_path, "r", encoding="utf-8") as f:
        source = f.read()

    print(f"→ spawn {package} ...")
    try:
        pid = device.spawn([package])
    except Exception as e:
        sys.exit(f"✗ spawn 失败: {e}\n  请确认包名正确且应用已安装")
    print(f"✓ pid = {pid}")

    print(f"→ attach 并加载 {script_path.name} ...")
    session = device.attach(pid)

    exited = threading.Event()
    def on_detached(reason):
        print(f"[!] session detached: {reason}")
        exited.set()

    session.on("detached", on_detached)
    print(f"[*] attach 成功")


    script = session.create_script(source)
    script.on("message", on_message)
    script.load()

    print("[*] agent 已注入")

    device.resume(pid)
    print(f"✓ 已恢复进程,agent 运行中。\n")

    try:
        while not exited.wait(0.5):
            pass
    except KeyboardInterrupt:
        print("\n[*] 退出")
        session.detach()
    
    # 阻塞主线程等待消息
    # try:
    #     sys.stdin.read()
    # except KeyboardInterrupt:
    #     pass
    # finally:
    #     print("\n→ 卸载脚本并 detach")
    #     try:
    #         script.unload()
    #         session.detach()
    #     except Exception:
    #         pass


def main():
    parser = argparse.ArgumentParser(description="启动 frida-server 并可选 spawn + 注入 ./dist/index.js")
    parser.add_argument("package", nargs="?", help="要 spawn 的应用包名(可选)")
    parser.add_argument("-s", "--script", default="dist/index.js", help="注入脚本路径(默认: ./dist/index.js)")
    args = parser.parse_args()

    print("=" * 50)
    print("  Frida Server 自动启动脚本")
    print("=" * 50)
    check_adb_device()
    arch = detect_arch()
    version = detect_frida_version()
    local_bin = ensure_local_binary(version, arch)
    push_and_start(local_bin)

    if args.package:
        # frida-server 启动后稍等片刻再连接
        time.sleep(1)
        spawn_and_inject(args.package, args.script)
    else:
        print("\n现在可以使用: frida-ps -U")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已中断")
    except Exception as e:
        sys.exit(f"✗ 错误: {e}")