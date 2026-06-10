import argparse
import os
import sys
import struct
import threading
from pathlib import Path
import re
import frida
import xdialog

if sys.platform == "win32":
    import winreg

sys.stdout.reconfigure(line_buffering=True)

def find_game_exe():
    if sys.platform == "win32":
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam")
        steam_path = winreg.QueryValueEx(key, "SteamPath")[0]
        winreg.CloseKey(key)

        vdf = os.path.join(steam_path, "steamapps", "libraryfolders.vdf")
        with open(vdf, encoding="utf-8") as f:
            content = f.read()

        for path in re.findall(r'"path"\s+"(.+?)"', content):
            target = os.path.join(path.replace("\\\\", "\\"), "steamapps", "common", "DeathRoadToCanada","prog.exe")
            return target
    if sys.platform == "linux":
        return "~/.steam/steam/steamapps/common/DeathRoadToCanada/prog-linux"
    elif sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/Steam/steamapps/common/DeathRoadToCanada/DR2C.app/Contents/MacOS/DR2C")
    return None

def on_message(message, data):
    # global window
    # global progress
    if message["type"] == "send":
        payload = message["payload"]

        if payload["type"]=="mkdir":
            os.makedirs(payload["data"]["path"], exist_ok=True)
            script.post({
                "type": "mkdir",
                "success": True
            })
        elif payload["type"]=="filedialog":
            result = xdialog.open_file("选择文件", filetypes=[("Zip", "*.zip")], multiple=False)
            
            script.post({
                "type": "filedialog",
                "success": True,
                "result": result
            })
        else:
            print("[agent]", payload)

    elif message["type"] == "error":
        print("[error]", message["stack"])
    else:
        print("[msg]", message)


def main():
    parser = argparse.ArgumentParser(description="启动 frida-server 并可选 spawn + 注入 main.js")
    parser.add_argument("-t", "--target", help="注入的对象exe")
    parser.add_argument("-s", "--script", default="./dist/main.js", help="注入脚本路径(默认: ./dist/main.js)")
    args = parser.parse_args()

    if not args.target:
        gameexe = find_game_exe()
        if not gameexe:
            raise Exception("Fail to find game directory")
        args.target = gameexe

    with open(args.script, "r", encoding="utf-8") as f:
        agent_source = f.read()

    # 原生 Windows：直接使用本地设备，无需 frida-server
    device = frida.get_local_device()
    print(f"[*] 已连接: {device}")
    print(f"[*] script: {args.script}")

    print(f"[*] spawn {args.target} ...")
    pid = device.spawn(os.path.expanduser(args.target), cwd=os.path.dirname(os.path.expanduser(args.target)))
    print(f"[*] PID = {pid}（已暂停）")

    session = device.attach(pid)
    exited = threading.Event()

    def on_detached(reason):
        print(f"[!] session detached: {reason}")
        exited.set()

    session.on("detached", on_detached)
    print(f"[*] attach 成功")

    global script
    script = session.create_script(agent_source, name=Path(args.script).stem)
    script.on("message", on_message)
    script.load()
    print("[*] agent 已注入")

    print("[*] agent 初始化完成")

    device.resume(pid)
    print("[*] 进程已 resume\n")

    try:
        exited.wait()
    except KeyboardInterrupt:
        print("\n[*] 退出")
        session.detach()


if __name__ == "__main__":
    main()
