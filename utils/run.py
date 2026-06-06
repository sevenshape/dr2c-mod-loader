#!/usr/bin/env python3
"""
frida-dr2c / run_win.py
直接 spawn prog.exe（暂停状态），attach + 注入 index.js，再 resume。
地址通过解析 PE 文件的 COFF 符号表获取。
原生 Windows 版本：使用 frida.get_local_device()，无需 frida-server。
"""

import argparse
import os
import sys
import struct
import threading
from pathlib import Path
import winreg
import re
import frida
import shutil
import filecmp

if sys.stdout is not None:
    sys.stdout.reconfigure(line_buffering=True)

def find_game_dir(game="DeathRoadToCanada"):
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam")
    steam_path = winreg.QueryValueEx(key, "SteamPath")[0]
    winreg.CloseKey(key)

    vdf = os.path.join(steam_path, "steamapps", "libraryfolders.vdf")
    with open(vdf, encoding="utf-8") as f:
        content = f.read()

    for path in re.findall(r'"path"\s+"(.+?)"', content):
        target = os.path.join(path.replace("\\\\", "\\"), "steamapps", "common", game)
        if os.path.isdir(target):
            return target
    return None

def files_equal(path1, path2):
    try:
        with open(path1, 'r', encoding='utf-8') as f1:
            with open(path2, 'r', encoding='utf-8') as f2:
                return f1.read() == f2.read()
    except FileNotFoundError:
        return False

def copy_resources_to(target_dir):
    """将打包的资源从临时目录拷贝到目标目录"""
    if getattr(sys, 'frozen', False):
        source_dir = os.path.join(sys._MEIPASS, 'dr2c-mod-loader')
    else:
        source_dir = os.path.abspath("./dist")

    d = os.path.join(target_dir, 'dr2c-mod-loader')

    if not files_equal(os.path.join(source_dir,'build_timestamp.txt'),os.path.join(d,'build_timestamp.txt')):
        shutil.copytree(source_dir, d, dirs_exist_ok=True)

# ── COFF 符号表解析 ──────────────────────────────────────────────────────────
def parse_coff_symbols(pe_path):
    with open(pe_path, "rb") as f:
        data = f.read()

    e_lfanew, = struct.unpack_from("<I", data, 0x3C)
    fh_off = e_lfanew + 4
    (machine, num_sections, _, ptr_symtab, num_syms,
     opt_size, _) = struct.unpack_from("<HHIIIHH", data, fh_off)

    oh_off = fh_off + 20
    image_base, = struct.unpack_from("<I", data, oh_off + 28)

    sh_off = oh_off + opt_size
    sections = []
    for i in range(num_sections):
        off = sh_off + i * 40
        name   = data[off:off+8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, off + 8)
        sections.append({"name": name, "va": va, "raw_off": raw_off})

    if not ptr_symtab or not num_syms:
        return {}

    str_table_off = ptr_symtab + num_syms * 18

    symbols = {}
    i = 0
    while i < num_syms:
        try:
            sym_off = ptr_symtab + i * 18
            raw_name = data[sym_off:sym_off+8]
            value,    = struct.unpack_from("<I", data, sym_off + 8)
            section_n,= struct.unpack_from("<h", data, sym_off + 12)
            storage   = data[sym_off + 16]
            aux_count = data[sym_off + 17]

            if raw_name[:4] == b"\x00\x00\x00\x00":
                str_off, = struct.unpack_from("<I", raw_name, 4)
                abs_off = str_table_off + str_off
                if abs_off >= len(data):
                    raise ValueError(f"str_off {str_off} 超出文件范围 (abs_off={abs_off}, file_size={len(data)})")
                end = data.index(b"\x00", abs_off)
                name = data[abs_off:end].decode("ascii", errors="replace")
            else:
                name = raw_name.rstrip(b"\x00").decode("ascii", errors="replace")

            if section_n >= 1 and section_n <= len(sections):
                sec = sections[section_n - 1]
                va  = image_base + sec["va"] + value
                symbols[name] = va

        except ValueError as e:
            print(f"[WARN] 符号 #{i} 名称解析失败: {e}")
            raise e
        except struct.error as e:
            print(f"[WARN] 符号 #{i} 结构解析失败: {e}")
            raise e
        except Exception as e:
            print(f"[WARN] 符号 #{i} 未知错误: {e}")
            raise e
        finally:
            i += 1 + (aux_count if 'aux_count' in dir() else 0)

    return symbols


def on_message(message, data):
    if message["type"] == "send":
        print("[agent]", message["payload"])
    elif message["type"] == "error":
        print("[error]", message["stack"])
        raise RuntimeError(f"[Frida Error] {message.get('description', '')}\n{message.get('stack', '')}")
    else:
        print("[msg]", message)


def main():
    # 解析 COFF 符号表，序列化为 JSON 注入 agent
    # print(f"[*] 解析 COFF 符号表: {TARGET_EXE}")
    # symbols = {}
    # try:
    #     symbols = parse_coff_symbols(TARGET_EXE)
    #     print(f"[*] 共解析 {len(symbols)} 个符号")
    #     symbols_json = json.dumps({k: hex(v) for k, v in symbols.items()})
    #     with open("_symbols.json", "w", encoding="utf-8") as f:
    #         f.write(symbols_json)
    # except Exception:
    #     with open('PANCREAS JUN-20-2024.10.25_symbols.json', 'r', encoding='utf-8') as file:
    #         symbols = json.load(file)
    #     print(f"[WARN] 解析COFF失败, 改为使用json读取共 {len(symbols)} 个符号")
    
    parser = argparse.ArgumentParser(description="启动 frida-server 并可选 spawn + 注入 main.js")
    parser.add_argument("-t", "--target", help="注入的对象exe")
    parser.add_argument("-s", "--script", default="./dist/main.js", help="注入脚本路径(默认: ./dist/main.js)")
    parser.add_argument("-i", "--inject", action='store_true', default=getattr(sys, 'frozen', False), help="将文件注入游戏目录并使用该目录下的脚本")
    args = parser.parse_args()

    if not args.target:
        if os.path.exists('prog.exe'): 
            args.target = '.\\prog.exe'
        else:
            gamedir = find_game_dir()
            if not gamedir:
                raise Exception("Fail to find game directory")
            args.target = gamedir+'\\prog.exe'
        print('[*] fill args.target',args.target)

    if args.inject:
        if os.path.exists('prog.exe'): 
            copy_resources_to('.\\')
            args.script = '.\\dr2c-mod-loader\\main.js'
            print('[*] inject','.\\','args.script',args.script)
        else:
            gamedir = find_game_dir()
            if not gamedir:
                raise Exception("Fail to find game directory")
            copy_resources_to(gamedir)
            args.script = gamedir+'\\dr2c-mod-loader\\main.js'
            print('[*] inject',gamedir,'args.script',args.script)

    with open(args.script, "r", encoding="utf-8") as f:
        agent_source = f.read()

    # 原生 Windows：直接使用本地设备，无需 frida-server
    device = frida.get_local_device()
    print(f"[*] 已连接: {device}")
    print(f"[*] script: {args.script}")

    print(f"[*] spawn {args.target} ...")
    pid = device.spawn(args.target, cwd=os.path.dirname(args.target))
    print(f"[*] PID = {pid}（已暂停）")

    session = device.attach(pid)
    exited = threading.Event()

    def on_detached(reason):
        print(f"[!] session detached: {reason}")
        exited.set()

    session.on("detached", on_detached)
    print(f"[*] attach 成功")

    script = session.create_script(agent_source,name=Path(args.script).stem)
    script.on("message", on_message)
    script.load()
    print("[*] agent 已注入")

    print("[*] agent 初始化完成")

    device.resume(pid)
    print("[*] 进程已 resume\n")

    try:
        while not exited.wait(0.5):
            pass
    except KeyboardInterrupt:
        print("\n[*] 退出")
        session.detach()


if __name__ == "__main__":
    main()
