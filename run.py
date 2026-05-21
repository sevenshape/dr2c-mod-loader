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

import frida

sys.stdout.reconfigure(line_buffering=True)


# ── ELF 符号表解析 (支持 ELF32/ELF64, 大小端) ─────────────────────────────
def parse_elf_symbols(elf_path):
    with open(elf_path, "rb") as f:
        data = f.read()

    if data[:4] != b"\x7fELF":
        raise ValueError("不是 ELF 文件")

    ei_class = data[4]            # 1=ELF32, 2=ELF64
    ei_data  = data[5]            # 1=小端,  2=大端
    endian   = "<" if ei_data == 1 else ">"
    is_64    = (ei_class == 2)

    # ── ELF Header ────────────────────────────────────────────────────
    if is_64:
        eh_fmt = endian + "HHIQQQIHHHHHH"
        sym_entry_size = 24
        # st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
        sym_fmt = endian + "IBBHQQ"
        # sh_name(4), sh_type(4), sh_flags(8), sh_addr(8), sh_offset(8),
        # sh_size(8), sh_link(4), sh_info(4), sh_addralign(8), sh_entsize(8)
        sh_fmt = endian + "IIQQQQIIQQ"
    else:
        eh_fmt = endian + "HHIIIIIHHHHHH"
        sym_entry_size = 16
        # st_name(4), st_value(4), st_size(4), st_info(1), st_other(1), st_shndx(2)
        sym_fmt = endian + "IIIBBH"
        sh_fmt  = endian + "IIIIIIIIII"

    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum,
     e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(eh_fmt, data, 16)

    # ── Section Headers ───────────────────────────────────────────────
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        vals = struct.unpack_from(sh_fmt, data, off)
        sections.append({
            "name_off": vals[0],
            "type":     vals[1],
            "addr":     vals[3],
            "offset":   vals[4],
            "size":     vals[5],
            "link":     vals[6],
            "entsize":  vals[9],
        })

    # 解析 section 名称（位于 .shstrtab）
    if 0 <= e_shstrndx < len(sections):
        shstr_off = sections[e_shstrndx]["offset"]
        for sec in sections:
            try:
                a = shstr_off + sec["name_off"]
                end = data.index(b"\x00", a)
                sec["name"] = data[a:end].decode("ascii", errors="replace")
            except Exception:
                sec["name"] = ""

    SHT_SYMTAB = 2
    SHT_DYNSYM = 11
    SHN_UNDEF  = 0

    symbols = {}

    # 同时处理 .symtab (静态) 和 .dynsym (动态)。
    # 若 .so 被 strip，.symtab 会缺失，.dynsym 一定存在。
    for sec in sections:
        if sec["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if sec["link"] >= len(sections):
            continue

        strtab_off = sections[sec["link"]]["offset"]
        ent_size   = sec["entsize"] or sym_entry_size
        num_syms   = sec["size"] // ent_size
        base_off   = sec["offset"]

        for i in range(num_syms):
            try:
                sym_off = base_off + i * ent_size
                vals = struct.unpack_from(sym_fmt, data, sym_off)
                if is_64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = vals
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = vals

                if st_name == 0 or st_shndx == SHN_UNDEF or st_value == 0:
                    continue

                a = strtab_off + st_name
                if a >= len(data):
                    raise ValueError(f"st_name {st_name} 超出文件范围")
                end = data.index(b"\x00", a)
                name = data[a:end].decode("ascii", errors="replace")
                if not name:
                    continue

                symbols[name] = st_value

            except ValueError as e:
                print(f"[WARN] ELF 符号 #{i} 名称解析失败: {e}，已跳过")
            except struct.error as e:
                print(f"[WARN] ELF 符号 #{i} 结构解析失败: {e}，已跳过")
            except Exception as e:
                print(f"[WARN] ELF 符号 #{i} 未知错误: {e}，已跳过")

    return symbols


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

    
    parser = argparse.ArgumentParser(description="启动 frida-server 并可选 spawn + 注入 index.js")
    parser.add_argument("-t", "--target", default=r"D:\dr2c\2024\prog.exe", help="注入的对象exe")
    parser.add_argument("-s", "--script", default="./dist/index.js", help="注入脚本路径(默认: ./dist/index.js)")
    args = parser.parse_args()

    with open(args.script, "r", encoding="utf-8") as f:
        agent_source = f.read()

    # 原生 Windows：直接使用本地设备，无需 frida-server
    device = frida.get_local_device()
    print(f"[*] 已连接: {device}")
    print(f"[*] script: {args.script}")

    # copy_game_data()

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
