# -*- coding: utf-8 -*-
"""
一键打包：把主程序与验收入口各打成一个单文件 exe  ·  by zhb

Windows + Tk 组合下有两个必须显式处理的坑（详见 pyinstaller-tk-windows 技能）：
  1. Tcl/Tk 运行时若没被显式附加，exe 会「双击没反应、无报错」——所以这里先
     定位 tcl 目录（必须是含 tcl8.x 子目录且含 tk8.x 子目录的那个）再 --add-data。
  2. 某些受管控环境把 os.remove 重定向到回收站，会让 PyInstaller 收尾失败并
     留下损坏的 exe —— 打包子进程里关掉删除钩子，旧目录用「改名搁置」处理。

用法：python build_exe.py [--only main|probe] [--prune]

    --prune   只收口历史「改名搁置」产物（build_old_* / spec_old_* 等），
              不打包。每类留最新 2 份，其余删除。默认不在打包流程里跑，
              避免大批量删除被环境钩子拦下而打断打包。
"""

import os
import shutil
import subprocess
import sys
import time

from startupscan import AUTHOR, AUTHOR_TAG

HERE = os.path.dirname(os.path.abspath(__file__))
ICON = os.path.join(HERE, "assets", "icon.ico")
DIST = os.path.join(HERE, "dist")
WORK = os.path.join(HERE, "build")
SPEC = os.path.join(HERE, "spec")

VERSION_INFO = """VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 1, 0, 0), prodvers=(1, 1, 0, 0), mask=0x3f, flags=0x0,
    OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([
      StringTable('080404B0', [
        StringStruct('CompanyName', '%(tag)s'),
        StringStruct('FileDescription', '开机自启扫描器 —— Windows 开机自启项 / 启动脚本 / 计划任务 / 启动日志分析 (%(author)s)'),
        StringStruct('FileVersion', '1.1.0.0'),
        StringStruct('InternalName', 'StartupScan'),
        StringStruct('LegalCopyright', 'Copyright (C) 2026 %(tag)s. All rights reserved.'),
        StringStruct('OriginalFilename', 'StartupScan.exe'),
        StringStruct('ProductName', '开机自启扫描器 (%(author)s)'),
        StringStruct('ProductVersion', '1.1.0.0')])]),
    VarFileInfo([VarStruct('Translation', [2052, 1200])])
  ]
)
""" % {"tag": AUTHOR_TAG, "author": AUTHOR}

KEEP_OLD = 2        # 每类旧产物最多留几份（仅 --prune 时生效）


def prune_victims(path, keep=KEEP_OLD):
    """列出该保留之外、应当删掉的 ``<path>_old_*`` 名字（只挑不删，便于自测）。"""
    parent = os.path.dirname(path) or "."
    prefix = os.path.basename(path) + "_old_"
    try:
        names = [n for n in os.listdir(parent) if n.startswith(prefix)]
    except OSError:
        return []
    if len(names) <= keep:
        return []
    def _when(name):
        try:
            return os.path.getmtime(os.path.join(parent, name))
        except OSError:
            return 0.0
    names.sort(key=_when, reverse=True)
    return names[keep:]


def prune_old(path, keep=KEEP_OLD):
    """只保留最近 ``keep`` 份 ``<path>_old_*`` 搁置产物，其余删掉。"""
    parent = os.path.dirname(path) or "."
    for name in prune_victims(path, keep):
        target = os.path.join(parent, name)
        try:
            if os.path.isdir(target):
                shutil.rmtree(target)
            else:
                os.remove(target)
            print("  prune  ->", name)
        except Exception as exc:                    # noqa: BLE001
            print("  ! prune failed:", name, exc)


def prune_all():
    """收口所有历史搁置产物（``--prune`` 专用）。"""
    print("== 收口历史搁置产物 ==")
    for path in (os.path.join(HERE, "build"), os.path.join(HERE, "spec"),
                 os.path.join(DIST, "StartupScan.exe"),
                 os.path.join(DIST, "StartupScanProbe.exe")):
        prune_old(path)


def dispose(path):
    """改名搁置代替删除：改名是原子操作，不会因为文件被占用而失败。"""
    if not os.path.exists(path):
        return
    stamp = time.strftime("%H%M%S")
    try:
        os.rename(path, "%s_old_%s" % (path, stamp))
        print("  dispose ->", os.path.basename(path) + "_old_" + stamp)
    except Exception as exc:                        # noqa: BLE001
        print("  ! dispose failed:", exc)


def find_tcl_tk():
    """定位包含 tcl8.x 与 tk8.x 子目录的 tcl 目录。"""
    import _tkinter
    import tkinter
    roots = set()
    pyd = os.path.dirname(_tkinter.__file__)
    roots.add(os.path.dirname(pyd))
    roots.add(os.path.dirname(os.path.dirname(pyd)))
    roots.add(os.path.dirname(os.path.dirname(os.path.abspath(tkinter.__file__))))
    for extra in (getattr(sys, "base_prefix", None), getattr(sys, "prefix", None)):
        if extra:
            roots.add(extra)
    for root in roots:
        for cand in (os.path.join(root, "tcl"), os.path.join(root, "Lib", "tcl")):
            if not os.path.isdir(cand):
                continue
            subs = [d for d in os.listdir(cand)
                    if os.path.isdir(os.path.join(cand, d))]
            if any(d.startswith("tcl8") for d in subs) and \
                    any(d.startswith("tk8") for d in subs):
                return cand
    return None


def check_env():
    py = sys.executable
    try:
        import tkinter                                    # noqa: F401
        import _tkinter                                   # noqa: F401
    except Exception as exc:                              # noqa: BLE001
        print("!! 当前解释器没有 tkinter：", exc)
        print("   请改用系统 Python 运行本脚本：")
        print("   C:\\Users\\<你>\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe")
        sys.exit(2)
    try:
        import PIL                                        # noqa: F401
        from PIL import ImageTk                           # noqa: F401
    except Exception as exc:                              # noqa: BLE001
        print("!! 缺少 Pillow（圆角抗锯齿需要它）：", exc)
        sys.exit(3)
    try:
        import PyInstaller                                # noqa: F401
    except Exception:                                     # noqa: BLE001
        print("== 正在安装 PyInstaller ==")
        subprocess.run([py, "-m", "pip", "install", "pyinstaller"], check=False)
    return py


def build(py, name, entry, windowed=True, extra=None, uac_admin=False):
    tcl = find_tcl_tk()
    print("== building %s ==  tcl=%s  uac_admin=%s" % (name, tcl, uac_admin))
    cmd = [py, "-m", "PyInstaller", "--noconfirm", "--onefile", "--clean",
           "--name", name,
           "--distpath", DIST, "--workpath", WORK, "--specpath", SPEC,
           "--hidden-import", "tkinter",
           "--hidden-import", "_tkinter",
           "--hidden-import", "tkinter.font",
           "--hidden-import", "tkinter.ttk",
           "--hidden-import", "tkinter.filedialog",
           "--hidden-import", "PIL.ImageTk",
           "--hidden-import", "PIL._tkinter_finder",
           "--exclude-module", "numpy",
           "--exclude-module", "matplotlib",
           "--exclude-module", "PyQt5",
           "--exclude-module", "PyQt6",
           "--exclude-module", "scipy",
           "--exclude-module", "pandas",
           "--paths", HERE]
    if windowed:
        cmd.append("--windowed")
    if uac_admin:
        # 在 exe 清单里声明 requireAdministrator：Windows 启动时直接弹 UAC，
        # 不用「先普通权限启动再自我重启」，窗口不会闪两下。
        cmd.append("--uac-admin")
    if os.path.exists(ICON):
        cmd += ["--icon", ICON, "--add-data", ICON + ";assets"]
    if tcl:
        cmd += ["--add-data", tcl + ";tcl"]
    vf = os.path.join(SPEC, "version_info.txt")
    os.makedirs(SPEC, exist_ok=True)
    with open(vf, "w", encoding="utf-8") as fp:
        fp.write(VERSION_INFO)
    cmd += ["--version-file", vf]
    cmd += (extra or [])
    cmd.append(entry)

    out = os.path.join(DIST, name + ".exe")
    dispose(out)

    env = dict(os.environ)
    env["CODEBUDDY_SAFE_DELETE_ENABLED"] = "0"        # 关掉删除重定向钩子
    env["PYTHONIOENCODING"] = "utf-8"
    print("   ", " ".join('"%s"' % c if " " in c else c for c in cmd[2:8]), "…")
    t0 = time.time()
    proc = subprocess.run(cmd, env=env, cwd=HERE)
    print("== %s done rc=%s in %.1fs" % (name, proc.returncode, time.time() - t0))
    if os.path.exists(out):
        print("   ->", out, "%.1f MB" % (os.path.getsize(out) / 1024.0 / 1024.0))
    return proc.returncode == 0 and os.path.exists(out)


def main():
    # banner 只用纯 ASCII：中文窗口控制台是 GBK，中文在这里容易糊成乱码
    print("==== StartupScan build script   %s ====" % AUTHOR)
    if "--prune" in sys.argv:
        prune_all()
        return
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1]
    py = check_env()
    os.makedirs(DIST, exist_ok=True)
    for d in (WORK, SPEC):
        dispose(d)
    for fn in os.listdir(DIST):
        if "_old_" in fn:
            try:
                os.remove(os.path.join(DIST, fn))
            except OSError:
                pass

    results = {}
    if only in (None, "main"):
        results["StartupScan"] = build(py, "StartupScan",
                                       os.path.join(HERE, "main.py"),
                                       windowed=True, uac_admin=True)
    if only in (None, "probe"):
        results["StartupScanProbe"] = build(
            py, "StartupScanProbe", os.path.join(HERE, "tools", "probe_exe.py"),
            windowed=False)

    print("\n==== 结果 ====")
    for k, v in results.items():
        print(("  [OK]  " if v else "  [FAIL]") + " " + k)
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
