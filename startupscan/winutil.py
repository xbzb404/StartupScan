# -*- coding: utf-8 -*-
"""Windows 子进程调用工具：统一避免弹出黑色控制台窗口。

背景：主程序用 PyInstaller ``--windowed`` 打包（本身没有控制台），但每次
``subprocess`` 调 ``wevtutil`` / ``schtasks`` / ``wmic`` 这类 console 程序时，
Windows 会**新建一个控制台窗口**，用户看到的就是「扫描时黑窗一闪一闪」。
加 ``CREATE_NO_WINDOW`` 后子进程在隐藏控制台里跑，界面干净。

用法::

    from .winutil import run_hidden
    proc = run_hidden(["wevtutil", "qe", ...], capture_output=True, timeout=45)
"""

import subprocess
import sys

# CreateProcess 的 creationflags：不创建控制台窗口
CREATE_NO_WINDOW = 0x08000000


def run_hidden(cmd, **kw):
    """静默执行子进程（不弹窗），参数与 ``subprocess.run`` 完全一致。"""
    if sys.platform.startswith("win"):
        kw.setdefault("creationflags", CREATE_NO_WINDOW)
    # 不继承父进程 stdin：windowed 进程下 stdin 无效，某些命令会卡住等输入
    kw.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)


def popen_hidden(cmd, **kw):
    """静默启动子进程（不弹窗），参数与 ``subprocess.Popen`` 一致。"""
    if sys.platform.startswith("win"):
        kw.setdefault("creationflags", CREATE_NO_WINDOW)
        kw.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.Popen(cmd, **kw)
