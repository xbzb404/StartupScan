# -*- coding: utf-8 -*-
"""管理员权限：检测、UAC 提权重启。  ·  by zhb

为什么要单独成模块：
  * 主程序（main.py）启动时要提权，界面上「受限模式」徽标也要能再次提权，
    两处逻辑必须一致，不能各写一份；
  * 提权重启的坑集中在三处，写在这里一次说清：

    1. **必须用 ShellExecuteW("runas")**，不能用 ``subprocess`` ——
       CreateProcess 不会触发 UAC，只会继承当前（非提升）令牌，看起来
       「重启了」但仍然是受限模式，形成无限循环。
    2. **必须传环境变量哨兵**（``STARTUPSCAN_ELEV_RETRY``）—— 用户点了
       UAC 的「否」时，ShellExecuteW 返回 <= 32，子进程根本没启动；
       但若用户允许后又因为别的原因没提升成功，没有哨兵会反复弹 UAC。
    3. **打包版要在 exe 清单里声明 requireAdministrator**（build_exe.py
       的 ``--uac-admin``）—— 这样 Windows 在启动瞬间就弹 UAC，不会出现
       「先以普通权限启动、再自我重启」的窗口闪烁。

用法::

    from .elevate import is_admin, ensure_admin, relaunch_as_admin
    state = ensure_admin()      # "admin" / "relaunching" / "restricted"
"""

import ctypes
import os
import subprocess
import sys

RETRY_ENV = "STARTUPSCAN_ELEV_RETRY"


def is_admin():
    """当前进程是否拥有管理员令牌。"""
    if os.name != "nt":
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:                                       # noqa: BLE001
        return False


def relaunch_as_admin(argv=None):
    """以管理员身份重新启动本程序。成功派生出进程返回 True。

    argv 传入完整参数列表（含程序名）；默认取 ``sys.argv``。
    """
    if os.name != "nt":
        return False
    argv = list(sys.argv if argv is None else argv)
    if not argv:
        return False
    exe = sys.executable
    if getattr(sys, "frozen", False):
        # 打包版：sys.executable 就是 exe 自己，参数直接透传
        args = argv[1:]
    else:
        # 源码版：sys.executable 是 python.exe，第一段要换成脚本绝对路径
        args = [os.path.abspath(argv[0])] + argv[1:]
    params = subprocess.list2cmdline(args)
    os.environ[RETRY_ENV] = "1"
    try:
        shell = ctypes.windll.shell32
        func = shell.ShellExecuteW
        func.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                         ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
        func.restype = ctypes.c_int
        rc = func(None, "runas", exe, params, None, 1)
        return int(rc) > 32
    except Exception:                                       # noqa: BLE001
        return False


def ensure_admin():
    """确保以管理员身份运行。

    返回：
        ``"admin"``       已经是管理员
        ``"relaunching"`` 已派生提权进程，调用方应立即退出自己
        ``"restricted"``  用户拒绝 / 无法提权，以受限模式继续
    """
    if os.name != "nt" or is_admin():
        return "admin"
    if os.environ.get(RETRY_ENV):
        return "restricted"
    if relaunch_as_admin():
        return "relaunching"
    return "restricted"


def warn(msg):
    """向控制台告警；**windowed 打包后 sys.stderr 为 None**，直接写会崩。"""
    try:
        if sys.stderr is not None:
            sys.stderr.write(msg + "\n")
            sys.stderr.flush()
    except Exception:                                       # noqa: BLE001
        pass
