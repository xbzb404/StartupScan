# -*- coding: utf-8 -*-
"""
开机自启扫描器 —— 程序入口  ·  by zhb

用法：
    python main.py                 直接运行源码版（会自动请求管理员权限）
    python main.py --demo          演示模式（用合成数据渲染界面）
    双击 StartupScan.exe           运行打包版（exe 清单已声明 requireAdministrator）

关于管理员权限（两套机制，双保险）：
  1. **打包版**：build_exe.py 传 ``--uac-admin``，Windows 在 exe 启动瞬间
     就弹 UAC —— 不会出现「先普通权限启动、再自我重启」的闪烁；
  2. **源码版 / 兜底**：本文件调用 ``elevate.ensure_admin()``，用
     ShellExecuteW("runas") 重新拉起自己。用户点了「否」就降级为受限模式
     继续运行，读取计划任务历史日志、管理 HKLM 自启项等能力会受限，
     界面右上角会显示「受限模式 · 提权」。

作者：zhb
"""

import os
import sys


def _setup_paths():
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    if base not in sys.path:
        sys.path.insert(0, base)


def _banner():
    from startupscan import AUTHOR, __version__
    from startupscan.elevate import warn
    warn("开机自启扫描器 v%s · %s" % (__version__, AUTHOR))


def _write_diag(app):
    """``--diag``：把 DPI / 窗口尺寸落盘后退出，用于打包版排障。

    打包后的进程没有控制台，DPI 缩放、窗口尺寸这类「只在此环境出现」的
    问题很难靠肉眼判断；把 ``SCALE`` / ``system_dpi`` / 实际窗口尺寸写成
    JSON，和源码版对比就能定位（实测打包版与源码版曾出现 SCALE 不一致）。
    """
    import json
    from startupscan import elevate
    from startupscan import theme as T
    root = app.root
    for _ in range(30):
        root.update()
        if root.winfo_width() > 400:
            break
    root.update_idletasks()
    data = {
        "scale": T.SCALE,
        "dpi": T.system_dpi(),
        "admin": elevate.is_admin(),
        "screen": [root.winfo_screenwidth(), root.winfo_screenheight()],
        "window": [root.winfo_width(), root.winfo_height()],
        "canvas": [app.scroll.canvas.winfo_width(),
                   app.scroll.canvas.winfo_height()],
    }
    base = (os.path.dirname(sys.executable)
            if getattr(sys, "frozen", False) else os.getcwd())
    path = os.path.join(base, "diag.json")
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, ensure_ascii=False, indent=1)


def main():
    _setup_paths()
    from startupscan import elevate

    state = elevate.ensure_admin()
    if state == "relaunching":
        # 已派生出管理员进程，当前进程必须退出，否则会出现两个窗口
        return
    if state == "restricted":
        elevate.warn("警告：未获得管理员权限，计划日志与本机级自启项的管理功能受限。")
    _banner()

    try:
        import multiprocessing
        multiprocessing.freeze_support()
    except Exception:                                       # noqa: BLE001
        pass

    from startupscan import theme as T
    T.init_scaling()

    from startupscan.app import App
    demo = "--demo" in sys.argv
    app = App(autorefresh_ms=None if demo else 600)
    if demo:
        app.load_demo()
    if "--diag" in sys.argv:
        _write_diag(app)
        app.root.destroy()
        return
    app.run()


def _run():
    """打包成 --windowed 后没有控制台，异常必须自己落盘，否则无从排查。"""
    try:
        main()
    except Exception:
        import traceback
        try:
            base = (os.path.dirname(sys.executable)
                    if getattr(sys, "frozen", False)
                    else os.path.dirname(os.path.abspath(__file__)))
            with open(os.path.join(base, "StartupScan_error.log"), "w",
                      encoding="utf-8") as fp:
                fp.write(traceback.format_exc())
        except Exception:                                   # noqa: BLE001
            pass
        raise


if __name__ == "__main__":
    _run()
