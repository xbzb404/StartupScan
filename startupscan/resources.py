# -*- coding: utf-8 -*-
"""资源辅助：窗口图标（打包后从 sys._MEIPASS 取用）。"""

import os
import sys


def _resource_path(rel):
    """取打包资源路径：冻结版在 sys._MEIPASS，源码版在包目录。"""
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, rel)


def icon_path():
    """返回 assets/icon.ico 的实际路径（可能不存在）。"""
    p = _resource_path(os.path.join("assets", "icon.ico"))
    return p if os.path.isfile(p) else ""


def apply_window_icon(root):
    """给 Tk 窗口设置任务栏/标题栏图标；失败静默（不影响运行）。"""
    p = icon_path()
    if not p:
        return ""
    try:
        import tkinter as tk
        if isinstance(root, tk.Tk):
            from PIL import ImageTk, Image
            im = Image.open(p)
            photo = ImageTk.PhotoImage(im)
            # 引用必须挂在 root 上，防止被回收后图标消失
            root._app_icon = photo
            try:
                root.iconphoto(True, photo)
            except Exception:
                try:
                    root.iconbitmap(p)
                except Exception:
                    pass
        else:
            root.iconbitmap(p)
        return p
    except Exception:
        return ""
