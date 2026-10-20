# -*- coding: utf-8 -*-
"""窗口级截图（PrintWindow）：窗口被遮挡 / 最小化也能拿到内容。

为什么不用 ``ImageGrab.grab``：它抓的是**屏幕像素**。在本机跑无头会话
（窗口没有被真正合成到桌面）时，抓到的整张图是全黑的，看起来像 UI 崩了。
``PrintWindow(hwnd, hdc, PW_RENDERFULLCONTENT)`` 让窗口自己把内容画到
内存 DC，与窗口是否可见无关 —— 这才是 UI 排版的可靠验收手段。

用法：
    python tools/capture_window.py [输出目录]
"""

import ctypes
import os
import sys
import time
from ctypes import wintypes

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER),
                ("bmiColors", wintypes.DWORD * 3)]


user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32


def enable_dpi_awareness():
    """让**截图进程**感知 DPI。

    这一步是必须的，而且坑很隐蔽：截图脚本如果是 DPI-unaware，Windows 会把
    ``GetWindowRect`` 的返回值按缩放比**虚拟化**（150% 时 1770 宽只报 1180），
    我们按这个尺寸建位图再 PrintWindow，就只能拿到窗口左上角一块，
    看起来像「右边按钮丢了 / 界面被裁了」—— 实际程序完全正常。
    """
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)   # PER_MONITOR
        return True
    except Exception:                                    # noqa: BLE001
        try:
            user32.SetProcessDPIAware()
            return True
        except Exception:                                # noqa: BLE001
            return False


enable_dpi_awareness()


def capture_hwnd(hwnd, path):
    """把 hwnd 窗口内容存成 PNG，返回 (ok, 说明)。"""
    from PIL import Image

    rect = wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        return False, "GetWindowRect failed"
    w = rect.right - rect.left
    h = rect.bottom - rect.top
    if w <= 0 or h <= 0:
        return False, "窗口尺寸为 0"
    hdc = user32.GetWindowDC(hwnd)
    mdc = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    old = gdi32.SelectObject(mdc, bmp)
    try:
        # 2 = PW_RENDERFULLCONTENT（Win 8.1+，支持 DWM 合成内容）
        ok = user32.PrintWindow(hwnd, mdc, 2)
        if not ok:
            user32.PrintWindow(hwnd, mdc, 0)
        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = w
        bmi.bmiHeader.biHeight = -h            # 负数 = 自上而下
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = 0        # BI_RGB
        buf = ctypes.create_string_buffer(w * h * 4)
        got = gdi32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bmi), 0)
        if got == 0:
            return False, "GetDIBits failed"
        im = Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1)
        im.convert("RGB").save(path)
        return True, "%dx%d" % (w, h)
    finally:
        gdi32.SelectObject(mdc, old)
        gdi32.DeleteObject(bmp)
        gdi32.DeleteDC(mdc)
        user32.ReleaseDC(hwnd, hdc)


def main():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        base, "screenshots")
    os.makedirs(out_dir, exist_ok=True)
    os.environ["USERPROFILE"] = os.environ["HOME"] = os.path.join(
        base, "_tmp_home")
    os.environ.setdefault("STARTUPSCAN_DATA_DIR",
                          os.path.join(base, "_tmp_home", "StartupScan"))
    os.makedirs(os.environ["USERPROFILE"], exist_ok=True)

    from startupscan import theme as T
    T.init_scaling()
    from startupscan.app import App, NAV

    app = App(autorefresh_ms=None)
    root = app.root
    # 等窗口真正拿到尺寸再截图：App() 刚返回时 geometry 可能还没生效，
    # 直接 PrintWindow 会拿到一张 200 多像素的「半成品」图。
    for _ in range(40):
        root.update()
        if root.winfo_width() > 400 and root.winfo_height() > 300:
            break
        time.sleep(0.1)
    app.load_demo()
    hwnd = int(root.frame(), 16) if isinstance(root.frame(), str) \
        else int(root.frame())

    ok_all = True
    for key, _icon, label in NAV:
        app.show_page(key)
        for _ in range(6):
            root.update()
            time.sleep(0.08)
        path = os.path.join(out_dir, "page_%s.png" % key)
        ok, info = capture_hwnd(hwnd, path)
        print("  %-9s %-8s %s" % (key, "ok" if ok else "FAIL", info))
        ok_all = ok_all and ok
    root.destroy()
    print("== %s ==" % ("CAPTURE OK" if ok_all else "CAPTURE FAIL"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
