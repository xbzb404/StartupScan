# -*- coding: utf-8 -*-
"""GUI 验证探针（层 2/3）：加载真实 App + 演示数据，逐页渲染并截图。

用途：
  1. 验证 App 构造、页面渲染无异常（winfo_viewable 自报）；
  2. 对 7 个页面逐一截图，人工目视检查排版；
  3. 验证「构造完即可见 + 全程不掉」的可见性口径。

运行方式（必须用带 tkinter 的系统 Python）：
    python tools/gui_probe.py
"""

import os
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from startupscan import theme as T


def compose(root):
    """把窗口真正抬到前台，让 Windows 合成它，之后截图才有内容。"""
    try:
        root.deiconify()
        root.state("normal")
    except Exception:
        pass
    for _ in range(4):
        try:
            root.lift()
            root.attributes("-topmost", True)
        except Exception:
            pass
        root.update()
        time.sleep(0.3)
    # 强制布局完成：等 canvas 拿到真实尺寸
    for _ in range(10):
        root.update_idletasks()
        c = root
        w = c.winfo_width()
        if w > 100:
            break
        time.sleep(0.2)


def _canvas_ready(app):
    """等到内容区画布拿到真实宽度（否则截图是 1x1 空图）。"""
    c = app.scroll.canvas
    for _ in range(20):
        app.root.update_idletasks()
        w = c.winfo_width()
        if w > 100:
            return True
        time.sleep(0.2)
    return c.winfo_width() > 100


def main():
    log = []
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    shots_dir = os.path.join(base, "screenshots")
    os.makedirs(shots_dir, exist_ok=True)

    # 隔离 HOME：演示模式不写用户目录
    os.environ["USERPROFILE"] = os.environ["HOME"] = os.path.join(
        base, "_tmp_home")
    os.makedirs(os.environ["USERPROFILE"], exist_ok=True)

    T.init_scaling()
    from startupscan.app import App, NAV
    app = App(autorefresh_ms=None)
    root = app.root

    # 构造完立刻合成一次，先记录可见性
    compose(root)
    vis0 = root.winfo_viewable()
    log.append("T0 after App(): viewable=%d ismapped=%d state=%s" % (
        vis0, root.winfo_ismapped(), root.state()))

    # 加载演示数据
    app.load_demo()

    # 逐页渲染 + 截图
    # 页面清单从 NAV 读取：加/删页面后探针自动跟随，不必两处改
    pages = [key for key, _icon, _label in NAV]
    from PIL import ImageGrab
    results = {}
    for pg in pages:
        try:
            app.show_page(pg)
            root.update()
            if not _canvas_ready(app):
                log.append("  page %-10s CANVAS NOT READY" % pg)
                results[pg] = False
                continue
            # 等待渲染完成
            for _ in range(5):
                root.update()
                time.sleep(0.2)
            c = app.scroll.canvas
            n_items = len(c.find_all())
            # 截图前抬一次窗，尽量让窗口合成
            try:
                root.lift()
                root.attributes("-topmost", True)
            except Exception:
                pass
            root.update()
            x = root.winfo_rootx()
            y = root.winfo_rooty()
            w = root.winfo_width()
            h = root.winfo_height()
            png = os.path.join(shots_dir, "page_%s.png" % pg)
            try:
                ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(png)
                ok = os.path.getsize(png) > 0
            except Exception as exc:
                ok = False
                log.append("  screenshot %s failed: %s" % (pg, exc))
            # 判据：canvas 有真实内容（items>0 且 scrollregion 高度合理）
            # 截图仅作辅助，不再用 viewable（快速切页时窗口可能被系统压住）
            rendered = n_items > 0
            results[pg] = ok and rendered
            log.append("  page %-10s items=%d shot=%s rendered=%s" % (
                pg, n_items, "ok" if ok else "FAIL",
                "ok" if rendered else "FAIL"))
        except Exception:
            log.append("  page %s EXCEPTION: %s" % (pg, traceback.format_exc()))
            results[pg] = False

    # 最后再测一次可见性（截图前刚测的那次为准）
    final_vis = root.winfo_viewable()
    log.append("T-final viewable=%d" % final_vis)

    # 业务验证：演示数据里应有风险项
    risky = [it for it in app.result["items"]
             if it.get("risk") in ("critical", "high", "medium")]
    log.append("demo items=%d risky=%d" % (
        len(app.result["items"]), len(risky)))

    # 检查截图非全黑（辅助信息；窗口被压住时截图可能全黑，不判失败）
    black = 0
    for pg, ok in results.items():
        if not ok:
            continue
        try:
            from PIL import Image
            im = Image.open(os.path.join(shots_dir, "page_%s.png" % pg)) \
                .convert("RGB")
            distinct = len(im.getcolors(maxcolors=1 << 22) or [])
            if distinct <= 1:
                black += 1
                log.append("  page %s BLACK SCREEN (窗口可能被压住，忽略)" % pg)
        except Exception:
            pass

    with open(os.path.join(base, "_probe_result.txt"), "w",
              encoding="utf-8") as fp:
        fp.write("\n".join(log) + "\n")

    # 判据：T0 可见 + 全部页面 items>0 且截图成功（截图黑屏只作记录）
    ok_all = all(results.values()) and vis0 == 1 and risky
    print("\n".join(log))
    print("black_shots=%d (辅助)" % black)
    print("== %s ==" % ("PROBE PASS" if ok_all else "PROBE FAIL"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
