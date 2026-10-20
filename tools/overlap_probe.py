# -*- coding: utf-8 -*-
"""UI 重叠检测：渲染每页后，取所有 text item 的 bbox，两两求交。

不依赖截图，也不依赖肉眼：Tk 自己知道每个 item 的精确包围盒。
输出「重叠且重叠面积占比 > 阈值」的文本对，便于定位排版 bug。
"""
import os
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.environ["USERPROFILE"] = os.environ["HOME"] = os.path.join(BASE, "_tmp_home")
os.makedirs(os.environ["USERPROFILE"], exist_ok=True)

from startupscan import theme as T  # noqa: E402

T.init_scaling()
from startupscan.app import App, NAV  # noqa: E402


def inter(a, b):
    x1 = max(a[0], b[0])
    y1 = max(a[1], b[1])
    x2 = min(a[2], b[2])
    y2 = min(a[3], b[3])
    if x2 <= x1 or y2 <= y1:
        return 0
    return (x2 - x1) * (y2 - y1)


def area(a):
    return max(0, a[2] - a[0]) * max(0, a[3] - a[1])


def main():
    app = App(autorefresh_ms=None)
    root = app.root
    root.deiconify()
    root.state("normal")
    for _ in range(3):
        root.lift()
        root.attributes("-topmost", True)
        root.update()
        time.sleep(0.2)
    app.load_demo()

    c = app.scroll.canvas
    total = 0
    for key, _icon, label in NAV:
        app.show_page(key)
        for _ in range(6):
            root.update()
            time.sleep(0.08)
        items = [it for it in c.find_all()
                 if c.type(it) == "text"]
        boxes = []
        for it in items:
            txt = c.itemcget(it, "text").replace("\n", " ")[:34]
            bb = c.bbox(it)
            if bb and txt.strip():
                boxes.append((bb, txt, it))
        hits = []
        for i in range(len(boxes)):
            for j in range(i + 1, len(boxes)):
                a, ta, ia = boxes[i]
                b, tb, ib = boxes[j]
                ov = inter(a, b)
                if not ov:
                    continue
                # 重叠占较小者面积的比例
                ratio = ov / max(1.0, min(area(a), area(b)))
                if ratio > 0.12:
                    hits.append((ratio, ta, tb, a, b))
        hits.sort(reverse=True)
        print("\n=== %-9s (%s)  text=%d  重叠对=%d" % (
            key, label, len(boxes), len(hits)))
        for ratio, ta, tb, a, b in hits[:12]:
            print("  %.0f%%  [%s] × [%s]" % (ratio * 100, ta, tb))
            print("        A=%s  B=%s" % (a, b))
        total += len(hits)

    print("\n总重叠对: %d" % total)
    root.destroy()
    return 0


if __name__ == "__main__":
    sys.exit(main())
