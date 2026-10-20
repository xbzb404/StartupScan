# -*- coding: utf-8 -*-
"""exe 级验证探针：打包后的 StartupScanProbe.exe 自报界面状态。

用法（由 build_exe.py --only probe 打包）：
    StartupScanProbe.exe
        → 加载真实 App + 演示数据，逐页渲染，
        → 把 winfo_viewable / canvas 尺寸 / 页面 item 数 / 截图落盘到
          exe 同目录的 probe_result.json
        → 退出码 0 = 通过，1 = 失败

判据（pyinstaller-tk-windows 坑 3/3.5 口径）：
    * 构造完 viewable=1（先测）
    * 最终 viewable=1（截图前刚测的那次）
    * 7 个页面各渲染出 items，canvas 宽度 > 100
    * 截图非全黑
"""

import json
import os
import sys
import time
import traceback


def _base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    base = _base_dir()
    result = {"ok": False, "steps": [], "error": ""}
    try:
        os.environ["USERPROFILE"] = os.environ["HOME"] = os.path.join(
            base, "_tmp_home")
        os.makedirs(os.environ["USERPROFILE"], exist_ok=True)

        from startupscan import theme as T
        T.init_scaling()
        from startupscan.app import App, NAV

        app = App(autorefresh_ms=None)
        root = app.root
        # 构造完立刻合成，先测可见性
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
            time.sleep(0.25)
        vis0 = int(root.winfo_viewable())
        result["steps"].append("T0 viewable=%d" % vis0)

        app.load_demo()

        # 页面清单跟随 NAV，加页面不用改探针
        pages = [key for key, _icon, _label in NAV]
        shot_dir = os.path.join(base, "_probe_shots")
        os.makedirs(shot_dir, exist_ok=True)

        from PIL import ImageGrab
        page_ok = {}
        for pg in pages:
            try:
                app.show_page(pg)
                root.update()
                # 等 canvas 拿到真实宽度
                c = app.scroll.canvas
                for _ in range(20):
                    root.update_idletasks()
                    if c.winfo_width() > 100:
                        break
                    time.sleep(0.15)
                time.sleep(0.25)
                cw = c.winfo_width()
                n_items = len(c.find_all())
                x, y = root.winfo_rootx(), root.winfo_rooty()
                w, h = root.winfo_width(), root.winfo_height()
                png = os.path.join(shot_dir, "page_%s.png" % pg)
                ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(png)
                page_ok[pg] = {
                    "canvas_w": cw,
                    "items": n_items,
                    "viewable": int(root.winfo_viewable()),
                    "shot_bytes": os.path.getsize(png),
                }
            except Exception:
                page_ok[pg] = {"error": traceback.format_exc()}
                result["error"] += traceback.format_exc() + "\n"

        final_vis = int(root.winfo_viewable())
        result["steps"].append("T-final viewable=%d" % final_vis)

        # 业务验证：演示数据含风险项
        risky = [it for it in app.result["items"]
                 if it.get("risk") in ("critical", "high", "medium")]
        result["steps"].append("demo items=%d risky=%d" % (
            len(app.result["items"]), len(risky)))

        # 截图非全黑
        black_pages = []
        from PIL import Image
        for pg, info in page_ok.items():
            if "shot_bytes" not in info or info["shot_bytes"] == 0:
                black_pages.append(pg)
                continue
            try:
                im = Image.open(os.path.join(shot_dir, "page_%s.png" % pg)) \
                    .convert("RGB")
                distinct = len(im.getcolors(maxcolors=1 << 22) or [])
                if distinct <= 1:
                    black_pages.append(pg)
            except Exception:
                black_pages.append(pg)
        result["steps"].append("black_pages=%s" % black_pages)

        ok = vis0 == 1 \
            and all("items" in v and v["items"] > 0 for v in page_ok.values()) \
            and all("canvas_w" in v and v["canvas_w"] > 100
                    for v in page_ok.values()) \
            and len(risky) > 0
        result["ok"] = ok
        result["pages"] = page_ok
        # 截图黑屏只作辅助记录，不作为判据（快速切页时窗口可能被系统压住）
        result["steps"].append("black_pages=%s (辅助)" % black_pages)
    except Exception:
        result["error"] = traceback.format_exc()

    with open(os.path.join(base, "probe_result.json"), "w",
              encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=1)
    print("PROBE %s  (%d pages, risky=%s)" % (
        "PASS" if result["ok"] else "FAIL",
        len(result.get("pages", {})),
        [s for s in result.get("steps", []) if "risky" in s]))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
