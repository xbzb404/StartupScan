# -*- coding: utf-8 -*-
"""层 3.5：卡片动作按钮的命中与分发验证。

前几层只验证「画出来了」，这一层验证「点下去真的对得上」：

  1. 用 ``Canvas.bbox`` 找到某个按钮（如「禁用」）的中心点；
  2. 用 ``action_at()`` 命中测试，确认拿到的是回调而不是 None；
  3. 把 ``messagebox`` 和 ``manage`` 的真实动作替换成桩，执行回调，
     确认最终落到正确的条目、正确的动作（不写注册表、不弹窗）。

这样可以在无人值守环境里覆盖「坐标 → 标签 → 回调 → 业务函数」整条链路，
而不需要真的点鼠标。

    python tools/ui_action_probe.py
"""

import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.environ["USERPROFILE"] = os.environ["HOME"] = os.path.join(BASE, "_tmp_home")
os.environ.setdefault("STARTUPSCAN_DATA_DIR",
                      os.path.join(BASE, "_tmp_home", "StartupScan"))
os.makedirs(os.environ["USERPROFILE"], exist_ok=True)

from startupscan import theme as T          # noqa: E402

T.init_scaling()

from startupscan import app as app_mod      # noqa: E402
from startupscan.widgets import action_at   # noqa: E402


def find_button(canvas, label):
    for item in canvas.find_all():
        if canvas.type(item) != "text":
            continue
        if canvas.itemcget(item, "text") != label:
            continue
        bb = canvas.bbox(item)
        if not bb:
            continue
        return (bb[0] + bb[2]) / 2.0, (bb[1] + bb[3]) / 2.0
    return None


def main():
    log = []
    ok_all = True

    app = app_mod.App(autorefresh_ms=None)
    root = app.root
    for _ in range(30):
        root.update()
        if app.scroll.canvas.winfo_width() > 400:
            break
    app.load_demo()
    app.show_page("apps")
    for _ in range(5):
        root.update()
    canvas = app.scroll.canvas

    # 桩：不弹窗、不真的改系统
    app_mod.messagebox.askyesno = lambda *a, **k: True
    app_mod.messagebox.showinfo = lambda *a, **k: None
    app_mod.messagebox.showerror = lambda *a, **k: None
    calls = []
    orig_toggle = app_mod.manage_mod.set_enabled
    orig_remove = app_mod.manage_mod.remove
    app_mod.manage_mod.set_enabled = lambda item, en: (
        calls.append(("toggle", item.get("key"), en)), (True, "ok"))[1]
    app_mod.manage_mod.remove = lambda item: (
        calls.append(("remove", item.get("key"))), (True, "ok"))[1]

    try:
        # ---- 禁用 ----
        pos = find_button(canvas, "禁用")
        if not pos:
            log.append("FAIL 找不到「禁用」按钮")
            ok_all = False
        else:
            cb = action_at(canvas, *pos)
            if not cb:
                log.append("FAIL 点击坐标未命中回调")
                ok_all = False
            else:
                cb()
                got = calls[-1] if calls else None
                log.append("禁用 -> %s" % (got,))
                if not (got and got[0] == "toggle" and got[2] is False):
                    log.append("FAIL 禁用动作参数不正确")
                    ok_all = False
                root.update()

        # ---- 删除（数量应减 1）----
        before = len(app.result["items"])
        pos = find_button(canvas, "删除")
        cb = action_at(canvas, *pos) if pos else None
        if not cb:
            log.append("FAIL 「删除」按钮未命中")
            ok_all = False
        else:
            cb()
            root.update()
            after = len(app.result["items"])
            log.append("删除 -> items %d -> %d, calls=%s" % (
                before, after, calls[-1]))
            if after != before - 1:
                log.append("FAIL 删除后列表未减少")
                ok_all = False

        # ---- 已禁用项的「启用」----
        app.show_page("manage")
        for _ in range(5):
            root.update()
        pos = find_button(canvas, "启用")
        cb = action_at(canvas, *pos) if pos else None
        if not cb:
            log.append("FAIL 管理页「启用」按钮未命中")
            ok_all = False
        else:
            cb()
            got = calls[-1]
            log.append("启用 -> %s" % (got,))
            if not (got[0] == "toggle" and got[2] is True):
                log.append("FAIL 启用动作参数不正确")
                ok_all = False
    finally:
        app_mod.manage_mod.set_enabled = orig_toggle
        app_mod.manage_mod.remove = orig_remove
        try:
            root.destroy()
        except Exception:                       # noqa: BLE001
            pass

    print("\n".join(log))
    print("== %s ==" % ("ACTION PROBE PASS" if ok_all else "ACTION PROBE FAIL"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
