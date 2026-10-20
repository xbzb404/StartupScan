# -*- coding: utf-8 -*-
"""
主界面：Windows 11 风格（NavigationView 侧边栏 + 卡片式内容 + 强调色按钮）·  by zhb

界面结构：
    ┌ 标题栏 ───────────────────────── [重新扫描] [导出报告] [深色] ┐
    ├ 侧边导航 ─┬ 内容区（可滚动，卡片式）                        ┤
    │ 概览      │  概览 / 自启应用 / 启动脚本 / 计划任务 /
    │ 自启应用  │  计划日志 / 风险提示 / 系统信息
    │ 启动脚本  │
    │ 计划任务  │
    │ 计划日志  │
    │ 风险提示  │
    │ 系统信息  │
    └ 状态栏（进度 + 提示 + 作者署名）────────────────────────────┘

数据流：
    后台线程跑 analyze.run_full_scan → 结果经 queue.Queue 回主线程 →
    重渲染当前页。扫描期间按钮置灰，避免重复触发。
"""

import datetime
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

from . import analyze as analyze_mod
from . import cmdparse as C
from . import elevate as elevate_mod
from . import manage as manage_mod
from . import report as report_mod
from . import theme as T
from . import AUTHOR, __version__
from .resources import apply_window_icon
from .theme import Fonts
from .widgets import (NavItem, Painter, PillButton, ScrollArea, action_at)

APP_NAME = "开机自启扫描器"
APP_SUB = "Windows 开机自启项 · 启动脚本 · 计划任务 · 启动日志"
VERSION = __version__
WINDOW_TITLE = "%s · %s · %s" % (APP_NAME, APP_SUB, AUTHOR)

NAV = [
    ("overview", "overview", "概览"),
    ("apps", "app", "自启应用"),
    ("scripts", "script", "启动脚本"),
    ("tasks", "task", "计划任务"),
    ("logs", "log", "计划日志"),
    ("risks", "risk", "风险提示"),
    ("manage", "manage", "管理记录"),
    ("system", "system", "系统信息"),
]

RISK_BADGE = {
    "critical": "失效",
    "high": "需关注",
    "medium": "可疑",
    "low": "一般",
    "info": "信息",
}


def _risk_colors(t, level):
    """返回 (背景, 前景)，供卡片底色等「先 bg 后 fg」的场景使用。"""
    return T.sev_colors(t, level)


def _chip_colors(t, level):
    """返回 (前景, 背景)。

    ``Painter.chip(text, fg, bg)`` 的入参顺序是「前景在前」，而
    ``theme.sev_colors`` 返回的是「背景在前」。直接 ``chip(..., *colors())``
    会把深浅色对调（浅底深字变成深底浅字），必须过这一层转换。
    """
    bg, fg = T.sev_colors(t, level)
    return fg, bg


class App(object):
    def __init__(self, autorefresh_ms=None):
        self.root = tk.Tk()
        self.scale, self.dpi = T.init_scaling()
        self.theme = dict(T.LIGHT)
        self.fonts = Fonts(self.root)
        self.page = "overview"
        self.result = None        # analyze.run_full_scan 的结果
        self._scanning = False
        self._pumping = False
        self._queue = None
        self.icon_path = ""
        self.admin = elevate_mod.is_admin()
        self._cursor = ""
        self._last_canvas_w = 0
        self._resize_job = None

        self._setup_window()
        self._build()
        if autorefresh_ms:
            self.root.after(autorefresh_ms, self.start_scan)

    # ------------------------------------------------------------ 窗口
    def _setup_window(self):
        r = self.root
        r.title(WINDOW_TITLE)
        self.icon_path = apply_window_icon(r)
        r.configure(bg=self.theme["bg"])
        sw, sh = r.winfo_screenwidth(), r.winfo_screenheight()
        w = min(T.px(1180), int(sw * 0.94))
        h = min(T.px(780), int(sh * 0.90))
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 3)
        r.geometry("%dx%d+%d+%d" % (w, h, x, y))
        r.minsize(min(T.px(900), int(sw * 0.62)), min(T.px(560), int(sh * 0.55)))
        # 先把 geometry 落地，再让 _build 去量 canvas 宽度。
        # 少了这一句，winfo_width() 还停在 1，Painter 会退回 900 的兜底宽度，
        # 于是窗口明明是 1770 宽，卡片却只铺了半屏（打包版实测）。
        r.update_idletasks()

    # ------------------------------------------------------------ 构建
    def _build(self):
        t = self.theme
        for child in self.root.winfo_children():
            child.destroy()

        # ---- 顶部标题栏 ----
        self.header = tk.Frame(self.root, bg=t["bg"], height=T.px(66))
        self.header.pack(side="top", fill="x")
        self.header.pack_propagate(False)

        left = tk.Frame(self.header, bg=t["bg"])
        left.pack(side="left", padx=(T.px(22), 0))
        name_row = tk.Frame(left, bg=t["bg"])
        name_row.pack(anchor="w", pady=(T.px(12), 0))
        if self.fonts.has_icons:
            tk.Label(name_row, text=T.icon("power"), font=self.fonts.icon_big,
                     bg=t["bg"], fg=t["accent"]).pack(side="left",
                                                      padx=(0, T.px(8)))
        tk.Label(name_row, text=APP_NAME, font=self.fonts.h2, bg=t["bg"],
                 fg=t["tx"]).pack(side="left")
        tk.Label(left, text="%s · %s" % (APP_SUB, AUTHOR), font=self.fonts.tiny,
                 bg=t["bg"], fg=t["tx3"]).pack(anchor="w", pady=(0, T.px(8)))

        right = tk.Frame(self.header, bg=t["bg"])
        right.pack(side="right", padx=(0, T.px(20)))
        # 权限徽标：管理功能（本机级自启项 / 计划任务）依赖管理员权限，
        # 状态必须一直可见；受限时点一下就能重新提权。
        if self.admin:
            tk.Label(right, text="● 管理员模式", font=self.fonts.tiny,
                     bg=t["bg"], fg=t["status_ok"]).pack(
                side="left", padx=(0, T.px(8)))
        else:
            self.btn_admin = PillButton(right, self.fonts, t, "受限模式 · 提权",
                                        self.elevate, style="secondary",
                                        icon="shield", bg=t["bg"])
            self.btn_admin.pack(side="left", padx=T.px(4))
        self.btn_theme = PillButton(right, self.fonts, t, "深色",
                                    self.toggle_theme, style="subtle",
                                    icon="theme", bg=t["bg"])
        self.btn_theme.pack(side="left", padx=T.px(4))
        self.btn_export = PillButton(right, self.fonts, t, "导出报告",
                                     self.export_report, style="secondary",
                                     icon="export", bg=t["bg"])
        self.btn_export.pack(side="left", padx=T.px(4))
        self.btn_export.set_enabled(False)
        self.btn_scan = PillButton(right, self.fonts, t, "开始扫描",
                                   self.start_scan, style="primary",
                                   icon="refresh", bg=t["bg"])
        self.btn_scan.pack(side="left", padx=T.px(4))

        # ---- 主体 ----
        self.body = tk.Frame(self.root, bg=t["bg"])
        self.body.pack(side="top", fill="both", expand=True)

        self.sidebar = tk.Frame(self.body, bg=t["bg"], width=T.px(236))
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        self.nav_items = {}
        for key, icon_name, label in NAV:
            item = NavItem(self.sidebar, self.fonts, t, label, icon_name,
                           command=lambda k=key: self.show_page(k),
                           width=236, bg=t["bg"])
            item.pack(padx=T.px(6), pady=T.px(1))
            self.nav_items[key] = item
        self.nav_items[self.page].set_selected(True)

        tip = tk.Frame(self.sidebar, bg=t["bg"])
        tip.pack(side="bottom", fill="x", pady=T.px(14), padx=T.px(14))
        tk.Label(tip, text="扫描范围：注册表 Run · 启动文件夹 · 组策略脚本 ·\n"
                           "任务计划程序 · 启动/关机事件日志",
                 font=self.fonts.tiny, bg=t["bg"], fg=t["tx3"],
                 wraplength=T.px(200), justify="left").pack(anchor="w")
        tk.Label(tip, text="%s · v%s" % (AUTHOR, VERSION), font=self.fonts.tiny,
                 bg=t["bg"], fg=t["tx3"]).pack(anchor="w", pady=(T.px(6), 0))

        self.content = tk.Frame(self.body, bg=t["bg"])
        self.content.pack(side="left", fill="both", expand=True)
        self.scroll = ScrollArea(self.content, t)
        self.scroll.pack(fill="both", expand=True)
        # 卡片内的操作按钮画在 canvas 上，点击在这里统一分发。
        # 用 canvas 级绑定 + 命中测试（action_at），而不是给每个按钮
        # tag_bind：重绘后 tag_bind 会重复累积，一次点击会触发多次。
        self.scroll.canvas.bind("<ButtonRelease-1>", self._on_canvas_click,
                                add="+")
        self.scroll.canvas.bind("<Motion>", self._on_canvas_motion, add="+")
        # 窗口变宽/变窄时重排内容：Painter 的换行宽度是渲染时取的 canvas
        # 宽度，不重排的话拖大窗口后卡片仍停在旧宽度，右边留一大片空白。
        self.scroll.canvas.bind("<Configure>", self._on_canvas_resize, add="+")

        # ---- 状态栏 ----
        self.footer = tk.Frame(self.root, bg=t["bg_alt"], height=T.px(34))
        self.footer.pack(side="bottom", fill="x")
        self.footer.pack_propagate(False)
        self.status = tk.Canvas(self.footer, bg=t["bg_alt"], height=T.px(34),
                                highlightthickness=0, bd=0)
        self.status.pack(fill="both", expand=True)
        self.status.bind("<Configure>", lambda _e: self._draw_status())
        self.status_txt = "准备就绪 —— 点击右上角「开始扫描」读取本机开机自启内容"
        self.status_frac = 0.0
        self._draw_status()

        self.render_page()

    # ------------------------------------------------------------ 状态栏
    def _draw_status(self):
        t = self.theme
        c = self.status
        c.delete("all")
        self._status_imgs = []
        w = c.winfo_width() or T.px(1100)
        h = T.px(34)
        sign = "%s · v%s" % (AUTHOR, VERSION)
        aw = T.px(96)
        c.create_text(w - T.px(22), h / 2, text=sign,
                      anchor="e", font=self.fonts.tiny, fill=t["tx3"])
        c.create_text(T.px(22), h / 2, text=self.status_txt,
                      anchor="w", font=self.fonts.tiny, fill=t["tx2"])
        if self.status_frac > 0:
            bw = T.px(180)
            bx = max(T.px(22), w - aw - bw - T.px(14))
            by = h / 2 - T.px(2)
            T.draw_round_rect(c, bx, by, bx + bw, by + T.px(4),
                              radius=T.px(2), fill=t["track"],
                              photo_holder=self._status_imgs)
            fw = max(T.px(4), bw * max(0.0, min(1.0, self.status_frac)))
            T.draw_round_rect(c, bx, by, bx + fw, by + T.px(4),
                              radius=T.px(2), fill=t["accent"],
                              photo_holder=self._status_imgs)

    def set_status(self, text, frac=None):
        self.status_txt = text
        if frac is not None:
            self.status_frac = frac
        self._draw_status()

    # ------------------------------------------------------------ 画布按钮
    def _on_canvas_click(self, event):
        """卡片内操作按钮的点击分发。"""
        c = self.scroll.canvas
        cb = action_at(c, c.canvasx(event.x), c.canvasy(event.y))
        if cb:
            cb()
            return "break"

    def _on_canvas_motion(self, event):
        """鼠标移到可点击按钮上时变成手型。"""
        c = self.scroll.canvas
        hit = action_at(c, c.canvasx(event.x), c.canvasy(event.y))
        want = "hand2" if hit else ""
        if self._cursor != want:
            self._cursor = want
            try:
                c.configure(cursor=want)
            except tk.TclError:
                pass

    def _on_canvas_resize(self, event):
        """窗口宽度变化后延迟重排（防抖，避免拖动时反复重绘）。

        重绘会清空 canvas，必须先记住滚动位置再恢复，否则用户滚到一半
        拖一下窗口就跳回顶部。
        """
        last = getattr(self, "_last_canvas_w", 0)
        if abs(event.width - last) < 6:
            return
        self._last_canvas_w = event.width
        job = getattr(self, "_resize_job", None)
        if job:
            try:
                self.root.after_cancel(job)
            except tk.TclError:
                pass
        self._resize_job = self.root.after(140, self._render_after_resize)

    def _render_after_resize(self):
        self._resize_job = None
        try:
            top = self.scroll.canvas.yview()[0]
        except tk.TclError:
            top = 0.0
        self.render_page()
        self.scroll.canvas.yview_moveto(top)

    # ------------------------------------------------------------ 提权
    def elevate(self):
        """受限模式下重新以管理员身份启动（会关闭当前窗口）。"""
        if elevate_mod.is_admin():
            self.admin = True
            self._build()
            return
        if not messagebox.askyesno(
                "以管理员身份重启",
                "程序将关闭并以管理员身份重新启动。\n\n"
                "管理本机级自启项（HKLM）与计划任务需要管理员权限。",
                parent=self.root):
            return
        if elevate_mod.relaunch_as_admin():
            try:
                self.root.destroy()
            finally:
                os._exit(0)
        messagebox.showerror(
            "提权失败",
            "未能获得管理员权限（可能取消了 UAC 提示）。\n"
            "程序将以受限模式继续运行。", parent=self.root)

    # ------------------------------------------------------------ 交互
    def toggle_theme(self):
        self.theme = dict(T.DARK if self.theme["name"] == "light" else T.LIGHT)
        self.root.configure(bg=self.theme["bg"])
        self._build()
        if self.btn_theme.text in ("深色", "浅色"):
            self.btn_theme.config_text("浅色" if self.theme["name"] == "dark"
                                       else "深色")

    def show_page(self, key):
        self.page = key
        for k, item in self.nav_items.items():
            item.set_selected(k == key)
        self.render_page()

    def load_demo(self):
        """演示模式：用合成数据渲染界面（本机没有数据时也能看效果）。"""
        from . import demo
        self.result = demo.demo_bundle()
        self.btn_export.set_enabled(True)
        self.set_status("演示模式：当前展示的是合成数据，不是本机真实记录", 1.0)
        self.render_page()

    # ------------------------------------------------------------ 扫描
    def start_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self.t0 = datetime.datetime.now()
        self.btn_scan.set_enabled(False)
        self.btn_scan.config_text("正在扫描…")
        self.set_status("正在读取系统信息与开机自启内容…", 0.05)
        self._queue = queue.Queue()
        threading.Thread(target=self._work, daemon=True).start()
        self.root.after(80, self._pump)

    def _work(self):
        try:
            def prog(msg, frac):
                self._queue.put(("status", (msg, frac)))
            self._queue.put(("status", ("正在扫描…", 0.05)))
            result = analyze_mod.run_full_scan(progress=prog)
            self._queue.put(("done", result))
        except Exception as exc:                        # noqa: BLE001
            self._queue.put(("error", "%s: %s" % (type(exc).__name__, exc)))

    def _pump(self):
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "status":
                    msg, frac = payload
                    self.set_status(msg, frac)
                elif kind == "done":
                    self.result = payload
                    self._scan_done()
                elif kind == "error":
                    self._scan_failed(payload)
        except queue.Empty:
            pass
        if self._scanning:
            self.root.after(80, self._pump)

    def _scan_done(self):
        self._scanning = False
        self.btn_scan.set_enabled(True)
        self.btn_scan.config_text("重新扫描")
        self.btn_export.set_enabled(True)
        s = self.result["stats"]
        self.set_status("扫描完成：自启项 %d 项（%d 条需关注）" % (
            s["total"], s["risks"].get("critical", 0)
            + s["risks"].get("high", 0) + s["risks"].get("medium", 0)), 1.0)
        self.show_page("overview")

    def _scan_failed(self, msg):
        self._scanning = False
        self.btn_scan.set_enabled(True)
        self.btn_scan.config_text("重新扫描")
        self.set_status("扫描失败：%s" % msg, 1.0)
        messagebox.showerror("扫描失败", msg, parent=self.root)

    # ------------------------------------------------------------ 导出
    def export_report(self):
        if not self.result:
            messagebox.showinfo("提示", "请先完成一次扫描", parent=self.root)
            return
        path = filedialog.asksaveasfilename(
            parent=self.root, title="导出扫描报告",
            defaultextension=".md",
            filetypes=[("Markdown 报告", "*.md"), ("HTML 报告", "*.html"),
                       ("所有文件", "*.*")])
        if not path:
            return
        ok, msg = report_mod.export(self.result, path)
        if ok:
            self.set_status("报告已导出：%s" % path, 1.0)
            messagebox.showinfo("导出完成",
                                "报告已保存到：\n%s\n\n是否在浏览器中打开？" % path)
            if messagebox.askyesno("打开报告", "是否立即打开这份报告？",
                                   parent=self.root):
                report_mod.open_report(path)
        else:
            self.set_status("导出失败：%s" % msg, 1.0)
            messagebox.showerror("导出失败", msg, parent=self.root)

    # ------------------------------------------------------------ 管理动作
    @staticmethod
    def _item_title(it):
        return (it.get("app_name") or it.get("key") or it.get("name") or "")

    def _identity(self, it):
        """条目的稳定身份。

        扫描结果里 ``items``（参与评级的副本）与 ``tasks``（原始任务列表）
        是两份数据，而页面各自从其中一份渲染。任何管理动作都必须同时改
        两份，否则切到「计划任务」页会看到旧状态。
        """
        role = manage_mod.role_of(it)
        if role == "task":
            return ("task", (it.get("path") or "").lower())
        if role == "registry":
            return ("registry", (it.get("source") or ""),
                    (it.get("reg_hive") or "").upper(),
                    (it.get("reg_path") or "").lower(),
                    (it.get("reg_name") or "").lower())
        if role == "folder":
            return ("folder", (it.get("source") or ""),
                    (it.get("file_path") or "").lower())
        return ("other", id(it))

    def _sync_item(self, it, enabled=None, deleted=False):
        """把管理动作的结果同步回扫描结果，并重算统计。"""
        res = self.result
        if not res:
            return
        ident = self._identity(it)
        for key in ("items", "tasks"):
            lst = res.get(key) or []
            if deleted:
                lst[:] = [x for x in lst if self._identity(x) != ident]
            else:
                for x in lst:
                    if self._identity(x) != ident:
                        continue
                    if enabled is not None:
                        x["enabled"] = bool(enabled)
                        x["approved_state"] = ("enabled" if enabled
                                               else "disabled")
        res["stats"] = analyze_mod.recount(res["items"])

    def _after_manage(self, msg, ok=True):
        self.set_status(msg, 1.0)
        self.render_page()

    def _toggle_item(self, it, enabled):
        """启用 / 禁用一条自启项（禁用不改原配置，随时可恢复）。"""
        title = self._item_title(it)
        verb = "启用" if enabled else "禁用"
        note = ("启用后会在下次开机 / 登录时自动运行。"
                if enabled else
                "禁用后原配置仍然保留，可随时在「管理记录」里撤销，"
                "不会删除任何文件。")
        if not messagebox.askyesno(
                "%s自启项" % verb,
                "确定要%s「%s」吗？\n\n%s" % (verb, title, note),
                parent=self.root):
            return
        ok, msg = manage_mod.set_enabled(it, enabled)
        if not ok:
            messagebox.showerror("%s失败" % verb, msg, parent=self.root)
            self.set_status("%s失败：%s" % (verb, msg), 1.0)
            return
        self._sync_item(it, enabled=enabled)
        self._after_manage(msg)

    def _delete_item(self, it):
        """删除一条自启项（先备份，可在管理记录里撤销）。"""
        ok, why = manage_mod.can_delete(it)
        if not ok:
            messagebox.showinfo("无法删除", why, parent=self.root)
            return
        role = manage_mod.role_of(it)
        kind = {"task": "计划任务", "folder": "启动文件夹条目"}.get(
            role, "注册表自启项")
        if not messagebox.askyesno(
                "删除%s" % kind,
                "确定删除%s「%s」吗？\n\n"
                "程序会先备份到：\n%s\n\n"
                "删除后可在「管理记录」里撤销。" % (
                    kind, self._item_title(it), manage_mod.backup_dir()),
                parent=self.root, icon="warning"):
            return
        ok, msg = manage_mod.remove(it)
        if not ok:
            messagebox.showerror("删除失败", msg, parent=self.root)
            self.set_status("删除失败：%s" % msg, 1.0)
            return
        self._sync_item(it, deleted=True)
        self._after_manage(msg)

    def _undo_record(self, rec):
        if not messagebox.askyesno(
                "撤销操作",
                "确定撤销「%s」吗？\n\n%s" % (rec.get("title", ""),
                                            rec.get("detail", "")),
                parent=self.root):
            return
        ok, msg = manage_mod.undo(rec)
        if not ok:
            messagebox.showerror("撤销失败", msg, parent=self.root)
            return
        # 撤销后本机状态已变，但内存里的条目无法可靠推断（删除类尤其如此），
        # 这里给明确指引，而不是假装列表已刷新。
        self.set_status("%s —— 请点右上角「重新扫描」刷新列表" % msg, 1.0)
        self.render_page()
        messagebox.showinfo("已撤销", msg, parent=self.root)

    def _copy_text(self, text, quiet=False):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text or "")
            self.root.update_idletasks()
        except tk.TclError:
            if not quiet:
                messagebox.showinfo("提示", "复制失败：剪贴板不可用",
                                    parent=self.root)
            return False
        if not quiet:
            self.set_status("已复制到剪贴板：%s" % (
                text if len(text) < 80 else text[:77] + "…"), 1.0)
        return True

    def _copy_command(self, it):
        text = (it.get("raw") or it.get("command")
                or it.get("target") or "")
        if not text:
            messagebox.showinfo("提示", "这一条没有可复制的命令",
                                parent=self.root)
            return
        self._copy_text(text)

    def _open_location(self, it):
        """按条目类型打开对应位置：注册表键 / 启动文件夹 / 任务定义。"""
        role = manage_mod.role_of(it)
        if role == "registry":
            ok, key = manage_mod.open_registry_location(it)
            if not ok:
                messagebox.showerror(
                    "打开失败", "无法启动注册表编辑器。\n\n路径：%s" % key,
                    parent=self.root)
                return
            self._copy_text(key, quiet=True)
            self.set_status("已打开注册表编辑器；注册表路径已复制到剪贴板", 1.0)
            return
        if role == "folder":
            path = it.get("file_path") or it.get("target")
            if path and os.path.exists(path):
                C.open_in_explorer(path)
                self.set_status("已定位：%s" % path, 1.0)
            else:
                messagebox.showinfo("提示", "文件已不存在，无法定位",
                                    parent=self.root)
            return
        if role == "task":
            ok, where = manage_mod.open_task_definition(it)
            if ok:
                self.set_status("已打开：%s" % where, 1.0)
            else:
                messagebox.showerror("打开失败", "无法打开任务定义位置",
                                     parent=self.root)
            return
        target = it.get("target")
        if target and it.get("exists"):
            C.open_in_explorer(target)
            self.set_status("已定位：%s" % target, 1.0)
        else:
            messagebox.showinfo("提示", "目标文件不存在，无法定位",
                                parent=self.root)

    def _card_actions(self, p, it):
        """在卡片底部画管理按钮行。"""
        t = self.theme
        role = manage_mod.role_of(it)
        acts = []
        can_toggle, why = manage_mod.can_toggle(it)
        if can_toggle:
            if it.get("enabled") is False:
                acts.append(("启用", lambda: self._toggle_item(it, True),
                             "secondary"))
            else:
                acts.append(("禁用", lambda: self._toggle_item(it, False),
                             "secondary"))
        elif why and "管理员" not in why:
            p.body(why, font=p.f.tiny, color=t["tx3"])
        acts.append(("打开位置", lambda: self._open_location(it), "subtle"))
        acts.append(("复制命令", lambda: self._copy_command(it), "subtle"))
        can_delete, _why = manage_mod.can_delete(it)
        if can_delete:
            acts.append(("删除", lambda: self._delete_item(it), "danger"))
        p.gap(2)
        p.actions(acts)

    # ------------------------------------------------------------ 渲染
    def render_page(self):
        c = self.scroll.canvas
        c.delete("all")
        # 清掉上一轮渲染留下的按钮回调，否则重绘后点到同一坐标会作用到
        # 已经不在屏幕上的旧条目（甚至已删除的条目）。
        c._act_map = {}
        c._act_seq = 0
        try:
            c.configure(cursor="")
        except tk.TclError:
            pass
        self._img_refs = []
        self._cursor = ""
        w = c.winfo_width() or T.px(900)
        h = c.winfo_height() or T.px(600)
        # 记录本次渲染用的宽度：若此刻 canvas 还没拿到真实尺寸（=1），
        # 记 0，让随后的 <Configure> 触发一次重排。
        self._last_canvas_w = w if c.winfo_width() > 100 else 0
        p = Painter(c, self.fonts, self.theme, w)
        fn = getattr(self, "_render_" + self.page, None)
        if fn:
            fn(p)
        else:
            p.heading("页面不存在", "这个页面还没有实现。")
        # 底部留白
        p.gap(10)
        self.scroll.set_scrollregion(p.y)

    # ---------------- 概览 ----------------
    def _render_overview(self, p):
        p.heading("概览", "本机开机自启内容一览（Windows 10 / 11）")
        res = self.result
        if res is None:
            p.empty_state(
                "还没有扫描结果",
                "点击右上角「开始扫描」，读取本机注册表 Run、启动文件夹、"
                "组策略脚本、计划任务与启动日志。",
                actions=["扫描完成后，这里会显示自启项总数与风险统计"])
            return
        s = res["stats"]
        critical = s["risks"].get("critical", 0)
        high = s["risks"].get("high", 0)
        medium = s["risks"].get("medium", 0)
        p.metric_tiles([
            ("自启项总数", s["total"]),
            ("应用程序", s["apps"]),
            ("脚本类", s["scripts"]),
            ("计划任务", s["tasks"]),
            ("注册表 Run", s["registry"]),
            ("启动文件夹", s["folders"]),
            ("组策略", s["gpo"]),
            ("失效/需关注", critical + high + medium),
        ], cols=4)

        p.section("扫描来源")
        p.card(lambda: (
            p.kv("注册表 Run / RunOnce", "%d 项" % s["registry"]),
            p.kv("启动文件夹", "%d 项" % s["folders"]),
            p.kv("组策略脚本", "%d 项" % s["gpo"]),
            p.kv("计划任务", "%d 项" % s["tasks"]),
            p.kv("已禁用（可恢复）", "%d 项" % s.get("disabled", 0)),
            p.kv("最近扫描时间", res.get("scanned_at", "")),
        ))

        p.section("风险概览")
        p.card(lambda: self._risk_chips(p, critical, high, medium))

        boot = res.get("boot_events") or []
        if boot:
            p.section("最近系统启动")
            for ev in boot[:3]:
                p.card(lambda ev=ev: (
                    p.inline_chip(ev["label"],
                                  *_chip_colors(self.theme,
                                                self._ev_level(ev["label"]))),
                    p.body(ev["date"] + "  " + ev["desc"], font=p.f.small),
                ), pad=14, gap=8)

    # ---------------- 自启应用 ----------------
    def _render_apps(self, p):
        p.heading("自启应用", "开机时自动运行的应用程序与快捷方式")
        res = self.result
        if res is None:
            p.empty_state("还没有数据", "先执行一次扫描。")
            return
        items = [it for it in res["items"] if it.get("kind") == "app"
                 and it.get("source") != "scheduled_task"]
        if not items:
            p.empty_state("没有发现自启应用", "本机注册表与启动文件夹里没有应用类自启项。")
            return
        p.body("共 %d 项 —— 卡片底部可直接「禁用 / 删除 / 打开位置」，"
               "所有变更都先备份、可撤销。" % len(items))
        for it in items:
            self._render_item_card(p, it)

    # ---------------- 启动脚本 ----------------
    def _render_scripts(self, p):
        p.heading("启动脚本", "开机/登录时自动运行的脚本（bat / vbs / ps1 等）")
        res = self.result
        if res is None:
            p.empty_state("还没有数据", "先执行一次扫描。")
            return
        items = [it for it in res["items"] if it.get("kind") == "script"]
        if not items:
            p.empty_state("没有发现启动脚本", "本机没有脚本类自启项。")
            return
        p.body("共 %d 项 —— 脚本类自启常被下载即运行的程序或恶意工具利用，建议逐一确认。" % len(items))
        for it in items:
            self._render_item_card(p, it)

    # ---------------- 计划任务 ----------------
    def _render_tasks(self, p):
        p.heading("计划任务", "任务计划程序中已注册的任务（含开机/登录触发）")
        res = self.result
        if res is None:
            p.empty_state("还没有数据", "先执行一次扫描。")
            return
        tasks = res.get("tasks") or []
        if not tasks:
            p.empty_state("没有发现计划任务", "任务计划程序里没有任务。")
            return
        p.body("共 %d 个任务 —— 已按触发类型标注，开机/登录相关的优先显示。" % len(tasks))
        boot = [t for t in tasks if t.get("start_from")]
        other = [t for t in tasks if not t.get("start_from")]
        if boot:
            p.section("开机 / 登录触发")
            for t in boot:
                self._render_task_card(p, t)
        if other:
            p.section("其他触发")
            for t in other:
                self._render_task_card(p, t)

    # ---------------- 计划日志 ----------------
    def _render_logs(self, p):
        p.heading("计划日志", "任务计划程序与系统启动/关机事件日志")
        res = self.result
        if res is None:
            p.empty_state("还没有数据", "先执行一次扫描。")
            return
        ev = res.get("events") or {}
        fails = res.get("task_failures") or []
        boot = res.get("boot_events") or []

        p.section("计划任务失败 / 触发异常")
        if fails:
            for f in fails:
                def draw(f=f):
                    p.inline_chip("失败",
                                  *_chip_colors(self.theme, "critical"))
                    title = f.get("task_name") or f.get("label") or ""
                    p.body(f.get("date", "") + "  ·  " + title,
                           font=p.f.body_b)
                    if f.get("description"):
                        p.body("作用：" + f["description"][:110],
                               font=p.f.small, color=p.t["tx2"])
                    if f.get("author"):
                        p.body("创建者：" + f["author"], font=p.f.tiny,
                               color=p.t["tx3"])
                    p.body((f.get("message") or "")[:120], font=p.f.small,
                           color=p.t["tx3"])
                p.card(draw, pad=14, gap=8)
        else:
            p.body("近期没有计划任务失败记录。", font=p.f.small)

        p.section("系统启动 / 关机事件")
        if boot:
            for ev_ in boot:
                p.card(lambda ev_=ev_: (
                    p.inline_chip(ev_["label"],
                                  *_chip_colors(self.theme,
                                                self._ev_level(ev_["label"]))),
                    p.body(ev_.get("date", "") + "  " + ev_.get("desc", ""),
                           font=p.f.small),
                ), pad=14, gap=8)
        else:
            p.body("没有读取到系统启动事件（可能需要管理员权限）。", font=p.f.small)

        notes = (ev.get("task_notes") or []) + (ev.get("sys_notes") or [])
        if notes:
            p.section("采集说明")
            for n in notes:
                p.body(n, font=p.f.tiny, color=p.t["tx3"])

    # ---------------- 风险提示 ----------------
    def _render_risks(self, p):
        p.heading("风险提示", "失效项、脚本类、临时目录自启等需要留意的内容")
        res = self.result
        if res is None:
            p.empty_state("还没有数据", "先执行一次扫描。")
            return
        items = [it for it in res["items"] if it.get("risk") in
                 ("critical", "high", "medium")]
        if not items:
            p.empty_state("未发现风险项", "所有自启项都指向存在的文件，且没有明显可疑特征。")
            return
        p.body("共 %d 项需要留意 —— 失效项建议清理，脚本类建议确认来源。" % len(items))
        for it in items:
            self._render_item_card(p, it, show_risk=True)

    # ---------------- 管理记录 ----------------
    def _render_manage(self, p):
        p.heading("管理记录", "启用 / 禁用 / 删除都先备份，全部可在这里撤销")
        t = self.theme

        p.section("运行权限")

        def draw_perm():
            if self.admin:
                p.chip_row([("管理员模式",) +
                            _chip_colors(self.theme, "low")])
                p.body("当前以管理员身份运行：可管理本机级（HKLM）自启项、"
                       "公共启动文件夹与计划任务。",
                       color=t["tx2"], font=p.f.small)
            else:
                p.chip_row([("受限模式",) +
                            _chip_colors(self.theme, "medium")])
                p.body("当前以普通权限运行：只能管理当前用户的自启项；"
                       "本机级条目与计划任务需要管理员权限。",
                       color=t["tx2"], font=p.f.small)
                p.actions([("以管理员身份重启", self.elevate, "primary")])

        p.card(draw_perm, pad=16, gap=8)

        res = self.result
        p.section("已禁用的自启项")
        if not res:
            p.body("先执行一次扫描。", font=p.f.small)
        else:
            disabled = [it for it in res["items"]
                        if it.get("enabled") is False]
            if disabled:
                p.body("共 %d 项 —— 这些条目仍保留在系统里，点「启用」即可"
                       "恢复；在任务管理器里关闭的启动项也会出现在这里。"
                       % len(disabled), color=t["tx3"], font=p.f.small)
                for it in disabled:
                    self._render_item_card(p, it)
            else:
                p.body("没有已禁用的自启项。", font=p.f.small)

        recs = manage_mod.history()
        p.section("变更记录", "共 %d 条" % len(recs))
        if not recs:
            p.body("还没有进行过管理操作。", font=p.f.small)
        for rec in recs[:60]:
            action = rec.get("action", "")
            level = {"disable": "medium", "enable": "info",
                     "delete": "critical"}.get(action, "low")

            def draw_rec(rec=rec, action=action, level=level):
                p.chip_row([
                    (manage_mod.ACTION_LABELS.get(action, action),
                     *_chip_colors(self.theme, level)),
                    (rec.get("time", ""), t["tx3"], t["chip_bg"]),
                ])
                p.body(rec.get("title", ""), font=p.f.body_b, color=t["tx"])
                if rec.get("detail"):
                    p.body(rec["detail"], font=p.f.small, color=t["tx3"])
                if rec.get("undone"):
                    p.body("已撤销（%s）" % rec.get("undone_at", ""),
                           font=p.f.tiny, color=t["status_ok"])
                elif rec.get("undo"):
                    p.actions([("撤销", lambda: self._undo_record(rec),
                                "secondary")])

            p.card(draw_rec, pad=14, gap=8)

        p.section("备份与恢复")
        p.body("备份目录：%s" % manage_mod.backup_dir(),
               color=t["tx3"], font=p.f.small)
        p.body("· 注册表值：完整数据（含类型）记入 history.json\n"
               "· 启动文件夹：文件移动到 backup\\files\\\n"
               "· 计划任务：定义备份为 backup\\tasks\\*.xml\n"
               "· 撤销入口在每条变更记录下方",
               color=t["tx3"], font=p.f.small)
        p.actions([("打开备份文件夹", manage_mod.open_backup_dir,
                    "secondary")])

    # ---------------- 系统信息 ----------------
    def _render_system(self, p):
        p.heading("系统信息", "本机系统基础信息")
        res = self.result
        if res is None:
            p.empty_state("还没有数据", "先执行一次扫描。")
            return
        info = res.get("sysinfo") or {}
        p.section("系统")
        p.card(lambda: (
            p.kv("操作系统", info.get("os", "")),
            p.kv("版本号", info.get("version", "")),
            p.kv("计算机名", info.get("computer", "")),
            p.kv("当前用户", info.get("user", "")),
            p.kv("系统架构", info.get("arch", "")),
            p.kv("处理器", info.get("cpu", "")),
            p.kv("物理内存", info.get("memory", "")),
            p.kv("运行权限", "管理员模式" if self.admin else "受限模式"),
            p.kv("系统启动时间", info.get("uptime", "")),
        ))

        p.section("扫描概况")
        s = res["stats"]
        p.card(lambda: (
            p.kv("扫描时间", res.get("scanned_at", "")),
            p.kv("自启项总数", "%d" % s["total"]),
            p.kv("失效项", "%d" % s["dead_count"]),
            p.kv("脚本类", "%d" % s["scripts"]),
        ))

    # ---------------- 通用卡片 ----------------
    def _risk_chips(self, p, critical, high, medium):
        """概览页风险统计：同一行并排三个标签。

        用 ``chip_row`` 而不是连续调 ``chip`` —— chip 不推进游标，
        连着调三个会全部叠在同一坐标上（实测三标签重叠 68%~84%）。
        """
        p.gap(2)
        p.chip_row([
            ("失效/高危：%d 项" % critical,) + _chip_colors(self.theme, "critical"),
            ("需关注：%d 项" % high,) + _chip_colors(self.theme, "high"),
            ("可疑：%d 项" % medium,) + _chip_colors(self.theme, "medium"),
        ])
        p.gap(2)

    def _render_item_card(self, p, it, show_risk=False):
        t = self.theme
        level = it.get("risk", "info")
        bg, fg = _risk_colors(t, level)
        label = RISK_BADGE.get(level, level)

        def draw():
            # 第一行：风险标签 + 启用状态 + 来源标签（并排）。chip 不推进
            # 游标，必须用 chip_row 让它们水平排列，否则标签会叠在一起。
            chips = [(label, fg, bg)]
            if it.get("enabled") is False:
                state = it.get("approved_state")
                text = "策略禁用" if state == "policy" else "已禁用"
                chips.append((text,) + _chip_colors(self.theme, "medium"))
            elif it.get("approved_state") == "unknown":
                chips.append(("状态未知",) + _chip_colors(self.theme, "low"))
            chips.append((it.get("location") or it.get("source", ""),
                          t["tx3"], t["chip_bg"]))
            p.chip_row(chips, gap=6)

            # 名称：优先「软件真名」（exe 版本资源里的 FileDescription），
            # 原始名降为副标题；两者相同则只显示一次。
            title = (it.get("app_name") or it.get("key")
                     or it.get("name") or "")
            _it, bb = p._text(p.x, p.y, title, p.f.h3, t["tx"],
                              width=p.w - T.px(4))
            p.y = bb[3] + T.px(2)
            key = it.get("key") or it.get("name") or ""
            if it.get("app_name") and it["app_name"] != key:
                p.body(key, color=t["tx3"], font=p.f.tiny)

            # 厂商 / 版本：回答「这是谁的软件」
            meta = " ｜ ".join(x for x in (it.get("vendor"),
                                          it.get("app_version")) if x)
            if meta:
                p.body(meta, color=t["tx3"], font=p.f.tiny)

            # 计划任务：作用 / 创建者 / 运行身份（来自任务 XML）
            if it.get("source") == "scheduled_task":
                if it.get("description"):
                    p.body("作用：%s" % it["description"][:120],
                           color=t["tx2"], font=p.f.small)
                bits = []
                if it.get("author"):
                    bits.append("创建者：%s" % it["author"])
                if it.get("run_as"):
                    bits.append("运行身份：%s" % it["run_as"])
                if bits:
                    p.body(" ｜ ".join(bits), color=t["tx3"], font=p.f.tiny)

            # 脚本：读前几行，回答「这脚本干什么」
            if it.get("preview"):
                p.body("脚本内容：", color=t["tx3"], font=p.f.tiny)
                for line in it["preview"]:
                    p.body("· " + line, color=t["tx3"], font=p.f.small,
                           indent=2)

            # 执行命令（含中文时自动切中文字体，避免豆腐块）
            raw = it.get("raw") or it.get("command") or ""
            if raw:
                p.mono_text(raw, color=t["tx2"])

            # 目标路径
            target = it.get("target") or ""
            if target:
                p.body("目标：%s" % target, color=t["tx3"], font=p.f.tiny)

            # 风险原因
            if show_risk and it.get("risk_reason"):
                p.body("原因：%s" % it["risk_reason"], color=fg,
                       font=p.f.small)

            # 计划任务运行信息
            if it.get("source") == "scheduled_task":
                if it.get("trigger"):
                    p.body("触发：%s" % it["trigger"], color=t["tx3"],
                           font=p.f.tiny)
                lr = it.get("last_run") or ""
                lres = it.get("last_result") or ""
                if lr or lres:
                    p.body("上次运行：%s ｜ 结果：%s" % (lr, lres),
                           color=t["tx3"], font=p.f.tiny)

            # 管理操作行：禁用 / 启用、打开位置、复制命令、删除
            self._card_actions(p, it)
        p.card(draw, pad=16, gap=8)

    def _render_task_card(self, p, t):
        self._render_item_card(p, t, show_risk=True)

    def _ev_level(self, label):
        """事件标签 → 风险级别（配色由 _chip_colors 转成 chip 要的顺序）。"""
        if label in ("失败", "异常"):
            return "critical"
        if label == "关机":
            return "low"
        return "info"

    def run(self):
        self.root.mainloop()
