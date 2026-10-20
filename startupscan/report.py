# -*- coding: utf-8 -*-
"""导出层：把一次扫描结果写成 Markdown 或 HTML 报告。

报告结构（与界面页面一一对应）：
  * 概览（统计数字）
  * 自启应用 / 启动脚本（按来源分组）
  * 计划任务（开机/登录触发优先）
  * 计划日志（失败记录 + 系统启动/关机事件）
  * 风险提示
  * 系统信息
"""

import html
import os
import webbrowser

from . import analyze as analyze_mod
from . import manage as manage_mod
from . import AUTHOR, __version__


def _fmt_path(p):
    return p or "（未解析）"


def _row(item):
    """把一条自启项格式化成 Markdown 表格行。

    除基本信息外带两列「人话」：
      * 软件 / 厂商 —— 来自 exe 的版本资源（FileDescription / CompanyName）
      * 创建者 / 作用 —— 来自计划任务 XML（Author / Description）
    这两列是回答「这到底是什么、谁弄的、干什么用的」的关键。
    """
    risk = item.get("risk", "info")
    risk_cn = analyze_mod.RISK_LABELS.get(risk, risk)
    kind = "脚本" if item.get("kind") == "script" else \
        ("DLL 入口" if item.get("kind") == "dll" else "应用")
    loc = item.get("location") or item.get("source", "")
    cmd = (item.get("raw") or item.get("command") or "").replace("|", "\\|")
    target = _fmt_path(item.get("target"))
    status = ""
    if item.get("dead"):
        status = "失效"
    elif item.get("enabled") is False:
        status = ("策略禁用" if item.get("approved_state") == "policy"
                  else "已禁用")
    elif manage_mod.role_of(item) in ("registry", "folder", "task"):
        status = "启用"

    key = item.get("key", "")
    app = item.get("app_name") or ""
    ident = ""
    if app and app != key:
        ident = app
    if item.get("vendor"):
        ident = (ident + " · " + item["vendor"]) if ident else item["vendor"]
    ident = (ident or "—").replace("|", "\\|")

    desc = (item.get("description") or "").strip()
    who = (item.get("author") or "").strip()
    if who and desc:
        owner = "%s：%s" % (who, desc[:70])
    elif who:
        owner = who
    elif desc:
        owner = desc[:70]
    else:
        owner = "—"
    owner = owner.replace("|", "\\|").replace("\n", " ")

    return "| %s | %s | %s | %s | %s | %s | %s | %s |" % (
        key.replace("|", "\\|"), ident, kind, risk_cn, status, loc, owner,
        "`%s` → %s" % (cmd, target))


_TABLE_HEAD = "| 名称 | 软件 / 厂商 | 类型 | 风险 | 状态 | 位置 | " \
              "创建者 / 作用 | 命令 / 目标 |\n" \
              "| --- | --- | --- | --- | --- | --- | --- | --- |"


def _export_markdown(res):
    s = res["stats"]
    lines = []
    lines.append("# 开机自启扫描报告\n")
    lines.append("> 生成时间：%s  ·  %s\n" % (res.get("scanned_at", ""), AUTHOR))
    lines.append("## 概览\n")
    lines.append("- 自启项总数：**%d**" % s["total"])
    lines.append("- 应用程序：%d ｜ 脚本类：%d ｜ 计划任务：%d" % (
        s["apps"], s["scripts"], s["tasks"]))
    lines.append("- 注册表 Run：%d ｜ 启动文件夹：%d ｜ 组策略：%d" % (
        s["registry"], s["folders"], s["gpo"]))
    lines.append("- 失效项：**%d** ｜ 需关注（高/中）：%d ｜ 重复指向同一程序：%d" % (
        s["dead_count"], s["risks"].get("high", 0) + s["risks"].get("medium", 0),
        s.get("duplicates", 0)))
    lines.append("- 已禁用（仍可恢复）：%d" % s.get("disabled", 0))
    lines.append("")

    lines.append("## 自启应用\n")
    apps = [it for it in res["items"] if it.get("kind") == "app"
            and it.get("source") != "scheduled_task"]
    if apps:
        lines.append(_TABLE_HEAD)
        for it in apps:
            lines.append(_row(it))
    else:
        lines.append("（无）")
    lines.append("")

    lines.append("## 启动脚本\n")
    scripts = [it for it in res["items"] if it.get("kind") == "script"]
    if scripts:
        lines.append(_TABLE_HEAD)
        for it in scripts:
            lines.append(_row(it))
    else:
        lines.append("（无）")
    lines.append("")

    lines.append("## 计划任务\n")
    tasks = res.get("tasks") or []
    if tasks:
        boot = [t for t in tasks if t.get("start_from")]
        other = [t for t in tasks if not t.get("start_from")]
        if boot:
            lines.append("### 开机 / 登录触发\n")
            lines.append(_TABLE_HEAD)
            for t in boot:
                lines.append(_row(t))
            lines.append("")
        if other:
            lines.append("### 其他触发\n")
            lines.append(_TABLE_HEAD)
            for t in other:
                lines.append(_row(t))
            lines.append("")
    else:
        lines.append("（无）")
    lines.append("")

    lines.append("## 计划日志\n")
    fails = res.get("task_failures") or []
    if fails:
        lines.append("### 计划任务失败 / 触发异常\n")
        lines.append("| 时间 | 事件 | 详情 |\n| --- | --- | --- |")
        for f in fails:
            lines.append("| %s | %s | %s |" % (
                f.get("date", ""), f.get("label", ""),
                (f.get("message", "") or "").replace("|", "\\|")[:150]))
        lines.append("")
    else:
        lines.append("近期没有计划任务失败记录。\n")
    boot_events = res.get("boot_events") or []
    if boot_events:
        lines.append("### 系统启动 / 关机事件\n")
        lines.append("| 时间 | 事件 | 说明 |\n| --- | --- | --- |")
        for ev in boot_events:
            lines.append("| %s | %s | %s |" % (
                ev.get("date", ""), ev.get("label", ""), ev.get("desc", "")))
        lines.append("")
    lines.append("")

    lines.append("## 风险提示\n")
    risky = [it for it in res["items"]
             if it.get("risk") in ("critical", "high", "medium")]
    if risky:
        lines.append(_TABLE_HEAD)
        for it in risky:
            lines.append(_row(it))
        lines.append("")
        lines.append("### 风险原因\n")
        for it in risky:
            lines.append("- **%s**（%s）：%s" % (
                it.get("key", ""),
                analyze_mod.RISK_LABELS.get(it.get("risk"), ""),
                it.get("risk_reason", "")))
        lines.append("")
    else:
        lines.append("未发现风险项。\n")

    lines.append("## 系统信息\n")
    info = res.get("sysinfo") or {}
    lines.append("| 项目 | 值 |\n| --- | --- |")
    for k, v in info.items():
        lines.append("| %s | %s |" % (k, v))
    lines.append("")
    lines.append("---")
    lines.append("*报告由「开机自启扫描器」生成  ·  %s · v%s*" % (AUTHOR, __version__))
    return "\n".join(lines)


def _html_esc(s):
    return html.escape(str(s or ""))


def _export_html(res):
    md = _export_markdown(res)
    # 简单转换：把 Markdown 表格变成 HTML 表格
    body_lines = []
    for line in md.splitlines():
        if line.startswith("# "):
            body_lines.append("<h1>%s</h1>" % _html_esc(line[2:]))
        elif line.startswith("## "):
            body_lines.append("<h2>%s</h2>" % _html_esc(line[3:]))
        elif line.startswith("### "):
            body_lines.append("<h3>%s</h3>" % _html_esc(line[4:]))
        elif line.startswith("> "):
            body_lines.append("<blockquote>%s</blockquote>" % _html_esc(line[2:]))
        elif line.startswith("| ") and "---" not in line:
            cells = [c.strip() for c in line.strip("|").split("|")]
            body_lines.append("<tr>" + "".join("<td>%s</td>" % _html_esc(c)
                                               for c in cells) + "</tr>")
        elif line.startswith("| ---"):
            body_lines.append("</table><table>")
        elif line.startswith("- "):
            body_lines.append("<li>%s</li>" % _html_esc(line[2:]))
        elif not line.strip():
            body_lines.append("")
        else:
            body_lines.append("<p>%s</p>" % _html_esc(line))
    body = "\n".join(body_lines)
    template = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>开机自启扫描报告</title>
<style>
body { font-family: "Segoe UI", "Microsoft YaHei", sans-serif; max-width: 980px;
       margin: 24px auto; padding: 0 20px; color: #1B1B1B; }
h1 { color: #0067C0; border-bottom: 2px solid #E3E3E3; padding-bottom: 8px; }
h2 { margin-top: 32px; color: #1B1B1B; }
blockquote { color: #5D5D5D; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 13px; }
th, td { border: 1px solid #E3E3E3; padding: 6px 10px; text-align: left;
         vertical-align: top; }
code { background: #F3F3F3; padding: 1px 5px; border-radius: 3px; }
</style>
</head>
<body>
@@BODY@@
</body>
</html>"""
    return template.replace("@@BODY@@", body)


def export(res, path):
    """把扫描结果写到 path（按扩展名选择 Markdown / HTML）。返回 (ok, msg)。"""
    try:
        ext = os.path.splitext(path)[1].lower()
        if ext == ".html":
            text = _export_html(res)
        else:
            text = _export_markdown(res)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(text)
        return True, ""
    except Exception as exc:                        # noqa: BLE001
        return False, "%s: %s" % (type(exc).__name__, exc)


def open_report(path):
    """用系统默认程序打开导出的报告。

    不要用 ``cmd /c start``：那会**弹出一个黑色控制台窗口**（一闪而过），
    用户在 --windowed 的 GUI 里点了「打开报告」会以为程序在跑命令行。
    ``os.startfile`` 直接走 ShellExecute，没有控制台。
    """
    try:
        os.startfile(path)                     # noqa: S606 (Windows only)
        return
    except Exception:                          # noqa: BLE001
        pass
    try:
        webbrowser.open("file:///" + path.replace("\\", "/"))
    except Exception:                          # noqa: BLE001
        pass
