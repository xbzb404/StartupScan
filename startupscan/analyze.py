# -*- coding: utf-8 -*-
"""分析聚合层：把三路采集结果归一化成界面/报告用的统一视图。

职责：
  * 汇总统计（总数、按类型、按来源、风险数）；
  * 风险评级（失效 / 临时目录 / 脚本类 / 可疑参数）；
  * 开机/登录相关的计划任务筛选；
  * 从事件日志里挑出最近一次开机相关事件。
"""

import datetime
import os
import re

from . import collect as collect_mod
from . import cmdparse as C
from . import eventlog as eventlog_mod
from . import fileinfo as FI
from . import sysinfo as sysinfo_mod
from . import tasks as tasks_mod

RISK_LEVELS = ["critical", "high", "medium", "low", "info"]

RISK_LABELS = {
    "critical": "失效/高危",
    "high": "需关注",
    "medium": "可疑",
    "low": "一般",
    "info": "信息",
}


# schtasks「上次结果」里的 SCHED_S_* 任务状态码 —— 是状态不是失败，
# 不算异常（0x41301=正在运行、0x41303=尚未运行 等，均为 HRESULT 成功段）。
_TASK_STATE_CODES = {"0x41300", "0x41301", "0x41302", "0x41303",
                     "0x41304", "0x41305", "0x41306"}


def is_system_task(item):
    """是否 Windows 自带系统任务（\\Microsoft\\... 路径下的计划任务）。"""
    if item.get("source") != "scheduled_task":
        return False
    return (item.get("path") or "").strip().lower().startswith("\\microsoft\\")


def risk_of(item):
    """给一条自启项/计划任务打风险评级，返回 (level, reason)。

    critical —— 目标文件已不存在（失效项，开机白跑且可能是卸载残留）
    high     —— 目标在临时/下载目录，或脚本类自启（bat/vbs/ps1，常见于
                下载即运行的程序与黑客工具）
    medium   —— 计划任务上次运行结果异常
    low      —— 常规项（含已禁用的用户计划任务：禁用即不参与自启，
                本身不构成风险，不再当「可疑」报虚警）
    info     —— Windows 系统任务被禁用（系统正常状态，纯提示）

    注意：已被禁用的系统任务**不算风险**。实测一台机器上有 40+ 条
    \\Microsoft\\ 下的任务被策略/用户禁用，旧逻辑全部报「可疑」，
    把真正的风险淹没在虚警里。
    """
    if item.get("dead"):
        return "critical", item.get("dead_reason") or "目标文件不存在"
    if item.get("suspicious"):
        return "high", "目标位于临时/下载目录"
    if item.get("kind") == "script":
        return "high", "脚本类自启项（.bat/.cmd/.vbs/.ps1）"
    if item.get("source") == "scheduled_task":
        if not item.get("enabled"):
            if is_system_task(item):
                return "info", "Windows 系统任务已禁用（正常，需要时可重新启用）"
            return "low", "计划任务已禁用（不参与自启，如非本人操作请留意）"
        lr = (item.get("last_result") or "").strip().lower()
        if lr and lr != "0x0" and lr != "0" and lr not in _TASK_STATE_CODES:
            return "medium", "上次运行结果异常（%s）" % lr
    return "low", ""


# ------------------------------------------------------------- 重复项检测

def _norm_target(target):
    """把目标路径归一化成可用于比对的形式；裸命令名返回空（不参与比对）。

    比对口径：大小写不敏感（normcase）、统一分隔符（normpath）。
    实测案例：同一台机器 HKCU Run 里同时有 ``vmware-tray`` 与
    ``vmware-tray.exe`` 两条不同名字的值，指向同一个 exe —— 用户想知道
    「为什么托盘里 VMware 图标出现两次」。
    """
    t = (target or "").strip().strip('"')
    if not t:
        return ""
    # 裸命令名（notepad、control 之类，无路径分隔符）不算重复
    if "\\" not in t and "/" not in t:
        return ""
    return os.path.normcase(os.path.normpath(t))


def mark_duplicates(items):
    """就地标出「多个自启项指向同一程序」的重复组。

    规则（宁少勿滥，避免制造新虚警）：
      * 只比对解析出的目标路径（已做环境变量展开与大小写归一）；
      * \\Microsoft\\ 下的系统任务不参与 —— 系统多个任务合法共用同一个
        二进制（如 usoclient、wsqmcons），报出来全是噪音；
      * 整组全部处于禁用状态时不报 —— 都不运行，没有清理价值；
      * 命中的每条记 ``duplicate_count``（该组条目数），由 classify
        在评级时决定是否升级为 medium。
    """
    groups = {}
    for it in items:
        if it.get("dead"):
            continue
        if is_system_task(it):
            continue
        nt = _norm_target(it.get("target"))
        if nt:
            groups.setdefault(nt, []).append(it)
    for members in groups.values():
        if len(members) < 2:
            continue
        if not any(m.get("enabled") is not False for m in members):
            continue
        for m in members:
            m["duplicate_count"] = len(members)
    return items


def enrich_one(it):
    """补「这是什么」：软件名 / 厂商 / 版本 / 脚本摘要 / 文件修改时间。

    只读目标文件自带的版本资源（PE 的 StringFileInfo），不联网、不查库，
    因此对「有版本信息的 exe」几乎百分百准确；脚本则读前几行看它干什么。
    读不到就留空，界面回退显示原始文件名 —— 不做猜测。
    """
    target = (it.get("target") or "").strip()
    if not target:
        return
    try:
        if os.path.isfile(target):
            it["file_mtime"] = datetime.datetime.fromtimestamp(
                os.path.getmtime(target)).strftime("%Y-%m-%d")
    except OSError:
        pass

    fi = FI.read_file_info(target)
    name = fi["file_desc"] or fi["file_product"]
    if name and not name.lower().endswith(".exe"):
        it["app_name"] = name
    if fi["file_company"]:
        it["vendor"] = fi["file_company"]
    if fi["file_version"]:
        it["app_version"] = fi["file_version"].split(" ")[0]

    if it.get("kind") == "script":
        prev = FI.script_preview(target)
        if prev:
            it["preview"] = prev


def build_stats(items):
    """按条目字段直接统计（不重新读文件），供分类与「管理后重算」共用。"""
    stats = {
        "total": len(items),
        "apps": 0,
        "scripts": 0,
        "tasks": 0,
        "registry": 0,
        "folders": 0,
        "gpo": 0,
        "risks": {lvl: 0 for lvl in RISK_LEVELS},
        "dead_count": 0,
        "disabled": 0,
        "duplicates": 0,
    }
    for it in items:
        k = it.get("kind")
        if k == "script":
            stats["scripts"] += 1
        elif k == "app":
            stats["apps"] += 1
        src = it.get("source", "")
        if src == "scheduled_task":
            stats["tasks"] += 1
        elif src in ("registry_user", "registry_machine", "registry_once_user",
                     "registry_once_machine", "registry_gpo"):
            stats["registry"] += 1
        elif src in ("startup_folder", "startup_folder_common"):
            stats["folders"] += 1
        elif src == "gpo_script":
            stats["gpo"] += 1
        level = it.get("risk", "info")
        stats["risks"][level] = stats["risks"].get(level, 0) + 1
        if it.get("dead"):
            stats["dead_count"] += 1
        if it.get("enabled") is False:
            stats["disabled"] += 1
        if it.get("duplicate_count"):
            stats["duplicates"] += 1
    return stats


def recount(items):
    """管理操作（禁用/删除）之后，就地重算统计。

    不能直接再跑一次 classify —— 那会对每条重新读 PE 版本资源，几百条
    要好几秒；此时 risk / kind / source 都已经在条目里了，纯计数即可。
    """
    return build_stats(items)


def classify(items):
    """按风险评级排序并统计。

    返回 (sorted_items, stats)。stats 结构：
        total / apps / scripts / tasks / registry / folders / gpo /
        risks {level: count} / dead_count / disabled / duplicates
    """
    scored = []
    mark_duplicates(items)                      # 先在原始条目上标记重复组
    for it in items:
        it = dict(it)
        enrich_one(it)
        level, reason = risk_of(it)
        # 重复项：比 medium 更轻的（low/info）升级为 medium，
        # 比 medium 更重的（失效/脚本/临时目录）保留原有更高评级
        dup = it.get("duplicate_count") or 0
        if dup > 1 and RISK_LEVELS.index(level) > RISK_LEVELS.index("medium"):
            level = "medium"
            reason = "与另外 %d 个自启项指向同一程序（疑似重复添加，可清理多余项）" % (dup - 1)
        it["risk"] = level
        it["risk_reason"] = reason
        scored.append(it)
    order = {lvl: i for i, lvl in enumerate(RISK_LEVELS)}
    scored.sort(key=lambda x: (order.get(x["risk"], 9),
                               x.get("key", "").lower()))
    return scored, build_stats(scored)


def boot_relevant_tasks(tasks):
    """只留下开机/登录相关的计划任务。"""
    return [t for t in tasks if t.get("start_from")]


def _parse_ev_date(s):
    """把事件日志的时间字符串解析成 datetime；解析失败返回 None。

    wevtutil /f:text 的 Date 形如 ``2026-10-20T12:42:48.1234567``，
    demo 数据是 ``2026/10/19 08:00:00``；两种都要能吃。
    统一丢掉时区信息（同一通道里时区一致，只用于窗口内比差值）。
    """
    s = (s or "").strip()
    if not s:
        return None
    dt = None
    try:
        dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        base = re.sub(r"\.\d+", "", s).replace("T", " ")
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                dt = datetime.datetime.strptime(base, fmt)
                break
            except ValueError:
                continue
    if dt is not None and dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    return dt


# 同一开机过程会产生一串事件（12/6005/6009 在几秒内连续落日志），
# 快速启动+休眠恢复时尤其密集；不合并的话「最近启动」会被同一次开机刷屏。
BOOT_DEDUP_WINDOW = datetime.timedelta(seconds=120)


def recent_boot_events(ev, dedup_window=BOOT_DEDUP_WINDOW):
    """从事件日志结果里挑最近的开机/关机/异常记录（最多 6 条）。

    去重规则：同一条事件 ID 在窗口时间内连续出现多条时只保留一条 ——
    它们属于同一次开机/关机过程，不是多次重启。
    """
    recs = []
    for rec in ev.get("sys_records") or []:
        eid = rec.get("eid")
        if eid in eventlog_mod.SYSTEM_EVENTS:
            label, desc = eventlog_mod.SYSTEM_EVENTS[eid]
            recs.append({
                "date": rec.get("date", ""),
                "eid": eid,
                "label": label,
                "desc": desc,
            })
    # wevtutil 已按时间倒序（/rd:true），同 EID 相邻且时间贴得近的合并
    out = []
    last_kept = {}                       # eid -> 上一条保留记录的时间
    for rec in recs:
        eid = rec.get("eid")
        d = _parse_ev_date(rec.get("date", ""))
        prev = last_kept.get(eid)
        if prev is not None and d is not None:
            delta = abs((prev - d).total_seconds())
            if delta <= dedup_window.total_seconds():
                continue                 # 同一次过程的重复事件，丢弃
        out.append(rec)
        if d is not None:
            last_kept[eid] = d
    return out[:6]


def _extract_task_path(message):
    """从任务计划事件的消息体里抠出任务路径（\\Microsoft\\...\\TaskName）。

    不同事件 ID 的措辞不同，中文是「任务“\\Microsoft\\…”」，英文是
    ``task "\\Microsoft\\…"``；共同点是被引号包住且含反斜杠。
    """
    if not message:
        return ""
    m = re.search(r"[“\"']([^”\"']*\\[^”\"']*)[”\"']", message)
    return m.group(1).strip() if m else ""


def task_failures(ev, tasks=None):
    """计划任务失败/触发异常记录（102 之外的失败类）。

    tasks 传入时会按任务路径关联出「这个任务是干什么的、谁创建的」，
    让计划日志不再是只有一串任务名的天书。
    """
    by_path = {t.get("path", ""): t for t in (tasks or [])}
    out = []
    for rec in ev.get("task_records") or []:
        eid = rec.get("eid")
        if eid in (103, 104, 107, 203, 329):
            msg = rec.get("message", "")
            path = _extract_task_path(msg)
            t = by_path.get(path) or {}
            out.append({
                "date": rec.get("date", ""),
                "eid": eid,
                "label": TASK_FAIL_LABELS.get(eid, "失败"),
                "message": msg,
                "task_path": path,
                "task_name": t.get("key", ""),
                "description": t.get("description", ""),
                "author": t.get("author", ""),
            })
    return out[:10]


TASK_FAIL_LABELS = {
    103: "任务未能启动",
    104: "任务失败（返回码非 0）",
    107: "任务失败",
    203: "任务触发失败",
    329: "任务无法启动",
}


def run_full_scan(progress=None):
    """一次完整扫描：自启项 + 计划任务 + 事件日志 + 系统信息。

    progress(msg, frac) 供 GUI 后台线程汇报。返回 dict：

        {
          "items": [...],        # 全部自启项（含风险评级）
          "tasks": [...],        # 全部计划任务（含评级）
          "events": {...},       # 事件日志原始结果
          "sysinfo": {...},      # 系统信息
          "stats": {...},        # 汇总统计
          "boot_events": [...],  # 最近开机/关机事件
          "task_failures": [...],
          "scanned_at": "…",     # 扫描时间字符串
        }
    """
    import datetime

    def p(msg, frac):
        if progress:
            progress(msg, frac)

    p("开始扫描…", 0.02)
    items_raw = collect_mod.collect(progress=p)
    p("计划任务…", 0.35)
    tasks = tasks_mod.collect(progress=p)
    p("事件日志…", 0.6)
    events = eventlog_mod.collect(progress=p)
    p("系统信息…", 0.85)
    sysinfo = sysinfo_mod.collect()

    # 合并计划任务进 items 统一评级（计划任务单列但同样参与统计）
    items, stats = classify(items_raw + tasks)
    # classify 返回的是条目拷贝；把任务条目的评级同步回原 tasks 列表，
    # 报告的「计划任务」表和界面的任务页才能拿到 risk / risk_reason
    cls_by_path = {}
    for it in items:
        if it.get("source") == "scheduled_task":
            cls_by_path.setdefault(it.get("path") or "", []).append(it)
    for t in tasks:
        for c in cls_by_path.get(t.get("path") or "", []):
            t["risk"] = c.get("risk", "info")
            t["risk_reason"] = c.get("risk_reason", "")
            t["duplicate_count"] = c.get("duplicate_count", 0)
            break                          # 同路径只有一个任务，取首个即可
    boot_events = recent_boot_events(events)
    task_failures_list = task_failures(events, tasks)

    scanned_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "items": items,
        "tasks": tasks,
        "events": events,
        "sysinfo": sysinfo,
        "stats": stats,
        "boot_events": boot_events,
        "task_failures": task_failures_list,
        "scanned_at": scanned_at,
    }
