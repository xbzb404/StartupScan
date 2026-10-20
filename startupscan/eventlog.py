# -*- coding: utf-8 -*-
"""采集层：事件日志（计划任务历史 + 系统启动/关机）。

用系统自带 ``wevtutil`` 查询两个通道，不引入第三方依赖：
  * Microsoft-Windows-TaskScheduler/Operational
        —— 计划任务触发(200)、成功(102)、失败(103/201)等；
  * System
        —— 事件 ID 6005（事件日志服务启动）、6009（系统启动版本）、
          6013（运行时长）、12/13（内核开机/关机）、42（休眠/唤醒）等。

wevtutil 的输出编码按系统代码页（中文 Windows = GBK）解码。
"""

import subprocess

from .winutil import run_hidden

LOG_SYSTEM = "System"
LOG_TASK = "Microsoft-Windows-TaskScheduler/Operational"

# 计划任务日志事件
TASK_EVENTS = {
    102: ("完成", "任务已完成运行"),
    103: ("失败", "任务未能启动"),
    104: ("失败", "任务失败：返回码非 0"),
    106: ("完成", "任务已完成（上次结果 0）"),
    107: ("失败", "任务失败"),
    200: ("触发", "任务已触发"),
    201: ("触发", "任务已触发（因错过）"),
    203: ("失败", "任务触发失败"),
    329: ("失败", "任务无法启动"),
}

SYSTEM_EVENTS = {
    6005: ("启动", "事件日志服务已启动"),
    6006: ("关机", "事件日志服务已停止（正常关机）"),
    6008: ("异常", "系统未正常关机（意外断电/强制重启）"),
    6009: ("信息", "系统启动（含版本与 CPU 信息）"),
    6013: ("信息", "系统运行时长（秒）"),
    12: ("启动", "操作系统已启动"),
    13: ("关机", "操作系统已关机"),
    42: ("电源", "系统已进入睡眠/从睡眠恢复"),
    1074: ("关机", "系统已计划重启/关机（原因代码）"),
}

TRUNCATE = 200          # 每条通道最多取的记录数
QUERY_TIMEOUT = 45


def _query(log, xpath, timeout=QUERY_TIMEOUT):
    """用 wevtutil 查一条通道，返回 (lines, error)。"""
    cmd = ["wevtutil", "qe", log, "/q:" + xpath, "/f:text",
           "/c:" + str(TRUNCATE), "/rd:true"]
    try:
        proc = run_hidden(cmd, capture_output=True, timeout=timeout)
    except Exception as exc:
        return [], "调用 wevtutil 失败：%s" % exc
    if proc.returncode != 0:
        err = proc.stderr.decode("gbk", "ignore").strip()
        return [], err or "wevtutil 返回码 %d" % proc.returncode
    raw = proc.stdout
    try:
        text = raw.decode("gbk", "ignore")
    except Exception:
        text = raw.decode("utf-8", "ignore")
    return text.splitlines(), ""


def _parse_records(lines):
    """把 wevtutil 文本输出切成记录列表（每条记录一个 dict）。

    wevtutil /f:text 的记录格式：
        Event[0]:
           Log Name: ...
           Source: ...
           Date: 2024-...
           Event ID: 200
           ...
           Message:
             ...
             （到下一个 Event[ 为止）
    """
    records = []
    cur = None
    for ln in lines:
        if ln.startswith("Event["):
            if cur is not None:
                records.append(cur)
            cur = {"lines": [ln]}
        elif cur is not None:
            cur["lines"].append(ln)
    if cur is not None:
        records.append(cur)
    out = []
    for rec in records:
        parsed = _parse_record(rec["lines"])
        if parsed:
            out.append(parsed)
    return out


def _parse_record(lines):
    """从单条记录的行里抽字段。"""
    rec = {}
    msg = []
    in_msg = False
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("Date:"):
            rec["date"] = s[len("Date:"):].strip()
            continue
        if s.startswith("Event ID:"):
            try:
                rec["eid"] = int(s[len("Event ID:"):].strip())
            except ValueError:
                rec["eid"] = None
            continue
        if s.startswith("Source:"):
            rec["source"] = s[len("Source:"):].strip()
            continue
        if s.startswith("Message:"):
            in_msg = True
            continue
        if in_msg:
            # 下一条字段以 "  键: " 开头（三个空格缩进）则消息结束
            if re_match_field(s):
                in_msg = False
            else:
                msg.append(s)
    if msg:
        rec["message"] = "\n".join(msg).strip()
    return rec


def re_match_field(s):
    """判断一行是否像字段行（用于在 Message 里识别字段边界）。"""
    import re
    return bool(re.match(r"^[A-Z][A-Za-z ]+:\s", s))


def _record_date(rec):
    return rec.get("date", "")


def query_task_history(progress=None):
    """查询计划任务触发/完成/失败记录。

    返回 (records, notes)：records 为解析后的记录列表，
    notes 为采集过程中的说明（如「无权限」「通道为空」）。
    """
    xpath = "*[System[(EventID=200 or EventID=102 or EventID=103 or " \
            "EventID=104 or EventID=201 or EventID=203 or EventID=329)]]"
    if progress:
        progress("查询计划任务历史日志…", 0.2)
    lines, err = _query(LOG_TASK, xpath)
    notes = []
    if err:
        notes.append("计划任务历史日志不可读：%s" % err)
        return [], notes
    records = _parse_records(lines)
    notes.append("计划任务历史：%d 条" % len(records))
    return records, notes


def query_system_events(progress=None):
    """查询系统启动/关机/运行时长事件。

    返回 (records, notes)。
    """
    eids = " or ".join("EventID=%d" % e for e in SYSTEM_EVENTS)
    xpath = "*[System[%s]]" % eids
    if progress:
        progress("查询系统启动/关机日志…", 0.5)
    lines, err = _query(LOG_SYSTEM, xpath)
    notes = []
    if err:
        notes.append("系统日志不可读：%s" % err)
        return [], notes
    records = _parse_records(lines)
    notes.append("系统事件：%d 条" % len(records))
    return records, notes


def collect(progress=None):
    """采集两路事件日志，返回统一 dict：

        {
          "task_records": [...],   # 计划任务历史记录
          "task_notes": [...],
          "sys_records": [...],    # 系统启动/关机记录
          "sys_notes": [...],
          "boot_time": "…",        # 最近一次系统启动时间（取自 6009/12）
          "uptime": "…",           # 当前运行时长
        }
    """
    if progress:
        progress("查询事件日志…", 0.1)
    task_records, task_notes = query_task_history(progress)
    sys_records, sys_notes = query_system_events(progress)
    boot_time, uptime = _system_boot(sys_records)
    return {
        "task_records": task_records,
        "task_notes": task_notes,
        "sys_records": sys_records,
        "sys_notes": sys_notes,
        "boot_time": boot_time,
        "uptime": uptime,
    }


def _system_boot(sys_records):
    """从系统事件里取最近一次开机时间与运行时长。"""
    boot_time = ""
    uptime = ""
    # 取时间最近的 6009/12 作为开机时间；6013 作为运行时长
    for rec in sys_records:
        eid = rec.get("eid")
        if eid in (6009, 12) and not boot_time:
            boot_time = rec.get("date", "")
        if eid == 6013 and not uptime:
            msg = rec.get("message", "")
            for token in msg.split():
                if token.isdigit():
                    uptime = _human_seconds(int(token))
                    break
    return boot_time, uptime


def _human_seconds(secs):
    """把秒数格式化成「N 天 N 小时 N 分钟」。"""
    try:
        secs = int(secs)
    except (TypeError, ValueError):
        return ""
    if secs < 0:
        return ""
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    parts = []
    if d:
        parts.append("%d 天" % d)
    if h:
        parts.append("%d 小时" % h)
    if m or not parts:
        parts.append("%d 分钟" % m)
    return " ".join(parts)
