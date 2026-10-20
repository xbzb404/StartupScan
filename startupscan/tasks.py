# -*- coding: utf-8 -*-
"""采集层：计划任务（任务计划程序）。

数据来源：
  * ``TaskCache\\Tasks\\<GUID>`` —— 每个任务一行：
      - Path：任务完整路径（取末段作显示名）
      - Actions：二进制编码的执行命令（UTF-16 嵌入可执行路径与参数）
      - Triggers：二进制触发器定义（触发类型用 TaskCache 的 Boot/Logon 分组）
  * ``TaskCache\\Boot`` / ``TaskCache\\Logon`` —— 触发类型分组：
      子键名 = 任务的 GUID，直接给出「开机触发 / 登录触发」的任务集合，
      比解析 Triggers 二进制快且稳。
  * ``%SystemRoot%\\System32\\Tasks\\<路径>`` —— 任务的 XML 定义文件，
      **唯一能拿到「谁创建的、干什么用的、以谁的身份运行、是否禁用」的地方**：
      ``<Author>`` / ``<Description>`` / ``<UserId>`` / ``<RunLevel>`` /
      ``<Settings><Enabled>``。注册表里没有这些值（实测 Tasks 下只有
      Path / Actions / Triggers / Schema 等二进制）。
  * ``schtasks /query`` —— 仅作为「上次运行时间 / 上次结果 / 下次运行」的
      补充数据源；拿不到（被策略拦、语言差异）时这些字段留空，不影响主流程。

每条任务归一化成 dict（字段与自启项对齐，便于界面统一渲染）：
    key         显示名（Path 末段）
    name        同上
    path        完整任务路径
    command     执行命令（原始）
    target      解析后的目标路径
    kind        app / script / other
    trigger     触发器中文描述
    trigger_raw 触发类型列表（boot / logon / time / …）
    enabled     是否启用（优先取任务 XML 的 <Enabled>，其次 schtasks）
    author      创建者（XML <Author>，常是公司名或用户名）
    description 任务作用（XML <Description>）
    run_as      运行身份（XML <UserId>）
    run_level   运行级别（HighestAvailable / LeastPrivilege）
    last_run / last_result / next_run   上次/下次运行信息
    location    固定为「任务计划程序」
    source      scheduled_task
    start_from  是否开机/登录触发（来自 Boot/Logon 分组）
"""

import os
import re
import subprocess
import winreg
import xml.etree.ElementTree as ET

from . import cmdparse as C
from . import fileinfo as F
from .winutil import run_hidden

_TASK_CACHE = (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
               winreg.HKEY_LOCAL_MACHINE)

# 任务 XML 定义所在目录（每个任务一个文件，路径与任务路径一一对应）
_TASKS_DIR = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                          "System32", "Tasks")

TRIGGER_LABELS = {
    "boot": "开机时",
    "logon": "用户登录时",
    "time": "按计划时间",
    "unknown": "未知触发器",
}


def _open_key(hive, path):
    try:
        return winreg.OpenKey(hive, path)
    except OSError:
        return None


def _query_value(key, name):
    try:
        return winreg.QueryValueEx(key, name)
    except OSError:
        return None


def _iter_subkeys(hive, path):
    out = []
    try:
        key = winreg.OpenKey(hive, path)
    except OSError:
        return out
    try:
        i = 0
        while True:
            try:
                out.append(winreg.EnumKey(key, i))
            except OSError:
                break
            i += 1
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass
    return out


def _principal_end(b):
    """返回 principal 字符串之后的偏移；结构不符返回 -1。

    实测头部布局（LE）::

        03 00 | <principal 字节长度 u16> | 00 00 | <principal UTF-16>

    两个真实样例：

    * ``03 00 0c 00 00 00`` + ``Author``(12 字节)  → 18
    * ``03 00 16 00 00 00`` + ``LocalSystem``(22 字节) → 28

    按头部长度跳过，比直接 find("Author") 通用：principal 可能是用户名、
    ``LocalSystem`` 或其它账号名，写死 "Author" 会漏掉系统任务。
    """
    if len(b) < 6 or b[0] != 0x03:
        return -1
    n = int.from_bytes(b[2:4], "little")
    end = 6 + n
    if 0 < n <= 256 and end <= len(b):
        return end
    return -1


def _actions_to_command(actions_bytes):
    """把 Actions 二进制解码成 (command, arguments)。

    TaskCache 的 Actions 是自定义二进制，实测布局：
        03 00 0c 00 00 00 ... 'Author'(UTF-16) ... ff ff 00 00 00 00
        [命令长度 u16 LE]  [命令 UTF-16 × len]  [\x00 填充]  可能还有参数段
    策略：定位 "Author"，在其后逐个尝试 [len_lo 00 len_hi 00] 模式，
    按长度取 UTF-16 串，命中「含盘符路径」即认为命令。参数段常见于
    Actions 更长的任务（Firefox 的 --MOZ_LOG 等），这里把命令后剩余
    可读串合并为参数。
    """
    if not actions_bytes:
        return "", ""
    b = actions_bytes
    p = _principal_end(b)
    if p < 0:
        # 头部结构不符：退回以 "Author" 为锚点
        idx = b.find(b"A\x00u\x00t\x00h\x00o\x00r\x00")
        if idx < 0:
            return _fallback_command(b)
        p = idx + 14          # "Author"(12) + 2 个尾字节
    # 从 p 起逐个试探长度头：len_hi 为 0 且 len_lo 在合理范围
    while p + 4 <= len(b):
        lo, hi = b[p], b[p + 1]
        if hi == 0 and 0 < lo < 600:
            q = p + 4
            end = q + lo          # 实测：长度单位是「UTF-16 编码后的字节数」
            if end <= len(b):
                cmd = b[q:end].decode("utf-16-le", errors="ignore")
                cmd = cmd.rstrip("\x00 ").strip()
                # 去掉尾部可能混入的控制字符 / 长度字节残留
                cmd = re.sub(r"[\x00-\x1f\x7f]+$", "", cmd).strip()
                # 去掉尾部可能粘上的「下一字段长度字节」（$ : 等单字符残留）
                cmd = re.sub(r"[$:;,]*$", "", cmd).strip()
                # 命令必须以盘符（C:\）、%VAR% 或引号包裹的同类路径**开头**。
                # 用 match 而非 search：search 会被二进制里的 GUID 片段骗到
                # （实测 RemoteAssistanceTask 曾解出 "47cd-...%windir%\system"）。
                if re.match(r'^["\']?(?:[A-Za-z]:\\|%[A-Za-z0-9_()]+%)', cmd):
                    # 命令之后（剩余部分）尽量补成参数
                    rest = b[end:]
                    args = _rest_to_args(rest)
                    return cmd, args
        p += 2
    return _fallback_command(b)


def _fallback_command(b):
    """兜底：UTF-16 解码后找第一个含可执行扩展名或环境变量的串。"""
    text = b.decode("utf-16-le", errors="ignore")
    m = re.search(r'(["\']?(?:[A-Za-z]:\\|%[A-Za-z0-9_()]+%\\)'
                  r'[^\x00"\']+?\.(?:exe|bat|cmd|ps1|vbs|com|dll)'
                  r"[^\x00]*)", text)
    if m:
        return _split_cmd_args(m.group(1).strip())
    return "", ""


def _rest_to_args(rest):
    """把命令后的剩余二进制转成参数串（可能有多个命令段，取第一个可读的）。"""
    if not rest:
        return ""
    # 剩余段可能也是 [len u16] + utf16 参数，也可能只是填充
    text = rest.decode("utf-16-le", errors="ignore")
    # 长度头/枚举的低字节会以控制字符形式混进来（如 \x10），先清掉再匹配，
    # 否则参数字符串里会夹着看不见的方块。
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    text = re.sub(r"\s{2,}", " ", text).strip()
    # 去掉纯数字长度头残留
    m = re.search(r"(?<![A-Za-z0-9_\-:.\\])([\-\/][^\s]+(?:\s+[^\s]+){0,6})", text)
    if not m:
        return ""
    args = m.group(1).strip()
    # 参数段后面常紧跟「下一段的路径」（%windir%\… 或 C:\…），那不属于参数
    args = re.split(r"\s+(?=(?:[A-Za-z]:\\|%[A-Za-z0-9_()]+%))", args)[0]
    return args.strip()


def _split_cmd_args(full):
    """把「命令 参数」拆开：命令带引号则整体算一段。"""
    full = full.strip()
    if not full:
        return "", ""
    if full.startswith('"'):
        end = full.find('"', 1)
        if end > 0:
            cmd = full[1:end]
            args = full[end + 1:].strip()
            return cmd, args
    parts = full.split(None, 1)
    cmd = parts[0]
    args = parts[1] if len(parts) > 1 else ""
    return cmd, args


def _read_task_xml(path):
    """读任务的 XML 定义，返回创建者 / 作用 / 运行身份 / 是否禁用。

    文件位置：``%SystemRoot%\\System32\\Tasks\\<任务路径>``（与任务路径一一对应）。
    这是唯一能拿到这些信息的地方 —— 注册表的 ``Tasks\\<GUID>`` 下没有
    Author / Description 值（实测只有 Path / Actions / Triggers / Schema）。

    返回 dict：
        author       创建者（多为公司名，如 "Microsoft Corporation"）
        description  任务作用（如 "此任务会更新 Windows 的 ... 信息"）
        user_id      运行身份（SID 或用户名，SYSTEM 为 S-1-5-18）
        run_level    HighestAvailable / LeastPrivilege
        enabled      True / False / None（None = XML 里没写，按启用处理）
        date         注册时间

    读不到（权限不足 / 文件不存在 / 非 XML）时字段留空，不抛异常。
    """
    out = {"author": "", "description": "", "user_id": "", "run_level": "",
           "enabled": None, "date": ""}
    if not path:
        return out
    full = os.path.join(_TASKS_DIR, path.strip("\\"))
    text = ""
    # 任务 XML 一般是 UTF-16（带 BOM），个别工具写的是 UTF-8
    for enc in ("utf-16", "utf-8-sig", "utf-8"):
        try:
            with open(full, "r", encoding=enc) as fp:
                text = fp.read()
            break
        except (OSError, UnicodeError):
            continue
    if not text:
        return out

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out

    def pick(tag):
        """按标签名取值（忽略命名空间）。"""
        for el in root.iter():
            if el.tag.rsplit("}", 1)[-1] == tag:
                return (el.text or "").strip()
        return ""

    # 系统任务存的是资源引用 $(@dll,-id)，需要解一层才是人话
    out["author"] = F.describe_resource(pick("Author"))
    out["description"] = F.describe_resource(pick("Description"))
    out["user_id"] = pick("UserId")
    out["run_level"] = pick("RunLevel")
    out["date"] = pick("Date")

    # 只认 <Settings><Enabled>，避免误取触发器里同名的 Enabled
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1] != "Settings":
            continue
        for ch in list(el):
            if ch.tag.rsplit("}", 1)[-1] == "Enabled":
                val = (ch.text or "").strip().lower()
                if val in ("true", "false"):
                    out["enabled"] = (val == "true")
                break
        break
    return out


def _task_cache_scan():
    """读注册表 TaskCache，返回 (tasks, boot_guids, logon_guids)。

    tasks: [{name, path, guid, command, arguments, author, description}]
    """
    cache_path, hive = _TASK_CACHE
    cache = _open_key(hive, cache_path)
    if cache is None:
        return [], set(), set()

    # 触发类型分组（子键名 = 任务 GUID）
    boot_guids = set()
    logon_guids = set()
    for group, target in (("Boot", boot_guids), ("Logon", logon_guids)):
        for g in _iter_subkeys(hive, cache_path + "\\" + group):
            target.add(g)

    tasks = []
    try:
        tasks_key = winreg.OpenKey(cache, "Tasks")
    except OSError:
        return [], boot_guids, logon_guids
    try:
        i = 0
        while True:
            try:
                guid = winreg.EnumKey(tasks_key, i)
            except OSError:
                break
            i += 1
            try:
                tk = winreg.OpenKey(tasks_key, guid)
            except OSError:
                continue
            try:
                path_val = _query_value(tk, "Path")
                actions_val = _query_value(tk, "Actions")
            finally:
                winreg.CloseKey(tk)
            path = (path_val[0] if path_val else "") or ""
            if not path:
                continue
            cmd, args = _actions_to_command(
                actions_val[0] if actions_val else b"")
            # 创建者 / 作用 / 运行身份 / 是否禁用只存在于任务 XML 文件里
            meta = _read_task_xml(path)
            tasks.append({
                "guid": guid,
                "path": path,
                "name": os.path.basename(path.strip("\\")) or guid,
                "command": cmd,
                "arguments": args,
                "author": meta["author"],
                "description": meta["description"],
                "user_id": meta["user_id"],
                "run_level": meta["run_level"],
                "enabled_xml": meta["enabled"],
            })
        winreg.CloseKey(tasks_key)
    except OSError:
        pass
    return tasks, boot_guids, logon_guids


def _schtasks_status():
    """schtasks /query /fo csv 一次性读状态表（补充数据源）。

    返回 {任务路径: {...}}；拿不到（被策略拦/语言差异）时返回空 dict。
    """
    out = {}
    try:
        proc = run_hidden(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            capture_output=True, timeout=30)
    except Exception:
        return out
    if proc.returncode != 0:
        return out
    raw = proc.stdout
    try:
        text = raw.decode("gbk", "ignore")
    except Exception:
        text = raw.decode("utf-8", "ignore")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return out
    header = [h.strip() for h in lines[0].split(",")]

    def col(row, *names):
        for i, h in enumerate(header):
            for n in names:
                if h == n or n in h:
                    return row[i] if i < len(row) else ""
        return ""

    for line in lines[1:]:
        row = line.split(",")
        if len(row) < 3:
            continue
        path = row[0].strip()
        out[path] = {
            "status": col(row, "状态", "Status"),
            "last_run": col(row, "上次运行时间", "Last Run Time"),
            "last_result": col(row, "上次结果", "Last Result"),
            "next": col(row, "下次运行时间", "Next Run Time"),
        }
    return out


def _trigger_label(guid, boot_guids, logon_guids):
    """按触发类型分组给任务打中文触发器描述。"""
    if guid in boot_guids:
        return "开机时"
    if guid in logon_guids:
        return "用户登录时"
    return "按计划时间"


def collect(progress=None):
    """采集全部计划任务。返回 tasks 列表。"""
    if progress:
        progress("读取计划任务定义…", 0.2)
    raw_tasks, boot_guids, logon_guids = _task_cache_scan()

    if progress:
        progress("读取任务运行状态…", 0.55)
    status_map = _schtasks_status()

    items = []
    for t in raw_tasks:
        key = t["path"]
        st = status_map.get(key) or {}
        status = st.get("status") or ""
        # 启用状态：任务 XML 的 <Settings><Enabled> 最权威（注册表无 State 值），
        # 没有显式写 Enabled 时再退回 schtasks 的状态列
        enabled = t.get("enabled_xml")
        if enabled is None:
            enabled = status in ("已启用", "已就绪", "Ready", "Enabled",
                                 "已启动") if status else True
        cmd = t["command"]
        args = t["arguments"]
        full = (cmd + (" " + args if args else "")).strip()
        # 兜底清洗：命令串里残留的控制字符（长度头低字节）会让界面出现方块
        full = re.sub(r"[\x00-\x1f\x7f]", "", full).strip()
        parsed = C.parse_command(full)
        is_boot = t["guid"] in boot_guids
        is_logon = t["guid"] in logon_guids
        trigger = "开机时" if is_boot else ("用户登录时" if is_logon
                                           else "按计划时间")
        kinds = []
        if is_boot:
            kinds.append("boot")
        if is_logon:
            kinds.append("logon")
        if not kinds:
            kinds.append("time")
        items.append({
            "key": t["name"],
            "name": t["name"],
            "path": key,
            "command": full,
            "target": parsed.get("target") or "",
            "kind": C.kind_of(parsed.get("target") or "", cmd) if cmd
            else "other",
            "trigger": trigger,
            "trigger_raw": kinds,
            "enabled": enabled,
            "last_run": st.get("last_run") or "",
            "last_result": st.get("last_result") or "",
            "next_run": st.get("next") or "",
            "author": t.get("author", ""),
            "description": t.get("description", ""),
            "run_as": t.get("user_id", ""),
            "run_level": t.get("run_level", ""),
            "location": "任务计划程序",
            "source": "scheduled_task",
            "managed_by": "scheduled_task",
            "dead": False,
            "dead_reason": "",
            "suspicious": False,
            "exists": parsed.get("exists"),
            "start_from": is_boot or is_logon,
        })
    if progress:
        progress("计划任务采集完成（%d 条）" % len(items), 1.0)
    return items
