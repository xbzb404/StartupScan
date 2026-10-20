# -*- coding: utf-8 -*-
"""命令 / 路径解析公共工具：环境变量展开、路径规范化、失效检测。

开机自启项的命令五花八门：有的带引号、有的用 %SystemRoot% 之类环境变量、
有的写成 `rundll32 xxx.dll,Entry`、还有的是没有扩展名的脚本。这里统一处理成
「尽量可读 + 可点击打开」的形式，并尽力判断目标文件是否还存在。
"""

import os
import re
import subprocess

_WIN_ENV = {
    "WINDIR": "C:\\Windows",
    "SYSTEMROOT": "C:\\Windows",
    "SystemRoot": "C:\\Windows",
    "ProgramFiles": "C:\\Program Files",
    "ProgramFiles(x86)": "C:\\Program Files (x86)",
    "ProgramData": "C:\\ProgramData",
    "APPDATA": "C:\\Users\\<USER>\\AppData\\Roaming",
    "LOCALAPPDATA": "C:\\Users\\<USER>\\AppData\\Local",
    "USERPROFILE": "C:\\Users\\<USER>",
    "HOMEDRIVE": "C:",
    "HOMEPATH": "\\Users\\<USER>",
    "PUBLIC": "C:\\Users\\Public",
    "USERNAME": "<USER>",
    "COMPUTERNAME": "<HOST>",
    "COMSPEC": "C:\\Windows\\System32\\cmd.exe",
    "TEMP": "C:\\Users\\<USER>\\AppData\\Local\\Temp",
    "TMP": "C:\\Users\\<USER>\\AppData\\Local\\Temp",
}

# 值里出现这些就可以判定为「该自启项大概率已失效/不完整」（大小写不敏感）
_DEAD_MARKERS = [
    "file not found",
    "system cannot find",
    "指定的文件不存在",
    "系统找不到",
    "（空）",
    "(null)",
    "nonexistent",
    "does not exist",
    "找不到",
]


def expand_env(text):
    """展开命令串里的 %VAR% 环境变量。

    不直接用 os.path.expandvars：很多自启命令是给 cmd 解释的，变量写法
    五花八门（%X%、% X %、%%X%%），而 ``expandvars`` 遇到未定义变量会
    静默丢弃。这里逐段把已定义/已知的变量展开，未定义的保留原样，
    方便用户看出「这行引用了哪个变量」。
    """
    if not text:
        return text

    def repl(m):
        name = m.group(1).strip()
        if not name:
            return m.group(0)
        # 优先真实环境，其次内置兜底表（用户目录等拿不到时就近似）
        v = os.environ.get(name)
        if v is None and name in _WIN_ENV:
            v = _WIN_ENV[name]
        return v if v is not None else m.group(0)

    return re.sub(r"%([^%]+)%", repl, text)


def _strip_quotes(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s


def _first_exe(text):
    """从命令串里挑出第一个「像可执行文件」的片段（去掉参数）。

    兼容常见写法：``"C:\\a b\\x.exe" -k``、``C:\\a b\\x.exe /s``、
    ``rundll32 shell32.dll,Control_RunDLL ...``、裸文件名 ``notepad``。

    关键：未加引号的路径可能含空格（``C:\\Program Files (x86)\\...\\x.exe``），
    不能按空格切分，否则会截断在 ``C:\\Program``。这里逐词累积，直到
    累积结果以可执行扩展名结尾为止。
    """
    t = text.strip()
    if not t:
        return ""
    # 带引号的可执行文件
    m = re.match(r'^"([^"]+)"', t)
    if m:
        return _strip_quotes(m.group(1))
    # 未加引号：逐词累积，命中可执行扩展名即返回
    tokens = t.split()
    exts = (".exe", ".bat", ".cmd", ".com", ".vbs", ".ps1", ".lnk", ".scr",
            ".msi", ".jar", ".dll")
    acc = ""
    for tok in tokens:
        acc = tok if not acc else acc + " " + tok
        # 去掉可能粘在结尾的标点再判断
        probe = acc.rstrip('";\',')
        if probe.lower().endswith(exts):
            return probe
        # 累积段已经不是路径形状（无盘符/无变量前缀）且尚未命中扩展名，
        # 说明开头是命令名，立即返回第一段
        if not re.match(r"^([A-Za-z]:|%[A-Za-z0-9_()]+%)", acc):
            break
    # rundll32 等：第二段是 dll，交给调用方判定
    if t.lower().startswith("rundll32"):
        parts = t.split(",")
        return (parts[0] + "," + parts[1]).strip() if len(parts) > 1 else t
    # 裸命令名
    m = re.match(r"^(\S+)", t)
    return m.group(1) if m else ""


def resolve_path(text):
    """把命令串解析成「目标可执行文件/文件」的绝对路径，失败返回空串。

    规则：
      1. 先做 %VAR% 展开；
      2. 取第一个可执行片段；
      3. 若片段里含环境变量展开后的路径且存在，直接返回；
      4. 带引号路径直接用；
      5. 纯文件名时去 PATH 里找（找不到不报错，返回原样）；
      6. rundll32 这类入口保留原串，交给失效判定处理。
    """
    if not text:
        return ""
    raw = _first_exe(text)
    if not raw:
        return ""
    expanded = expand_env(raw)
    candidates = []

    q = _strip_quotes(expanded)
    if q:
        candidates.append(q)

    # 引号内还可能残留未展开的变量（如 %ProgramFiles%）
    q2 = expand_env(q)
    if q2 != q:
        candidates.append(q2)

    for c in candidates:
        c = c.strip()
        if not c:
            continue
        if os.path.sep in c or c.startswith("%") or re.match(r"^[A-Za-z]:", c):
            if os.path.isfile(c):
                return os.path.normpath(c)
            # 相对路径常见于从启动目录读取：相对的是 cwd，尝试补全
            if os.path.isfile(c) is False and os.path.isabs(c):
                continue
            return os.path.normpath(c) if os.path.isabs(c) else c

    # 裸命令名走 PATH
    if not re.match(r"^[A-Za-z]:", q):
        found = _which(q)
        if found:
            return os.path.normpath(found)
        return q
    return q


def _which(name):
    """在 PATH 里找可执行文件（Windows 附加 PATHEXT 后缀）。"""
    if not name:
        return None
    exts = (os.environ.get("PATHEXT") or ".EXE;.BAT;.CMD;.COM").split(";")
    for d in (os.environ.get("PATH") or "").split(os.pathsep):
        d = d.strip('"')
        if not d:
            continue
        for ext in exts:
            p = os.path.join(d, name + ("" if ext.lower() in
                                        name.lower()[-4:] else ext))
            if os.path.isfile(p):
                return p
    return None


def exists_on_disk(path):
    """判断解析出的目标是否真实存在（纯命令名给 None 表示「无法判定」）。"""
    if not path:
        return False
    try:
        return os.path.exists(path)
    except Exception:
        return False


def looks_dead(raw, path, exists):
    """综合判断一个自启项是否「已失效/可疑」。

    返回 (is_dead, reason)。判据：
      * 目标解析出来但文件不存在 → 失效
      * 命令里出现明显的「找不到」标记 → 失效
      * 目标在临时目录 / 下载目录 / 回收站 → 可疑（常见于下载即运行的程序）
      * 目标是脚本（bat/cmd/vbs/ps1）→ 提示脚本类（见 collect.kind）
    """
    low = (raw or "").lower()
    for marker in _DEAD_MARKERS:
        if marker in low:
            return True, "命令里包含错误提示：%s" % marker
    if path and exists is False:
        # 裸命令名（无路径分隔符、非绝对路径）可能通过 PATH 解析，
        # 无法可靠判定失效，保守按「存活」处理
        if _is_bare_command(path):
            return False, ""
        return True, "目标文件不存在"
    return False, ""


def _is_bare_command(path):
    """「解析出来但没有完整路径」的命令名（纯文件名，可能通过 PATH 解析）。"""
    if not path:
        return False
    if os.path.sep in path or os.path.isabs(path) or re.match(r"^[A-Za-z]:", path):
        return False
    return True


def in_temp_dir(path):
    """目标是否位于临时/下载/回收站这类「一次性质」目录。"""
    if not path:
        return False
    low = path.lower()
    marks = ["\\temp", "\\tmp", "\\downloads", "\\$recycle.bin",
             "\\appdata\\local\\temp", "%temp%"]
    return any(m in low for m in marks)


SCRIPT_EXTS = {".bat", ".cmd", ".vbs", ".ps1", ".js", ".vbe", ".wsf"}


def kind_of(path, raw):
    """判定自启项类型：app（应用程序）/ script（脚本）/ dll / other。"""
    low_raw = (raw or "").lower()
    if low_raw.startswith("rundll32"):
        return "dll"
    if path:
        ext = os.path.splitext(path)[1].lower()
        if ext in SCRIPT_EXTS:
            return "script"
        if ext in (".exe", ".com", ".scr", ".msi", ".jar"):
            return "app"
        if ext == ".dll":
            return "dll"
    if low_raw.endswith((".bat", ".cmd", ".vbs", ".ps1")):
        return "script"
    return "app"


def parse_command(raw):
    """一次解析命令串，返回 dict：

        raw          原始命令
        expanded     展开 %VAR% 后的文本
        target       解析出的目标路径（可能为空）
        kind         app / script / dll / other
        exists       True/False（无法判定时 False）
        dead         是否判定为失效
        dead_reason  失效原因
        suspicious   是否命中临时/下载目录等可疑特征
    """
    expanded = expand_env(raw)
    target = resolve_path(raw)
    exists = exists_on_disk(target)
    dead, reason = looks_dead(raw, target, exists)
    suspicious = in_temp_dir(target)
    return {
        "raw": raw or "",
        "expanded": expanded,
        "target": target,
        "kind": kind_of(target, raw),
        "exists": exists,
        "dead": dead,
        "dead_reason": reason,
        "suspicious": suspicious,
    }


def open_in_explorer(path):
    """在资源管理器中选中该文件（供界面「定位文件」按钮使用）。"""
    if not path:
        return False
    try:
        subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        return True
    except Exception:
        return False
