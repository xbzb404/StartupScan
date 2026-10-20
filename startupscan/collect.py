# -*- coding: utf-8 -*-
"""采集层：注册表 Run 键 + 启动文件夹 + 组策略启动脚本。

扫描范围（Windows 10 / 11 通用）：
  1. 注册表 Run / RunOnce 键：
       HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
       HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
       HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run
       HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
       HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
       (加上 Policies\\Explorer\\Run 组策略入口)
  2. 启动文件夹：
       用户启动目录  %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup
       公共启动目录  %ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp
  3. 组策略「计算机启动/关机」与「用户登录/注销」脚本（.bat/.cmd/.ps1）

每条自启项归一化成同一份 dict：
    key        显示名（注册表值名 / 文件名 / 组策略脚本名）
    kind       app / script / dll / other
    source     来源分类：registry_user / registry_machine / startup_folder /
                startup_folder_common / gpo_script
    location   人类可读的「位置说明」
    raw        原始命令或完整脚本路径
    ...        见 cmdparse.parse_command 的字段
    enabled    是否启用（RunOnce 标记为一次性，注册表本身无禁用概念，
               统一 True；禁用状态主要来自计划任务与启动文件夹）
"""

import os
import winreg

from . import cmdparse as C
from . import manage

# 来源 → 中文说明（界面/报告共用）
SOURCE_LABELS = {
    "registry_user": "当前用户注册表 Run",
    "registry_machine": "本机注册表 Run",
    "registry_once_user": "当前用户 RunOnce（一次性）",
    "registry_once_machine": "本机 RunOnce（一次性）",
    "registry_gpo": "组策略 Run",
    "startup_folder": "用户启动文件夹",
    "startup_folder_common": "公共启动文件夹",
    "gpo_script": "组策略启动/登录脚本",
}

_RUN_KEYS = [
    ("registry_machine",
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     winreg.HKEY_LOCAL_MACHINE),
    ("registry_machine",
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
     winreg.HKEY_LOCAL_MACHINE),
    ("registry_once_machine",
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
     winreg.HKEY_LOCAL_MACHINE),
    ("registry_once_machine",
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
     winreg.HKEY_LOCAL_MACHINE),
    ("registry_user",
     r"Software\Microsoft\Windows\CurrentVersion\Run",
     winreg.HKEY_CURRENT_USER),
    ("registry_once_user",
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     winreg.HKEY_CURRENT_USER),
    ("registry_gpo",
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
     winreg.HKEY_CURRENT_USER),
    ("registry_gpo",
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
     winreg.HKEY_LOCAL_MACHINE),
]

_GPO_SCRIPT_SUBKEYS = [
    (r"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup",
     winreg.HKEY_LOCAL_MACHINE, "计算机启动脚本"),
    (r"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown",
     winreg.HKEY_LOCAL_MACHINE, "计算机关机脚本"),
    (r"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon",
     winreg.HKEY_CURRENT_USER, "用户登录脚本"),
    (r"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff",
     winreg.HKEY_CURRENT_USER, "用户注销脚本"),
]

_STARTUP_FOLDER = (
    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
    r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp",
)


def _iter_values(hive, path):
    """遍历注册表键下的所有值，返回 (name, value, vtype) 列表；失败返回空。"""
    out = []
    try:
        key = winreg.OpenKey(hive, path)
    except OSError:
        return out
    try:
        i = 0
        while True:
            try:
                name, value, vtype = winreg.EnumValue(key, i)
            except OSError:
                break
            out.append((name, value, vtype))
            i += 1
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass
    return out


def _iter_subkeys(hive, path):
    """返回子键名列表；失败返回空。"""
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


def _reg_value_to_str(value, vtype):
    """注册表值转字符串（REG_EXPAND_SZ 保留原样，二进制值转可读文本）。"""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-16-le", "ignore").rstrip("\x00")
        except Exception:
            return repr(value)
    if vtype == winreg.REG_DWORD:
        return str(value)
    return str(value)


def _scan_registry():
    """扫描所有 Run / RunOnce / GPO Run 注册表键。"""
    items = []
    for source, path, hive in _RUN_KEYS:
        # RunOnce 的 HKLM 与 HKCU 用同一个路径，但来源标签要区分
        for name, value, vtype in _iter_values(hive, path):
            raw = _reg_value_to_str(value, vtype)
            if not raw:
                continue
            once = "RunOnce" in path
            src = source
            if once and "once" not in src:
                src = "registry_once_machine" if hive == winreg.HKEY_LOCAL_MACHINE \
                    else "registry_once_user"
            parsed = C.parse_command(raw)
            parsed.update({
                "key": name,
                "kind": parsed.get("kind") or C.kind_of(parsed.get("target"), raw),
                "source": src,
                "location": SOURCE_LABELS.get(src, src),
                "enabled": True,
                # ---- 管理定位信息（启用/禁用/删除都靠这几个字段）----
                "managed_by": "gpo" if "Policies\\Explorer\\Run" in path
                else "registry",
                "reg_hive": "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE
                else "HKCU",
                "reg_path": path,
                "reg_name": name,
                "reg_type": vtype,
            })
            items.append(parsed)
    return items


def _scan_startup_folders():
    """扫描用户与公共启动文件夹里的快捷方式/脚本/程序。"""
    items = []
    folders = [
        (C.expand_env(_STARTUP_FOLDER[0]), "startup_folder", "用户启动文件夹"),
        (C.expand_env(_STARTUP_FOLDER[1]), "startup_folder_common",
         "公共启动文件夹"),
    ]
    for folder, source, label in folders:
        if not folder or not os.path.isdir(folder):
            continue
        try:
            names = sorted(os.listdir(folder))
        except OSError:
            continue
        for name in names:
            path = os.path.join(folder, name)
            if not os.path.isfile(path):
                continue
            low = name.lower()
            # 隐藏文件（desktop.ini 等）跳过
            if low in ("desktop.ini", "thumbs.db"):
                continue
            # 处理 .lnk 快捷方式：读它的 Target 属性
            target = path
            if low.endswith(".lnk"):
                target = _resolve_lnk_target(path) or path
            parsed = C.parse_command(target)
            parsed.update({
                "key": name,
                "kind": C.kind_of(target, target),
                "source": source,
                "location": label,
                "enabled": True,
                "lnk_target": target if low.endswith(".lnk") else "",
                # 启动文件夹的「管理」定位：删/禁用的对象是这个文件本身
                "managed_by": "folder",
                "file_path": path,
                "folder": folder,
            })
            items.append(parsed)
    return items


def _resolve_lnk_target(lnk_path):
    """读取 .lnk 快捷方式的目标路径。

    不依赖第三方库：用 shell32 的 IShellLink COM 接口。
    """
    try:
        import pythoncom
        from win32com.shell import shell
        import win32com.client
    except Exception:
        return _resolve_lnk_manual(lnk_path)
    try:
        shell_link = pythoncom.CoCreateInstance(
            shell.CLSID_ShellLink, None,
            pythoncom.CLSCTX_INPROC_SERVER, shell.IID_IShellLink)
        shell_link.QueryInterface(pythoncom.IID_IPersistFile).Load(
            lnk_path, 0)
        return shell_link.GetPath(0, shell.SLGP_UNCPRIORITY)[0]
    except Exception:
        return _resolve_lnk_manual(lnk_path)


def _resolve_lnk_manual(lnk_path):
    """没有 pywin32 时手动解析 .lnk（只取「本地路径」字段，够用）。"""
    try:
        with open(lnk_path, "rb") as fp:
            data = fp.read()
        if len(data) < 0x4C or data[0:4] != b"\x4c\x00\x00\x00":
            return ""
        # 从 0x4C 起逐个读 StringData，本地路径在第二个（或第三个）字符串
        # （各 ShellLink 结构略有差异，这里做宽容解析）
        offset = 0x4C
        strs = []
        for _ in range(4):
            if offset + 2 > len(data):
                break
            clen = int.from_bytes(data[offset:offset + 2], "little")
            offset += 2
            if clen * 2 > len(data) - offset:
                break
            s = data[offset:offset + clen * 2].decode("utf-16-le",
                                                     errors="ignore")
            offset += clen * 2
            if s:
                strs.append(s)
        # 常见顺序：相对路径、本地路径、参数、描述
        for s in strs:
            if os.path.sep in s and not s.startswith("-"):
                return s
        return ""
    except Exception:
        return ""


def _scan_gpo_scripts():
    """扫描组策略启动/关机/登录/注销脚本。"""
    items = []
    for path, hive, label in _GPO_SCRIPT_SUBKEYS:
        for sub in _iter_subkeys(hive, path):
            # 每个子键（脚本名）下有一个 0 号值=脚本命令，若干 1/2... 号值=参数
            for name, value, vtype in _iter_values(hive,
                                                   path + "\\" + sub):
                if name == "0":
                    raw = _reg_value_to_str(value, vtype)
                    if not raw:
                        continue
                    parsed = C.parse_command(raw)
                    parsed.update({
                        "key": sub,
                        "kind": C.kind_of(parsed.get("target"), raw),
                        "source": "gpo_script",
                        "location": label,
                        "enabled": True,
                        "managed_by": "gpo",
                    })
                    items.append(parsed)
    return items


def collect(progress=None):
    """执行全部自启项扫描，返回 items 列表。

    progress 回调可选：``progress(msg, frac)``，在 GUI 后台线程里报告进度。
    """
    if progress:
        progress("扫描注册表 Run 键…", 0.15)
    reg_items = _scan_registry()

    if progress:
        progress("扫描启动文件夹…", 0.45)
    folder_items = _scan_startup_folders()

    if progress:
        progress("扫描组策略启动脚本…", 0.65)
    gpo_items = _scan_gpo_scripts()

    items = reg_items + folder_items + gpo_items
    # 读 Explorer\StartupApproved，标注真实的启用/禁用状态
    # （Run 键里的项即使被任务管理器禁用，注册表值仍然存在，不能一律当启用）
    if progress:
        progress("读取启动项启用状态…", 0.8)
    manage.apply_approved_state(items)
    if progress:
        progress("自启项扫描完成（%d 条）" % len(items), 1.0)
    return items
