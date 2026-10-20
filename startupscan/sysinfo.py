# -*- coding: utf-8 -*-
"""采集层：基础系统信息（OS 版本、计算机名、用户、架构等）。

全部走注册表与内置命令，不引入第三方库。
"""

import os
import platform
import socket
import winreg


def _reg_str(hive, path, name):
    try:
        key = winreg.OpenKey(hive, path)
    except OSError:
        return ""
    try:
        try:
            v, _ = winreg.QueryValueEx(key, name)
            return str(v) if v else ""
        except OSError:
            return ""
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass


def os_version():
    """Windows 版本描述，如 Windows 11 Pro 23H2 (Build 22631)。"""
    ver = platform.version()          # "10.0.22631.4460"
    rel = _reg_str(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion")
    ed = _reg_str(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID")
    name = _reg_str(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName")
    build = ""
    try:
        parts = ver.split(".")
        if len(parts) >= 3:
            build = "Build %s.%s" % (parts[2], parts[3]) if len(parts) > 3 \
                else "Build %s" % parts[2]
    except Exception:
        pass
    out = name or "Windows"
    if ed and ed != "Invalid":
        # EditionID 是内部代号（Professional / CoreSingleLanguage…），
        # 直接拼上去会出现「Windows 10 Pro Professional」这种叠词，
        # 先映射成友好名，再和产品名去重
        label = _edition_label(ed)
        if label and label.lower() not in out.lower():
            out += " " + label
    if rel:
        out += " " + rel
    if build:
        out += " (%s)" % build
    return out


# EditionID → 友好名（覆盖常见桌面版；查不到原样展示）
_EDITION_LABELS = {
    "Core": "家庭版",
    "CoreN": "家庭版 N",
    "CoreSingleLanguage": "家庭中文版",
    "CoreCountrySpecific": "家庭中文版（特定国家）",
    "Professional": "专业版",
    "ProfessionalN": "专业版 N",
    "ProfessionalWorkstation": "专业工作站版",
    "ProfessionalEducation": "专业教育版",
    "Enterprise": "企业版",
    "EnterpriseN": "企业版 N",
    "EnterpriseG": "企业版 G",
    "Education": "教育版",
    "EducationN": "教育版 N",
    "ServerStandard": "服务器标准版",
    "ServerDatacenter": "服务器数据中心版",
}


def _edition_label(ed):
    """EditionID → 友好名（纯函数，可单测）。"""
    if not ed:
        return ""
    return _EDITION_LABELS.get(ed.strip(), ed.strip())


def computer_name():
    try:
        return socket.gethostname()
    except Exception:
        return ""


def username():
    return os.environ.get("USERNAME") or ""


def architecture():
    try:
        arch, _ = platform.architecture()
        return arch.replace("bit", " 位")
    except Exception:
        return ""


_CPU_REG_KEY = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"


def cpu_model():
    """CPU 型号名，如「12th Gen Intel(R) Core(TM) i7-12700」。

    platform.processor() 在 Windows 上只返回「Intel64 Family 6 Model 186
    Stepping 2, GenuineIntel」这种家族/型号代号，对用户没有信息量；
    改读注册表 CentralProcessor\\0 的 ProcessorNameString（设备管理器里
    看到的就是它），读不到再退回 platform.processor()。
    """
    name = _reg_str(winreg.HKEY_LOCAL_MACHINE, _CPU_REG_KEY,
                    "ProcessorNameString")
    if name:
        # Intel 的 ProcessorNameString 常带连续双空格，收拢成单空格
        return " ".join(name.split())
    try:
        return platform.processor() or ""
    except Exception:
        return ""


def total_memory():
    """物理内存总量（GB，取整）。"""
    try:
        import ctypes
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            gb = stat.ullTotalPhys / (1024 ** 3)
            return "%.0f GB" % gb
    except Exception:
        pass
    return ""


def _format_boot_from_tick(tick_seconds, now=None):
    """GetTickCount64 毫秒数 → 「启动时间（已运行 …）」描述。

    纯函数（now 可注入），方便单元测试。运行时长按天/小时/分钟取整。
    """
    import datetime
    tick = int(tick_seconds)
    if tick < 0:
        return ""
    now = now or datetime.datetime.now()
    boot = now - datetime.timedelta(seconds=tick)
    d, rem = divmod(tick, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    parts = []
    if d:
        parts.append("%d 天" % d)
    if h:
        parts.append("%d 小时" % h)
    if m or not parts:
        parts.append("%d 分钟" % m)
    return "%s（已运行 %s）" % (boot.strftime("%Y/%m/%d %H:%M:%S"),
                               " ".join(parts))


def uptime_human():
    """系统启动时间 + 运行时长。

    旧实现解析 ``systeminfo /FO CSV`` 的中文输出 —— 既慢（systeminfo 要
    跑好几秒）又脆：字段错位/编码一变就取错值（实测把「OS 名称」当成了
    启动时间）。改用 kernel32.GetTickCount64（系统开机至今的毫秒数），
    本地运算反推启动时刻，无子进程、无本地化问题。
    """
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # 不设 restype 的话默认按 32 位 c_int 截断，开机 25 天后就溢出
        kernel32.GetTickCount64.restype = ctypes.c_ulonglong
        tick_ms = kernel32.GetTickCount64()
        if tick_ms:
            return _format_boot_from_tick(tick_ms / 1000.0)
    except Exception:
        pass
    return ""


def collect():
    """汇总系统信息为 dict。"""
    return {
        "os": os_version(),
        "computer": computer_name(),
        "user": username(),
        "arch": architecture(),
        "cpu": cpu_model(),
        "memory": total_memory(),
        "uptime": uptime_human(),
        "version": platform.version(),
    }
