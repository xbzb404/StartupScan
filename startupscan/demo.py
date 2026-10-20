# -*- coding: utf-8 -*-
"""演示数据：合成一批自启项 / 计划任务 / 事件日志 / 系统信息。

用途：
  1. GUI 探针与本机无自启数据时，也能看到完整页面渲染效果；
  2. 单元测试用稳定输入验证分析逻辑（失效 / 临时目录 / 脚本类评级等）。
"""

from . import analyze as A
from . import collect as collect_mod
from . import eventlog as eventlog_mod
from . import sysinfo as sysinfo_mod
from . import tasks as tasks_mod


def _item(key, raw, source, location, kind=None, enabled=True,
          dead=False, dead_reason="", suspicious=False, target=None,
          exists=True, **extra):
    """构造一条演示自启项。

    extra 用于补「这是什么」类字段（app_name / vendor / app_version /
    preview / author / description / run_as），与真实扫描的字段保持一致，
    这样 GUI 探针能覆盖到完整卡片布局。
    """
    from . import cmdparse as C
    if target is None:
        parsed = C.parse_command(raw)
        target = parsed.get("target")
        if kind is None:
            kind = parsed.get("kind")
    it = {
        "key": key,
        "kind": kind or "app",
        "source": source,
        "location": location,
        "raw": raw,
        "expanded": C.expand_env(raw),
        "target": target or "",
        "exists": exists,
        "dead": dead,
        "dead_reason": dead_reason,
        "suspicious": suspicious,
        "enabled": enabled,
    }
    it.update(extra)
    return it


def _attach_management_fields(items):
    """给演示数据补上真实的「管理定位字段」。

    这些字段就是启用/禁用/删除按钮的入参：注册表条目要有 hive / 路径 /
    值名，启动文件夹条目要有文件路径。演示数据补全后，GUI 探针截图里
    才能看到与管理功能一致的按钮布局。
    """
    for it in items:
        src = it.get("source", "")
        if src in ("registry_user", "registry_machine", "registry_once_user",
                   "registry_once_machine"):
            it["managed_by"] = "registry"
            it["reg_hive"] = "HKLM" if "machine" in src else "HKCU"
            it["reg_path"] = (
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
                if "once" in src
                else r"Software\Microsoft\Windows\CurrentVersion\Run")
            it["reg_name"] = it.get("key", "")
        elif src == "registry_gpo":
            it["managed_by"] = "gpo"
            it["reg_hive"] = "HKCU"
            it["reg_path"] = (r"Software\Microsoft\Windows\CurrentVersion"
                              r"\Policies\Explorer\Run")
            it["reg_name"] = it.get("key", "")
        elif src in ("startup_folder", "startup_folder_common"):
            it["managed_by"] = "folder"
            it["folder"] = (r"%APPDATA%\Microsoft\Windows\Start Menu"
                            r"\Programs\Startup"
                            if src == "startup_folder"
                            else r"%ProgramData%\Microsoft\Windows\Start Menu"
                                 r"\Programs\StartUp")
            it["file_path"] = it["folder"] + "\\" + it.get("key", "x.lnk")
        elif src == "gpo_script":
            it["managed_by"] = "gpo"
    return items


def demo_items():
    """合成一批自启项（覆盖各种类型与风险）。"""
    items = [
        _item("NVIDIA GeForce Experience",
              r'"C:\Program Files\NVIDIA Corporation\NVIDIA GeForce Experience\NVIDIA GeForce Experience.exe"',
              "registry_machine", "本机注册表 Run",
              app_name="NVIDIA GeForce Experience",
              vendor="NVIDIA Corporation", app_version="3.28.0.417"),
        _item("Realtek Audio",
              r"RtkAudUService.exe", "registry_machine", "本机注册表 Run",
              app_name="Realtek Audio Universal Service",
              vendor="Realtek Semiconductor", app_version="1.0.0.20"),
        _item("OneDrive",
              r'"%LocalAppData%\Microsoft\OneDrive\OneDrive.exe" /background',
              "registry_user", "当前用户注册表 Run",
              app_name="Microsoft OneDrive",
              vendor="Microsoft Corporation", app_version="24.151.0811"),
        _item("微信", r'"C:\Program Files (x86)\Tencent\WeChat\WeChat.exe"',
              "registry_user", "当前用户注册表 Run",
              app_name="微信", vendor="Tencent", app_version="3.9.12.55"),
        _item("QQ", r'"D:\Softwares\QQ\Bin\QQScLauncher.exe"',
              "registry_user", "当前用户注册表 Run",
              app_name="QQ", vendor="Tencent", app_version="9.9.27"),
        _item("远程管理工具",
              r'"C:\Users\Public\Downloads\TeamViewer_Setup.exe" /silent',
              "startup_folder", "公共启动文件夹",
              suspicious=True, exists=False,
              app_name="TeamViewer Setup", vendor="TeamViewer Germany GmbH"),
        _item("临时下载程序",
              r'"%TEMP%\downloaded_tool.exe" --autostart',
              "startup_folder", "用户启动文件夹",
              suspicious=True, preview=None),
        _item("过期卸载残留",
              r'"C:\Program Files\OldApp\gone.exe"',
              "registry_machine", "本机注册表 Run",
              dead=True, dead_reason="目标文件不存在", exists=False),
        _item("开机脚本.bat",
              r'C:\Scripts\startup_helper.bat',
              "gpo_script", "组策略登录脚本", kind="script",
              preview=[r"net start Spooler",
                       r"copy \\fileserver\share\config.ini C:\Scripts\ /Y"],
              file_mtime="2024-03-05"),
        _item("恶意伪装脚本",
              r"C:\Users\Public\update_helper.vbs",
              "startup_folder", "公共启动文件夹",
              kind="script", suspicious=True,
              preview=[r'CreateObject("WScript.Shell").Run "powershell -enc SQBFAFgA"',
                       r'CreateObject("Scripting.FileSystemObject")'],
              file_mtime="2026-10-01"),
        _item("Steam", r'"C:\Program Files (x86)\Steam\steam.exe" -silent',
              "registry_user", "当前用户注册表 Run"),
        _item("截图工具", r'"C:\Program Files\Screenshot\shot.exe"',
              "registry_user", "当前用户注册表 Run"),
        _item("旧版小助手",
              r'"D:\Tools\Helper\helper.exe"',
              "registry_user", "当前用户注册表 Run", exists=False, dead=True,
              dead_reason="目标文件不存在"),
    ]
    return _attach_management_fields(items)


def demo_tasks():
    """合成一批计划任务。"""
    tasks = [
        {
            "name": "Windows Defender 定期扫描",
            "path": r"\Microsoft\Windows\Windows Defender\扫描",
            "command": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "target": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "kind": "app",
            "trigger": "每周",
            "trigger_raw": ["weekly"],
            "enabled": True,
            "last_run": "2026/10/18 03:00:00",
            "last_result": "0x0",
            "next_run": "2026/10/25 03:00:00",
            "location": "任务计划程序",
            "source": "scheduled_task",
            "dead": False, "dead_reason": "", "suspicious": False,
            "exists": True,
            "start_from": False,
            "author": "Microsoft Corporation",
            "description": "定期扫描计算机以查找潜在威胁，并自动处理发现的恶意软件。",
            "run_as": "S-1-5-18",
            "run_level": "HighestAvailable",
        },
        {
            "name": "开机自启服务",
            "path": r"\MyApp\AutoStart",
            "command": r'"C:\Program Files\MyApp\daemon.exe" --boot',
            "target": r"C:\Program Files\MyApp\daemon.exe",
            "kind": "app",
            "trigger": "开机时",
            "trigger_raw": ["boot"],
            "enabled": True,
            "last_run": "2026/10/19 08:12:00",
            "last_result": "0x0",
            "next_run": "",
            "location": "任务计划程序",
            "source": "scheduled_task",
            "dead": False, "dead_reason": "", "suspicious": False,
            "exists": True,
            "start_from": True,
            "author": "MyApp Setup",
            "description": "在系统启动后拉起 MyApp 后台服务，保证开机即可接收消息。",
            "run_as": "SYSTEM",
            "run_level": "HighestAvailable",
        },
        {
            "name": "登录同步脚本",
            "path": r"\Tools\LoginSync",
            "command": r'C:\Scripts\login_sync.ps1',
            "target": r"C:\Scripts\login_sync.ps1",
            "kind": "script",
            "trigger": "用户登录时",
            "trigger_raw": ["logon"],
            "enabled": True,
            "last_run": "2026/10/19 08:10:00",
            "last_result": "0x1",
            "next_run": "",
            "location": "任务计划程序",
            "source": "scheduled_task",
            "dead": False, "dead_reason": "", "suspicious": False,
            "exists": True,
            "start_from": True,
            "author": "IT 部门",
            "description": "用户登录后同步共享盘映射与打印机配置。",
            "run_as": "DESKTOP-USER\\zhb",
            "preview": [r"net use Z: \\fileserver\share /persistent:no",
                        r"rundll32 printui.dll,PrintUIEntry /in /n \\print01\HP01"],
        },
        {
            "name": "已禁用旧任务",
            "path": r"\Old\DisabledTask",
            "command": r'"C:\Program Files\Old\thing.exe"',
            "target": r"C:\Program Files\Old\thing.exe",
            "kind": "app",
            "trigger": "按计划时间",
            "trigger_raw": ["time"],
            "enabled": False,
            "last_run": "2026/09/01 00:00:00",
            "last_result": "0x41303",
            "next_run": "",
            "location": "任务计划程序",
            "source": "scheduled_task",
            "dead": False, "dead_reason": "", "suspicious": False,
            "exists": True,
            "start_from": False,
            "author": "Old Software Inc.",
            "description": "旧版本软件的自动更新任务，软件卸载后未清理，已禁用。",
            "run_as": "S-1-5-18",
        },
    ]
    for t in tasks:
        t["managed_by"] = "scheduled_task"
        # 真实扫描的 tasks.collect 会给每条任务补 key（= name），演示数据
        # 之前漏了这个字段，导致卡片标题取不到、渲染出一条空白行。
        t.setdefault("key", t.get("name", ""))
    return tasks


def demo_events():
    """合成事件日志结果。"""
    return {
        "task_records": [
            {"date": "2026/10/19 08:12:00", "eid": 200, "source": "Microsoft-Windows-TaskScheduler",
             "message": "任务 \\MyApp\\AutoStart 已触发"},
            {"date": "2026/10/19 08:12:01", "eid": 102, "source": "Microsoft-Windows-TaskScheduler",
             "message": "任务 \\MyApp\\AutoStart 已完成运行"},
            {"date": "2026/10/19 08:10:00", "eid": 103, "source": "Microsoft-Windows-TaskScheduler",
             "message": "任务 \\Tools\\LoginSync 未能启动"},
        ],
        "task_notes": ["计划任务历史：3 条"],
        "sys_records": [
            {"date": "2026/10/19 08:00:00", "eid": 6009, "source": "EventLog",
             "message": "系统启动，版本 10.0.22631"},
            {"date": "2026/10/19 08:00:05", "eid": 6005, "source": "EventLog",
             "message": "事件日志服务已启动"},
            {"date": "2026/10/19 08:00:10", "eid": 6013, "source": "EventLog",
             "message": "系统已运行 86400 秒"},
        ],
        "sys_notes": ["系统事件：3 条"],
        "boot_time": "2026/10/19 08:00:00",
        "uptime": "1 天 0 小时 0 分钟",
    }


def demo_sysinfo():
    """合成系统信息。"""
    return {
        "os": "Windows 11 Pro 23H2 (Build 22631.4460)",
        "computer": "ZHUBO-DESKTOP",
        "user": "zhb",
        "arch": "64 位",
        "cpu": "Intel(R) Core(TM) i7-12700",
        "memory": "32 GB",
        "uptime": "2026/10/19 08:00:00",
        "version": "10.0.22631.4460",
    }


def demo_bundle():
    """完整的演示扫描结果（供 --demo 模式与 GUI 探针）。"""
    import datetime
    items_raw = demo_items()
    tasks = demo_tasks()
    items, stats = A.classify(items_raw + tasks)
    events = demo_events()
    return {
        "items": items,
        "tasks": tasks,
        "events": events,
        "sysinfo": demo_sysinfo(),
        "stats": stats,
        "boot_events": A.recent_boot_events(events),
        "task_failures": A.task_failures(events),
        "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
