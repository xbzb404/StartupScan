# -*- coding: utf-8 -*-
"""管理动作层：启用 / 禁用 / 删除 / 撤销 / 备份。  ·  by zhb

设计原则（每一条都是踩过坑之后定下来的）：

1. **禁用走 Windows 官方机制，不动原配置。**
   任务管理器的「启动」页看到的就是 ``Explorer\\StartupApproved`` 下的
   二进制值：首字节 ``0x02`` = 启用，``0x03`` = 用户禁用（后 8 字节是
   FILETIME），``0x06`` = 策略禁用。写这个值不删除 Run 键，也不移动文件，
   所以随时可以恢复 —— 这是「禁用」按钮唯一正确的实现方式。
   RunOnce 没有对应机制（一次性条目），只能删除，界面会明确提示。

2. **删除前必须备份，并且能撤销。**
   * 注册表值：记下 hive / 路径 / 值名 / 类型 / 原始数据（base64）；
   * 启动文件夹：把文件**移动**到备份目录（不是永久删除），撤销时移回；
   * 计划任务：先把定义 XML（``%SystemRoot%\\System32\\Tasks\\<路径>``）
     复制一份，撤销时用 ``schtasks /create /xml`` 重新注册。

3. **系统任务只允许禁用，绝不删除。**
   ``\\Microsoft\\Windows\\…`` 下的任务是操作系统的一部分，删掉可能让
    Defender / 更新 / 维护任务永久失效。这里硬性拦截，不给「手滑」的机会。

4. **失败只返回 (ok, msg)，不向界面抛异常。**
   所有 winreg / schtasks 调用都包在 try 里，失败信息带上下文（错误码 +
   命令回显），界面直接弹给用户看。

5. **数据目录可用环境变量覆盖**（``STARTUPSCAN_DATA_DIR``），
   单元测试因此不会污染真实用户目录。
"""

import base64
import datetime
import json
import os
import re
import shutil
import struct
import winreg

from . import cmdparse as C
from . import elevate
from .winutil import run_hidden

# ------------------------------------------------------------------ 常量

_HIVES = {
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
}

_APPROVED_ROOT = (r"Software\Microsoft\Windows\CurrentVersion"
                  r"\Explorer\StartupApproved")
APPROVED_RUN = _APPROVED_ROOT + r"\Run"
APPROVED_RUN32 = _APPROVED_ROOT + r"\Run32"
APPROVED_FOLDER = _APPROVED_ROOT + r"\StartupFolder"

_TASKS_DIR = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                          "System32", "Tasks")

# 首字节 → 状态。0x02 启用；0x03 用户禁用；0x06 策略禁用；
# 实测还有 0x01（带时间戳），语义没有公开文档，统一按「未知」如实展示，
# 不猜成启用或禁用 —— 猜错会让用户以为点「禁用」无效。
_APPROVED_STATES = {
    0x02: "enabled",
    0x03: "disabled",
    0x06: "policy",
    0x01: "unknown",
}

STATE_LABELS = {
    "enabled": "已启用",
    "disabled": "已禁用",
    "policy": "策略禁用",
    "unknown": "状态未知",
    "none": "无状态记录",
    "n/a": "不适用",
}

ACTION_LABELS = {
    "disable": "已禁用",
    "enable": "已启用",
    "delete": "已删除",
    "undo": "已撤销",
}

_BACKUP_KEEP = 300          # history.json 最多保留多少条记录


# ------------------------------------------------------------------ 目录

def app_dir():
    """数据目录：默认 ``%LOCALAPPDATA%\\StartupScan``，可用环境变量覆盖。"""
    override = os.environ.get("STARTUPSCAN_DATA_DIR")
    if override:
        return override
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "StartupScan")


def backup_dir():
    return os.path.join(app_dir(), "backup")


def _files_dir():
    return os.path.join(backup_dir(), "files")


def _tasks_backup_dir():
    return os.path.join(backup_dir(), "tasks")


def _history_path():
    return os.path.join(app_dir(), "history.json")


def ensure_dirs():
    for d in (_files_dir(), _tasks_backup_dir()):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass


def _stamp():
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


# ------------------------------------------------------------------ 角色判定

def role_of(item):
    """返回管理角色：registry / folder / task / gpo / unknown。"""
    role = (item or {}).get("managed_by") or ""
    if role in ("registry", "folder", "task", "gpo"):
        return role
    src = (item or {}).get("source") or ""
    if src == "scheduled_task":
        return "task"
    if src in ("startup_folder", "startup_folder_common"):
        return "folder"
    if src in ("gpo_script", "registry_gpo"):
        return "gpo"
    if src.startswith("registry"):
        return "registry"
    return "unknown"


def _needs_admin(item):
    role = role_of(item)
    if role == "task":
        return True
    if role == "registry" and (item.get("reg_hive") or "HKCU") == "HKLM":
        return True
    if role == "folder" and item.get("source") == "startup_folder_common":
        return True
    return False


def can_toggle(item):
    """能否启用/禁用，返回 (ok, reason)。"""
    role = role_of(item)
    if role == "gpo":
        return False, "由组策略统一管理，需要在本机/域组策略里修改"
    if role == "task":
        if not item.get("path"):
            return False, "任务路径缺失，无法定位"
    elif role == "registry":
        if "RunOnce" in (item.get("reg_path") or ""):
            return False, "RunOnce 是一次性条目，没有禁用机制，只能删除"
    elif role == "folder":
        if not item.get("file_path"):
            return False, "启动文件夹路径缺失，无法定位"
    else:
        return False, "无法识别的自启类型"
    if _needs_admin(item) and not elevate.is_admin():
        return False, "需要管理员权限（点击右上角「受限模式」提权）"
    return True, ""


def _is_system_task(path):
    """``\\Microsoft\\Windows\\…`` 是操作系统自带任务。"""
    p = (path or "").replace("/", "\\").lower()
    return p.startswith("\\microsoft\\windows\\")


def can_delete(item):
    """能否删除，返回 (ok, reason)。"""
    role = role_of(item)
    if role == "gpo":
        return False, "组策略条目不能单独删除，请修改组策略"
    if role == "task":
        if _is_system_task(item.get("path")):
            return False, ("这是 Windows 系统任务（\\Microsoft\\Windows\\…），"
                           "删除会影响系统功能，只允许禁用")
        if not item.get("path"):
            return False, "任务路径缺失，无法定位"
    elif role in ("registry", "folder"):
        pass
    else:
        return False, "无法识别的自启类型"
    if _needs_admin(item) and not elevate.is_admin():
        return False, "需要管理员权限（点击右上角「受限模式」提权）"
    return True, ""


# ------------------------------------------------------------------ StartupApproved

def _approved_value_name(item):
    if role_of(item) == "registry":
        return item.get("reg_name") or item.get("key") or ""
    return item.get("key") or ""


def _approved_candidates(item):
    """StartupApproved 里的候选值名。

    实测同一台机器上 Run 值叫 ``vmware-tray``，审批值却有 ``vmware-tray``
    和 ``vmware-tray.exe`` 两条 —— 不同安装器写法不一致，因此按「原名 →
    加 .exe → 去 .exe」依次找。
    """
    name = _approved_value_name(item)
    out = [name]
    if role_of(item) == "registry" and name:
        low = name.lower()
        if not low.endswith(".exe"):
            out.append(name + ".exe")
        else:
            out.append(name[:-4])
    return [n for n in out if n]


def _approved_location(item):
    """返回 (hive, 注册表路径) 或 None（该类型没有审批机制）。"""
    role = role_of(item)
    if role == "registry":
        path = item.get("reg_path") or ""
        if "RunOnce" in path:
            return None
        hive = item.get("reg_hive") or "HKCU"
        key_path = APPROVED_RUN32 if "WOW6432Node" in path else APPROVED_RUN
        return hive, key_path
    if role == "folder":
        hive = "HKLM" if item.get("source") == "startup_folder_common" \
            else "HKCU"
        return hive, APPROVED_FOLDER
    return None


def _read_value(hive_name, path, name):
    """读一个注册表值，返回 (value, type, existed)。"""
    hive = _HIVES.get(hive_name)
    if hive is None:
        return b"", winreg.REG_BINARY, False
    try:
        key = winreg.OpenKey(hive, path)
    except OSError:
        return b"", winreg.REG_BINARY, False
    try:
        value, vtype = winreg.QueryValueEx(key, name)
        return value, vtype, True
    except OSError:
        return b"", winreg.REG_BINARY, False
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass


def _write_value(hive_name, path, name, value, vtype=winreg.REG_BINARY):
    hive = _HIVES.get(hive_name)
    if hive is None:
        return False
    key = winreg.CreateKeyEx(hive, path, 0,
                             winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE)
    try:
        winreg.SetValueEx(key, name, 0, vtype, value)
        return True
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass


def _delete_value(hive_name, path, name):
    hive = _HIVES.get(hive_name)
    if hive is None:
        return False
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
    except OSError:
        return False
    try:
        winreg.DeleteValue(key, name)
        return True
    except OSError:
        return False
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass


def decode_approved(raw):
    """二进制审批值 → 状态字符串。"""
    if not raw or not isinstance(raw, (bytes, bytearray)):
        return "none"
    return _APPROVED_STATES.get(raw[0], "unknown")


def encode_approved(enabled):
    """生成审批值：启用 = 02 + 11 个 0；禁用 = 03 + FILETIME(now)。"""
    if enabled:
        return b"\x02" + b"\x00" * 11
    try:
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        delta = now - datetime.datetime(1601, 1, 1)
        ft = int(delta.total_seconds() * 10000000)
    except Exception:                                       # noqa: BLE001
        ft = 0
    return b"\x03\x00\x00\x00" + struct.pack("<Q", ft)


def locate_approved(item):
    """找到该条目在 StartupApproved 下的实际记录。

    返回 dict 或 None：hive / path / name / existed / vtype / value
    """
    loc = _approved_location(item)
    if not loc:
        return None
    hive_name, path = loc
    for name in _approved_candidates(item):
        value, vtype, existed = _read_value(hive_name, path, name)
        if existed:
            return {"hive": hive_name, "path": path, "name": name,
                    "existed": True, "vtype": vtype, "value": value}
    # 没找到已有记录：用主名（写入时创建）
    name = _approved_value_name(item)
    return {"hive": hive_name, "path": path, "name": name,
            "existed": False, "vtype": winreg.REG_BINARY, "value": b""}


def approved_state(item):
    """只读：当前审批状态（不改任何东西）。"""
    if role_of(item) in ("gpo", "unknown", "task"):
        return "n/a"
    info = locate_approved(item)
    if not info or not info.get("existed"):
        return "none"
    return decode_approved(info.get("value"))


def apply_approved_state(items):
    """扫描结束后调用：给每条自启项标注真实的启用状态。

    这是 1.0 版的一个准确性缺口：注册表 Run 键里的项即使被任务管理器
    禁用，值仍然在，之前一律显示「启用」。现在读 StartupApproved，
    与任务管理器 / 设置里的开关保持一致。
    """
    for it in items:
        role = role_of(it)
        if role in ("gpo", "unknown"):
            it.setdefault("enabled", True)
            it["approved_state"] = "n/a"
            continue
        if role == "task":
            continue                     # 计划任务的状态来自任务 XML
        state = approved_state(it)
        it["approved_state"] = state
        if state in ("disabled", "policy"):
            it["enabled"] = False
        elif state == "enabled":
            it["enabled"] = True
        # "none"：没有审批记录 = 系统按启用处理，保持原值（RunOnce 也是 True）
    return items


# ------------------------------------------------------------------ 历史记录

def _load_history():
    path = _history_path()
    try:
        with open(path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_history(records):
    ensure_dirs()
    path = _history_path()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fp:
            json.dump(records[:_BACKUP_KEEP], fp, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def history():
    """变更记录（最新在前）。"""
    return _load_history()


def _log(action, title, detail, undo=None, extra=None):
    rec = {
        "id": "%s-%04x" % (_stamp().replace("-", ""),
                           int(datetime.datetime.now().microsecond / 16)),
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "title": title,
        "detail": detail or "",
        "undo": undo,
        "undone": False,
    }
    if extra:
        rec.update(extra)
    records = _load_history()
    records.insert(0, rec)
    _save_history(records)
    return rec


def _mark_undone(record_id):
    records = _load_history()
    changed = False
    for rec in records:
        if rec.get("id") == record_id:
            rec["undone"] = True
            rec["undone_at"] = datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S")
            changed = True
            break
    if changed:
        _save_history(records)
    return changed


# ------------------------------------------------------------------ 启用 / 禁用

def _title_of(item):
    return (item.get("app_name") or item.get("key")
            or item.get("name") or "")


def _pack_reg(value):
    """注册表值 → JSON 可存的形式。

    不能一律 base64：``REG_SZ`` 读出来是 ``str``，按 bytes 还原时
    ``SetValueEx`` 会抛 ``ValueError: Could not convert the data to the
    specified type``（实测）。二进制值用 base64 包装，字符串/整数原样存。
    """
    if isinstance(value, (bytes, bytearray)):
        return {"b64": base64.b64encode(bytes(value)).decode("ascii")}
    return value


def _unpack_reg(value, vtype):
    """还原 _pack_reg 的结果，按值类型交回 SetValueEx 需要的 Python 类型。"""
    if isinstance(value, dict) and "b64" in value:
        try:
            return base64.b64decode(value["b64"].encode("ascii"))
        except Exception:                                   # noqa: BLE001
            return b""
    if vtype in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and \
            not isinstance(value, str):
        return "" if value is None else str(value)
    if vtype == winreg.REG_DWORD and not isinstance(value, int):
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0
    return value


def _expected(state_enabled):
    return "enabled" if state_enabled else "disabled"


def set_enabled(item, enabled):
    """启用 / 禁用一条自启项。返回 (ok, msg)。"""
    role = role_of(item)
    if role == "task":
        return _task_set_enabled(item, enabled)

    ok, why = can_toggle(item)
    if not ok:
        return False, why

    loc = _approved_location(item)
    if not loc:
        return False, "该类型没有启用/禁用机制，只能删除"

    info = locate_approved(item)
    if info is None:
        return False, "无法定位 StartupApproved 记录"
    if info.get("existed") and decode_approved(info["value"]) == _expected(enabled):
        return True, "该条目已经是%s状态" % ("启用" if enabled else "禁用")

    undo = {
        "op": "registry_set",
        "hive": info["hive"],
        "path": info["path"],
        "name": info["name"],
        "existed": bool(info.get("existed")),
        "vtype": int(info.get("vtype") or winreg.REG_BINARY),
        "value": _pack_reg(info.get("value") or b""),
    }
    try:
        _write_value(info["hive"], info["path"], info["name"],
                     encode_approved(enabled))
    except OSError as exc:
        return False, "写入 StartupApproved 失败：%s" % exc

    # 回读校验：写入没报错但值没变（权限/重定向）时不能谎报成功
    after = locate_approved(item)
    state = decode_approved(after["value"]) if after and after.get("existed") \
        else "none"
    if state != _expected(enabled):
        return False, "写入后状态仍为「%s」，可能被策略或权限拦截" % \
            STATE_LABELS.get(state, state)

    item["enabled"] = bool(enabled)
    item["approved_state"] = state
    _log("enable" if enabled else "disable", _title_of(item),
         "启动项：%s" % (item.get("location") or item.get("source", "")),
         undo=undo)
    return True, "已%s「%s」" % ("启用" if enabled else "禁用", _title_of(item))


def _decode_out(data):
    if not data:
        return ""
    if isinstance(data, str):
        return data.strip()
    for enc in ("gbk", "utf-8", "mbcs"):
        try:
            return data.decode(enc, "ignore").strip()
        except Exception:                                   # noqa: BLE001
            continue
    return str(data)[:400]


def _schtasks(args, timeout=60):
    """跑 schtasks，返回 (rc, 输出文本)。失败不抛异常。"""
    try:
        proc = run_hidden(["schtasks"] + list(args), capture_output=True,
                          timeout=timeout)
    except Exception as exc:                                # noqa: BLE001
        return -1, "无法执行 schtasks：%s" % exc
    out = _decode_out(proc.stdout) or _decode_out(proc.stderr)
    return proc.returncode, out


def _task_set_enabled(item, enabled):
    path = item.get("path") or ""
    if not path:
        return False, "任务路径缺失，无法定位"
    if _needs_admin(item) and not elevate.is_admin():
        return False, "需要管理员权限（点击右上角「受限模式」提权）"
    rc, out = _schtasks(["/change", "/tn", path,
                         "/enable" if enabled else "/disable"])
    if rc != 0:
        return False, "计划任务%s失败（rc=%s）：%s" % (
            "启用" if enabled else "禁用", rc, out[:300])
    item["enabled"] = bool(enabled)
    item["approved_state"] = "enabled" if enabled else "disabled"
    _log("enable" if enabled else "disable", _title_of(item),
         "计划任务：%s" % path,
         undo={"op": "task_set", "path": path, "enabled": not enabled})
    return True, "已%s计划任务「%s」" % ("启用" if enabled else "禁用",
                                       _title_of(item))


# ------------------------------------------------------------------ 删除

def _safe_name(text):
    return re.sub(r'[\\/:*?"<>|]+', "_", text or "item")[:80]


def remove(item):
    """删除一条自启项（先备份，可撤销）。返回 (ok, msg)。"""
    ok, why = can_delete(item)
    if not ok:
        return False, why
    role = role_of(item)
    if role == "registry":
        return _remove_registry(item)
    if role == "folder":
        return _remove_folder(item)
    if role == "task":
        return _remove_task(item)
    return False, "无法识别的自启类型"


def _remove_registry(item):
    hive = item.get("reg_hive") or "HKCU"
    path = item.get("reg_path") or ""
    name = item.get("reg_name") or ""
    if not (path and name):
        return False, "注册表位置信息缺失，无法删除"
    value, vtype, existed = _read_value(hive, path, name)
    if not existed:
        return False, "注册表值已不存在（可能已被其它程序删除）"

    approved = locate_approved(item)
    undo = {
        "op": "registry_delete",
        "hive": hive,
        "path": path,
        "name": name,
        "vtype": int(vtype),
        "value": _pack_reg(value),
        "approved": None,
    }
    if approved and approved.get("existed"):
        undo["approved"] = {
            "hive": approved["hive"],
            "path": approved["path"],
            "name": approved["name"],
            "vtype": int(approved["vtype"]),
            "value": _pack_reg(approved["value"]),
        }

    if not _delete_value(hive, path, name):
        return False, "删除注册表值失败（权限不足或被保护）"
    if approved and approved.get("existed"):
        _delete_value(approved["hive"], approved["path"], approved["name"])

    _log("delete", _title_of(item), "注册表值：%s\\%s\\%s" % (hive, path, name),
         undo=undo)
    return True, "已删除「%s」，备份可在管理记录中撤销" % _title_of(item)


def _remove_folder(item):
    file_path = item.get("file_path") or ""
    if not file_path or not os.path.isfile(file_path):
        return False, "启动文件夹里的文件不存在，可能已被移动或删除"
    ensure_dirs()
    dest = os.path.join(_files_dir(), "%s_%s" % (_stamp(),
                                                 os.path.basename(file_path)))
    try:
        shutil.move(file_path, dest)
    except OSError as exc:
        return False, "移动文件失败：%s" % exc

    approved = locate_approved(item)
    undo = {"op": "file_move", "src": dest, "dst": file_path,
            "approved": None}
    if approved and approved.get("existed"):
        undo["approved"] = {
            "hive": approved["hive"], "path": approved["path"],
            "name": approved["name"], "vtype": int(approved["vtype"]),
            "value": _pack_reg(approved["value"]),
        }
        _delete_value(approved["hive"], approved["path"], approved["name"])

    _log("delete", _title_of(item), "启动文件夹文件：%s（已备份）" % file_path,
         undo=undo)
    return True, "已移出启动文件夹并备份「%s」" % _title_of(item)


def _task_xml_path(task_path):
    return os.path.join(_TASKS_DIR, (task_path or "").strip("\\"))


def _remove_task(item):
    path = item.get("path") or ""
    if _is_system_task(path):
        return False, ("Windows 系统任务不允许删除（会影响系统功能），"
                       "请改用「禁用」")
    ensure_dirs()
    xml_src = _task_xml_path(path)
    xml_backup = ""
    if os.path.isfile(xml_src):
        xml_backup = os.path.join(
            _tasks_backup_dir(),
            "%s_%s.xml" % (_stamp(), _safe_name(path.strip("\\"))))
        try:
            shutil.copy2(xml_src, xml_backup)
        except OSError:
            xml_backup = ""

    rc, out = _schtasks(["/delete", "/tn", path, "/f"])
    if rc != 0:
        return False, "删除计划任务失败（rc=%s）：%s" % (rc, out[:300])

    undo = {"op": "task_create", "xml": xml_backup, "path": path} \
        if xml_backup else None
    _log("delete", _title_of(item), "计划任务：%s" % path, undo=undo)
    if undo:
        return True, "已删除计划任务「%s」，可通过管理记录撤销" % _title_of(item)
    return True, ("已删除计划任务「%s」，但未找到任务定义 XML，"
                  "此操作无法撤销" % _title_of(item))


# ------------------------------------------------------------------ 撤销

def undo(record):
    """撤销一条历史记录。返回 (ok, msg)。"""
    payload = (record or {}).get("undo") or {}
    op = payload.get("op")
    if not op:
        return False, "这条记录没有可撤销的内容"
    if (record or {}).get("undone"):
        return False, "这条记录已经撤销过了"

    if op == "registry_set":
        if payload.get("existed"):
            vtype = int(payload.get("vtype") or winreg.REG_BINARY)
            try:
                _write_value(payload["hive"], payload["path"], payload["name"],
                             _unpack_reg(payload.get("value"), vtype), vtype)
            except OSError as exc:
                return False, "恢复注册表值失败：%s" % exc
        else:
            _delete_value(payload["hive"], payload["path"], payload["name"])
        msg = "已恢复原来的启用状态"

    elif op == "registry_delete":
        vtype = int(payload.get("vtype") or winreg.REG_BINARY)
        try:
            _write_value(payload["hive"], payload["path"], payload["name"],
                         _unpack_reg(payload.get("value"), vtype), vtype)
        except OSError as exc:
            return False, "恢复注册表值失败：%s" % exc
        appr = payload.get("approved")
        if appr:
            try:
                atype = int(appr.get("vtype") or winreg.REG_BINARY)
                _write_value(appr["hive"], appr["path"], appr["name"],
                             _unpack_reg(appr.get("value"), atype), atype)
            except OSError:
                pass
        msg = "已恢复被删除的注册表自启项"

    elif op == "file_move":
        src, dst = payload.get("src"), payload.get("dst")
        if not (src and dst and os.path.exists(src)):
            return False, "备份文件不存在，无法恢复"
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(src, dst)
        except OSError as exc:
            return False, "恢复文件失败：%s" % exc
        appr = payload.get("approved")
        if appr:
            try:
                atype = int(appr.get("vtype") or winreg.REG_BINARY)
                _write_value(appr["hive"], appr["path"], appr["name"],
                             _unpack_reg(appr.get("value"), atype), atype)
            except OSError:
                pass
        msg = "已把文件放回启动文件夹"

    elif op == "task_set":
        rc, out = _schtasks(["/change", "/tn", payload.get("path", ""),
                             "/enable" if payload.get("enabled") else
                             "/disable"])
        if rc != 0:
            return False, "恢复任务状态失败（rc=%s）：%s" % (rc, out[:300])
        msg = "已恢复计划任务状态"

    elif op == "task_create":
        xml = payload.get("xml")
        if not (xml and os.path.isfile(xml)):
            return False, "任务备份 XML 不存在，无法恢复"
        rc, out = _schtasks(["/create", "/xml", xml,
                             "/tn", payload.get("path", ""), "/f"])
        if rc != 0:
            return False, "重建计划任务失败（rc=%s）：%s" % (rc, out[:300])
        msg = "已从备份 XML 重新注册计划任务"

    else:
        return False, "未知的撤销类型：%s" % op

    _mark_undone(record.get("id"))
    return True, msg


# ------------------------------------------------------------------ 打开位置

def open_registry_location(item):
    """在注册表编辑器里跳到该条目的键，并把路径复制到剪贴板。

    regedit 没有「跳转到键」的命令行参数，但会读取
    ``HKCU\\...\\Applets\\Regedit\\LastKey`` 作为上次位置。先写这个值再
    启动 regedit，绝大多数情况下能直接定位到目标键。
    """
    hive = item.get("reg_hive") or "HKCU"
    path = item.get("reg_path") or ""
    friendly = "HKEY_CURRENT_USER" if hive == "HKCU" else "HKEY_LOCAL_MACHINE"
    last_key = "Computer\\%s\\%s" % (friendly, path)
    try:
        _write_value("HKCU", r"Software\Microsoft\Windows\CurrentVersion"
                            r"\Applets\Regedit", "LastKey", last_key,
                     winreg.REG_SZ)
    except OSError:
        pass
    try:
        os.startfile("regedit.exe")                        # noqa: S606
        return True, last_key
    except Exception:                                       # noqa: BLE001
        return False, last_key


def open_task_definition(item):
    """打开任务定义 XML 所在位置；找不到就打开任务计划程序。"""
    xml = _task_xml_path(item.get("path"))
    if os.path.isfile(xml):
        C.open_in_explorer(xml)
        return True, xml
    try:
        os.startfile("taskschd.msc")                        # noqa: S606
        return True, "taskschd.msc"
    except Exception:                                       # noqa: BLE001
        return False, ""


def open_backup_dir():
    ensure_dirs()
    target = backup_dir()
    try:
        os.startfile(target)                                # noqa: S606
        return True
    except Exception:                                       # noqa: BLE001
        return False
