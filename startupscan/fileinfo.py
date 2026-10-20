# -*- coding: utf-8 -*-
"""读取可执行文件的版本资源，回答「这个自启项到底是什么软件」。

Windows 的 PE 文件里带 StringFileInfo，常见字段：

    CompanyName      发行公司（Tencent / Microsoft Corporation）
    FileDescription  文件描述，通常就是**产品的中文名**（如「微信」）
    ProductName      产品名
    FileVersion      文件版本

用 version.dll 的三个 API 读取，不依赖 pywin32：

    GetFileVersionInfoSizeW → GetFileVersionInfoW → VerQueryValueW

读取失败（文件不存在 / 无版本资源 / 被占用）一律返回空字段，不抛异常 ——
自启项里大量是脚本和无版本信息的裸 exe，不能因为一个文件读不到就中断扫描。
"""

import ctypes
import ctypes.wintypes as wt
import os
import re
import struct

_ver = ctypes.windll.version

# 常见的中英文翻译块（langid + codepage）
_FALLBACK_KEYS = ("080404B0", "040904B0", "000004B0")


class _Info(object):
    __slots__ = ("description", "product", "company", "version", "original")

    def __init__(self, description="", product="", company="",
                 version="", original=""):
        self.description = description
        self.product = product
        self.company = company
        self.version = version
        self.original = original

    def as_dict(self):
        return {
            "file_desc": self.description,
            "file_product": self.product,
            "file_company": self.company,
            "file_version": self.version,
            "file_original": self.original,
        }


_cache = {}


def _query(buf, sub):
    """查一个字符串字段；失败返回 ""。"""
    ptr = ctypes.c_void_p()
    ln = ctypes.c_uint()
    ok = _ver.VerQueryValueW(buf, sub, ctypes.byref(ptr), ctypes.byref(ln))
    if not ok or not ptr.value or not ln.value:
        return ""
    try:
        raw = ctypes.wstring_at(ptr.value, ln.value)
    except Exception:                                    # noqa: BLE001
        return ""
    return raw.split("\x00")[0].strip()


def _translations(buf):
    """读 VarFileInfo\\Translation，返回 ['080404B0', ...]。"""
    ptr = ctypes.c_void_p()
    ln = ctypes.c_uint()
    ok = _ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation",
                             ctypes.byref(ptr), ctypes.byref(ln))
    keys = []
    if ok and ptr.value and ln.value >= 4:
        raw = ctypes.string_at(ptr.value, ln.value)
        for i in range(0, len(raw) - 3, 4):
            lang, cp = struct.unpack("<HH", raw[i:i + 4])
            keys.append("%04x%04x" % (lang, cp))
    return keys


def read_file_info(path):
    """读 exe/dll 的版本信息，返回 dict（字段缺失为空串）。

    结果带缓存：同一次扫描里同一个 exe 可能被多个自启项引用。
    """
    key = os.path.normcase(path or "")
    if key in _cache:
        return _cache[key].as_dict()

    info = _Info()
    try:
        if path and os.path.isfile(path):
            size = _ver.GetFileVersionInfoSizeW(path, None)
            if size:
                buf = ctypes.create_string_buffer(size)
                if _ver.GetFileVersionInfoW(path, 0, size, buf):
                    keys = _translations(buf) or list(_FALLBACK_KEYS)
                    fields = {}
                    for lang in keys:
                        for name in ("FileDescription", "ProductName",
                                     "CompanyName", "FileVersion",
                                     "OriginalFilename"):
                            if name in fields:
                                continue
                            val = _query(buf, "\\StringFileInfo\\%s\\%s"
                                         % (lang, name))
                            if val:
                                fields[name] = val
                        if "FileDescription" in fields:
                            break
                    info = _Info(
                        description=fields.get("FileDescription", ""),
                        product=fields.get("ProductName", ""),
                        company=fields.get("CompanyName", ""),
                        version=fields.get("FileVersion", ""),
                        original=fields.get("OriginalFilename", ""),
                    )
    except Exception:                                     # noqa: BLE001
        info = _Info()

    _cache[key] = info
    return info.as_dict()


def friendly_name(path, fallback=""):
    """把路径变成「能看懂的名字」：优先文件描述，其次产品名，最后文件名。"""
    fi = read_file_info(path)
    for cand in (fi["file_desc"], fi["file_product"]):
        if cand and not cand.lower().endswith(".exe"):
            return cand
    base = os.path.splitext(os.path.basename(path or ""))[0]
    return base or fallback


def resolve_indirect_string(text):
    """解析 Windows 的「间接字符串」资源引用。

    系统自带的任务在 XML 里存的是资源 ID 而不是文案，例如::

        $(@%systemroot%\\system32\\regidle.dll,-600)

    直接用 ``SHLoadIndirectString``（shlwapi.dll）换成当前语言的真实文案，
    比正则猜 dll 再用 LoadString 简单可靠，且自动处理 MUI 语言回退。

    解析不了（不是间接字符串 / dll 不存在 / 无该资源）时原样返回。
    """
    text = (text or "").strip()
    if not text.startswith("$("):
        return text
    # SHLoadIndirectString 要的是裸 "@dll,-id"；"$(...)" 是 Task XML 的转义壳，
    # 直接喂进去它虽然返回 S_OK 却原样吐回（实测），必须先剥壳。
    src = text[2:-1] if text.endswith(")") else text[2:]
    if not src.startswith("@"):
        return text
    try:
        buf = ctypes.create_unicode_buffer(2048)
        hr = ctypes.windll.shlwapi.SHLoadIndirectString(src, buf, 2048, None)
        if hr == 0 and buf.value.strip() and buf.value.strip() != src:
            return buf.value.strip()
    except Exception:                                     # noqa: BLE001
        pass
    return text


def describe_resource(text):
    """任务 XML 里的作者/描述字段 → 可直接展示的文案。

    第三方任务本身多为明文；系统任务是资源引用，解一层；
    解不出来（仍是天书）就返回空，界面上宁可不显示也不显示乱码。
    """
    text = resolve_indirect_string(text)
    # 极少数资源解不出来，会残留 "@dll,-123" 形式的天书，宁可不显示
    if text.startswith("$(") or re.search(r"@[^,]*,-?\d+\s*$", text):
        return ""
    return text


_SCRIPT_EXT = (".bat", ".cmd", ".ps1", ".vbs", ".js")


def script_preview(path, max_lines=3):
    """读脚本前几行有效内容，回答「这个自启脚本到底在干什么」。

    跳过空行与 ``@echo off`` / ``rem`` / ``::`` / ``#`` 这类噪声行；
    编码按 UTF-8(BOM) → GBK → UTF-16 依次尝试（.bat 在中文系统上多为 GBK）。
    读不到或不是脚本返回 []。
    """
    if os.path.splitext(path or "")[1].lower() not in _SCRIPT_EXT:
        return []
    for enc in ("utf-8-sig", "gbk", "utf-16"):
        try:
            out = []
            with open(path, "r", encoding=enc, errors="ignore") as fp:
                for _ in range(80):
                    ln = fp.readline()
                    if not ln:
                        break
                    s = ln.strip()
                    if not s:
                        continue
                    low = s.lower()
                    if (low.startswith("@echo") or low.startswith("rem ")
                            or low.startswith("rem\t") or low.startswith("::")
                            or low.startswith("#") or low.startswith("<#")):
                        continue
                    out.append(s[:140])
                    if len(out) >= max_lines:
                        break
            return out
        except (OSError, UnicodeError):
            continue
    return []
