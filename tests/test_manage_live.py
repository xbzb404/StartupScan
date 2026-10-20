# -*- coding: utf-8 -*-
"""层 1.5：管理动作**真机**联调（默认跳过，需显式开启）。

为什么单独一个文件：这些用例会真的写 HKCU\\Run、真的创建/删除计划任务。
虽然全部用 ``StartupScanSelfTest`` 命名并在 finally 里清理，但不应在
日常 ``python -m unittest`` 里顺手跑。开启方式：

    set STARTUPSCAN_LIVE_TEST=1
    python -m unittest tests.test_manage_live -v

覆盖链路（每条都要求「操作 → 回读校验 → 撤销 → 再校验」）：
    * 注册表 Run 项：禁用 / 启用 / 删除 / 撤销（StartupApproved 同步）
    * 计划任务：禁用 / 启用 / 删除 / 撤销（定义 XML 备份重建）
"""

import os
import shutil
import sys
import tempfile
import unittest
import winreg

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from startupscan import collect as collect_mod       # noqa: E402
from startupscan import manage as M                  # noqa: E402
from startupscan import tasks as tasks_mod           # noqa: E402

LIVE = os.environ.get("STARTUPSCAN_LIVE_TEST") == "1"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
TASK_NAME = r"\StartupScanSelfTest"
VALUE_NAME = "StartupScanSelfTest"

_TMP_DATA = ""


def setUpModule():
    """历史记录 / 备份写到临时目录，别污染用户真实的 StartupScan 数据。"""
    global _TMP_DATA
    if not LIVE:
        return
    _TMP_DATA = tempfile.mkdtemp(prefix="startupscan_live_")
    os.environ["STARTUPSCAN_DATA_DIR"] = _TMP_DATA


def tearDownModule():
    if _TMP_DATA:
        shutil.rmtree(_TMP_DATA, ignore_errors=True)


def _schtasks_blocked():
    """schtasks 是否被安全策略拦截。

    某些受管控环境把 ``schtasks.exe`` 加入程序黑名单，CreateProcess 直接
    返回「拒绝访问」。这不是我们代码的问题，相关用例应跳过而不是误报。
    """
    rc, out = M._schtasks(["/query", "/tn", r"\Microsoft\Windows"])
    return rc == -1 and ("拒绝访问" in (out or "") or "无法执行" in (out or ""))


def _set_run_value(value):
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                             winreg.KEY_SET_VALUE)
    try:
        winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, value)
    finally:
        winreg.CloseKey(key)


def _del_run_value():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                             winreg.KEY_SET_VALUE)
    except OSError:
        return
    try:
        winreg.DeleteValue(key, VALUE_NAME)
    except OSError:
        pass
    finally:
        winreg.CloseKey(key)


def _cleanup_approved():
    info = {"managed_by": "registry", "source": "registry_user",
            "reg_hive": "HKCU", "reg_path": RUN_KEY, "reg_name": VALUE_NAME,
            "key": VALUE_NAME}
    loc = M._approved_location(info)
    if loc:
        M._delete_value(loc[0], loc[1], VALUE_NAME)


@unittest.skipUnless(LIVE, "真机联调需 STARTUPSCAN_LIVE_TEST=1")
class TestLiveRegistry(unittest.TestCase):
    TARGET = r'"C:\Windows\System32\notepad.exe"'

    def setUp(self):
        _del_run_value()
        _cleanup_approved()
        _set_run_value(self.TARGET)

    def tearDown(self):
        _del_run_value()
        _cleanup_approved()

    def _find(self):
        items = collect_mod.collect()
        found = [it for it in items
                 if it.get("managed_by") == "registry"
                 and it.get("reg_name") == VALUE_NAME]
        self.assertEqual(len(found), 1, "扫描应能发现测试自启项")
        return found[0]

    def test_disable_enable(self):
        item = self._find()
        self.assertTrue(item.get("enabled"), "新建的 Run 值应为启用")

        ok, msg = M.set_enabled(item, False)
        self.assertTrue(ok, msg)
        self.assertEqual(M.approved_state(item), "disabled")
        self.assertFalse(self._find().get("enabled"),
                         "禁用后重新扫描应显示为已禁用")

        ok, msg = M.set_enabled(item, True)
        self.assertTrue(ok, msg)
        self.assertEqual(M.approved_state(item), "enabled")
        self.assertTrue(self._find().get("enabled"))

    def test_delete_and_undo(self):
        item = self._find()
        ok, msg = M.remove(item)
        self.assertTrue(ok, msg)
        self.assertEqual(self._find_count(), 0, "删除后扫描不应再出现")

        rec = M.history()[0]
        self.assertEqual(rec["action"], "delete")
        ok, msg = M.undo(rec)
        self.assertTrue(ok, msg)
        self.assertEqual(self._find_count(), 1, "撤销后应恢复自启项")
        self.assertEqual(self._read_run(), self.TARGET)

    def _find_count(self):
        return len([it for it in collect_mod.collect()
                    if it.get("managed_by") == "registry"
                    and it.get("reg_name") == VALUE_NAME])

    def _read_run(self):
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY)
        try:
            return winreg.QueryValueEx(key, VALUE_NAME)[0]
        finally:
            winreg.CloseKey(key)


@unittest.skipUnless(LIVE, "真机联调需 STARTUPSCAN_LIVE_TEST=1")
class TestLiveTask(unittest.TestCase):
    def setUp(self):
        if _schtasks_blocked():
            self.skipTest("schtasks.exe 被安全策略拦截，跳过计划任务联调")
        self._delete(quiet=True)
        rc, out = M._schtasks(["/create", "/tn", TASK_NAME,
                               "/tr", r"C:\Windows\System32\notepad.exe",
                               "/sc", "onlogon", "/f"])
        self.assertEqual(rc, 0, "创建测试任务失败：%s" % out)

    def tearDown(self):
        self._delete(quiet=True)

    @staticmethod
    def _delete(quiet=False):
        rc, out = M._schtasks(["/delete", "/tn", TASK_NAME, "/f"])
        if not quiet and rc != 0:
            print("cleanup task failed:", out)

    def _find(self):
        found = [t for t in tasks_mod.collect()
                 if (t.get("path") or "").lower() == TASK_NAME.lower()]
        self.assertEqual(len(found), 1, "扫描应能发现测试任务")
        return found[0]

    def test_disable_enable_delete_undo(self):
        item = self._find()
        self.assertTrue(item.get("enabled"))

        ok, msg = M.set_enabled(item, False)
        self.assertTrue(ok, msg)
        self.assertFalse(self._find().get("enabled"))

        ok, msg = M.set_enabled(item, True)
        self.assertTrue(ok, msg)
        self.assertTrue(self._find().get("enabled"))

        ok, msg = M.remove(item)
        self.assertTrue(ok, msg)
        self.assertEqual(self._count(), 0)

        rec = M.history()[0]
        self.assertEqual(rec["action"], "delete")
        self.assertTrue(rec.get("undo"), "删除任务应留下可撤销的 XML 备份")
        ok, msg = M.undo(rec)
        self.assertTrue(ok, msg)
        self.assertEqual(self._count(), 1, "撤销后任务应被重新注册")

    def _count(self):
        return len([t for t in tasks_mod.collect()
                    if (t.get("path") or "").lower() == TASK_NAME.lower()])


if __name__ == "__main__":
    unittest.main(verbosity=2)
