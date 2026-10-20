# -*- coding: utf-8 -*-
"""层 1：核心库单元测试（无 GUI 依赖，托管 Python 即可跑）。

覆盖 cmdparse 的命令解析 / 失效判定 / 类型判定，analyze 的风险评级与统计，
demo 数据的结构完整性，report 的 Markdown 导出。
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from startupscan import analyze as A            # noqa: E402
from startupscan import cmdparse as C          # noqa: E402
from startupscan import demo                   # noqa: E402
from startupscan import manage as M            # noqa: E402
from startupscan import report                 # noqa: E402


class TestCmdParse(unittest.TestCase):
    def test_expand_env(self):
        # 真实环境里 SystemRoot 可能是 C:\WINDOWS（大写），只做大小写不敏感比较
        self.assertEqual(C.expand_env(r"%SystemRoot%\x").lower(),
                         r"c:\windows\x")
        # 未定义变量保留原样
        self.assertEqual(C.expand_env(r"%NOTDEFINED%\x"), r"%NOTDEFINED%\x")

    def test_quoted_path(self):
        r = C.parse_command(r'"C:\Program Files\A\a.exe" /s')
        self.assertEqual(r["target"], r"C:\Program Files\A\a.exe")
        self.assertEqual(r["kind"], "app")

    def test_bare_command(self):
        r = C.parse_command("notepad")
        # 裸命令名在 PATH 里可能找得到也可能找不到，但至少不报错
        self.assertEqual(r["kind"], "app")

    def test_script_kind(self):
        r = C.parse_command(r"C:\Scripts\startup.bat")
        self.assertEqual(r["kind"], "script")

    def test_dll_kind(self):
        r = C.parse_command(r"rundll32 shell32.dll,Control_RunDLL")
        self.assertEqual(r["kind"], "dll")

    def test_dead_marker(self):
        dead, reason = C.looks_dead(
            r'"C:\x\gone.exe" 系统找不到指定的文件', "", False)
        self.assertTrue(dead)

    def test_missing_file_detected(self):
        r = C.parse_command(r"C:\Definitely\Not\There\app.exe")
        self.assertFalse(r["exists"])
        self.assertTrue(r["dead"])

    def test_in_temp(self):
        self.assertTrue(C.in_temp_dir(r"C:\Users\x\AppData\Local\Temp\t.exe"))
        self.assertFalse(C.in_temp_dir(r"C:\Program Files\ok.exe"))


class TestAnalyze(unittest.TestCase):
    def test_risk_levels(self):
        item = {"dead": True, "dead_reason": "没了", "suspicious": False,
                "kind": "app", "source": "registry_machine"}
        level, reason = A.risk_of(item)
        self.assertEqual(level, "critical")

        item2 = {"dead": False, "suspicious": True, "kind": "app",
                 "source": "startup_folder"}
        level, _ = A.risk_of(item2)
        self.assertEqual(level, "high")

        item3 = {"dead": False, "suspicious": False, "kind": "app",
                 "source": "registry_machine"}
        level, _ = A.risk_of(item3)
        self.assertEqual(level, "low")

        item4 = {"dead": False, "suspicious": False, "kind": "script",
                 "source": "startup_folder"}
        level, _ = A.risk_of(item4)
        self.assertEqual(level, "high")

    def test_classify_stats(self):
        items = [
            {"key": "a", "kind": "app", "source": "registry_user",
             "dead": False, "suspicious": False},
            {"key": "b", "kind": "script", "source": "startup_folder",
             "dead": False, "suspicious": False},
            {"key": "c", "kind": "app", "source": "scheduled_task",
             "dead": False, "suspicious": False},
        ]
        scored, stats = A.classify(items)
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["apps"], 2)
        self.assertEqual(stats["scripts"], 1)
        self.assertEqual(stats["tasks"], 1)
        self.assertEqual(stats["registry"], 1)
        self.assertEqual(stats["folders"], 1)

    def test_boot_relevant(self):
        tasks = [
            {"start_from": True, "name": "a"},
            {"start_from": False, "name": "b"},
        ]
        self.assertEqual(len(A.boot_relevant_tasks(tasks)), 1)

    def test_recount_disabled(self):
        items = [
            {"key": "a", "kind": "app", "source": "registry_user",
             "risk": "low", "enabled": False},
            {"key": "b", "kind": "app", "source": "registry_user",
             "risk": "low", "enabled": True},
        ]
        stats = A.recount(items)
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["disabled"], 1)


class TestManage(unittest.TestCase):
    """管理动作层：只测纯逻辑与可安全回滚的文件操作，不碰真实注册表/任务。"""

    def test_approved_codec(self):
        self.assertEqual(M.decode_approved(M.encode_approved(True)), "enabled")
        self.assertEqual(M.decode_approved(M.encode_approved(False)), "disabled")
        self.assertEqual(len(M.encode_approved(False)), 12)
        self.assertEqual(M.decode_approved(b""), "none")
        self.assertEqual(M.decode_approved(b"\x03" + b"\x00" * 11), "disabled")
        self.assertEqual(M.decode_approved(b"\x06" + b"\x00" * 11), "policy")

    def test_role_of(self):
        self.assertEqual(M.role_of({"source": "scheduled_task"}), "task")
        self.assertEqual(M.role_of({"source": "startup_folder"}), "folder")
        self.assertEqual(M.role_of({"source": "registry_user"}), "registry")
        self.assertEqual(M.role_of({"source": "gpo_script"}), "gpo")
        self.assertEqual(M.role_of({"source": "registry_gpo"}), "gpo")
        self.assertEqual(M.role_of({}), "unknown")

    def test_gpo_is_read_only(self):
        item = {"source": "gpo_script", "managed_by": "gpo"}
        ok, why = M.can_toggle(item)
        self.assertFalse(ok)
        self.assertIn("组策略", why)
        ok, _ = M.can_delete(item)
        self.assertFalse(ok)

    def test_runonce_cannot_toggle(self):
        item = {"source": "registry_once_user", "managed_by": "registry",
                "reg_hive": "HKCU", "reg_name": "x",
                "reg_path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce"}
        ok, why = M.can_toggle(item)
        self.assertFalse(ok)
        self.assertIn("RunOnce", why)
        ok, _ = M.can_delete(item)
        self.assertTrue(ok)

    def test_system_task_protected(self):
        item = {"source": "scheduled_task", "managed_by": "scheduled_task",
                "path": r"\Microsoft\Windows\Defrag\ScheduledDefrag"}
        ok, why = M.can_delete(item)
        self.assertFalse(ok)
        self.assertIn("系统任务", why)

    def test_folder_remove_and_undo(self):
        """启动文件夹删除 = 移动到备份目录；撤销必须把文件放回原处。"""
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp()
        old = os.environ.get("STARTUPSCAN_DATA_DIR")
        os.environ["STARTUPSCAN_DATA_DIR"] = os.path.join(tmp, "data")
        try:
            startup = os.path.join(tmp, "Startup")
            os.makedirs(startup)
            name = "__startupscan_test__.lnk"
            path = os.path.join(startup, name)
            with open(path, "w", encoding="utf-8") as fp:
                fp.write("test")
            item = {"key": name, "source": "startup_folder",
                    "managed_by": "folder", "file_path": path}

            ok, msg = M.remove(item)
            self.assertTrue(ok, msg)
            self.assertFalse(os.path.exists(path), "文件应已移入备份目录")
            self.assertTrue(os.path.isdir(M._files_dir()))

            rec = M.history()[0]
            self.assertEqual(rec["action"], "delete")
            ok, msg = M.undo(rec)
            self.assertTrue(ok, msg)
            self.assertTrue(os.path.exists(path), "撤销后文件应回到启动文件夹")
            self.assertTrue(M.history()[0]["undone"])
        finally:
            if old is None:
                os.environ.pop("STARTUPSCAN_DATA_DIR", None)
            else:
                os.environ["STARTUPSCAN_DATA_DIR"] = old
            shutil.rmtree(tmp, ignore_errors=True)


class TestTaskCommands(unittest.TestCase):
    """计划任务的命令拼装与状态回写（拦截 ``_schtasks``，不真的执行）。"""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix="startupscan_task_")
        self._orig_schtasks = M._schtasks
        self._orig_tasks_dir = M._TASKS_DIR
        self._orig_data = os.environ.get("STARTUPSCAN_DATA_DIR")
        self._orig_is_admin = M.elevate.is_admin
        M._TASKS_DIR = self.tmp
        M.elevate.is_admin = lambda: True
        os.environ["STARTUPSCAN_DATA_DIR"] = os.path.join(self.tmp, "data")
        self.calls = []

        def fake(args, timeout=60):
            self.calls.append(list(args))
            return 0, "成功"

        M._schtasks = fake

    def tearDown(self):
        import shutil
        M._schtasks = self._orig_schtasks
        M._TASKS_DIR = self._orig_tasks_dir
        M.elevate.is_admin = self._orig_is_admin
        if self._orig_data is None:
            os.environ.pop("STARTUPSCAN_DATA_DIR", None)
        else:
            os.environ["STARTUPSCAN_DATA_DIR"] = self._orig_data
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _task():
        return {"key": "T", "name": "T", "path": r"\Test\T",
                "source": "scheduled_task",
                "managed_by": "scheduled_task", "enabled": True}

    def test_disable_enable_uses_change(self):
        item = self._task()
        ok, msg = M.set_enabled(item, False)
        self.assertTrue(ok, msg)
        self.assertEqual(self.calls[-1][:2], ["/change", "/tn"])
        self.assertIn("/disable", self.calls[-1])
        self.assertFalse(item["enabled"])
        self.assertEqual(M.history()[0]["action"], "disable")

        ok, msg = M.set_enabled(item, True)
        self.assertTrue(ok, msg)
        self.assertIn("/enable", self.calls[-1])
        self.assertTrue(item["enabled"])

    def test_delete_backs_up_xml_and_undo_recreates(self):
        xml = os.path.join(self.tmp, "Test", "T")
        os.makedirs(os.path.dirname(xml), exist_ok=True)
        with open(xml, "w", encoding="utf-8") as fp:
            fp.write("<Task/>")

        item = self._task()
        ok, msg = M.remove(item)
        self.assertTrue(ok, msg)
        self.assertEqual(self.calls[-1][:2], ["/delete", "/tn"])
        self.assertIn("/f", self.calls[-1])
        rec = M.history()[0]
        self.assertEqual(rec["undo"]["op"], "task_create")
        self.assertTrue(os.path.isfile(rec["undo"]["xml"]), "应备份任务 XML")

        ok, msg = M.undo(rec)
        self.assertTrue(ok, msg)
        self.assertEqual(self.calls[-1][:2], ["/create", "/xml"])
        self.assertTrue(M.history()[0]["undone"])


class TestDisabledAndDuplicates(unittest.TestCase):
    """虚警治理：禁用任务降级、SCHED_S 状态码白名单、重复项检测。"""

    def test_disabled_system_task_is_info(self):
        """\\Microsoft\\ 下的已禁用任务只是信息，不是「可疑」。"""
        it = {"dead": False, "suspicious": False, "kind": "app",
              "source": "scheduled_task", "enabled": False,
              "path": r"\Microsoft\Windows\Maps\MapsToastTask"}
        level, reason = A.risk_of(it)
        self.assertEqual(level, "info")
        self.assertIn("系统任务", reason)

    def test_disabled_user_task_is_low(self):
        it = {"dead": False, "suspicious": False, "kind": "app",
              "source": "scheduled_task", "enabled": False,
              "path": r"\Quark\QuarkUpdaterTaskUser1.0.0.21"}
        level, _ = A.risk_of(it)
        self.assertEqual(level, "low")

    def test_task_state_codes_not_abnormal(self):
        """0x41301（正在运行）/0x41303（尚未运行）是状态码，不是失败。"""
        for code in ("0x41301", "0x41303", "0x41300"):
            it = {"dead": False, "suspicious": False, "kind": "app",
                  "source": "scheduled_task", "enabled": True,
                  "path": r"\Test\T", "last_result": code}
            level, _ = A.risk_of(it)
            self.assertEqual(level, "low", code)
        # 真失败码仍要报 medium
        it["last_result"] = "0x2"
        level, reason = A.risk_of(it)
        self.assertEqual(level, "medium")
        self.assertIn("0x2", reason)

    def test_duplicate_registry_entries_flagged(self):
        """同名/不同名但指向同一 exe 的两条 Run 值要互相标出来（vmware-tray 案）。"""
        items = [
            {"key": "vmware-tray", "kind": "app", "source": "registry_user",
             "dead": False, "suspicious": False, "enabled": True,
             "target": r"C:\Program Files (x86)\VMware\vmware-tray.exe"},
            {"key": "vmware-tray.exe", "kind": "app",
             "source": "registry_machine", "dead": False, "suspicious": False,
             "enabled": True,
             "target": r'"C:\Program Files (x86)\VMware\vmware-tray.exe"'},
        ]
        scored, stats = A.classify(items)
        self.assertEqual(stats["duplicates"], 2)
        for it in scored:
            self.assertEqual(it["risk"], "medium")
            self.assertIn("重复", it["risk_reason"])

    def test_duplicate_cross_source(self):
        """注册表禁用 + 计划任务启用指向同一更新器，两条都应标重复（夸克案）。"""
        items = [
            {"key": "QuarkUpdater", "kind": "app",
             "source": "registry_user", "dead": False, "suspicious": False,
             "enabled": False,
             "target": r"C:\Users\x\AppData\Local\updater.exe"},
            {"key": "QuarkUpdaterTask", "kind": "app",
             "source": "scheduled_task", "dead": False, "suspicious": False,
             "enabled": True, "path": r"\Quark\QuarkUpdater",
             "target": r"C:\Users\x\AppData\Local\updater.exe"},
        ]
        scored, stats = A.classify(items)
        self.assertEqual(stats["duplicates"], 2)
        self.assertTrue(all(it["risk"] == "medium" for it in scored))

    def test_duplicate_exclusions(self):
        """全禁用不报；\\Microsoft\\ 系统任务不参与；失效项不参与。"""
        target = r"C:\x\same.exe"
        items = [
            {"key": "a", "kind": "app", "source": "registry_user",
             "dead": False, "suspicious": False, "enabled": False,
             "target": target},
            {"key": "b", "kind": "app", "source": "registry_machine",
             "dead": False, "suspicious": False, "enabled": False,
             "target": target},
        ]
        _, stats = A.classify(items)
        self.assertEqual(stats["duplicates"], 0)

        items = [
            {"key": "t1", "kind": "app", "source": "scheduled_task",
             "dead": False, "suspicious": False, "enabled": True,
             "path": r"\Microsoft\Windows\A\T1", "target": target},
            {"key": "t2", "kind": "app", "source": "scheduled_task",
             "dead": False, "suspicious": False, "enabled": True,
             "path": r"\Microsoft\Windows\B\T2", "target": target},
        ]
        _, stats = A.classify(items)
        self.assertEqual(stats["duplicates"], 0)

        items = [
            {"key": "d1", "kind": "app", "source": "registry_user",
             "dead": True, "dead_reason": "没了", "suspicious": False,
             "enabled": True, "target": target},
            {"key": "d2", "kind": "app", "source": "registry_machine",
             "dead": True, "dead_reason": "没了", "suspicious": False,
             "enabled": True, "target": target},
        ]
        _, stats = A.classify(items)
        self.assertEqual(stats["duplicates"], 0)

    def test_duplicate_keeps_higher_risk(self):
        """重复但本身是脚本/失效项的，保留更高评级不降级。"""
        target = r"C:\x\tool.exe"
        items = [
            {"key": "s1", "kind": "script", "source": "startup_folder",
             "dead": False, "suspicious": False, "enabled": True,
             "target": target},
            {"key": "s2", "kind": "app", "source": "registry_user",
             "dead": False, "suspicious": False, "enabled": True,
             "target": target},
        ]
        scored, stats = A.classify(items)
        self.assertEqual(stats["duplicates"], 2)
        by_key = {it["key"]: it for it in scored}
        self.assertEqual(by_key["s1"]["risk"], "high")    # 脚本类保持 high
        self.assertEqual(by_key["s2"]["risk"], "medium")  # 普通项升 medium


class TestBootEventDedup(unittest.TestCase):
    """开机事件去重：同一次开机产生的一串同 ID 事件只保留一条。"""

    def test_burst_dedup(self):
        # 模拟 12:42 附近 6 条 eid=12 挤在几秒内 + 更早一次正常开机
        # （时间戳用 wevtutil 真实格式：Z 后缀 + 7 位小数）
        recs = [
            {"date": "2026-10-20T12:42:41.4700000Z", "eid": 12},
            {"date": "2026-10-20T12:42:41.1060000Z", "eid": 12},
            {"date": "2026-10-20T12:42:40.4410000Z", "eid": 12},
            {"date": "2026-10-20T12:42:39.6220000Z", "eid": 12},
            {"date": "2026-10-20T12:42:32.2940000Z", "eid": 12},
            {"date": "2026-10-20T12:42:31.2810000Z", "eid": 12},
            {"date": "2026-10-19T08:00:00.0000000Z", "eid": 12},
        ]
        out = A.recent_boot_events({"sys_records": recs})
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["date"], "2026-10-20T12:42:41.4700000Z")
        self.assertEqual(out[1]["date"], "2026-10-19T08:00:00.0000000Z")

    def test_mixed_eids_and_slash_dates(self):
        recs = [
            {"date": "2026/10/19 08:00:05", "eid": 6005},
            {"date": "2026/10/19 08:00:02", "eid": 12},
            {"date": "2026/10/19 08:00:00", "eid": 12},
            {"date": "2026/10/19 07:59:00", "eid": 6008},
        ]
        out = A.recent_boot_events({"sys_records": recs})
        eids = [r["eid"] for r in out]
        self.assertEqual(eids, [6005, 12, 6008])

    def test_unparseable_date_kept(self):
        recs = [
            {"date": "", "eid": 12},
            {"date": "garbage", "eid": 12},
        ]
        out = A.recent_boot_events({"sys_records": recs})
        self.assertEqual(len(out), 2)

    def test_outside_window_kept(self):
        recs = [
            {"date": "2026-10-20T12:42:48", "eid": 12},
            {"date": "2026-10-20T12:30:00", "eid": 12},   # 相差 >2 分钟
        ]
        out = A.recent_boot_events({"sys_records": recs})
        self.assertEqual(len(out), 2)


class TestSysInfo(unittest.TestCase):
    """系统信息层：CPU 型号读取、启动时间格式化、EditionID 映射。"""

    def test_edition_label(self):
        from startupscan import sysinfo as S
        self.assertEqual(S._edition_label("Professional"), "专业版")
        self.assertEqual(S._edition_label("CoreSingleLanguage"), "家庭中文版")
        self.assertEqual(S._edition_label("UnknownEdition"), "UnknownEdition")
        self.assertEqual(S._edition_label(""), "")

    def test_edition_label_no_english_stack(self):
        """映射后不再出现 Pro Professional 这类英文叠词。"""
        from startupscan import sysinfo as S
        label = S._edition_label("Professional")
        self.assertNotIn("Professional", label)

    def test_format_boot_from_tick(self):
        import datetime
        from startupscan import sysinfo as S
        now = datetime.datetime(2026, 10, 20, 14, 0, 0)
        # 运行 2 小时 5 分钟
        out = S._format_boot_from_tick(2 * 3600 + 5 * 60, now=now)
        self.assertIn("2026/10/20 11:55:00", out)
        self.assertIn("2 小时 5 分钟", out)
        # 运行 3 天
        out = S._format_boot_from_tick(3 * 86400, now=now)
        self.assertIn("2026/10/17 14:00:00", out)
        self.assertIn("3 天", out)
        # 运行 0 秒
        out = S._format_boot_from_tick(0, now=now)
        self.assertIn("0 分钟", out)
        # 非法输入
        self.assertEqual(S._format_boot_from_tick(-1), "")

    def test_cpu_reads_processor_name_string(self):
        from startupscan import sysinfo as S
        orig = S._reg_str
        S._reg_str = lambda hive, path, name: (
            "12th Gen  Intel(R)  Core(TM)  i7-12700"
            if name == "ProcessorNameString" else "")
        try:
            out = S.cpu_model()
            # 连续空格应收拢
            self.assertEqual(out, "12th Gen Intel(R) Core(TM) i7-12700")
        finally:
            S._reg_str = orig

    def test_cpu_fallback_when_registry_empty(self):
        from startupscan import sysinfo as S
        orig_reg, orig_pl = S._reg_str, S.platform
        S._reg_str = lambda *a, **k: ""
        import types
        fake = types.SimpleNamespace(processor=lambda: "Fake CPU Family")
        S.platform = fake
        try:
            self.assertEqual(S.cpu_model(), "Fake CPU Family")
        finally:
            S._reg_str = orig_reg
            S.platform = orig_pl

    def test_collect_has_required_keys(self):
        from startupscan import sysinfo as S
        info = S.collect()
        for k in ("os", "computer", "user", "arch", "cpu",
                  "memory", "uptime", "version"):
            self.assertIn(k, info)


class TestDemo(unittest.TestCase):
    def test_bundle_structure(self):
        b = demo.demo_bundle()
        self.assertIn("items", b)
        self.assertIn("tasks", b)
        self.assertIn("events", b)
        self.assertIn("sysinfo", b)
        self.assertIn("stats", b)
        # 演示数据里应包含失效项与脚本类，覆盖风险评级分支
        kinds = {it.get("kind") for it in b["items"]}
        self.assertIn("script", kinds)
        dead = [it for it in b["items"] if it.get("dead")]
        self.assertTrue(dead, "演示数据应包含失效项")
        # 有风险项
        risky = [it for it in b["items"]
                 if it.get("risk") in ("critical", "high", "medium")]
        self.assertTrue(risky)


class TestReport(unittest.TestCase):
    def test_export_markdown(self):
        import tempfile
        b = demo.demo_bundle()
        fd, path = tempfile.mkstemp(suffix=".md")
        os.close(fd)
        try:
            ok, msg = report.export(b, path)
            self.assertTrue(ok, msg)
            with open(path, "r", encoding="utf-8") as fp:
                text = fp.read()
            self.assertIn("# 开机自启扫描报告", text)
            self.assertIn("风险提示", text)
            self.assertIn("系统信息", text)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass

    def test_export_html(self):
        import tempfile
        b = demo.demo_bundle()
        fd, path = tempfile.mkstemp(suffix=".html")
        os.close(fd)
        try:
            ok, msg = report.export(b, path)
            self.assertTrue(ok, msg)
            with open(path, "r", encoding="utf-8") as fp:
                text = fp.read()
            self.assertIn("<html", text)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
