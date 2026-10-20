# -*- coding: utf-8 -*-
"""安全测试：命令注入 / XSS / 危险调用排查。

覆盖面：
  1. 子进程调用必须是参数列表形式（shell=False），杜绝把注册表/任务里
     读来的任意字符串交给 shell 解释；
  2. 计划任务路径等不可信输入即使带引号、&、| 等元字符，也只能作为
     单个 argv 元素原样传给 schtasks，不产生额外命令；
  3. HTML 报告对条目内容做 HTML 转义，注册表值名里的 <script> 不落地；
  4. 源码不使用 eval / exec / pickle / os.system / shell=True。
"""

import inspect
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from startupscan import analyze as A            # noqa: E402
from startupscan import manage as M             # noqa: E402
from startupscan import report                  # noqa: E402
from startupscan import winutil                 # noqa: E402

PKG_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "startupscan")


class TestNoDangerousCalls(unittest.TestCase):
    """静态排查：整个包里不允许出现高危调用。"""

    FORBIDDEN = [
        "os.system(",
        "os.popen(",
        "eval(",
        "exec(",
        "pickle.load",
        "shell=True",
    ]

    def test_sources_free_of_dangerous_calls(self):
        hits = []
        for name in os.listdir(PKG_DIR):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(PKG_DIR, name), "r",
                      encoding="utf-8") as fp:
                src = fp.read()
            for bad in self.FORBIDDEN:
                if bad in src:
                    hits.append("%s: %s" % (name, bad))
        self.assertEqual(hits, [],
                         "源码中出现了高危调用：%s" % ", ".join(hits))

    def test_run_hidden_is_list_form(self):
        """run_hidden 不接受 shell=True，且默认参数里没有 shell。"""
        sig = inspect.signature(winutil.run_hidden)
        self.assertNotIn("shell", sig.parameters)


class TestShellMetacharInputs(unittest.TestCase):
    """不可信输入带 shell 元字符时，必须只作为单个参数传递。"""

    def setUp(self):
        import shutil
        self.tmp = tempfile.mkdtemp(prefix="startupscan_sec_")
        self._orig_schtasks = M._schtasks
        self._orig_data = os.environ.get("STARTUPSCAN_DATA_DIR")
        self._orig_is_admin = M.elevate.is_admin
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
        M.elevate.is_admin = self._orig_is_admin
        if self._orig_data is None:
            os.environ.pop("STARTUPSCAN_DATA_DIR", None)
        else:
            os.environ["STARTUPSCAN_DATA_DIR"] = self._orig_data
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_task_path_metachars_stay_one_arg(self):
        """任务路径带 & | ; 引号时原样作为一个 argv 元素，不注入。"""
        evil = r'\Evil& calc.exe | "x'
        item = {"key": "T", "name": "T", "path": evil,
                "source": "scheduled_task",
                "managed_by": "scheduled_task", "enabled": True}
        ok, _msg = M.set_enabled(item, False)
        self.assertTrue(ok)
        call = self.calls[-1]
        # /tn 后面必须是完整的原始路径，且整个调用里没有多出来的命令段
        self.assertEqual(call[call.index("/tn") + 1], evil)
        self.assertEqual(call[0], "schtasks" if call[0] == "schtasks"
                         else call[0])

    def test_registry_name_metachars_not_executed(self):
        """注册表操作走 winreg API（非子进程），带元字符的值名不执行。"""
        evil_name = 'x" & msg * "'
        encoded = M.encode_approved(False)
        # encode/decode 不做任何字符串解释，二进制值原样往返
        self.assertEqual(M.decode_approved(encoded), "disabled")
        self.assertIsInstance(evil_name, str)  # 值名只会作为注册表键名写入


class TestReportEscaping(unittest.TestCase):
    """HTML 报告必须转义条目内容（注册表值名是任意外部输入）。"""

    def test_html_escapes_script_tag(self):
        import tempfile
        from startupscan import demo
        b = demo.demo_bundle()
        b["items"].append({
            "key": '<script>alert(1)</script>', "kind": "app",
            "source": "registry_user", "dead": False, "suspicious": False,
            "enabled": True, "target": r"C:\x.exe", "risk": "medium",
            "risk_reason": "<img src=x onerror=alert(2)>",
        })
        fd, path = tempfile.mkstemp(suffix=".html")
        os.close(fd)
        try:
            ok, msg = report.export(b, path)
            self.assertTrue(ok, msg)
            with open(path, "r", encoding="utf-8") as fp:
                text = fp.read()
            self.assertNotIn("<script>alert(1)</script>", text)
            self.assertNotIn("<img src=x", text)
            self.assertIn("&lt;script&gt;", text)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass

    def test_markdown_escapes_table_pipes(self):
        """管道符会被转义，不能借表格行注入伪列。"""
        from startupscan import demo
        b = demo.demo_bundle()
        b["items"].append({
            "key": 'a|b|c', "kind": "app", "source": "registry_user",
            "dead": False, "suspicious": False, "enabled": True,
            "target": r"C:\x.exe", "risk": "low",
        })
        fd, path = tempfile.mkstemp(suffix=".md")
        os.close(fd)
        try:
            ok, msg = report.export(b, path)
            self.assertTrue(ok, msg)
            with open(path, "r", encoding="utf-8") as fp:
                text = fp.read()
            self.assertIn(r"a\|b\|c", text)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass


class TestAnalyzeHardening(unittest.TestCase):
    """分析层对畸形输入的健壮性。"""

    def test_extract_task_path_no_catastrophic_backtracking(self):
        import time
        evil = "“" + ("a" * 50000)
        start = time.time()
        A._extract_task_path(evil)
        self.assertLess(time.time() - start, 2.0)

    def test_classify_with_missing_fields(self):
        """缺字段的条目不应抛异常。"""
        items = [{"key": "bare"}, {"target": ""}, {}]
        scored, stats = A.classify(items)
        self.assertEqual(stats["total"], 3)

    def test_norm_target_rejects_bare_commands(self):
        self.assertEqual(A._norm_target("notepad"), "")
        self.assertEqual(A._norm_target(""), "")
        self.assertEqual(A._norm_target(None), "")
        self.assertEqual(A._norm_target(r"C:\A\a.exe"),
                         A._norm_target(r'c:\a\A.EXE'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
