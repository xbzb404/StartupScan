# -*- coding: utf-8 -*-
"""开机自启扫描器 —— 包入口。

作者署名在这里单点定义：界面标题栏／侧边栏／状态栏、导出的 Markdown 与
HTML 报告、控制台输出，以及打包后 exe 的 Windows 版本资源，全部引用同一组
常量。分散写死很容易出现「标题栏改了、报告页脚没改」这类不一致，所以新增
落点时请一律引用 :data:`AUTHOR`。
"""

__author__ = "zhb"
__version__ = "1.1"

AUTHOR = "by zhb"           # 完整署名（界面 / 报告 / 打包脚本统一引用）
AUTHOR_TAG = "zhb"          # 简短标识（版本资源、User-Agent 等）
