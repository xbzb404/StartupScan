# 开机自启扫描器 StartupScan · by zhb

[![GitHub release](https://img.shields.io/badge/download-Release-blue)](https://github.com/xbzb404/StartupScan/releases/latest)
[![platform](https://img.shields.io/badge/platform-Windows%2010%20/%2011-lightgrey)]()
[![python](https://img.shields.io/badge/python-3.12%2B-green)]()

> **开源地址**：<https://github.com/xbzb404/StartupScan>
> **免安装下载**：到 [Releases](https://github.com/xbzb404/StartupScan/releases/latest)
> 下载 `StartupScan.exe` 双击即可（无需装 Python）。

Windows 10 / 11 开机自启内容扫描 **与管理** 工具 —— 一键扫描本机「开机自启
应用程序、开机自运行脚本、计划任务、启动/关机日志」，按风险分级（失效 /
需关注 / 可疑 / 一般）呈现，并可直接**启用 / 禁用 / 删除**这些自启项。

所有管理动作都走「先备份、可撤销」流程；程序默认以管理员身份启动。

## 功能

### 扫描

| 扫描范围 | 说明 |
| --- | --- |
| 注册表 Run / RunOnce | 当前用户与本机（含 32 位重定向、组策略 Run） |
| 启动文件夹 | 用户启动目录 + 公共启动目录（含 .lnk 目标解析） |
| 组策略启动脚本 | 计算机启动/关机脚本、用户登录/注销脚本 |
| 计划任务 | 从注册表 TaskCache 读全部任务，标注开机/登录触发，解析执行命令 |
| 启动/关机日志 | 任务计划失败记录 + 系统 6005/6009/6013 等启动事件 |

每个自启项都会解析出：执行命令、目标路径、类型（应用/脚本/DLL）、
是否存在、**真实启用状态**（读 `Explorer\StartupApproved`，与任务管理器一致）、
软件名 / 厂商 / 版本（读 exe 版本资源）、脚本摘要、任务创建者与作用。

### 管理

| 操作 | 注册表 Run | 启动文件夹 | 计划任务 |
| --- | --- | --- | --- |
| 禁用 / 启用 | 写 `StartupApproved`（不删原值） | 写 `StartupApproved\StartupFolder` | `schtasks /change` |
| 删除 | 备份值 + 类型后删除 | 文件移入备份目录 | 备份任务 XML 后删除 |
| 撤销 | 还原审批值 / 还原注册表值 | 文件移回原处 | `schtasks /create /xml` 重建 |

- **系统任务保护**：`\Microsoft\Windows\…` 下的任务只允许禁用，不允许删除。
- **组策略条目只读**：由组策略统一管理，界面明确提示，不提供禁用/删除。
- **变更记录**：每次操作写入 `%LOCALAPPDATA%\StartupScan\history.json`，
  在「管理记录」页可逐条撤销；备份位于同目录 `backup\`。
- **RunOnce**：一次性条目没有禁用机制，界面提示只能删除。

## 界面

Win11 Fluent 风格（浅色/深色可切换），八个页面：

- **概览**：统计磁贴 + 风险分布 + 最近系统启动
- **自启应用**：注册表与启动文件夹中的应用
- **启动脚本**：bat / vbs / ps1 等脚本类自启
- **计划任务**：按「开机/登录触发」优先分组
- **计划日志**：任务失败记录 + 系统启动/关机事件
- **风险提示**：失效项、临时目录自启、脚本类等需关注内容
- **管理记录**：运行权限、已禁用项、变更记录（可撤销）、备份目录
- **系统信息**：OS 版本、CPU、内存、启动时间、运行权限

## 使用

```
StartupScan.exe            # 双击运行，Windows 直接弹 UAC（清单声明 requireAdministrator）
StartupScan.exe --demo     # 演示模式（合成数据渲染界面，不改动系统）
```

> 管理员权限是管理功能的硬前提：本机级（HKLM）自启项与计划任务都需要
> 管理员令牌。取消 UAC 后仍可以「受限模式」查看与导出报告，但只能管理
> 当前用户的自启项，右上角会显示「受限模式 · 提权」按钮。

## 开发

```bash
# 单元/集成测试（托管 Python，无 tkinter 依赖）
python -m unittest discover -s tests

# 真机管理联调（会写 HKCU Run 与创建测试任务，自动清理）
set STARTUPSCAN_LIVE_TEST=1
python -m unittest tests.test_manage_live -v

# GUI 探针（系统 Python，带 tkinter）
python tools/gui_probe.py

# 窗口级截图（窗口被遮挡也能出图，用于检查排版）
python tools/capture_window.py screenshots

# 排版重叠检测
python tools/overlap_probe.py

# 打包（系统 Python，带 tkinter + PyInstaller）
python build_exe.py
```

打包时 `build_exe.py` 会给主程序加 `--uac-admin`，把
`requestedExecutionLevel level="requireAdministrator"` 写进 exe 清单；
源码运行时由 `elevate.ensure_admin()` 用 ShellExecuteW("runas") 兜底。

## 结构

```
startupscan\
├─ main.py              入口（管理员权限 + --demo）
├─ startupscan\
│  ├─ theme.py          Win11 视觉层（颜色/字体/DPI/圆角）
│  ├─ widgets.py        自绘控件（按钮/导航/滚动区/Painter/可点击动作行）
│  ├─ app.py            主界面（8 页面）
│  ├─ collect.py        注册表 Run + 启动文件夹 + 组策略脚本
│  ├─ tasks.py          计划任务（注册表 TaskCache + Boot/Logon 分组）
│  ├─ eventlog.py       wevtutil 事件日志（任务历史 + 系统启动）
│  ├─ analyze.py        聚合 + 风险评级 + 统计
│  ├─ manage.py         管理动作（启用/禁用/删除/撤销/备份）
│  ├─ elevate.py        管理员权限检测与 UAC 提权重启
│  ├─ cmdparse.py       命令/路径解析（环境变量、失效检测）
│  ├─ sysinfo.py        系统信息
│  ├─ report.py         Markdown / HTML 报告导出
│  ├─ demo.py           演示数据
│  └─ resources.py      窗口图标
├─ tests\               单元测试 + 真机联调（默认跳过）
├─ tools\               gui_probe / probe_exe / overlap_probe / capture_window
├─ build_exe.py         打包脚本
└─ assets\              icon.ico / icon.png
```
