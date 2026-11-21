# FlowGuard 流量哨兵

计算机网络课程设计。当前完成阶段 0 工程骨架；尚未实现采集、解析、统计和回放。

## 首次配置环境

每位开发者克隆同一份仓库，各自安装工具并配置本机路径，不修改共享源码。

1. 使用 Windows x64，安装 Visual Studio C++ Build Tools 的桌面 C++ 工作负载及 Windows SDK。
2. 安装 Qt 的 **MSVC x64** 开发套件，建议 Qt 6.11.0，须包含 Widgets；当前脚本不支持 MinGW。
3. 安装 CMake 3.21 或更新版本并添加到 PATH，准备 Ninja（Qt 安装器可提供）。
4. 从 [Npcap 官网](https://npcap.com/)安装 Npcap 驱动。
5. 用 VS Code 打开克隆后的仓库根目录，即包含 `CMakeLists.txt` 的目录。在 PowerShell 终端执行：

```powershell
Copy-Item .\local-env.example.cmd .\local-env.cmd
```

编辑 `local-env.cmd`，取消其中两行 `set` 命令的注释，分别填写本机的 Qt MSVC x64 套件目录、
`ninja.exe` 完整路径。路径可以包含空格，保留模板中的双引号。
Qt 套件目录下应能找到 `bin/Qt6Widgets.dll` 和 `lib/Qt6Widgets.lib`。
也可直接设置 `FLOWGUARD_QT_DIR`、`FLOWGUARD_NINJA` 环境变量；Ninja 未配置时会从 PATH 查找。

**`local-env.cmd` 被 Git 忽略，每个人维护自己的文件，不会随拉取代码被覆盖。**
模板不含任何开发者的专属路径。VS Code 的构建、运行、检查任务均读取同一份本机配置。

首次下载开发 SDK：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-deps.ps1
```

## 构建和运行

在仓库根目录执行：

```powershell
.\scripts\build.cmd
.\scripts\run.cmd
```

第一条配置并编译程序，看到成功链接或 `ninja: no work to do` 即表示构建成功。
第二条启动窗口，关闭窗口即可结束程序。窗口目前显示阶段 0 状态和 Npcap 版本。

自动启动检查：

```powershell
.\scripts\test.cmd
```

应显示 `100% tests passed`。此检查只加载库和显示窗口，不采集流量。
构建后可重复运行；修改源码后先重新构建。不要用单文件“运行 C++”按钮构建整个工程。

也可以按 **Ctrl+Shift+B** 构建，通过“终端 → 运行任务”选择 `FlowGuard: Run` 或 `FlowGuard: Check`。
任务配置要求 VS Code 打开的是本仓库根目录。

## 工具链与依赖

- C++17，MSVC x64，Qt 6.11.0 Widgets，CMake，Ninja。
- `build.cmd` 自动查找已安装的 Visual Studio C++ Build Tools 并加载开发环境。
- Qt 和 Ninja 路径由本机 `local-env.cmd` 或环境变量提供，共享脚本没有个人路径默认值。
- 运行脚本临时添加 Qt 和 Npcap DLL 路径，不修改系统 PATH。
- 开发 SDK 位于 `third_party/npcap-sdk`，没有提交到 Git。

SDK 来自 https://npcap.com/dist/npcap-sdk-1.17.zip 。脚本核对阶段 0 下载文件的 SHA256，
用于确保重复获取相同文件；该摘要不是独立的官方签名认证。驱动需自行通过 Npcap 官方安装程序安装。
最终交付包还需要 Qt 部署与运行验证，当前开发程序应通过 `run.cmd` 启动。

## 目录

| 位置 | 内容 |
| --- | --- |
| `CMakeLists.txt` | 源文件、Qt 和 Npcap 依赖定义 |
| `CMakePresets.json` | 构建目录和 Release 配置 |
| `local-env.example.cmd` | 不含个人路径的本机配置模板 |
| `local-env.cmd` | 个人配置，不提交 Git |
| `src/core` | 原始报文和解析记录公共数据结构 |
| `src/capture` | 采集、线程与有界缓冲，后续实现 |
| `src/parser` | 协议解析，后续实现 |
| `src/statistics` | 统计，后续实现 |
| `src/storage` | PCAP 读写，后续实现 |
| `src/ui` | 主窗口 |
| `tests/data` | 可重复测试用的小型报文样本 |
| `docs` | 阶段记录、接口约定和后续说明 |
| `build` | 自动生成，可重新构建，不提交 Git |

## Git 和阶段验收

本地仓库已初始化，分支为 `main`，暂未配置远程仓库。
阶段 0 等用户亲自运行验收；确认通过后再做首次提交和阶段标签。
源码应纳入 Git，编译文件、本地 SDK 和个人抓包文件不应纳入。
不要伪造作者、测试结果或两人的实际贡献，报告按真实情况填写。

换电脑时不要复制 `build` 目录；它包含本机路径，需在新电脑重新构建。
更换编译器或 Qt 套件时，移走旧 `build` 目录后重新构建。
提交前检查 `git status` 和暂存差异；Git 作者邮箱属于提交元数据，需要在提交前自行确认，
如有隐私需要可使用 GitHub 提供的 noreply 邮箱。

阶段记录见 [docs/stages.md](docs/stages.md)，接口约定见 [docs/interfaces.md](docs/interfaces.md)。
