# FlowGuard 流量哨兵

## 双方功能融合分支

当前融合异常预警与分段保存，以及完整 PCAP 分页、协议字段和图表交互。首次启动由用户选择报文及日志目录，不预设盘符、桌面或系统目录；取消后可继续分析，未设置的项目不写文件。分支、验证与人工检查见 [融合验收记录](docs/integration-acceptance.md)。

## 报文保存交互更新

开始采集时统一弹出两个直接选项：“立即开始保存报文”或“暂不开始保存报文”，选择即开始，以本次选择为准；关闭弹窗保持原状态。“准备实时采集”菜单已移除，PCAP 仅通过文件菜单或 Ctrl+O 打开。

在顶部“保存设置 → 数据保存位置…”先选择报文目录，可提前开启保存等待，从第一包记录，也可采集中直接开启后续保存，不再选路径。结束后确认正式文件名和位置；取消最终保存会丢弃本段。PCAP 与日志目录统一记在程序旁 `data/storage.ini`，不依赖注册表；旧版已选择的目录可继续读取，失效时要求重选。PCAP 分析模式禁用保存。详见 [保存流程说明](docs/recording-workflow.md)。

## 预警监测扩展

新增侧边“预警监测”：支持 SYN 请求异常、ICMP/ICMPv6 回声请求异常、TCP 端口扫描、UDP 高频流量和 ARP 地址映射变化。实时采集与 PCAP 文件共用后台检测；会话中可修改规则，PCAP 自动重新检测受影响规则。现有统计图表不增加内容。规则口径、边界和固定样本验收见 [预警监测说明](docs/alert-monitoring.md)。

## 第三阶段 Qt 接入分支

本分支已接入报文工作台、统计图表、PCAP 导入/回放/后续报文保存、显示筛选、资源监控和持续日志。
当前为待人工验收的开发版本，尚未完成正式至少 24 小时运行。实现范围、操作步骤、记录格式和性能分析入口见 [第三阶段验收说明](docs/stage3-acceptance.md)。下方早期阶段介绍保留为历史参考，以本说明和验收记录为准。

计算机网络课程设计，采用 C++17、Qt Widgets 和 Npcap。阶段 0 工程骨架已建立；
当前 `feat/processing-storage` 基于双方第一阶段合并版本，已完成采集、解析、字段树、
PCAP 读取与保存、长度/协议统计、速率及统一后台回放控制。
按最新分工，何俊杰负责本阶段后台，谢福祥下一阶段接入完整 Qt 窗口、图表及资源监控。
交接接口与用法见 [第二阶段交接说明](docs/stage2-handoff.md)。

## 开发依赖

当前验证的环境为 Windows x64、MSVC、Qt 6.11.0。需要：

- Visual Studio 或 Build Tools 的桌面 C++ 工作负载及 Windows SDK。
- Qt 的 MSVC x64 套件，包含 Widgets；后续图表阶段需要 Charts。
- CMake 3.21 或更新版本，以及 Ninja。两者需能从开发终端调用。
- [Npcap 驱动](https://npcap.com/)和 [Npcap SDK 1.17](https://npcap.com/dist/npcap-sdk-1.17.zip)。

驱动通过官方安装程序安装。SDK 解压到仓库的 `third_party/npcap-sdk`，使其包含
`Include/pcap.h` 和 `Lib/x64/wpcap.lib`。SDK 和构建产物不提交 Git。
也可以在 CMake 配置时通过 `-DNPCAP_SDK_DIR=...` 指定自己的 SDK 位置。

每位开发者自行配置工具位置，共享文件不包含个人安装路径。
当前预设使用 MSVC x64；MinGW 不是当前已验证的构建方式。

## 从源码到程序

编辑器中的“运行”通常包含构建和启动两个过程。本项目通过 CMake 组织多个源文件和依赖：

1. **配置**：CMake 读取 `CMakeLists.txt`，找到编译器、Qt 和 Npcap SDK，并生成 Ninja 构建规则。
2. **构建**：Ninja 调用 MSVC 编译各个源文件，再链接成 `FlowGuard.exe`。
3. **运行**：Windows 启动 exe，同时加载 Qt 和 Npcap 的 DLL。
4. **测试**：CTest 执行项目已注册的测试，并检查退出结果。

CMake 预设 `CMakePresets.json` 只记录共享构建选项；个人路径通过命令行、编辑器配置，
或被 Git 忽略的标准 `CMakeUserPresets.json` 提供。项目不要求自定义配置脚本。

## 配置与构建

在开始菜单打开 Visual Studio 的 **Developer PowerShell**，确保选择 x64 开发环境。
这个终端由微软工具提供，用于设置编译器和 Windows SDK 的环境，并非项目自定义脚本。
进入克隆后的仓库根目录（含 `CMakeLists.txt` 的目录）。也可以从此终端执行 `code .` 打开 VS Code。

以下是 PowerShell 命令。首次配置时输入自己机器的 Qt MSVC x64 套件目录（包含 bin、lib、plugins），不带额外引号：

```powershell
$qtRoot = Read-Host '请输入本机 Qt MSVC x64 套件目录'
cmake --preset windows-msvc "-DCMAKE_PREFIX_PATH=$qtRoot"
cmake --build --preset windows-msvc
```

Ninja 应位于 PATH；如果没有，可以在配置命令中额外加入 `-DCMAKE_MAKE_PROGRAM=...` 指向 ninja.exe。
首次配置成功应显示 `Configuring done` 和 `Generating done`。
构建成功会生成 `build/windows-msvc/FlowGuard.exe`；无改动时显示 `ninja: no work to do`。
Qt 路径会缓存在本机 build 目录里，通常修改源码后只需再次执行构建命令。

不要将单文件“运行 C++”命令用于整个工程，它不会自动处理其他源文件、Qt 和 Npcap 依赖。

## 开发运行

在同一个 PowerShell 终端中，使用上面的 `$qtRoot`：

```powershell
$env:PATH = "$qtRoot\bin;$env:SystemRoot\System32\Npcap;$env:PATH"
$env:QT_QPA_PLATFORM_PLUGIN_PATH = "$qtRoot\plugins\platforms"
.\build\windows-msvc\FlowGuard.exe
```

这里临时告诉 Windows 去哪里寻找 DLL，并告诉 Qt 去哪里找窗口平台插件，设置只影响当前终端及其子进程。
重新打开终端时，重新设置 `$qtRoot` 和上述运行环境；不需要重新配置 CMake。
如果缺少 DLL，说明运行依赖未准备好，并不一定是源码编译失败。

阶段 0 窗口应显示项目名称、阶段说明和 Npcap 版本，可以调整大小并正常关闭。
该窗口暂未接入后台采集控件；实际采集、统计和保存可通过命令行程序或 ProcessingSession 使用。

## 测试与验收

完成构建并设置运行环境后执行：

```powershell
ctest --test-dir build/windows-msvc --output-on-failure --no-tests=error
```

CTest 当前包含采集、解析、Reader 和第二阶段后台等 12 项测试（可选 TShark 对照需另行配置）。其中 `stage0_smoke` 加载实际的
Qt/Npcap 库，启动窗口并进入事件循环，检查后自动退出；后者验证设备信息转换、
资源释放、命令行参数、并发队列和采集生命周期；`capture_loopback_live` 会打开
Npcap 回环设备并收发本机自产 UDP 流量。无回环设备时该项明确跳过，不能视为实机验证通过。
公共头文件还有独立编译检查目标。新增解析与读取测试见 [解析说明](src/parser/README.md) 和 [读取说明](src/storage/README.md)。
预期结果为 `100% tests passed`。这不能替代人工查看中文显示、窗口操作和退出是否正常。
队友也应在自己的电脑上配置、构建和运行，确认工程能独立复现。

只验证采集基础而不启动窗口时：

```powershell
ctest --test-dir build/windows-msvc -R "^capture_" --output-on-failure --no-tests=error
.\build\windows-msvc\flowguard_capture_probe.exe --list-devices
```

这里的命令行程序仅依赖 Npcap 和系统库，不依赖 Qt DLL；枚举模式输出网卡设备标识、
说明、IPv4/IPv6 地址和回环标记。详细行为见 [采集模块说明](src/capture/README.md)。

最终交付前还需要单独部署和验证运行库。Qt 提供 `windeployqt` 工具；
开发终端可以运行程序，并不代表单独复制一个 exe 就能在另一台电脑运行。

## 项目结构

| 位置 | 内容 |
| --- | --- |
| `CMakeLists.txt` | 源码、依赖与测试定义 |
| `CMakePresets.json` | 共享构建选项 |
| `src/core` | 原始报文、解析结果及公共模块接口声明 |
| `src/capture` | 已实现枚举、实际采集、线程、有界缓冲与命令行验证 |
| `src/parser` | 协议解析、字段树和固定样本测试 |
| `src/statistics` | 长度/协议/DNS/异常计数与区间速率 |
| `src/storage` | 经典 PCAP 读取与安全保存，复用第一阶段 Reader |
| `src/processing` | 统一后台、互斥输入、回放控制、统计与保存及有界界面批次 |
| `src/ui` | 窗口与显示 |
| `tests/data` | 可重复验证的报文样本 |
| `docs` | 阶段记录和接口约定 |
| `build` | 本机生成文件，不提交 Git |

## 协作

提交源码、CMake 配置、测试与说明，不提交个人配置、SDK、编译产物和个人抓包数据。
换电脑时重新构建，不复制 build 目录；更换编译器或 Qt 套件时使用新的构建目录。
保留各自正常的 Git 作者身份，功能分支通过审查和验收后合并到 main。

阶段指南见 [docs/stages.md](docs/stages.md)，接口约定见 [docs/interfaces.md](docs/interfaces.md)。
报文工作台右下角按协议展示关键字段与含义，支持滚动和复制；范围与验收方式见 [报文解读说明](docs/packet-interpretation.md)。

## 第二阶段后台交付

```powershell
.\build\windows-msvc\flowguard_processing_probe.exe --input .\tests\data\stage1-protocols.pcap
.\build\windows-msvc\flowguard_processing_probe.exe --input .\tests\data\stage1-protocols.pcap --output .\build\新的保存文件.pcap
```

相同程序可用 `--device ID --bpf EXPR --seconds N` 做实机采集处理。
第三阶段请链接 `flowguard_processing` 并包含 `core/processing_session.h`，不要另写一套统计或保存逻辑。
本轮持续试运行按用户最新要求为 5 分钟；不代表最终 24 小时测试已完成。

## 谢福祥阶段 1 交付

任务书阶段1中的解析、关键字段、ARP/DNS、异常边界、单元测试和真实Ethernet集成验证已实现并完成助手自查，待用户最终验收。
标准构建与测试见上文，解析接口和离线工具用法见 [解析模块说明](src/parser/README.md)。
当前含18包固定协议集的独立TShark对照，以及真实WLAN的IPv4/IPv6 UDP验证证据。
