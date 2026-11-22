# v0.1.1：修复桌面程序的终端窗口

用户反馈 v0.1.0 安装后启动、关闭时出现终端。检查其 PE 头，Subsystem 为 3（Windows Console）；CMake 主程序目标缺少 WIN32 参数。

将主程序改为 `qt_add_executable(FlowGuard WIN32 ...)`，由 CMake/Qt 生成 GUI 子系统并处理 Windows 入口点。WIN32 表示窗口程序类型，不改变 x64 架构。命令行工具和测试程序仍保持原目标类型。版本同步为 0.1.1，安装 AppId 保持不变，便于覆盖升级并保留用户配置。

验证：Release 构建成功；直接解析新 exe 的 PE 头，Subsystem 为 2（Windows GUI）。完整 CTest 与发布副本启动、PCAP 验证的结果记录在本机 build 的 gui-fix 日志中。没有通过启动器或运行时隐藏控制台绕过构建设置。

本修复消除的是 FlowGuard 主程序的自动控制台分配。Npcap 的管理员权限辅助进程由驱动控制；如果仍有其他窗口，应结合进程名继续定位。v0.1.0 的干净电脑、首次配置、缺失运行库和长时间稳定性验收限制仍然适用。
