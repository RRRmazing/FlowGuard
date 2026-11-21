# 阶段 1：谢福祥交付与验收指南

本次范围是任务书截图“阶段 1：网络底层”中谢福祥负责的全部内容，另包含新版接口约定要求的 PCAP 基础读取。
不把后续统计、图表、资源监控或统一主窗口列为本次任务未完成项。
当前代码在 `feat/parser`，已整合队友采集分支 `5c50b0d`，采用唯一公共头文件 `core/module_contracts.h`。
改动处于待验收、待提交状态，main 不变。

## 逐项完成情况

| 任务书要求 | 实现和证据 |
| --- | --- |
| Ethernet、IPv4/IPv6、TCP/UDP | packet_parser.cpp；IPv4 选项、两层 VLAN、最多八个 IPv6 扩展头 |
| MAC、IP、TTL/Hop Limit、端口、TCP 标志 | PacketRecord 与 ProtocolField 字段树；18 包 TShark 对照覆盖 SYN/ACK/FIN/RST |
| 短包、非 IP、异常长度 | 元数据及逐层边界检查；明确 Complete/Truncated/Malformed/Unsupported，保留安全字段 |
| ARP 识别与关键字段 | 请求/回复，opcode、发送/目标 MAC 和 IP |
| DNS 识别与关键字段 | UDP 和单段 TCP，ID/flags/问题与答案数量、首个问题名/类型/类别，压缩指针边界/循环/16 跳限制 |
| 解析单元测试及异常补充测试 | 4328 项原解析检查；18 种协议种子的全部前缀与定点变异、字段树预算共 75374 项检查 |
| 真实报文捕获并解析 | 使用队友 CaptureSession 的实时解析程序；真实 WLAN DLT=1，IPv4/IPv6 各四个自产 UDP，全部 Complete，零队列丢包 |
| 对照 Wireshark 关键字段 | 已安装 TShark 4.6.10：固定 18 包共 312 字段、真实 8 包共 128 字段一致；此前用户已目视核对单包 IPv4/UDP |
| 讲解自己的代码 | 本文下面的代码导读，供本人和队友远程查阅，不要求两人同处一地 |
| 新接口追加 PCAP 基础读取 | PcapReader：大小端、微秒/纳秒、中文路径、异常文件与资源上限；346 项检查 |

真实 8 包还验证了在线 ParsedPacket 与保存证据后离线重读的 ParsedPacket 完全相同（包括时间、长度及字段树）。
只有自产测试端口流量被捕获。真实 PCAP 和详细输出留在被 Git 忽略的 build/stage1-evidence，不提交个人地址或抓包。

## 你现在怎样亲自验收

在 Visual Studio Developer PowerShell（x64）进入仓库，按主 README 准备运行环境。
CMake 负责把源码编译为库和 exe；CTest 运行这些 exe 检查结果；离线程序让你目视检查相同解析接口的输出。
本机已完成配置，不必重建环境或重新输入依赖路径：

```powershell
cmake --build --preset windows-msvc
ctest --test-dir build/windows-msvc --output-on-failure --no-tests=error
.\build\windows-msvc\flowguard_offline_probe.exe .\tests\data\stage1-protocols.pcap
```

本次机器配置下应为 12/12 通过，末条显示 18 个包，前 17 个 Complete、最后一个非 IP 包 Unsupported。
其中两项硬件测试需要 Npcap 权限；本机开启 Admin-only Mode，使用管理员开发终端才能复现完整硬件测试。
缺少 Qt 运行环境的终端应先按根 README 设置 Qt bin、平台插件及 Npcap DLL 路径。

Wireshark 的可选对照测试通过标准 CMake 缓存项启用，不写个人路径到共享文件。
在新电脑上若未启用该项，CTest 会有 11 项。想启用时在已有配置命令追加：

```powershell
$tsharkExe = Read-Host '请输入本机 tshark.exe 完整路径'
cmake --preset windows-msvc "-DFLOWGUARD_TSHARK_EXECUTABLE=$tsharkExe"
```

此可选测试需要 Python 3，只用于独立对照，主程序和普通解析测试不依赖 Python/TShark。
`generate_stage1_samples.py` 仅用于维护合成测试样本；`tshark_compare.py` 是测试，不是构建、运行或环境配置封装。

## Wireshark 目视检查

打开 `tests/data/stage1-protocols.pcap`，按包号对照旁边的 `stage1-protocols.json` 或下表。
与终端中同号 Packet 的字段树比较。无需另外抓一次流量；两边必须读取同一个文件。

| 包号 | 内容 | 建议核对 |
| --- | --- | --- |
| 1 | IPv4 UDP | 192.0.2.1 → 198.51.100.2，TTL 64，1234 → 8080 |
| 2、3、4 | IPv4 TCP | 2345 → 443；flags 分别 0x02、0x11、0x14；展开 SYN/FIN/ACK/RST |
| 5、6 | IPv6 UDP / TCP | 2001:db8::1 → 2001:db8::2，Hop Limit 63；TCP flags 0x12 |
| 7、8 | ARP 请求/回复 | opcode 1/2，发送/目标 MAC 和 IPv4 地址 |
| 9、10、11、12 | UDP DNS 查询/回复、IPv6 DNS、TCP DNS | ID 0x4321（17185），example.com，type/class 1；回复答案数 1 |
| 13、14 | VLAN / 双 VLAN | VLAN 100；双层 VLAN 200、100；最终 IP 地址和 UDP 端口 |
| 15、16、17 | IPv6 Hop-by-Hop、原子分片、IPv4 选项 | 安全跳过扩展/选项后，UDP 端口仍正确 |
| 18 | 非 IP EtherType 0x88b5 | FlowGuard 给 Unsupported、有诊断，不出现猜测的 IP 或端口 |

真实报文证据也可打开 `build/stage1-evidence/wlan-owned-udp.pcap`，再运行：

```powershell
.\build\windows-msvc\flowguard_offline_probe.exe .\build\stage1-evidence\wlan-owned-udp.pcap
```

应有 8 个 Complete 包，IPv4/IPv6 各四个，端口 49871 → 49872。真实 MAC/IP 来自本机，不是固定合成地址。
同文件的自动 TShark 对照已由助手执行通过，无需你重复写测试。

## 代码导读：你和队友应该能解释什么

1. `RawPacket` 拥有字节副本。采集器将它从有界队列交给处理方；解析函数只读它，不保存 Npcap 临时指针。
2. `packet_parser.cpp` 的 Reader 用 need 在每次读取前检查边界，u16 按网络大端拼接两字节。
   不把任意字节指针强转为协议结构，避免对齐和越界问题。
3. Ethernet 固定头是 14 字节，EtherType 决定后续协议；VLAN 每层再跳过 4 字节。
4. IPv4 的 IHL 决定头长度（乘 4），total length 限制 IP 内层边界；IPv6 固定头 40 字节，随后受限遍历扩展头。
   MAC/IP/TTL 等安全读到后写进 record，内层错误不抹掉此前数据。
5. TCP data offset 决定头长度，flags 是位掩码，字段树展开八个位；UDP 固定头 8 字节，其 length 再收紧 DNS 读取边界。
6. 不凭 53 端口直接判断 DNS。dns/name 验证头、计数、名称、指针及资源记录长度，成功后才 isDns=true。
   TCP DNS 还先读两字节消息长度，不跨 TCP 段拼接。
7. parseRecord 产生基本结果，fields 只构造有界展示节点；外部唯一入口 parsePacket 返回 ParsedPacket。
8. pcap_reader.cpp 先识别全局头字节序和精度，再逐条读取包头和字节；正常 EOF 与文件损坏严格区分。
9. live_parse_probe.cpp 用队友的 CaptureSession 真正取包后调用同一 parsePacket。证据文件由 Npcap dumper 写，
   只供本阶段验证，最多 256 包，拒绝覆盖。它不替代下一阶段正式 PcapWriter 的文件管理、保存和回放需求。
10. TShark 测试比较同一份 PCAP 的两种独立解析结果，先规范化十六进制、IPv6 和时间，再逐项断言；
    边界测试从有效协议种子截短或变异，覆盖仅随机数据难以进入的内层路径。

## 明确边界

阶段 1 合同不要求 IP 分片/TCP 流重组、校验和验证、ESP 解密或任意 DLT 支持。
这些输入应有明确状态和诊断，不崩溃、不伪装解析成功；IPv6 原子分片可继续解析。
真实网络验证覆盖 IPv4/IPv6 UDP；TCP/ARP/DNS 等本阶段实现由固定样本与独立 TShark 对照验证，
不把固定样本称作真实抓包。

上述任务实现与助手自查均已完成，等待用户最终验收。未自动提交、推送或合入 main。
