# 报文解析模块（谢福祥，阶段 1）

唯一公共声明来自 `src/core/module_contracts.h`，模块入口头文件为 `parser/packet_parser.h`：

```cpp
ParsedPacket parsePacket(const RawPacket& packet, std::uint64_t sequence);
```

函数无状态、只读输入，不保留原始字节。调用者传递会话序号，结果的 `record` 保留时间、长度、
协议分类与可选字段，`fields` 是可供 Qt 主窗口直接展开的字段树。不要再按旧版 `PacketRecord` 返回值调用。

```cpp
#include "parser/packet_parser.h"
auto parsed = flowguard::parsePacket(rawPacket, sequence);
const auto& record = parsed.record;
// 检查 record.status 后使用字段；异常包仍可能有安全取得的部分字段。
// parsed.fields 供界面展示，不需要保留 RawPacket。
```

## 已实现范围

- Ethernet II：小写冒号 MAC、最终 EtherType；802.1Q/802.1ad 最多两层 VLAN。
- IPv4：点分地址、版本、TTL、协议、IHL/总长度检查，跳过选项。
- IPv6：压缩小写文本地址、Hop Limit；安全跳过最多八个 Hop-by-Hop、Routing、Destination、Fragment、AH 扩展头。
- TCP：端口、data offset/选项长度、原始 flags；UDP：端口、长度及内层边界。
- ARP：Ethernet/IPv4 格式，源/目标 IP、opcode；字段树包含发送/目标 MAC 和 IP。
- DNS：候选端口 53，校验头、问题和所有区记录边界、压缩指针（最多 16 次，必须回指）后才置 `isDns`。
  TCP 识别本段第一条完整的有两字节长度前缀消息，允许后续消息，不跨段重组。
  字段树展示事务 ID、flags、各区数量及首个问题名、类型和类别。
- ICMP/ICMPv6：基础分类和最小四字节头检查。
- 字段树按 Ethernet、VLAN、网络、传输、DNS 顺序排列；展开 TCP 标志。固定有限树形，
  不批量展开 DNS 资源记录或载荷；最终再检查节点 256、文本 16 KiB、深度 16 的预算。

## 状态与限制

优先级为 `Malformed > Truncated > Unsupported > Complete`。先验证元数据；只根据安全读出的内容判断。
`capturedLength < originalLength` 至少为 Truncated，即使仅缺少以太网填充；明确长度矛盾仍为 Malformed。
DNS 结构缺字节为 Truncated，非法标志/名称或声明长度矛盾为 Malformed。

不做 IP/TCP 重组。实际分片保留网络字段和可确定的协议分类，标为 Unsupported，不猜测端口；IPv6 原子分片正常继续。
未知 DLT、ESP、未知协议、超出支持的 VLAN/扩展层数均为 Unsupported。
不做校验和验证、IPv6 jumbogram、DNS RDATA 语义解码。Complete 不代表全部协议语义或校验和有效。

## 从源码到验收

CMake 将解析源码编译为 `flowguard_parser` 静态库，分别链接到程序和测试。
解析库不链接 Qt/Npcap；离线程序将 `flowguard_storage` 的原始包交给同一解析入口。
在仓库根目录的 MSVC x64 开发终端中，按根 README 配置本机依赖后：

```powershell
cmake --build --preset windows-msvc
ctest --test-dir build/windows-msvc -R 'packet_parser|pcap_reader|offline_parser_fixture' --output-on-failure --no-tests=error
.\build\windows-msvc\flowguard_offline_probe.exe .\tests\data\ethernet-ipv4-udp.pcap
```

最后一条应显示 Packet 1、length=42、status=Complete，字段树中源 IP `192.0.0.1`、目的 IP `10.0.0.2`、
源端口 1234、目的端口 80。该程序也接受自己的经典 PCAP 路径（支持中文路径），不会修改文件。
可在 `parsePacket` 设置断点，观察 `parsed.record` 与 `parsed.fields`，再用短包测试观察状态变化。

完整 CTest 还包含窗口、采集及真实回环测试，需要 Qt/Npcap 的运行环境；Npcap 仅管理员模式可能需要管理员终端。
真实回环测试仅向本机生成 UDP：实际 DLT 为 1 时校验 UDP 端口，否则校验明确返回 Unsupported。
本机实际回环 DLT 为 0，因此该测试证明接口交接和不误解析，并不代替真实 Ethernet 解析/Wireshark 对照。

项目测试保存在 tests：可选 TShark 对照通过 CMake 缓存项 FLOWGUARD_TSHARK_EXECUTABLE 启用；Python 仅供该项测试使用。
现已完成真实 WLAN DLT=1 的 IPv4/IPv6 UDP 采集解析与 TShark 对照，主窗口不属于任务书截图中本次解析职责。
新增 live_parse_probe 用队友 CaptureSession 实际取包并调用同一解析入口；PCAP 证据输出最多 256 包，拒绝覆盖。
离线程序支持 `--json` 输出基本字段、捕获长度、时间和树，供独立工具逐字段比较。
18 包固定协议集与 TShark 的 312 字段比较已通过；真实 8 包 128 字段比较及在线/离线一致性已通过。
助手自查完成，待用户最终验收，尚未新增提交。
