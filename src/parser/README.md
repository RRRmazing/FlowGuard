# 报文解析模块（谢福祥，阶段 1）

入口为 `flowguard::parsePacket(const RawPacket&, std::uint64_t sequence = 0)`，
头文件 `parser/packet_parser.h`。CMake 目标 `flowguard_parser` 不链接 Qt/Npcap。
函数只读输入，返回独立的 `PacketRecord`，没有全局可变状态，可在采集线程或离线读取流程调用。
调用者负责递增序号；时间戳和两个长度原样传递。

```cpp
#include "parser/packet_parser.h"
auto record = flowguard::parsePacket(rawPacket, sequence);
// 先检查 record.status，再使用可选字段；异常包也可保留已读出的字段。
```

## 当前范围

- Ethernet II：源/目的 MAC、最终 EtherType；支持 802.1Q/802.1ad VLAN，最多八层标签。
- IPv4：地址、版本、TTL、协议号，验证 IHL、总长度，跳过选项。
- IPv6：地址、版本、Hop Limit；遍历 Hop-by-Hop、Routing、Destination、Fragment、AH 扩展头。
  `ipProtocol` 保存扩展头之后的协议号。IPv6 字符串使用八组十六进制，未做零压缩。
- TCP：端口、标志、data offset 和选项长度；UDP：端口和 UDP 长度。
- Ethernet/IPv4 ARP：请求/响应的 IP 地址，opcode 放在 summary。
- DNS：仅候选端口 53；校验 DNS 头、问题名、压缩指针、各区记录边界后才设置 `isDns`。
  不仅凭端口确认 DNS。TCP 要求单段内恰好一个有两字节长度前缀的完整消息。
- ICMP/ICMPv6：基础分类和最小四字节头检查。

## 状态与限制

- `Complete` 表示上述支持范围内的结构检查通过，不代表校验和或全部协议语义有效。
- `Truncated` 表示所需字节不可用，包括抓包截断和 DNS 内部声明的字段超出可用数据。
- `Malformed` 表示元数据矛盾、IP/TCP/UDP 长度不合法、版本不一致或 DNS 名称格式不合法。
- `Unsupported` 表示未知链路/协议、非支持的 ARP、需要重组的分片或 TCP DNS 流。
  首片在头完整时可提供端口；后续分片不将数据误读为端口。不会把分片标为完整解析。

不做 IP 分片或 TCP 流重组、校验和验证、IPv6 jumbogram、ESP 解密、DNS RDATA 语义解码。
不保留 DNS 问题名/资源记录详情，也不新增 ARP 专用字段；当前公共结构提供地址、分类和摘要。
DNS TC 标志本身是有效协议字段，但如果记录字节不完整，仍不标记 `isDns`。
忽略 IP 数据报之外的以太网填充；UDP 长度限定 DNS 解析边界。

## 测试与亲自检查

在仓库根目录的 MSVC x64 开发终端中，按主 README 配置本机依赖后：

```powershell
cmake --build --preset windows-msvc
ctest --test-dir build/windows-msvc -R packet_parser --output-on-failure --no-tests=error
.\build\windows-msvc\packet_parser_tests.exe
```

CMake 把解析源码编译为静态库，再链接到程序和测试可执行文件；CTest 运行测试程序并检查退出码。
此测试可执行文件不需要 Qt/Npcap DLL。完整 CTest 包含窗口测试，仍需 README 中的运行环境。

样本在 `tests/packet_parser_tests.cpp` 中构造，字节序明确、可重复、不含个人抓包数据。
可在 `parsePacket` 设置断点，以 IPv4 UDP 样本观察：源地址 `192.0.0.1`、目的地址 `10.0.0.2`、
源端口 `1234`、目的端口 `80`；再看截断循环中 status 如何变成 `Truncated`。
修改一个预期值再运行测试，可以确认测试会报 FAILED 并以非零退出；之后撤销修改。

真实 Npcap 采集、PCAP 文件读取、界面展示和 Wireshark 对照尚未接入，应在双方共同联调时验收。
