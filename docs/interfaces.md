# 公共接口约定

阶段 0 仅定义数据契约，采集器和解析器的函数接口随阶段 1、2 的实现补充。
公共结构位于 `src/core/packet_types.h`，不依赖 Qt，便于离线测试。

- `RawPacket` 持有字节副本；Npcap 的临时数据指针不能直接交给后台队列或界面。
- 时间使用 `std::chrono::system_clock::time_point`；文件微秒或纳秒时间精度在读取时转换。
- `originalLength` 是线上报文长度，`capturedLength` 是实际捕获长度，二者不可混用。
- 有效输入要求 `bytes.size() == capturedLength` 且 `capturedLength <= originalLength`；读取层校验，解析层仍须做边界检查。
- 报文长度统计统一采用 `originalLength`，分为 `<=46`、`47..1500`、`>1500` 字节。
- `linkType` 决定链路层解释方式，不把所有输入默认当成以太网；未知类型保留原始数据并标为不支持。
- `PacketRecord` 的 MAC/IP 字符串为空表示字段不可用；数字字段使用 `std::optional`，零不是错误标记。
- TCP 标志保存原始位掩码，后续界面展开 SYN/ACK/FIN/RST 等标志。
- `ParseStatus` 区分完整、截断、不支持和格式异常；报文的网络和传输协议分类分别保存。
- `isDns` 的确认规则、IPv6 扩展头、分片和 ARP/DNS 详细字段在阶段 1 验收前补全。
- 采集和离线读取都产生 `RawPacket`，复用同一个解析与统计流程。
- 界面使用汇总值和有限列表；不在界面或统计模块永久保留所有原始字节。

线程队列上限、界面历史条数、图表点数、磁盘轮换与过滤后的统计口径在相关阶段实现前明确。
