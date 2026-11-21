# 固定报文样本

`ethernet-ipv4-udp.pcap` 是人工构造的经典 PCAP 2.4、小端、微秒样本，不来自个人网络流量。
一个 42 字节 Ethernet/IPv4/UDP 报文：

| 字段 | 期望 |
| --- | --- |
| DLT | 1（Ethernet） |
| 时间 | Unix 1700000000.123456 秒 |
| 源/目的 MAC | 00:00:00:00:00:00（合成样本） |
| 源/目的 IP | 192.0.0.1 → 10.0.0.2 |
| 源/目的端口 | 1234 → 80 |
| TTL | 64 |
| IP 总长度 / UDP 长度 | 28 / 8 |
| 捕获长度 / 原始长度 | 42 / 42 |
| 预期状态 | Complete，非 DNS |

IPv4 校验和有效，UDP 校验和为 0（IPv4 允许），没有载荷或 Ethernet FCS。
可以在 Wireshark 打开，按上表独立核对。用户已安装 Wireshark，并提供该样本展开详情截图，关键字段一致。

更多 IPv6、TCP、ARP、DNS、VLAN、分片、异常报文在 `tests/packet_parser_tests.cpp` 内直接构造；
PCAP 字节序、精度和残缺文件在 `tests/pcap_reader_tests.cpp` 内生成。它们都不含个人流量或凭据。

## 阶段1完整协议集

`stage1-protocols.pcap` 含 18 个合成包，逐包名称和预期状态见 `stage1-protocols.json`。
覆盖 IPv4/IPv6 TCP/UDP、SYN/ACK/FIN/RST、ARP请求回复、UDP/TCP DNS、VLAN/QinQ、扩展头与非IP。
所有地址采用文档示例地址，MAC采用本地管理示例地址，不含个人抓包。
`python tests/generate_stage1_samples.py` 可从标准库确定性重新生成这两个文件。
独立 TShark 比较脚本为 `tests/tshark_compare.py`，可选注册到标准 CTest。
已通过 18 包/312 字段对照；按 JSON 清单中的包号与离线程序字段输出比较。
真实报文证据仅保存在 build/stage1-evidence，不提交 Git。
