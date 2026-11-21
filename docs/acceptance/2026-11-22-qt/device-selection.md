# 网卡选择器与真实流量复核

本次为 `51a6086` 后的本地修改，尚未提交。包括此前的界面精简、计时标签修正，以及本次网卡选择器修复。

## 显示与设备完整性

- Npcap 当前返回 10 个设备，界面保留相同数量并逐一核对稳定 ID，没有按名称、类型或连接状态删掉设备。
- 使用 Windows IP Helper API 的 AdapterName GUID 关联 Npcap ID，读取友好名称、接口类型和连接状态。元数据读取失败时保留设备并显示状态未知，不把它当成不可采集。
- 已连接 WLAN 在首位；有线 Realtek 显示“以太网 · 有线以太网 · 未连接”；虚拟网卡、蓝牙和回环仍可选。
- 展开列表自动增加宽度，型号单独一行；IPv4 与 IPv6 数量单列，全部地址在可换行的详情中查看和复制。悬停提示包含完整设备标识。
- 每次刷新尽量保持原设备 ID，显示文本不再参与采集设备的定位。
- 原生截图只留在 build/device-selector-final-preview，包含本机实际地址，未纳入共享资料。

## 已执行验证

| 检查 | 结果 |
| --- | --- |
| MSVC Release 构建 | 成功 |
| 完整 CTest（含 TShark 字段对照） | 17/17 通过，无跳过 |
| 选择器模拟用例 | 有线未连接仍保留；虚拟网卡不优先；完整型号/IPv6 不丢失；刷新后 ID 保持 |
| Qt 真实设备检查 | 所有 Npcap ID 均在界面中，没有漏设备 |
| 真实 WLAN 5 秒采集/解析 | 处理 524 包、采集队列丢弃 0；前 256 包有界输出均为 Complete，均有源/目的 MAC 与 IPv4 字段 |
| Windows 原生 Qt 工作台 WLAN 联调 | 实际收到 8 包，进入列表、展开 Ethernet 字段并停止，通过 |

真实流量来自本机当前 WLAN；原始 JSON 字段输出只保留在忽略的 build 目录，未共享载荷或本机网络地址。两次短时验证的流量不同，不能将计数相加为一段测试。

## 支持范围与未验证项

- 课程要求是捕获进出本机的报文；本次确认 WLAN 的实际采集与 Ethernet/IP 字段展示。Ethernet、IPv4/IPv6、TCP/UDP、ARP/DNS 的固定样本及边界已有回归，不要求一次现场流量必须恰好出现每种协议。
- Npcap 枚举包含 Realtek PCIe GbE Family Controller，Windows 名称“以太网”，本次检查为未连接。有线设备已提供选择入口，但尚需接入网线、建立链路后作有线实机验收；不能用“已列出”代替“已实测”。
- 状态与地址是刷新时快照，配置了 IPv4 不等于物理链路已连接；插拔或切换网络后请刷新。
- 不承诺捕获其他机器的所有通信、解密 HTTPS/VPN 内容、解析任意链路类型或无线监控模式帧。回环 DLT=0 按现有合同标为 Unsupported；此限制不影响本次 DLT Ethernet 的实测。
- 这些短时结果不代替正式至少 24 小时持续采集与人工验收。

实现参考：[Windows GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)、[GetIfEntry2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2)、[Qt QComboBox](https://doc.qt.io/qt-6/qcombobox.html)。
