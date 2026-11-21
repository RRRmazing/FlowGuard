# 补充 UI 设计图生成记录

日期：2026-11-22。使用内置 image_gen，主工作台 v1 作为风格参考。图中数据全部用于设计演示，不是实际运行或长测证据。保留原 v1 文件。

## flowguard-workbench-v2.png

```text
Use case: ui-mockup. High fidelity Chinese Windows Qt Widgets desktop application FlowGuard 流量哨兵. Use the supplied main workbench image as STYLE REFERENCE only: preserve its professional cool off-white surfaces, dark navy text, teal selection and actions, fine grey borders, compact native controls, system titlebar and menu, left navigation 报文工作台 / 统计分析 / 资源监控. Front-on flat application screenshot proposal, landscape 1536x1024 or larger. NOT browser or website. Crisp readable Chinese text, excellent alignment. All values are illustrative, show 设计示例数据. Use same teal shield-wave icon. Bottom status bar ALWAYS includes clearly labeled 软件连续运行 1天 02:15:32, independently of session. No hex viewer or security threat features.
Asset: flowguard-workbench-v2.png, revised main workbench, selected TCP packet. Keep familiar original layout but give lower detail panel 50% of window so expanded fields are legible; 5 table rows only.
Top toolbar: disabled 网卡 WLAN, disabled 开始采集, enabled red 停止, visibly disabled 打开 PCAP, button 保存后续报文, green 正在采集, label 会话时长 00:05:12. Locked capture filter BPF udp or tcp.
Small four metrics cards 累计报文 12,486 / 累计流量 8.42 MiB / 当前速率 214 pkt/s / 吞吐速率 96.3 KiB/s.
Structured 显示筛选 strip, table columns 序号 时间 源地址 目的地址 协议 长度(B) 摘要, selected sequence 12480 at 2026-11-22 10:05:12.120 source 192.168.1.108 destination 192.168.1.1 TCP length 60 summary 52544 → 443 [SYN].
Lower left 60% width expandable tree "协议字段（选中报文）", all expanded:
Ethernet II
  源 MAC: 02:11:22:33:44:55
  目的 MAC: 02:AA:BB:CC:DD:EE
  以太网类型: 0x0800 (IPv4)
IPv4
  源 IP: 192.168.1.108
  目的 IP: 192.168.1.1
  IP 版本: 4
  TTL: 64
  协议号: 6 (TCP)
TCP
  源端口: 52544
  目的端口: 443
  标志位: 0x02
  SYN: 1   ACK: 0   FIN: 0   RST: 0
Lower right "报文摘要", TCP blue badge, 解析完整 green label, source/destination endpoints, 原始长度60B 捕获长度60B. Below muted teaching hint "选中 IPv6 报文时显示 IP版本 6、Hop Limit 与 Next Header；不适用字段显示 —" (this is a compact field hint, not simultaneously another selected packet). Another muted hint "仅展示解析字段 · 原始数据通过 PCAP 保存".
Footer counters 采集队列丢弃0 / 展示淘汰10,486 / 保存未开启 / 软件连续运行1天02:15:32. Must include explicit MAC, EtherType, IP version, protocol, ports and all four TCP flags.
```

## flowguard-resources-v1.png

```text
Use case: ui-mockup. High fidelity Chinese Windows Qt Widgets desktop application FlowGuard 流量哨兵. Use the supplied main workbench image as STYLE REFERENCE only: preserve its professional cool off-white surfaces, dark navy text, teal selection and actions, fine grey borders, compact native controls, system titlebar and menu, left navigation 报文工作台 / 统计分析 / 资源监控. Front-on flat application screenshot proposal, landscape 1536x1024 or larger. NOT browser or website. Crisp readable Chinese text, excellent alignment. All values are illustrative, show 设计示例数据. Use same teal shield-wave icon. Bottom status bar ALWAYS includes clearly labeled 软件连续运行 1天 02:15:32, independently of session. No hex viewer or security threat features.
Asset: flowguard-resources-v1.png, full resource monitoring page, left navigation 资源监控 selected. Retain main window title and capture toolbar with green 正在采集, disabled 打开PCAP, 停止, 会话时长00:05:12.
Main heading "资源监控", subtitle "软件进程资源 · 连续运行记录", right 设计示例数据.
Very clear top time card with five fields:
软件启动 2026-11-21 08:00:00
当前时间 2026-11-22 10:15:32
连续运行 1天 02:15:32
本次采集开始 2026-11-22 10:10:20
会话时长 00:05:12
Timezone label 本地时间 UTC+08:00. Distinguish process uptime versus capture duration.
Four metric tiles CPU 2.1% / 工作集内存84.6MiB / 累计读取128MiB / 累计写入64MiB.
Middle two side-by-side time line charts CPU占用(%) and 工作集内存(MiB), teal and blue, steady low usage. Caption 每秒采样 · 屏幕最多保留3600点.
Bottom left card "采集与展示" small two column metric grid: 驱动接收12486 / 驱动丢弃0 / 接口丢弃不可用 / 采集队列32包 / 队列占用24KiB / 采集队列丢弃0 / 展示淘汰10486 / 已保存报文3200.
Bottom right card "连续运行记录" with green 日志记录中 badge, "记录文件 resources.csv", "记录开始 2026-11-21 08:00:00", "运行事件 logs/events.log", subdued text "记录 CPU、内存、累计进程 I/O 与异常；日志独立于屏幕历史保留". A neutral note "示例设计，不代表已完成24小时验收".
Small footnote "CPU为进程占整机能力比例；I/O为进程累计读写量，不等于物理磁盘吞吐". No reset timer button, no fabricated test pass badge.
```

## flowguard-replay-v1.png

```text
Use case: ui-mockup. High fidelity Chinese Windows Qt Widgets desktop application FlowGuard 流量哨兵. Use the supplied main workbench image as STYLE REFERENCE only: preserve its professional cool off-white surfaces, dark navy text, teal selection and actions, fine grey borders, compact native controls, system titlebar and menu, left navigation 报文工作台 / 统计分析 / 资源监控. Front-on flat application screenshot proposal, landscape 1536x1024 or larger. NOT browser or website. Crisp readable Chinese text, excellent alignment. All values are illustrative, show 设计示例数据. Use same teal shield-wave icon. Bottom status bar ALWAYS includes clearly labeled 软件连续运行 1天 02:15:32, independently of session. No hex viewer or security threat features.
Asset: flowguard-replay-v1.png, desktop software file replay interaction design board. Same style and shell. One large MAIN app window in PAUSED file replay state, plus a clean floating inset dialog at lower right clearly captioned "启动前：打开文件设置" (inset is separate prior state, do not imply active file picker during replay).
Main toolbar FILE source "stage1-protocols.pcap", disabled 开始采集 and 打开PCAP, teal enabled 继续回放, red 停止, disabled speed value 1.0×, amber status 已暂停, 会话时长00:00:12.
Heading 报文工作台, source banner "文件回放 · 按原捕获时间 · 1.0×", "暂停读取，已分析结果保留".
Metrics 已处理报文18 / 原始流量2.41KiB. Table 5 synthetic TCP UDP DNS ARP rows, selected UDP row, source192.168.1.108 destination192.168.1.1; details full simple IPv6 UDP EXAMPLE selected row actually use 2001:db8::1 to 2001:db8::2, EtherType0x86DD, IP版本6, Hop Limit64, Next Header17(UDP), source port5353 destination5353. Label "IPv6 / UDP 字段示例"; all data for selected IPv6 UDP row consistent.
Bottom file summary "当前捕获时间 2026-11-21 14:23:58.112" and "显示筛选不影响统计与保存". No playback seek bar, no completion percentage, no runtime speed editing. Saved data label 未开启保存.
Lower right inset contains file input example.pcap with browse button, radio 快速导入分析 and selected 按捕获时间回放, speed spinbox1.0× with allowed0.1–100×, explanatory copy "启动后锁定倍速", file type 经典PCAP (*.pcap), buttons 取消 / 开始回放. Small error example directly below "PCAPNG 暂不支持，请转换为经典PCAP".
One compact state strip below inset "回放中：暂停 → 已暂停：继续 → 文件结束：分析完成", no automatic restart.
Footer independent 软件连续运行1天02:15:32. Make inset not cover critical IPv6 field tree.
```

## 资源页定点修正

将右上时间卡片中的会话时长从 00:00:12 修正为 00:05:12，与当前时间减采集开始时间及顶部工具栏保持一致，其余布局与内容保留。
