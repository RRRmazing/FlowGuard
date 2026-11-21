# FlowGuard 设计图生成记录

使用内置 image_gen 工具；均为概念提案，示例数据不代表运行结果。生成日期：2026-11-22。

## 主工作台 → flowguard-workbench-v1.png

```text
Use case: ui-mockup
Asset type: High fidelity Windows desktop Qt Widgets application design proposal, FlowGuard 流量哨兵.
Primary request: Create a beautiful polished professional desktop packet capture and network traffic analysis software UI, flat front-on actual application window, NOT a website, no browser, no device frame, no perspective. Landscape 1800x1200-ish. Crisp Chinese UI typography, high density but readable. Light cool off-white background, navy text, teal primary action, subtle borders, 6px corners, restrained blue/cyan/violet protocol chips. Realistic Qt desktop window chrome title "FlowGuard 流量哨兵" with minimize/maximize/close. Small teal shield mark with a white flowing network pulse in top left.
Composition: Large SINGLE main window filling canvas. Native menu "文件  采集  视图  帮助". Below a toolbar with device combo "WLAN · 192.168.1.108", secondary "刷新", disabled-looking "开始采集", active outlined red "停止", "打开 PCAP", "开始保存". A status pill "正在采集" and elapsed "00:05:12". Separate small capture settings line "捕获过滤 BPF: udp or tcp" with lock icon, illustrating capture options locked during running.
A slim left navigation rail with three text/icon items "报文工作台" active, "统计分析", "资源监控", bottom settings.
Main top has four compact factual metric tiles: "累计报文 12,486", "累计流量 8.42 MiB", "当前速率 214 pkt/s", "吞吐速率 96.3 KiB/s".
Under tiles a horizontal structured display filter strip labeled "显示筛选", protocol dropdown "全部协议", IP field placeholder "源或目的 IP", port field "端口", "应用", "重置". Small note "仅筛选列表 · 统计与保存不受影响".
Center packet table ~10 readable rows, columns "序号", "时间", "源地址", "目的地址", "协议", "长度(B)", "摘要". Plausible synthetic local IPv4, IPv6 and documentation IP addresses only. Chips TCP UDP DNS ARP IPv6. Selected DNS row 12481 from 192.168.1.108 to 192.168.1.1, length 74, summary "Standard query A example.com". Include another IPv6 UDP row, and ARP row, single pale amber row with status "截断". No intimidating security threats.
Bottom third split panel: left header "协议字段" tree expanded Frame / Ethernet II / IPv4 / UDP / DNS, with one selected "查询名称: example.com", and values source destination TTL 64 port 53. Right header "报文摘要" with large DNS pill, parse "解析完整", timestamp, original length 74 B captured 74 B, source/destination endpoint, and a muted box "仅展示解析字段 · 原始数据通过 PCAP 保存". NO hex viewer, no raw bytes. Above table footer "显示 2,000 条最近记录 · 匹配 2,000 条" and toggle "自动滚动" on.
Bottom status bar clearly distinct counters "采集队列丢弃 0" / "展示淘汰 10,486" / "保存：未开启" / "CPU 2.1%" / "内存 84.6 MiB". Small neutral bottom corner "设计示例数据".
Constraints: desktop engineering software, excellent alignment and hierarchy, compact native controls, realistic interactions, no giant web hero, no gradients or glassmorphism, no unrelated AI/security features. Chinese labels accurate. This is proposed design with illustrative data, not a screenshot of implemented code.
```

## 统计分析 → flowguard-statistics-v1.png

```text
undefined
```

## 图标 → flowguard-icon-concept-v1.png

```text
undefined
```
