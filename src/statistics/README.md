# 第二阶段：统计与速率（何俊杰）

`StatisticsEngine` / `calculateRate` 由 `core/module_contracts.h` 声明，链接
`flowguard_statistics`。统计器只在处理线程使用；Qt 通过 ProcessingSession 快照读取。

以 originalLength 统计字节、长度频次与 <=46 / 47..1500 / >1500 三分组；
频次中 >65535 归 65536，避免恶意长度无限增加键值。网络、传输、解析状态分别计数。
协议图表须把 Arp 与 Other 合并为网络“其他”，TCP/UDP 与 ARP 不能视为同层枚举。

calculateRate 返回区间 packet/s、byte/s 和 DNS fraction（0..1），按实际间隔计算；
间隔无效/非有限、累计计数回退或 DNS 增量大于总包增量时返回零。异常包仍计入累计统计。
离线时间序列按捕获时间分桶，由 ProcessingSession 维护，不使用文件导入速度。

公开结构保持 v1，StatisticsEngine 增加私有累计值；使用新版头文件重新构建所有调用方。
测试覆盖边界、分类、64 位字节数、DNS 分母、空闲区间、reset 与异常间隔。
