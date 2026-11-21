# 第二阶段交接：处理与存储 → 第三阶段 Qt

日期：2026-11-22。负责人：何俊杰。分支：`feat/processing-storage`，起点 `7e38e47`。
用户最新分工覆盖原任务书的逐人分工：第二阶段后台由何俊杰独立完成，第三阶段全部
Qt 可视化与集成由谢福祥完成。已有解析器和 PCAP Reader 保持复用，未重写。

## 1. 已交付的后台能力

| 能力 | 接口/实现 |
| --- | --- |
| 累计统计 | StatisticsEngine：原始字节、长度频次、三区间、网络/传输分类、DNS 和解析状态 |
| 实时速率 | calculateRate：区间包/秒、字节/秒、DNS 占比；live 用 steady_clock 的实际间隔 |
| PCAP 保存 | PcapWriter：经典 PCAP 2.4、微秒时间戳、中文路径、CREATE_NEW 拒绝覆盖、文件上限和显式 flush |
| 统一流程 | ProcessingSession：实时/文件互斥，经同一 parsePacket 和统计器；可选原始数据保存 |
| 回放 | 无节奏导入，或按捕获时间 0.1..100 倍速回放；文件来源支持暂停/继续/停止 |
| 界面交接 | 线程安全的统计/状态快照、最多 3600 个时间点、带 sessionId 的有界报文批次 |

新增产品代码不依赖 Qt。Qt 主程序、控件、图表、显示过滤、资源监控仍由队友第三阶段接入。
测试脚本的 psutil 只记录验收资源，不是产品 sampleResources 实现。

## 2. 给队友的最小调用流程

链接 `flowguard_processing`，包含 `core/processing_session.h`。从新的功能分支同步
本次完整公共头文件并重新构建，不能把旧类布局和新静态库混用。

```cpp
#include "core/processing_session.h"

flowguard::ProcessingSession backend;
flowguard::CaptureOptions capture;
capture.deviceId = selectedDeviceId; // 从 enumerateDevices 得到的原样标识
capture.bpfExpression = "ip";        // 空字符串代表不设置捕获过滤
flowguard::ProcessingOptions options;
// 可在开始时配置保存；也可运行中调用 enableSaving。
// options.savePath = std::filesystem::path(nativeWideSavePath);
auto started = backend.startLive(capture, options);
// started.ok()==false 时展示 started.message，不假装进入采集状态。

auto status = backend.snapshot();   // 统计、曲线、错误和保存状态
auto batch = backend.takePackets(); // 每次最多 500 条，带 sessionId
// 只展示当前 sessionId 的批次；ParsedPacket.fields 可直接构造字段树。
// 停止按钮触发后台控制线程调用 backend.stop()。
```

Qt 适配建议：控制对象由专门后台线程持有，开始/停止/导入通过队列投递到同一控制线程。
不要在 GUI 主线程执行打开设备、文件启动或 stop/join。Qt 主线程用 QTimer 每 100 ms
读取 snapshot/takePackets 并更新模型；不为每个报文发送独立 queued signal。
对象生命期需覆盖所有读者；销毁前停止定时器、结束控制请求并 stop，避免悬空引用。

所有 start/stop/enableSaving/disableSaving/pause/resume 控制方法在同一控制线程串行调用。
snapshot 可并发读取；takePackets 仅给一个 UI 消费者使用。输入错误与 I/O 错误返回
OperationResult；后台错误通过 snapshot.error 报告，不跨线程抛给 UI。

## 3. 文件、回放与保存控制

- `startFile(nativePath, options)` 开新会话并清空统计、历史和待显示数据；默认尽快导入。
- `options.pacedReplay=true`、`replaySpeed=1` 按原时间间隔回放。pause/resume 仅适用于活动文件会话；它们可重复调用。
- 暂停后最多可能完成一个已进入处理中的包；后续不再读取处理。恢复时暂停时长不算作回放经过时间；轮询精度约 10 ms。
- live 与 file 不能同时开始；切换须先 stop。会话编号递增，停止后的结果保留至下一次成功初始化。
- `enableSaving(path, maxBytes)` 只提交异步保存请求，返回成功不等于文件已打开；界面观察 savingRequested、savingActive 和 savingError。切换保存目标会先关闭旧 Writer。
- `disableSaving()` 异步关闭并 flush，不停止解析/统计。savedPackets 是本会话所有保存目标合计包数；每个文件有独立大小限制。
- 保存失败或达到默认 1 GiB 时，关闭保存并保留 savingError；分析继续。已有文件永不覆盖，不自动删除或轮转。
- live 需要第一包才能确定 DLT，因而保存请求可能短暂为 requested=true、active=false；整个会话无包时不会猜 DLT 创建文件。file 可从全局头建立合法空 PCAP。
- stop 会停止采集、排空已入队包，再关闭 Writer；文件来源则停止回放，不强行分析余下全部文件。析构调用 stop。
- PcapWriter 可单独使用，新增 flush；需要检查显式 close 的返回值。输出原字节与长度不变，纳秒输入截断至微秒（误差小于 1 微秒）。
- `Stopped` 是手动结束，`Completed` 是文件自然 EOF，`Failed` 是来源/处理致命错误；保存错误是独立字段。空闲对象为 Idle。

## 4. 图表口径与边界

- 统计以处理线程实际收到的每一包为准，包含异常包。采集端 BPF 和入队丢包单列；显示筛选不允许修改后台统计或保存范围。
- lengthGroups 顺序为 <=46、47..1500、>1500；长度频次按原长度，>65535 归键 65536。网络 Arp 与 Other 相加构成“IPv4/IPv6/其他”柱状图的其他。
- TCP/UDP 取 transportCounts，ARP 取 networkCounts。DNS 占比为当前采样区间 DNS 包数/总包数，0..1，界面显示百分比时乘 100。
- 实时 TimeSample.intervalSeconds 是实际单调时间间隔；networkCounts/transportCounts 是该区间增量。空闲期仍生成零流量采样，最后一次停止可追加不足一秒的采样。
- 离线按捕获时间整秒分桶，不能把导入速度当流量速率。最多保留最近 3600 秒；窗口内乱序更新桶，过旧乱序仍计累计统计并增加 lateHistoryPackets，不回插历史曲线。缺失秒补零。
- 时间点不含原始字节或完整字段树。待显示解析结果默认最多 2000 条，pendingLimit 可设为 1..2000；满时丢最旧展示记录，增加 displayDroppedPackets，分析与保存继续。
- `takePackets(max)` 每批最多 500 条；丢弃 UI 数据与采集队列丢包是两种指标，不能相加为同一种网络丢包。
- 本阶段未实现 matchesDisplayFilter、sampleResources 或 Qt 接入；这些属于第三阶段。公共结构和方法可继续复用，但有声明不等于已实现。

## 5. 命令行和验收

按根 README 配好 MSVC x64、Qt/Ninja/SDK 与当前终端的运行环境：

```powershell
cmake --preset windows-msvc
cmake --build --preset windows-msvc
ctest --test-dir build/windows-msvc --output-on-failure --no-tests=error
.\build\windows-msvc\flowguard_processing_probe.exe --input .\tests\data\stage1-protocols.pcap
.\build\windows-msvc\flowguard_processing_probe.exe --input .\tests\data\stage1-protocols.pcap --output .\build\新文件.pcap
# live 模式：设备 ID 从枚举取，--seconds 允许 1..86400；只显示统计，不打印载荷/IP。
.\build\windows-msvc\flowguard_processing_probe.exe --device $deviceId --bpf "ip" --seconds 5
```

处理 probe 使用 Windows 宽字符参数入口以正确支持中文路径。界面/库使用原生 filesystem::path，
不要把 Windows 本地代码页字节直接当 UTF-8。
probe 是限时验收工具，--seconds 默认 5 秒；较大的离线输入需显式给足时长，
到时会按手动 stop 保留已分析结果，不代表自然 EOF。ProcessingSession 本身没有这个限时，
第三阶段界面可一直运行至 Completed 或用户停止。

`stage2_processing_storage` 检查统计边界、64 位计数、中文路径、保存重读、拒绝覆盖、
文件上限、暂停恢复、异步保存切换、会话互斥、时间序列和显示缓冲。
短时实机试运行脚本是 `tests/stage2_soak.py`；需要测试专用 psutil，输出目录必须不存在。
用户已明确将本轮持续测试改为 300 秒，不沿用原任务书 1～2 小时的时长要求。
这个 5 分钟结果不等同于第三阶段完成后的正式 24 小时测试。

下一步只将本分支交给队友检查和接 Qt，main 的合并另行共同确认。
