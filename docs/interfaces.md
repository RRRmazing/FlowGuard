# FlowGuard 公共开发接口文档 v1.0

更新日期：2026-11-21。原始设计源码基线：`main` / `3dcb4d67ba543df5539c61fa9e93195c9015d02b`。

后续实现状态（`feat/capture`）：公共声明头文件已在 `44ecf65` 落地；当前分支已实现
`enumerateDevices()` 与 `flowguard_capture_probe --list-devices`，通过独立编译、
模拟设备测试和本机实际枚举。除此以外的功能仍为待实现合同。双方须取得该分支的
公共头文件提交，或由本人将其 cherry-pick 到自己的功能分支；不据此自动合并 main。

供何俊杰、谢福祥及双方使用的 AI 共同开发、代码审查和联调使用。职责依据《网络流量检测课程设计任务书_最终整合版.docx》的“阶段职责分配”；代码与构建依据本基线的 README、CMake 配置、公共头文件和阶段指南。

## 1. 依据、状态与协作边界

### 1.1 已有事实与本次新增合同

| 内容 | 状态与依据 |
| --- | --- |
| C++17、Qt Widgets、Npcap、CMake、MSVC x64 | 阶段 0 已建立，见根目录 README 和 CMakeLists.txt |
| `RawPacket`、`PacketRecord` 与三个协议/状态枚举 | 已存在于 `src/core/packet_types.h`，本次不改变其字段或枚举值 |
| 构建、依赖加载和窗口启动 | 本机已验收，记录在 `docs/acceptance/2026-11-21-hejunjie/`；不代表采集、解析等功能已完成 |
| 本文第 4 节函数、扩展类型和 Qt 交接规则 | 已落地公共声明；仅枚举有实现，其他功能仍待实现，Qt 交接规则仍是设计约定 |
| 队列容量、刷新周期、历史上限等 | 为合作开发选定的 v1 可调默认值，尚非性能测试结论 |

本文区分接口合同与实际实现；有声明不等于有实现。公共头文件已先行提交，后续分别开发模块。
双方应使用本文的同名类型和方法；调整签名、所有权或统计含义时，必须同步修改本文与调用方。

Qt 继续用于主窗口、控件、图表、信号/槽和界面刷新。核心数据及解析/统计接口使用标准 C++，便于离线测试；这不改变整个项目使用 Qt 的技术路线。图表实现前按 README 补齐同套件 Qt Charts，并在 CMake 中增加相应依赖。

### 1.2 按最终任务书的阶段明细落实负责人

| 模块/共享文件 | 主要负责人 | 交付及边界 |
| --- | --- | --- |
| `src/capture` | 何俊杰 | 枚举网卡、捕获、开始/停止、采集线程、有界队列、应用 BPF |
| `src/parser` | 谢福祥 | 协议解析、字段树、ARP/DNS、边界检查和固定样本测试 |
| `src/statistics` | 何俊杰 | 长度/协议计数、速率和时间序列的数据接口 |
| `src/storage` | 谢福祥 | PCAP 读取、保存和错误处理；按阶段细表分工，不按简表概述重复实现 |
| `src/ui/main_window.*`、`src/main.cpp`、系统处理流程 | 何俊杰 | 统一主窗口、报文列表、字段树显示、控制入口、实时与离线集成 |
| 独立图表/显示过滤/资源监控组件 | 谢福祥 | 开发独立组件交由主窗口接入，避免双方同时修改 main_window |
| `src/core`、CMakeLists.txt、本文 | 何俊杰合并维护，双方审查 | 谢福祥提出所需字段和依赖变更，由集成负责人统一合并 |

BPF 由谢福祥提供输入配置与过滤测试，何俊杰在采集层编译并安装；文件按钮和保存控制由何俊杰接入，实际文件读写由谢福祥实现。

仓库阶段 1 是离线解析、阶段 2 是实时采集；任务书阶段 1 将二者合称“网络底层”。二者编号不同，不改变负责人。沟通和提交时同时写模块名，例如“采集：网卡枚举”，避免只说“完成阶段 1”。

### 1.3 版本同步规则

- 功能分支从最新 `main` 创建：采集使用 `feat/capture`，解析使用 `feat/parser`；存储、统计、图表分别使用对应的 `feat/*` 分支。
- 公共头文件先以独立提交共享，双方更新自己的功能分支后实现；当前不直接提交或合并 main。代码未推送前，聊天中的文档不能代替队友仓库中的版本。
- 每次交接注明 commit、模块、接口版本、已实现/未实现方法、运行命令和真实测试结果。
- 本次文档不自动提交或推送；共享前只暂存明确检查过的文件。当前残留的个人 `local-env.cmd` 不再被新版 Git 忽略，不能提交。
- 按最新 README 使用标准 CMake/CTest；旧 `scripts/build.cmd`、`run.cmd`、`test.cmd` 等已删除，不作为后续运行入口。

## 2. 数据流、生命周期与所有权

```text
采集线程 ──拥有字节副本的 RawPacket──> 有界队列 ──> 处理线程
PCAP 导入 ──PcapReader::readNext─────────────────> 处理线程
                                                   │
                         ┌─────────────────────────┤
                         │                         │
                parsePacket(raw, sequence)   PcapWriter::write(raw)
                         │                    仅启用保存时调用
                     ParsedPacket
                         │
               StatisticsEngine::add(record)
                         │
                  有界 UI 结果缓存
                         │
              Qt 主线程批量取出并刷新列表/图表
```

1. 实时采集与离线导入互斥，切换前停止旧来源并处理完其剩余队列。新的会话重置序号、统计、列表和图表；旧会话消息不得混入新会话。
2. 集成层持有一个会话编号；每批 UI 数据携带该编号。界面只接收当前会话，序号从 1 开始递增。
3. `RawPacket` 自持有 `std::vector` 字节副本。不得把 Npcap 的临时指针、局部引用或裸 `pcap_t*` 传给队列和界面。
4. 采集复制后移动入队；处理线程拥有出队包，完成解析和可选保存后释放原始字节。界面保存解析字段，不永久保留所有原始流量。
5. `CaptureSession` 的控制方法由同一控制线程串行调用；`tryPop` 仅由一个处理线程调用；`status` 可跨线程读取一致快照。
6. 解析器无状态，可分别用于固定样本、实时与文件输入。统计器、Reader、Writer 各自仅由处理线程调用，不自行操作 UI。
7. Qt 主线程不抓包、不读大文件、不做磁盘写入、不等待采集线程退出。开始/停止和导入工作由集成层后台执行，状态再通知 UI。

## 3. 已有类型必须保持的含义

### 3.1 RawPacket

| 字段 | 含义 |
| --- | --- |
| `timestamp` | `system_clock::time_point`，报文捕获时间；PCAP 微秒/纳秒精度读入时转换 |
| `originalLength` | 线上原始长度，用于字节总量、长度分组、速率统计 |
| `capturedLength` | 实际保留字节数，用于解析边界检查 |
| `linkType` | PCAP DLT 值；默认 1 是 Ethernet，不代表所有输入都是 Ethernet |
| `bytes` | 报文原始字节；`bytes.size() == capturedLength <= originalLength` |

采集/读取层先校验长度，解析器仍须独立检查。长度约束不满足返回 `Malformed`，不能越界。

### 3.2 PacketRecord

保留原有 `sequence`、`timestamp`、两类长度、`network`、`transport`、`status`、MAC/IP、EtherType、IP 版本、TTL/Hop Limit、IP 协议号、端口、TCP flags、`isDns`、`summary` 和 `diagnostic`。

- MAC 统一为小写冒号格式；IPv4 为点分十进制，IPv6 为压缩文本；所有文本使用 UTF-8。
- 空字符串或空 `optional` 表示字段不可用；数值零是合法数据，不作错误标记。
- `network` 与 `transport` 独立分类。ARP 是网络分类，不是 TCP/UDP 的同层协议。
- TCP flags 保存原始位掩码，由字段树展开 SYN/ACK/FIN/RST 等。
- `Complete`：所支持的协议字段可完整解析；`Truncated`：捕获/文件中缺少本应存在的字节；`Malformed`：已知字段自相矛盾；`Unsupported`：链路/协议/重组能力不支持。
- 同时遇到多个问题时，优先级为 `Malformed > Truncated > Unsupported > Complete`；保留此前安全取得的字段，填写 `diagnostic`。
- `capturedLength < originalLength` 的包至少标为 `Truncated`，即便当前头部可读取完整，也不得把捕获截断隐藏为完整报文。
- 解析器先复制时间和长度到 `record`，再解析字段，保证异常包也可显示和统计。

## 4. 待实现的公共接口

下方是共同采用的声明合同，不表示每个方法均已实现。公共声明已落入 `src/core/module_contracts.h`；各模块自己的头文件包含它，不复制声明。现有 `packet_types.h` 保持不变。

预期的设备、文件和输入错误使用 OperationResult/ParseStatus 表达；资源已取得后发生失败须释放。后台线程入口捕获未预期异常并转换为会话错误，禁止异常直接逃逸线程造成进程退出。

`ParsedPacket` 包装现有 `PacketRecord` 并携带字段树，避免双方分别扩写原有结构。函数和类实现仍位于各自模块目录，不在公共头文件中实现业务。

```cpp
#pragma once
#include "core/packet_types.h"
#include <array>
#include <cstddef>
#include <filesystem>
#include <map>

namespace flowguard {

enum class ErrorCode {
    None, InvalidArgument, InvalidState, DeviceError,
    FilterError, IoError, Unsupported, ResourceLimit
};
struct OperationResult {
    ErrorCode code = ErrorCode::None;
    std::string message;
    bool ok() const { return code == ErrorCode::None; }
};

struct CaptureDevice {
    std::string id;                   // 传回 Npcap 的稳定设备标识
    std::string description;          // 供用户选择，不作设备键值
    std::vector<std::string> addresses;
    bool loopback = false;
};
struct DeviceListResult {
    OperationResult result;
    std::vector<CaptureDevice> devices;
};
struct CaptureOptions {
    std::string deviceId;
    std::string bpfExpression;         // 空字符串表示不过滤
    std::uint32_t snapshotLength = 65535;
    int readTimeoutMs = 100;
    bool promiscuous = false;
    std::size_t maxQueuePackets = 8192;
    std::size_t maxQueueBytes = 64 * 1024 * 1024;
};
enum class CaptureState { Stopped, Running, Failed };
struct CaptureStatus {
    CaptureState state = CaptureState::Stopped;
    OperationResult lastError;
    std::uint64_t receivedPackets = 0;
    std::uint64_t enqueuedPackets = 0;
    std::uint64_t queueDroppedPackets = 0;
    std::uint64_t invalidPackets = 0;
    std::size_t queuedPackets = 0;
    std::size_t queuedBytes = 0;
    std::optional<std::uint64_t> driverReceived;
    std::optional<std::uint64_t> driverDropped;
    std::optional<std::uint64_t> interfaceDropped;
};
DeviceListResult enumerateDevices();
class CaptureSession {
public:
    CaptureSession();
    ~CaptureSession();
    CaptureSession(const CaptureSession&) = delete;
    CaptureSession& operator=(const CaptureSession&) = delete;
    OperationResult start(const CaptureOptions& options);
    void stop();
    bool tryPop(RawPacket& packet);
    CaptureStatus status() const;
    // 具体私有成员由实现者补充；不暴露 pcap_t 或内部队列。
};

struct ProtocolField {
    std::string name;
    std::string value;
    std::vector<ProtocolField> children;
};
struct ParsedPacket {
    PacketRecord record;
    std::vector<ProtocolField> fields;
};
ParsedPacket parsePacket(const RawPacket& packet, std::uint64_t sequence);

struct StatisticsSnapshot {
    std::uint64_t totalPackets = 0;
    std::uint64_t totalBytes = 0;
    std::map<std::uint32_t, std::uint64_t> lengthFrequency;
    std::array<std::uint64_t, 3> lengthGroups{};
    std::map<NetworkProtocol, std::uint64_t> networkCounts;
    std::map<TransportProtocol, std::uint64_t> transportCounts;
    std::map<ParseStatus, std::uint64_t> parseCounts;
    std::uint64_t dnsPackets = 0;
};
struct RateSample {
    double packetsPerSecond = 0;
    double bytesPerSecond = 0;
    double dnsFraction = 0;            // 0..1，界面自行乘 100 显示百分比
};
class StatisticsEngine {
public:
    void reset();
    void add(const PacketRecord& record);
    StatisticsSnapshot snapshot() const;
};
RateSample calculateRate(const StatisticsSnapshot& previous,
                         const StatisticsSnapshot& current,
                         double elapsedSeconds);

enum class ReadStatus { Packet, EndOfFile, Error };
struct PcapFileInfo {
    std::uint32_t linkType = 1;
    std::uint32_t snapshotLength = 65535;
    bool nanosecondPrecision = false;
};
class PcapReader {
public:
    PcapReader();
    ~PcapReader();
    PcapReader(const PcapReader&) = delete;
    PcapReader& operator=(const PcapReader&) = delete;
    OperationResult open(const std::filesystem::path& path);
    PcapFileInfo info() const;
    ReadStatus readNext(RawPacket& packet, OperationResult& result);
    void close();
};
struct PcapWriteOptions {
    std::uint32_t linkType = 1;
    std::uint32_t snapshotLength = 65535;
    std::uint64_t maxFileBytes = 1024ULL * 1024 * 1024;
};
class PcapWriter {
public:
    PcapWriter();
    ~PcapWriter();
    PcapWriter(const PcapWriter&) = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;
    OperationResult open(const std::filesystem::path& path,
                         const PcapWriteOptions& options);
    OperationResult write(const RawPacket& packet);
    OperationResult close();
};

enum class ProtocolFilter { All, IPv4, IPv6, Arp, Tcp, Udp, Dns, Other };
struct DisplayFilter {
    ProtocolFilter protocol = ProtocolFilter::All;
    std::optional<std::string> ipAddress;
    std::optional<std::uint16_t> port;
};
bool matchesDisplayFilter(const PacketRecord& record,
                          const DisplayFilter& filter);

struct ResourceSample {
    std::chrono::system_clock::time_point timestamp;
    std::optional<double> cpuPercent;  // 进程占整机总逻辑处理器能力，0..100
    std::optional<std::uint64_t> workingSetBytes;
    std::optional<std::uint64_t> processReadBytes;
    std::optional<std::uint64_t> processWriteBytes;
};
ResourceSample sampleResources();

} // namespace flowguard
```

### 4.1 采集方法的行为

- `enumerateDevices` 失败返回错误和空列表；成功但无网卡返回成功和空列表，由 UI 提示。
- `start` 校验设备、正数容量、快照长度和读取超时，打开网卡、检查链路类型、编译并安装 BPF 后才成功。失败释放已取得的资源；重复启动返回 `InvalidState`。
- 读取循环必须有可退出机制；超时不能当成错误。停止请求应在正常情况下 2 秒内结束，不只依赖下一包到来。
- 每次成功开始新会话重置队列和本模块计数。容量达到包数或字节数任一上限时丢弃新包并递增 `queueDroppedPackets`；单包超出容量也如此。
- `receivedPackets` 统计本采集循环交付的包头数；分成成功入队、队列丢弃和非法输入三类。运行时另有队列内/已消费数量，不能把驱动统计混为应用统计。
- `tryPop` 非阻塞；无包返回 false 且不修改输出，成功时将字节所有权交给调用者。
- `stop` 可重复调用，返回前采集线程退出、设备已释放。它保留剩余队列供处理线程排空；集成层排空后才能结束旧会话。
- 致命读取错误使状态变为 `Failed` 并记录错误，释放设备；之后仍允许排空已入队数据。析构必须安全停止。
- BPF 在新采集会话开始前生效；运行中修改需要停止并重新开始。错误表达式返回 `FilterError`，不能悄悄退回“全部采集”。

### 4.2 解析范围与字段树

- 第一版支持 DLT_EN10MB(1) Ethernet、常见 802.1Q/802.1ad VLAN（最多两层）、IPv4、IPv6、TCP、UDP、ARP、DNS。其他链路类型返回 `Unsupported`，不硬套 Ethernet；回环设备是否可解析由实际 DLT 决定。
- 对 Ethernet/IP/传输层头逐级检查长度；支持安全跳过 IPv6 Hop-by-Hop、Routing、Destination Options、Fragment、AH 扩展头，最多 8 个；ESP 或不认识的扩展返回 `Unsupported`。
- 不做 IP 分片重组或 TCP 流重组。分片仍展示可安全解析的网络字段；实际分片报文状态为 `Unsupported`，不从非首片猜测端口。IPv6 原子分片可继续解析。
- ARP 字段树至少含操作码、发送/目标 MAC 与 IP；Ethernet/IPv4 ARP 可填入已有 source/destination 字段。
- DNS 至少检查 12 字节头、计数字段和实际报文边界，展示事务 ID、flags、问题/答案数量，以及可解码的首个问题名、类型和类别；压缩指针检查边界与循环，限制跳转 16 次。
- `isDns` 仅在 TCP/UDP 任一端口为 53 且 DNS 内容结构验证通过时置 true。DNS over TCP 还须有 2 字节长度及完整消息；单包多消息检查首条完整消息，不跨 TCP 段拼接。仅端口为 53 不算已识别 DNS。
- 字段树按 Ethernet → VLAN（若有）→ IPv4/IPv6/ARP → TCP/UDP → DNS 排列；所有节点文本总计最多 16 KiB，节点最多 256 个、深度最多 16 层，超限停止展开并在 diagnostic 说明；已有基本解析字段保留。
- DNS 未通过校验时保留 TCP/UDP 分类，按照实际缺字节或格式问题设置状态。外层的包长不能替代内层协议边界。

### 4.3 统计口径与图表

- 每个处理线程接收的报文仅调用一次 `add`，异常包也计入总包数；未知分类进入 Other。被采集 BPF 排除和入队前丢弃的包不在处理统计内，单独显示丢弃指标。
- 字节数与长度频次使用 `originalLength`；`lengthGroups[0..2]` 固定为 `<=46`、`47..1500`、`>1500`。长度 0 归第一区间，并保留其解析异常信息。长度频次键 0..65535 保留精确值，超过 65535 的统一进入键 65536，图中标为“>65535”；避免异常长度造成无限增长的键集合，累计字节数仍使用原始长度。
- 网络计数保留 Arp/IPv4/IPv6/Other；“IPv4/IPv6/其他”图中的其他 = Arp + Other。IPv4/IPv6 饼图同时提供其他，避免分母含糊。
- TCP、UDP 取传输层计数，ARP 取网络层计数，分别交给 TCP/UDP/ARP 柱状图；不能把两类枚举合并覆盖。
- map 缺少某枚举键等价于零；计数器均为会话内累计的 64 位数。
- `calculateRate` 返回累计差值/实际间隔秒数，DNS 占比是区间 DNS 增量/区间总包增量。无包时占比为零；间隔非正或任一计数回退时三个结果均为零，不能跨 reset 计算。
- 实时每秒采样，间隔使用 `steady_clock` 的实际差值。离线分析按捕获时间的整秒分桶，不把文件读取速度显示成网络速率；只维护当前最多 3600 秒时间窗口，超出窗口的旧桶淘汰，落入该窗口前的乱序包仍计入累计统计，但不回插历史曲线，并在导入结果中说明。窗口内乱序包更新对应桶；无流量秒补零。
- 保留长度频次折线、长度三区间柱状、IPv4/IPv6/其他柱状、IPv4/IPv6 饼图、TCP/UDP/ARP 柱状及 DNS 占比折线，参照仓库 stages.md 中课程必做项；任务书将部分长度图称为扩展，不据此删掉课程要求。

### 4.4 PCAP 读取、保存与回放

- 路径使用 `std::filesystem::path`，支持中文路径。`open` 仅对已关闭对象调用，重复打开返回 `InvalidState`。
- Reader 第一版支持经典 PCAP 2.4、小/大端、微秒/纳秒输入；第一版不支持 PCAPNG，须识别并返回 `Unsupported`。
- Reader 成功返回一包时为 `Packet` 且 result 成功；记录之间的正常 EOF 为 `EndOfFile` 且 result 成功；残缺文件头/包头/包体是 `Error`，不能当作正常 EOF。非 Packet 时输出参数不变。
- 空的经典 PCAP（合法全局头、没有记录）允许正常 EOF；零字节文件不合法。记录须满足 caplen <= originalLength、caplen <= 文件 snaplen、单包 caplen <= 16 MiB；非法记录返回错误，避免任意大分配。
- Writer 写经典 PCAP，微秒精度；纳秒输入下取整至微秒。保存原始字节、originalLength、capturedLength 和捕获时间，不从 PacketRecord 重建报文。
- Writer 拒绝覆盖已有文件；同一文件的 linkType 固定，包的 caplen 不得超出选定 snapshotLength。参数/格式不一致返回错误，不截断后伪装成功。
- 文件大小含头部；若下一记录会越过默认 1 GiB 上限，返回 `ResourceLimit`，不写该记录。集成层关闭保存、显示到达上限，采集/统计继续；v1 不自动删文件、不隐式磁盘轮转。
- 写入失败停止本次保存并报告；每秒及关闭时 flush，`close` 返回 flush/关闭错误；重复关闭成功。析构释放资源，正式结束保存须显式 close 检查结果。
- 开启保存之后只写后续进入处理流程的包；不承诺保存 UI 历史或已入队前丢掉的包。停止采集后排空队列，再关闭 Writer，最后完成会话。
- “导入分析”尽快处理；“回放”由集成层控制节奏，仍逐包调用同一个 Reader/解析/统计流程，提供暂停、继续、停止，不额外实现第二套解析器。

### 4.5 Qt 界面、显示过滤与资源监控

- UI 数据带 `sessionId`、按序 `ParsedPacket` 批次和累计统计快照，通过互斥保护的有界缓存交接。UI 每 100 ms 用 QTimer 取最多 500 条；不为每一包投递一个 Qt queued signal，避免事件队列无界增长。
- UI 待取缓存最多 2000 条，溢出淘汰最旧展示记录并累计 UI 丢弃数；不影响后台解析、统计和保存。列表也最多 2000 条，图表每个序列最多 3600 点；超出淘汰最旧项。
- 列表至少展示序号、时间、源/目的地址、协议、原始长度和摘要；选中项直接用字段树展示。v1 不提供原始十六进制载荷查看，以免另存无限量原始字节。
- `DisplayFilter` 中启用条件按 AND 组合；IP 匹配源或目的地址，port 匹配源或目的端口；IP 先规范化，不能用模糊子串匹配。All 不限制协议，Other 指 `network == Other`。
- `matchesDisplayFilter` 只做显示判定，不修改数据。启用显示过滤后从保留的最近列表历史重新筛选；图表、统计和 PCAP 保存不随显示过滤改变。
- BPF 使用 Npcap 语法；显示过滤使用上述结构化字段，两者不得混用同一套字符串语法。UI 校验失败保留上一份有效条件并显示错误。
- 资源每秒采样：CPU 是进程占整机总逻辑处理器能力的百分比，内存为工作集字节，I/O 为进程累计读写字节（不是 PCAP 文件大小，也不是精确的物理磁盘吞吐）。首次 CPU 无区间或读取失败使用空 optional，不伪造为零。
- 24 小时测试资源样本持续写日志，不能只依赖最多 3600 点的屏幕曲线。记录会话、源码 commit、起止时间、真实时长、丢包与异常；日志写入失败须提示。

## 5. 实施顺序、验收与交接

### 5.1 当前两边马上做什么

1. 何俊杰将本文和公共声明头文件以功能分支提交共享，通知谢福祥公共头文件 commit `44ecf65`。双方确认使用相同版本后开工；main 的合并另行共同确认。
2. 何俊杰实现 enumerateDevices、CaptureSession 和采集测试；谢福祥同时实现固定样本、parsePacket、PcapReader 基础读取及解析测试。解析不等待真实采集，采集不依赖 Qt 报文列表。
3. 第一轮联调完成“真实网卡 → RawPacket → ParsedPacket → 简易列表”，对照固定 PCAP 与 Wireshark 检查字段，保留真实结果。
4. 下一轮分别补统计、保存回放和 Qt 图表/过滤/监控，每完成一个模块就接入。双方讲解关键代码并检查差异后合并。
5. 开发目标为 11 月 22 日晚冻结完整测试版本，随后连续运行至少 24 小时，11 月 24 日晚前提交。开发中应提前做短时运行测试；时间紧不改变必做项与实际测试时长。

### 5.2 最小验收矩阵

| 模块 | 必测场景 | 通过标准 |
| --- | --- | --- |
| 采集 | 无设备、错误设备/BPF、开始/停止/重启、无流量停止、队列溢出 | 失败可说明；资源释放；队列受限；丢包计数可核对 |
| 解析 | Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ARP/DNS，短包、错误长度、未知 DLT、分片 | 不越界；状态明确；MAC/IP/TTL/端口/flags 与固定期望一致 |
| DNS | UDP、单包完整 TCP DNS、假 53 端口、压缩指针循环与越界 | 不凭端口误判；错误内容可诊断；无死循环 |
| 统计 | 长度 46/47/1500/1501，IPv4/IPv6/ARP/其他，零流量、reset | 三分组边界正确；分类总数一致；DNS 分母与速率单位正确 |
| 文件 | 空/坏文件、两类字节序、微秒/纳秒、中文路径、已有文件、写失败/容量上限 | EOF 与错误可区分；不覆盖；保存重读字节/长度一致，时间误差小于 1 微秒 |
| 界面 | 高包速率、切换会话、过滤、字段展开、保存/导入/回放 | 主线程响应；历史受限；旧消息隔离；过滤不改后台计数 |
| 联调 | 同一固定流量经实时保存重读、离线分析 | 在无丢包且同样输入范围下，解析结果和累计统计一致 |
| 长测 | 固定 commit 至少连续 24 小时 | 起止/时长/CPU/内存/I/O/丢包/错误有记录；不得拼接崩溃重启前后的时长 |

### 5.3 使用新版标准构建入口

按根目录 README 准备 MSVC x64 开发环境、Qt、Ninja、SDK，先用本机路径配置 CMake。以下均在仓库根目录运行，环境变量只影响当前终端：

```powershell
$qtRoot = Read-Host '请输入本机 Qt MSVC x64 套件目录'
cmake --preset windows-msvc "-DCMAKE_PREFIX_PATH=$qtRoot"
# Ninja 不在 PATH 时，配置命令另加 -DCMAKE_MAKE_PROGRAM=本机ninja.exe完整路径
cmake --build --preset windows-msvc
$env:PATH = "$qtRoot\bin;$env:SystemRoot\System32\Npcap;$env:PATH"
$env:QT_QPA_PLATFORM_PLUGIN_PATH = "$qtRoot\plugins\platforms"
ctest --test-dir build/windows-msvc --output-on-failure --no-tests=error
```

这里的测试命令随功能合入后执行新增的测试；基线只有 stage0_smoke，通过该测试只证明启动检查。需要查看程序时用户自行启动 `build/windows-msvc/FlowGuard.exe` 并提供截图；本轮协作一律由 AI 使用命令行，不自动控制桌面。

### 5.4 发给另一方 AI 的交接模板

```text
项目：FlowGuard，C++17 + Qt Widgets + Npcap + CMake。
先检查当前分支、git status、提交和 docs/interfaces.md；保留本机未提交改动。
双方公共接口以仓库中本文件的版本为准，已有事实和待实现合同须区分。
我负责：填写模块名及负责人。
本次范围：填写要实现的具体方法与测试。
公共头文件基线：填写双方已经取得的 commit；尚未合入时先报告差异。
只修改自己负责的模块；公共结构、CMake 或主窗口需要调整时先给集成负责人列出差异。
每项交付说明实现/未实现范围、真实测试命令与结果、已知问题和 commit。
使用标准 CMake/CTest 入口；不恢复已删除的私人环境和构建脚本。
不提交个人路径、SDK、build、个人抓包；不自动推送或代替另一人验收。
```

### 5.5 变更记录

| 版本 | 变更 |
| --- | --- |
| 阶段 0 原文 | 仅有 RawPacket/PacketRecord 数据契约与基本原则 |
| v1.0 / 2026-11-21 | 以 3dcb4d6 为源码基线，保留已有数据类型；增加待实现模块合同、负责人、Qt 交接、资源边界、统计/过滤口径与联调标准；本次未实现功能代码 |
| v1.0 落地 / 2026-11-21 | feat/capture 的 44ecf65 提供公共头文件；随后实现枚举、命令行验证与测试，其他模块仍待实现；不改动远程 main |
