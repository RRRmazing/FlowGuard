# 采集模块：网卡枚举与实际采集

负责人：何俊杰。公共接口依据 `docs/interfaces.md`，调用方包含
`core/module_contracts.h`，调用 `flowguard::enumerateDevices()`。

已实现设备标识、说明、IPv4/IPv6 地址与回环标记转换，以及 Npcap 链表的
RAII 释放。成功但无设备与枚举失败分别返回成功空列表、DeviceError。
设备名称或说明按默认 Npcap Windows 编码转换为 UTF-8；空说明保留为空，
未知或空地址跳过，重复地址合并，IPv6 非零 scope ID 以 `%数字` 保留。
无可用设备标识的记录跳过；设备顺序保留 Npcap 返回顺序。

## 命令行验证

按根目录 README 配置 MSVC、CMake、Ninja、Qt 和 Npcap SDK 后：

```powershell
cmake --build --preset windows-msvc
$env:PATH = "$env:SystemRoot\System32\Npcap;$env:PATH"
.\build\windows-msvc\flowguard_capture_probe.exe --list-devices
```

该命令行程序没有 Qt 链接依赖，不需要 Qt DLL 路径或平台插件；`--list-devices` 只列举设备，
不打开网卡。设备数量会随机器和网络配置变化，不写死为测试断言。
输出为 UTF-8，连接控制台时临时设置并恢复输出代码页。

退出码：成功（含零设备）为 0，枚举失败为 1，错误参数为 2。
`--help` / `-h` 仅显示用法并返回 0；不带参数也视为用法错误。

## 测试与后续

```powershell
ctest --test-dir build/windows-msvc -R "^capture_" --output-on-failure --no-tests=error
```

测试通过私有适配层模拟 Npcap 设备链表，覆盖空列表、失败/部分失败释放、
空说明、无地址、IPv4/IPv6、scope ID、回环标记、去重与结果自持有。
`device_enumerator_detail.h` 只供模块实现及测试使用，其他模块不要引用。

## 实际采集与开始/停止/重启

```powershell
# 设备 ID 必须取自上面的枚举结果，包含反斜杠时保留原样。
$deviceId = Read-Host '输入需要采集的设备 ID'
.\build\windows-msvc\flowguard_capture_probe.exe --capture --device $deviceId --seconds 3 --cycles 2 --bpf "ip"
```

每轮开始后持续消费队列，到时停止、排空并输出计数。仅显示前 5 包的时间戳、
原始长度、捕获长度及链路类型，不输出载荷或保存文件；去掉 --bpf 表示采集全部。
--seconds 范围 1..300，默认 3；--cycles 范围 1..10，默认 1。
设备错误、无权限或错误 BPF 返回 1，参数错误返回 2。调用 API 可自行控制会话时长。

CaptureSession 的 start/stop 由同一控制线程串行调用，tryPop 由单一消费者调用，
status 可跨线程取一致快照。start 失败不会悄悄启动；停止后保留已入队包，下一轮
成功开始才清空队列/计数。采集线程使用 Npcap 非阻塞读取，可唤醒等待，空闲停止
不依赖下一包。析构会停止并释放句柄；网络错误状态保留诊断，支持恢复后重启。

队列同时受包数和字节数限制，满时丢弃新包并计数；RawPacket 拥有字节副本。
receivedPackets = enqueuedPackets + queueDroppedPackets + invalidPackets。
计数为会话累计；queuedPackets/queuedBytes 是当前待消费量。驱动统计单列，不混为
应用层收到的包数。Reader、Writer、解析器、统计计算和 Qt 图表不在本次实现范围。

测试新增 capture_session_unit（长度/容量边界、10,000 包并发计数、参数与空闲停止）
及 capture_loopback_live（真实回环、BPF、时间戳、重启、溢出、失败恢复、析构）。
后者只向本机临时 UDP 端口发送自产载荷，测试无需外部服务器。
只运行无需实机抓包的测试可额外加 `-LE hardware`。
