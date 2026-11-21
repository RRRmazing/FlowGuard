# 采集模块：网卡枚举

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

该命令行程序没有 Qt 链接依赖，不需要 Qt DLL 路径或平台插件；它只列举设备，
不打开网卡，也不采集报文。设备数量会随机器和网络配置变化，不写死为测试断言。
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

CaptureSession、采集线程、BPF、开始/停止和有界队列仍只有公共声明，尚未实现。
不需要等待上述实现，队友即可使用同一公共头文件开发解析与 PCAP 读取。
