# PCAP 基础读取（谢福祥，当前阶段）

`storage/pcap_reader.h` 包含唯一公共声明 `core/module_contracts.h`。
已实现 `PcapReader` 全部公开方法，保持签名不变；仅为该类增加私有 Impl 指针持有文件状态。
CMake 目标为 `flowguard_storage`，不依赖 Qt/Npcap。

```cpp
flowguard::PcapReader reader;
auto result = reader.open(path); // std::filesystem::path，支持中文路径
if (!result.ok()) { /* 显示 result.message */ }
flowguard::RawPacket packet;
// 每次 readNext 同时检查返回状态与 result。
// Packet -> 交给 parsePacket(packet, sequence)；EndOfFile -> 正常结束；Error -> 报错。
```

支持经典 PCAP 2.4 的大小端、微秒/纳秒输入，保留时间、原始长度、捕获长度、链路类型与原始字节。
时间转换到 system_clock 的平台精度（Windows 通常为 100 ns）。PCAPNG、未知 magic、非 2.4 版本及含额外 DLT 元数据位的格式返回 Unsupported。

重复 open 返回 InvalidState；失败 open 会关闭文件，允许重新尝试。合法全局头后没有记录是正常 EOF，
残缺头/记录/包体均是错误。读取错误后须 close 并重开，不能继续从损坏位置尝试。
非 Packet 返回时输出 RawPacket 不变，正常 EOF 的 result 为成功；重复 EOF 仍正常。
close 可重复调用，析构释放资源。

读取前校验 caplen <= originalLength、caplen <= snaplen、单包最多 16 MiB、时间小数范围。
未知 DLT 保留，由解析器报告 Unsupported。不会把所有文件当 Ethernet，也不会通过记录长度触发无限分配。

`tests/pcap_reader_tests.cpp` 在构建目录临时创建可重复的中文路径样本，结束删除自己的文件和空目录。
测试包含四种字节序/时间精度组合、逐字节残缺、EOF 与错误、非法长度、资源上限及读取后调用公共解析接口。
固定可分享样本见 `tests/data/README.md`，离线查看命令见 `src/parser/README.md`。

当前只实现基础读取；PcapWriter、保存、回放节奏与 UI 导入按钮属于后续任务，本次未实现。
