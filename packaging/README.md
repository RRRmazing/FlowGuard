# Windows 安装包

`FlowGuard.iss` 是 Inno Setup 7 安装配置。保留 AppId，升级时通过它识别应用。

标准步骤：在 x64 Developer PowerShell 中用 CMake 配置、构建并运行 CTest；将主程序及 HTML 指南复制到 `build/deploy/windows-x64`，用对应 Qt 的 `windeployqt --release --no-compiler-runtime` 收集 Qt 依赖。把微软官方 `vc_redist.x64.exe` 放到 `build/prerequisites`。将 LICENSE、THIRD_PARTY_NOTICES.md、第三方许可证复制到发布目录，然后运行 Inno Setup 的 ISCC 编译本脚本。

输出：`build/installer/FlowGuard-0.1.1-windows-x64-Setup.exe`。可通过 `Get-FileHash -Algorithm SHA256` 生成校验值。不要把构建产物或运行库二进制提交到 Git；安装包作为 GitHub Release 附件上传。

安装为当前用户模式；首次安装写入 `{localappdata}/FlowGuard/storage.ini`，Qt 的 GenericDataLocation 在 Windows 上对应此位置。使用 UTF-8 INI，路径转为正斜杠并加引号。已有配置不覆盖，卸载不删除配置、报文或日志。安装前会创建首次选择的数据目录，取消安装后可能保留空目录。运行时由应用再次校验数据目录可写性与可用空间。

Npcap 由用户从官网安装，不捆绑。VC++ 运行库由微软官方安装程序处理，可能要求提权。运行库最低版本按当前 MSVC 14.51.36231 设置；更换工具链后应更新检测值。当前未验证 Windows on ARM 和干净电脑安装，不代表完成 24 小时稳定性验收。
