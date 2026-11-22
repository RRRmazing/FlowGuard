# Third-party components

FlowGuard is distributed under GPL-3.0-only. Copyright remains with the respective contributors. This does not change the licenses of third-party components.

The Windows package dynamically links to unmodified Qt 6.11.0 (Qt Base, Qt Charts and Qt SVG, plus image plugins and translations). Qt Charts is available under GPL-3.0-only or commercial terms; this release uses its GPL terms. Qt Base/SVG components and their dependencies retain the license choices described in their included notices. License texts, available third-party notices, and the installed Qt SPDX bills of materials are included under `third-party-licenses`.

Corresponding Qt source for version 6.11.0 is available from https://download.qt.io/archive/qt/6.11/6.11.0/submodules/ (qtbase, qtcharts, qtsvg, qtimageformats and qttranslations source archives). The package uses shared DLLs and does not prevent their replacement. FlowGuard's corresponding source and build instructions are available at https://github.com/RRRmazing/FlowGuard ; use the release's tag to obtain the matching version.

The Qt Windows deployment also contains ICU, Mesa software OpenGL, DirectX shader compiler/runtime helpers and other dependencies identified by the included SBOM and source notices. These are third-party components, not relicensed as FlowGuard code.

Microsoft Visual C++ Redistributable is the unmodified official, digitally signed Microsoft installer, distributed under Microsoft's terms: https://learn.microsoft.com/cpp/windows/redistributing-visual-cpp-files . It may require administrator approval and a restart.

Npcap is NOT included in this package. Download and install it separately from https://npcap.com/ and follow its license terms. Linking against the Npcap SDK does not install the driver. The SDK itself and its runtime DLLs are not redistributed by this release.
