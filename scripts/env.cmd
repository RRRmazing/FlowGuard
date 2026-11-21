@echo off
rem Called inside each entry script's setlocal scope; never changes system PATH.
if exist "%~dp0..\local-env.cmd" call "%~dp0..\local-env.cmd"
if not defined FLOWGUARD_QT_DIR (
  echo ERROR: FLOWGUARD_QT_DIR is not set.
  echo Copy local-env.example.cmd to local-env.cmd and configure your Qt MSVC x64 kit.
  exit /b 1
)
if not exist "%FLOWGUARD_QT_DIR%\bin\Qt6Widgets.dll" (
  echo ERROR: Qt Widgets was not found in the configured Qt kit.
  exit /b 1
)
if not exist "%FLOWGUARD_QT_DIR%\lib\Qt6Widgets.lib" (
  echo ERROR: Select the MSVC x64 Qt kit, not the MinGW kit.
  exit /b 1
)
set "PATH=%FLOWGUARD_QT_DIR%\bin;%SystemRoot%\System32\Npcap;%PATH%"
set "QT_QPA_PLATFORM_PLUGIN_PATH=%FLOWGUARD_QT_DIR%\plugins\platforms"
exit /b 0
