@echo off
setlocal
set "VSLANG=1033"
cd /d "%~dp0.."
call "%~dp0env.cmd"
if errorlevel 1 exit /b %errorlevel%
if not defined FLOWGUARD_NINJA for /f "delims=" %%i in ('where ninja.exe 2^>nul') do if not defined FLOWGUARD_NINJA set "FLOWGUARD_NINJA=%%i"
if not defined FLOWGUARD_NINJA (
  echo ERROR: Configure FLOWGUARD_NINJA in local-env.cmd or add Ninja to PATH.
  exit /b 1
)
if not exist "%FLOWGUARD_NINJA%" (
  echo ERROR: The configured ninja.exe does not exist.
  exit /b 1
)
where cmake.exe >nul 2>nul
if errorlevel 1 (
  echo ERROR: Install CMake 3.21 or newer and add it to PATH.
  exit /b 1
)
if not exist "third_party\npcap-sdk\Include\pcap.h" (
  echo ERROR: Npcap SDK missing. Run scripts\setup-deps.ps1 first.
  exit /b 1
)
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo ERROR: Visual Studio Installer vswhere.exe not found.
  exit /b 1
)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "FLOWGUARD_VS=%%i"
if not defined FLOWGUARD_VS (
  echo ERROR: MSVC C++ tools not found.
  exit /b 1
)
call "%FLOWGUARD_VS%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b %errorlevel%
cmake --preset windows-msvc
if errorlevel 1 exit /b %errorlevel%
cmake --build --preset windows-msvc
exit /b %errorlevel%
