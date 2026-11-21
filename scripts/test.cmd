@echo off
setlocal
cd /d "%~dp0.."
call "%~dp0env.cmd"
if errorlevel 1 exit /b %errorlevel%
if not exist "build\windows-msvc\FlowGuard.exe" (
  echo ERROR: Build first: .\scripts\build.cmd
  exit /b 1
)
ctest --test-dir build/windows-msvc --output-on-failure
exit /b %errorlevel%
