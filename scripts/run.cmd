@echo off
setlocal
cd /d "%~dp0.."
call "%~dp0env.cmd"
if errorlevel 1 exit /b %errorlevel%
if not exist "build\windows-msvc\FlowGuard.exe" (
  echo ERROR: Build first: .\scripts\build.cmd
  exit /b 1
)
"build\windows-msvc\FlowGuard.exe" %*
exit /b %errorlevel%
