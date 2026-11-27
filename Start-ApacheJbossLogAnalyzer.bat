@echo off
setlocal
set "SCRIPT_PATH=%~dp0src\ApacheJbossLogAnalyzer.ps1"

if not exist "%SCRIPT_PATH%" (
    echo ERROR: Analyzer script not found: "%SCRIPT_PATH%"
    pause
    exit /b 1
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_PATH%"
set "EXIT_CODE=%ERRORLEVEL%"
if "%EXIT_CODE%"=="0" exit /b 0

echo ERROR: Apache / JBoss Log Analyzer exited with code %EXIT_CODE%.
pause
exit /b %EXIT_CODE%
