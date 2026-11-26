# Apache JBoss Log Analyzer

## Repository

Standalone Windows PowerShell 5.1 application. See README.md and docs/design.md.

## Validation

Run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\Run-Tests.ps1` using synthetic fixtures. PSScriptAnalyzer is optional and is not installed as a runtime dependency.

## Safety

Never copy production log content into this repository or external tools. HTML and CSV output must remove URL query strings by default.
