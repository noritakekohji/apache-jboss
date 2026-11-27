# Apache / JBoss Log Analyzer

Windows PowerShell 5.1 GUI for local analysis of Apache access, JBoss server, and Java GC logs. The tool does not send data to a network service.

## Requirements

- Windows PowerShell 5.1 and Windows Forms
- No external PowerShell modules or runtime installation

## Run

Double-click `Start-ApacheJbossLogAnalyzer.bat`. Add one or more files in each log-type tab; files are analyzed in the order shown. Select the output folder (Desktop by default), then choose Analyze. The HTML report and three CSV files are written there.

The launcher starts `powershell.exe` with `-ExecutionPolicy Bypass` for that process only. It does not change machine or user execution-policy settings and does not request administrator privileges. Group Policy, AppLocker, WDAC, or other endpoint controls can still block the launch; follow the device administrator's policy.

Apache response-time statistics require an optional trailing duration field in seconds. Standard Combined logs usually do not include that field.

## GC analysis

The self-contained HTML report includes GC pause summaries and charts, full-GC intervals, post-GC heap trends, and event details. Charts label their axes and units; reports include interpretation notes. GC CSV includes event kind, cause, pause duration, heap before/after/capacity, and source line. Supported inputs are representative Java 8 legacy and Java 9+ unified JVM log patterns, not every collector or JDK release. Known parallel-GC detail phases such as `Adjust Pointers` are excluded from collection totals.

The feature set takes inspiration from GCViewer's changelog, but this project has its own implementation. See [docs/design.md](docs/design.md) for supported patterns and limitations.

## Tests

Synthetic fixtures do not use production logs. Run the tests where the organization's PowerShell policy permits script execution:

```powershell
powershell.exe -NoProfile -File .\tests\Run-Tests.ps1
```

## Version and license

See [CHANGELOG.md](CHANGELOG.md). This project is MIT licensed; see [LICENSE](LICENSE).
