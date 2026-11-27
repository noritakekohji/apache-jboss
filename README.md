# Apache / JBoss Log Analyzer

Windows PowerShell 5.1 GUI for local analysis of Apache access, JBoss server, and Java GC logs. The tool does not send data to a network service.

## Requirements

- Windows PowerShell 5.1 and Windows Forms
- No external PowerShell modules or runtime installation

## Run

Double-click `Start-ApacheJbossLogAnalyzer.bat`. Add one or more files in each log-type tab; files are analyzed in the order shown. Exact duplicate lines shared between files of the same log type are counted once; repeated identical lines within a single file are retained. Set the inclusive start and end date/time in JST. Only records within that period are included in the summary, HTML report, and CSV files. Records without a wall-clock timestamp cannot be assigned to the period, so they are omitted and counted in the report. Select the output folder (Desktop by default), then choose Analyze.

The launcher starts `powershell.exe` with `-ExecutionPolicy Bypass` for that process only. It does not change machine or user execution-policy settings and does not request administrator privileges. Group Policy, AppLocker, WDAC, or other endpoint controls can still block the launch; follow the device administrator's policy.

Apache response-time statistics require an optional trailing duration field in seconds. Standard Combined logs usually do not include that field.

## GC analysis

The self-contained HTML report includes five-minute request counts, GC pause summaries, full-GC intervals, post-GC heap trends, and event details. Request/error charts split each five-minute total into normal requests and HTTP errors. Time-axis labels are thinned to at most about eight labels per chart; all chart time axes use JST. GC events without a wall-clock timestamp are omitted from time-series charts and their counts are shown. Charts label their axes and units; reports include interpretation notes. GC CSV includes event kind, cause, pause duration, heap before/after/capacity, and source line. Supported inputs are representative Java 8 legacy and Java 9+ unified JVM log patterns, not every collector or JDK release. Known parallel-GC detail phases such as `Adjust Pointers` are excluded from collection totals.

The feature set takes inspiration from GCViewer's changelog, but this project has its own implementation. See [docs/design.md](docs/design.md) for supported patterns and limitations.

## Tests

Synthetic fixtures do not use production logs. Run the tests where the organization's PowerShell policy permits script execution:

```powershell
powershell.exe -NoProfile -File .\tests\Run-Tests.ps1
```

## Version and license

See [CHANGELOG.md](CHANGELOG.md). This project is MIT licensed; see [LICENSE](LICENSE).
