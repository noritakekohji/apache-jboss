# Apache / JBoss Log Analyzer

Windows PowerShell 5.1 GUI for local analysis of Apache access, JBoss server, and Java GC logs. The tool does not send data to a network service.

## Requirements

- Windows PowerShell 5.1 and Windows Forms
- No external PowerShell modules or runtime installation
- PowerShell script execution must be allowed by the device administrator policy

## Run

From an approved PowerShell session, run:

```powershell
.\src\ApacheJbossLogAnalyzer.ps1
```

Choose Apache, JBoss, and GC log files in the GUI. The initial version writes an HTML report plus request, JBoss, and GC CSV files to the current user's Desktop. Apache timing statistics are only available when the access log includes a trailing duration field in seconds.

## Tests

Run the synthetic fixture tests (no production logs are used) in an environment where the organization permits script execution:

```powershell
powershell.exe -NoProfile -File .\tests\Run-Tests.ps1
```

Follow the organization's PowerShell execution policy on all endpoints. Do not change or bypass a managed policy.

## GC analysis

Based on analysis ideas from GCViewer's changelog, the report shows per-event pause times, heap before/after/capacity, post-GC heap trends, and min/average/max pause plus full-GC intervals. It recognizes a subset of Java 8 legacy and Java 9+ unified logs. Application-stop events are counted when present. It deliberately excludes known internal phases such as Adjust Pointers from collection totals. It is not a complete parser for every collector or JDK release.

The self-contained HTML report includes GC pause summaries, full-GC intervals, post-GC heap trends, and event details for supported legacy and unified JVM log patterns. The parser intentionally ignores recognized parallel-GC subphases so they do not inflate pause counts. It is an initial subset, not a complete replacement for GCViewer; verify compatibility against the target Java version locally.

## Design and limitations

See [docs/design.md](docs/design.md). Current parsers handle a limited set of common formats. Verify format compatibility on the target machine without exporting production log content. The initial version does not claim request-level correlation between Apache and JBoss logs.

## Version

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
