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

## Design and limitations

See [docs/design.md](docs/design.md). Current parsers handle a limited set of common formats. Verify format compatibility on the target machine without exporting production log content. The initial version does not claim request-level correlation between Apache and JBoss logs.

## Version

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
