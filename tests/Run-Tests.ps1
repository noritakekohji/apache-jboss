$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\src\ApacheJbossLogAnalyzer.ps1')

function Assert-Equal {
    param($Expected,$Actual,[string]$Name)
    if ($Expected -ne $Actual) { throw "${Name}: expected [$Expected], got [$Actual]" }
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ('apache-jboss-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $apachePath = Join-Path $temp 'access.log'
    @('127.0.0.1 - - [26/Nov/2026:10:00:00 +0900] "GET /home?token=secret HTTP/1.1" 200 123 "-" "test" 0.125','127.0.0.1 - - [26/Nov/2026:10:01:00 +0900] "GET /standard HTTP/1.1" 200 42 "-" "test"','127.0.0.1 - - [26/Nov/2026:10:02:00 +0900] "GET /fail HTTP/1.1" 503 0 "-" "test"','bad line') | Set-Content -LiteralPath $apachePath -Encoding utf8
    $apache = Read-ApacheAccessLog @($apachePath)
    Assert-Equal 3 $apache.Records.Count 'Apache parsed count'
    Assert-Equal 1 $apache.Issues.Count 'Apache issue count'
    Assert-Equal 125 $apache.Records[0].DurationMs 'Apache duration conversion'
    Assert-Equal 200 $apache.Records[0].Status 'Apache status'
    Assert-Equal 10 $apache.Records[0].Time.Hour 'Apache timezone normalization'
    Assert-Equal $null $apache.Records[1].DurationMs 'Standard Combined has no duration'
    $apachePath2 = Join-Path $temp 'access-2.log'
    '127.0.0.1 - - [26/Nov/2026:10:03:00 +0900] "GET /second HTTP/1.1" 201 12 "-" "test" 0.050' | Set-Content -LiteralPath $apachePath2 -Encoding utf8
    $apacheCombined = Read-ApacheAccessLog @($apachePath,$apachePath2)
    Assert-Equal 4 $apacheCombined.Records.Count 'Apache multiple files concatenate'
    Assert-Equal $apachePath2 $apacheCombined.Records[3].Source 'Apache concatenation preserves source'

    $jbossPath = Join-Path $temp 'server.log'
    @('2026-11-26 10:00:01,123 ERROR [org.example] failed','unrecognized') | Set-Content -LiteralPath $jbossPath -Encoding utf8
    $jboss = Read-JBossLog @($jbossPath)
    Assert-Equal 1 $jboss.Records.Count 'JBoss parsed count'
    Assert-Equal 'ERROR' $jboss.Records[0].Level 'JBoss level'
    Assert-Equal 10 $jboss.Records[0].Time.Hour 'JBoss assumed JST'
    Assert-Equal 1 $jboss.Issues.Count 'JBoss issue count'
    $jbossPath2 = Join-Path $temp 'server-2.log'
    '2026-11-26 10:02:01,123 INFO [org.example] next' | Set-Content -LiteralPath $jbossPath2 -Encoding utf8
    $jbossCombined=Read-JBossLog @($jbossPath,$jbossPath2)
    Assert-Equal 2 $jbossCombined.Records.Count 'JBoss multiple files concatenate'
    Assert-Equal $jbossPath2 $jbossCombined.Records[1].Source 'JBoss concatenation preserves source'

    $gcPath = Join-Path $temp 'gc.log'
    @('2026-11-26T10:00:02.000+0900: [Full GC (Ergonomics) 125M->50M(512M), 0.250 secs]','[2026-11-26T10:01:02.500+09:00][info][gc] GC(3) Pause Full (System.gc()) 250M->80M(512M) 15.7ms','Total time for which application threads were stopped: 0.020 seconds','[2026-11-26T10:01:03.000+09:00][info][gc] GC(3) Adjust Pointers 1.4ms','[0.500s][info][gc] GC(4) Pause Young (Normal) 80M->10M(512M) 2.3ms','[10.0s][info][gc] GC(5) Pause Full 125M->50M(512M) 4.0ms','[70.0s][info][gc] GC(6) Pause Full 125M->50M(512M) 3.0ms') | Set-Content -LiteralPath $gcPath -Encoding utf8
    $gc = Read-GcLog @($gcPath)
    Assert-Equal 6 $gc.Records.Count 'GC parsed count'
    Assert-Equal 0 $gc.Issues.Count 'GC known phases ignored'
    Assert-Equal 250 $gc.Records[0].DurationMs 'GC duration conversion'
    Assert-Equal 125 $gc.Records[0].HeapBeforeMb 'Legacy GC heap before'
    Assert-Equal 80 $gc.Records[1].HeapAfterMb 'Unified GC heap after'
    Assert-Equal 10 $gc.Records[1].Time.Hour 'Unified GC timezone normalization'
    Assert-Equal 'Application Stopped' $gc.Records[2].Kind 'Application stop event'
    Assert-Equal 0.5 $gc.Records[3].ElapsedSeconds 'Uptime unified GC event'
    Assert-Equal 10 $gc.Records[4].ElapsedSeconds 'Uptime Full GC start'
    Assert-Equal 70 $gc.Records[5].ElapsedSeconds 'Uptime Full GC end'
    $gcPath2=Join-Path $temp 'gc-2.log'
    '[80.0s][info][gc] GC(7) Pause Full 100M->40M(512M) 5.0ms' | Set-Content -LiteralPath $gcPath2 -Encoding utf8
    $gcCombined=Read-GcLog @($gcPath,$gcPath2)
    Assert-Equal 7 $gcCombined.Records.Count 'GC multiple files concatenate'
    Assert-Equal $gcPath2 $gcCombined.Records[6].Source 'GC concatenation preserves source'

    $summary = Get-AnalysisSummary $apache.Records $jboss.Records $gc.Records
    Assert-Equal 3 $summary.RequestCount 'Summary request count'
    Assert-Equal 1 $summary.HttpErrors 'Summary HTTP errors'
    Assert-Equal 33.33 $summary.HttpErrorRate 'Summary HTTP error rate'
    Assert-Equal 1 $summary.JBossErrors 'Summary JBoss errors'
    Assert-Equal 4 $summary.FullGcCount 'Summary full GC count'
    Assert-Equal 1 $summary.MinFullGcIntervalMin 'Summary uptime Full GC interval'
    Assert-Equal 2.3 $summary.MinGcPauseMs 'Summary min pause'
    Assert-Equal 250 $summary.MaxGcPauseMs 'Summary max pause'
    Assert-Equal "'=1+1" (ConvertTo-CsvSafeValue '=1+1' | ForEach-Object { $_.Trim('"') }) 'CSV injection prefix'
    Assert-Equal '&lt;script&gt;' (ConvertTo-SafeHtml '<script>') 'HTML escaping'

    $htmlPath = Join-Path $temp 'report.html'
    Export-AnalysisHtml $summary $apache.Records $jboss.Records $gc.Records $htmlPath
    $html = Get-Content -LiteralPath $htmlPath -Raw
    if ($html.Contains('token=secret')) { throw 'HTML report leaked query string' }
    if (-not $html.Contains('フルGC')) { throw 'HTML report omitted full GC summary label' }
    if (-not $html.Contains('class="chart"')) { throw 'HTML report omitted hourly chart' }
    if (-not $html.Contains('heap-chart')) { throw 'HTML report omitted heap graph' }
    if (-not $html.Contains('125/50 MB')) { throw 'HTML report omitted heap event detail' }
    if (-not $html.Contains('pause-chart')) { throw 'HTML report omitted pause chart' }
    if (-not $html.Contains('data-kind="hourly-chart"')) { throw 'HTML report omitted hourly chart' }
    if (-not $html.Contains('リクエスト数（件/時）')) { throw 'HTML report omitted request axis units' }
    if (-not $html.Contains('停止時間（ms）')) { throw 'HTML report omitted GC pause axis units' }
    if (-not $html.Contains('ヒープ使用量（MB）')) { throw 'HTML report omitted heap axis units' }
    if (-not $html.Contains('class="grid"')) { throw 'HTML report omitted labeled chart grid ticks' }
    if ($html.Contains('failed')) { throw 'HTML report included raw JBoss log text' }

    $csvPath = Join-Path $temp 'requests.csv'
    Export-AnalysisCsv $apache.Records $csvPath
    $csv = [IO.File]::ReadAllText($csvPath)
    $bytes = [IO.File]::ReadAllBytes($csvPath)
    if ($bytes[0] -ne 0xEF -or $bytes[1] -ne 0xBB -or $bytes[2] -ne 0xBF) { throw 'CSV must include UTF-8 BOM for Excel' }
    if ($csv.Contains('token=secret')) { throw 'CSV request URL should be query-free by default' }

    $emptyHtml = Join-Path $temp 'empty.html'
    $emptySummary = Get-AnalysisSummary @() @() @()
    Export-AnalysisHtml $emptySummary @() @() @() $emptyHtml
    if (-not (Test-Path -LiteralPath $emptyHtml)) { throw 'Empty inputs should still produce an HTML report' }

    $launcherPath = Join-Path $PSScriptRoot '..\Start-ApacheJbossLogAnalyzer.bat'
    $launcher = [IO.File]::ReadAllText($launcherPath)
    if ($launcher -notmatch '(?im)^powershell\.exe .*?-ExecutionPolicy Bypass .*?-File "%SCRIPT_PATH%"') { throw 'Launcher must apply process-scoped ExecutionPolicy Bypass' }
    if ($launcher -match '(?im)^\s*Set-ExecutionPolicy\b') { throw 'Launcher must not change a persistent execution policy' }
    'PASS: 53 assertions'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}
