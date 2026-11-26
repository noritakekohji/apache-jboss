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
    Assert-Equal $null $apache.Records[1].DurationMs 'Standard Combined has no duration'

    $jbossPath = Join-Path $temp 'server.log'
    @('2026-11-26 10:00:01,123 ERROR [org.example] failed','unrecognized') | Set-Content -LiteralPath $jbossPath -Encoding utf8
    $jboss = Read-JBossLog @($jbossPath)
    Assert-Equal 1 $jboss.Records.Count 'JBoss parsed count'
    Assert-Equal 'ERROR' $jboss.Records[0].Level 'JBoss level'
    Assert-Equal 1 $jboss.Issues.Count 'JBoss issue count'

    $gcPath = Join-Path $temp 'gc.log'
    '2026-11-26T10:00:02.000+0900: [Full GC (Ergonomics) 0.250 secs]' | Set-Content -LiteralPath $gcPath -Encoding utf8
    $gc = Read-GcLog @($gcPath)
    Assert-Equal 1 $gc.Records.Count 'GC parsed count'
    Assert-Equal 250 $gc.Records[0].DurationMs 'GC duration conversion'

    $summary = Get-AnalysisSummary $apache.Records $jboss.Records $gc.Records
    Assert-Equal 3 $summary.RequestCount 'Summary request count'
    Assert-Equal 1 $summary.HttpErrors 'Summary HTTP errors'
    Assert-Equal 33.33 $summary.HttpErrorRate 'Summary HTTP error rate'
    Assert-Equal 1 $summary.JBossErrors 'Summary JBoss errors'
    Assert-Equal 1 $summary.FullGcCount 'Summary full GC count'
    Assert-Equal "'=1+1" (ConvertTo-CsvSafeValue '=1+1' | ForEach-Object { $_.Trim('"') }) 'CSV injection prefix'
    Assert-Equal '&lt;script&gt;' (ConvertTo-SafeHtml '<script>') 'HTML escaping'

    $htmlPath = Join-Path $temp 'report.html'
    Export-AnalysisHtml $summary $apache.Records $jboss.Records $gc.Records $htmlPath
    $html = Get-Content -LiteralPath $htmlPath -Raw
    if ($html.Contains('token=secret')) { throw 'HTML report leaked query string' }
    if (-not $html.Contains('フルGC')) { throw 'HTML report omitted full GC summary label' }
    if (-not $html.Contains('class="chart"')) { throw 'HTML report omitted hourly chart' }

    $csvPath = Join-Path $temp 'requests.csv'
    Export-AnalysisCsv $apache.Records $csvPath
    $csv = [IO.File]::ReadAllText($csvPath)
    $bytes = [IO.File]::ReadAllBytes($csvPath)
    if ($bytes[0] -ne 0xEF -or $bytes[1] -ne 0xBB -or $bytes[2] -ne 0xBF) { throw 'CSV must include UTF-8 BOM for Excel' }
    if ($csv.Contains('token=secret')) { throw 'CSV request URL should be query-free by default' }
    'PASS: 22 assertions'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}
