Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-SafeHtml {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Value)
}

function ConvertTo-CsvSafeValue {
    param([AllowNull()][object]$Value)
    $text = if ($null -eq $Value) { '' } else { [string]$Value }
    if ($text -match '^[\s]*[=+@\-]') { $text = "'$text" }
    return '"' + $text.Replace('"', '""') + '"'
}

function Get-LogTimestamp {
    param([string]$Text)
    $formats = @('yyyy-MM-dd HH:mm:ss,fff','yyyy-MM-dd HH:mm:ss.fff','yyyy-MM-dd HH:mm:ss','yyyy-MM-dd''T''HH:mm:ss.fffK','yyyy-MM-dd''T''HH:mm:ssK')
    $styles = [Globalization.DateTimeStyles]::AssumeLocal
    if ($Text -match '[+-]\d{4}$') { $Text = $Text.Insert($Text.Length - 2, ':') }
    $parsed = [datetime]::MinValue
    foreach ($format in $formats) {
        if ([datetime]::TryParseExact($Text, $format, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed }
    }
    return $null
}

function Read-ApacheAccessLog {
    param([string[]]$Path)
    $records = [Collections.Generic.List[object]]::new()
    $issues = [Collections.Generic.List[object]]::new()
    $pattern = '^(?<host>\S+) \S+ \S+ \[(?<time>[^\]]+)\] "(?<method>\S+) (?<url>\S+) (?<protocol>[^"]+)" (?<status>\d{3}) (?<bytes>\S+)(?: "(?<referer>[^"]*)" "(?<agent>[^"]*)")?(?: (?<duration>\d+(?:\.\d+)?))?$'
    foreach ($file in $Path) {
        $lineNo = 0
        foreach ($line in [IO.File]::ReadLines($file)) {
            $lineNo++
            if ($line -notmatch $pattern) { $issues.Add([pscustomobject]@{ File=$file; Line=$lineNo; Reason='Apache access log format not recognized'; Text=$line }); continue }
            $timestamp = [datetime]::MinValue
            if (-not [datetime]::TryParseExact($Matches.time, 'dd/MMM/yyyy:HH:mm:ss zzz', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$timestamp)) {
                $issues.Add([pscustomobject]@{ File=$file; Line=$lineNo; Reason='Invalid Apache timestamp'; Text=$line }); continue
            }
            $duration = $null
            if ($Matches.ContainsKey('duration') -and $Matches.duration) {
                $duration = [double]::Parse($Matches.duration, [Globalization.CultureInfo]::InvariantCulture) * 1000
            }
            $records.Add([pscustomobject]@{ Time=$timestamp; Method=$Matches.method; Url=$Matches.url; Status=[int]$Matches.status; Bytes=$Matches.bytes; DurationMs=$duration; Source=$file; Line=$lineNo; Kind='Request' })
        }
    }
    return [pscustomobject]@{ Records=$records; Issues=$issues }
}

function Read-JBossLog {
    param([string[]]$Path)
    $records = [Collections.Generic.List[object]]::new()
    $issues = [Collections.Generic.List[object]]::new()
    $pattern = '^(?<time>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,.]\d{3})?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+(?<message>.*)$'
    foreach ($file in $Path) {
        $lineNo = 0
        foreach ($line in [IO.File]::ReadLines($file)) {
            $lineNo++
            if ($line -notmatch $pattern) { $issues.Add([pscustomobject]@{ File=$file; Line=$lineNo; Reason='JBoss timestamp/level format not recognized'; Text=$line }); continue }
            $stampText = $Matches.time.Replace('T',' ')
            $stampText = $stampText -replace '(\d{2}),(\d{3})','$1.$2'
            $timestamp = Get-LogTimestamp $stampText
            if ($null -eq $timestamp) { $issues.Add([pscustomobject]@{ File=$file; Line=$lineNo; Reason='Invalid JBoss timestamp'; Text=$line }); continue }
            $records.Add([pscustomobject]@{ Time=$timestamp; Level=$Matches.level; Message=$Matches.message; Source=$file; Line=$lineNo; Kind='JBoss' })
        }
    }
    return [pscustomobject]@{ Records=$records; Issues=$issues }
}

function Read-GcLog {
    param([string[]]$Path)
    $records = [Collections.Generic.List[object]]::new()
    $issues = [Collections.Generic.List[object]]::new()
    foreach ($file in $Path) {
        $lineNo = 0
        foreach ($line in [IO.File]::ReadLines($file)) {
            $lineNo++
            $timestamp = $null; $duration = $null; $kind = 'GC'; $match = $false
            if ($line -match '^(?:\[)?(?<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{4})(?:\])?:?\s*\[(?<event>Full GC|GC).*?(?<duration>\d+(?:\.\d+)?)\s+secs') {
                $match = $true; $timestamp = Get-LogTimestamp $Matches.time; $duration = [double]$Matches.duration * 1000
                if ($Matches.event -eq 'Full GC') { $kind = 'Full GC' }
            } elseif ($line -match '^\[(?<uptime>\d+(?:\.\d+)?): \[(?<gc>Full GC|GC)') {
                $match = $true; $kind = if ($Matches.gc -eq 'Full GC') { 'Full GC' } else { 'GC' }; $duration = $null
            } elseif ($line -match '^\[(?<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:?\d{2})\].*(?<event>Pause Full|Pause Young|Pause Remark|Pause Cleanup|Concurrent Mark Cycle).*?(?<duration>\d+(?:\.\d+)?)ms') {
                $match = $true; $timestamp = Get-LogTimestamp $Matches.time; $duration = [double]$Matches.duration; $kind = if ($Matches.event -eq 'Pause Full') { 'Full GC' } else { 'GC' }
            }
            if (-not $match) { $issues.Add([pscustomobject]@{ File=$file; Line=$lineNo; Reason='GC log format/event not recognized'; Text=$line }); continue }
            $records.Add([pscustomobject]@{ Time=$timestamp; Kind=$kind; DurationMs=$duration; Message=$line; Source=$file; Line=$lineNo })
        }
    }
    return [pscustomobject]@{ Records=$records; Issues=$issues }
}

function Get-AnalysisSummary {
    param([object[]]$Requests,[object[]]$Events,[object[]]$GcEvents)
    $durations = @($Requests | Where-Object { $null -ne $_.DurationMs } | ForEach-Object { [double]$_.DurationMs } | Sort-Object)
    $percentile = { param($items,$p) if ($items.Count -eq 0) { return $null }; $index=[math]::Ceiling($items.Count*$p)-1; return $items[[math]::Max(0,$index)] }
    $errors = @($Requests | Where-Object { $_.Status -ge 400 }).Count
    $fullGc = @($GcEvents | Where-Object Kind -eq 'Full GC')
    $pauseTotal = 0.0
    foreach ($gcEvent in $fullGc) {
        if ($null -ne $gcEvent.DurationMs) { $pauseTotal += [double]$gcEvent.DurationMs }
    }
    $errorRate = 0
    if ($Requests.Count -gt 0) { $errorRate = [math]::Round(100 * $errors / $Requests.Count, 2) }
    return [pscustomobject]@{
        RequestCount = $Requests.Count
        HttpErrors = $errors
        HttpErrorRate = $errorRate
        MedianMs = &$percentile $durations 0.50
        P95Ms = &$percentile $durations 0.95
        P99Ms = &$percentile $durations 0.99
        JBossErrors = @($Events | Where-Object Level -in @('ERROR','FATAL')).Count
        FullGcCount = $fullGc.Count
        FullGcPauseMs = $pauseTotal
    }
}

function Export-AnalysisCsv {
    param([object[]]$Rows,[string]$Path)
    $encoding = [Text.UTF8Encoding]::new($true)
    $writer = [IO.StreamWriter]::new($Path,$false,$encoding)
    try {
        if ($Rows.Count -eq 0) { return }
        $columns = @($Rows[0].PSObject.Properties.Name)
        $writer.WriteLine(($columns | ForEach-Object { ConvertTo-CsvSafeValue $_ }) -join ',')
        foreach ($row in $Rows) {
            $values = foreach ($column in $columns) {
                $value = $row.$column
                if ($column -eq 'Url' -and $null -ne $value) { $value = ([string]$value -split '\?')[0] }
                if ($column -eq 'Source' -and $null -ne $value) { $value = [IO.Path]::GetFileName([string]$value) }
                ConvertTo-CsvSafeValue $value
            }
            $writer.WriteLine(($values -join ','))
        }
    } finally { $writer.Dispose() }
}

function Export-AnalysisHtml {
    param([object]$Summary,[object[]]$Requests,[object[]]$Events,[object[]]$GcEvents,[string]$Path)
    $requestBuckets = @($Requests | Where-Object { $null -ne $_.Time } | Group-Object { $_.Time.ToString('yyyy-MM-dd HH:00') } | Sort-Object Name)
    $maxCount = 1
    foreach ($bucket in $requestBuckets) {
        if ($bucket.Count -gt $maxCount) { $maxCount = $bucket.Count }
    }
    $chartBars = foreach ($bucket in $requestBuckets) {
        $height = [math]::Max(2, [math]::Round(100 * $bucket.Count / $maxCount))
        $errors = @($bucket.Group | Where-Object { $_.Status -ge 400 }).Count
        $timeLabel = ConvertTo-SafeHtml $bucket.Name
        '<div class="hour" title="{0}: {1} requests, {2} HTTP errors"><div class="bar" style="height:{3}%"></div><small>{4}</small></div>' -f $timeLabel, $bucket.Count, $errors, $height, (ConvertTo-SafeHtml $bucket.Name.Substring(11,2))
    }
    $rows = foreach ($item in @($Requests | Sort-Object DurationMs -Descending | Select-Object -First 100)) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (ConvertTo-SafeHtml $item.Time.ToString('yyyy-MM-dd HH:mm:ss.fff')), (ConvertTo-SafeHtml $item.Method), (ConvertTo-SafeHtml (($item.Url -split '\?')[0])), $item.Status, $item.DurationMs
    }
    $html = @"
<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Apache / JBoss ログ分析</title>
<style>body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033}h1{color:#173b65}.cards{display:flex;gap:1rem;flex-wrap:wrap}.card{background:#eef4fa;padding:1rem;border-radius:8px;min-width:130px}.chart{height:190px;display:flex;align-items:end;gap:3px;border-bottom:1px solid #ccd5df;padding:1rem 0}.hour{height:100%;flex:1;display:flex;flex-direction:column;justify-content:end;align-items:center;min-width:12px}.bar{background:#3984bd;width:75%;min-height:2px}.hour small{font-size:10px;writing-mode:vertical-rl;color:#586575;margin-top:4px}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ccd5df;padding:.5rem;text-align:left}small{color:#586575}</style>
<h1>Apache / JBoss ログ分析</h1><p>生成日時: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') JST（ローカル時刻）</p><div class="cards">
<div class="card">リクエスト<br><b>$($Summary.RequestCount)</b></div><div class="card">HTTPエラー<br><b>$($Summary.HttpErrors) ($($Summary.HttpErrorRate)%)</b></div><div class="card">p95 応答時間<br><b>$($Summary.P95Ms) ms</b></div><div class="card">JBoss ERROR<br><b>$($Summary.JBossErrors)</b></div><div class="card">フルGC<br><b>$($Summary.FullGcCount) 回</b></div><div class="card">フルGC停止合計<br><b>$($Summary.FullGcPauseMs) ms</b></div></div>
<h2>時間帯別リクエスト数</h2><small>棒の高さは時間ごとの件数です。棒にカーソルを合わせるとHTTPエラー数も表示します。</small><div class="chart">$($chartBars -join "`n")</div>
<h2>遅延上位リクエスト</h2><small>Apacheログに処理時間がある場合のみ応答時間を集計します。URLのクエリ文字列は除去しています。</small><table><thead><tr><th>時刻</th><th>Method</th><th>Path</th><th>Status</th><th>ms</th></tr></thead><tbody>$($rows -join "`n")</tbody></table>
<h2>注意</h2><p>時刻の近接は因果関係を示しません。ApacheとJBoss間の相関はリクエストID未確認のため、この初版では自動断定しません。ログ本文は出力していません。</p></html>
"@
    [IO.File]::WriteAllText($Path,$html,[Text.UTF8Encoding]::new($true))
}

function Start-LogAnalyzerGui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = [Windows.Forms.Form]::new()
    $form.Text = 'Apache / JBoss Log Analyzer'
    $form.Size = [Drawing.Size]::new(850, 600)
    $form.StartPosition = 'CenterScreen'
    $inputs = @{}
    $types = @('Apache access logs','JBoss server logs','Java GC logs')
    for ($index = 0; $index -lt $types.Count; $index++) {
        $y = 16 + (40 * $index)
        $label = [Windows.Forms.Label]::new()
        $label.Text = $types[$index]
        $label.Location = [Drawing.Point]::new(16, $y + 4)
        $label.Size = [Drawing.Size]::new(150, 24)
        $form.Controls.Add($label)
        $box = [Windows.Forms.TextBox]::new()
        $box.Location = [Drawing.Point]::new(170, $y)
        $box.Size = [Drawing.Size]::new(500, 24)
        $form.Controls.Add($box)
        $inputs[$index] = $box
        $button = [Windows.Forms.Button]::new()
        $button.Text = 'Browse...'
        $button.Location = [Drawing.Point]::new(680, $y - 2)
        $button.Tag = $index
        $button.Add_Click({
            $dialog = [Windows.Forms.OpenFileDialog]::new()
            $dialog.Multiselect = $true
            if ($dialog.ShowDialog() -eq 'OK') { $inputs[[int]$this.Tag].Text = $dialog.FileNames -join ';' }
        }.GetNewClosure())
        $form.Controls.Add($button)
    }
    $output = [Windows.Forms.TextBox]::new()
    $output.Multiline = $true
    $output.ScrollBars = 'Vertical'
    $output.Location = [Drawing.Point]::new(16, 140)
    $output.Size = [Drawing.Size]::new(790, 350)
    $form.Controls.Add($output)
    $run = [Windows.Forms.Button]::new()
    $run.Text = 'Analyze and export report'
    $run.Location = [Drawing.Point]::new(16, 510)
    $run.Add_Click({
        try {
            $apacheResult = Read-ApacheAccessLog @($inputs[0].Text -split ';' | Where-Object { $_ })
            $jbossResult = Read-JBossLog @($inputs[1].Text -split ';' | Where-Object { $_ })
            $gcResult = Read-GcLog @($inputs[2].Text -split ';' | Where-Object { $_ })
            $summary = Get-AnalysisSummary $apacheResult.Records $jbossResult.Records $gcResult.Records
            $outDir = [Environment]::GetFolderPath('Desktop')
            Export-AnalysisHtml $summary $apacheResult.Records $jbossResult.Records $gcResult.Records (Join-Path $outDir 'apache-jboss-report.html')
            Export-AnalysisCsv $apacheResult.Records (Join-Path $outDir 'requests.csv')
            Export-AnalysisCsv @($jbossResult.Records | Select-Object Time,Level,Source,Line) (Join-Path $outDir 'jboss-events.csv')
            Export-AnalysisCsv @($gcResult.Records | Select-Object Time,Kind,DurationMs,Source,Line) (Join-Path $outDir 'gc-events.csv')
            $issueCount = $apacheResult.Issues.Count + $jbossResult.Issues.Count + $gcResult.Issues.Count
            $output.Text = "Completed`r`nRequests: $($summary.RequestCount)`r`nHTTP errors: $($summary.HttpErrors)`r`nJBoss errors: $($summary.JBossErrors)`r`nFull GC: $($summary.FullGcCount)`r`nUnrecognized rows: $issueCount`r`nHTML report and 3 CSV files were written to Desktop."
        } catch { $output.Text = $_.Exception.Message }
    }.GetNewClosure())
    $form.Controls.Add($run)
    [void]$form.ShowDialog()
}

if ($MyInvocation.InvocationName -ne '.') { Start-LogAnalyzerGui }
