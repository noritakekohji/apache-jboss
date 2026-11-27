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
    $formats = @('yyyy-MM-dd HH:mm:ss,fffzzz','yyyy-MM-dd HH:mm:ss.fffzzz','yyyy-MM-dd HH:mm:sszzz','yyyy-MM-dd HH:mm:ss,fff','yyyy-MM-dd HH:mm:ss.fff','yyyy-MM-dd HH:mm:ss','yyyy-MM-dd''T''HH:mm:ss.fffzzz','yyyy-MM-dd''T''HH:mm:sszzz')
    if ($Text -match '[+-]\d{4}$') { $Text = $Text.Insert($Text.Length - 2, ':') }
    if ($Text.EndsWith('Z')) { $Text = $Text.Substring(0, $Text.Length - 1) + '+00:00' }
    if ($Text -match '(?:Z|[+-]\d{2}:\d{2})$') {
        $offset = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParseExact($Text, $formats, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$offset)) {
            return $offset.ToOffset([TimeSpan]::FromHours(9)).DateTime
        }
        if ([DateTimeOffset]::TryParse($Text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$offset)) {
            return $offset.ToOffset([TimeSpan]::FromHours(9)).DateTime
        }
        return $null
    }
    $styles = [Globalization.DateTimeStyles]::None
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
            $timestampOffset = [DateTimeOffset]::MinValue
            if (-not [DateTimeOffset]::TryParseExact($Matches.time, 'dd/MMM/yyyy:HH:mm:ss zzz', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$timestampOffset)) {
                $issues.Add([pscustomobject]@{ File=$file; Line=$lineNo; Reason='Invalid Apache timestamp'; Text=$line }); continue
            }
            $timestamp = $timestampOffset.ToOffset([TimeSpan]::FromHours(9)).DateTime
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
            if ([string]::IsNullOrWhiteSpace($line) -or $line -match '^(?:CommandLine flags:|Java HotSpot\(TM\)|Using .+ collector|\[Times: user=|\[Heap (?:before|after) GC|\[?(?:Eden|From Space|To Space|PSYoungGen|ParOldGen|ParNew|DefNew|Tenured|G1 Eden Space):|Desired survivor size\b)') { continue }

            $timestamp = $null
            $elapsedSeconds = $null
            $message = $line
            if ($line -match '^\[(?<elapsed>\d+(?:\.\d+)?)s\](?<decorations>(?:\[[^\]]+\])*)\s*(?<message>.*)$') {
                $elapsedSeconds = [double]$Matches.elapsed
                $message = $Matches.message
            } elseif ($line -match '^\[(?<time>\d{4}-\d{2}-\d{2}T[^\]]+)\](?<decorations>(?:\[[^\]]+\])*)\s*(?<message>.*)$') {
                $timestamp = Get-LogTimestamp $Matches.time
                $message = $Matches.message
            } elseif ($line -match '^(?<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?):\s*(?<message>.*)$') {
                $timestamp = Get-LogTimestamp $Matches.time
                $message = $Matches.message
            } elseif ($line -match '^\[(?<elapsed>\d+(?:\.\d+)?)(?:s|:)\s*(?<message>.*)$') {
                $elapsedSeconds = [double]$Matches.elapsed
                $message = $Matches.message
            }
            if ($message -match 'Total time for which application threads were stopped:\s*(?<duration>\d+(?:\.\d+)?)\s+seconds?') {
                $durationMs = [double]$Matches.duration * 1000
                $records.Add([pscustomobject]@{ Time=$timestamp; ElapsedSeconds=$elapsedSeconds; Kind='Application Stopped'; Cause='Stop-the-world interval'; DurationMs=$durationMs; HeapBeforeMb=$null; HeapAfterMb=$null; HeapCapacityMb=$null; Source=$file; Line=$lineNo; Message=$line })
                continue
            }

            $eventLabel = $null
            $cause = ''
            if ($message -match '(?:GC\(\d+\)\s+)?(?<event>Pause Full|Full GC|Pause Young|Pause Mixed|Pause Remark|Pause Cleanup|Pause Last ditch|Pause Init Mark|Pause Final Mark|Pause Degenerated(?: GC)?|Pause Init Update Refs|Pause Final Update Refs|Concurrent Mark Cycle|Concurrent Undo Cycle|Concurrent Start|Garbage Collection|(?<!\w)GC(?!\(\d+\)))') {
                $eventLabel = $Matches.event.Trim()
                if ($message -match '(?:Pause Full|Full GC|Pause Young|Pause Mixed|\bGC)\s*\((?<cause>[^)]*)\)') { $cause = $Matches.cause }
            }
            if ($null -eq $eventLabel -and $message -match '\bGC\(\d+\)\s+(?:Forward|Adjust Pointers|Scan Heap Roots|Update Remembered Set|Object Copy)\b') { continue }
            if ($null -eq $eventLabel) {
                $issues.Add([pscustomobject]@{ File=$file; Line=$lineNo; Reason='GC event not recognized'; Text=$line })
                continue
            }

            $kind = switch -Regex ($eventLabel) {
                '^(?:Pause Full|Full GC)$' { 'Full GC'; break }
                '^Pause Young$' { 'Young GC'; break }
                '^Pause Mixed$' { 'Mixed GC'; break }
                '^Pause Remark$' { 'Remark'; break }
                '^Pause Cleanup$' { 'Cleanup'; break }
                '^Pause Degenerated' { 'Degenerated'; break }
                '^Concurrent' { 'Concurrent'; break }
                '^Garbage Collection$' { 'Collection'; break }
                default { 'GC' }
            }
            if ($kind -eq 'GC' -and $message -match '\(young\)') { $kind = 'Young GC' }
            if ($kind -eq 'GC' -and $message -match '\(mixed\)') { $kind = 'Mixed GC' }

            $durationMs = $null
            if ($message -match '(?<duration>\d+(?:\.\d+)?)\s*(?<unit>ms|secs?|s)\b') {
                $durationMs = [double]$Matches.duration
                if ($Matches.unit -match '^s(?:ec)?s?$') { $durationMs *= 1000 }
            }
            $heapBefore = $null; $heapAfter = $null; $heapCapacity = $null
            if ($message -match '(?<before>\d+(?:\.\d+)?\s*[BKMG])(?:\((?<beforeCapacity>\d+(?:\.\d+)?\s*[BKMG])\))?->(?<after>\d+(?:\.\d+)?\s*[BKMG])(?:\((?<capacity>\d+(?:\.\d+)?\s*[BKMG])\))?') {
                $heapBefore = ConvertTo-GcMegabyte $Matches.before
                $heapAfter = ConvertTo-GcMegabyte $Matches.after
                $capacityText = if ($Matches.capacity) { $Matches.capacity } else { $Matches.beforeCapacity }
                if ($capacityText) { $heapCapacity = ConvertTo-GcMegabyte $capacityText }
            }
            if ($null -eq $durationMs -and $null -eq $heapBefore -and $null -eq $elapsedSeconds) {
                $issues.Add([pscustomobject]@{ File=$file; Line=$lineNo; Reason='GC event has no measurable pause, heap, or elapsed time'; Text=$line })
                continue
            }
            $records.Add([pscustomobject]@{ Time=$timestamp; ElapsedSeconds=$elapsedSeconds; Kind=$kind; Cause=$cause; DurationMs=$durationMs; HeapBeforeMb=$heapBefore; HeapAfterMb=$heapAfter; HeapCapacityMb=$heapCapacity; Source=$file; Line=$lineNo; Message=$line })
        }
    }
    return [pscustomobject]@{ Records=$records; Issues=$issues }
}

function ConvertTo-GcMegabyte {
    param([string]$Value)
    if ($Value -notmatch '^\s*(?<amount>\d+(?:\.\d+)?)\s*(?<unit>[BKMG])\s*$') { return $null }
    $amount = [double]$Matches.amount
    switch ($Matches.unit) {
        'K' { return $amount / 1024 }
        'M' { return $amount }
        'G' { return $amount * 1024 }
        'B' { return $amount / 1048576 }
    }
}

function Get-AnalysisSummary {
    param([object[]]$Requests,[object[]]$Events,[object[]]$GcEvents)
    $durations = @($Requests | Where-Object { $null -ne $_.DurationMs } | ForEach-Object { [double]$_.DurationMs } | Sort-Object)
    $percentile = { param($items,$p) if ($items.Count -eq 0) { return $null }; $index=[math]::Ceiling($items.Count*$p)-1; return $items[[math]::Max(0,$index)] }
    $errors = @($Requests | Where-Object { $_.Status -ge 400 }).Count
    $fullGc = @($GcEvents | Where-Object Kind -eq 'Full GC' | Sort-Object Time)
    $pauseTotal = 0.0
    foreach ($gcEvent in $fullGc) {
        if ($null -ne $gcEvent.DurationMs) { $pauseTotal += [double]$gcEvent.DurationMs }
    }
    $gcPauses = @($GcEvents | Where-Object { $null -ne $_.DurationMs } | ForEach-Object { [double]$_.DurationMs } | Sort-Object)
    $fullGcIntervals = [Collections.Generic.List[double]]::new()
    for ($index = 1; $index -lt $fullGc.Count; $index++) {
        $previousGc = $fullGc[$index - 1]
        $currentGc = $fullGc[$index]
        $intervalMinutes = $null
        if ($null -ne $currentGc.Time -and $null -ne $previousGc.Time) {
            $intervalMinutes = ($currentGc.Time - $previousGc.Time).TotalMinutes
        } elseif ($currentGc.Source -eq $previousGc.Source -and $null -ne $currentGc.ElapsedSeconds -and $null -ne $previousGc.ElapsedSeconds) {
            $intervalMinutes = ($currentGc.ElapsedSeconds - $previousGc.ElapsedSeconds) / 60
        }
        if ($null -ne $intervalMinutes -and $intervalMinutes -gt 0) { $fullGcIntervals.Add($intervalMinutes) }
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
        MinGcPauseMs = if ($gcPauses.Count -gt 0) { $gcPauses[0] } else { $null }
        MaxGcPauseMs = if ($gcPauses.Count -gt 0) { $gcPauses[-1] } else { $null }
        AvgGcPauseMs = if ($gcPauses.Count -gt 0) { [math]::Round(($gcPauses | Measure-Object -Average).Average, 2) } else { $null }
        MinFullGcIntervalMin = if ($fullGcIntervals.Count -gt 0) { [math]::Round(($fullGcIntervals | Measure-Object -Minimum).Minimum, 2) } else { $null }
        MaxFullGcIntervalMin = if ($fullGcIntervals.Count -gt 0) { [math]::Round(($fullGcIntervals | Measure-Object -Maximum).Maximum, 2) } else { $null }
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
    $reportTime = [DateTimeOffset]::Now.ToOffset([TimeSpan]::FromHours(9)).ToString('yyyy-MM-dd HH:mm:ss')
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
    $pauseEvents = @($GcEvents | Where-Object { $null -ne $_.DurationMs })
    $maxPauseMs = 1.0
    foreach ($pauseEvent in $pauseEvents) {
        if ($pauseEvent.DurationMs -gt $maxPauseMs) { $maxPauseMs = $pauseEvent.DurationMs }
    }
    $pauseBars = foreach ($pauseEvent in $pauseEvents) {
        $height = [math]::Max(2, [math]::Round(100 * $pauseEvent.DurationMs / $maxPauseMs))
        '<div class="hour" title="{0}: {1} ms"><div class="pause-bar" style="height:{2}%"></div><small>{3}</small></div>' -f (ConvertTo-SafeHtml $pauseEvent.Kind), $pauseEvent.DurationMs, $height, (ConvertTo-SafeHtml $pauseEvent.DurationMs)
    }
    $heapEvents = @($GcEvents | Where-Object { $null -ne $_.HeapAfterMb } | Sort-Object Time)
    $maxHeapMb = 1.0
    $heapMarkers = @()
    $heapPoints = @()
    foreach ($heapEvent in $heapEvents) {
        if ($heapEvent.HeapAfterMb -gt $maxHeapMb) { $maxHeapMb = $heapEvent.HeapAfterMb }
    }
    if ($heapEvents.Count -gt 0) {
        $heapMarkers = foreach ($index in 0..($heapEvents.Count - 1)) {
            $x = if ($heapEvents.Count -eq 1) { 500 } else { [math]::Round(1000 * $index / ($heapEvents.Count - 1)) }
            $y = [math]::Round(190 - (170 * $heapEvents[$index].HeapAfterMb / $maxHeapMb))
            $label = '{0}: {1} MB' -f (ConvertTo-SafeHtml $heapEvents[$index].Kind), $heapEvents[$index].HeapAfterMb
            '<circle cx="{0}" cy="{1}" r="5"><title>{2}</title></circle>' -f $x, $y, $label
        }
        $heapPoints = foreach ($index in 0..($heapEvents.Count - 1)) {
            $x = if ($heapEvents.Count -eq 1) { 500 } else { [math]::Round(1000 * $index / ($heapEvents.Count - 1)) }
            $y = [math]::Round(190 - (170 * $heapEvents[$index].HeapAfterMb / $maxHeapMb))
            '{0},{1}' -f $x, $y
        }
    }
    $gcRows = foreach ($gcEvent in @($GcEvents | Sort-Object Time | Select-Object -First 200)) {
        $eventTime = if ($null -ne $gcEvent.Time) { $gcEvent.Time.ToString('yyyy-MM-dd HH:mm:ss.fff') } elseif ($null -ne $gcEvent.ElapsedSeconds) { 'uptime {0}s' -f $gcEvent.ElapsedSeconds } else { 'time unavailable' }
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}/{6} MB</td><td>{7} MB</td></tr>' -f (ConvertTo-SafeHtml $eventTime), (ConvertTo-SafeHtml $gcEvent.Kind), (ConvertTo-SafeHtml $gcEvent.Cause), $gcEvent.DurationMs, (ConvertTo-SafeHtml $gcEvent.HeapBeforeMb), (ConvertTo-SafeHtml $gcEvent.HeapAfterMb), (ConvertTo-SafeHtml $gcEvent.HeapCapacityMb), (ConvertTo-SafeHtml ([IO.Path]::GetFileName($gcEvent.Source)))
    }
    $jbossRows = foreach ($jbossEvent in @($Events | Where-Object Level -in @('ERROR','FATAL') | Select-Object -First 100)) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (ConvertTo-SafeHtml $jbossEvent.Time.ToString('yyyy-MM-dd HH:mm:ss.fff')), (ConvertTo-SafeHtml $jbossEvent.Level), (ConvertTo-SafeHtml ([IO.Path]::GetFileName($jbossEvent.Source))), $jbossEvent.Line
    }
    $rows = foreach ($item in @($Requests | Sort-Object DurationMs -Descending | Select-Object -First 100)) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (ConvertTo-SafeHtml $item.Time.ToString('yyyy-MM-dd HH:mm:ss.fff')), (ConvertTo-SafeHtml $item.Method), (ConvertTo-SafeHtml (($item.Url -split '\?')[0])), $item.Status, $item.DurationMs
    }
    $html = @"
<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Apache / JBoss ログ分析</title>
<style>body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033}h1{color:#173b65}.cards{display:flex;gap:1rem;flex-wrap:wrap}.card{background:#eef4fa;padding:1rem;border-radius:8px;min-width:130px}.chart{height:190px;display:flex;align-items:end;gap:3px;border-bottom:1px solid #ccd5df;padding:1rem 0}.hour{height:100%;flex:1;display:flex;flex-direction:column;justify-content:end;align-items:center;min-width:12px}.bar{background:#3984bd;width:75%;min-height:2px}.pause-bar{background:#e35d5b;width:75%;min-height:2px}.hour small{font-size:10px;writing-mode:vertical-rl;color:#586575;margin-top:4px}.heap-chart{width:100%;height:220px}.heap-chart polyline{fill:none;stroke:#3984bd;stroke-width:3}.heap-chart circle{fill:#e35d5b}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ccd5df;padding:.5rem;text-align:left}small{color:#586575}</style>
<h1>Apache / JBoss ログ分析</h1><p>生成日時: $reportTime JST</p><div class="cards">
<div class="card">リクエスト<br><b>$($Summary.RequestCount)</b></div><div class="card">HTTPエラー<br><b>$($Summary.HttpErrors) ($($Summary.HttpErrorRate)%)</b></div><div class="card">p95 応答時間<br><b>$($Summary.P95Ms) ms</b></div><div class="card">JBoss ERROR<br><b>$($Summary.JBossErrors)</b></div><div class="card">フルGC<br><b>$($Summary.FullGcCount) 回</b></div><div class="card">フルGC停止合計<br><b>$($Summary.FullGcPauseMs) ms</b></div><div class="card">GC停止 min / avg / max<br><b>$($Summary.MinGcPauseMs) / $($Summary.AvgGcPauseMs) / $($Summary.MaxGcPauseMs) ms</b></div><div class="card">Full GC間隔 min / max<br><b>$($Summary.MinFullGcIntervalMin) / $($Summary.MaxFullGcIntervalMin) 分</b></div></div>
<h2>時間帯別リクエスト数</h2><small>棒の高さは時間ごとの件数です。棒にカーソルを合わせるとHTTPエラー数も表示します。</small><div class="chart">$($chartBars -join "`n")</div>
<h2>GC停止時間</h2><small>赤い棒が個々のGC停止時間です。棒にカーソルを合わせると種別と時間を表示します。</small><div class="chart pause-chart">$($pauseBars -join "`n")</div>
<h2>GC後ヒープ使用量の推移</h2><small>各点はGC後の使用量です。単位はMB。イベント行の順に並べています。</small><svg class="heap-chart" viewBox="0 0 1000 220" role="img" aria-label="GC後ヒープ使用量">$(if($heapEvents.Count -gt 0){'<polyline points="'+($heapPoints -join ' ')+'"/>' + ($heapMarkers -join '')})</svg>
<h2>GCイベント詳細</h2><p>平均停止: $($Summary.AvgGcPauseMs) ms / 最大停止: $($Summary.MaxGcPauseMs) ms / Full GC間隔: $($Summary.MinFullGcIntervalMin)〜$($Summary.MaxFullGcIntervalMin) 分</p><table><thead><tr><th>時刻</th><th>種別</th><th>原因</th><th>停止(ms)</th><th>ヒープ前/後(MB)</th><th>最大ヒープ(MB)</th><th>ファイル</th></tr></thead><tbody>$($gcRows -join "`n")</tbody></table>
<h2>JBossエラー行</h2><p>ログ本文は共有レポートへ含めず、元ファイル名と行番号のみを表示します。</p><table><thead><tr><th>時刻(JST)</th><th>レベル</th><th>ファイル</th><th>行</th></tr></thead><tbody>$($jbossRows -join "`n")</tbody></table>
<h2>遅延上位リクエスト</h2><small>Apacheログに処理時間がある場合のみ応答時間を集計します。URLのクエリ文字列は除去しています。</small><table><thead><tr><th>時刻</th><th>Method</th><th>Path</th><th>Status</th><th>ms</th></tr></thead><tbody>$($rows -join "`n")</tbody></table>
<h2>注意</h2><p>時刻の近接は因果関係を示しません。ApacheとJBoss間の相関はリクエストID未確認のため、この初版では自動断定しません。ログ本文は出力していません。</p></html>
"@
    [IO.File]::WriteAllText($Path,$html,[Text.UTF8Encoding]::new($true))
}

function Show-LogAnalyzerGui {
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
            Export-AnalysisCsv @($gcResult.Records | Select-Object Time,ElapsedSeconds,Kind,Cause,DurationMs,HeapBeforeMb,HeapAfterMb,HeapCapacityMb,Source,Line) (Join-Path $outDir 'gc-events.csv')
            $issueCount = $apacheResult.Issues.Count + $jbossResult.Issues.Count + $gcResult.Issues.Count
            $output.Text = "Completed`r`nRequests: $($summary.RequestCount)`r`nHTTP errors: $($summary.HttpErrors)`r`nJBoss errors: $($summary.JBossErrors)`r`nFull GC: $($summary.FullGcCount)`r`nUnrecognized rows: $issueCount`r`nHTML report and 3 CSV files were written to Desktop."
        } catch { $output.Text = $_.Exception.Message }
    }.GetNewClosure())
    $form.Controls.Add($run)
    [void]$form.ShowDialog()
}

if ($MyInvocation.InvocationName -ne '.') { Show-LogAnalyzerGui }
