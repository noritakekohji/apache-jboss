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
    $seenLines = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $duplicateCount = 0
    $pattern = '^(?<host>\S+) \S+ \S+ \[(?<time>[^\]]+)\] "(?<method>\S+) (?<url>\S+) (?<protocol>[^"]+)" (?<status>\d{3}) (?<bytes>\S+)(?: "(?<referer>[^"]*)" "(?<agent>[^"]*)")?(?: (?<duration>\d+(?:\.\d+)?))?$'
    foreach ($file in $Path) {
        $seenInFile = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $lineNo = 0
        foreach ($line in [IO.File]::ReadLines($file)) {
            $lineNo++
            $isFirstInFile = $seenInFile.Add($line)
            if ($isFirstInFile -and $seenLines.Contains($line)) { $duplicateCount++; continue }
            [void]$seenLines.Add($line)
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
    return [pscustomobject]@{ Records=$records; Issues=$issues; DuplicateCount=$duplicateCount }
}

function Read-JBossLog {
    param([string[]]$Path)
    $records = [Collections.Generic.List[object]]::new()
    $issues = [Collections.Generic.List[object]]::new()
    $seenLines = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $duplicateCount = 0
    $pattern = '^(?<time>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,.]\d{3})?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+(?<message>.*)$'
    foreach ($file in $Path) {
        $seenInFile = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $lineNo = 0
        foreach ($line in [IO.File]::ReadLines($file)) {
            $lineNo++
            $isFirstInFile = $seenInFile.Add($line)
            if ($isFirstInFile -and $seenLines.Contains($line)) { $duplicateCount++; continue }
            [void]$seenLines.Add($line)
            if ($line -notmatch $pattern) { $issues.Add([pscustomobject]@{ File=$file; Line=$lineNo; Reason='JBoss timestamp/level format not recognized'; Text=$line }); continue }
            $stampText = $Matches.time.Replace('T',' ')
            $stampText = $stampText -replace '(\d{2}),(\d{3})','$1.$2'
            $timestamp = Get-LogTimestamp $stampText
            if ($null -eq $timestamp) { $issues.Add([pscustomobject]@{ File=$file; Line=$lineNo; Reason='Invalid JBoss timestamp'; Text=$line }); continue }
            $records.Add([pscustomobject]@{ Time=$timestamp; Level=$Matches.level; Message=$Matches.message; Source=$file; Line=$lineNo; Kind='JBoss' })
        }
    }
    return [pscustomobject]@{ Records=$records; Issues=$issues; DuplicateCount=$duplicateCount }
}

function Read-GcLog {
    param([string[]]$Path)
    $records = [Collections.Generic.List[object]]::new()
    $issues = [Collections.Generic.List[object]]::new()
    $seenLines = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $duplicateCount = 0
    foreach ($file in $Path) {
        $seenInFile = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $lineNo = 0
        foreach ($line in [IO.File]::ReadLines($file)) {
            $lineNo++
            $isFirstInFile = $seenInFile.Add($line)
            if ($isFirstInFile -and $seenLines.Contains($line)) { $duplicateCount++; continue }
            [void]$seenLines.Add($line)
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
    return [pscustomobject]@{ Records=$records; Issues=$issues; DuplicateCount=$duplicateCount }
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

function Select-RecordsInTimeRange {
    param([object[]]$Records,[datetime]$StartTime,[datetime]$EndTime)
    $matched = [Collections.Generic.List[object]]::new()
    $withoutTime = 0
    foreach ($record in $Records) {
        if ($null -eq $record.Time) { $withoutTime++; continue }
        if ($record.Time -ge $StartTime -and $record.Time -le $EndTime) { $matched.Add($record) }
    }
    return [pscustomobject]@{ Records=@($matched.ToArray()); UntimedCount=$withoutTime }
}

function Export-AnalysisHtml {
    param([object]$Summary,[object[]]$Requests,[object[]]$Events,[object[]]$GcEvents,[string]$Path,[datetime]$StartTime,[datetime]$EndTime,[int]$UntimedExcludedCount=0,[int]$DuplicateCount=0)
    $reportTime = [DateTimeOffset]::Now.ToOffset([TimeSpan]::FromHours(9)).ToString('yyyy-MM-dd HH:mm:ss')
    $periodText = if ($StartTime -and $EndTime) { '{0} 〜 {1} JST' -f $StartTime.ToString('yyyy-MM-dd HH:mm'),$EndTime.ToString('yyyy-MM-dd HH:mm') } else { '期間指定なし' }
    $requestBuckets = @($Requests | Where-Object { $null -ne $_.Time } | Group-Object { $_.Time.AddMinutes(-($_.Time.Minute % 5)).ToString('yyyy-MM-dd HH:mm') } | Sort-Object Name)
    $pauseEvents = @($GcEvents | Where-Object { $null -ne $_.DurationMs -and $null -ne $_.Time } | Sort-Object Time)
    $heapEvents = @($GcEvents | Where-Object { $null -ne $_.HeapAfterMb -and $null -ne $_.Time } | Sort-Object Time)
    $untimedPauseCount = @($GcEvents | Where-Object { $null -ne $_.DurationMs -and $null -eq $_.Time }).Count
    $untimedHeapCount = @($GcEvents | Where-Object { $null -ne $_.HeapAfterMb -and $null -eq $_.Time }).Count
    $requestSvg = Get-ReportBarChart $requestBuckets '5分単位のリクエスト数' 'リクエスト数（件/5分）' 'five-minute'
    $pauseSvg = Get-ReportBarChart $pauseEvents 'GC停止時間' '停止時間（ms）' 'pause'
    $heapSvg = Get-ReportHeapChart $heapEvents
    $gcRows = foreach ($gcEvent in @($GcEvents | Sort-Object Time | Select-Object -First 200)) {
        $eventTime = if ($null -ne $gcEvent.Time) { $gcEvent.Time.ToString('yyyy-MM-dd HH:mm:ss.fff') } elseif ($null -ne $gcEvent.ElapsedSeconds) { 'uptime {0}s' -f $gcEvent.ElapsedSeconds } else { 'time unavailable' }
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}/{5} MB</td><td>{6} MB</td><td>{7}</td></tr>' -f (ConvertTo-SafeHtml $eventTime), (ConvertTo-SafeHtml $gcEvent.Kind), (ConvertTo-SafeHtml $gcEvent.Cause), $gcEvent.DurationMs, (ConvertTo-SafeHtml $gcEvent.HeapBeforeMb), (ConvertTo-SafeHtml $gcEvent.HeapAfterMb), (ConvertTo-SafeHtml $gcEvent.HeapCapacityMb), (ConvertTo-SafeHtml ([IO.Path]::GetFileName($gcEvent.Source)))
    }
    $jbossRows = foreach ($jbossEvent in @($Events | Where-Object Level -in @('ERROR','FATAL') | Select-Object -First 100)) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (ConvertTo-SafeHtml $jbossEvent.Time.ToString('yyyy-MM-dd HH:mm:ss.fff')), (ConvertTo-SafeHtml $jbossEvent.Level), (ConvertTo-SafeHtml ([IO.Path]::GetFileName($jbossEvent.Source))), $jbossEvent.Line
    }
    $rows = foreach ($item in @($Requests | Sort-Object DurationMs -Descending | Select-Object -First 100)) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (ConvertTo-SafeHtml $item.Time.ToString('yyyy-MM-dd HH:mm:ss.fff')), (ConvertTo-SafeHtml $item.Method), (ConvertTo-SafeHtml (($item.Url -split '\?')[0])), $item.Status, $item.DurationMs
    }
    $html = @"
<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Apache / JBoss ログ分析</title>
<style>body{font:15px/1.55 "Segoe UI",Meiryo,sans-serif;max-width:1200px;margin:0 auto;padding:24px;color:#182b40;background:#f4f7fb}h1{color:#123c62}h2{margin:0 0 .6rem;color:#174b72}.intro,.panel{background:#fff;border:1px solid #dbe4ed;border-radius:12px;padding:20px;margin:16px 0}.muted,small{color:#526579}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}.card{background:#edf4fa;border-left:4px solid #2878ad;padding:12px;border-radius:7px}.card b{font-size:1.2rem}.chart{width:100%;height:auto;display:block}.chart text{font:12px "Segoe UI",Meiryo,sans-serif;fill:#34495e}.grid{stroke:#d9e2eb}.axis{stroke:#60758a}.bar{fill:#277eae}.pause{fill:#c94d4d}.heap-line{fill:none;stroke:#277eae;stroke-width:3}.heap-point{fill:#c94d4d}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #dbe4ed;padding:.55rem;text-align:left}th{background:#edf4fa}.table-wrap{overflow:auto;max-height:480px}.note{background:#fff7df;border-left:4px solid #d89d16;padding:12px}.empty{fill:#60758a}.legend{display:inline-block;width:12px;height:12px;margin:0 5px 0 14px;border-radius:2px}.legend-blue{background:#277eae}.legend-red{background:#c94d4d}</style>
<header class="intro"><h1>Apache / JBoss ログ分析レポート</h1><p>生成日時: $reportTime JST</p><p>対象期間: $periodText</p><p class="muted">各グラフに軸の値と単位を表示します。</p></header><section class="panel"><h2>概要</h2><div class="cards">
<div class="card">リクエスト<br><b>$($Summary.RequestCount)</b></div><div class="card">HTTPエラー<br><b>$($Summary.HttpErrors) ($($Summary.HttpErrorRate)%)</b></div><div class="card">p95 応答時間<br><b>$($Summary.P95Ms) ms</b></div><div class="card">JBoss ERROR<br><b>$($Summary.JBossErrors)</b></div><div class="card">フルGC<br><b>$($Summary.FullGcCount) 回</b></div><div class="card">フルGC停止合計<br><b>$($Summary.FullGcPauseMs) ms</b></div><div class="card">GC停止 min / avg / max<br><b>$($Summary.MinGcPauseMs) / $($Summary.AvgGcPauseMs) / $($Summary.MaxGcPauseMs) ms</b></div><div class="card">Full GC間隔 min / max<br><b>$($Summary.MinFullGcIntervalMin) / $($Summary.MaxFullGcIntervalMin) 分</b></div></div>
<p class="muted">HTTPエラーは400以上。標準Combinedには応答時間がない場合があります。指定期間内のレコードのみを集計しています。</p><p class="muted">複数ファイル間などの完全一致重複行を除外: $DuplicateCount 行。</p><p class="muted">期間内か判別できない時刻なしレコード（GCを含む）: $UntimedExcludedCount 件（出力対象外）</p></section><section class="panel"><h2>5分単位のリクエスト数</h2><p class="muted"><span class="legend legend-blue"></span>正常系 <span class="legend legend-red"></span>HTTPエラー<br>縦軸: 件/5分、横軸: 時刻（JST）。時刻ラベルは読みやすさのため間引いています。</p>$requestSvg</section><section class="panel"><h2>GC停止時間</h2><p class="muted">縦軸: 停止時間（ms）、横軸: 時刻（JST）。時刻ラベルは読みやすさのため間引いています。</p>$pauseSvg<p class="muted">時刻を記録していないGC停止イベント: $untimedPauseCount 件（グラフ対象外）</p></section><section class="panel"><h2>GC後ヒープ使用量</h2><p class="muted">縦軸: 使用量（MB）、横軸: 時刻（JST）。</p>$heapSvg<p class="muted">時刻を記録していないヒープイベント: $untimedHeapCount 件（グラフ対象外）</p></section>
<section class="panel"><h2>GCイベント詳細</h2><p>平均停止: $($Summary.AvgGcPauseMs) ms / 最大停止: $($Summary.MaxGcPauseMs) ms / Full GC間隔: $($Summary.MinFullGcIntervalMin)〜$($Summary.MaxFullGcIntervalMin) 分</p><div class="table-wrap"><table><thead><tr><th>時刻</th><th>種別</th><th>原因</th><th>停止(ms)</th><th>ヒープ前/後(MB)</th><th>最大ヒープ(MB)</th><th>ファイル</th></tr></thead><tbody>$($gcRows -join "`n")</tbody></table></div></section><section class="panel"><h2>JBossエラー行</h2><p>本文を含めず、ファイル名と行番号のみ表示します。</p><div class="table-wrap"><table><thead><tr><th>時刻(JST)</th><th>レベル</th><th>ファイル</th><th>行</th></tr></thead><tbody>$($jbossRows -join "`n")</tbody></table></div></section><section class="panel"><h2>遅延上位リクエスト</h2><p>応答時間がある場合のみ表示し、URLクエリを除去します。</p><div class="table-wrap"><table><thead><tr><th>時刻</th><th>Method</th><th>Path</th><th>Status</th><th>ms</th></tr></thead><tbody>$($rows -join "`n")</tbody></table></div></section><section class="panel note"><b>注意</b><p>時刻の近接は因果関係を意味しません。リクエストID未確認のためApache/JBoss間を自動対応付けしません。ログ本文とURLクエリは含めません。</p></section></html>
"@
    [IO.File]::WriteAllText($Path,$html,[Text.UTF8Encoding]::new($true))
}

function Get-ReportBarChart {
    param([object[]]$Items,[string]$Title,[string]$AxisLabel,[string]$Mode)
    $left=72;$top=22;$plotW=790;$plotH=205
    $isRequestChart=$Mode -eq 'five-minute'
    $values=if($isRequestChart){@($Items|ForEach-Object{[double]$_.Count})}else{@($Items|ForEach-Object{[double]$_.DurationMs})}
    $values=@($values)
    if($values.Count -eq 0){return '<svg class="chart" viewBox="0 0 900 300" role="img" aria-label="{0}"><text class="empty" x="80" y="150">対象データがありません</text></svg>' -f (ConvertTo-SafeHtml $Title)}
    $max=($values|Measure-Object -Maximum).Maximum;if($max -le 0){$max=1};$step=[math]::Max(1,[math]::Ceiling($max/4));$svg=[Collections.Generic.List[string]]::new()
    $isMultiDay=$false
    if(-not $isRequestChart){$isMultiDay=$Items[0].Time.Date -ne $Items[$Items.Count-1].Time.Date}
    for($tick=0;$tick -le $max;$tick+=$step){$y=$top+$plotH-($tick/$max*$plotH);$svg.Add(('<line class="grid" x1="{0}" y1="{1}" x2="{2}" y2="{1}"/><text x="{3}" y="{4}" text-anchor="end">{5}</text>' -f $left,$y,($left+$plotW),($left-10),($y+4),$tick))}
    $svg.Add(('<text x="16" y="{0}" transform="rotate(-90 16 {0})" text-anchor="middle">{1}</text><text x="{2}" y="292" text-anchor="middle">時刻（JST）</text>' -f ($top+$plotH/2),(ConvertTo-SafeHtml $AxisLabel),($left+$plotW/2)))
    $slot=$plotW/$values.Count;$barW=[math]::Max(2,$slot*0.64);$labelStep=[math]::Max(1,[math]::Ceiling(($values.Count-1)/7))
    for($i=0;$i -lt $values.Count;$i++){
        $x=$left+$slot*$i+($slot-$barW)/2;$barH=$values[$i]/$max*$plotH;$y=$top+$plotH-$barH
        if($isRequestChart){
            $errorCount=@($Items[$i].Group|Where-Object Status -ge 400).Count;$normalCount=$values[$i]-$errorCount;$errorHeight=$errorCount/$max*$plotH;$normalHeight=$normalCount/$max*$plotH
            if($normalHeight -gt 0){$svg.Add(('<rect class="bar" x="{0}" y="{1}" width="{2}" height="{3}"><title>{4}: 合計 {5} 件、HTTPエラー {6} 件</title></rect>' -f $x,($y+$errorHeight),$barW,$normalHeight,(ConvertTo-SafeHtml $Items[$i].Name),$Items[$i].Count,$errorCount))}
            if($errorHeight -gt 0){$svg.Add(('<rect class="pause" x="{0}" y="{1}" width="{2}" height="{3}"><title>{4}: 合計 {5} 件、HTTPエラー {6} 件</title></rect>' -f $x,$y,$barW,$errorHeight,(ConvertTo-SafeHtml $Items[$i].Name),$Items[$i].Count,$errorCount))}
            $bucketTime=[datetime]::ParseExact($Items[$i].Name,'yyyy-MM-dd HH:mm',[Globalization.CultureInfo]::InvariantCulture)
            $isMultiDay=([datetime]::ParseExact($Items[$values.Count-1].Name,'yyyy-MM-dd HH:mm',[Globalization.CultureInfo]::InvariantCulture).Date -gt [datetime]::ParseExact($Items[0].Name,'yyyy-MM-dd HH:mm',[Globalization.CultureInfo]::InvariantCulture).Date)
            $label=if($isMultiDay){$bucketTime.ToString('MM/dd HH:mm')}else{$bucketTime.ToString('HH:mm')}
        }else{
            $timeLabel=$Items[$i].Time.ToString('yyyy-MM-dd HH:mm:ss');$svg.Add(('<rect class="pause" x="{0}" y="{1}" width="{2}" height="{3}"><title>{4}: {5} ms</title></rect>' -f $x,$y,$barW,[math]::Max(1,$barH),(ConvertTo-SafeHtml $timeLabel),$values[$i]));$label=if($isMultiDay){$Items[$i].Time.ToString('MM/dd HH:mm')}else{$Items[$i].Time.ToString('HH:mm')}
        }
        if(($i%$labelStep -eq 0)-or($i -eq $values.Count-1)){$svg.Add(('<text x="{0}" y="{1}" text-anchor="middle">{2}</text>' -f ($x+$barW/2),($top+$plotH+18),(ConvertTo-SafeHtml $label)))}
    }
    return '<svg class="chart" data-kind="{0}" viewBox="0 0 900 300" role="img" aria-label="{1}">{2}</svg>' -f $(if($Mode -eq 'pause'){'pause-chart'}else{'request-chart'}),(ConvertTo-SafeHtml $Title),($svg -join '')
}

function Get-ReportHeapChart {
    param([object[]]$Items)
    $left=72;$top=22;$plotW=790;$plotH=205
    if($Items.Count -eq 0){return '<svg class="chart heap-chart" viewBox="0 0 900 300"><text class="empty" x="80" y="150">ヒープ情報がありません</text></svg>'}
    $max=($Items|ForEach-Object{[double]$_.HeapAfterMb}|Measure-Object -Maximum).Maximum;if($max -le 0){$max=1};$step=[math]::Max(1,[math]::Ceiling($max/4));$svg=[Collections.Generic.List[string]]::new();for($tick=0;$tick -le $max;$tick+=$step){$y=$top+$plotH-($tick/$max*$plotH);$svg.Add(('<line class="grid" x1="{0}" y1="{1}" x2="{2}" y2="{1}"/><text x="{3}" y="{4}" text-anchor="end">{5} MB</text>' -f $left,$y,($left+$plotW),($left-10),($y+4),$tick))}
    $points=[Collections.Generic.List[string]]::new();$marks=[Collections.Generic.List[string]]::new();$slot=if($Items.Count -eq 1){0}else{$plotW/($Items.Count-1)};for($i=0;$i -lt $Items.Count;$i++){$x=$left+$(if($Items.Count -eq 1){$plotW/2}else{$slot*$i});$y=$top+$plotH-([double]$Items[$i].HeapAfterMb/$max*$plotH);$time=$Items[$i].Time.ToString('yyyy-MM-dd HH:mm:ss');$points.Add(('{0},{1}' -f $x,$y));$marks.Add(('<circle class="heap-point" cx="{0}" cy="{1}" r="4"><title>{2}: {3} MB</title></circle>' -f $x,$y,$time,$Items[$i].HeapAfterMb))}
    $svg.Add('<polyline class="heap-line" points="'+($points -join ' ')+'"/>');$svg.AddRange([string[]]$marks.ToArray());$labelStep=[math]::Max(1,[math]::Ceiling(($Items.Count-1)/5));$isMultiDay=$Items[0].Time.Date -ne $Items[$Items.Count-1].Time.Date;$seenLabels=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);for($i=0;$i -lt $Items.Count;$i++){if(($i%$labelStep -ne 0)-and($i -ne $Items.Count-1)){continue};$label=if($isMultiDay){$Items[$i].Time.ToString('MM/dd HH:mm')}else{$Items[$i].Time.ToString('HH:mm')};if(-not $seenLabels.Add($label)){continue};$x=$left+$(if($Items.Count -eq 1){$plotW/2}else{$slot*$i});$svg.Add(('<text x="{0}" y="{1}" text-anchor="middle">{2}</text>' -f $x,($top+$plotH+18),(ConvertTo-SafeHtml $label)))};$svg.Add(('<text x="16" y="{0}" transform="rotate(-90 16 {0})" text-anchor="middle">ヒープ使用量（MB）</text><text x="{1}" y="292" text-anchor="middle">時刻（JST）</text>' -f ($top+$plotH/2),($left+$plotW/2)));return '<svg class="chart heap-chart" viewBox="0 0 900 300">{0}</svg>' -f ($svg -join '')
}

function Show-LogAnalyzerGui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = [Windows.Forms.Form]::new()
    $form.Text = 'Apache / JBoss ログ分析'
    $form.Size = [Drawing.Size]::new(980, 760)
    $form.MinimumSize = [Drawing.Size]::new(850, 650)
    $form.StartPosition = 'CenterScreen'
    $form.Font = [Drawing.Font]::new('Segoe UI', 9)
    $layout = [Windows.Forms.TableLayoutPanel]::new()
    $layout.Dock = 'Fill'
    $layout.Padding = [Windows.Forms.Padding]::new(18)
    $layout.ColumnCount = 1
    $layout.RowCount = 6
    foreach ($rowStyle in @([Windows.Forms.RowStyle]::new('AutoSize'), [Windows.Forms.RowStyle]::new('Percent', 50), [Windows.Forms.RowStyle]::new('AutoSize'), [Windows.Forms.RowStyle]::new('AutoSize'), [Windows.Forms.RowStyle]::new('Absolute', 54), [Windows.Forms.RowStyle]::new('Percent', 40))) { $layout.RowStyles.Add($rowStyle) | Out-Null }
    $form.Controls.Add($layout)
    $intro = [Windows.Forms.Label]::new()
    $intro.Text = 'ログ種別ごとに複数ファイルを追加し、まとめて解析します。ファイルは一覧の順に読み込みます。'
    $intro.AutoSize = $true
    $intro.Padding = [Windows.Forms.Padding]::new(0, 0, 0, 12)
    $layout.Controls.Add($intro, 0, 0)
    $inputs = @{}
    $captions = @('Apache アクセスログ', 'JBoss サーバーログ', 'Java GCログ')
    $tabs = [Windows.Forms.TabControl]::new()
    $tabs.Dock = 'Fill'
    $layout.Controls.Add($tabs, 0, 1)
    for ($index = 0; $index -lt 3; $index++) {
        $page = [Windows.Forms.TabPage]::new($captions[$index])
        $tabs.TabPages.Add($page)
        $grid = [Windows.Forms.TableLayoutPanel]::new()
        $grid.Dock = 'Fill'
        $grid.Padding = [Windows.Forms.Padding]::new(10)
        $grid.ColumnCount = 2
        $grid.RowCount = 2
        $grid.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Percent', 100)) | Out-Null
        $grid.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Absolute', 125)) | Out-Null
        $grid.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 100)) | Out-Null
        $grid.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 44)) | Out-Null
        $page.Controls.Add($grid)
        $list = [Windows.Forms.ListBox]::new()
        $list.Dock = 'Fill'
        $list.SelectionMode = 'MultiExtended'
        $list.HorizontalScrollbar = $true
        $list.IntegralHeight = $false
        $grid.Controls.Add($list, 0, 0)
        $inputs[$index] = $list
        $buttons = [Windows.Forms.FlowLayoutPanel]::new()
        $buttons.Dock = 'Fill'
        $buttons.FlowDirection = 'TopDown'
        $buttons.WrapContents = $false
        $grid.Controls.Add($buttons, 1, 0)
        $addButton = [Windows.Forms.Button]::new()
        $addButton.Text = 'ログを追加…'
        $addButton.Width = 105
        $addButton.Tag = $index
        $addButton.Add_Click({ $dialog = [Windows.Forms.OpenFileDialog]::new(); $dialog.Multiselect = $true; $dialog.Title = $captions[[int]$this.Tag] + ' を追加'; if ($dialog.ShowDialog($form) -eq 'OK') { foreach ($file in $dialog.FileNames) { if (-not $inputs[[int]$this.Tag].Items.Contains($file)) { [void]$inputs[[int]$this.Tag].Items.Add($file) } } } }.GetNewClosure())
        $buttons.Controls.Add($addButton)
        $removeButton = [Windows.Forms.Button]::new()
        $removeButton.Text = '選択を削除'
        $removeButton.Width = 105
        $removeButton.Tag = $index
        $removeButton.Add_Click({ $targetList = $inputs[[int]$this.Tag]; foreach ($file in @($targetList.SelectedItems)) { [void]$targetList.Items.Remove($file) } }.GetNewClosure())
        $buttons.Controls.Add($removeButton)
        $clearButton = [Windows.Forms.Button]::new()
        $clearButton.Text = 'すべて削除'
        $clearButton.Width = 105
        $clearButton.Tag = $index
        $clearButton.Add_Click({ $inputs[[int]$this.Tag].Items.Clear() }.GetNewClosure())
        $buttons.Controls.Add($clearButton)
        $hint = [Windows.Forms.Label]::new()
        $hint.Text = 'Ctrl / Shift で複数選択'
        $hint.AutoSize = $true
        $hint.Padding = [Windows.Forms.Padding]::new(4, 8, 0, 0)
        $grid.Controls.Add($hint, 0, 1)
    }
    $destinationRow = [Windows.Forms.FlowLayoutPanel]::new()
    $destinationRow.Dock = 'Fill'
    $destinationRow.WrapContents = $false
    $destinationRow.Padding = [Windows.Forms.Padding]::new(0, 5, 0, 5)
    $rangeRow = [Windows.Forms.FlowLayoutPanel]::new()
    $rangeRow.Dock = 'Fill'
    $rangeRow.WrapContents = $false
    $rangeRow.Padding = [Windows.Forms.Padding]::new(0, 5, 0, 5)
    $layout.Controls.Add($rangeRow, 0, 2)
    $rangeLabel = [Windows.Forms.Label]::new()
    $rangeLabel.Text = '対象期間（JST）'
    $rangeLabel.AutoSize = $true
    $rangeLabel.Padding = [Windows.Forms.Padding]::new(0, 7, 0, 0)
    $rangeRow.Controls.Add($rangeLabel)
    $rangeStart = [Windows.Forms.DateTimePicker]::new()
    $rangeStart.Format = 'Custom'
    $rangeStart.CustomFormat = 'yyyy/MM/dd HH:mm'
    $rangeStart.ShowUpDown = $true
    $rangeStart.Width = 145
    $rangeStart.Value = [datetime]::Today.AddDays(-1)
    $rangeRow.Controls.Add($rangeStart)
    $rangeTo = [Windows.Forms.Label]::new()
    $rangeTo.Text = '〜'
    $rangeTo.AutoSize = $true
    $rangeTo.Padding = [Windows.Forms.Padding]::new(4, 7, 4, 0)
    $rangeRow.Controls.Add($rangeTo)
    $rangeEnd = [Windows.Forms.DateTimePicker]::new()
    $rangeEnd.Format = 'Custom'
    $rangeEnd.CustomFormat = 'yyyy/MM/dd HH:mm'
    $rangeEnd.ShowUpDown = $true
    $rangeEnd.Width = 145
    $rangeEnd.Value = [datetime]::Now
    $rangeRow.Controls.Add($rangeEnd)
    $layout.Controls.Add($destinationRow, 0, 3)
    $destinationLabel = [Windows.Forms.Label]::new()
    $destinationLabel.Text = '出力先'
    $destinationLabel.AutoSize = $true
    $destinationLabel.Padding = [Windows.Forms.Padding]::new(0, 7, 0, 0)
    $destinationRow.Controls.Add($destinationLabel)
    $destinationPath = [Windows.Forms.TextBox]::new()
    $destinationPath.ReadOnly = $true
    $destinationPath.Width = 650
    $destinationPath.Text = [Environment]::GetFolderPath('Desktop')
    $destinationRow.Controls.Add($destinationPath)
    $chooseButton = [Windows.Forms.Button]::new()
    $chooseButton.Text = 'フォルダー選択…'
    $chooseButton.Add_Click({ $dialog = [Windows.Forms.FolderBrowserDialog]::new(); $dialog.SelectedPath = $destinationPath.Text; if ($dialog.ShowDialog($form) -eq 'OK') { $destinationPath.Text = $dialog.SelectedPath } }.GetNewClosure())
    $destinationRow.Controls.Add($chooseButton)
    $output = [Windows.Forms.TextBox]::new()
    $output.Multiline = $true
    $output.ReadOnly = $true
    $output.ScrollBars = 'Vertical'
    $output.Dock = 'Fill'
    $output.BackColor = [Drawing.Color]::White
    $layout.Controls.Add($output, 0, 5)
    $runButton = [Windows.Forms.Button]::new()
    $runButton.Text = '解析してHTML / CSVを出力'
    $runButton.Height = 38
    $runButton.Dock = 'Fill'
    $runButton.BackColor = [Drawing.Color]::FromArgb(32, 105, 155)
    $runButton.ForeColor = [Drawing.Color]::White
    $runButton.FlatStyle = 'Flat'
    $layout.Controls.Add($runButton, 0, 4)
    $runButton.Add_Click({
        try {
            $paths = @{}
            foreach ($index in 0..2) { $paths[$index] = @($inputs[$index].Items | ForEach-Object { [string]$_ }); foreach ($file in $paths[$index]) { if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "ファイルが見つかりません: $file" } } }
            if (($paths.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum -eq 0) { throw '少なくとも1つのログファイルを追加してください。' }
            if (-not (Test-Path -LiteralPath $destinationPath.Text -PathType Container)) { throw '出力先フォルダーが見つかりません。' }
            $startTime = $rangeStart.Value
            $endTime = $rangeEnd.Value
            if ($startTime -gt $endTime) { throw '開始日時は終了日時以前にしてください。' }
            $runButton.Enabled = $false
            $form.Cursor = 'WaitCursor'
            $output.Text = '解析しています…'
            $apacheResult = Read-ApacheAccessLog $paths[0]
            $jbossResult = Read-JBossLog $paths[1]
            $gcResult = Read-GcLog $paths[2]
            $apacheInRange = Select-RecordsInTimeRange $apacheResult.Records $startTime $endTime
            $jbossInRange = Select-RecordsInTimeRange $jbossResult.Records $startTime $endTime
            $gcInRange = Select-RecordsInTimeRange $gcResult.Records $startTime $endTime
            $rangeRequests = $apacheInRange.Records
            $rangeEvents = $jbossInRange.Records
            $rangeGcEvents = $gcInRange.Records
            $summary = Get-AnalysisSummary $rangeRequests $rangeEvents $rangeGcEvents
            $outputFolder = $destinationPath.Text
            $untimedCount = $apacheInRange.UntimedCount + $jbossInRange.UntimedCount + $gcInRange.UntimedCount
            $duplicateCount = $apacheResult.DuplicateCount + $jbossResult.DuplicateCount + $gcResult.DuplicateCount
            Export-AnalysisHtml $summary $rangeRequests $rangeEvents $rangeGcEvents (Join-Path $outputFolder 'apache-jboss-report.html') $startTime $endTime $untimedCount $duplicateCount
            Export-AnalysisCsv $rangeRequests (Join-Path $outputFolder 'requests.csv')
            Export-AnalysisCsv @($rangeEvents | Select-Object Time, Level, Source, Line) (Join-Path $outputFolder 'jboss-events.csv')
            Export-AnalysisCsv @($rangeGcEvents | Select-Object Time, ElapsedSeconds, Kind, Cause, DurationMs, HeapBeforeMb, HeapAfterMb, HeapCapacityMb, Source, Line) (Join-Path $outputFolder 'gc-events.csv')
            $issueCount = $apacheResult.Issues.Count + $jbossResult.Issues.Count + $gcResult.Issues.Count
            $output.Text = "解析完了`r`n対象期間（JST）: $($startTime.ToString('yyyy/MM/dd HH:mm')) 〜 $($endTime.ToString('yyyy/MM/dd HH:mm'))`r`n範囲内リクエスト: $($summary.RequestCount) / HTTPエラー: $($summary.HttpErrors)`r`n範囲内JBoss ERROR/FATAL: $($summary.JBossErrors) / Full GC: $($summary.FullGcCount)`r`n完全一致の重複行を除外: $duplicateCount 行`r`n時刻がなく範囲判定できない行: $untimedCount / 未認識行: $issueCount`r`n`r`n出力先: $outputFolder`r`napache-jboss-report.html`r`nrequests.csv / jboss-events.csv / gc-events.csv"
        } catch { $output.Text = "解析に失敗しました`r`n$($_.Exception.Message)" } finally { $runButton.Enabled = $true; $form.Cursor = 'Default' }
    }.GetNewClosure())
    [void]$form.ShowDialog()
}
if ($MyInvocation.InvocationName -ne '.') { Show-LogAnalyzerGui }
