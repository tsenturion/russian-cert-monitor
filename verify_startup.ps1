[CmdletBinding()]
param([string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $PSScriptRoot 'work\release-checks'
}
$startupExe = Join-Path ([Environment]::GetFolderPath('Startup')) 'RussianCertMonitor.exe'
$distExe = Join-Path $PSScriptRoot 'dist\RussianCertMonitor.exe'
$dataDirectory = Join-Path $env:LOCALAPPDATA 'RussianCertMonitor'
$statePath = Join-Path $dataDirectory 'monitor-state.json'
$settingsPath = Join-Path $dataDirectory 'settings.json'
$historyDirectory = Join-Path $dataDirectory 'History'
$logDirectory = Join-Path $dataDirectory 'Logs'
$report = [ordered]@{
    status = 'failed'; timestampUtc = [DateTime]::UtcNow.ToString('o')
    startupExe = $startupExe; processId = $null; details = @()
    stateRestored = 'not-tested'; periodic = 'not-tested'
    invalidArgumentsExitCode = $null; helperExitCode = $null
}
$primary = $null
$stoppedPrevious = $false
$utf8Bom = New-Object System.Text.UTF8Encoding($true)
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Write-VerificationEvent([string]$name, [string]$message) {
    $now = [DateTime]::UtcNow
    $path = Join-Path $OutputDirectory ('VerificationStartup-{0}-{1}.jsonl' -f $now.ToString('yyyy-MM-dd'), $PID)
    $line = [ordered]@{ timestampUtc = $now.ToString('o'); processId = $PID; eventName = $name; message = $message } |
        ConvertTo-Json -Compress -Depth 4
    [IO.File]::AppendAllText($path, $line + [Environment]::NewLine, $utf8)
}
function Get-StartupProcesses {
    @(Get-CimInstance Win32_Process -Filter "Name = 'RussianCertMonitor.exe'" |
        Where-Object { $_.ExecutablePath -eq $startupExe })
}
function Get-AppEvents([int]$processId) {
    $files = @(Get-ChildItem -LiteralPath $logDirectory -Filter ('RussianCertMonitor-*-{0}.jsonl' -f $processId) -File -ErrorAction SilentlyContinue)
    $events = @()
    foreach ($file in $files) {
        foreach ($line in (Get-Content -LiteralPath $file.FullName -Encoding UTF8 -ErrorAction SilentlyContinue)) {
            try { $events += ($line | ConvertFrom-Json -ErrorAction Stop) } catch { }
        }
    }
    @($events | Sort-Object timestamp)
}
function Wait-Until([scriptblock]$condition, [int]$seconds, [string]$message) {
    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
    do {
        if (& $condition) { return }
        Start-Sleep -Milliseconds 150
    } while ([DateTime]::UtcNow -lt $deadline)
    throw $message
}
function Get-StateInventory {
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { return $null }
    $document = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $document.snapshot) { return $null }
    $certificates = @($document.snapshot.certificates | ForEach-Object {
        [pscustomobject]@{
            id = $_.metadata.certificateId
            locations = @($_.locations | ForEach-Object { '{0}\{1}' -f $_.location, $_.name } | Sort-Object)
        }
    } | Sort-Object id)
    return (ConvertTo-Json -InputObject $certificates -Depth 5 -Compress)
}
function Get-StateContents {
    $document = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -ne $document.snapshot) {
        $document.snapshot.PSObject.Properties.Remove('scannedAt')
    }
    $document.PSObject.Properties.Remove('savedAt')
    return (ConvertTo-Json -InputObject $document -Depth 30 -Compress)
}
function Get-ProtectedFiles {
    $paths = @($settingsPath, $statePath)
    if (Test-Path -LiteralPath $historyDirectory -PathType Container) {
        $paths += @(Get-ChildItem -LiteralPath $historyDirectory -File | ForEach-Object FullName)
    }
    $result = @{}
    foreach ($path in $paths) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $item = Get-Item -LiteralPath $path
            $result[$item.FullName] = '{0}|{1}' -f $item.Length, $item.LastWriteTimeUtc.Ticks
        }
    }
    return $result
}
function Assert-ProtectedFiles($before, $after, [string]$context) {
    if (($before | ConvertTo-Json -Compress) -ne ($after | ConvertTo-Json -Compress)) {
        $keys = @($before.Keys + $after.Keys | Sort-Object -Unique)
        foreach ($key in $keys) {
            if ($before[$key] -ne $after[$key]) { throw "$context изменил пользовательский файл: $key" }
        }
    }
}
function Open-InstalledWindow {
    $secondary = Start-Process -FilePath $startupExe -WorkingDirectory (Split-Path -Parent $startupExe) -WindowStyle Hidden -PassThru
    if (-not $secondary.WaitForExit(5000) -or $secondary.ExitCode -ne 0) {
        throw 'Второй запуск не завершился с кодом 0.'
    }
    Wait-Until { $primary.Refresh(); $primary.MainWindowHandle -ne [IntPtr]::Zero } 5 'Главное окно не открылось.'
}
function Close-InstalledWindow {
    if (-not $primary.CloseMainWindow()) { throw 'Главное окно не приняло закрытие.' }
    Wait-Until { $primary.Refresh(); -not $primary.HasExited -and $primary.MainWindowHandle -eq [IntPtr]::Zero } 5 'Окно не вернулось в трей.'
}

try {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $cutoff = [DateTime]::UtcNow.Date.AddDays(-29)
    foreach ($file in @(Get-ChildItem -LiteralPath $OutputDirectory -Filter 'VerificationStartup-*.jsonl' -File)) {
        if ($file.Name -match '^VerificationStartup-(\d{4}-\d{2}-\d{2})-(\d+)\.jsonl$') {
            $date = [DateTime]::MinValue
            if ([DateTime]::TryParseExact($Matches[1], 'yyyy-MM-dd',
                    [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$date) -and
                $date -le $cutoff) { Remove-Item -LiteralPath $file.FullName }
        }
    }
    Write-VerificationEvent 'verification.started' 'Начата проверка установленного приложения.'
    $installed = Get-Item -LiteralPath $startupExe -ErrorAction Stop
    $built = Get-Item -LiteralPath $distExe -ErrorAction Stop
    if ($installed.PSIsContainer -or $built.PSIsContainer -or
        $installed.Length -ne $built.Length -or
        $installed.VersionInfo.FileVersion -ne $built.VersionInfo.FileVersion) {
        throw 'Установленный EXE не соответствует сборке dist по размеру и версии.'
    }
    $previous = @(Get-StartupProcesses)
    if ($previous.Count -gt 1) { throw 'Найдено несколько экземпляров установленного EXE.' }
    $priorState = Get-StateInventory
    $hadPriorSnapshot = $null -ne $priorState
    if ($previous.Count -eq 1) {
        Stop-Process -Id $previous[0].ProcessId -Force
        Wait-Until { @(Get-StartupProcesses).Count -eq 0 } 5 'Установленный экземпляр не завершился.'
        $stoppedPrevious = $true
        Write-VerificationEvent 'verification.previous-stopped' "Остановлен установленный процесс $($previous[0].ProcessId)."
    }
    $primary = Start-Process -FilePath $startupExe -WorkingDirectory (Split-Path -Parent $startupExe) -WindowStyle Hidden -PassThru
    $report.processId = $primary.Id
    Write-VerificationEvent 'verification.primary-started' "Запущен установленный процесс $($primary.Id)."
    Wait-Until {
        $events = @(Get-AppEvents $primary.Id)
        @($events | Where-Object eventName -eq 'application.started').Count -ge 1 -and
        @($events | Where-Object eventName -eq 'tray.ready').Count -ge 1 -and
        @($events | Where-Object eventName -eq 'inventory.completed').Count -ge 1
    } 15 'Не найдены application.started, tray.ready и inventory.completed.'
    $events = @(Get-AppEvents $primary.Id)
    $startedMessage = @($events | Where-Object eventName -eq 'application.started')[0].message
    if (-not $startedMessage.Contains($startupExe) -or
        -not $startedMessage.Contains(('Запуск {0};' -f $installed.VersionInfo.ProductVersion))) {
        throw 'Журнал запуска указывает другой путь или версию EXE.'
    }
    $loaded = @($events | Where-Object eventName -eq 'monitor.state-loaded' | Select-Object -First 1)
    if ($hadPriorSnapshot) {
        if ($loaded.Count -ne 1 -or $loaded[0].message -notlike '*снимок: имеется*') {
            throw 'Предыдущий снимок не восстановлен.'
        }
        $report.stateRestored = 'verified'
    } else {
        $report.stateRestored = 'not-applicable'
        $report.details += 'До перезапуска сохранённого снимка не было.'
    }
    Wait-Until { Test-Path -LiteralPath $statePath -PathType Leaf } 5 'Файл состояния после первой проверки не создан.'
    Wait-Until { @((Get-AppEvents $primary.Id) | Where-Object eventName -eq 'monitor.state-saved').Count -ge 1 } 5 'Первый снимок не сохранён.'
    $events = @(Get-AppEvents $primary.Id)
    $initialInventory = Get-StateInventory
    Open-InstalledWindow
    Close-InstalledWindow
    Open-InstalledWindow
    Close-InstalledWindow
    if (@(Get-StartupProcesses).Count -ne 1) { throw 'После открытия окна число установленных процессов не равно одному.' }
    $events = @(Get-AppEvents $primary.Id)
    $initialNotifications = @($events | Where-Object eventName -eq 'monitor.notification-requested').Count
    Write-VerificationEvent 'verification.window-checked' 'Повторное открытие и закрытие окна проверено.'
    $settings = if (Test-Path -LiteralPath $settingsPath -PathType Leaf) {
        Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } else { [pscustomobject]@{ pollIntervalSeconds = 10 } }
    $interval = [int]$settings.pollIntervalSeconds
    if ($interval -lt 5 -or $interval -gt 3600) { throw 'Недопустимый интервал мониторинга в настройках.' }
    $events = @(Get-AppEvents $primary.Id)
    $scanCount = @($events | Where-Object eventName -eq 'inventory.completed').Count
    $stateWriteTime = (Get-Item -LiteralPath $statePath).LastWriteTimeUtc
    $stateContents = Get-StateContents
    if ($interval -gt 30) {
        $report.periodic = 'not-tested'
        $report.details += 'Интервал больше 30 секунд; две автоматические проверки не ожидались.'
    } else {
        Wait-Until {
            $events = @(Get-AppEvents $primary.Id)
            @($events | Where-Object eventName -eq 'inventory.completed').Count -ge ($scanCount + 2)
        } 25 'За 25 секунд не завершились две периодические проверки.'
        $events = @(Get-AppEvents $primary.Id)
        $report.periodic = 'verified'
        $laterInventory = Get-StateInventory
        if ($stateContents -eq (Get-StateContents) -and
            (Get-Item -LiteralPath $statePath).LastWriteTimeUtc -ne $stateWriteTime) {
            throw 'При неизменном содержимом файл состояния был переписан.'
        }
        if ($initialInventory -eq $laterInventory) {
            $laterNotifications = @($events | Where-Object eventName -eq 'monitor.notification-requested').Count
            if ($laterNotifications -gt $initialNotifications) { throw 'При неизменном снимке повторилось уведомление.' }
        } else { $report.details += 'Состав сертификатов изменился; подавление повторного уведомления не оценивалось.' }
        Write-VerificationEvent 'verification.periodic-checked' 'Проверены две периодические проверки.'
    }
    $events = @(Get-AppEvents $primary.Id)
    $errors = @($events | Where-Object { $_.eventName -match 'error|failed' })
    if ($errors.Count -gt 0) { throw "Новые ошибки приложения: $($errors.eventName -join ', ')." }
    $beforeGuard = Get-ProtectedFiles
    $invalid = Start-Process -FilePath $startupExe -ArgumentList '--invalid-verification-argument' -WorkingDirectory (Split-Path -Parent $startupExe) -WindowStyle Hidden -PassThru -Wait
    $report.invalidArgumentsExitCode = $invalid.ExitCode
    if ($invalid.ExitCode -ne 2) { throw 'Некорректный аргумент не завершился кодом 2.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $helper = Start-Process -FilePath $startupExe -ArgumentList @('--disallowed-helper', [Guid]::NewGuid().ToString('N'), $PID) -WorkingDirectory (Split-Path -Parent $startupExe) -WindowStyle Hidden -PassThru -Wait
        $report.helperExitCode = $helper.ExitCode
        if ($helper.ExitCode -ne 3) { throw 'Непривилегированный helper не завершился кодом 3.' }
    } else { $report.details += 'Проверка helper с корректными аргументами пропущена в сеансе администратора.' }
    Assert-ProtectedFiles $beforeGuard (Get-ProtectedFiles) 'Проверка аргументов'
    $primary.Refresh()
    if ($primary.HasExited -or $primary.MainWindowHandle -ne [IntPtr]::Zero) {
        throw 'Проверка аргументов затронула главное окно или завершила основной процесс.'
    }
    if (@(Get-StartupProcesses).Count -ne 1) { throw 'После проверки аргументов изменилось число установленных процессов.' }
    $report.status = 'succeeded'
    Write-VerificationEvent 'verification.succeeded' 'Проверка установленного приложения завершена.'
}
catch {
    $report.details += $_.Exception.Message
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        Write-VerificationEvent 'verification.failed' $_.Exception.Message
    }
    Write-Error $_.Exception.Message -ErrorAction Continue
}
finally {
    if ($stoppedPrevious -and @(Get-StartupProcesses).Count -eq 0) {
        try {
            $primary = Start-Process -FilePath $startupExe -WorkingDirectory (Split-Path -Parent $startupExe) -WindowStyle Hidden -PassThru
            $report.details += "Установленный экземпляр восстановлен: $($primary.Id)."
            Write-VerificationEvent 'verification.primary-restored' "Восстановлен процесс $($primary.Id)."
        } catch { $report.details += "Не удалось восстановить установленный экземпляр: $($_.Exception.Message)" }
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        [IO.File]::WriteAllText((Join-Path $OutputDirectory 'startup-verification.json'),
            ($report | ConvertTo-Json -Depth 7), $utf8Bom)
    }
}
if ($report.status -ne 'succeeded') { exit 1 }
