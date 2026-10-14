[CmdletBinding()]
param([string]$OutputDirectory, [switch]$VerifyOffline)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $PSScriptRoot 'work\release-checks'
}
$report = [ordered]@{ status = 'failed'; timestampUtc = [DateTime]::UtcNow.ToString('o'); exitCode = $null; output = ''; details = ''; offline = 'not-tested'; firewallRuleRemoved = $null }
$firewallRule = $null
try {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $report.status = 'admin-required'
        throw 'Откройте PowerShell от имени администратора и повторите запуск этого скрипта.'
    }
    $testDll = Join-Path $PSScriptRoot 'tests\RussianCertMonitor.Tests\bin\Release\net10.0-windows\RussianCertMonitor.Tests.dll'
    if (-not (Test-Path -LiteralPath $testDll -PathType Leaf)) {
        throw 'Тестовая DLL отсутствует. Сначала выполните verify_release.ps1 для сборки, затем повторите эту проверку.'
    }
    $lines = @(& dotnet $testDll --live-disallowed-machine 2>&1 | ForEach-Object { $_.ToString() })
    $report.exitCode = $LASTEXITCODE
    $report.output = $lines -join [Environment]::NewLine
    if ($report.exitCode -ne 0) { throw 'Проверка LocalMachine Disallowed не пройдена.' }
    if ($VerifyOffline) {
        if (@(Get-NetFirewallProfile | Where-Object { $_.Enabled -ne 'True' }).Count -gt 0) {
            throw 'Один из профилей брандмауэра отключён; блокировка сети приложения не может считаться подтверждённой.'
        }
        $startupExe = Join-Path ([Environment]::GetFolderPath('Startup')) 'RussianCertMonitor.exe'
        $installed = @(Get-CimInstance Win32_Process -Filter "Name = 'RussianCertMonitor.exe'" | Where-Object { $_.ExecutablePath -eq $startupExe })
        if ($installed.Count -ne 1) { throw 'Для проверки без сети нужен один запущенный экземпляр из Startup.' }
        $processId = $installed[0].ProcessId
        $logDirectory = Join-Path $env:LOCALAPPDATA 'RussianCertMonitor\Logs'
        function Read-ScanEvents {
            @(Get-ChildItem -LiteralPath $logDirectory -Filter ('RussianCertMonitor-*-{0}.jsonl' -f $processId) -File | ForEach-Object {
                Get-Content -LiteralPath $_.FullName -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json }
            } | Where-Object eventName -eq 'inventory.completed')
        }
        $before = @(Read-ScanEvents).Count
        $settingsPath = Join-Path $env:LOCALAPPDATA 'RussianCertMonitor\settings.json'
        $interval = [int](Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json).pollIntervalSeconds
        if ($interval -lt 5 -or $interval -gt 30) { throw 'Для ограниченной по времени проверки без сети нужен интервал 5–30 секунд.' }
        $firewallRule = 'RCM-OfflineVerification-' + [Guid]::NewGuid().ToString('N')
        [void](New-NetFirewallRule -Name $firewallRule -DisplayName 'RussianCertMonitor: временная проверка без сети' -Program $startupExe -Direction Outbound -Action Block -Profile Any)
        $deadline = [DateTime]::UtcNow.AddSeconds($interval + 10)
        do {
            Start-Sleep -Milliseconds 250
            $scans = @(Read-ScanEvents)
        } while ($scans.Count -le $before -and [DateTime]::UtcNow -lt $deadline)
        if ($scans.Count -le $before -or $scans[-1].message -notlike '*полнота: полная*') {
            throw 'После блокировки исходящей сети приложения полная проверка не подтверждена.'
        }
        $report.offline = 'verified'
    }
    $report.status = 'succeeded'
    $report.details = 'Изолированная проверка завершена; Root и CA не изменялись.'
    Write-Host $report.details
}
catch {
    $report.details = $_.Exception.Message
    Write-Error $report.details -ErrorAction Continue
}
finally {
    if ($null -ne $firewallRule) {
        try {
            Remove-NetFirewallRule -Name $firewallRule -ErrorAction Stop
            $report.firewallRuleRemoved = $true
        }
        catch {
            $report.status = 'failed'
            $report.firewallRuleRemoved = $false
            $report.details += ' Не удалось удалить собственное временное правило: ' + $_.Exception.Message
        }
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        $json = $report | ConvertTo-Json -Depth 5
        [IO.File]::WriteAllText((Join-Path $OutputDirectory 'machine-verification.json'), $json, (New-Object System.Text.UTF8Encoding($true)))
    }
}
if ($report.status -ne 'succeeded') { exit 1 }
