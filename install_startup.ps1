[CmdletBinding()]
param(
    [string]$SourceExe
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($SourceExe)) { $SourceExe = Join-Path $PSScriptRoot 'dist\RussianCertMonitor.exe' }
$sourceFile = Get-Item -LiteralPath $SourceExe
if ($sourceFile.PSIsContainer -or $sourceFile.Name -ne 'RussianCertMonitor.exe') {
    throw 'Источник должен быть файлом RussianCertMonitor.exe.'
}

$startupDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)
if ([string]::IsNullOrWhiteSpace($startupDirectory)) {
    throw 'Не удалось определить папку автозагрузки текущего пользователя.'
}
New-Item -ItemType Directory -Path $startupDirectory -Force | Out-Null
$startupExe = Join-Path $startupDirectory 'RussianCertMonitor.exe'
if ($sourceFile.FullName -eq $startupExe) {
    throw 'В качестве источника выбрана уже установленная копия.'
}

$installedProcesses = Get-CimInstance Win32_Process -Filter "Name = 'RussianCertMonitor.exe'" |
    Where-Object { $_.ExecutablePath -eq $startupExe }
foreach ($installedProcess in $installedProcesses) {
    $process = Get-Process -Id $installedProcess.ProcessId -ErrorAction SilentlyContinue
    if ($process) {
        Stop-Process -Id $process.Id -Force
        if (-not $process.WaitForExit(5000)) {
            throw 'Установленный экземпляр не завершился за отведённое время.'
        }
    }
}

Copy-Item -LiteralPath $sourceFile.FullName -Destination $startupExe -Force
$installedFile = Get-Item -LiteralPath $startupExe
if ($installedFile.Length -ne $sourceFile.Length -or
    $installedFile.VersionInfo.FileVersion -ne $sourceFile.VersionInfo.FileVersion) {
    throw 'Размер или версия установленного EXE не соответствует результату сборки.'
}

Start-Process -FilePath $startupExe -WorkingDirectory $startupDirectory -WindowStyle Hidden
$deadline = [DateTime]::UtcNow.AddSeconds(10)
do {
    Start-Sleep -Milliseconds 250
    $running = @(Get-CimInstance Win32_Process -Filter "Name = 'RussianCertMonitor.exe'" |
        Where-Object { $_.ExecutablePath -eq $startupExe })
} while ($running.Count -eq 0 -and [DateTime]::UtcNow -lt $deadline)

if ($running.Count -eq 0) {
    throw 'Экземпляр из папки Startup не запущен. Проверьте журнал приложения или другой открытый экземпляр.'
}

[pscustomobject]@{
    УстановленныйФайл = $startupExe
    Версия = $installedFile.VersionInfo.FileVersion
    Размер = $installedFile.Length
    Процессы = ($running.ProcessId -join ', ')
}
