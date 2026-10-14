[CmdletBinding()]
param([switch]$SkipVerification)

$ErrorActionPreference = 'Stop'
$checksDirectory = Join-Path $PSScriptRoot 'work\release-checks'
if (-not $SkipVerification) {
    & (Join-Path $PSScriptRoot 'verify_release.ps1') -OutputDirectory $checksDirectory
}
$version = ([xml][IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Directory.Build.props'))).Project.PropertyGroup.Version
$checkReportPath = Join-Path $checksDirectory 'release-verification.json'
if (-not (Test-Path -LiteralPath $checkReportPath -PathType Leaf)) { throw 'Сначала выполните verify_release.ps1.' }
$checkReport = Get-Content -LiteralPath $checkReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($checkReport.status -ne 'passed' -or $checkReport.version -ne $version) { throw 'Нет успешных целевых проверок для текущей версии.' }
& (Join-Path $PSScriptRoot 'build_exe.ps1')
$exePath = Join-Path $PSScriptRoot 'dist\RussianCertMonitor.exe'
$file = Get-Item -LiteralPath $exePath
if ($file.VersionInfo.FileVersion -ne "$version.0") { throw 'Версия собранного EXE не соответствует проекту.' }
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archivePath = Join-Path $PSScriptRoot "dist\RussianCertMonitor-$version-win-x64.zip"
$temporary = Join-Path $PSScriptRoot ('dist\.package-' + [Guid]::NewGuid().ToString('N') + '.tmp')
$stream = $null
$archive = $null
try {
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
    $files = [ordered]@{
        'dist/RussianCertMonitor.exe'=$exePath
        'install_startup.ps1'=(Join-Path $PSScriptRoot 'install_startup.ps1')
        'Дистрибутив.md'=(Join-Path $PSScriptRoot 'Дистрибутив.md')
    }
    foreach ($entry in $files.GetEnumerator()) {
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $entry.Value, $entry.Key, [IO.Compression.CompressionLevel]::Optimal)
    }
    $archive.Dispose(); $archive=$null
    $stream.Flush($true)
    $stream.Dispose(); $stream=$null
    $opened = [IO.Compression.ZipFile]::OpenRead($temporary)
    try {
        $contents = @($opened.Entries | Select-Object -ExpandProperty FullName)
        if ($opened.Entries.Count -ne 3 -or @(Compare-Object @($files.Keys) $contents).Count -gt 0 -or
            $opened.GetEntry('dist/RussianCertMonitor.exe').Length -ne $file.Length) {
            throw 'Содержимое дистрибутива не соответствует ожидаемым файлам.'
        }
    }
    finally { $opened.Dispose() }
    if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath }
    [IO.File]::Move($temporary, $archivePath)
    $report = [ordered]@{ createdAt=[DateTimeOffset]::UtcNow.ToString('o'); version=$version; runtime='Microsoft.WindowsDesktop.App 10 x64'; selfContained=$false; singleFile=$true; executable=$exePath; executableSize=$file.Length; archive=$archivePath; entries=$contents; hashesCalculated=$false }
    [IO.File]::WriteAllText((Join-Path $checksDirectory 'package-verification.json'), ($report | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    Write-Host "Дистрибутив готов: $archivePath"
}
finally {
    if ($null -ne $archive) { $archive.Dispose() }
    if ($null -ne $stream) { $stream.Dispose() }
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
}
