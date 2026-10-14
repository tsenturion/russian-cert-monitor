[CmdletBinding()]
param(
    [switch]$SelfContained
)

$ErrorActionPreference = 'Stop'
$projectFile = Join-Path $PSScriptRoot 'src\RussianCertMonitor\RussianCertMonitor.csproj'
$outputDirectory = Join-Path $PSScriptRoot 'dist'
$selfContainedValue = if ($SelfContained) { 'true' } else { 'false' }
$arguments = @(
    'publish', $projectFile,
    '-c', 'Release',
    '-r', 'win-x64',
    '--self-contained', $selfContainedValue,
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:PublishTrimmed=false',
    '-o', $outputDirectory
)

Push-Location $PSScriptRoot
try {
    & dotnet.exe @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Сборка завершилась с кодом $LASTEXITCODE."
    }
    $builtExe = Join-Path $outputDirectory 'RussianCertMonitor.exe'
    if (-not (Test-Path -LiteralPath $builtExe -PathType Leaf)) {
        throw 'Сборка не создала ожидаемый RussianCertMonitor.exe.'
    }
    $file = Get-Item -LiteralPath $builtExe
    [pscustomobject]@{
        Путь = $file.FullName
        Размер = $file.Length
        Версия = $file.VersionInfo.FileVersion
        АвтономнаяСборка = [bool]$SelfContained
    }
}
finally {
    Pop-Location
}
