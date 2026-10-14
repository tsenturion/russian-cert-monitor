[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $PSScriptRoot 'work\release-checks' }
$verificationRoot = [IO.Path]::GetFullPath($OutputDirectory)
$logDirectory = Join-Path $verificationRoot 'Logs'
[void][IO.Directory]::CreateDirectory($logDirectory)
$utf8 = [Text.UTF8Encoding]::new($false)
$cutoff = (Get-Date).ToUniversalTime().Date.AddDays(-29)
Get-ChildItem -LiteralPath $logDirectory -Filter 'ReleaseVerification-*.jsonl' -File | ForEach-Object {
    if ($_.Name -match '^ReleaseVerification-(\d{4}-\d{2}-\d{2})-\d+\.jsonl$') {
        $date = [DateTime]::ParseExact($Matches[1], 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        if ($date -le $cutoff) { Remove-Item -LiteralPath $_.FullName }
    }
}
function Write-VerificationEvent([string]$name, [string]$message) {
    $now = [DateTimeOffset]::UtcNow
    $path = Join-Path $logDirectory ('ReleaseVerification-{0}-{1}.jsonl' -f $now.ToString('yyyy-MM-dd'), $PID)
    $record = [ordered]@{ timestamp=$now.ToString('o'); eventName=$name; message=$message }
    [IO.File]::AppendAllText($path, ($record | ConvertTo-Json -Compress) + [Environment]::NewLine, $utf8)
}
function Read-PowerShellInventory {
    $storeNames = [Collections.Generic.List[string]]::new()
    $observations = [Collections.Generic.List[string]]::new()
    $issues = [Collections.Generic.List[string]]::new()
    foreach ($scope in @('CurrentUser', 'LocalMachine')) {
        try { $stores = @(Get-ChildItem -LiteralPath ('Cert:\' + $scope)) }
        catch { $issues.Add($scope + ': ' + $_.Exception.Message); continue }
        foreach ($entry in $stores) {
            $storePath = $scope + '\' + $entry.Name
            $store = [Security.Cryptography.X509Certificates.X509Store]::new($entry.Name, [Security.Cryptography.X509Certificates.StoreLocation]::$scope)
            $certificates = $null
            try {
                $flags = [Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::IncludeArchived
                $store.Open($flags)
                $storeNames.Add($storePath)
                $certificates = $store.Certificates
                foreach ($certificate in $certificates) { $observations.Add($certificate.Thumbprint.ToUpperInvariant() + '|' + $storePath) }
            }
            catch { $issues.Add($storePath + ': ' + $_.Exception.Message) }
            finally {
                if ($null -ne $certificates) { foreach ($certificate in $certificates) { $certificate.Dispose() } }
                $store.Dispose()
            }
        }
    }
    return [pscustomobject]@{ Stores=@($storeNames.ToArray() | Sort-Object); Observations=@($observations.ToArray() | Sort-Object); Issues=$issues.ToArray() }
}

$started = [DateTimeOffset]::UtcNow
$status = 'failed'
$failure = $null
$inventoryResult = $null
$version = ([xml][IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Directory.Build.props'))).Project.PropertyGroup.Version
Push-Location $PSScriptRoot
try {
    Write-VerificationEvent 'verification.started' "Целевые проверки выпуска $version."
    $testProject = Join-Path $PSScriptRoot 'tests\RussianCertMonitor.Tests\RussianCertMonitor.Tests.csproj'
    $testDll = Join-Path $PSScriptRoot 'tests\RussianCertMonitor.Tests\bin\Release\net10.0-windows\RussianCertMonitor.Tests.dll'
    if (-not $SkipBuild) {
        & dotnet build $testProject -c Release --no-restore -v:q
        if ($LASTEXITCODE -ne 0) { throw 'Сборка целевых проверок не пройдена. Для первого запуска подготовьте зависимости командой dotnet restore.' }
    }
    if (-not (Test-Path -LiteralPath $testDll -PathType Leaf)) { throw 'Не найден собранный проект целевых проверок.' }
    & dotnet $testDll --stage6 --output-directory $verificationRoot
    if ($LASTEXITCODE -ne 0) { throw 'Интеграционные проверки этапа 6 не пройдены; подробности в stage6-results.json.' }
    Write-VerificationEvent 'verification.integration-passed' 'Метаданные ГОСТ, ошибки импорта, неполный снимок и изолированный CurrentUser Disallowed проверены.'

    $appJson = (& dotnet $testDll --inventory) -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 0) { throw 'Живое чтение инвентаря приложения не завершено.' }
    $app = $appJson | ConvertFrom-Json
    if (-not $app.IsComplete) { throw 'Живой снимок приложения неполон. Отсутствие сертификатов в недоступных хранилищах не подтверждено.' }
    $independent = Read-PowerShellInventory
    if ($independent.Issues.Count -gt 0) { throw ('PowerShell не прочитал все хранилища: ' + ($independent.Issues -join '; ')) }
    $appObservations = @($app.Certificates | ForEach-Object {
        $id = $_.CertificateId.ToUpperInvariant()
        foreach ($location in $_.Locations) { $id + '|' + $location }
    } | Sort-Object)
    $differentStores = @()
    if (@($app.Stores).Count -gt 0 -and $independent.Stores.Count -gt 0) {
        $differentStores = @(Compare-Object -ReferenceObject @($app.Stores | Sort-Object) -DifferenceObject $independent.Stores)
    } elseif (@($app.Stores).Count -ne $independent.Stores.Count) { $differentStores = @('Количество хранилищ отличается.') }
    $differentCertificates = @()
    if ($appObservations.Count -gt 0 -and $independent.Observations.Count -gt 0) {
        $differentCertificates = @(Compare-Object -ReferenceObject $appObservations -DifferenceObject $independent.Observations)
    } elseif ($appObservations.Count -ne $independent.Observations.Count) { $differentCertificates = @('Количество наблюдений отличается.') }
    [IO.File]::WriteAllText((Join-Path $verificationRoot 'application-inventory.json'), $appJson, $utf8)
    [IO.File]::WriteAllText((Join-Path $verificationRoot 'powershell-inventory.json'), ($independent | ConvertTo-Json -Depth 5), $utf8)
    if ($differentStores.Count -gt 0 -or $differentCertificates.Count -gt 0) {
        throw "Инвентари различаются: хранилищ $($differentStores.Count), расположений сертификатов $($differentCertificates.Count). Состояние могло измениться между чтениями; снимки сохранены для сравнения."
    }
    $inventoryResult = [ordered]@{ matched=$true; stores=@($app.Stores).Count; observations=$app.ObservationCount; unique=$app.UniqueCount; russian=$app.RussianCount; issues=@($app.Issues).Count }
    Write-VerificationEvent 'verification.inventory-matched' "Инвентарь PowerShell совпал: хранилищ $($inventoryResult.stores), уникальных $($inventoryResult.unique)."
    $status = 'passed'
}
catch {
    $failure = $_.Exception.ToString()
    Write-VerificationEvent 'verification.failed' $failure
    throw
}
finally {
    Pop-Location
    $report = [ordered]@{ startedAt=$started.ToString('o'); completedAt=[DateTimeOffset]::UtcNow.ToString('o'); version=$version; status=$status; inventory=$inventoryResult; failure=$failure }
    [IO.File]::WriteAllText((Join-Path $verificationRoot 'release-verification.json'), ($report | ConvertTo-Json -Depth 7), $utf8)
}
Write-Host "Целевые проверки выпуска пройдены. Результаты: $verificationRoot"
