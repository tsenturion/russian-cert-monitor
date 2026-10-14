using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using RussianCertMonitor.Catalog;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.Classification;
using RussianCertMonitor.Disallowed;
using RussianCertMonitor.History;
using RussianCertMonitor.Infrastructure;
using RussianCertMonitor.Inventory;
using RussianCertMonitor.Monitoring;
using RussianCertMonitor.Settings;

namespace RussianCertMonitor.Tests;

internal static class Stage6Checks
{
    public static void Run(string outputDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        string directory = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(directory);
        List<object> checks = [];
        string? fixtureId = null;
        string? failure = null;
        try
        {
            VerifyGostMetadata(checks);
            VerifyInvalidImports(directory, checks);
            VerifyIncompleteSnapshot(checks);
            fixtureId = VerifyCurrentUserRoundtrip(directory, checks);
        }
        catch (Exception error)
        {
            failure = error.ToString();
            throw;
        }
        finally
        {
            File.WriteAllText(Path.Combine(directory, "stage6-results.json"), JsonSerializer.Serialize(new
            {
                completedAt = DateTimeOffset.UtcNow,
                status = failure is null ? "passed" : "failed",
                fixtureId,
                checks,
                failure
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    private static void VerifyGostMetadata(List<object> checks)
    {
        (byte[] der, byte[] name) = GostDerFixture.Create();
        PublicCertificateData data = PublicCertificateData.FromDer(der);
        CertificateMetadata metadata = data.Metadata;
        Require(metadata.CertificateId.Length == 40 && metadata.CertificateId.All(Uri.IsHexDigit)
            && metadata.SubjectNameRaw.SequenceEqual(name) && metadata.IssuerNameRaw.SequenceEqual(name)
            && metadata.Subject.Contains("RU", StringComparison.OrdinalIgnoreCase)
            && metadata.Issuer.Contains("RU", StringComparison.OrdinalIgnoreCase)
            && metadata.SerialNumber == "01" && metadata.NotBefore is not null
            && metadata.NotAfter is not null && metadata.NotAfter > metadata.NotBefore
            && metadata.RawData.SequenceEqual(der), "Метаданные синтетического ГОСТ DER не прочитаны.");
        CertificateClassification classification = new RussianCertificateClassifier(CertificateCatalog.Load())
            .Classify(metadata.CertificateId, metadata.SubjectNameRaw, metadata.IssuerNameRaw);
        Require(classification.IsRussian && classification.Errors.Count == 0,
            "DER имени RU должен давать российскую классификацию.");
        checks.Add(new { name = "gostMetadata", status = "passed", metadataOnly = true,
            synthetic = true, certificateId = metadata.CertificateId, classificationRussian = true });
    }

    private static void VerifyInvalidImports(string directory, List<object> checks)
    {
        string garbagePath = Path.Combine(directory, "stage6-invalid.cer");
        string pfxPath = Path.Combine(directory, "stage6-pfx-like.pfx");
        File.WriteAllBytes(garbagePath, [1, 2, 3, 4]);
        File.WriteAllBytes(pfxPath,
            [0x30, 0x18, 0x02, 0x01, 0x03, 0x30, 0x13, 0x06, 0x09, 0x2A, 0x86, 0x48,
                0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0xA0, 0x06, 0x04, 0x04, 0x30, 0x02,
                0x30, 0x00]);
        Require(RejectsPublicImport(garbagePath) && RejectsPublicImport(pfxPath),
            "Некорректный публичный файл должен отклоняться до записи в хранилище.");
        checks.Add(new { name = "invalidPublicImport", status = "passed", storeWrites = 0 });
    }

    private static bool RejectsPublicImport(string path)
    {
        try { _ = PublicCertificateData.FromFile(path); }
        catch (Exception error) when (error is CryptographicException or ArgumentException)
        { return true; }
        return false;
    }

    private static void VerifyIncompleteSnapshot(List<object> checks)
    {
        RussianCertificateClassifier classifier = new(CertificateCatalog.Load());
        CertificateInventorySnapshot empty = new CertificateInventoryService(new EmptyProvider(), classifier).Scan();
        CertificateInventorySnapshot unavailable = new CertificateInventoryService(new UnavailableProvider(), classifier).Scan();
        Require(empty.IsComplete && empty.Certificates.Count == 0 && empty.Issues.Count == 0
            && !unavailable.IsComplete && unavailable.Certificates.Count == 0 && unavailable.Issues.Count > 0,
            "Недоступное хранилище нельзя считать полным пустым снимком.");
        checks.Add(new { name = "incompleteSnapshot", status = "passed", issues = unavailable.Issues.Count });
    }

    private static string VerifyCurrentUserRoundtrip(string directory, List<object> checks)
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new($"CN=RCM-Verification-{Guid.NewGuid():N}, C=US", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        PublicCertificateData data = PublicCertificateData.FromDer(certificate.Export(X509ContentType.Cert));
        string id = data.Metadata.CertificateId;
        WindowsDisallowedStoreBackend backend = new();
        Require(!backend.Contains(StoreLocation.CurrentUser, id), "Тестовый сертификат уже находится в Disallowed.");
        Require(!InRootOrCa(id), "Тестовый сертификат уже находится в Root или CA.");

        DiagnosticLog log = new(Path.Combine(directory, "diagnostics"));
        HistoryStore history = new(Path.Combine(directory, "history"));
        history.Prune();
        log.AttachHistory(history);
        DisallowedManager manager = new(backend, log);
        MonitorSettings settings = MonitorSettings.Default with { RussianCertificateIds = [id] };
        CertificateInventoryService inventory = new(new WindowsCertificateStoreProvider(),
            new RussianCertificateClassifier(CertificateCatalog.Load(), settings), log);
        string statePath = Path.Combine(directory, $"stage6-monitor-state-{Guid.NewGuid():N}.json");
        MonitorService monitor = new(token => inventory.Scan(token), new MonitorStateStore(statePath), log);
        try
        {
            MonitorCycleResult first = monitor.RunOnce();
            RequireComplete(first);
            Require(!Own(first).Any(), "Тестовый сертификат присутствует до добавления.");

            DisallowedResult added = manager.Execute(manager.Preview(DisallowedOperation.Add,
                StoreLocation.CurrentUser, data));
            Require(added.Changed && added.OwnPresentAfter && backend.Find(StoreLocation.CurrentUser, id)!
                .SequenceEqual(data.Metadata.RawData), "Добавление не подтверждено собственным Disallowed.");
            MonitorCycleResult found = monitor.RunOnce();
            RequireComplete(found);
            Require(Own(found).Single().Kind == MonitorChangeKind.Found
                && OwnCertificate(found, id).DisallowedStatus == "Disallowed: пользователь",
                "Монитор не обнаружил появление в пользовательском Disallowed.");
            MonitorCycleResult unchanged = monitor.RunOnce();
            RequireComplete(unchanged);
            Require(!Own(unchanged).Any(), "Неизменный снимок создал повторное событие.");

            MonitorService restored = new(token => inventory.Scan(token), new MonitorStateStore(statePath), log);
            Require(restored.InitializationWarning is null && restored.RestoredSnapshot is not null,
                "Состояние монитора не восстановлено.");
            MonitorCycleResult afterRestart = restored.RunOnce();
            RequireComplete(afterRestart);
            Require(!Own(afterRestart).Any(), "После восстановления возникло повторное событие.");

            DisallowedResult removed = manager.Execute(manager.Preview(DisallowedOperation.Remove,
                StoreLocation.CurrentUser, data));
            Require(removed.Changed && !removed.OwnPresentAfter && !backend.Contains(StoreLocation.CurrentUser, id),
                "Удаление не подтверждено собственным Disallowed.");
            MonitorCycleResult disappeared = restored.RunOnce();
            RequireComplete(disappeared);
            Require(Own(disappeared).Single().Kind == MonitorChangeKind.Disappeared,
                "Монитор не обнаружил исчезновение.");

            DisallowedResult addedAgain = manager.Execute(manager.Preview(DisallowedOperation.Add,
                StoreLocation.CurrentUser, data));
            Require(addedAgain.Changed && addedAgain.OwnPresentAfter,
                "Повторное добавление не подтверждено.");
            MonitorCycleResult reappeared = restored.RunOnce();
            RequireComplete(reappeared);
            Require(Own(reappeared).Single().Kind == MonitorChangeKind.Reappeared,
                "Монитор не обнаружил повторное появление.");

            HistoryReadResult historyResult = history.ReadRecent();
            HistoryEvent[] completions = historyResult.Events.Where(item => item.EventName == "disallowed.completed"
                && string.Equals(item.CertificateId, id, StringComparison.OrdinalIgnoreCase)).ToArray();
            Require(historyResult.Errors.Count == 0 && completions.Length == 3
                && completions.All(item => item.Location == "CurrentUser\\Disallowed"
                    && item.Result is not null && item.Result.Contains("changed=True", StringComparison.Ordinal)),
                "История операций Disallowed не содержит структурированных результатов.");
            Require(log.HistoryWarning is null && log.DiagnosticWarning is null,
                "Журнал или история не были сохранены.");
            checks.Add(new { name = "currentUserRoundtrip", status = "passed", certificateId = id,
                found = true, persistence = true, disappeared = true, reappeared = true,
                historyCompleted = completions.Length, ownPresenceConfirmed = true,
                privateKeyWritten = false, rootAndCaAbsent = true,
                baselineStores = first.Snapshot.Stores.Count,
                baselineObservations = first.Snapshot.ObservationCount });
        }
        finally
        {
            if (backend.Contains(StoreLocation.CurrentUser, id))
                backend.Remove(StoreLocation.CurrentUser, id);
            Require(!backend.Contains(StoreLocation.CurrentUser, id), "Тестовый сертификат остался в Disallowed.");
            Require(!InRootOrCa(id), "Тестовый сертификат обнаружен в Root или CA.");
        }
        return id;

        IEnumerable<MonitorChange> Own(MonitorCycleResult result) => result.Changes.Where(item =>
            string.Equals(item.Certificate.CertificateId, id, StringComparison.OrdinalIgnoreCase));
    }

    private static InventoryCertificate OwnCertificate(MonitorCycleResult cycle, string id) =>
        cycle.Snapshot.Certificates.Single(item => item.Metadata.CertificateId.Equals(id,
            StringComparison.OrdinalIgnoreCase));

    private static void RequireComplete(MonitorCycleResult cycle)
    {
        Require(cycle.Snapshot.IsComplete && cycle.PersistenceWarning is null,
            "Снимок Windows неполон или состояние не сохранено.");
    }

    private static bool InRootOrCa(string id) =>
        new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine }.Any(location =>
            new[] { StoreName.Root, StoreName.CertificateAuthority }.Any(name => InStore(location, name, id)));

    private static bool InStore(StoreLocation location, StoreName name, string id)
    {
        using X509Store store = new(name, location);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived);
        X509Certificate2Collection certificates = store.Certificates;
        try { return certificates.Cast<X509Certificate2>().Any(item =>
            string.Equals(item.Thumbprint, id, StringComparison.OrdinalIgnoreCase)); }
        finally { foreach (X509Certificate2 item in certificates) item.Dispose(); }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class EmptyProvider : ICertificateStoreProvider
    {
        public IReadOnlyList<CertificateStoreDescriptor> EnumerateStores(StoreLocation _) => [];
        public CertificateStoreReadResult ReadStore(CertificateStoreDescriptor _) => throw new NotSupportedException();
    }

    private sealed class UnavailableProvider : ICertificateStoreProvider
    {
        public IReadOnlyList<CertificateStoreDescriptor> EnumerateStores(StoreLocation location) =>
            [new CertificateStoreDescriptor(location, "Недоступное")];
        public CertificateStoreReadResult ReadStore(CertificateStoreDescriptor _) =>
            throw new UnauthorizedAccessException("Нет доступа к хранилищу.");
    }
}
