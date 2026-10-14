using System.ComponentModel;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Classification;
using RussianCertMonitor.Infrastructure;

namespace RussianCertMonitor.Inventory;

internal sealed class CertificateInventoryService(
    ICertificateStoreProvider provider, RussianCertificateClassifier classifier, DiagnosticLog? log = null)
{
    public CertificateInventorySnapshot Scan(CancellationToken cancellationToken = default)
    {
        log?.TryWrite("inventory.started", "Начато чтение CurrentUser и LocalMachine.");
        List<InventoryIssue> issues = [];
        List<CertificateStoreDescriptor> readStores = [];
        Dictionary<string, AccumulatedCertificate> certificates = new(StringComparer.OrdinalIgnoreCase);
        int observationCount = 0;

        foreach (StoreLocation location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyList<CertificateStoreDescriptor> stores;
            try
            {
                stores = provider.EnumerateStores(location);
            }
            catch (Exception error) when (IsReadError(error))
            {
                AddIssue(location.ToString(), "Список хранилищ недоступен: " + ErrorText.Describe(error));
                continue;
            }

            foreach (CertificateStoreDescriptor store in stores)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CertificateStoreReadResult result;
                try
                {
                    result = provider.ReadStore(store);
                }
                catch (Exception error) when (IsReadError(error))
                {
                    AddIssue(store.Path, "Хранилище не прочитано: " + ErrorText.Describe(error));
                    continue;
                }
                readStores.Add(store);
                foreach (string error in result.Errors)
                    AddIssue(store.Path, error);

                foreach (CertificateObservation observation in result.Certificates)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    observationCount++;
                    string id = observation.Metadata.CertificateId;
                    if (!certificates.TryGetValue(id, out AccumulatedCertificate? accumulated))
                    {
                        CertificateClassification classification = classifier.Classify(id,
                            observation.Metadata.SubjectNameRaw, observation.Metadata.IssuerNameRaw);
                        accumulated = new AccumulatedCertificate(observation.Metadata, classification);
                        certificates.Add(id, accumulated);
                        foreach (string error in classification.Errors)
                            AddIssue(store.Path, $"{id}: {error}");
                    }
                    if (!accumulated.Locations.Contains(store))
                        accumulated.Locations.Add(store);
                    foreach (string error in observation.Errors)
                    {
                        accumulated.ReadErrors.Add(error);
                        AddIssue(store.Path, $"{id}: {error}");
                    }
                }
            }
        }

        InventoryCertificate[] inventory = certificates.Values.Select(item => new InventoryCertificate(
            item.Metadata, item.Locations.ToArray(), item.Classification,
            item.ReadErrors.Distinct(StringComparer.Ordinal).ToArray()))
            .OrderByDescending(item => item.NeedsAttention)
            .ThenBy(item => item.Metadata.DisplayName, StringComparer.OrdinalIgnoreCase).ToArray();
        CertificateInventorySnapshot snapshot = new(DateTimeOffset.UtcNow, inventory,
            readStores, issues, observationCount);
        log?.TryWrite("inventory.completed",
            $"Хранилищ: {readStores.Count}; записей: {observationCount}; уникальных: {inventory.Length}; " +
            $"российских: {snapshot.RussianCount}; косвенных: {snapshot.PossibleCount}; " +
            $"неопределённых из истории: {snapshot.HistoricalUnknownCount}; ошибок: {issues.Count}; " +
            $"полнота: {(snapshot.IsComplete ? "полная" : "неполная")}.");
        return snapshot;

        void AddIssue(string location, string message)
        {
            issues.Add(new InventoryIssue(location, message));
            log?.TryWrite("inventory.read-error", $"{location}: {message}");
        }
    }

    private static bool IsReadError(Exception error) => error is CryptographicException
        or UnauthorizedAccessException or SecurityException or IOException
        or Win32Exception or InvalidOperationException or NotSupportedException or ArgumentException;

    private sealed class AccumulatedCertificate(
        CertificateMetadata metadata, CertificateClassification classification)
    {
        public CertificateMetadata Metadata { get; } = metadata;
        public CertificateClassification Classification { get; } = classification;
        public List<CertificateStoreDescriptor> Locations { get; } = [];
        public List<string> ReadErrors { get; } = [];
    }
}
