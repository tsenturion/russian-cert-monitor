using RussianCertMonitor.Infrastructure;
using RussianCertMonitor.Inventory;

namespace RussianCertMonitor.Monitoring;

internal sealed record MonitorCycleResult(
    CertificateInventorySnapshot Snapshot, IReadOnlyList<MonitorChange> Changes,
    string? PersistenceWarning, bool StateSaved);

internal sealed class MonitorService
{
    public const int PollIntervalMilliseconds = 10_000;
    private readonly Func<CancellationToken, CertificateInventorySnapshot> scan;
    private readonly IMonitorStateStore store;
    private readonly DiagnosticLog? log;
    private readonly object cycleLock = new();
    private MonitorTrackingState tracking;
    private CertificateInventorySnapshot? lastSavedSnapshot;
    private string? lastSaveWarning;
    private bool firstCycle = true;
    private bool savePending;
    private string? lastCoverage;

    public CertificateInventorySnapshot? RestoredSnapshot { get; }
    public string? InitializationWarning { get; }

    public MonitorService(Func<CancellationToken, CertificateInventorySnapshot> scan,
        IMonitorStateStore store, DiagnosticLog? log = null)
    {
        this.scan = scan;
        this.store = store;
        this.log = log;
        MonitorStateLoadResult loaded = store.Load();
        tracking = loaded.Document?.Tracking ?? MonitorTrackingState.Empty;
        RestoredSnapshot = lastSavedSnapshot = loaded.Document?.Snapshot;
        InitializationWarning = loaded.Warning;
        log?.TryWrite(loaded.Warning is null ? "monitor.state-loaded" : "monitor.state-load-error",
            loaded.Warning ?? $"Состояние восстановлено; отслеживаемых идентификаторов: {tracking.Matches.Count}; " +
                $"сохранённый снимок: {(RestoredSnapshot is null ? "отсутствует" : "имеется")}.");
    }

    public MonitorCycleResult RunOnce(CancellationToken cancellationToken = default)
    {
        lock (cycleLock)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CertificateInventorySnapshot snapshot = scan(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            string coverage = snapshot.IsComplete ? "Проверка полная."
                : "Проверка неполная; отсутствие сертификатов в недоступных хранилищах не подтверждено. "
                    + string.Join("; ", snapshot.Issues.Select(item => item.Location + ": " + item.Message));
            if (lastCoverage != coverage)
            {
                log?.TryWrite("monitor.coverage-changed", coverage, context: new(Result: snapshot.IsComplete ? "complete" : "incomplete"));
                lastCoverage = coverage;
            }
            MonitorComparison comparison = MonitorChangeDetector.Compare(tracking, snapshot);
            tracking = comparison.State;
            bool shouldSave = firstCycle || savePending || comparison.Changes.Count > 0
                || !SnapshotContentsEqual(lastSavedSnapshot, snapshot);
            firstCycle = false;
            bool saved = false;
            string? warning = null;
            if (shouldSave)
            {
                try
                {
                    store.Save(new MonitorStateDocument(1, DateTimeOffset.UtcNow, snapshot, tracking));
                    lastSavedSnapshot = snapshot;
                    savePending = false;
                    saved = true;
                    log?.TryWrite("monitor.state-saved",
                        $"Снимок и состояние сохранены; уникальных: {snapshot.Certificates.Count}; " +
                        $"отслеживаемых: {tracking.Matches.Count}; изменений: {comparison.Changes.Count}.");
                    if (lastSaveWarning is not null)
                        log?.TryWrite("monitor.state-save-recovered", "Сохранение состояния снова доступно.");
                }
                catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException)
                {
                    savePending = true;
                    warning = "Состояние не сохранено. После перезапуска уведомления могут повториться. " + error.Message;
                    if (!string.Equals(lastSaveWarning, warning, StringComparison.Ordinal))
                        log?.TryWrite("monitor.state-save-error", warning, error);
                }
            }
            lastSaveWarning = warning;
            foreach (MonitorChange change in comparison.Changes)
            {
                log?.TryWrite("monitor.match-changed",
                    $"{Describe(change.Kind)}: {change.Certificate.DisplayName}; " +
                    $"идентификатор: {change.Certificate.CertificateId}; категория: {change.Certificate.Category}; " +
                    $"наблюдаемые хранилища: {string.Join("; ", change.Certificate.Locations.Select(item => item.Path))}." +
                    (change.Kind == MonitorChangeKind.TrustWeakened
                        ? $" Доверие Windows: пользователь 0x{change.Certificate.LastUserTrustStatus:X8}, компьютер 0x{change.Certificate.LastMachineTrustStatus:X8}."
                        : ""),
                    context: new(change.Certificate.CertificateId,
                        string.Join("; ", change.Certificate.Locations.Select(item => item.Path)), change.Kind.ToString()));
            }
            return new MonitorCycleResult(snapshot, comparison.Changes, warning, saved);
        }
    }

    public static bool SnapshotContentsEqual(CertificateInventorySnapshot? left, CertificateInventorySnapshot right)
    {
        if (left is null || left.ObservationCount != right.ObservationCount
            || left.Certificates.Count != right.Certificates.Count
            || !LocationsEqual(left.Stores, right.Stores)
            || !left.Issues.OrderBy(item => item.Location).ThenBy(item => item.Message)
                .SequenceEqual(right.Issues.OrderBy(item => item.Location).ThenBy(item => item.Message)))
            return false;

        Dictionary<string, InventoryCertificate> previous = left.Certificates.ToDictionary(
            item => item.Metadata.CertificateId, StringComparer.OrdinalIgnoreCase);
        foreach (InventoryCertificate current in right.Certificates)
        {
            if (!previous.TryGetValue(current.Metadata.CertificateId, out InventoryCertificate? old)
                || !MetadataEqual(old.Metadata, current.Metadata) || !LocationsEqual(old.Locations, current.Locations)
                || old.Trust != current.Trust
                || !(old.BackupScopes ?? []).SequenceEqual(current.BackupScopes ?? [])
                || old.Classification.IsRussian != current.Classification.IsRussian
                || old.Classification.IsPossibleRussian != current.Classification.IsPossibleRussian
                || old.Classification.WasPreviouslyDeleted != current.Classification.WasPreviouslyDeleted
                || old.Classification.IsExcluded != current.Classification.IsExcluded
                || !old.Classification.Reasons.SequenceEqual(current.Classification.Reasons)
                || !old.Classification.Errors.SequenceEqual(current.Classification.Errors)
                || !old.ReadErrors.SequenceEqual(current.ReadErrors))
                return false;
        }
        return true;
    }

    private static bool MetadataEqual(CertificateMetadata left, CertificateMetadata right) =>
        left.DisplayName == right.DisplayName && left.Subject == right.Subject && left.Issuer == right.Issuer
        && left.SerialNumber == right.SerialNumber && left.NotBefore == right.NotBefore && left.NotAfter == right.NotAfter
        && left.SubjectNameRaw.AsSpan().SequenceEqual(right.SubjectNameRaw)
        && left.IssuerNameRaw.AsSpan().SequenceEqual(right.IssuerNameRaw)
        && left.RawData.AsSpan().SequenceEqual(right.RawData);

    private static bool LocationsEqual(IEnumerable<CertificateStoreDescriptor> left,
        IEnumerable<CertificateStoreDescriptor> right) => left.Select(item => item.Path)
        .OrderBy(item => item, StringComparer.OrdinalIgnoreCase).SequenceEqual(
            right.Select(item => item.Path).OrderBy(item => item, StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);

    public static string Describe(MonitorChangeKind kind) => kind switch
    {
        MonitorChangeKind.Found => "Новое совпадение",
        MonitorChangeKind.Reappeared => "Повторное появление совпадения",
        MonitorChangeKind.LocationsChanged => "Изменение расположений совпадения",
        MonitorChangeKind.ClassificationChanged => "Усиление признаков принадлежности",
        MonitorChangeKind.Disappeared => "Совпадение больше не наблюдается",
        MonitorChangeKind.NoLongerMatches => "Сертификат присутствует, но больше не совпадает с правилами",
        MonitorChangeKind.TrustWeakened => "Явный запрет исчез или цепочка снова проходит проверку",
        MonitorChangeKind.ComputerBlockRemoved => "Запись Disallowed исчезла из области компьютера",
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };
}
