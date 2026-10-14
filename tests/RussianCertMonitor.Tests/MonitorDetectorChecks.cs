using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Classification;
using RussianCertMonitor.Inventory;
using RussianCertMonitor.Monitoring;

namespace RussianCertMonitor.Tests;

internal static class MonitorDetectorChecks
{
    private static readonly CertificateStoreDescriptor Root = new(StoreLocation.CurrentUser, "Root");
    private static readonly CertificateStoreDescriptor MachineRoot = new(StoreLocation.LocalMachine, "Root");
    private static readonly CertificateStoreDescriptor Disallowed = new(StoreLocation.CurrentUser, "Disallowed");

    public static void Run()
    {
        InventoryCertificate russian = Certificate("RU", russian: true, locations: [Root]);
        MonitorComparison found = MonitorChangeDetector.Compare(MonitorTrackingState.Empty, Snapshot([russian]));
        RequireChange(found, "RU", MonitorChangeKind.Found);
        Require(found.Changes[0].ShouldNotify && found.State.Matches[0].IsRussian,
            "Первое российское совпадение должно уведомлять.");
        Require(MonitorChangeDetector.Compare(found.State, Snapshot([russian])).Changes.Count == 0,
            "Неизменный снимок не должен уведомлять повторно.");
        Require(MonitorChangeDetector.Compare(MonitorTrackingState.Empty, Snapshot([])).Changes.Count == 0,
            "Пустой первый снимок не должен порождать события.");
        RequireChange(MonitorChangeDetector.Compare(MonitorTrackingState.Empty, Snapshot([russian])),
            "RU", MonitorChangeKind.Found);

        MonitorComparison disappeared = MonitorChangeDetector.Compare(found.State, Snapshot([]));
        RequireChange(disappeared, "RU", MonitorChangeKind.Disappeared);
        Require(!disappeared.Changes[0].ShouldNotify && !disappeared.State.Matches[0].IsPresent,
            "Исчезнувший ID должен сохраняться без уведомления.");
        Require(MonitorChangeDetector.Compare(disappeared.State, Snapshot([])).Changes.Count == 0,
            "Подтверждённое исчезновение не должно повторяться.");
        MonitorComparison reappeared = MonitorChangeDetector.Compare(disappeared.State, Snapshot([russian]));
        RequireChange(reappeared, "RU", MonitorChangeKind.Reappeared);
        Require(MonitorChangeDetector.Compare(reappeared.State, Snapshot([russian])).Changes.Count == 0,
            "Состояние, переданное следующему сравнению, должно предотвращать дубли.");

        InventoryCertificate twoLocations = russian with { Locations = [Root, MachineRoot] };
        MonitorComparison added = MonitorChangeDetector.Compare(found.State, Snapshot([twoLocations]));
        RequireChange(added, "RU", MonitorChangeKind.LocationsChanged);
        Require(MonitorChangeDetector.Compare(added.State, Snapshot([russian])).Changes.Count == 0,
            "Удаление части расположений само по себе не должно уведомлять.");

        InventoryCertificate blocked = russian with { Locations = [Root, Disallowed] };
        MonitorComparison blockedFound = MonitorChangeDetector.Compare(MonitorTrackingState.Empty, Snapshot([blocked]));
        RequireChange(blockedFound, "RU", MonitorChangeKind.Found);
        Require(blockedFound.State.Matches[0].HasDisallowed,
            "Наличие Disallowed должно сохраняться как свойство конкретного совпадения.");
        Require(MonitorChangeDetector.Compare(blockedFound.State, Snapshot([blocked])).Changes.Count == 0,
            "Неизменное блокированное совпадение не должно уведомлять повторно.");
        RequireChange(MonitorChangeDetector.Compare(blockedFound.State, Snapshot([russian])),
            "RU", MonitorChangeKind.LocationsChanged);

        MonitorComparison missingPartial = MonitorChangeDetector.Compare(blockedFound.State,
            Snapshot([], complete: false));
        Require(missingPartial.Changes.Count == 0 && missingPartial.State.Matches[0].IsPresent
            && missingPartial.State.Matches[0].HasDisallowed,
            "Неполный снимок не подтверждает исчезновение и снятие Disallowed.");
        Require(MonitorChangeDetector.Compare(missingPartial.State, Snapshot([blocked])).Changes.Count == 0,
            "Неполный пропуск не должен создавать ложное повторное появление.");
        MonitorComparison partialAdded = MonitorChangeDetector.Compare(found.State,
            Snapshot([twoLocations], complete: false));
        RequireChange(partialAdded, "RU", MonitorChangeKind.LocationsChanged);
        Require(partialAdded.State.Matches[0].Locations.Count == 2,
            "Неполный снимок должен объединять старые и новые расположения.");
        MonitorComparison partialNew = MonitorChangeDetector.Compare(found.State,
            Snapshot([russian, Certificate("NEW", possible: true, locations: [MachineRoot])], complete: false));
        RequireChange(partialNew, "NEW", MonitorChangeKind.Found);
        RequireChange(MonitorChangeDetector.Compare(disappeared.State,
            Snapshot([russian], complete: false)), "RU", MonitorChangeKind.Reappeared);
        Require(MonitorChangeDetector.Compare(blockedFound.State,
            Snapshot([russian], complete: false)).Changes.Count == 0,
            "Неполный снимок не должен подтверждать снятие Disallowed.");

        InventoryCertificate weak = Certificate("WEAK", possible: true, locations: [Root]);
        InventoryCertificate historical = Certificate("HISTORY", historical: true, locations: [Root]);
        InventoryCertificate other = Certificate("OTHER", locations: [Root]);
        MonitorComparison distinct = MonitorChangeDetector.Compare(MonitorTrackingState.Empty,
            Snapshot([weak, historical, other]));
        Require(distinct.Changes.Count == 2 && distinct.State.Matches.Count == 2,
            "Отслеживаются только нуждающиеся во внимании сертификаты.");
        Require(distinct.State.Matches.Single(item => item.CertificateId == "WEAK") is
            { IsRussian: false, IsPossibleRussian: true, WasPreviouslyDeleted: false },
            "Косвенные признаки должны сохраняться отдельно от российской принадлежности.");
        Require(distinct.State.Matches.Single(item => item.CertificateId == "HISTORY") is
            { IsRussian: false, IsPossibleRussian: false, WasPreviouslyDeleted: true },
            "Неизвестная историческая принадлежность не доказывает российскую.");
        RequireChange(MonitorChangeDetector.Compare(distinct.State,
            Snapshot([Certificate("WEAK", russian: true, locations: [Root]), historical, other])),
            "WEAK", MonitorChangeKind.ClassificationChanged);
        Require(MonitorChangeDetector.Compare(found.State,
            Snapshot([Certificate("RU", possible: true, locations: [Root])])).Changes.Count == 0,
            "Ослабление классификации не должно уведомлять.");
        Require(MonitorChangeDetector.Compare(found.State, Snapshot([other])).Changes.Single().Kind
            == MonitorChangeKind.Disappeared,
            "Исчезновение совпадения означает потерю сигнала NeedsAttention.");
        Require(MonitorChangeDetector.Compare(found.State, Snapshot([russian with
        {
            Metadata = russian.Metadata with { DisplayName = "Другое имя" }
        }])).Changes.Count == 0, "Изменение имени не является событием.");

        CertificateStoreDescriptor[] sourceLocations = [MachineRoot, Root];
        InventoryCertificate source = russian with { Locations = sourceLocations };
        TrackedMatch[] sourceMatches = [found.State.Matches[0]];
        MonitorTrackingState prior = new(sourceMatches);
        MonitorChangeDetector.Compare(prior, Snapshot([source]));
        Require(sourceLocations.SequenceEqual([MachineRoot, Root])
            && ReferenceEquals(sourceMatches[0], found.State.Matches[0]),
            "Сравнение не должно изменять входные коллекции.");
    }

    private static InventoryCertificate Certificate(string id, bool russian = false,
        bool possible = false, bool historical = false, IReadOnlyList<CertificateStoreDescriptor>? locations = null)
    {
        CertificateMetadata metadata = new(id, id, id, id, "01", null, null, [], [], []);
        CertificateClassification classification = new(russian, possible, historical, [], []);
        return new(metadata, locations ?? [Root], classification, []);
    }

    private static CertificateInventorySnapshot Snapshot(IReadOnlyList<InventoryCertificate> certificates,
        bool complete = true) => new(DateTimeOffset.UnixEpoch, certificates, [],
            complete ? [] : [new InventoryIssue("Root", "Чтение не завершено")], certificates.Count);

    private static void RequireChange(MonitorComparison comparison, string id, MonitorChangeKind kind) =>
        Require(comparison.Changes.Count == 1 && comparison.Changes[0].Certificate.CertificateId == id
            && comparison.Changes[0].Kind == kind, $"Ожидалось событие {kind} для {id}.");

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
