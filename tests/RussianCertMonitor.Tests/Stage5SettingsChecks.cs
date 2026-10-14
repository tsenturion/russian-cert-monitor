using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using RussianCertMonitor.Catalog;
using RussianCertMonitor.Classification;
using RussianCertMonitor.History;
using RussianCertMonitor.Infrastructure;
using RussianCertMonitor.Inventory;
using RussianCertMonitor.Monitoring;
using RussianCertMonitor.Settings;

namespace RussianCertMonitor.Tests;

internal static class Stage5SettingsChecks
{
    private const string Id = "0123456789ABCDEF0123456789ABCDEF01234567";

    public static void Run()
    {
        string directory = Path.Combine(Path.GetTempPath(), "RussianCertMonitor-Settings-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            VerifySettings(directory);
            VerifyRulesAndNotifications();
            VerifyHistorySink(directory);
        }
        finally { Directory.Delete(directory, true); }
    }

    private static void VerifySettings(string directory)
    {
        SettingsStore store = new(Path.Combine(directory, "settings.json"));
        Require(store.Load().Settings.PollIntervalSeconds == 10 && store.Load().Warning is null,
            "Первый запуск должен использовать стандартные настройки без ошибки.");
        MonitorSettings selected = new()
        {
            PollIntervalSeconds = 25, NotificationsEnabled = false,
            AuthorityNames = ["  Example Authority  ", "example authority"],
            RussianCertificateIds = [Id.ToLowerInvariant()], NotificationExclusions = [Id]
        };
        store.Save(selected);
        SettingsLoadResult loaded = new SettingsStore(store.FilePath).Load();
        Require(loaded.Warning is null && loaded.Settings.PollIntervalSeconds == 25
            && !loaded.Settings.NotificationsEnabled && loaded.Settings.AuthorityNames.Length == 1
            && loaded.Settings.RussianCertificateIds.Single() == Id
            && loaded.Settings.NotificationExclusions.Single() == Id,
            "Настройки и нормализованные правила должны восстанавливаться после перезапуска.");
        string saved = File.ReadAllText(store.FilePath);
        using (FileStream locked = new(store.FilePath, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Require(store.Load().Warning is not null, "Занятый файл не должен считаться отсутствующими настройками.");
            try { store.Save(selected with { PollIntervalSeconds = 35 }); throw new InvalidOperationException("Не ожидалась запись занятого файла."); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        }
        Require(File.ReadAllText(store.FilePath) == saved, "Ошибка сохранения не должна повреждать действующий файл.");
        Require(!Directory.EnumerateFiles(directory, ".settings-*.tmp").Any(), "Собственный временный файл должен убираться.");
        foreach (string invalid in new[]
        {
            "{", "null", "{\"schemaVersion\":2}", "{\"pollIntervalSeconds\":0}",
            "{\"pollIntervalSeconds\":10,\"pollIntervalSeconds\":30}", "{\"notificationExclusions\":[\"ABC\"]}",
            "{\"authorityNames\":null}", "{\"unknownOption\":true}"
        })
        {
            File.WriteAllText(store.FilePath, invalid);
            SettingsLoadResult result = store.Load();
            Require(result.Warning is not null && result.Settings.PollIntervalSeconds == 10,
                "Повреждённые или недопустимые настройки должны давать явное предупреждение.");
            Require(File.ReadAllText(store.FilePath) == invalid, "Чтение не должно перезаписывать повреждённые настройки.");
        }
        File.WriteAllText(store.FilePath, saved, new UTF8Encoding(true));
        Require(store.Load().Warning is null, "UTF-8 с BOM из PowerShell должен поддерживаться.");
        File.WriteAllText(store.FilePath, new string(' ', 256 * 1024 + 1));
        Require(store.Load().Warning is not null, "Чтение настроек должно ограничиваться по размеру.");
        SettingsStore inaccessible = new(directory);
        Require(inaccessible.Load().Warning is not null, "Ошибка доступа не должна превращаться в успешное чтение пустого файла.");
    }

    private static void VerifyRulesAndNotifications()
    {
        CertificateCatalog catalog = CertificateCatalog.Load();
        byte[] foreign = Name("2.5.4.6", "US");
        MonitorSettings settings = new() { AuthorityNames = ["Example Authority"], NotificationExclusions = [Id] };
        RussianCertificateClassifier classifier = new(catalog, settings);
        CertificateClassification russian = classifier.Classify(Id, Name("2.5.4.3", "Example Authority CA"), foreign);
        Require(russian.IsRussian && russian.IsExcluded && russian.Reasons.Any(item => item.Contains("пользовательским правилом")),
            "Пользовательское правило должно сохранять основание принадлежности и отдельное исключение уведомлений.");
        Require(!classifier.Classify(Id, Name("2.5.4.3", "PrefixExample AuthoritySuffix"), foreign).IsRussian,
            "Пользовательское название не должно совпадать внутри другого слова.");
        RussianCertificateClassifier explicitId = new(catalog, settings with { RussianCertificateIds = [Id] });
        Require(explicitId.Classify(Id.ToLowerInvariant(), foreign, foreign).IsRussian,
            "Пользовательские идентификаторы должны совпадать без учёта регистра.");
        CertificateStoreDescriptor location = new(StoreLocation.CurrentUser, "Root");
        CertificateMetadata metadata = new(Id, "Тест", "CN=Example", "CN=Issuer", "1", null, null, foreign, foreign, []);
        InventoryCertificate certificate = new(metadata, [location], russian, []);
        Require(certificate.NeedsAttention, "Исключение уведомлений не должно скрывать совпадение из инвентаря.");
        CertificateInventorySnapshot snapshot = new(DateTimeOffset.UtcNow, [certificate], [location], [], 1);
        MonitorComparison first = MonitorChangeDetector.Compare(MonitorTrackingState.Empty, snapshot);
        Require(first.Changes.Count == 1 && MonitorNotification.Create(first.Changes) is not null,
            "Обнаружение должно продолжаться независимо от настроек уведомлений.");
        Require(MonitorNotification.Create(first.Changes, settings) is null,
            "Исключение должно подавлять уведомление только указанного идентификатора.");
        Require(MonitorNotification.Create(first.Changes, settings with { NotificationExclusions = [], NotificationsEnabled = false }) is null,
            "Общий выключатель должен подавлять уведомления.");
        Require(MonitorChangeDetector.Compare(first.State, snapshot).Changes.Count == 0,
            "Выключенные уведомления не должны мешать запоминанию уже обнаруженного совпадения.");
        InventoryCertificate nonMatch = certificate with { Classification = new(false, false, false, [], []) };
        MonitorComparison removedRule = MonitorChangeDetector.Compare(first.State, snapshot with { Certificates = [nonMatch] });
        Require(removedRule.Changes.Single().Kind == MonitorChangeKind.NoLongerMatches
            && !removedRule.Changes.Single().ShouldNotify,
            "Отмена пользовательского правила не должна выдаваться за исчезновение сертификата.");
    }

    private static void VerifyHistorySink(string directory)
    {
        HistoryStore history = new(Path.Combine(directory, "History"));
        DiagnosticLog log = new(Path.Combine(directory, "Logs"));
        log.AttachHistory(history);
        log.TryWrite("inventory.completed", "Обычный цикл без изменений.");
        log.TryWrite("disallowed.completed", "Собственная запись подтверждена.", context: new(Id, "CurrentUser\\Disallowed", "Add; ownPresent=True"));
        log.TryWrite("inventory.failed", "Ошибка доступа.", new UnauthorizedAccessException());
        log.TryWrite("inventory.failed", "Ошибка доступа.", new UnauthorizedAccessException());
        HistoryReadResult read = history.ReadRecent();
        Require(read.Events.Count == 2 && read.Errors.Count == 0
            && read.Events.Any(item => item.CertificateId == Id && item.Location == "CurrentUser\\Disallowed"
                && item.Result!.Contains("ownPresent=True")),
            "История должна подтверждать область и результат операции без повторов неизменных циклов или одной ошибки.");
        log.TryWrite("inventory.recovered", "Чтение снова доступно.");
        log.TryWrite("inventory.failed", "Ошибка доступа.", new UnauthorizedAccessException());
        Require(history.ReadRecent().Events.Count == 4, "После восстановления повторный сбой должен снова попасть в историю.");
        string blocked = Path.Combine(directory, "blocked-history");
        File.WriteAllText(blocked, "Это файл, а не папка.");
        log.AttachHistory(new HistoryStore(blocked));
        log.TryWrite("disallowed.completed", "Операция подтверждена.");
        Require(log.HistoryWarning is not null, "Ошибка записи истории должна быть доступна интерфейсу.");
    }

    private static byte[] Name(string oid, string value)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        using (writer.PushSetOf())
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);
        }
        return writer.Encode();
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
