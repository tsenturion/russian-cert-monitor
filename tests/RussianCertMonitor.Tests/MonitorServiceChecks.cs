using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using RussianCertMonitor.Catalog;
using RussianCertMonitor.Classification;
using RussianCertMonitor.Inventory;
using RussianCertMonitor.Monitoring;
using RussianCertMonitor.UI;

namespace RussianCertMonitor.Tests;

internal static class MonitorServiceChecks
{
    private const string Id = "1111111111111111111111111111111111111111";
    private static readonly CertificateStoreDescriptor Root = new(StoreLocation.CurrentUser, "Root");

    public static void Run()
    {
        VerifyPersistenceAndRestart();
        VerifyCorruptState();
        VerifySaveRetryAndConcurrency();
        VerifyNotifications();
        VerifyWindowUpdates();
    }

    private static void VerifyPersistenceAndRestart()
    {
        string directory = CreateCheckDirectory("state");
        string path = Path.Combine(directory, "monitor-state.json");
        CertificateInventorySnapshot current = Snapshot(Certificate());
        MonitorService monitor = new(_ => current, new MonitorStateStore(path));
        Require(monitor.RestoredSnapshot is null, "Первый запуск должен обходиться без файла состояния.");
        MonitorCycleResult first = monitor.RunOnce();
        Require(first.StateSaved && first.Changes.Single().Kind == MonitorChangeKind.Found,
            "Первое совпадение должно сохраняться до передачи уведомления интерфейсу.");
        byte[] original = File.ReadAllBytes(path);
        current = current with { ScannedAt = current.ScannedAt.AddSeconds(10) };
        MonitorCycleResult unchanged = monitor.RunOnce();
        Require(!unchanged.StateSaved && unchanged.Changes.Count == 0
            && File.ReadAllBytes(path).AsSpan().SequenceEqual(original),
            "Неизменное содержимое с новым временем проверки не должно переписываться и уведомлять.");

        MonitorService restarted = new(_ => current, new MonitorStateStore(path));
        Require(restarted.RestoredSnapshot is { Certificates.Count: 1 }
            && restarted.RestoredSnapshot.Certificates[0].Metadata.RawData.SequenceEqual(new byte[] { 1, 2, 3 }),
            "Сохранённый снимок должен восстанавливаться вместе с публичными данными.");
        Require(restarted.RunOnce().Changes.Count == 0, "Перезапуск не должен повторять уведомление о присутствующем совпадении.");
        current = Snapshot();
        Require(restarted.RunOnce().Changes.Single().Kind == MonitorChangeKind.Disappeared,
            "Подтверждённое исчезновение должно сохраняться.");
        current = Snapshot(Certificate());
        MonitorService afterAbsence = new(_ => current, new MonitorStateStore(path));
        Require(afterAbsence.RunOnce().Changes.Single().Kind == MonitorChangeKind.Reappeared,
            "Повторное появление должно различаться даже после перезапуска во время отсутствия.");
        current = Snapshot() with { Issues = [new InventoryIssue(Root.Path, "Нет доступа")] };
        Require(afterAbsence.RunOnce().Changes.Count == 0, "Неполная проверка не подтверждает исчезновение.");
        current = Snapshot(Certificate());
        MonitorService afterPartial = new(_ => current, new MonitorStateStore(path));
        Require(afterPartial.RunOnce().Changes.Count == 0,
            "Частичный снимок, сохранённый перед перезапуском, не должен создавать ложное повторное появление.");

        MonitorStateStore store = new(path);
        MonitorStateDocument document = store.Load().Document!;
        try
        {
            store.Save(document with
            {
                Tracking = new MonitorTrackingState([document.Tracking.Matches[0], document.Tracking.Matches[0]])
            });
            throw new InvalidOperationException("Повреждённое состояние принято для записи.");
        }
        catch (InvalidDataException)
        {
            Require(store.Load().Document is not null, "Отказ от неверной записи не должен повреждать старый файл.");
        }
        Require(!Directory.EnumerateFiles(directory, "*.tmp").Any(), "Временные файлы завершённой записи должны удаляться.");
    }

    private static void VerifyCorruptState()
    {
        string path = Path.Combine(CreateCheckDirectory("corrupt"), "monitor-state.json");
        foreach (string invalid in new[] { "{неверный JSON", "{\"schemaVersion\":99}",
            "{\"schemaVersion\":1,\"snapshot\":null,\"tracking\":null}" })
        {
            File.WriteAllText(path, invalid);
            MonitorStateStore store = new(path);
            Require(store.Load() is { Document: null, Warning: not null },
                "Повреждённый или неизвестный формат должен возвращать явное предупреждение.");
            MonitorService service = new(_ => Snapshot(Certificate()), store);
            Require(service.InitializationWarning is not null && service.RunOnce().StateSaved,
                "Монитор должен восстановить работу после повреждения состояния.");
            Require(File.ReadAllText(path + ".invalid.json") == invalid && store.Load().Document is not null,
                "Повреждённый файл должен сохраняться отдельно перед заменой исправным.");
        }
        string occupied = Path.Combine(CreateCheckDirectory("write-failure"), "occupied.json");
        Directory.CreateDirectory(occupied);
        MonitorCycleResult failed = new MonitorService(_ => Snapshot(Certificate()), new MonitorStateStore(occupied)).RunOnce();
        Require(!failed.StateSaved && failed.PersistenceWarning is not null,
            "Ошибка записи настоящей файловой системы должна быть видна в результате.");
        Require(!Directory.EnumerateFiles(Path.GetDirectoryName(occupied)!, "*.tmp").Any(),
            "При отказе замены должен удаляться только временный файл текущей операции.");
    }

    private static void VerifySaveRetryAndConcurrency()
    {
        MemoryStore store = new() { FailNextSave = true };
        CertificateInventorySnapshot current = Snapshot(Certificate());
        MonitorService monitor = new(_ => current, store);
        Require(monitor.RunOnce() is { PersistenceWarning: not null, StateSaved: false, Changes.Count: 1 },
            "Ошибка сохранения не должна скрываться.");
        Require(monitor.RunOnce() is { PersistenceWarning: null, StateSaved: true, Changes.Count: 0 },
            "Повтор сохранения не должен повторять уведомление в текущем процессе.");
        Require(new MonitorService(_ => current, store).RunOnce().Changes.Count == 0,
            "После восстановления записи состояние должно подавлять уведомления при перезапуске.");
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        int writesBefore = store.SaveCount;
        try
        {
            monitor.RunOnce(cancellation.Token);
            throw new InvalidOperationException("Отмена цикла не сработала.");
        }
        catch (OperationCanceledException)
        {
            Require(store.SaveCount == writesBefore, "Отменённый цикл не должен менять сохранённое состояние.");
        }

        int active = 0;
        int maximum = 0;
        MonitorService serialized = new(_ =>
        {
            int count = Interlocked.Increment(ref active);
            maximum = Math.Max(maximum, count);
            Thread.Sleep(40);
            Interlocked.Decrement(ref active);
            return current;
        }, new MemoryStore());
        Task<MonitorCycleResult>[] tasks = Enumerable.Range(0, 3).Select(_ => Task.Run(() => serialized.RunOnce())).ToArray();
        Task.WaitAll(tasks);
        Require(maximum == 1 && tasks.Sum(task => task.Result.Changes.Count) == 1,
            "Конкурентные запросы должны читаться последовательно и не дублировать совпадение.");
    }

    private static void VerifyNotifications()
    {
        TrackedMatch match = new(Id, "Тестовый сертификат", "Российский", true, false, false, [Root]);
        Require(MonitorNotification.Create([new(MonitorChangeKind.Disappeared, match)]) is null,
            "Исчезновение записывается в журнал без предупреждения Windows.");
        Require(MonitorNotification.Create([new(MonitorChangeKind.Found, match)]) is { IsWarning: true },
            "Новое российское совпадение должно использовать предупреждение.");
        TrackedMatch blocked = match with { Locations = [Root, new(StoreLocation.CurrentUser, "Disallowed")] };
        Require(MonitorNotification.Create([new(MonitorChangeKind.Found, blocked)]) is { IsWarning: false },
            "Наблюдаемое Disallowed должно давать информационное сообщение.");
        TrackedMatch weak = match with { IsRussian = false, IsPossibleRussian = true };
        Require(MonitorNotification.Create([new(MonitorChangeKind.Found, weak)]) is { IsWarning: false },
            "Косвенный признак не должен получать предупреждение о подтверждённой принадлежности.");
        MonitorChange[] many = Enumerable.Range(0, 50).Select(index => new MonitorChange(MonitorChangeKind.Found,
            match with { DisplayName = new string('Я', 200) + index })).ToArray();
        MonitorNotification combined = MonitorNotification.Create(many)!;
        Require(combined.Title.Contains("50", StringComparison.Ordinal) && combined.Text.Length <= 240,
            "Множество совпадений должно группироваться в одно короткое уведомление.");
    }

    private static void VerifyWindowUpdates()
    {
        using MainForm form = new(CertificateCatalog.Load(), () => { });
        CertificateInventorySnapshot snapshot = Snapshot(Certificate());
        form.ShowSnapshot(snapshot);
        form.ShowScanFailure("Ошибка проверки");
        form.ShowSnapshot(snapshot with { ScannedAt = snapshot.ScannedAt.AddSeconds(10) });
        TabPage errorsPage = Controls(form).OfType<TabPage>().Single(page => page.Text.StartsWith("Ошибки чтения"));
        Require(errorsPage.Text == "Ошибки чтения (0)"
            && Controls(errorsPage).OfType<TextBox>().Single().Text.StartsWith("Ошибок чтения не зарегистрировано"),
            "Успешная проверка после ошибки должна очищать старую ошибку даже при том же содержимом снимка.");
    }

    private static IEnumerable<Control> Controls(Control parent)
    {
        foreach (Control child in parent.Controls)
        {
            yield return child;
            foreach (Control descendant in Controls(child))
                yield return descendant;
        }
    }

    private static InventoryCertificate Certificate()
    {
        byte[] name = new X500DistinguishedName("CN=Тест, C=RU").RawData;
        return new InventoryCertificate(new CertificateMetadata(Id, "Тест", "CN=Тест", "CN=Тест", "01",
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddYears(80), name, name, [1, 2, 3]),
            [Root], new CertificateClassification(true, false, false, ["Страна RU"], []), []);
    }

    private static CertificateInventorySnapshot Snapshot(params InventoryCertificate[] certificates) =>
        new(DateTimeOffset.UtcNow, certificates, [Root], [], certificates.Length);

    private static string CreateCheckDirectory(string name)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "global.json")))
            directory = directory.Parent;
        if (directory is null)
            throw new InvalidOperationException("Не найден корень проекта.");
        string path = Path.Combine(directory.FullName, "work", "checks", $"stage3-{name}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private sealed class MemoryStore : IMonitorStateStore
    {
        public MonitorStateDocument? Document { get; private set; }
        public bool FailNextSave { get; set; }
        public int SaveCount { get; private set; }
        public MonitorStateLoadResult Load() => new(Document, null);
        public void Save(MonitorStateDocument document)
        {
            SaveCount++;
            if (FailNextSave)
            {
                FailNextSave = false;
                throw new IOException("Тестовый отказ записи.");
            }
            Document = document;
        }
    }
}
