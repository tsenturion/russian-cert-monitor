using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using RussianCertMonitor.Classification;
using RussianCertMonitor.History;
using RussianCertMonitor.Inventory;
using RussianCertMonitor.Reporting;

namespace RussianCertMonitor.Tests;

internal static class Stage5DataChecks
{
    public static void Run()
    {
        string directory = Path.Combine(Path.GetTempPath(), "RussianCertMonitor-Stage5-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            HistoryStore store = new(directory);
            DateTimeOffset today = DateTimeOffset.UtcNow;
            store.Append(new HistoryEvent(today, "scan", "Проверка", "ID", "CurrentUser\\Root", "ok"));
            store.Append(new HistoryEvent(today.AddMinutes(1), "scan", "Повторная проверка"));
            File.WriteAllText(Path.Combine(directory, $"History-{today.AddDays(-30):yyyy-MM-dd}.jsonl"), "старое");
            string foreign = Path.Combine(directory, "History-unknown.jsonl");
            File.WriteAllText(foreign, "постороннее");
            store.Prune();
            Require(!File.Exists(Path.Combine(directory, $"History-{today.AddDays(-30):yyyy-MM-dd}.jsonl"))
                && File.Exists(foreign), "Очистка должна удалять только устаревшие собственные файлы.");

            string current = Path.Combine(directory, $"History-{today:yyyy-MM-dd}.jsonl");
            File.AppendAllText(current, "{ повреждено\n");
            File.AppendAllText(current, new string('x', 70 * 1024) + "\n");
            HistoryReadResult damaged = store.ReadRecent();
            Require(damaged.Events.Count == 2 && damaged.Errors.Count == 2,
                "Повреждённая или слишком длинная строка не должна скрывать остальные события.");
            HistoryReadResult limited = store.ReadRecent(1);
            Require(limited.Events.Count == 1 && limited.Truncated,
                "Лимит чтения должен отмечаться в результате.");

            byte[] marker = [0x0A, 0x0B, 0x0C, 0x0D];
            CertificateMetadata metadata = new("CERT-ID", "Тест", "CN=Тест", "CN=Издатель", "123",
                today.AddDays(-1), today.AddDays(1), marker, marker, marker);
            InventoryCertificate certificate = new(metadata,
                [new CertificateStoreDescriptor(StoreLocation.CurrentUser, "Root")],
                new CertificateClassification(true, false, false, ["Признак"], ["Ошибка классификации"], true),
                ["Ошибка чтения"]);
            CertificateInventorySnapshot snapshot = new(today.AddDays(-1), [certificate],
                [new CertificateStoreDescriptor(StoreLocation.CurrentUser, "Root")],
                [new InventoryIssue("CurrentUser\\Root", "Нет доступа")], 1);
            string json = Path.Combine(directory, "report.json");
            string txt = Path.Combine(directory, "report.txt");
            CertificateReportContext context = new(snapshot, "Сканирование прервано", "Сохранение не удалось",
                "Настройки неполны", true);
            CertificateReportExporter.WriteJson(json, context, damaged, new { Mode = "test" });
            CertificateReportExporter.WriteText(txt, context, damaged, new { Mode = "test" });
            string jsonText = File.ReadAllText(json);
            string text = File.ReadAllText(txt);
            using JsonDocument report = JsonDocument.Parse(jsonText);
            Require(report.RootElement.GetProperty("ScanStatus").GetString() == "stale"
                && report.RootElement.GetProperty("Inventory").GetProperty("IsComplete").GetBoolean() == false
                && report.RootElement.GetProperty("History").GetProperty("Errors").GetArrayLength() > 0,
                "Отчёт должен показывать давность, неполноту и ошибки.");
            Require(jsonText.Contains("ExcludedFromNotifications") && jsonText.Contains("IsRussian")
                && text.Contains("Исключён из уведомлений: да") && text.Contains("Российский: да"),
                "Исключение из уведомлений не должно стирать классификацию.");
            Require(text.Contains("Состояние сканирования: предыдущие данные, могут быть устаревшими")
                && text.Contains("CurrentUser может наследовать сертификаты LocalMachine")
                && text.Contains("Firefox и Java не проверялись")
                && jsonText.Contains("ScopeNotes"),
                "Отчёт должен пояснять давность и границы проверки.");
            Require(!jsonText.Contains("RawData") && !jsonText.Contains("SubjectNameRaw")
                && !jsonText.Contains("IssuerNameRaw"), "Бинарные поля не должны попадать в отчёт.");
            object recursiveSettings = new RecursiveSettings();
            try
            {
                CertificateReportExporter.WriteJson(json, context, damaged, recursiveSettings);
                throw new InvalidOperationException("Сериализация рекурсивных настроек неожиданно прошла.");
            }
            catch (JsonException) { }
            Require(File.ReadAllText(json) == jsonText,
                "Ошибка сериализации не должна заменять готовый отчёт.");
            CertificateReportContext failedScan = new(snapshot with { Issues = [] },
                "Новая проверка завершилась ошибкой", null, null);
            CertificateReportExporter.WriteJson(json, failedScan, damaged, new { Mode = "test" });
            CertificateReportExporter.WriteText(txt, failedScan, damaged, new { Mode = "test" });
            using JsonDocument failedReport = JsonDocument.Parse(File.ReadAllText(json));
            Require(failedReport.RootElement.GetProperty("ScanStatus").GetString() == "stale"
                && failedReport.RootElement.GetProperty("SnapshotStale").GetBoolean()
                && failedReport.RootElement.GetProperty("ScanIncomplete").GetBoolean()
                && !failedReport.RootElement.GetProperty("SnapshotRestored").GetBoolean()
                && File.ReadAllText(txt).Contains("Состояние сканирования: предыдущие данные, могут быть устаревшими"),
                "Ошибка новой проверки должна отмечать предыдущий снимок как устаревший.");
            CertificateReportExporter.WriteJson(json, new CertificateReportContext(null, "Ошибка", null, null),
                damaged, new { Mode = "test" });
            Require(JsonDocument.Parse(File.ReadAllText(json)).RootElement.GetProperty("ScanStatus").GetString()
                == "unavailable", "Отсутствие снимка должно отражаться явно.");
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private sealed class RecursiveSettings
    {
        public RecursiveSettings Self => this;
    }
}
