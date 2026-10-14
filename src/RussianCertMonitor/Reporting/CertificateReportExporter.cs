using System.Reflection;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using RussianCertMonitor.History;
using RussianCertMonitor.Inventory;

namespace RussianCertMonitor.Reporting;

internal sealed record CertificateReportContext(CertificateInventorySnapshot? Snapshot,
    string? ScanFailure, string? PersistenceWarning, string? SettingsWarning,
    bool SnapshotRestored = false);

internal static class CertificateReportExporter
{
    private static readonly string[] ScopeNotes =
    [
        "Наблюдения относятся к логическим хранилищам CurrentUser и LocalMachine.",
        "CurrentUser может наследовать сертификаты LocalMachine.",
        "Disallowed действует для проверки сертификатов через Windows validation API; отдельные хранилища Firefox и Java не проверялись."
    ];
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static void WriteJson(string path, CertificateReportContext context,
        HistoryReadResult history, object settings)
    {
        byte[] data = JsonSerializer.SerializeToUtf8Bytes(CreateReport(context, history, settings), JsonOptions);
        WriteAtomically(path, data);
    }

    public static void WriteText(string path, CertificateReportContext context,
        HistoryReadResult history, object settings)
    {
        StringBuilder text = new();
        text.AppendLine("Отчёт о сертификатах");
        text.AppendLine($"Версия приложения: {ApplicationVersion()}");
        text.AppendLine($"Создан: {DateTimeOffset.UtcNow:O}");
        text.AppendLine($"Состояние сканирования: {TextScanStatus(context)}");
        text.AppendLine($"Сканирование неполное: {Bool(ScanIncomplete(context))}");
        text.AppendLine($"Снимок восстановлен: {(context.SnapshotRestored ? "да" : "нет")}");
        text.AppendLine($"Время снимка: {context.Snapshot?.ScannedAt.ToString("O") ?? "нет"}");
        foreach (string note in ScopeNotes)
            text.AppendLine(note);
        AddWarning(text, "Ошибка сканирования", context.ScanFailure);
        AddWarning(text, "Предупреждение о сохранении", context.PersistenceWarning);
        AddWarning(text, "Предупреждение о настройках", context.SettingsWarning);
        text.AppendLine();
        text.AppendLine("Настройки:");
        text.AppendLine(JsonSerializer.Serialize(settings, JsonOptions));

        CertificateInventorySnapshot? snapshot = context.Snapshot;
        if (snapshot is not null)
        {
            text.AppendLine();
            text.AppendLine($"Сертификатов: {snapshot.Certificates.Count}; наблюдений: {snapshot.ObservationCount}; " +
                $"российских: {snapshot.RussianCount}; косвенных: {snapshot.PossibleCount}; " +
                $"ранее удалённых без установленной принадлежности: {snapshot.HistoricalUnknownCount}.");
            text.AppendLine($"Хранилищ: {snapshot.Stores.Count}; проблем сканирования: {snapshot.Issues.Count}.");
            foreach (CertificateStoreDescriptor store in snapshot.Stores)
                text.AppendLine($"  Хранилище: {store.Path}");
            foreach (InventoryIssue issue in snapshot.Issues)
                text.AppendLine($"  Проблема [{issue.Location}]: {issue.Message}");
            foreach (InventoryCertificate item in snapshot.Certificates)
            {
                text.AppendLine();
                text.AppendLine($"Сертификат: {item.Metadata.DisplayName} ({item.Metadata.CertificateId})");
                text.AppendLine($"  Субъект: {item.Metadata.Subject}");
                text.AppendLine($"  Издатель: {item.Metadata.Issuer}");
                text.AppendLine($"  Серийный номер: {item.Metadata.SerialNumber}");
                text.AppendLine($"  Действует с: {item.Metadata.NotBefore:O}; до: {item.Metadata.NotAfter:O}");
                text.AppendLine($"  Категория: {item.Category}; статус: {item.DisallowedStatus}");
                text.AppendLine($"  Российский: {Bool(item.Classification.IsRussian)}; косвенные признаки: {Bool(item.Classification.IsPossibleRussian)}; ранее удалён: {Bool(item.Classification.WasPreviouslyDeleted)}");
                text.AppendLine($"  Исключён из уведомлений: {Bool(item.Classification.IsExcluded)}");
                foreach (CertificateStoreDescriptor location in item.Locations)
                    text.AppendLine($"  Расположение: {location.Path}");
                foreach (string reason in item.Classification.Reasons)
                    text.AppendLine($"  Причина: {reason}");
                foreach (string error in item.Classification.Errors)
                    text.AppendLine($"  Ошибка классификации: {error}");
                foreach (string error in item.ReadErrors)
                    text.AppendLine($"  Ошибка чтения: {error}");
            }
        }
        text.AppendLine();
        text.AppendLine($"История: {history.Events.Count} событий; ограничена: {Bool(history.Truncated)}; ошибок: {history.Errors.Count}.");
        foreach (string error in history.Errors)
            text.AppendLine($"  Ошибка истории: {error}");
        foreach (HistoryEvent item in history.Events)
            text.AppendLine($"  {item.Timestamp:O} | {item.EventName} | {item.Message} | сертификат: {item.CertificateId ?? "—"} | расположение: {item.Location ?? "—"} | результат: {item.Result ?? "—"}");
        WriteAtomically(path, new UTF8Encoding(false).GetBytes(text.ToString()));
    }

    private static object CreateReport(CertificateReportContext context, HistoryReadResult history, object settings)
    {
        CertificateInventorySnapshot? snapshot = context.Snapshot;
        return new
        {
            ApplicationVersion = ApplicationVersion(),
            GeneratedAt = DateTimeOffset.UtcNow,
            ScanStatus = ScanStatus(context),
            ScanIncomplete = ScanIncomplete(context),
            SnapshotStale = SnapshotStale(context),
            context.SnapshotRestored,
            SnapshotScannedAt = snapshot?.ScannedAt,
            context.ScanFailure,
            context.PersistenceWarning,
            context.SettingsWarning,
            ScopeNotes,
            Settings = settings,
            Inventory = snapshot is null ? null : new
            {
                snapshot.IsComplete,
                snapshot.ObservationCount,
                UniqueCount = snapshot.Certificates.Count,
                snapshot.RussianCount,
                snapshot.PossibleCount,
                snapshot.HistoricalUnknownCount,
                Stores = snapshot.Stores.Select(item => new { item.Location, item.Name, item.Path }),
                snapshot.Issues,
                Certificates = snapshot.Certificates.Select(item => new
                {
                    item.Metadata.CertificateId,
                    item.Metadata.DisplayName,
                    item.Metadata.Subject,
                    item.Metadata.Issuer,
                    item.Metadata.SerialNumber,
                    item.Metadata.NotBefore,
                    item.Metadata.NotAfter,
                    Locations = item.Locations.Select(location => new { location.Location, location.Name, location.Path }),
                    item.Category,
                    item.DisallowedStatus,
                    item.Classification.IsRussian,
                    item.Classification.IsPossibleRussian,
                    item.Classification.WasPreviouslyDeleted,
                    ExcludedFromNotifications = item.Classification.IsExcluded,
                    item.Classification.Reasons,
                    ClassificationErrors = item.Classification.Errors,
                    item.ReadErrors
                })
            },
            History = new { history.Events, history.Errors, history.Truncated }
        };
    }

    private static void WriteAtomically(string path, byte[] data)
    {
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(directory);
        string temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllBytes(temporary, data);
            File.Move(temporary, fullPath, true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    private static void AddWarning(StringBuilder text, string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            text.AppendLine($"{label}: {value}");
    }

    private static string Bool(bool value) => value ? "да" : "нет";

    private static string ApplicationVersion() =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "неизвестна";

    private static string ScanStatus(CertificateReportContext context) =>
        context.Snapshot is null ? "unavailable"
        : SnapshotStale(context) ? "stale"
        : !context.Snapshot.IsComplete ? "incomplete" : "complete";

    private static string TextScanStatus(CertificateReportContext context) => ScanStatus(context) switch
    {
        "complete" => "полная",
        "incomplete" => "неполная",
        "stale" => "предыдущие данные, могут быть устаревшими",
        _ => "снимок отсутствует"
    };

    private static bool SnapshotStale(CertificateReportContext context) =>
        context.Snapshot is not null && (context.SnapshotRestored || context.ScanFailure is not null);

    private static bool ScanIncomplete(CertificateReportContext context) =>
        context.Snapshot is null || !context.Snapshot.IsComplete || context.ScanFailure is not null;
}
