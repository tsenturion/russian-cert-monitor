using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using RussianCertMonitor.History;

namespace RussianCertMonitor.Infrastructure;

internal sealed class DiagnosticLog
{
    private const string FilePrefix = "RussianCertMonitor-";
    private readonly object writeLock = new();
    private HistoryStore? history;
    private readonly Dictionary<string, string> lastHistoryErrors = new(StringComparer.Ordinal);
    public string? HistoryWarning { get; private set; }
    public string? DiagnosticWarning { get; private set; }
    public string? RetentionWarning { get; private set; }
    public long HistoryRevision { get; private set; }
    private readonly JsonSerializerOptions options = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public string DirectoryPath { get; }

    public DiagnosticLog(string directoryPath)
    {
        DirectoryPath = Path.GetFullPath(directoryPath);
        try { Directory.CreateDirectory(DirectoryPath); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            DiagnosticWarning = "Папка диагностического журнала недоступна. " + ErrorText.Describe(error);
        }
        Prune();
    }

    public void AttachHistory(HistoryStore store)
    {
        lock (writeLock)
        {
            history = store;
            HistoryWarning = null;
        }
    }

    public void SetHistoryWarning(string warning)
    {
        lock (writeLock)
            HistoryWarning = warning;
    }

    public void Write(string eventName, string message, Exception? exception = null, LogContext? context = null)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string record = JsonSerializer.Serialize(new
        {
            timestamp = now,
            processId = Environment.ProcessId,
            eventName,
            message,
            exception = exception?.ToString(),
            certificateId = context?.CertificateId,
            location = context?.Location,
            result = context?.Result
        }, options);

        string filePath = Path.Combine(DirectoryPath,
            $"{FilePrefix}{now:yyyy-MM-dd}-{Environment.ProcessId}.jsonl");

        lock (writeLock)
        {
            AppendHistory(now, eventName, message, exception, context);
            File.AppendAllText(filePath, record + Environment.NewLine, new UTF8Encoding(false));
            DiagnosticWarning = null;
        }
    }

    public void TryWrite(string eventName, string message, Exception? exception = null, LogContext? context = null)
    {
        try
        {
            Write(eventName, message, exception, context);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            DiagnosticWarning = "Диагностический журнал не сохранён. " + ErrorText.Describe(error);
            System.Diagnostics.Debug.WriteLine($"Журнал недоступен: {error.Message}");
        }
    }

    private void AppendHistory(DateTimeOffset timestamp, string eventName, string message,
        Exception? exception, LogContext? context)
    {
        if (history is null || !(eventName is "application.started" or "application.stopped"
            or "monitor.match-changed" or "monitor.coverage-changed" or "settings.saved" or "report.exported"
            or "inventory.failed" or "inventory.recovered" or "certificate.exported"
            || eventName.StartsWith("disallowed.", StringComparison.Ordinal)
            || eventName.EndsWith("-error", StringComparison.Ordinal)
            || eventName.EndsWith("-recovered", StringComparison.Ordinal)))
            return;
        string detail = exception is null ? message : message + " " + ErrorText.Describe(exception);
        // Повтор одной ошибки не заполняет историю на каждом цикле проверки.
        bool isError = eventName.EndsWith("-error", StringComparison.Ordinal) || eventName == "inventory.failed";
        if (isError && lastHistoryErrors.TryGetValue(eventName, out string? previous) && previous == detail)
            return;
        try
        {
            string bounded = detail.Length > 6000 ? detail[..6000] + " … Запись сокращена; подробности в диагностическом журнале." : detail;
            history.Append(new HistoryEvent(timestamp, eventName, bounded, context?.CertificateId,
                context?.Location is { Length: > 2000 } location ? location[..2000] : context?.Location, context?.Result));
            if (isError)
                lastHistoryErrors[eventName] = detail;
            else if (eventName == "inventory.recovered")
                lastHistoryErrors.Remove("inventory.failed");
            else if (eventName.EndsWith("-recovered", StringComparison.Ordinal))
                lastHistoryErrors.Remove(eventName[..^10] + "-error");
            HistoryWarning = null;
            HistoryRevision++;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
        {
            HistoryWarning = "История событий не сохранена. " + ErrorText.Describe(error);
            System.Diagnostics.Debug.WriteLine(HistoryWarning);
        }
    }

    public void Prune()
    {
        RetentionWarning = null;
        // Запас в один календарный день удерживает журналы в пределах 30 дней между проверками.
        DateOnly cutoff = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-29));
        string[] files;
        try { files = Directory.GetFiles(DirectoryPath, $"{FilePrefix}*.jsonl"); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            RetentionWarning = "Не удалось проверить срок хранения диагностических журналов. " + ErrorText.Describe(error);
            TryWrite("log.retention-error", RetentionWarning, error);
            return;
        }
        foreach (string filePath in files)
        {
            string fileName = Path.GetFileName(filePath);
            string remainder = fileName[FilePrefix.Length..];
            if (remainder.Length < 17 || remainder[10] != '-')
                continue;

            string processId = remainder[11..^6];
            if (!int.TryParse(processId, out _)
                || !DateOnly.TryParseExact(remainder[..10], "yyyy-MM-dd",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly date)
                || date > cutoff)
                continue;

            try
            {
                File.Delete(filePath);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                RetentionWarning = "Не удалось удалить старые диагностические журналы. " + ErrorText.Describe(error);
                TryWrite("log.retention-error", "Не удалось удалить старый журнал приложения.", error);
            }
        }
    }
}

internal sealed record LogContext(string? CertificateId = null, string? Location = null, string? Result = null);
