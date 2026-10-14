using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RussianCertMonitor.History;

internal sealed record HistoryEvent(DateTimeOffset Timestamp, string EventName, string Message,
    string? CertificateId = null, string? Location = null, string? Result = null);

internal sealed record HistoryReadResult(IReadOnlyList<HistoryEvent> Events,
    IReadOnlyList<string> Errors, bool Truncated);

internal sealed class HistoryStore(string directory)
{
    private const int MaximumLineBytes = 64 * 1024;
    private const long MaximumReadBytes = 4 * 1024 * 1024;
    private const int MaximumReturnedEvents = 1000;
    private const int MaximumErrors = 100;
    private static readonly Regex FileNamePattern = new(@"^History-(\d{4}-\d{2}-\d{2})\.jsonl$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly ConcurrentDictionary<string, object> Gates = new(StringComparer.OrdinalIgnoreCase);
    private readonly object gate = Gates.GetOrAdd(Path.GetFullPath(directory), static _ => new object());

    public void Append(HistoryEvent item)
    {
        byte[] line = JsonSerializer.SerializeToUtf8Bytes(item);
        if (line.Length > MaximumLineBytes)
            throw new ArgumentException("Событие истории превышает допустимый размер.", nameof(item));

        lock (gate)
        {
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, FileName(item.Timestamp.UtcDateTime.Date));
            using FileStream stream = new(path, FileMode.Append, FileAccess.Write, FileShare.Read);
            stream.Write(line);
            stream.WriteByte((byte)'\n');
            stream.Flush(true);
        }
    }

    public HistoryReadResult ReadRecent(int maximumEvents = MaximumReturnedEvents)
    {
        if (maximumEvents < 1)
            throw new ArgumentOutOfRangeException(nameof(maximumEvents));
        int limit = Math.Min(maximumEvents, MaximumReturnedEvents);
        List<string> errors = [];
        List<HistoryEvent> events = [];
        bool truncated = false;
        long remaining = MaximumReadBytes;
        lock (gate)
        {
            foreach ((DateOnly date, string path) in OwnFiles(errors).OrderByDescending(item => item.Date))
            {
                DateOnly today = DateOnly.FromDateTime(DateTime.UtcNow.Date);
                if (date > today)
                {
                    if (errors.Count < MaximumErrors)
                        errors.Add($"Файл истории датирован будущим: {Path.GetFileName(path)}.");
                    truncated = true;
                    continue;
                }
                if (date <= today.AddDays(-29))
                    continue;
                if (events.Count >= limit || remaining <= 0 || errors.Count >= MaximumErrors)
                {
                    truncated = true;
                    break;
                }
                try
                {
                    using FileStream stream = new(path, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);
                    long readBudget = Math.Min(remaining, stream.Length);
                    long budgetStart = stream.Length > readBudget ? stream.Length - readBudget : 0;
                    long end = Math.Min(stream.Length, budgetStart + readBudget);
                    if (stream.Length > readBudget)
                    {
                        stream.Position = budgetStart;
                        SkipPartialLine(stream, end);
                        truncated = true;
                    }
                    List<HistoryEvent> fromFile = [];
                    while (stream.Position < end && TryReadLine(stream, end, out byte[] line,
                        out bool oversized, out bool incomplete))
                    {
                        if (incomplete)
                        {
                            truncated = true;
                            break;
                        }
                        if (oversized)
                        {
                            errors.Add($"Слишком длинная строка истории: {Path.GetFileName(path)}.");
                            if (errors.Count >= MaximumErrors)
                            {
                                truncated = true;
                                break;
                            }
                            continue;
                        }
                        try
                        {
                            HistoryEvent? item = JsonSerializer.Deserialize<HistoryEvent>(line);
                            if (item is null || string.IsNullOrWhiteSpace(item.EventName))
                                throw new JsonException("Пустое событие.");
                            if (item.Timestamp > DateTimeOffset.UtcNow.AddMinutes(5))
                                throw new JsonException("Событие датировано будущим.");
                            fromFile.Add(item);
                            if (fromFile.Count > limit)
                            {
                                fromFile.RemoveAt(0);
                                truncated = true;
                            }
                        }
                        catch (Exception exception) when (exception is JsonException or NotSupportedException)
                        {
                            errors.Add($"Повреждена строка истории {Path.GetFileName(path)}: {exception.Message}");
                            if (errors.Count >= MaximumErrors)
                            {
                                truncated = true;
                                break;
                            }
                        }
                    }
                    remaining -= stream.Position - budgetStart;
                    foreach (HistoryEvent item in fromFile.AsEnumerable().Reverse())
                    {
                        if (events.Count >= limit)
                        {
                            truncated = true;
                            break;
                        }
                        events.Add(item);
                    }
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    errors.Add($"Не удалось прочитать историю {Path.GetFileName(path)}: {exception.Message}");
                }
            }
        }
        events.Reverse();
        return new HistoryReadResult(events, errors, truncated);
    }

    public void Prune()
    {
        lock (gate)
        {
            DateOnly oldestRetained = DateOnly.FromDateTime(DateTime.UtcNow.Date.AddDays(-29));
            List<string> errors = [];
            foreach ((DateOnly date, string path) in OwnFiles(errors))
            {
                if (date <= oldestRetained)
                    File.Delete(path);
            }
            if (errors.Count > 0)
                throw new IOException(errors[0]);
        }
    }

    private IEnumerable<(DateOnly Date, string Path)> OwnFiles(List<string> errors)
    {
        string[] paths;
        try { paths = Directory.GetFiles(directory, "History-*.jsonl", SearchOption.TopDirectoryOnly); }
        catch (DirectoryNotFoundException) { paths = []; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            errors.Add($"Не удалось перечислить файлы истории: {exception.Message}");
            paths = [];
        }
        foreach (string path in paths)
        {
            Match match = FileNamePattern.Match(Path.GetFileName(path));
            if (match.Success && DateOnly.TryParseExact(match.Groups[1].Value, "yyyy-MM-dd",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly date))
                yield return (date, path);
        }
    }

    private static string FileName(DateTime date) => $"History-{date:yyyy-MM-dd}.jsonl";

    private static void SkipPartialLine(Stream stream, long end)
    {
        while (stream.Position < end && stream.ReadByte() is int value && value >= 0 && value != '\n') { }
    }

    private static bool TryReadLine(Stream stream, long end, out byte[] line,
        out bool oversized, out bool incomplete)
    {
        using MemoryStream buffer = new();
        oversized = false;
        incomplete = false;
        int value = -1;
        while (stream.Position < end && (value = stream.ReadByte()) >= 0 && value != '\n')
        {
            if (buffer.Length < MaximumLineBytes)
                buffer.WriteByte((byte)value);
            else
                oversized = true;
        }
        if (stream.Position == end && end < stream.Length && value != '\n')
            incomplete = true;
        line = buffer.ToArray();
        return value >= 0 || line.Length > 0 || oversized;
    }
}
