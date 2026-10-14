using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using RussianCertMonitor.Infrastructure;

namespace RussianCertMonitor.Settings;

internal sealed record SettingsLoadResult(MonitorSettings Settings, string? Warning);

internal sealed class SettingsStore(string filePath)
{
    private const int MaximumBytes = 256 * 1024;
    public static JsonSerializerOptions JsonOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public string FilePath { get; } = Path.GetFullPath(filePath);

    public SettingsLoadResult Load()
    {
        try
        {
            using FileStream stream = new(FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (stream.Length > MaximumBytes)
                throw new InvalidDataException("Файл настроек превышает 256 КБ.");
            using MemoryStream content = new();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = stream.Read(buffer)) > 0)
            {
                if (content.Length + read > MaximumBytes)
                    throw new InvalidDataException("Файл настроек превышает 256 КБ.");
                content.Write(buffer, 0, read);
            }
            ReadOnlySpan<byte> json = content.ToArray();
            if (json.StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
                json = json[3..];
            using JsonDocument document = JsonDocument.Parse(json.ToArray());
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("Настройки должны быть объектом JSON.");
            HashSet<string> names = new(StringComparer.Ordinal);
            foreach (JsonProperty property in document.RootElement.EnumerateObject())
                if (!names.Add(property.Name))
                    throw new InvalidDataException($"Повторяющееся поле настроек: {property.Name}.");
            MonitorSettings settings = JsonSerializer.Deserialize<MonitorSettings>(json, JsonOptions)
                ?? throw new InvalidDataException("Файл настроек пуст.");
            return new(settings.Validate(), null);
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
        {
            return new(MonitorSettings.Default, null);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            return new(MonitorSettings.Default, "Настройки не прочитаны; действуют стандартные параметры. " + ErrorText.Describe(error));
        }
    }

    public void Save(MonitorSettings settings)
    {
        string json = JsonSerializer.Serialize(settings.Validate(), JsonOptions);
        if (Encoding.UTF8.GetByteCount(json) > MaximumBytes)
            throw new InvalidDataException("Настройки превышают допустимый размер 256 КБ.");
        string directory = Path.GetDirectoryName(FilePath)!;
        Directory.CreateDirectory(directory);
        string temporary = Path.Combine(directory, $".settings-{Guid.NewGuid():N}.tmp");
        try
        {
            using (FileStream stream = new(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                byte[] bytes = Encoding.UTF8.GetBytes(json);
                stream.Write(bytes);
                stream.Flush(true);
            }
            File.Move(temporary, FilePath, true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }
}
