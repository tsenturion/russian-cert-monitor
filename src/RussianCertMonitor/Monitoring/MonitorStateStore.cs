using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Text.Json;
using RussianCertMonitor.Inventory;

namespace RussianCertMonitor.Monitoring;

internal sealed record MonitorStateDocument(
    int SchemaVersion, DateTimeOffset SavedAt, CertificateInventorySnapshot Snapshot, MonitorTrackingState Tracking);

internal sealed record MonitorStateLoadResult(MonitorStateDocument? Document, string? Warning);

internal interface IMonitorStateStore
{
    MonitorStateLoadResult Load();
    void Save(MonitorStateDocument document);
}

internal sealed class MonitorStateStore(string filePath) : IMonitorStateStore
{
    private readonly string path = Path.GetFullPath(filePath);
    private readonly JsonSerializerOptions options = new(JsonSerializerDefaults.Web)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        IgnoreReadOnlyProperties = true
    };
    private bool preserveInvalidFile;

    public MonitorStateLoadResult Load()
    {
        try
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            MonitorStateDocument document = JsonSerializer.Deserialize<MonitorStateDocument>(stream, options)
                ?? throw new InvalidDataException("Файл состояния пуст.");
            Validate(document);
            return new MonitorStateLoadResult(document, null);
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
        {
            return new MonitorStateLoadResult(null, null);
        }
        catch (Exception error) when (error is IOException or InvalidDataException
            or UnauthorizedAccessException or JsonException)
        {
            preserveInvalidFile = error is JsonException or InvalidDataException;
            return new MonitorStateLoadResult(null,
                "Предыдущее состояние не прочитано. Подавление уведомлений начнётся заново. " + error.Message);
        }
    }

    public void Save(MonitorStateDocument document)
    {
        Validate(document);
        string directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);
        if (preserveInvalidFile)
        {
            File.Copy(path, path + ".invalid.json", overwrite: true);
            preserveInvalidFile = false;
        }

        string temporaryPath = path + $".{Guid.NewGuid():N}.tmp";
        try
        {
            using (FileStream stream = new(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(stream, document, options);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            // Удаляется только временный файл этой операции, если замена не состоялась.
            try
            {
                File.Delete(temporaryPath);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                System.Diagnostics.Debug.WriteLine($"Временный файл состояния не удалён: {error.Message}");
            }
        }
    }

    private static void Validate(MonitorStateDocument document)
    {
        if (document.SchemaVersion != 1 || document.Snapshot is null || document.Tracking?.Matches is null)
            throw new InvalidDataException("Неподдерживаемый формат состояния мониторинга.");
        CertificateInventorySnapshot snapshot = document.Snapshot;
        if (snapshot.Certificates is null || snapshot.Stores is null || snapshot.Issues is null
            || snapshot.ObservationCount < snapshot.Certificates.Count)
            throw new InvalidDataException("Повреждён снимок хранилищ.");

        HashSet<string> ids = new(StringComparer.OrdinalIgnoreCase);
        foreach (TrackedMatch? match in document.Tracking.Matches)
        {
            if (match is null || !IsId(match.CertificateId) || !ids.Add(match.CertificateId)
                || match.DisplayName is null || match.Category is null || match.Locations is null
                || !(match.IsRussian || match.IsPossibleRussian || match.WasPreviouslyDeleted))
                throw new InvalidDataException("Повреждена запись отслеживания совпадения.");
            ValidateStores(match.Locations);
        }
        ids.Clear();
        foreach (InventoryCertificate? certificate in snapshot.Certificates)
        {
            CertificateMetadata? metadata = certificate?.Metadata;
            if (metadata is null || !IsId(metadata.CertificateId) || !ids.Add(metadata.CertificateId)
                || metadata.DisplayName is null || metadata.Subject is null || metadata.Issuer is null
                || metadata.SerialNumber is null || metadata.SubjectNameRaw is null
                || metadata.IssuerNameRaw is null || metadata.RawData is null
                || certificate!.Locations is null || certificate.Classification?.Reasons is null
                || certificate.Classification.Errors is null || certificate.ReadErrors is null
                || (certificate.Trust is not null
                    && (certificate.Trust.CurrentUser is null || certificate.Trust.LocalMachine is null)))
                throw new InvalidDataException("Повреждены данные сертификата в снимке.");
            ValidateStores(certificate.Locations);
        }
        ValidateStores(snapshot.Stores);
        if (snapshot.Issues.Any(issue => issue is null || issue.Location is null || issue.Message is null))
            throw new InvalidDataException("Повреждён список ошибок снимка.");
    }

    private static bool IsId(string? id) => id is { Length: 40 } && id.All(Uri.IsHexDigit);

    private static void ValidateStores(IEnumerable<CertificateStoreDescriptor> stores)
    {
        if (stores.Any(store => store is null || string.IsNullOrWhiteSpace(store.Name)
            || store.Location is not (StoreLocation.CurrentUser or StoreLocation.LocalMachine)))
            throw new InvalidDataException("Повреждено расположение хранилища.");
    }
}
