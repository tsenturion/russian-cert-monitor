using System.Reflection;
using System.Text.Json;

namespace RussianCertMonitor.Catalog;

internal sealed record CatalogCertificate(
    string CertificateId,
    string? Name,
    string Affiliation,
    string? Subject,
    string? Issuer,
    string? ValidFrom,
    string? ValidTo,
    bool WasPreviouslyDeleted = false);

internal sealed record CertificateCatalog(
    int SchemaVersion,
    string SourceDate,
    string SourceDescription,
    IReadOnlyList<CatalogCertificate> Certificates)
{
    public int KnownRussianCount => Certificates.Count(item => item.Affiliation == "russian");

    public static CertificateCatalog Load(string? localHistoryPath = null)
    {
        using Stream resource = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream("RussianCertMonitor.CertificateCatalog.json")
            ?? throw new InvalidDataException("Встроенный справочник сертификатов отсутствует.");

        CertificateCatalog catalog = ReadCatalog(resource, "Встроенный справочник сертификатов пуст.");
        Validate(catalog);

        if (localHistoryPath is null)
            return catalog;

        try
        {
            using FileStream history = new(localHistoryPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (history.Length > 2 * 1024 * 1024)
                throw new InvalidDataException("Локальный справочник превышает допустимый размер 2 МиБ.");
            CertificateCatalog local = ReadCatalog(history, "Локальная история сертификатов пуста.");
            Validate(local);

            Dictionary<string, CatalogCertificate> merged = catalog.Certificates
                .ToDictionary(item => item.CertificateId, StringComparer.OrdinalIgnoreCase);
            foreach (CatalogCertificate certificate in local.Certificates)
                merged[certificate.CertificateId] = merged.TryGetValue(certificate.CertificateId, out CatalogCertificate? existing)
                    ? existing with { WasPreviouslyDeleted = true }
                    : certificate with { WasPreviouslyDeleted = true };

            return catalog with { Certificates = merged.Values.ToArray() };
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
        {
            return catalog;
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new InvalidDataException("Не удалось прочитать локальную историю сертификатов.", error);
        }
    }

    private static CertificateCatalog ReadCatalog(Stream stream, string emptyMessage)
    {
        try
        {
            return JsonSerializer.Deserialize<CertificateCatalog>(
                stream, new JsonSerializerOptions(JsonSerializerDefaults.Web))
                ?? throw new InvalidDataException(emptyMessage);
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("Файл справочника сертификатов содержит некорректный JSON.", error);
        }
    }

    private static void Validate(CertificateCatalog catalog)
    {
        if (catalog.SchemaVersion != 1 || catalog.Certificates is null || catalog.Certificates.Count > 5000)
            throw new InvalidDataException("Неподдерживаемый формат справочника сертификатов.");

        HashSet<string> identifiers = new(StringComparer.OrdinalIgnoreCase);
        foreach (CatalogCertificate certificate in catalog.Certificates)
        {
            if (certificate is null || string.IsNullOrWhiteSpace(certificate.CertificateId)
                || certificate.CertificateId.Length != 40
                || !certificate.CertificateId.All(Uri.IsHexDigit)
                || !identifiers.Add(certificate.CertificateId))
                throw new InvalidDataException("В справочнике есть неверный или повторяющийся идентификатор.");

            if (certificate.Affiliation is not ("russian" or "unknown")
                || (certificate.Affiliation == "russian" && string.IsNullOrWhiteSpace(certificate.Name)))
                throw new InvalidDataException("В справочнике неверно указана принадлежность сертификата.");
        }
    }
}
