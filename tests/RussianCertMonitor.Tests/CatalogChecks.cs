using System.Text.Json;
using RussianCertMonitor.Catalog;

namespace RussianCertMonitor.Tests;

internal static class CatalogChecks
{
    private const string LocalUnknownId = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    public static void Run()
    {
        CertificateCatalog publicCatalog = CertificateCatalog.Load();
        Require(publicCatalog.Certificates.Count == 33
            && publicCatalog.KnownRussianCount == 33
            && publicCatalog.Certificates.All(item => !item.WasPreviouslyDeleted)
            && publicCatalog.Certificates.All(item => item.Affiliation == "russian"),
            "Встроенный справочник должен содержать только 33 публичных российских УЦ.");

        using (Stream resource = typeof(CertificateCatalog).Assembly
            .GetManifestResourceStream("RussianCertMonitor.CertificateCatalog.json")
            ?? throw new InvalidOperationException("Встроенный JSON справочника отсутствует."))
        using (JsonDocument document = JsonDocument.Parse(resource))
        {
            JsonElement certificates = document.RootElement.GetProperty("certificates");
            foreach (JsonElement certificate in certificates.EnumerateArray())
            {
                Require(!certificate.TryGetProperty("deletionEventId", out _)
                    && !certificate.TryGetProperty("deletedAt", out _)
                    && !string.Equals(certificate.GetProperty("affiliation").GetString(), "unknown",
                        StringComparison.Ordinal),
                    "Встроенный справочник не должен включать локальные события или неизвестные ID.");
            }
        }

        string directory = Path.Combine(Path.GetTempPath(), $"rcm-catalog-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "history.json");
        try
        {
            Require(CertificateCatalog.Load(path).Certificates.Count == 33,
                "Отсутствие необязательной локальной истории не должно давать ошибку.");
            CatalogCertificate known = publicCatalog.Certificates[0];
            CatalogCertificate unknown = new(LocalUnknownId, null, "unknown", null, null, null, null);
            File.WriteAllText(path, MakeLocalJson([known, unknown]));
            CertificateCatalog merged = CertificateCatalog.Load(path);
            CatalogCertificate mergedKnown = merged.Certificates.Single(item => item.CertificateId == known.CertificateId);
            CatalogCertificate mergedUnknown = merged.Certificates.Single(item => item.CertificateId == LocalUnknownId);
            Require(mergedKnown.WasPreviouslyDeleted && mergedKnown.Affiliation == "russian"
                && mergedUnknown.WasPreviouslyDeleted && mergedUnknown.Affiliation == "unknown",
                "Локальная история должна помечать совпавший публичный ID и сохранять неизвестный ID.");

            File.WriteAllText(path, "");
            Reject(() => CertificateCatalog.Load(path));
            File.WriteAllText(path, "null");
            Reject(() => CertificateCatalog.Load(path));
            File.WriteAllText(path, "{\"schemaVersion\":1,\"sourceDate\":\"2026-10-15\",\"sourceDescription\":\"test\",\"certificates\":null}");
            Reject(() => CertificateCatalog.Load(path));
            File.WriteAllText(path, MakeLocalJson([unknown, unknown]));
            Reject(() => CertificateCatalog.Load(path));
            File.WriteAllText(path, "{\"schemaVersion\":1,\"certificates\":[null]}");
            Reject(() => CertificateCatalog.Load(path));
            File.WriteAllText(path, new string(' ', 2 * 1024 * 1024 + 1));
            Reject(() => CertificateCatalog.Load(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string MakeLocalJson(IReadOnlyList<CatalogCertificate> certificates) =>
        JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            sourceDate = "2020-01-01",
            sourceDescription = "Локальная история сертификатов",
            certificates = certificates.Select(item => new
            {
                certificateId = item.CertificateId,
                name = item.Name,
                affiliation = item.Affiliation,
                subject = item.Subject,
                issuer = item.Issuer,
                validFrom = item.ValidFrom,
                validTo = item.ValidTo,
                deletionEventId = 1,
                deletedAt = "2020-01-01T00:00:00+00:00"
            })
        });

    private static void Reject(Action action)
    {
        try { action(); }
        catch (InvalidDataException) { return; }
        throw new InvalidOperationException("Некорректная локальная история должна отклоняться.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
