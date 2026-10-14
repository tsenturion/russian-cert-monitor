using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Classification;

namespace RussianCertMonitor.Inventory;

internal sealed record CertificateStoreDescriptor(StoreLocation Location, string Name)
{
    public string Path => $"{Location}\\{Name}";
}

internal sealed record CertificateMetadata(
    string CertificateId, string DisplayName, string Subject, string Issuer, string SerialNumber,
    DateTimeOffset? NotBefore, DateTimeOffset? NotAfter,
    byte[] SubjectNameRaw, byte[] IssuerNameRaw, byte[] RawData);

internal sealed record CertificateObservation(
    CertificateMetadata Metadata, IReadOnlyList<string> Errors);

internal sealed record InventoryIssue(string Location, string Message);

internal sealed record CertificateStoreReadResult(
    IReadOnlyList<CertificateObservation> Certificates, IReadOnlyList<string> Errors);

internal sealed record InventoryCertificate(
    CertificateMetadata Metadata, IReadOnlyList<CertificateStoreDescriptor> Locations,
    CertificateClassification Classification, IReadOnlyList<string> ReadErrors)
{
    public bool NeedsAttention => Classification.IsRussian || Classification.IsPossibleRussian
        || Classification.WasPreviouslyDeleted;

    public string Category => Classification.IsRussian ? "Российский"
        : Classification.IsPossibleRussian ? "Косвенные признаки"
        : Classification.WasPreviouslyDeleted ? "Ранее удалён; принадлежность неизвестна"
        : "Без совпадений";

    public string DisallowedStatus
    {
        get
        {
            bool user = Locations.Any(item => item.Location == StoreLocation.CurrentUser
                && item.Name.Equals("Disallowed", StringComparison.OrdinalIgnoreCase));
            bool machine = Locations.Any(item => item.Location == StoreLocation.LocalMachine
                && item.Name.Equals("Disallowed", StringComparison.OrdinalIgnoreCase));
            return (user, machine) switch
            {
                (true, true) => "Disallowed: пользователь и компьютер",
                (true, false) => "Disallowed: пользователь",
                (false, true) => "Disallowed: компьютер",
                _ => "Не обнаружен в Disallowed"
            };
        }
    }

    public string ValidityStatus(DateTimeOffset now) => Metadata.NotBefore is null || Metadata.NotAfter is null
        ? "Срок не прочитан"
        : now < Metadata.NotBefore ? "Ещё не действует"
        : now > Metadata.NotAfter ? "Истёк"
        : "Действует";
}

internal sealed record CertificateInventorySnapshot(
    DateTimeOffset ScannedAt, IReadOnlyList<InventoryCertificate> Certificates,
    IReadOnlyList<CertificateStoreDescriptor> Stores, IReadOnlyList<InventoryIssue> Issues,
    int ObservationCount)
{
    public bool IsComplete => Issues.Count == 0;
    public int RussianCount => Certificates.Count(item => item.Classification.IsRussian);
    public int PossibleCount => Certificates.Count(item => !item.Classification.IsRussian
        && item.Classification.IsPossibleRussian);
    public int HistoricalUnknownCount => Certificates.Count(item => item.Classification.WasPreviouslyDeleted
        && !item.Classification.IsRussian && !item.Classification.IsPossibleRussian);
}

internal interface ICertificateStoreProvider
{
    IReadOnlyList<CertificateStoreDescriptor> EnumerateStores(StoreLocation location);
    CertificateStoreReadResult ReadStore(CertificateStoreDescriptor store);
}
