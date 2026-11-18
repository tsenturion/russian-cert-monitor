using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Text.Json;
using RussianCertMonitor.Catalog;
using RussianCertMonitor.Classification;
using RussianCertMonitor.Inventory;

namespace RussianCertMonitor.Tests;

internal static class InventoryChecks
{
    public static void Run()
    {
        CertificateStoreDescriptor userRoot = new(StoreLocation.CurrentUser, "Root");
        CertificateStoreDescriptor machineRoot = new(StoreLocation.LocalMachine, "Root");
        CertificateStoreDescriptor userDisallowed = new(StoreLocation.CurrentUser, "Disallowed");
        CertificateStoreDescriptor machineDisallowed = new(StoreLocation.LocalMachine, "Disallowed");
        CertificateStoreDescriptor custom = new(StoreLocation.LocalMachine, "Нестандартное хранилище");
        CertificateObservation shared = Observation("1111111111111111111111111111111111111111");
        CertificateObservation expired = Observation("2222222222222222222222222222222222222222") with
        {
            Metadata = shared.Metadata with
            {
                CertificateId = "2222222222222222222222222222222222222222",
                NotBefore = DateTimeOffset.UtcNow.AddYears(-5), NotAfter = DateTimeOffset.UtcNow.AddYears(-1)
            }
        };
        FakeProvider complete = new(new Dictionary<CertificateStoreDescriptor, CertificateStoreReadResult>
        {
            [userRoot] = Result(shared), [machineRoot] = Result(shared),
            [userDisallowed] = Result(shared), [machineDisallowed] = Result(expired),
            [custom] = Result(expired)
        });
        CertificateInventorySnapshot snapshot = Service(complete).Scan();
        Require(snapshot.IsComplete && snapshot.ObservationCount == 5 && snapshot.Certificates.Count == 2,
            "Одинаковый сертификат в нескольких логических хранилищах должен объединяться.");
        InventoryCertificate certificate = snapshot.Certificates.Single(item => item.Metadata.CertificateId == shared.Metadata.CertificateId);
        Require(certificate.Locations.Count == 3, "После объединения должны сохраняться все расположения.");
        Require(certificate.DisallowedStatus == "Disallowed: пользователь",
            "Наличие в CurrentUser Disallowed не должно превращаться в блокировку компьютера.");
        InventoryCertificate expiredResult = snapshot.Certificates.Single(item => item.Metadata.CertificateId == expired.Metadata.CertificateId);
        Require(expiredResult.ValidityStatus(DateTimeOffset.UtcNow) == "Истёк"
            && expiredResult.DisallowedStatus == "Disallowed: компьютер",
            "Просроченный сертификат должен оставаться в инвентаре с точным расположением Disallowed.");
        Require(snapshot.Stores.Contains(custom), "Нестандартные хранилища должны учитываться.");

        complete.FailedStore = machineRoot;
        CertificateInventorySnapshot partial = Service(complete).Scan();
        Require(!partial.IsComplete && partial.Issues.Count == 1 && partial.Certificates.Count == 2
            && partial.ObservationCount == 4, "Ошибка отдельного хранилища должна давать неполный результат, сохраняя остальные.");
        complete.FailedStore = null;
        complete.FailedScope = StoreLocation.CurrentUser;
        partial = Service(complete).Scan();
        Require(!partial.IsComplete && partial.Stores.Count == 3 && partial.Certificates.Count == 2,
            "Ошибка перечисления CurrentUser не должна прерывать проверку LocalMachine.");

        FakeProvider damaged = new(new Dictionary<CertificateStoreDescriptor, CertificateStoreReadResult>
        {
            [userRoot] = new([shared with { Errors = ["Ошибка чтения срока"] }], ["Сертификат без идентификатора пропущен."]),
            [machineRoot] = Result(Observation("3333333333333333333333333333333333333333") with
            {
                Metadata = shared.Metadata with
                {
                    CertificateId = "3333333333333333333333333333333333333333", SubjectNameRaw = [0x01]
                }
            })
        });
        partial = Service(damaged).Scan();
        Require(!partial.IsComplete && partial.Issues.Count == 3 && partial.Certificates.Count == 2,
            "Пропущенный сертификат, ошибка поля и повреждённый DER должны отражаться в неполном результате.");

        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        try
        {
            Service(complete).Scan(cancellation.Token);
            throw new InvalidOperationException("Отмена чтения не сработала.");
        }
        catch (OperationCanceledException)
        {
            // Завершение приложения не должно ожидать следующего хранилища.
        }
    }

    public static void WriteLiveSnapshot(bool checkTrust)
    {
        CertificateInventorySnapshot snapshot = new CertificateInventoryService(new WindowsCertificateStoreProvider(),
            new RussianCertificateClassifier(CertificateCatalog.Load()), verifyWindowsTrust: checkTrust).Scan();
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            snapshot.ScannedAt, snapshot.IsComplete, snapshot.ObservationCount,
            UniqueCount = snapshot.Certificates.Count, snapshot.RussianCount, snapshot.PossibleCount,
            snapshot.HistoricalUnknownCount, Stores = snapshot.Stores.Select(item => item.Path), snapshot.Issues,
            snapshot.TrustComplete, snapshot.RussianAcceptedByComputerCount, snapshot.UserOnlyDistrustedCount,
            Certificates = snapshot.Certificates.Select(item => new
            {
                item.Metadata.CertificateId, item.Metadata.DisplayName, Locations = item.Locations.Select(location => location.Path),
                item.Category, item.DisallowedStatus, Reasons = item.Classification.Reasons,
                Errors = item.ReadErrors.Concat(item.Classification.Errors), item.Trust
            })
        }, new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
    }

    private static CertificateInventoryService Service(ICertificateStoreProvider provider) =>
        new(provider, new RussianCertificateClassifier(CertificateCatalog.Load()));

    private static CertificateObservation Observation(string id)
    {
        byte[] name = new X500DistinguishedName("CN=Example, O=Example, C=US").RawData;
        return new CertificateObservation(new CertificateMetadata(id, "Example", "CN=Example", "CN=Example",
            "01", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), name, name, []), []);
    }

    private static CertificateStoreReadResult Result(params CertificateObservation[] certificates) => new(certificates, []);

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private sealed class FakeProvider(Dictionary<CertificateStoreDescriptor, CertificateStoreReadResult> stores)
        : ICertificateStoreProvider
    {
        public StoreLocation? FailedScope { get; set; }
        public CertificateStoreDescriptor? FailedStore { get; set; }

        public IReadOnlyList<CertificateStoreDescriptor> EnumerateStores(StoreLocation location)
        {
            if (location == FailedScope)
                throw new UnauthorizedAccessException("Нет доступа к списку.");
            return stores.Keys.Where(item => item.Location == location).ToArray();
        }

        public CertificateStoreReadResult ReadStore(CertificateStoreDescriptor store)
        {
            if (store == FailedStore)
                throw new UnauthorizedAccessException("Нет доступа к хранилищу.");
            return stores[store];
        }
    }
}
