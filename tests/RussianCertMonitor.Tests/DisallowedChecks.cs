using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.Disallowed;

namespace RussianCertMonitor.Tests;

internal static class DisallowedChecks
{
    public static void Run()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new($"CN=Проверка-{Guid.NewGuid():N}, C=US", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        byte[] der = certificate.Export(X509ContentType.Cert);
        PublicCertificateData data = PublicCertificateData.FromDer(der);
        Require(!string.IsNullOrWhiteSpace(data.Metadata.CertificateId)
            && data.Metadata.RawData.SequenceEqual(der), "Должен читаться только публичный DER.");

        string directory = Path.Combine(Path.GetTempPath(), $"rcm-disallowed-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string pemPath = Path.Combine(directory, "certificate.pem");
        string exported = Path.Combine(directory, "export.cer");
        try
        {
            File.WriteAllText(pemPath, PemEncoding.WriteString("CERTIFICATE", der), Encoding.ASCII);
            Require(PublicCertificateData.FromFile(pemPath).Metadata.CertificateId == data.Metadata.CertificateId,
                "Один PEM CERTIFICATE должен читаться.");
            File.WriteAllText(pemPath, "\uFEFF" + PemEncoding.WriteString("CERTIFICATE", der),
                new UTF8Encoding(false));
            Require(PublicCertificateData.FromFile(pemPath).Metadata.CertificateId == data.Metadata.CertificateId,
                "Один PEM CERTIFICATE с UTF-8 BOM должен читаться.");
            data.ExportCer(exported);
            Require(File.ReadAllBytes(exported).SequenceEqual(der), "CER должен содержать публичный DER.");
            Reject(() => PublicCertificateData.FromDer([]));
            Reject(() => PublicCertificateData.FromDer([1, 2, 3]));
            Reject(() => PublicCertificateData.FromDer(certificate.Export(X509ContentType.Pfx)));
            File.WriteAllText(pemPath, PemEncoding.WriteString("CERTIFICATE", der)
                + PemEncoding.WriteString("CERTIFICATE", der));
            Reject(() => PublicCertificateData.FromFile(pemPath));
            File.WriteAllText(pemPath, PemEncoding.WriteString("PRIVATE KEY", key.ExportPkcs8PrivateKey()));
            Reject(() => PublicCertificateData.FromFile(pemPath));
        }
        finally
        {
            File.Delete(pemPath);
            File.Delete(exported);
            Directory.Delete(directory);
        }

        FakeBackend backend = new();
        DisallowedManager manager = new(backend);
        string id = data.Metadata.CertificateId;
        DisallowedPreview add = manager.Preview(DisallowedOperation.Add, StoreLocation.CurrentUser, data);
        Require(!add.OwnPresent, "Первичная проверка должна видеть отсутствие записи.");
        DisallowedResult result = manager.Execute(add);
        Require(result.Changed && result.OwnPresentAfter && result.LogicalPresentAfter,
            "Добавление должно подтвердить собственную и логическую запись.");
        Require(!manager.Execute(add).Changed, "Повторное добавление должно быть идемпотентным.");
        Require(!backend.Contains(StoreLocation.LocalMachine, id), "Области должны быть независимы.");
        backend.ReturnWrongDer = true;
        Reject(() => manager.Preview(DisallowedOperation.Remove, StoreLocation.CurrentUser, data));
        backend.ReturnWrongDer = false;
        backend.Inherited = true;
        DisallowedPreview remove = manager.Preview(DisallowedOperation.Remove, StoreLocation.CurrentUser, data);
        Require(remove.OwnPresent && backend.FindCalls > 0 && !ReferenceEquals(remove.Certificate, data)
            && remove.Certificate.Metadata.RawData.SequenceEqual(der),
            "Предпросмотр удаления должен содержать заново прочитанный DER.");
        backend.ReturnWrongDer = true;
        Reject(() => manager.Execute(remove));
        backend.ReturnWrongDer = false;
        result = manager.Execute(remove);
        Require(result.Changed && !result.OwnPresentAfter && result.LogicalPresentAfter,
            "После удаления собственная запись может оставаться в логическом хранилище.");
        Require(!manager.Execute(remove).Changed, "Повторное удаление должно быть идемпотентным.");
        backend.SuppressAdd = true;
        Reject(() => manager.Execute(add));
        backend.SuppressAdd = false;
        manager.Execute(add);
        backend.SuppressRemove = true;
        Reject(() => manager.Execute(remove));
        backend.SuppressRemove = false;
        manager.Execute(remove);
        backend.ThrowAccess = true;
        Reject(() => manager.Preview(DisallowedOperation.Add, StoreLocation.CurrentUser, data));
        backend.ThrowAccess = false;
        Reject(() => manager.Preview((DisallowedOperation)99, StoreLocation.CurrentUser, data));
        Reject(() => manager.Preview(DisallowedOperation.Add, (StoreLocation)99, data));
    }

    public static void RunLive(StoreLocation location)
    {
        if (location is not (StoreLocation.CurrentUser or StoreLocation.LocalMachine))
            throw new ArgumentOutOfRangeException(nameof(location));
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new($"CN=RussianCertMonitor-Test-{Guid.NewGuid():N}, C=US", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        PublicCertificateData data = PublicCertificateData.FromDer(certificate.Export(X509ContentType.Cert));
        string id = data.Metadata.CertificateId;
        WindowsDisallowedStoreBackend backend = new();
        DisallowedManager manager = new(backend);
        Require(!backend.Contains(location, id), "Тестовый сертификат уже находится в собственном Disallowed.");
        Require(!InStore(location, StoreName.Root, id) && !InStore(location, StoreName.CertificateAuthority, id),
            "Тестовый сертификат уже находится в Root или CA.");
        try
        {
            DisallowedResult added = manager.Execute(manager.Preview(DisallowedOperation.Add, location, data));
            Require(added.Changed && added.OwnPresentAfter
                && backend.Find(location, id)!.SequenceEqual(data.Metadata.RawData),
                "Собственный Disallowed должен содержать тот же публичный сертификат.");
            if (location == StoreLocation.LocalMachine)
            {
                Require(!backend.Contains(StoreLocation.CurrentUser, id), "Запись компьютера не должна становиться собственной пользовательской записью.");
                DisallowedResult userRemoval = manager.Execute(manager.Preview(DisallowedOperation.Remove, StoreLocation.CurrentUser, data));
                Require(!userRemoval.Changed && backend.Contains(StoreLocation.LocalMachine, id),
                    "Удаление в области пользователя не должно затрагивать собственную запись компьютера.");
            }
            DisallowedResult removed = manager.Execute(manager.Preview(DisallowedOperation.Remove, location, data));
            Require(removed.Changed && !removed.OwnPresentAfter && !backend.Contains(location, id),
                "Тестовый сертификат должен удаляться из собственного Disallowed.");
        }
        finally
        {
            if (backend.Contains(location, id))
                backend.Remove(location, id);
            Require(!InStore(location, StoreName.Root, id) && !InStore(location, StoreName.CertificateAuthority, id),
                "Root и CA не должны изменяться.");
        }
    }

    private static bool InStore(StoreLocation location, StoreName name, string id)
    {
        using X509Store store = new(name, location);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived);
        X509Certificate2Collection certificates = store.Certificates;
        try { return certificates.Cast<X509Certificate2>().Any(item => item.Thumbprint == id); }
        finally { foreach (X509Certificate2 item in certificates) item.Dispose(); }
    }

    private static void Reject(Action action)
    {
        try { action(); }
        catch (Exception error) when (error is CryptographicException or ArgumentException
            or UnauthorizedAccessException or InvalidOperationException) { return; }
        throw new InvalidOperationException("Некорректная операция должна отклоняться.");
    }

    private static void Require(bool value, string message)
    {
        if (!value) throw new InvalidOperationException(message);
    }

    private sealed class FakeBackend : IDisallowedStoreBackend
    {
        private readonly Dictionary<(StoreLocation, string), byte[]> entries = [];
        public bool Inherited { get; set; }
        public bool SuppressAdd { get; set; }
        public bool SuppressRemove { get; set; }
        public bool ReturnWrongDer { get; set; }
        public bool ThrowAccess { get; set; }
        public int FindCalls { get; private set; }
        public bool Contains(StoreLocation location, string id)
        {
            if (ThrowAccess) throw new UnauthorizedAccessException("Доступ запрещён.");
            return entries.ContainsKey((location, id));
        }
        public byte[]? Find(StoreLocation location, string id)
        {
            FindCalls++;
            return ReturnWrongDer ? [1, 2, 3] : entries.GetValueOrDefault((location, id));
        }
        public void Add(StoreLocation location, byte[] der)
        {
            if (!SuppressAdd)
                entries[(location, PublicCertificateData.FromDer(der).Metadata.CertificateId)] = der;
        }
        public void Remove(StoreLocation location, string id)
        {
            if (!SuppressRemove) entries.Remove((location, id));
        }
        public bool ContainsLogical(StoreLocation location, string id) => Inherited || Contains(location, id);
    }
}
