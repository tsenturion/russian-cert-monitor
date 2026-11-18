using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.Disallowed;

namespace RussianCertMonitor.Tests;

internal static class TrustCopyQuarantineChecks
{
    private const string Id = "TEST-CERTIFICATE";
    private static readonly string[] AllowedStores = ["Root", "CA", "TrustedPeople", "TrustedPublisher", "AuthRoot"];

    public static void Run()
    {
        SaveFailureDoesNotRemove();
        IsolateOnlyExactCopies();
        RepeatedIsolateAndConflict();
        PartialRemovalKeepsCompleteBackup();
        PartialRestoreCanBeRetried();
        RestoreOnlySelectedScope();
    }

    public static void RunLive(StoreLocation location)
    {
        if (location is not (StoreLocation.CurrentUser or StoreLocation.LocalMachine))
            throw new ArgumentOutOfRangeException(nameof(location));
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new($"CN=RussianCertMonitor-TrustCopy-Test-{Guid.NewGuid():N}, C=US",
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using X509Certificate2 signed = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(signed.RawData);
        certificate.FriendlyName = "Проверка сохранения доверенной копии";
        string id = certificate.Thumbprint;
        WindowsTrustCopyStore store = new();
        RegistryTrustCopyVault vault = new();
        TrustCopyQuarantine quarantine = new(store, vault);
        WindowsDisallowedStoreBackend disallowed = new();
        Require(!certificate.HasPrivateKey && store.Read(location, "TrustedPublisher", id) is null &&
            store.Read(location, "Root", id) is null && store.Read(location, "CA", id) is null &&
            vault.Read(location, id).Count == 0,
            "Синтетический сертификат должен отсутствовать в хранилищах и архиве.");

        try
        {
            disallowed.Add(location, certificate.RawData);
            AssertNativeBlock(certificate, location);
            using (X509Store publisher = new(StoreName.TrustedPublisher, location))
            {
                publisher.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                publisher.Add(certificate);
            }
            byte[] original = store.Read(location, "TrustedPublisher", id)
                ?? throw new InvalidOperationException("Не удалось прочитать тестовую копию.");
            TrustCopyChange blocked = quarantine.Isolate(location, id);
            Require(blocked.ChangedStores.SequenceEqual(["TrustedPublisher"]) &&
                blocked.Issues.Length == 0 && quarantine.HasBackup(location, id) &&
                store.Read(location, "TrustedPublisher", id) is null,
                "Копия TrustedPublisher должна быть сохранена и удалена.");
            using (X509Store publisher = new(StoreName.TrustedPublisher, location))
            {
                publisher.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                publisher.Add(certificate);
            }
            AssertNativeBlock(certificate, location);
            Require(quarantine.Isolate(location, id).ChangedStores.SequenceEqual(["TrustedPublisher"]),
                "Повторный импорт под запретом должен оставаться обратимым.");
            TrustCopyChange restored = quarantine.Restore(location, id);
            Require(restored.ChangedStores.SequenceEqual(["TrustedPublisher"]) &&
                restored.Issues.Length == 0 && !quarantine.HasBackup(location, id) &&
                WindowsTrustCopyStore.DecodePublicCertificate(store.Read(location, "TrustedPublisher", id)!)
                    .SequenceEqual(certificate.RawData),
                "Восстановление должно вернуть исходный сертификат с проверенными свойствами: " +
                string.Join("; ", restored.Issues));
            store.Restore(location, "TrustedPublisher", id, original);
            AssertNativeBlock(certificate, location);
            disallowed.Remove(location, id);
            using (WindowsTrustVerifier verifier = new())
            {
                WindowsTrustAssessment trust = verifier.Verify(certificate.RawData);
                Require(!trust.CurrentUser.IsExplicitlyDistrusted && !trust.LocalMachine.IsExplicitlyDistrusted,
                    "Явный запрет должен исчезнуть после восстановления и снятия записи.");
            }
            Require(store.Read(location, "Root", id) is null && store.Read(location, "CA", id) is null,
                "Root и CA не должны изменяться.");
        }
        finally
        {
            RemoveSynthetic(location, certificate);
            vault.Clear(location, id);
            if (disallowed.Contains(location, id))
                disallowed.Remove(location, id);
        }
    }

    private static void AssertNativeBlock(X509Certificate2 certificate, StoreLocation location)
    {
        using WindowsTrustVerifier verifier = new();
        WindowsTrustAssessment trust = verifier.Verify(certificate.RawData);
        Require(trust.CurrentUser.IsExplicitlyDistrusted
            && (location != StoreLocation.LocalMachine || trust.LocalMachine.IsExplicitlyDistrusted),
            "Повторный импорт или восстановление копии не должны выключать запрет Windows.");
    }

    private static void RemoveSynthetic(StoreLocation location, X509Certificate2 expected)
    {
        using X509Store publisher = new(StoreName.TrustedPublisher, location);
        publisher.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived);
        X509Certificate2Collection matches = publisher.Certificates.Find(
            X509FindType.FindByThumbprint, expected.Thumbprint, validOnly: false);
        try
        {
            foreach (X509Certificate2 match in matches)
            {
                if (!match.RawData.AsSpan().SequenceEqual(expected.RawData))
                    throw new InvalidOperationException("Тестовая запись изменилась; автоматическое удаление запрещено.");
                publisher.Remove(match);
            }
        }
        finally { foreach (X509Certificate2 match in matches) match.Dispose(); }
    }

    private static void SaveFailureDoesNotRemove()
    {
        FakeStore store = new();
        FakeVault vault = new() { FailSave = true };
        store.Put(StoreLocation.CurrentUser, "Root", Id, [1]);
        TrustCopyQuarantine quarantine = new(store, vault);

        Reject(() => quarantine.Isolate(StoreLocation.CurrentUser, Id));
        Require(store.RemoveCalls == 0, "Ошибка сохранения копии не должна приводить к удалению.");
        Require(store.Get(StoreLocation.CurrentUser, "Root", Id)!.SequenceEqual(new byte[] { 1 }),
            "Исходная запись должна сохраниться после ошибки сохранения.");
    }

    private static void IsolateOnlyExactCopies()
    {
        FakeStore store = new();
        FakeVault vault = new();
        TrustCopyQuarantine quarantine = new(store, vault);
        foreach (string name in AllowedStores)
            store.Put(StoreLocation.CurrentUser, name, Id, [(byte)(Array.IndexOf(AllowedStores, name) + 1)]);
        store.Put(StoreLocation.LocalMachine, "Root", Id, [91]);
        store.Put(StoreLocation.CurrentUser, "Root", "OTHER", [92]);
        foreach (string name in new[] { "My", "Disallowed", "Policies" })
            store.Put(StoreLocation.CurrentUser, name, Id, [93]);

        TrustCopyChange change = quarantine.Isolate(StoreLocation.CurrentUser, Id);
        Require(change.Scope == StoreLocation.CurrentUser &&
            change.ChangedStores.Order().SequenceEqual(AllowedStores.Order()),
            "Должны удаляться только копии в разрешённых хранилищах выбранной области.");
        Require(change.Issues.Length == 0, "Успешное удаление не должно сообщать об ошибках.");
        Require(quarantine.HasBackup(StoreLocation.CurrentUser, Id), "Копии должны оставаться в архиве.");
        Require(vault.Read(StoreLocation.CurrentUser, Id).Count == AllowedStores.Length,
            "В архиве должны сохраниться все исходные копии.");
        Require(store.Get(StoreLocation.LocalMachine, "Root", Id)!.SequenceEqual(new byte[] { 91 }) &&
            store.Get(StoreLocation.CurrentUser, "Root", "OTHER")!.SequenceEqual(new byte[] { 92 }),
            "Другая область и другой отпечаток не должны изменяться.");
        foreach (string name in new[] { "My", "Disallowed", "Policies" })
            Require(store.Get(StoreLocation.CurrentUser, name, Id)!.SequenceEqual(new byte[] { 93 }),
                "Запрещённое хранилище не должно изменяться.");
    }

    private static void RepeatedIsolateAndConflict()
    {
        FakeStore store = new();
        FakeVault vault = new();
        TrustCopyQuarantine quarantine = new(store, vault);
        store.Put(StoreLocation.CurrentUser, "TrustedPublisher", Id, [1, 2]);
        quarantine.Isolate(StoreLocation.CurrentUser, Id);
        TrustCopyChange missing = quarantine.Isolate(StoreLocation.CurrentUser, Id);
        Require(missing.ChangedStores.Length == 0 && missing.Issues.Length == 0 &&
            quarantine.HasBackup(StoreLocation.CurrentUser, Id),
            "Повторное удаление отсутствующей записи должно сохранить архив.");

        store.Put(StoreLocation.CurrentUser, "TrustedPublisher", Id, [1, 2]);
        TrustCopyChange identical = quarantine.Isolate(StoreLocation.CurrentUser, Id);
        Require(identical.ChangedStores.SequenceEqual(["TrustedPublisher"]) &&
            store.Get(StoreLocation.CurrentUser, "TrustedPublisher", Id) is null,
            "Повторный явный блок должен удалять точно такую же импортированную копию.");

        store.Put(StoreLocation.CurrentUser, "TrustedPublisher", Id, [3, 4]);
        TrustCopyChange conflict = quarantine.Isolate(StoreLocation.CurrentUser, Id);
        Require(conflict.ChangedStores.Length == 0 && conflict.Issues.Length > 0 &&
            store.Get(StoreLocation.CurrentUser, "TrustedPublisher", Id)!.SequenceEqual(new byte[] { 3, 4 }) &&
            vault.Read(StoreLocation.CurrentUser, Id).Single().Serialized.SequenceEqual(new byte[] { 1, 2 }),
            "Отличающаяся копия должна остаться без изменений, а исходный архив сохраниться.");
    }

    private static void PartialRemovalKeepsCompleteBackup()
    {
        FakeStore store = new() { FailRemoveStore = "CA" };
        FakeVault vault = new();
        TrustCopyQuarantine quarantine = new(store, vault);
        store.Put(StoreLocation.CurrentUser, "Root", Id, [1]);
        store.Put(StoreLocation.CurrentUser, "CA", Id, [2]);

        TrustCopyChange change = quarantine.Isolate(StoreLocation.CurrentUser, Id);
        Require(change.Issues.Length > 0 && quarantine.HasBackup(StoreLocation.CurrentUser, Id),
            "Ошибка частичного удаления должна сохранять архив.");
        Require(vault.Read(StoreLocation.CurrentUser, Id).Count == 2,
            "Архив должен содержать все исходные копии, включая удалённые до ошибки.");
    }

    private static void PartialRestoreCanBeRetried()
    {
        FakeStore store = new();
        FakeVault vault = new();
        TrustCopyQuarantine quarantine = new(store, vault);
        store.Put(StoreLocation.CurrentUser, "Root", Id, [1]);
        store.Put(StoreLocation.CurrentUser, "CA", Id, [2]);
        quarantine.Isolate(StoreLocation.CurrentUser, Id);

        store.FailRestoreStore = "CA";
        TrustCopyChange partial = quarantine.Restore(StoreLocation.CurrentUser, Id);
        Require(partial.Issues.Length > 0 && quarantine.HasBackup(StoreLocation.CurrentUser, Id),
            "Архив нельзя очищать после частичного восстановления.");
        store.FailRestoreStore = null;
        TrustCopyChange complete = quarantine.Restore(StoreLocation.CurrentUser, Id);
        Require(complete.Issues.Length == 0 && !quarantine.HasBackup(StoreLocation.CurrentUser, Id) &&
            store.Get(StoreLocation.CurrentUser, "Root", Id)!.SequenceEqual(new byte[] { 1 }) &&
            store.Get(StoreLocation.CurrentUser, "CA", Id)!.SequenceEqual(new byte[] { 2 }),
            "Повторное восстановление должно вернуть все копии и очистить архив.");
    }

    private static void RestoreOnlySelectedScope()
    {
        FakeStore store = new();
        FakeVault vault = new();
        TrustCopyQuarantine quarantine = new(store, vault);
        store.Put(StoreLocation.CurrentUser, "TrustedPeople", Id, [1]);
        store.Put(StoreLocation.LocalMachine, "TrustedPeople", Id, [2]);
        quarantine.Isolate(StoreLocation.CurrentUser, Id);
        quarantine.Isolate(StoreLocation.LocalMachine, Id);

        quarantine.Restore(StoreLocation.CurrentUser, Id);
        Require(store.Get(StoreLocation.CurrentUser, "TrustedPeople", Id)!.SequenceEqual(new byte[] { 1 }) &&
            store.Get(StoreLocation.LocalMachine, "TrustedPeople", Id) is null &&
            !quarantine.HasBackup(StoreLocation.CurrentUser, Id) &&
            quarantine.HasBackup(StoreLocation.LocalMachine, Id),
            "Восстановление одной области не должно менять архив и записи другой области.");
    }

    private static void Reject(Action action)
    {
        try { action(); }
        catch (Exception error) when (error is IOException or InvalidOperationException) { return; }
        throw new InvalidOperationException("Ожидалась ошибка сохранения архива.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class FakeStore : ITrustCopyStore
    {
        private readonly Dictionary<(StoreLocation, string, string), byte[]> entries = [];
        public string? FailRemoveStore { get; set; }
        public string? FailRestoreStore { get; set; }
        public int RemoveCalls { get; private set; }

        public void Put(StoreLocation scope, string name, string id, byte[] data) =>
            entries[(scope, name, id)] = data.ToArray();

        public byte[]? Get(StoreLocation scope, string name, string id) =>
            entries.GetValueOrDefault((scope, name, id))?.ToArray();

        public byte[]? Read(StoreLocation scope, string store, string id) => Get(scope, store, id);

        public void Remove(StoreLocation scope, string store, string id, byte[] expected)
        {
            RemoveCalls++;
            if (store == FailRemoveStore) throw new IOException("Ошибка удаления тестовой копии.");
            if (!entries.TryGetValue((scope, store, id), out byte[]? current) || !current.SequenceEqual(expected))
                throw new InvalidOperationException("Тестовая копия изменилась.");
            entries.Remove((scope, store, id));
        }

        public void Restore(StoreLocation scope, string store, string id, byte[] serialized)
        {
            if (store == FailRestoreStore) throw new IOException("Ошибка восстановления тестовой копии.");
            entries[(scope, store, id)] = serialized.ToArray();
        }
    }

    private sealed class FakeVault : ITrustCopyVault
    {
        private readonly Dictionary<(StoreLocation, string), TrustCopyBackup[]> archives = [];
        public bool FailSave { get; set; }
        public IReadOnlyList<TrustCopyBackup> Read(StoreLocation scope, string id) =>
            archives.GetValueOrDefault((scope, id)) ?? [];

        public void Save(StoreLocation scope, string id, IReadOnlyList<TrustCopyBackup> records)
        {
            if (FailSave) throw new IOException("Ошибка сохранения тестового архива.");
            archives[(scope, id)] = records.Select(record =>
                new TrustCopyBackup(record.Store, record.Serialized.ToArray())).ToArray();
        }

        public void Clear(StoreLocation scope, string id) => archives.Remove((scope, id));
    }
}
