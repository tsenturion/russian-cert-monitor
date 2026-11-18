using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32;

namespace RussianCertMonitor.Disallowed;

internal sealed record TrustCopyBackup(string Store, byte[] Serialized);

internal interface ITrustCopyVault
{
    IReadOnlyList<TrustCopyBackup> Read(StoreLocation scope, string id);
    void Save(StoreLocation scope, string id, IReadOnlyList<TrustCopyBackup> records);
    void Clear(StoreLocation scope, string id);
}

internal sealed class RegistryTrustCopyVault : ITrustCopyVault
{
    private const string Path = @"SOFTWARE\RussianCertMonitor\TrustCopies";
    private const string Journal = "Journal";
    private const int Version = 1;
    private const int MaximumItemSize = 1024 * 1024;
    private const int MaximumJournalSize = 5 * 1024 * 1024;

    public IReadOnlyList<TrustCopyBackup> Read(StoreLocation scope, string id)
    {
        Validate(scope, id);
        using RegistryKey? parent = Root(scope).OpenSubKey(Path, writable: false);
        if (parent is null)
            return [];
        using RegistryKey? key = parent.OpenSubKey(id, writable: false);
        if (key is null || (key.ValueCount == 0 && key.SubKeyCount == 0))
            return [];
        return ReadJournal(key, id);
    }

    public void Save(StoreLocation scope, string id, IReadOnlyList<TrustCopyBackup> records)
    {
        Validate(scope, id);
        ArgumentNullException.ThrowIfNull(records);
        byte[] journal = Encode(records, id);
        using RegistryKey parent = Root(scope).CreateSubKey(Path, writable: true)
            ?? throw new IOException("Не удалось открыть раздел резервных копий сертификатов.");
        using RegistryKey key = parent.CreateSubKey(id, writable: true)
            ?? throw new IOException("Не удалось создать раздел резервной копии сертификата.");
        if (key.ValueCount != 0 || key.SubKeyCount != 0)
        {
            IReadOnlyList<TrustCopyBackup> existing = ReadJournal(key, id);
            if (key.ValueCount != 1 || key.SubKeyCount != 0 || existing.Any(previous =>
                !records.Any(current => previous.Store == current.Store
                    && previous.Serialized.AsSpan().SequenceEqual(current.Serialized))))
                throw new InvalidDataException("Исходные резервные копии должны остаться в журнале.");
        }
        key.SetValue(Journal, journal, RegistryValueKind.Binary);
        key.Flush();
    }

    public void Clear(StoreLocation scope, string id)
    {
        Validate(scope, id);
        using RegistryKey? parent = Root(scope).OpenSubKey(Path, writable: true);
        if (parent is null)
            return;
        using (RegistryKey? key = parent.OpenSubKey(id, writable: false))
        {
            if (key is null)
                return;
            _ = ReadJournal(key, id);
            if (key.SubKeyCount != 0 || key.ValueCount != 1)
                throw new InvalidDataException("Раздел резервной копии содержит посторонние данные.");
        }
        parent.DeleteSubKey(id, throwOnMissingSubKey: true);
        parent.Flush();
    }

    public IReadOnlyList<string> ListIds(StoreLocation scope)
    {
        ValidateScope(scope);
        using RegistryKey? parent = Root(scope).OpenSubKey(Path, writable: false);
        if (parent is null)
            return [];
        List<string> ids = [];
        foreach (string id in parent.GetSubKeyNames())
        {
            ValidateId(id);
            ids.Add(id);
        }
        return ids;
    }

    private static IReadOnlyList<TrustCopyBackup> ReadJournal(RegistryKey key, string id)
    {
        if (key.GetValueKind(Journal) != RegistryValueKind.Binary || key.GetValue(Journal) is not byte[] bytes
            || bytes.Length == 0 || bytes.Length > MaximumJournalSize)
            throw new InvalidDataException("Повреждён журнал резервных копий сертификата.");
        try
        {
            using MemoryStream stream = new(bytes, writable: false);
            using BinaryReader reader = new(stream, Encoding.UTF8);
            if (reader.ReadInt32() != Version)
                throw new InvalidDataException("Неизвестная версия журнала резервных копий.");
            int count = reader.ReadInt32();
            if (count < 1 || count > WindowsTrustCopyStore.Stores.Count)
                throw new InvalidDataException("Недопустимое число резервных копий.");
            List<TrustCopyBackup> records = new(count);
            HashSet<string> stores = new(StringComparer.Ordinal);
            for (int i = 0; i < count; i++)
            {
                string store = reader.ReadString();
                int length = reader.ReadInt32();
                if (!WindowsTrustCopyStore.Stores.Contains(store, StringComparer.Ordinal) ||
                    !stores.Add(store) || length <= 0 || length > MaximumItemSize)
                    throw new InvalidDataException("Недопустимая запись резервной копии.");
                byte[] serialized = reader.ReadBytes(length);
                if (serialized.Length != length)
                    throw new EndOfStreamException();
                ValidateCertificate(serialized, id);
                records.Add(new TrustCopyBackup(store, serialized));
            }
            if (stream.Position != stream.Length)
                throw new InvalidDataException("Журнал резервных копий содержит лишние данные.");
            return records;
        }
        catch (Exception error) when (error is EndOfStreamException or ArgumentException or IOException or FormatException)
        {
            throw new InvalidDataException("Повреждён журнал резервных копий сертификата.", error);
        }
    }

    private static byte[] Encode(IReadOnlyList<TrustCopyBackup> records, string id)
    {
        if (records.Count < 1 || records.Count > WindowsTrustCopyStore.Stores.Count)
            throw new ArgumentException("Недопустимое число резервных копий.", nameof(records));
        HashSet<string> stores = new(StringComparer.Ordinal);
        using MemoryStream stream = new();
        using (BinaryWriter writer = new(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(Version);
            writer.Write(records.Count);
            foreach (TrustCopyBackup record in records)
            {
                if (record is null || !WindowsTrustCopyStore.Stores.Contains(record.Store, StringComparer.Ordinal)
                    || !stores.Add(record.Store) || record.Serialized is null
                    || record.Serialized.Length == 0 || record.Serialized.Length > MaximumItemSize)
                    throw new ArgumentException("Недопустимая резервная копия сертификата.", nameof(records));
                ValidateCertificate(record.Serialized, id);
                writer.Write(record.Store);
                writer.Write(record.Serialized.Length);
                writer.Write(record.Serialized);
            }
        }
        if (stream.Length > MaximumJournalSize)
            throw new ArgumentException("Журнал резервных копий слишком велик.", nameof(records));
        return stream.ToArray();
    }

    private static RegistryKey Root(StoreLocation scope) => scope == StoreLocation.CurrentUser
        ? Registry.CurrentUser : Registry.LocalMachine;

    private static void ValidateCertificate(byte[] serialized, string id)
    {
        byte[] der = WindowsTrustCopyStore.DecodePublicCertificate(serialized);
        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(der);
        if (!string.Equals(certificate.Thumbprint, id, StringComparison.Ordinal))
            throw new InvalidDataException("Резервная копия не соответствует идентификатору сертификата.");
    }

    private static void Validate(StoreLocation scope, string id)
    {
        ValidateScope(scope);
        ValidateId(id);
    }

    private static void ValidateScope(StoreLocation scope)
    {
        if (scope is not (StoreLocation.CurrentUser or StoreLocation.LocalMachine))
            throw new ArgumentOutOfRangeException(nameof(scope));
    }

    private static void ValidateId(string id)
    {
        if (id is null || id.Length != 40 || id.Any(c => c is not (>= '0' and <= '9' or >= 'A' and <= 'F')))
            throw new ArgumentException("Недопустимый идентификатор сертификата.", nameof(id));
    }
}
