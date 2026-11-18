using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RussianCertMonitor.Disallowed;

internal interface ITrustCopyStore
{
    byte[]? Read(StoreLocation scope, string store, string id);
    void Remove(StoreLocation scope, string store, string id, byte[] expected);
    void Restore(StoreLocation scope, string store, string id, byte[] serialized);
    bool AreEquivalent(byte[] first, byte[] second) => first.AsSpan().SequenceEqual(second);
}

internal sealed class WindowsTrustCopyStore : ITrustCopyStore
{
    private const int SystemRegistryProvider = 13;
    private const uint CurrentUser = 0x00010000;
    private const uint LocalMachine = 0x00020000;
    private const uint OpenExisting = 0x00004000;
    private const uint ReadOnly = 0x00008000;
    private const uint IncludeArchived = 0x00000200;
    private const uint AddNew = 1;
    private const uint CertificateContextType = 1;
    private const uint CertificateContextFlag = 1 << (int)CertificateContextType;
    private const int CryptNotFound = unchecked((int)0x80092004);

    public static IReadOnlyList<string> Stores { get; } = Array.AsReadOnly(
        new[] { "Root", "CA", "AuthRoot", "TrustedPeople", "TrustedPublisher" });

    public byte[]? Read(StoreLocation scope, string store, string id)
    {
        Validate(scope, store, id);
        IntPtr handle = Open(scope, store, false);
        if (handle == IntPtr.Zero)
            return null;
        try
        {
            IntPtr context = Find(handle, id);
            if (context == IntPtr.Zero)
                return null;
            try { return SerializePublic(context); }
            finally { CertFreeCertificateContext(context); }
        }
        finally { CertCloseStore(handle, 0); }
    }

    public bool AreEquivalent(byte[] first, byte[] second) => first.AsSpan().SequenceEqual(second)
        || WithDecodedCopy(first, context => MatchesSerialized(context, second));

    public void Remove(StoreLocation scope, string store, string id, byte[] expected)
    {
        Validate(scope, store, id);
        ArgumentNullException.ThrowIfNull(expected);
        DecodeAndValidate(expected, id);
        IntPtr handle = Open(scope, store, true);
        if (handle == IntPtr.Zero)
            return;
        try
        {
            IntPtr context = Find(handle, id);
            if (context == IntPtr.Zero)
                return;
            try
            {
                if (!MatchesSerialized(context, expected))
                    throw new CryptographicException("Запись сертификата изменилась после резервного копирования.");
                bool deleted = CertDeleteCertificateFromStore(context);
                int error = Marshal.GetLastWin32Error();
                context = IntPtr.Zero;
                if (!deleted)
                    throw new Win32Exception(error, "Не удалось удалить копию сертификата.");
            }
            finally
            {
                if (context != IntPtr.Zero)
                    CertFreeCertificateContext(context);
            }
        }
        finally { CertCloseStore(handle, 0); }
    }

    public void Restore(StoreLocation scope, string store, string id, byte[] serialized)
    {
        Validate(scope, store, id);
        ArgumentNullException.ThrowIfNull(serialized);
        DecodeAndValidate(serialized, id);
        IntPtr handle = Open(scope, store, true, create: true);
        try
        {
            IntPtr existing = Find(handle, id);
            if (existing != IntPtr.Zero)
            {
                try
                {
                    if (!MatchesSerialized(existing, serialized))
                        throw new CryptographicException("В хранилище уже есть другая запись этого сертификата.");
                    return;
                }
                finally { CertFreeCertificateContext(existing); }
            }
            if (!CertAddSerializedElementToStore(handle, serialized, (uint)serialized.Length, AddNew, 0,
                    CertificateContextFlag, out uint contextType, out IntPtr added))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось восстановить копию сертификата.");
            if (added != IntPtr.Zero)
                CertFreeCertificateContext(added);
            IntPtr restored = Find(handle, id);
            if (restored == IntPtr.Zero)
                throw new CryptographicException("Восстановленная запись сертификата не прошла проверку.");
            try
            {
                if (contextType != CertificateContextType || !MatchesSerialized(restored, serialized))
                    throw new CryptographicException("Свойства восстановленной записи отличаются от резервной копии.");
            }
            finally { CertFreeCertificateContext(restored); }
        }
        finally { CertCloseStore(handle, 0); }
    }

    public static byte[] DecodePublicCertificate(byte[] serialized)
    {
        ArgumentNullException.ThrowIfNull(serialized);
        return DecodeAndValidate(serialized, null);
    }

    private static byte[] DecodeAndValidate(byte[] serialized, string? id) => WithDecodedCopy(serialized, context =>
    {
        byte[] der = GetDer(context);
        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(der);
        if (id is not null && !string.Equals(certificate.Thumbprint, id, StringComparison.Ordinal))
            throw new CryptographicException("Резервная копия не соответствует выбранному сертификату.");
        return der;
    });

    private static T WithDecodedCopy<T>(byte[] serialized, Func<IntPtr, T> read)
    {
        if (serialized.Length == 0 || serialized.Length > 1024 * 1024)
            throw new InvalidDataException("Недопустимый размер резервной копии сертификата.");
        if (!CertAddSerializedElementToStore(IntPtr.Zero, serialized, (uint)serialized.Length, AddNew, 0,
                CertificateContextFlag, out uint contextType, out IntPtr context))
            throw new CryptographicException("Повреждена резервная копия сертификата.");
        try
        {
            if (contextType != CertificateContextType || context == IntPtr.Zero)
                throw new CryptographicException("Резервная копия не содержит сертификат.");
            EnsurePublic(context);
            return read(context);
        }
        finally
        {
            if (context != IntPtr.Zero)
                CertFreeCertificateContext(context);
        }
    }

    private static bool MatchesSerialized(IntPtr actual, byte[] serialized) => WithDecodedCopy(serialized, expected =>
    {
        EnsurePublic(actual);
        if (!GetDer(actual).AsSpan().SequenceEqual(GetDer(expected)))
            return false;
        Dictionary<uint, byte[]> first = ReadProperties(expected);
        Dictionary<uint, byte[]> second = ReadProperties(actual);
        return first.Count == second.Count && first.All(item =>
            second.TryGetValue(item.Key, out byte[]? bytes) && bytes.AsSpan().SequenceEqual(item.Value));
    });

    private static Dictionary<uint, byte[]> ReadProperties(IntPtr context)
    {
        // Windows может вернуть те же свойства в другом порядке. Вычисляемые свойства отпечатка не хранят настройки доверия.
        Dictionary<uint, byte[]> properties = [];
        uint property = 0;
        while ((property = CertEnumCertificateContextProperties(context, property)) != 0)
        {
            if (property is 3 or 4)
                continue;
            uint size = 0;
            if (!CertGetCertificateContextProperty(context, property, null, ref size) || size > 1024 * 1024)
                throw new CryptographicException("Не удалось прочитать свойства записи сертификата.");
            byte[] value = new byte[size];
            if (size > 0 && (!CertGetCertificateContextProperty(context, property, value, ref size) || size != value.Length))
                throw new CryptographicException("Не удалось проверить данные свойства сертификата.");
            properties.Add(property, value);
        }
        return properties;
    }

    private static byte[] SerializePublic(IntPtr context)
    {
        EnsurePublic(context);
        uint size = 0;
        if (!CertSerializeCertificateStoreElement(context, 0, null, ref size) || size == 0 || size > 1024 * 1024)
            throw new CryptographicException("Не удалось определить размер копии сертификата.");
        byte[] serialized = new byte[size];
        if (!CertSerializeCertificateStoreElement(context, 0, serialized, ref size))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось сохранить копию сертификата.");
        if (size != serialized.Length)
            Array.Resize(ref serialized, (int)size);
        return serialized;
    }

    private static void EnsurePublic(IntPtr context)
    {
        using X509Certificate2 certificate = new(context);
        if (certificate.HasPrivateKey || HasProperty(context, 1) || HasProperty(context, 2) ||
            HasProperty(context, 5) || HasProperty(context, 6) || HasProperty(context, 78) ||
            HasProperty(context, 79) || HasProperty(context, 117) || HasProperty(context, 118))
            throw new CryptographicException("Сертификат содержит ссылку на закрытый ключ; копирование запрещено.");
    }

    private static bool HasProperty(IntPtr context, uint property)
    {
        uint size = 0;
        if (CertGetCertificateContextProperty(context, property, null, ref size))
            return true;
        int error = Marshal.GetLastWin32Error();
        if (error != CryptNotFound)
            throw new Win32Exception(error, "Не удалось проверить свойства сертификата.");
        return false;
    }

    private static byte[] GetDer(IntPtr context)
    {
        CertContext native = Marshal.PtrToStructure<CertContext>(context);
        if (native.EncodedSize == 0 || native.EncodedSize > 1024 * 1024)
            throw new CryptographicException("Недопустимый размер сертификата.");
        byte[] der = new byte[native.EncodedSize];
        Marshal.Copy(native.Encoded, der, 0, der.Length);
        return der;
    }

    private static IntPtr Find(IntPtr handle, string id)
    {
        IntPtr context = IntPtr.Zero;
        while ((context = CertEnumCertificatesInStore(handle, context)) != IntPtr.Zero)
        {
            try
            {
                using X509Certificate2 certificate = new(context);
                if (string.Equals(certificate.Thumbprint, id, StringComparison.Ordinal))
                    return context;
            }
            catch
            {
                CertFreeCertificateContext(context);
                throw;
            }
        }
        int error = Marshal.GetLastWin32Error();
        if (error is not (0 or CryptNotFound or 18))
            throw new Win32Exception(error, "Не удалось прочитать записи хранилища.");
        return IntPtr.Zero;
    }

    private static IntPtr Open(StoreLocation scope, string store, bool writable, bool create = false)
    {
        uint flags = (scope == StoreLocation.CurrentUser ? CurrentUser : LocalMachine) | IncludeArchived |
            (writable ? 0u : ReadOnly) | (create ? 0u : OpenExisting);
        IntPtr handle = CertOpenStore(new IntPtr(SystemRegistryProvider), 0, IntPtr.Zero, flags, store);
        if (handle == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            if (!create && error is 2 or 3 or CryptNotFound or unchecked((int)0x80070002) or unchecked((int)0x80070003))
                return IntPtr.Zero;
            throw new Win32Exception(error, $"Не удалось открыть хранилище {store}.");
        }
        return handle;
    }

    private static void Validate(StoreLocation scope, string store, string id)
    {
        if (scope is not (StoreLocation.CurrentUser or StoreLocation.LocalMachine))
            throw new ArgumentOutOfRangeException(nameof(scope));
        if (!Stores.Contains(store, StringComparer.Ordinal))
            throw new ArgumentOutOfRangeException(nameof(store));
        if (id is null || id.Length != 40 || id.Any(c => c is not (>= '0' and <= '9' or >= 'A' and <= 'F')))
            throw new ArgumentException("Недопустимый идентификатор сертификата.", nameof(id));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CertContext
    {
        public uint Encoding;
        public IntPtr Encoded;
        public uint EncodedSize;
        public IntPtr Info;
        public IntPtr Store;
    }

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CertOpenStore(IntPtr provider, uint encoding, IntPtr cryptoProvider, uint flags, string? name);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertCloseStore(IntPtr store, uint flags);
    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern IntPtr CertEnumCertificatesInStore(IntPtr store, IntPtr previous);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertFreeCertificateContext(IntPtr context);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertDeleteCertificateFromStore(IntPtr context);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertSerializeCertificateStoreElement(IntPtr context, uint flags, byte[]? serialized, ref uint size);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertAddSerializedElementToStore(IntPtr store, byte[] serialized, uint size, uint disposition,
        uint flags, uint contextTypeFlags, out uint contextType, out IntPtr context);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertGetCertificateContextProperty(IntPtr context, uint property, byte[]? data, ref uint size);
    [DllImport("crypt32.dll")]
    private static extern uint CertEnumCertificateContextProperties(IntPtr context, uint property);
}
