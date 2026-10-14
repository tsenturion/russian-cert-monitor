using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace RussianCertMonitor.Disallowed;

internal sealed class WindowsDisallowedStoreBackend : IDisallowedStoreBackend
{
    private const int ProviderSystemRegistryW = 13;
    private const uint CurrentUser = 0x00010000;
    private const uint LocalMachine = 0x00020000;
    private const uint OpenExisting = 0x00004000;
    private const uint ReadOnly = 0x00008000;
    private const uint IncludeArchived = 0x00000200;
    private const int FileNotFound = 2;
    private const int PathNotFound = 3;
    private const int CryptNotFound = unchecked((int)0x80092004);

    public bool Contains(StoreLocation location, string id) => Find(location, id) is not null;

    public byte[]? Find(StoreLocation location, string id) => WithPhysical(location, false, store =>
    {
        X509Certificate2Collection certificates = store.Certificates;
        try
        {
            foreach (X509Certificate2 certificate in certificates)
                if (string.Equals(certificate.Thumbprint, id, StringComparison.OrdinalIgnoreCase))
                    return certificate.Export(X509ContentType.Cert);
            return null;
        }
        finally
        {
            foreach (X509Certificate2 certificate in certificates)
                certificate.Dispose();
        }
    });

    public void Add(StoreLocation location, byte[] der)
    {
        ArgumentNullException.ThrowIfNull(der);
        WithPhysical(location, true, store =>
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(der);
            store.Add(certificate);
            return true;
        });
    }

    public void Remove(StoreLocation location, string id)
    {
        WithPhysical(location, true, store =>
        {
            X509Certificate2Collection certificates = store.Certificates;
            try
            {
                foreach (X509Certificate2 certificate in certificates)
                    if (string.Equals(certificate.Thumbprint, id, StringComparison.OrdinalIgnoreCase))
                    {
                        store.Remove(certificate);
                        break;
                    }
            }
            finally
            {
                foreach (X509Certificate2 certificate in certificates)
                    certificate.Dispose();
            }
            return true;
        }, openExisting: true);
    }

    public bool ContainsLogical(StoreLocation location, string id)
    {
        Validate(location);
        using X509Store store = new("Disallowed", location);
        try
        {
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived);
        }
        catch (Exception error) when (IsMissing(error))
        {
            return false;
        }
        X509Certificate2Collection certificates = store.Certificates;
        try
        {
            return certificates.Cast<X509Certificate2>().Any(certificate =>
                string.Equals(certificate.Thumbprint, id, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            foreach (X509Certificate2 certificate in certificates)
                certificate.Dispose();
        }
    }

    private static T WithPhysical<T>(StoreLocation location, bool writable, Func<X509Store, T> action,
        bool openExisting = false)
    {
        Validate(location);
        uint flags = (location == StoreLocation.CurrentUser ? CurrentUser : LocalMachine)
            | IncludeArchived | (writable ? 0u : ReadOnly) | (openExisting || !writable ? OpenExisting : 0u);
        IntPtr handle = CertOpenStore(new IntPtr(ProviderSystemRegistryW), 0, IntPtr.Zero,
            flags, "Disallowed");
        if (handle == IntPtr.Zero)
        {
            int code = Marshal.GetLastWin32Error();
            if ((openExisting || !writable) && IsMissingCode(code))
                return default!;
            throw new Win32Exception(code, "Не удалось открыть собственное хранилище Disallowed.");
        }
        try
        {
            using X509Store store = new(handle);
            return action(store);
        }
        finally
        {
            CertCloseStore(handle, 0);
        }
    }

    private static bool IsMissing(Exception error) => error is System.Security.Cryptography.CryptographicException crypto
        && IsMissingCode(crypto.HResult);

    private static bool IsMissingCode(int code) => code is FileNotFound or PathNotFound or CryptNotFound
        or unchecked((int)0x80070002) or unchecked((int)0x80070003);

    private static void Validate(StoreLocation location)
    {
        if (location is not (StoreLocation.CurrentUser or StoreLocation.LocalMachine))
            throw new ArgumentOutOfRangeException(nameof(location));
    }

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CertOpenStore(IntPtr provider, uint encodingType, IntPtr cryptProvider,
        uint flags, string name);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertCloseStore(IntPtr store, uint flags);
}
