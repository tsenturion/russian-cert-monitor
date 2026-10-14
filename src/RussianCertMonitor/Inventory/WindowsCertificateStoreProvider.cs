using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RussianCertMonitor.Inventory;

internal sealed class WindowsCertificateStoreProvider : ICertificateStoreProvider
{
    public IReadOnlyList<CertificateStoreDescriptor> EnumerateStores(StoreLocation location)
    {
        List<CertificateStoreDescriptor> stores = [];
        Exception? callbackError = null;
        EnumStoreCallback callback = (namePointer, _, _, _, _) =>
        {
            try
            {
                string name = Marshal.PtrToStringUni(namePointer)
                    ?? throw new InvalidOperationException("Windows вернула пустое имя хранилища.");
                stores.Add(new CertificateStoreDescriptor(location, name));
                return true;
            }
            catch (Exception error)
            {
                callbackError = error;
                return false;
            }
        };

        uint flags = location == StoreLocation.CurrentUser ? 0x00010000u : 0x00020000u;
        bool success = CertEnumSystemStore(flags, IntPtr.Zero, IntPtr.Zero, callback);
        int nativeError = Marshal.GetLastWin32Error();
        GC.KeepAlive(callback);
        if (callbackError is not null)
            throw new InvalidOperationException("Не удалось получить список хранилищ Windows.", callbackError);
        if (!success)
            throw new Win32Exception(nativeError, "Не удалось перечислить хранилища Windows.");

        return stores.DistinctBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public CertificateStoreReadResult ReadStore(CertificateStoreDescriptor descriptor)
    {
        using X509Store store = new(descriptor.Name, descriptor.Location);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived);
        List<CertificateObservation> observations = [];
        List<string> storeErrors = [];
        X509Certificate2Collection certificates = store.Certificates;
        try
        {
            foreach (X509Certificate2 certificate in certificates)
            {
                List<string> errors = [];
                string id = Read(() => certificate.Thumbprint, "идентификатор", "", errors);
                if (string.IsNullOrWhiteSpace(id))
                {
                    storeErrors.Add("Сертификат пропущен: идентификатор недоступен. " + string.Join(" ", errors));
                    continue;
                }

                string subject = Read(() => certificate.Subject, "владелец", "", errors);
                string issuer = Read(() => certificate.Issuer, "издатель", "", errors);
                string displayName = Read(() => certificate.GetNameInfo(X509NameType.SimpleName, false),
                    "название", "", errors);
                if (string.IsNullOrWhiteSpace(displayName))
                    displayName = string.IsNullOrWhiteSpace(subject) ? id : subject;

                CertificateMetadata metadata = new(
                    id, displayName, subject, issuer,
                    Read(() => certificate.SerialNumber, "серийный номер", "", errors),
                    Read<DateTimeOffset?>(() => new DateTimeOffset(certificate.NotBefore),
                        "начало срока", null, errors),
                    Read<DateTimeOffset?>(() => new DateTimeOffset(certificate.NotAfter),
                        "конец срока", null, errors),
                    Read(() => certificate.SubjectName.RawData, "DER владельца", [], errors),
                    Read(() => certificate.IssuerName.RawData, "DER издателя", [], errors),
                    Read(() => certificate.RawData, "DER сертификата", [], errors));
                observations.Add(new CertificateObservation(metadata, errors));
            }
        }
        finally
        {
            foreach (X509Certificate2 certificate in certificates)
                certificate.Dispose();
        }
        return new CertificateStoreReadResult(observations, storeErrors);
    }

    private static T Read<T>(Func<T> getter, string field, T fallback, List<string> errors)
    {
        try
        {
            return getter();
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException
            or NotSupportedException)
        {
            errors.Add($"Не удалось прочитать поле «{field}»: {error.Message}");
            return fallback;
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool EnumStoreCallback(IntPtr name, uint flags, IntPtr info, IntPtr reserved, IntPtr argument);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertEnumSystemStore(uint flags, IntPtr location, IntPtr argument,
        EnumStoreCallback callback);
}
