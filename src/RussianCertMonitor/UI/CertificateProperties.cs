using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Certificates;

namespace RussianCertMonitor.UI;

internal static class CertificateProperties
{
    public static void Show(IWin32Window? owner, PublicCertificateData data)
    {
        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(data.Metadata.RawData);
        CertificateView view = new()
        {
            Size = (uint)Marshal.SizeOf<CertificateView>(), Parent = owner?.Handle ?? IntPtr.Zero,
            Flags = 0x00000004 | 0x00000010 | 0x00002000 | 0x00040000,
            Title = "Свойства сертификата", CertificateContext = certificate.Handle
        };
        if (!CryptUIDlgViewCertificateW(ref view, out _))
        {
            int code = Marshal.GetLastWin32Error();
            if (code != 0 && code != 1223)
                throw new Win32Exception(code, "Не удалось открыть свойства сертификата.");
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CertificateView
    {
        public uint Size;
        public IntPtr Parent;
        public uint Flags;
        public string? Title;
        public IntPtr CertificateContext;
        public IntPtr Purposes;
        public uint PurposeCount;
        public IntPtr TrustData;
        public int TrustedUsage;
        public uint SignerIndex;
        public uint CertificateIndex;
        public int CounterSigner;
        public uint CounterSignerIndex;
        public uint StoreCount;
        public IntPtr Stores;
        public uint PageCount;
        public IntPtr Pages;
        public uint StartPage;
    }

    [DllImport("cryptui.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUIDlgViewCertificateW(ref CertificateView view,
        [MarshalAs(UnmanagedType.Bool)] out bool propertiesChanged);
}
