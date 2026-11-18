using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace RussianCertMonitor.Certificates;

internal sealed record WindowsChainResult(uint? ErrorStatus, string? Failure = null)
{
    private const uint ExplicitDistrust = 0x04000000;

    public bool IsAccepted => ErrorStatus == 0;
    public bool IsExplicitlyDistrusted => (ErrorStatus.GetValueOrDefault() & ExplicitDistrust) != 0;

    public string StatusText => ErrorStatus is null ? "Не проверено"
        : IsExplicitlyDistrusted ? "Явный запрет в цепочке"
        : IsAccepted ? "Цепочка без ошибок"
        : "Ошибки цепочки";

    public string Details => ErrorStatus is null ? Failure ?? "Результат Windows недоступен."
        : IsAccepted ? StatusText
        : $"{StatusText} (0x{ErrorStatus:X8}, {(X509ChainStatusFlags)ErrorStatus.Value}).";
}

internal sealed record WindowsTrustAssessment(WindowsChainResult CurrentUser, WindowsChainResult LocalMachine);

internal sealed class WindowsTrustVerifier : IDisposable
{
    private const uint CacheOnlyUrls = 0x00000004;
    private const uint UseMachineStore = 0x00000008;
    private const uint DisableRootAutoUpdate = 0x00000100;
    private const uint DisableAia = 0x00002000;
    private readonly ChainScope user = new(machine: false);
    private readonly ChainScope machine = new(machine: true);

    public WindowsTrustAssessment Verify(byte[] der)
    {
        try
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(der);
            return new(user.Check(certificate), machine.Check(certificate));
        }
        catch (CryptographicException error)
        {
            WindowsChainResult failure = new(null, $"Не удалось прочитать публичный сертификат: {error.Message}");
            return new(failure, failure);
        }
    }

    public void Dispose()
    {
        user.Dispose();
        machine.Dispose();
    }

    private sealed class ChainScope(bool machine) : IDisposable
    {
        private SafeChainEngine? engine;
        private WindowsChainResult? engineFailure;

        public WindowsChainResult Check(X509Certificate2 certificate)
        {
            if (engineFailure is not null)
                return engineFailure;
            if (engine is null)
            {
                ChainEngineConfig config = new()
                {
                    Size = (uint)Marshal.SizeOf<ChainEngineConfig>(),
                    Flags = CacheOnlyUrls | DisableAia | (machine ? UseMachineStore : 0)
                };
                if (!CertCreateCertificateChainEngine(ref config, out SafeChainEngine created))
                {
                    int error = Marshal.GetLastWin32Error();
                    created.Dispose();
                    return engineFailure = NativeFailure("Не удалось создать средство проверки цепочки Windows", error);
                }
                engine = created;
            }

            ChainParameters parameters = new() { Size = (uint)Marshal.SizeOf<ChainParameters>() };
            bool built = CertGetCertificateChain(engine, certificate.Handle, IntPtr.Zero, IntPtr.Zero, ref parameters,
                CacheOnlyUrls | DisableAia | DisableRootAutoUpdate, IntPtr.Zero, out SafeChain chain);
            int buildError = Marshal.GetLastWin32Error();
            GC.KeepAlive(certificate);
            using (chain)
            {
                if (!built)
                    return NativeFailure("Windows не удалось построить цепочку", buildError);
                // Первые поля CERT_CHAIN_CONTEXT — размер структуры и CERT_TRUST_STATUS.
                ChainContextHeader context = Marshal.PtrToStructure<ChainContextHeader>(chain.DangerousGetHandle());
                return new(context.ErrorStatus);
            }
        }

        public void Dispose() => engine?.Dispose();
    }

    private static WindowsChainResult NativeFailure(string step, int error) =>
        new(null, $"{step} (код {error}): {new Win32Exception(error).Message}");

    [StructLayout(LayoutKind.Sequential)]
    private struct ChainContextHeader
    {
        public uint Size;
        public uint ErrorStatus;
        public uint InfoStatus;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UsageMatch
    {
        public uint MatchType;
        public uint UsageCount;
        public IntPtr UsageOids;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ChainParameters
    {
        public uint Size;
        public UsageMatch RequestedUsage;
        public UsageMatch RequestedIssuancePolicy;
        public uint UrlTimeout;
        public int CheckRevocationFreshness;
        public uint RevocationFreshness;
        public IntPtr CacheResyncTime;
        public IntPtr StrongSignatureParameters;
        public uint StrongSignatureFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ChainEngineConfig
    {
        public uint Size;
        public IntPtr RestrictedRoot;
        public IntPtr RestrictedTrust;
        public IntPtr RestrictedOther;
        public uint AdditionalStoreCount;
        public IntPtr AdditionalStores;
        public uint Flags;
        public uint UrlTimeout;
        public uint MaximumCachedCertificates;
        public uint CycleDetectionModulus;
        public IntPtr ExclusiveRoot;
        public IntPtr ExclusiveTrustedPeople;
        public uint ExclusiveFlags;
    }

    private sealed class SafeChainEngine() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
    {
        protected override bool ReleaseHandle()
        {
            CertFreeCertificateChainEngine(handle);
            return true;
        }
    }

    private sealed class SafeChain() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
    {
        protected override bool ReleaseHandle()
        {
            CertFreeCertificateChain(handle);
            return true;
        }
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertCreateCertificateChainEngine(ref ChainEngineConfig config, out SafeChainEngine engine);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertGetCertificateChain(SafeChainEngine engine, IntPtr certificate, IntPtr time,
        IntPtr additionalStore, ref ChainParameters parameters, uint flags, IntPtr reserved, out SafeChain chain);

    [DllImport("crypt32.dll")]
    private static extern void CertFreeCertificateChainEngine(IntPtr engine);

    [DllImport("crypt32.dll")]
    private static extern void CertFreeCertificateChain(IntPtr chain);
}
