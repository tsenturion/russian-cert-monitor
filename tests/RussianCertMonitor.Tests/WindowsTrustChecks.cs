using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.Disallowed;

namespace RussianCertMonitor.Tests;

internal static class WindowsTrustChecks
{
    public static void Run()
    {
        using X509Certificate2 certificate = CreateCertificate();
        byte[] der = certificate.Export(X509ContentType.Cert);
        using WindowsTrustVerifier verifier = new();
        WindowsTrustAssessment baseline = verifier.Verify(der);
        RequireUntrusted(baseline.CurrentUser, "Пользователь");
        RequireUntrusted(baseline.LocalMachine, "Компьютер");

        WindowsTrustAssessment invalid = verifier.Verify([1, 2, 3]);
        RequireFailure(invalid.CurrentUser, "Пользователь");
        RequireFailure(invalid.LocalMachine, "Компьютер");
    }

    public static void RunLive(StoreLocation location)
    {
        if (location is not (StoreLocation.CurrentUser or StoreLocation.LocalMachine))
            throw new ArgumentOutOfRangeException(nameof(location));

        using X509Certificate2 certificate = CreateCertificate();
        byte[] der = certificate.Export(X509ContentType.Cert);
        PublicCertificateData data = PublicCertificateData.FromDer(der);
        string id = data.Metadata.CertificateId;
        WindowsDisallowedStoreBackend backend = new();
        DisallowedManager manager = new(backend);
        Require(!backend.Contains(StoreLocation.CurrentUser, id)
            && !backend.Contains(StoreLocation.LocalMachine, id),
            "Тестовый сертификат уже находится в Disallowed.");
        foreach (StoreLocation scope in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
            Require(!InStore(scope, StoreName.Root, id) && !InStore(scope, StoreName.CertificateAuthority, id),
                "Тестовый сертификат уже находится в Root или CA.");

        try
        {
            using (WindowsTrustVerifier verifier = new())
            {
                WindowsTrustAssessment baseline = verifier.Verify(der);
                RequireUntrusted(baseline.CurrentUser, "Пользователь до добавления");
                RequireUntrusted(baseline.LocalMachine, "Компьютер до добавления");
            }

            DisallowedResult added = manager.Execute(manager.Preview(DisallowedOperation.Add, location, data));
            Require(added.Changed && added.OwnPresentAfter && backend.Contains(location, id),
                "Добавление в собственный Disallowed не подтверждено.");
            using (WindowsTrustVerifier verifier = new())
            {
                WindowsTrustAssessment blocked = verifier.Verify(der);
                RequireExplicitlyDistrusted(blocked.CurrentUser, "Пользователь после добавления");
                if (location == StoreLocation.LocalMachine)
                    RequireExplicitlyDistrusted(blocked.LocalMachine, "Компьютер после добавления");
                else
                    RequireUntrusted(blocked.LocalMachine, "Компьютер после добавления пользователю");
            }

            DisallowedResult removed = manager.Execute(manager.Preview(DisallowedOperation.Remove, location, data));
            Require(removed.Changed && !removed.OwnPresentAfter && !backend.Contains(location, id),
                "Удаление из собственного Disallowed не подтверждено.");
            using (WindowsTrustVerifier verifier = new())
            {
                WindowsTrustAssessment restored = verifier.Verify(der);
                RequireUntrusted(restored.CurrentUser, "Пользователь после удаления");
                RequireUntrusted(restored.LocalMachine, "Компьютер после удаления");
            }
        }
        finally
        {
            if (backend.Contains(location, id))
                backend.Remove(location, id);
            Require(!backend.Contains(location, id), "Тестовый сертификат остался в Disallowed.");
        }
    }

    private static X509Certificate2 CreateCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new($"CN=RussianCertMonitor-Trust-Test-{Guid.NewGuid():N}, C=US", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static bool InStore(StoreLocation location, StoreName name, string id)
    {
        using X509Store store = new(name, location);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived);
        X509Certificate2Collection certificates = store.Certificates;
        try { return certificates.Cast<X509Certificate2>().Any(item => item.Thumbprint == id); }
        finally { foreach (X509Certificate2 item in certificates) item.Dispose(); }
    }

    private static void RequireUntrusted(WindowsChainResult result, string scope)
    {
        Require(result.Failure is null && result.ErrorStatus is uint status
            && (status & (uint)X509ChainStatusFlags.UntrustedRoot) != 0
            && !result.IsAccepted && !result.IsExplicitlyDistrusted,
            $"{scope}: ожидается обычное недоверие к самоподписанному сертификату; {result.Details}");
    }

    private static void RequireExplicitlyDistrusted(WindowsChainResult result, string scope)
    {
        Require(result.Failure is null && !result.IsAccepted && result.IsExplicitlyDistrusted,
            $"{scope}: ожидается явный запрет Windows; {result.Details}");
    }

    private static void RequireFailure(WindowsChainResult result, string scope)
    {
        Require(!string.IsNullOrWhiteSpace(result.Failure) && !result.IsAccepted
            && !result.IsExplicitlyDistrusted,
            $"{scope}: некорректный DER должен давать ошибку без признака доверия; {result.Details}");
    }

    private static void Require(bool value, string message)
    {
        if (!value) throw new InvalidOperationException(message);
    }
}
