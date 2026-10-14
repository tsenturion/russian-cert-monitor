using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.UI;

namespace RussianCertMonitor.Tests;

internal static class CertificatePropertiesChecks
{
    public static void Run()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new("CN=Properties-Test, C=US", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        bool seen = false;
        bool installDisabled = false;
        using System.Windows.Forms.Timer timer = new() { Interval = 250 };
        timer.Tick += (_, _) => EnumWindows((handle, _) =>
        {
            GetWindowThreadProcessId(handle, out uint processId);
            StringBuilder text = new(256);
            GetWindowTextW(handle, text, text.Capacity);
            if (processId != Environment.ProcessId || text.ToString() != "Свойства сертификата") return true;
            seen = true;
            EnumChildWindows(handle, (child, _) =>
            {
                StringBuilder name = new(256);
                GetWindowTextW(child, name, name.Capacity);
                if (name.ToString().Contains("Установить", StringComparison.OrdinalIgnoreCase)
                    || name.ToString().Contains("Install", StringComparison.OrdinalIgnoreCase))
                    installDisabled = !IsWindowEnabled(child);
                return true;
            }, IntPtr.Zero);
            PostMessageW(handle, 0x0010, IntPtr.Zero, IntPtr.Zero);
            return true;
        }, IntPtr.Zero);
        timer.Start();
        CertificateProperties.Show(null, PublicCertificateData.FromDer(certificate.Export(X509ContentType.Cert)));
        timer.Stop();
        if (!seen || !installDisabled)
            throw new InvalidOperationException("Нативное окно свойств не открылось или установка сертификата в нём разрешена.");
        Console.WriteLine("Нативные свойства открыты; установка сертификата отключена; окно автоматически закрыто.");
    }

    private delegate bool WindowCallback(IntPtr handle, IntPtr argument);
    [DllImport("user32.dll")] private static extern bool EnumWindows(WindowCallback callback, IntPtr argument);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr parent, WindowCallback callback, IntPtr argument);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr handle, out uint processId);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern int GetWindowTextW(IntPtr handle, StringBuilder text, int count);
    [DllImport("user32.dll")] private static extern bool IsWindowEnabled(IntPtr handle);
    [DllImport("user32.dll", ExactSpelling = true)] private static extern bool PostMessageW(IntPtr handle, uint message, IntPtr wparam, IntPtr lparam);
}
