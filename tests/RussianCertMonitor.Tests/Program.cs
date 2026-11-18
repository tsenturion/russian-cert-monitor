using RussianCertMonitor.Infrastructure;

namespace RussianCertMonitor.Tests;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            if (args.Contains("--computer-block", StringComparer.Ordinal))
            {
                ComputerDisallowedWorkflowChecks.Run();
                Console.WriteLine("Проверки общего запрета и обработки прежней пользовательской записи пройдены.");
                return 0;
            }
            if (args.Contains("--trust", StringComparer.Ordinal))
            {
                WindowsTrustChecks.Run();
                Console.WriteLine("Встроенная проверка доверия Windows пройдена.");
                return 0;
            }
            if (args.Contains("--live-trust-user", StringComparer.Ordinal)
                || args.Contains("--live-trust-machine", StringComparer.Ordinal))
            {
                bool machine = args.Contains("--live-trust-machine", StringComparer.Ordinal);
                using System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                if (machine && !new System.Security.Principal.WindowsPrincipal(identity)
                    .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
                    throw new InvalidOperationException("Проверка доверия LocalMachine требует запуска от администратора.");
                var scope = machine ? System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine
                    : System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser;
                WindowsTrustChecks.RunLive(scope);
                Console.WriteLine($"Windows подтвердила явный запрет в {scope}, его область и снятие.");
                return 0;
            }
            if (args.Contains("--logging", StringComparer.Ordinal))
            {
                LoggingChecks.Run();
                Console.WriteLine("Проверки отказа и восстановления диагностического журнала пройдены.");
                return 0;
            }
            if (args.Contains("--catalog", StringComparer.Ordinal))
            {
                CatalogChecks.Run();
                Console.WriteLine("Проверки публичного справочника и локальной истории пройдены.");
                return 0;
            }
            if (args.Contains("--stage6", StringComparer.Ordinal))
            {
                int outputIndex = Array.IndexOf(args, "--output-directory");
                string output = outputIndex >= 0 && outputIndex + 1 < args.Length ? args[outputIndex + 1]
                    : Path.Combine(FindRepositoryRoot(), "work", "release-checks");
                Stage6Checks.Run(output);
                Console.WriteLine("Интеграционные проверки этапа 6 пройдены.");
                return 0;
            }
            if (args.Contains("--stage5", StringComparer.Ordinal))
            {
                Stage5SettingsChecks.Run();
                Stage5DataChecks.Run();
                SettingsFormChecks.Run();
                MainFormChecks.Run();
                Console.WriteLine("Проверки настроек, правил, истории, отчётов и интерфейса этапа 5 пройдены.");
                return 0;
            }
            if (args.Contains("--stage5-settings", StringComparer.Ordinal))
            {
                Stage5SettingsChecks.Run();
                Console.WriteLine("Проверки настроек, правил, уведомлений и записи истории пройдены.");
                return 0;
            }
            if (args.Contains("--stage5-ui", StringComparer.Ordinal))
            {
                SettingsFormChecks.Run();
                Console.WriteLine("Проверки интерфейса настроек пройдены.");
                return 0;
            }
            if (args.Contains("--stage5-data", StringComparer.Ordinal))
            {
                Stage5DataChecks.Run();
                Console.WriteLine("Проверки истории и экспорта отчётов пройдены.");
                return 0;
            }
            if (args.Contains("--mainform", StringComparer.Ordinal))
            {
                MainFormChecks.Run();
                Console.WriteLine("Проверки интерфейса пройдены.");
                return 0;
            }
            if (args.Contains("--properties-smoke", StringComparer.Ordinal))
            {
                CertificatePropertiesChecks.Run();
                return 0;
            }
            if (args.Contains("--stage4", StringComparer.Ordinal))
            {
                DisallowedChecks.Run();
                MainFormChecks.Run();
                OperationProtocolChecks.Run();
                Console.WriteLine("Проверки публичных сертификатов, чёрного списка, интерфейса и протокола этапа 4 пройдены.");
                return 0;
            }
            if (args.Contains("--live-disallowed-user", StringComparer.Ordinal))
            {
                DisallowedChecks.RunLive(System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
                Console.WriteLine("Добавление и удаление изолированного тестового сертификата в CurrentUser Disallowed проверены.");
                return 0;
            }
            if (args.Contains("--live-disallowed-machine", StringComparer.Ordinal))
            {
                using System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                if (!new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
                    throw new InvalidOperationException("Проверка LocalMachine требует запуска от администратора.");
                DisallowedChecks.RunLive(System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
                Console.WriteLine("Добавление и удаление изолированного тестового сертификата в LocalMachine Disallowed проверены.");
                return 0;
            }
            if (args.Contains("--stage3", StringComparer.Ordinal))
            {
                MonitorDetectorChecks.Run();
                MonitorServiceChecks.Run();
                Console.WriteLine("Проверки мониторинга, сохранения состояния и уведомлений третьего этапа пройдены.");
                return 0;
            }
            if (args.Contains("--inventory", StringComparer.Ordinal) || args.Contains("--trust-inventory", StringComparer.Ordinal))
            {
                InventoryChecks.WriteLiveSnapshot(args.Contains("--trust-inventory", StringComparer.Ordinal));
                return 0;
            }
            if (args.Contains("--stage2", StringComparer.Ordinal))
            {
                ClassifierChecks.Run();
                InventoryChecks.Run();
                Console.WriteLine("Проверки классификации и инвентаря второго этапа пройдены.");
                return 0;
            }
            VerifySingleInstance();
            VerifyLogRetention();
            Console.WriteLine("Проверки единичного экземпляра и хранения журналов пройдены.");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"Проверка не пройдена: {error}");
            return 1;
        }
    }

    private static void VerifySingleInstance()
    {
        string instanceId = $"RussianCertMonitor.Tests.{Guid.NewGuid():N}";
        using (SingleInstanceCoordinator primary = new(instanceId))
        using (SingleInstanceCoordinator secondary = new(instanceId))
        {
            Require(primary.IsPrimaryInstance, "Первый экземпляр должен владеть блокировкой.");
            Require(!secondary.IsPrimaryInstance, "Второй экземпляр не должен получать блокировку.");
            secondary.RequestActivation();
            Require(primary.ActivationEvent.WaitOne(TimeSpan.FromSeconds(1)),
                "Запрос второго экземпляра должен достигать первого.");
        }
        using SingleInstanceCoordinator next = new(instanceId);
        Require(next.IsPrimaryInstance, "После завершения приложения блокировка должна освобождаться.");
    }

    private static void VerifyLogRetention()
    {
        string root = FindRepositoryRoot();
        string directory = Path.Combine(root, "work", "checks", $"retention-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string old = Path.Combine(directory,
            $"RussianCertMonitor-{DateTime.UtcNow.AddDays(-40):yyyy-MM-dd}-1.jsonl");
        string recent = Path.Combine(directory,
            $"RussianCertMonitor-{DateTime.UtcNow.AddDays(-2):yyyy-MM-dd}-1.jsonl");
        string foreign = Path.Combine(directory, "данные-пользователя.jsonl");
        File.WriteAllText(old, "Старый журнал приложения.");
        File.WriteAllText(recent, "Недавний журнал приложения.");
        File.WriteAllText(foreign, "Посторонний файл.");

        DiagnosticLog log = new(directory);
        Require(!File.Exists(old), "Журнал старше 30 дней должен удаляться.");
        Require(File.Exists(recent), "Недавний журнал должен сохраняться.");
        Require(File.Exists(foreign), "Посторонние файлы не должны удаляться.");
        log.Write("test.record", "Проверка записи диагностического события.");
        string recordPath = Directory.EnumerateFiles(directory,
            $"RussianCertMonitor-{DateTime.UtcNow:yyyy-MM-dd}-{Environment.ProcessId}.jsonl").Single();
        Require(File.ReadAllText(recordPath).Contains("Проверка записи", StringComparison.Ordinal),
            "Диагностическое событие должно сохраняться на диске.");
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "global.json")))
                return current.FullName;
            current = current.Parent;
        }
        throw new InvalidOperationException("Не найден корень проекта для временных файлов проверки.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
