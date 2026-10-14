using RussianCertMonitor.Infrastructure;

namespace RussianCertMonitor.Tests;

internal static class LoggingChecks
{
    public static void Run()
    {
        string root = Path.Combine(Path.GetTempPath(), "RCM-Logging-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string path = Path.Combine(root, "Logs");
            DiagnosticLog log = new(path);
            log.TryWrite("test.started", "Начало проверки.");
            string record = Directory.GetFiles(path).Single();
            File.Delete(record);
            Directory.Delete(path);
            File.WriteAllText(path, "Папка журналов заменена недоступным объектом.");
            log.Prune();
            log.TryWrite("test.failed", "Проверка продолжает работать без доступного журнала.");
            Require(log.RetentionWarning is not null && log.DiagnosticWarning is not null,
                "Ошибка перечисления или записи должна возвращать предупреждение вместо остановки приложения.");
            DiagnosticLog unavailableAtStartup = new(path);
            Require(unavailableAtStartup.DiagnosticWarning is not null,
                "Недоступный журнал при запуске не должен мешать созданию приложения.");
            File.Delete(path);
            Directory.CreateDirectory(path);
            log.Prune();
            log.TryWrite("test.recovered", "Журнал снова доступен.");
            Require(log.RetentionWarning is null && log.DiagnosticWarning is null && Directory.GetFiles(path).Length == 1,
                "После восстановления доступа запись должна возобновляться и предупреждение сбрасываться.");
        }
        finally { Directory.Delete(root, true); }
    }

    private static void Require(bool value, string message)
    {
        if (!value)
            throw new InvalidOperationException(message);
    }
}
