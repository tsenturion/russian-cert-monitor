using System.Security.Principal;
using RussianCertMonitor.Catalog;
using RussianCertMonitor.Disallowed;
using RussianCertMonitor.Infrastructure;
using RussianCertMonitor.UI;
using RussianCertMonitor.History;

namespace RussianCertMonitor;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        if (args.Length != 0)
            return PrivilegedOperationHost.Run(args);
        DiagnosticLog? log = null;
        try
        {
            log = new DiagnosticLog(AppPaths.LogDirectory);
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            string userId = identity.User?.Value ?? Environment.UserName;
            using SingleInstanceCoordinator instance = new($"RussianCertMonitor.{userId}");
            if (!instance.IsPrimaryInstance)
            {
                instance.RequestActivation();
                log.TryWrite("instance.activation-requested",
                    "Второй экземпляр передал запрос на открытие окна работающему приложению.");
                return 0;
            }

            HistoryStore history = new(AppPaths.HistoryDirectory);
            log.AttachHistory(history);
            try
            {
                Directory.CreateDirectory(AppPaths.HistoryDirectory);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                log.SetHistoryWarning("История событий недоступна. " + ErrorText.Describe(error));
                log.TryWrite("history.storage-error", "Не удалось подготовить историю событий.", error);
            }
            CertificateCatalog catalog;
            string? catalogWarning = null;
            try { catalog = CertificateCatalog.Load(AppPaths.LocalCatalogFile); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException or System.Text.Json.JsonException)
            {
                catalog = CertificateCatalog.Load();
                catalogWarning = "Локальная история сертификатов не прочитана; используется публичный справочник. " + ErrorText.Describe(error);
                log.TryWrite("catalog.load-error", catalogWarning, error);
            }
            log.TryWrite("application.started",
                $"Запуск {Application.ProductVersion}; путь: {Environment.ProcessPath}; " +
                $"записей справочника: {catalog.Certificates.Count}; " +
                $"российских: {catalog.KnownRussianCount}.");

            Application.ThreadException += (_, eventArgs) =>
            {
                log.TryWrite("application.ui-error", "Ошибка интерфейса приложения.", eventArgs.Exception);
                MessageBox.Show(
                    "Произошла ошибка интерфейса. Подробности сохранены в журнале приложения.",
                    "RussianCertMonitor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            };
            AppDomain.CurrentDomain.UnhandledException += (_, eventArgs) =>
                log.TryWrite("application.unhandled-error", "Необработанная ошибка приложения.",
                    eventArgs.ExceptionObject as Exception);

            using TrayApplicationContext context = new(catalog, log, instance, history, catalogWarning);
            Application.Run(context);
            return 0;
        }
        catch (Exception error)
        {
            log?.TryWrite("application.startup-error", "Не удалось запустить приложение.", error);
            MessageBox.Show(
                $"Не удалось запустить RussianCertMonitor.\n\n{ErrorText.Describe(error)}",
                "RussianCertMonitor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
