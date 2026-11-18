using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.Disallowed;
using RussianCertMonitor.Infrastructure;
using RussianCertMonitor.Inventory;

namespace RussianCertMonitor.UI;

internal sealed class CertificateActionController(
    Func<IWin32Window?> owner, Func<bool> beginOperation, Action endOperation,
    Func<Task> refresh, DiagnosticLog log, CancellationToken cancellationToken)
{
    private readonly DisallowedManager manager = new(new WindowsDisallowedStoreBackend(), log);
    private readonly ElevatedOperationClient elevated = new(new PrivilegedProcessLauncher());

    public CertificateUiActions Actions => new(ShowProperties, Export,
        certificate => ChangeAsync(certificate, DisallowedOperation.Add),
        certificate => ChangeAsync(certificate, DisallowedOperation.Remove),
        () => ChangeAsync(null, DisallowedOperation.Add));

    private void ShowProperties(InventoryCertificate certificate)
    {
        try
        {
            CertificateProperties.Show(owner(), PublicCertificateData.FromDer(certificate.Metadata.RawData));
            log.TryWrite("certificate.properties", $"Просмотр свойств: {certificate.Metadata.CertificateId}.");
        }
        catch (Exception error) { ShowError("Не удалось открыть свойства сертификата.", error); }
    }

    private void Export(InventoryCertificate certificate)
    {
        try
        {
            PublicCertificateData data = PublicCertificateData.FromDer(certificate.Metadata.RawData);
            using SaveFileDialog dialog = new()
            {
                Title = "Экспорт публичного сертификата", Filter = "Публичный сертификат (*.cer)|*.cer",
                DefaultExt = "cer", AddExtension = true, OverwritePrompt = true,
                FileName = data.Metadata.CertificateId + ".cer"
            };
            if (dialog.ShowDialog(owner()) != DialogResult.OK)
                return;
            if (!Path.GetExtension(dialog.FileName).Equals(".cer", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Для экспорта публичного сертификата выберите файл с расширением .cer.");
            data.ExportCer(dialog.FileName);
            log.TryWrite("certificate.exported", $"Публичный CER: {data.Metadata.CertificateId}; путь: {dialog.FileName}.",
                context: new(data.Metadata.CertificateId, Result: "exported"));
        }
        catch (Exception error) { ShowError("Не удалось экспортировать публичный сертификат.", error); }
    }

    private async Task ChangeAsync(InventoryCertificate? selected, DisallowedOperation operation)
    {
        if (!beginOperation())
            return;
        bool attempted = false;
        LogContext? actionContext = null;
        try
        {
            PublicCertificateData certificate;
            if (selected is null)
            {
                using OpenFileDialog dialog = new()
                {
                    Title = "Импорт одного публичного сертификата в чёрный список",
                    Filter = "Публичный сертификат (*.cer;*.crt;*.pem)|*.cer;*.crt;*.pem",
                    CheckFileExists = true, Multiselect = false
                };
                if (dialog.ShowDialog(owner()) != DialogResult.OK)
                    return;
                certificate = await Task.Run(() => PublicCertificateData.FromFile(dialog.FileName), cancellationToken);
            }
            else
                certificate = PublicCertificateData.FromDer(selected.Metadata.RawData);

            actionContext = new(certificate.Metadata.CertificateId, "LocalMachine\\Disallowed", operation.ToString());
            attempted = true;
            ComputerDisallowedWorkflow workflow = new(manager, elevated.ExecuteAsync, log);
            ComputerDisallowedChange? change = await workflow.ChangeAsync(operation, certificate, cancellationToken);
            if (change is null)
                return;
            string message = operation == DisallowedOperation.Add
                ? "Запрет компьютера: собственная запись в LocalMachine\\Disallowed подтверждена."
                : "Запрет компьютера: отсутствие собственной записи в LocalMachine\\Disallowed подтверждено.";
            if (!change.Computer.Changed)
                message += "\r\nСостояние запрета компьютера уже было установлено.";
            if (change.UserCleanup is { } userCleanup)
                message += userCleanup.Changed
                    ? "\r\nПрежняя запись текущего пользователя удалена."
                    : "\r\nСобственной записи текущего пользователя уже не было.";
            else if (change.UserCleanupError is not null)
                message += $"\r\nНе удалось убрать прежнюю запись текущего пользователя: {change.UserCleanupError}";
            else if (operation == DisallowedOperation.Add
                && (!change.Trust.CurrentUser.IsExplicitlyDistrusted || !change.Trust.LocalMachine.IsExplicitlyDistrusted))
                message += "\r\nПрежняя запись текущего пользователя не проверялась: запрет не подтверждён в обеих областях Windows.";
            else
                message += "\r\nПрежней собственной записи текущего пользователя нет.";
            if (operation == DisallowedOperation.Remove && change.Computer.LogicalPresentAfter)
                message += "\r\nЗапись остаётся видимой в логическом Disallowed компьютера; возможно действие политики Windows.";
            message += $"\r\n\r\nЦепочка Windows (пользователь): {change.Trust.CurrentUser.Details}" +
                $"\r\nЦепочка Windows (компьютер): {change.Trust.LocalMachine.Details}";
            if (!change.IsConfirmed)
                message += "\r\nОперация подтверждена не полностью. Состояние записей и результаты Windows приведены выше.";
            message += "\r\nПриложения с собственной политикой доверия могут оценивать сертификат иначе.";
            bool verificationWarning = !change.IsConfirmed || change.UserCleanupError is not null;
            MessageBox.Show(owner(), message, "RussianCertMonitor", MessageBoxButtons.OK,
                verificationWarning ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Завершение основного приложения отменяет ещё не выполненную операцию.
        }
        catch (Exception error) { ShowError("Операция с чёрным списком не завершена.", error, actionContext); }
        finally
        {
            endOperation();
            if (attempted && !cancellationToken.IsCancellationRequested)
                await refresh();
        }
    }

    private void ShowError(string message, Exception error, LogContext? context = null)
    {
        log.TryWrite("certificate.action-error", message, error, context);
        if (!cancellationToken.IsCancellationRequested)
            MessageBox.Show(owner(), message + "\r\n\r\n" + ErrorText.Describe(error), "RussianCertMonitor",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

}
