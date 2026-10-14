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

            StoreLocation initial = selected is not null && operation == DisallowedOperation.Remove
                && !selected.Locations.Any(item => item.Location == StoreLocation.CurrentUser && item.Name.Equals("Disallowed", StringComparison.OrdinalIgnoreCase))
                ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
            StoreLocation? scope = DisallowedDialogs.SelectScope(owner(), certificate, operation, initial);
            if (scope is null)
                return;
            actionContext = new(certificate.Metadata.CertificateId, $"{scope}\\Disallowed", operation.ToString());
            attempted = true;
            DisallowedResult? result;
            if (scope == StoreLocation.LocalMachine)
            {
                log.TryWrite("disallowed.elevation-requested", $"Операция: {operation}; LocalMachine; ID: {certificate.Metadata.CertificateId}.",
                    context: new(certificate.Metadata.CertificateId, "LocalMachine\\Disallowed", operation.ToString()));
                DisallowedReply reply = await elevated.ExecuteAsync(new DisallowedJob(1, operation, scope.Value,
                    certificate.Metadata.CertificateId, certificate.Metadata.RawData), cancellationToken);
                if (reply.Cancelled)
                {
                    log.TryWrite("disallowed.cancelled", "Операция отменена в UAC или окне подтверждения.",
                        context: new(certificate.Metadata.CertificateId, "LocalMachine\\Disallowed", "cancelled"));
                    return;
                }
                if (reply.Error is not null)
                    throw new InvalidOperationException(reply.Error);
                result = reply.Result ?? throw new InvalidDataException("Операция не вернула подтверждённый результат.");
                log.TryWrite("disallowed.completed", $"Операция: {result.Operation}; область: {result.Location}; ID: {result.CertificateId}; " +
                    $"изменено: {result.Changed}; своё: {result.OwnPresentAfter}; логическое: {result.LogicalPresentAfter}.",
                    context: new(result.CertificateId, "LocalMachine\\Disallowed",
                        $"{result.Operation}; changed={result.Changed}; ownPresent={result.OwnPresentAfter}; logicalPresent={result.LogicalPresentAfter}"));
            }
            else
            {
                DisallowedPreview preview = await Task.Run(() => manager.Preview(operation, scope.Value, certificate), cancellationToken);
                if (!DisallowedDialogs.Confirm(owner(), preview))
                {
                    log.TryWrite("disallowed.cancelled", "Операция отменена перед изменением CurrentUser.",
                        context: new(certificate.Metadata.CertificateId, "CurrentUser\\Disallowed", "cancelled"));
                    return;
                }
                result = await Task.Run(() => manager.Execute(preview), cancellationToken);
            }
            string message = operation == DisallowedOperation.Add
                ? $"Собственная запись в чёрном списке подтверждена: {DisallowedDialogs.ScopeName(result.Location)}."
                : $"Отсутствие собственной записи подтверждено: {DisallowedDialogs.ScopeName(result.Location)}.";
            if (operation == DisallowedOperation.Remove && result.LogicalPresentAfter)
                message += "\r\nСертификат остаётся видимым в логическом Disallowed. Возможны наследование из области компьютера или политика Windows.";
            if (!result.Changed)
                message += "\r\nИзменения не потребовались: выбранное состояние уже было установлено.";
            MessageBox.Show(owner(), message, "RussianCertMonitor", MessageBoxButtons.OK, MessageBoxIcon.Information);
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
