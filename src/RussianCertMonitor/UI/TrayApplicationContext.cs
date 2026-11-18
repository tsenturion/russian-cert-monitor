using System.Diagnostics;
using RussianCertMonitor.Catalog;
using RussianCertMonitor.Classification;
using RussianCertMonitor.Infrastructure;
using RussianCertMonitor.Inventory;
using RussianCertMonitor.Monitoring;
using RussianCertMonitor.History;
using RussianCertMonitor.Reporting;
using RussianCertMonitor.Settings;

namespace RussianCertMonitor.UI;

internal sealed class TrayApplicationContext : ApplicationContext
{
    private readonly CertificateCatalog catalog;
    private readonly DiagnosticLog log;
    private readonly Control dispatcher = new();
    private readonly ContextMenuStrip menu = new();
    private readonly Icon trayIcon = (Icon)SystemIcons.Shield.Clone();
    private readonly NotifyIcon notifyIcon;
    private readonly RegisteredWaitHandle activationRegistration;
    private readonly System.Windows.Forms.Timer retentionTimer = new();
    private readonly System.Windows.Forms.Timer pollTimer = new();
    private readonly CancellationTokenSource scanCancellation = new();
    private readonly MonitorService monitor;
    private readonly CertificateActionController certificateActions;
    private readonly ToolStripItem scanMenuItem;
    private readonly ToolStripItem settingsMenuItem;
    private readonly ToolStripItem reportMenuItem;
    private readonly HistoryStore history;
    private readonly SettingsStore settingsStore = new(AppPaths.SettingsFile);
    private MonitorSettings settings;
    private string? settingsWarning;
    private readonly string? catalogWarning;
    private string? historyRetentionWarning;
    private bool snapshotRestored;
    private long shownHistoryRevision = -1;
    private CertificateInventorySnapshot? snapshot;
    private string? scanFailure;
    private string? persistenceWarning;
    private bool scanning;
    private bool operationBusy;
    private MainForm? window;
    private volatile bool disposed;

    public TrayApplicationContext(
        CertificateCatalog catalog,
        DiagnosticLog log,
        SingleInstanceCoordinator instance,
        HistoryStore history,
        string? catalogWarning = null)
    {
        this.catalog = catalog;
        this.log = log;
        this.history = history;
        this.catalogWarning = catalogWarning;
        PruneHistory();
        SettingsLoadResult loaded = settingsStore.Load();
        settings = loaded.Settings;
        settingsWarning = loaded.Warning;
        if (loaded.Warning is not null)
            log.TryWrite("settings.load-error", loaded.Warning);
        else if (!File.Exists(settingsStore.FilePath))
        {
            try { settingsStore.Save(settings); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                settingsWarning = "Стандартные настройки не сохранены. " + ErrorText.Describe(error);
                log.TryWrite("settings.save-error", settingsWarning, error);
            }
        }
        monitor = new MonitorService(token => new CertificateInventoryService(new WindowsCertificateStoreProvider(),
            new RussianCertificateClassifier(catalog, settings), log, verifyWindowsTrust: true).Scan(token),
            new MonitorStateStore(AppPaths.MonitorStateFile), log);
        snapshot = monitor.RestoredSnapshot;
        snapshotRestored = snapshot is not null;
        persistenceWarning = monitor.InitializationWarning;
        certificateActions = new CertificateActionController(() => window, BeginOperation, EndOperation,
            () => ScanAsync(automatic: false), log, scanCancellation.Token);
        _ = dispatcher.Handle;

        menu.Items.Add("Открыть", null, (_, _) => ShowWindow());
        scanMenuItem = menu.Items.Add("Проверить сейчас", null, (_, _) => RequestScan());
        settingsMenuItem = menu.Items.Add("Настройки", null, (_, _) => _ = ShowSettingsAsync());
        reportMenuItem = menu.Items.Add("Экспорт отчёта", null, (_, _) => _ = ExportReportAsync());
        menu.Items.Add("Журнал", null, (_, _) => OpenLogDirectory());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Выход", null, (_, _) => ExitThread());

        notifyIcon = new NotifyIcon
        {
            Icon = trayIcon,
            Text = "RussianCertMonitor — мониторинг запускается",
            ContextMenuStrip = menu,
            Visible = true
        };
        notifyIcon.DoubleClick += (_, _) => ShowWindow();
        notifyIcon.BalloonTipClicked += (_, _) => ShowWindow();

        activationRegistration = ThreadPool.RegisterWaitForSingleObject(
            instance.ActivationEvent, (_, _) => QueueActivation(),
            null, Timeout.Infinite, false);

        retentionTimer.Interval = 60 * 60 * 1000;
        retentionTimer.Tick += (_, _) =>
        {
            try
            {
                log.Prune();
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                log.TryWrite("log.retention-error", "Проверка сроков хранения журналов не выполнена.", error);
            }
            PruneHistory();
            UpdateWarnings();
        };
        retentionTimer.Start();
        pollTimer.Interval = settings.PollIntervalSeconds * 1000;
        pollTimer.Tick += (_, _) => StartScan(automatic: true);
        pollTimer.Start();
        log.TryWrite("tray.ready", "Значок приложения добавлен в область уведомлений.");
        log.TryWrite("monitor.started", $"Проверка каждые {pollTimer.Interval / 1000} секунд; " +
            $"файл состояния: {AppPaths.MonitorStateFile}.");
        dispatcher.BeginInvoke(new Action(RequestScan));
    }

    private void QueueActivation()
    {
        if (disposed)
            return;
        try
        {
            dispatcher.BeginInvoke(new Action(() =>
            {
                if (!disposed)
                    ShowWindow();
            }));
        }
        catch (InvalidOperationException) when (disposed)
        {
            // Запрос, поступивший во время завершения приложения, уже не требует окна.
        }
    }

    private void ShowWindow()
    {
        if (window is null || window.IsDisposed)
        {
            window = new MainForm(catalog, RequestScan, certificateActions.Actions,
                new ApplicationUiActions(() => _ = ShowSettingsAsync(), () => _ = ExportReportAsync(), ReadHistoryAsync));
            window.FormClosed += (_, _) => window = null;
            if (snapshot is not null)
                window.ShowSnapshot(snapshot, snapshotRestored);
            if (scanFailure is not null)
                window.ShowScanFailure(scanFailure);
            window.ShowMonitorSettings(settings);
            UpdateWarnings();
            window.SetScanning(scanning);
            window.SetOperationBusy(operationBusy);
        }
        window.Show();
        if (window.WindowState == FormWindowState.Minimized)
            window.WindowState = FormWindowState.Normal;
        WindowVisibility.EnsureVisible(window);
        window.Activate();
        log.TryWrite("window.shown", $"Открыто окно сертификатов Windows; DPI: {window.DeviceDpi}; " +
            $"область окна: {window.ClientSize.Width}×{window.ClientSize.Height}.");
    }

    private void RequestScan() => StartScan(automatic: false);

    private void StartScan(bool automatic) => _ = ScanAsync(automatic);

    private async Task ScanAsync(bool automatic)
    {
        if (scanning || operationBusy || disposed)
            return;
        scanning = true;
        string? previousFailure = scanFailure;
        scanFailure = null;
        SetMenuBusy(true);
        notifyIcon.Text = "RussianCertMonitor — проверка…";
        window?.SetScanning(true, showProgress: !automatic);
        try
        {
            CancellationToken token = scanCancellation.Token;
            MonitorCycleResult cycle = await Task.Run(() => monitor.RunOnce(token));
            if (disposed)
                return;
            CertificateInventorySnapshot result = cycle.Snapshot;
            snapshot = result;
            snapshotRestored = false;
            persistenceWarning = cycle.PersistenceWarning;
            window?.ShowSnapshot(result);
            if (previousFailure is not null)
                log.TryWrite("inventory.recovered", "Чтение хранилищ снова завершено; результат обновлён.");
            UpdateWarnings();
            notifyIcon.Text = persistenceWarning is not null
                ? "RussianCertMonitor — ошибка сохранения состояния"
                : !result.IsComplete ? "RussianCertMonitor — хранилища прочитаны не полностью"
                : !result.TrustComplete ? "RussianCertMonitor — проверка доверия неполная"
                : $"RussianCertMonitor — компьютер принимает: {result.RussianAcceptedByComputerCount}";
            ShowNotification(cycle.Changes);
            RefreshHistory();
        }
        catch (OperationCanceledException) when (disposed)
        {
            // Фоновое чтение прекращается при завершении приложения.
        }
        catch (Exception error)
        {
            log.TryWrite("inventory.failed", "Проверка не завершена; предыдущий результат может быть устаревшим.", error);
            if (!disposed)
            {
                scanFailure = ErrorText.Describe(error);
                window?.ShowScanFailure(scanFailure);
                notifyIcon.Text = "RussianCertMonitor — ошибка проверки";
            }
        }
        finally
        {
            scanning = false;
            if (!disposed)
            {
                SetMenuBusy(operationBusy);
                window?.SetScanning(false);
                UpdateWarnings();
                RefreshHistory();
            }
        }
    }

    private bool BeginOperation()
    {
        if (disposed || scanning || operationBusy)
            return false;
        operationBusy = true;
        SetMenuBusy(true);
        window?.SetOperationBusy(true);
        return true;
    }

    private void EndOperation()
    {
        operationBusy = false;
        if (!disposed)
        {
            SetMenuBusy(scanning);
            window?.SetOperationBusy(false);
            UpdateWarnings();
            RefreshHistory();
        }
    }

    private void ShowNotification(IReadOnlyList<MonitorChange> changes)
    {
        MonitorNotification? notification = MonitorNotification.Create(changes, settings);
        if (notification is null)
            return;
        try
        {
            notifyIcon.ShowBalloonTip(10_000, notification.Title, notification.Text,
                notification.IsWarning ? ToolTipIcon.Warning : ToolTipIcon.Info);
            log.TryWrite("monitor.notification-requested",
                $"Передано одно уведомление Windows; совпадений: {changes.Count(item => item.ShouldNotify)}.");
        }
        catch (Exception error)
        {
            log.TryWrite("monitor.notification-error", "Не удалось передать уведомление Windows.", error);
        }
    }

    private void SetMenuBusy(bool busy) => scanMenuItem.Enabled = settingsMenuItem.Enabled = reportMenuItem.Enabled = !busy;

    private void UpdateWarnings() => window?.ShowMonitoringWarning(string.Join("\r\n",
        new[] { persistenceWarning, settingsWarning, catalogWarning, historyRetentionWarning, log.HistoryWarning, log.DiagnosticWarning, log.RetentionWarning }
            .Where(item => !string.IsNullOrWhiteSpace(item))) is { Length: > 0 } warning ? warning : null);

    private void PruneHistory()
    {
        try
        {
            history.Prune();
            historyRetentionWarning = null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            historyRetentionWarning = "Не удалось удалить старую историю. " + ErrorText.Describe(error);
            log.TryWrite("history.retention-error", historyRetentionWarning, error);
        }
    }

    private void RefreshHistory()
    {
        if (shownHistoryRevision == log.HistoryRevision)
            return;
        shownHistoryRevision = log.HistoryRevision;
        window?.RefreshHistoryIfVisible();
    }

    private async Task<HistoryReadResult> ReadHistoryAsync()
    {
        HistoryReadResult result = await Task.Run(() => history.ReadRecent());
        if (result.Errors.Count > 0)
            log.TryWrite("history.read-error", string.Join("; ", result.Errors));
        string? warning = log.HistoryWarning;
        if (warning is not null)
            result = result with { Errors = result.Errors.Append(warning).ToArray() };
        return result;
    }

    private async Task ShowSettingsAsync()
    {
        if (!BeginOperation())
            return;
        bool saved = false;
        try
        {
            using SettingsForm dialog = new(settings, settingsWarning);
            if (dialog.ShowDialog(window) != DialogResult.OK || dialog.SelectedSettings is null)
                return;
            MonitorSettings selected = dialog.SelectedSettings.Validate();
            await Task.Run(() => settingsStore.Save(selected));
            if (disposed)
                return;
            settings = selected;
            settingsWarning = null;
            pollTimer.Interval = settings.PollIntervalSeconds * 1000;
            window?.ShowMonitorSettings(settings);
            saved = true;
            log.TryWrite("settings.saved", $"Настройки сохранены; интервал: {settings.PollIntervalSeconds} с; "
                + $"уведомления: {settings.NotificationsEnabled}; названий УЦ: {settings.AuthorityNames.Length}; "
                + $"пользовательских ID: {settings.RussianCertificateIds.Length}; исключений уведомлений: {settings.NotificationExclusions.Length}.");
        }
        catch (Exception error)
        {
            settingsWarning = "Настройки не сохранены; действуют предыдущие параметры. " + ErrorText.Describe(error);
            ShowApplicationError("settings.save-error", settingsWarning, error);
        }
        finally { EndOperation(); }
        if (saved && !disposed)
            await ScanAsync(automatic: false);
    }

    private async Task ExportReportAsync()
    {
        if (disposed || operationBusy || scanning)
            return;
        await ScanAsync(automatic: false);
        if (!BeginOperation())
            return;
        try
        {
            using SaveFileDialog dialog = new()
            {
                Title = "Экспорт полного отчёта о сертификатах",
                Filter = "Отчёт JSON (*.json)|*.json|Текстовый отчёт (*.txt)|*.txt",
                DefaultExt = "json", AddExtension = true, OverwritePrompt = true,
                FileName = $"Сертификаты-{DateTime.Now:yyyy-MM-dd-HHmmss}"
            };
            if (dialog.ShowDialog(window) != DialogResult.OK)
                return;
            string extension = Path.GetExtension(dialog.FileName).ToLowerInvariant();
            if (extension is not (".json" or ".txt"))
                throw new InvalidDataException("Выберите расширение .json или .txt для отчёта.");
            string destination = Path.GetFullPath(dialog.FileName);
            if (destination.Equals(AppPaths.SettingsFile, StringComparison.OrdinalIgnoreCase)
                || destination.Equals(AppPaths.MonitorStateFile, StringComparison.OrdinalIgnoreCase)
                || destination.StartsWith(AppPaths.HistoryDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || destination.StartsWith(AppPaths.LogDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Выберите файл за пределами настроек, состояния и журналов приложения.");
            CertificateReportContext report = new(snapshot, scanFailure, persistenceWarning,
                string.Join("\r\n", new[] { settingsWarning, catalogWarning, historyRetentionWarning, log.HistoryWarning, log.DiagnosticWarning, log.RetentionWarning }
                    .Where(item => item is not null)), snapshotRestored);
            HistoryReadResult events = await ReadHistoryAsync();
            await Task.Run(() =>
            {
                if (extension == ".json")
                    CertificateReportExporter.WriteJson(destination, report, events, settings);
                else
                    CertificateReportExporter.WriteText(destination, report, events, settings);
            });
            log.TryWrite("report.exported", $"Отчёт сохранён: {destination}; время снимка: {snapshot?.ScannedAt:O}; "
                + $"проверка: {(scanFailure is not null ? "ошибка, данные могут быть устаревшими" : snapshot?.IsComplete == true ? "полная" : "неполная")}.");
            if (!disposed)
                MessageBox.Show(window, "Отчёт сохранён. В него включены все сертификаты, настройки, история и ошибки проверки.",
                    "RussianCertMonitor", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception error) { ShowApplicationError("report.export-error", "Отчёт не сохранён. " + ErrorText.Describe(error), error); }
        finally { EndOperation(); }
    }

    private void ShowApplicationError(string eventName, string message, Exception error)
    {
        log.TryWrite(eventName, message, error);
        if (!disposed)
            MessageBox.Show(window, message, "RussianCertMonitor", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    private void OpenLogDirectory()
    {
        try
        {
            Process.Start(new ProcessStartInfo(log.DirectoryPath) { UseShellExecute = true });
        }
        catch (Exception error)
        {
            log.TryWrite("log.open-error", "Не удалось открыть папку журналов.", error);
            MessageBox.Show("Не удалось открыть папку журналов.", "RussianCertMonitor",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    protected override void ExitThreadCore()
    {
        DisposeResources();
        base.ExitThreadCore();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            DisposeResources();
        base.Dispose(disposing);
    }

    private void DisposeResources()
    {
        if (disposed)
            return;
        disposed = true;
        scanCancellation.Cancel();
        scanCancellation.Dispose();
        activationRegistration.Unregister(null);
        retentionTimer.Dispose();
        pollTimer.Dispose();
        notifyIcon.Visible = false;
        notifyIcon.Dispose();
        window?.Dispose();
        dispatcher.Dispose();
        menu.Dispose();
        trayIcon.Dispose();
        log.TryWrite("application.stopped", "Приложение завершено.");
    }
}
