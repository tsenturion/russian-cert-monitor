using RussianCertMonitor.Catalog;
using RussianCertMonitor.Inventory;
using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Infrastructure;
using RussianCertMonitor.Settings;
using RussianCertMonitor.Monitoring;

namespace RussianCertMonitor.UI;

internal sealed class MainForm : Form
{
    private readonly Label summary = new() { AutoSize = true, Dock = DockStyle.Fill };
    private readonly Button scanButton = new() { Text = "Проверить сейчас", AutoSize = true };
    private readonly Button propertiesButton = new() { Text = "Свойства", AutoSize = true };
    private readonly Button exportButton = new() { Text = "Экспорт CER", AutoSize = true };
    private readonly Button addButton = new() { Text = "Добавить в чёрный список", AutoSize = true };
    private readonly Button removeButton = new() { Text = "Убрать из чёрного списка", AutoSize = true };
    private readonly Button importButton = new() { Text = "Импорт CER/CRT", AutoSize = true };
    private readonly Button settingsButton = new() { Text = "Настройки", AutoSize = true };
    private readonly Button reportButton = new() { Text = "Экспорт отчёта", AutoSize = true };
    private readonly Label monitorLabel = new() { AutoSize = true, Margin = new Padding(16, 8, 0, 8) };
    private readonly HistoryPanel? historyPanel;
    private readonly TabPage historyPage = new("История");
    private readonly TableLayoutPanel layout;
    private readonly TextBox search = new() { Width = 360, PlaceholderText = "Поиск по сертификатам" };
    private readonly ComboBox categoryFilter = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 320 };
    private readonly ComboBox scopeFilter = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 320 };
    private readonly TabControl tabs = new() { Dock = DockStyle.Fill };
    private readonly CertificateUiActions actions;
    private bool operationBusy;
    private bool scanning;
    private readonly Label monitoringWarning = new()
    {
        AutoSize = true, Dock = DockStyle.Fill, ForeColor = Color.DarkRed, Visible = false
    };
    private CertificateInventorySnapshot? renderedSnapshot;
    private readonly ListView matches = CreateInventoryList();
    private readonly ListView allCertificates = CreateInventoryList();
    private readonly ListView blacklisted = CreateInventoryList();
    private readonly TextBox details = new()
    {
        Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
        ScrollBars = ScrollBars.Vertical, BackColor = SystemColors.Window,
        Text = "Выберите сертификат, чтобы увидеть его данные и причины классификации."
    };
    private readonly TextBox errors = new()
    {
        Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
        ScrollBars = ScrollBars.Both, BackColor = SystemColors.Window, WordWrap = false
    };
    private readonly TabPage matchesPage = new("Совпадения");
    private readonly TabPage allPage = new("Все сертификаты");
    private readonly TabPage blacklistedPage = new("Чёрный список");
    private readonly TabPage errorsPage = new("Ошибки чтения");

    public MainForm(CertificateCatalog catalog, Action requestScan, CertificateUiActions? actions = null,
        ApplicationUiActions? applicationActions = null)
    {
        this.actions = actions ?? CertificateUiActions.Disabled;
        Text = "RussianCertMonitor — сертификаты Windows";
        AutoScaleDimensions = new SizeF(96, 96);
        AutoScaleMode = AutoScaleMode.Dpi;
        Icon = SystemIcons.Shield;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(800, 600);
        Size = new Size(1440, 940);
        Font = new Font("Segoe UI", 10);

        layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, Padding = new Padding(16), ColumnCount = 1, RowCount = 6
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 62));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 38));
        FlowLayoutPanel toolbar = new() { Dock = DockStyle.Fill, AutoSize = true };
        toolbar.Controls.Add(scanButton);
        toolbar.Controls.Add(propertiesButton);
        toolbar.Controls.Add(exportButton);
        toolbar.Controls.Add(addButton);
        toolbar.Controls.Add(removeButton);
        toolbar.Controls.Add(importButton);
        if (applicationActions is not null)
        {
            toolbar.Controls.Add(settingsButton);
            toolbar.Controls.Add(reportButton);
            settingsButton.Click += (_, _) => applicationActions.Settings();
            reportButton.Click += (_, _) => applicationActions.ExportReport();
            historyPanel = new HistoryPanel(applicationActions.LoadHistory);
            historyPage.Controls.Add(historyPanel);
        }
        toolbar.Controls.Add(monitorLabel);
        ShowMonitorSettings(MonitorSettings.Default);
        scanButton.Click += (_, _) => requestScan();
        layout.Controls.Add(toolbar, 0, 0);
        FlowLayoutPanel filters = new() { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        filters.Controls.Add(search);
        categoryFilter.Items.AddRange(["Все категории", "Российские", "Косвенные признаки", "Ранее удалённые", "Исключения уведомлений"]);
        scopeFilter.Items.AddRange(["Оба расположения", "Пользователь", "Компьютер"]);
        categoryFilter.SelectedIndex = 0;
        scopeFilter.SelectedIndex = 0;
        categoryFilter.Items.AddRange(["Российские цепочки ПК без ошибок", "Явный запрет только у пользователя"]);
        filters.Controls.Add(categoryFilter);
        filters.Controls.Add(scopeFilter);
        layout.Controls.Add(filters, 0, 1);
        summary.Margin = new Padding(0, 8, 0, 12);
        summary.Text = "Проверка ещё не выполнена.";
        layout.Controls.Add(summary, 0, 2);
        layout.Controls.Add(monitoringWarning, 0, 3);

        matchesPage.Controls.Add(matches);
        allPage.Controls.Add(allCertificates);
        blacklistedPage.Controls.Add(blacklisted);
        errorsPage.Controls.Add(errors);
        TabPage catalogPage = new($"Справочник ({catalog.Certificates.Count})");
        catalogPage.Controls.Add(CreateCatalogPanel(catalog));
        tabs.TabPages.AddRange([matchesPage, allPage, blacklistedPage, errorsPage, catalogPage]);
        if (historyPanel is not null)
            tabs.TabPages.Add(historyPage);
        layout.Controls.Add(tabs, 0, 4);
        layout.Controls.Add(details, 0, 5);
        foreach (ListView list in new[] { matches, allCertificates, blacklisted })
            list.SelectedIndexChanged += (_, _) => UpdateSelection();
        tabs.SelectedIndexChanged += (_, _) =>
        {
            UpdateSelection();
            bool showHistory = tabs.SelectedTab == historyPage;
            details.Visible = !showHistory;
            layout.RowStyles[4].Height = showHistory ? 100 : 62;
            layout.RowStyles[5].Height = showHistory ? 0 : 38;
            if (showHistory)
                _ = historyPanel?.RefreshAsync();
        };
        search.TextChanged += (_, _) => RefreshLists();
        categoryFilter.SelectedIndexChanged += (_, _) => RefreshLists();
        scopeFilter.SelectedIndexChanged += (_, _) => RefreshLists();
        propertiesButton.Click += (_, _) => RunAction(certificate => this.actions.ShowProperties(certificate));
        exportButton.Click += (_, _) => RunAction(certificate => this.actions.Export(certificate));
        addButton.Click += async (_, _) => await RunActionAsync(certificate => this.actions.AddToDisallowed(certificate));
        removeButton.Click += async (_, _) => await RunActionAsync(certificate => this.actions.RemoveFromDisallowed(certificate));
        importButton.Click += async (_, _) => await RunImportAsync();
        Controls.Add(layout);
        UpdateSelection();
    }

    public void SetScanning(bool scanning, bool showProgress = true)
    {
        this.scanning = scanning;
        UpdateButtons();
        settingsButton.Enabled = reportButton.Enabled = !scanning && !operationBusy;
        scanButton.Text = scanning ? "Проверка…" : "Проверить сейчас";
        if (scanning && showProgress)
            summary.Text = "Чтение доступных хранилищ Windows… Предыдущие строки могут быть устаревшими.";
    }

    public void ShowMonitoringWarning(string? message)
    {
        monitoringWarning.Text = message ?? "";
        monitoringWarning.Visible = message is not null;
    }

    public void ShowScanFailure(string message)
    {
        renderedSnapshot = null;
        summary.Text = "Проверка не завершена. Предыдущие строки могут быть устаревшими.";
        summary.ForeColor = Color.DarkRed;
        errors.Text = message;
        errorsPage.Text = "Ошибка проверки";
        SetScanning(false);
    }

    public void SetOperationBusy(bool busy)
    {
        operationBusy = busy;
        UpdateButtons();
        settingsButton.Enabled = reportButton.Enabled = !busy && !scanning;
    }

    public void ShowMonitorSettings(MonitorSettings settings) => monitorLabel.Text =
        $"Проверка каждые {settings.PollIntervalSeconds} с · CurrentUser и LocalMachine · "
        + (settings.NotificationsEnabled ? "Уведомления включены" : "Уведомления выключены");

    public void RefreshHistoryIfVisible()
    {
        if (tabs.SelectedTab == historyPage)
            _ = historyPanel?.RefreshAsync();
    }

    public void ShowSnapshot(CertificateInventorySnapshot snapshot, bool restored = false)
    {
        bool unchanged = MonitorService.SnapshotContentsEqual(renderedSnapshot, snapshot);
        string completeness = restored ? "Сохранённый снимок. Ожидается проверка"
            : snapshot.TrustComplete ? "Проверка завершена" : "Проверка неполная";
        string trustedRussian = snapshot.TrustComplete ? snapshot.RussianAcceptedByComputerCount.ToString()
            : $"подтверждено {snapshot.RussianAcceptedByComputerCount}, охват неполный";
        summary.Text = $"{completeness} · {snapshot.ScannedAt.ToLocalTime():dd.MM.yyyy HH:mm:ss}\r\n" +
            $"Уникальных в хранилищах: {snapshot.ObservedCertificateCount} · Наблюдений: {snapshot.ObservationCount} · " +
            $"Хранилищ прочитано: {snapshot.Stores.Count} · Российских: {snapshot.RussianCount} · " +
            $"Косвенные признаки: {snapshot.PossibleCount} · Из истории без принадлежности: {snapshot.HistoricalUnknownCount}\r\n" +
            $"Российских цепочек ПК без ошибок: {trustedRussian} · Явный запрет только у пользователя: {snapshot.UserOnlyDistrustedCount}";
        summary.ForeColor = snapshot.TrustComplete && !restored ? SystemColors.ControlText : Color.DarkRed;
        errorsPage.Text = $"Ошибки чтения ({snapshot.Issues.Count})";
        errors.Text = snapshot.IsComplete
            ? "Ошибок чтения не зарегистрировано.\r\nПрочитанные логические хранилища:\r\n" +
                string.Join("\r\n", snapshot.Stores.Select(item => item.Path))
            : string.Join("\r\n\r\n", snapshot.Issues.Select(item => $"{item.Location}\r\n{item.Message}"));
        if (unchanged)
        {
            renderedSnapshot = snapshot;
            foreach (ListView list in new[] { matches, allCertificates, blacklisted })
                foreach (ListViewItem row in list.Items)
                    if (row.Tag is InventoryCertificate certificate)
                    {
                        row.SubItems[2].Text = certificate.ValidityStatus(snapshot.ScannedAt);
                    }
            SetScanning(false);
            return;
        }
        renderedSnapshot = snapshot;
        RefreshLists();
        SetScanning(false);
    }

    private void RefreshLists()
    {
        if (renderedSnapshot is null)
            return;
        CertificateInventorySnapshot snapshot = renderedSnapshot;
        Populate(matches, snapshot.Certificates.Where(item => item.NeedsAttention && PassesFilters(item, false)), snapshot.ScannedAt);
        Populate(allCertificates, snapshot.Certificates.Where(item => PassesFilters(item, false)), snapshot.ScannedAt);
        Populate(blacklisted, snapshot.Certificates.Where(item => HasDisallowed(item) && PassesFilters(item, true)), snapshot.ScannedAt);
        matchesPage.Text = $"Совпадения ({matches.Items.Count})";
        allPage.Text = $"Все сертификаты ({allCertificates.Items.Count})";
        blacklistedPage.Text = $"Чёрный список ({blacklisted.Items.Count})";
        UpdateSelection();
    }

    private bool PassesFilters(InventoryCertificate certificate, bool disallowedOnly)
    {
        bool categoryMatches = categoryFilter.SelectedIndex switch
        {
            1 => certificate.Classification.IsRussian,
            2 => !certificate.Classification.IsRussian && certificate.Classification.IsPossibleRussian,
            3 => certificate.Classification.WasPreviouslyDeleted,
            4 => certificate.Classification.IsExcluded,
            5 => certificate.Classification.IsRussian && certificate.Trust?.LocalMachine.IsAccepted == true,
            6 => certificate.IsDistrustedOnlyByUser,
            _ => true
        };
        if (!categoryMatches)
            return false;
        IEnumerable<CertificateStoreDescriptor> locations = disallowedOnly
            ? certificate.Locations.Where(IsDisallowed) : certificate.Locations;
        StoreLocation? selectedScope = scopeFilter.SelectedIndex switch
        {
            1 => StoreLocation.CurrentUser,
            2 => StoreLocation.LocalMachine,
            _ => null
        };
        if (selectedScope is StoreLocation scope && !locations.Any(item => item.Location == scope)
            && !(disallowedOnly && certificate.BackupScopes?.Contains(scope) == true))
            return false;
        string term = search.Text.Trim();
        if (term.Length == 0)
            return true;
        CertificateMetadata metadata = certificate.Metadata;
        return new[] { metadata.DisplayName, metadata.Subject, metadata.Issuer,
            metadata.CertificateId, metadata.SerialNumber }
            .Any(value => value.Contains(term, StringComparison.CurrentCultureIgnoreCase))
            || certificate.Locations.Any(item => item.Path.Contains(term, StringComparison.CurrentCultureIgnoreCase));
    }

    private static bool IsDisallowed(CertificateStoreDescriptor location) =>
        location.Name.Equals("Disallowed", StringComparison.OrdinalIgnoreCase);

    private static bool HasDisallowed(InventoryCertificate certificate) =>
        certificate.HasDisallowedEntry(StoreLocation.CurrentUser)
        || certificate.HasDisallowedEntry(StoreLocation.LocalMachine) || certificate.HasTrustCopyBackup;

    private ListView? CurrentList => tabs.SelectedTab == matchesPage ? matches
        : tabs.SelectedTab == allPage ? allCertificates
        : tabs.SelectedTab == blacklistedPage ? blacklisted : null;

    private InventoryCertificate? SelectedCertificate => CurrentList?.SelectedItems.Count > 0
        ? CurrentList.SelectedItems[0].Tag as InventoryCertificate : null;

    private void UpdateButtons()
    {
        InventoryCertificate? certificate = SelectedCertificate;
        bool available = certificate is not null && certificate.Metadata.RawData.Length > 0;
        bool enabled = !operationBusy && actions != CertificateUiActions.Disabled;
        scanButton.Enabled = !operationBusy && !scanning;
        propertiesButton.Enabled = enabled && available;
        exportButton.Enabled = enabled && available;
        addButton.Enabled = enabled && !scanning && available;
        removeButton.Enabled = enabled && !scanning && available && certificate is not null && HasDisallowed(certificate);
        importButton.Enabled = enabled && !scanning;
    }

    private void UpdateSelection()
    {
        UpdateButtons();
        InventoryCertificate? certificate = SelectedCertificate;
        if (certificate is null)
        {
            details.Text = "Выберите сертификат, чтобы увидеть его данные и причины классификации.";
            return;
        }
        CertificateMetadata metadata = certificate.Metadata;
        string reasons = certificate.Classification.Reasons.Count == 0
            ? "Совпадений с правилами не обнаружено."
            : string.Join("\r\n", certificate.Classification.Reasons.Select(item => "• " + item));
        string readErrors = string.Join("\r\n", certificate.ReadErrors.Concat(certificate.Classification.Errors));
        details.Text = $"{metadata.DisplayName}\r\nКатегория: {certificate.Category}\r\n" +
            $"Идентификатор Windows: {metadata.CertificateId}\r\nСерийный номер: {metadata.SerialNumber}\r\n" +
            $"Владелец: {metadata.Subject}\r\nИздатель: {metadata.Issuer}\r\n" +
            $"Срок: {FormatDate(metadata.NotBefore)} — {FormatDate(metadata.NotAfter)}\r\n" +
            (certificate.HasTrustCopyBackup ? $"Резервные копии: {string.Join(", ", certificate.BackupScopes!)}.\r\n" : "") +
            $"{certificate.DisallowedStatus}\r\nНаблюдается в логических хранилищах: " +
            string.Join("; ", certificate.Locations.Select(item => item.Path)) + "\r\n" +
            "Расположение в CurrentUser может быть унаследовано из LocalMachine.\r\n" +
            $"Цепочка Windows (пользователь): {certificate.Trust?.CurrentUser.Details ?? "не проверена"}\r\n" +
            $"Цепочка Windows (компьютер): {certificate.Trust?.LocalMachine.Details ?? "не проверена"}\r\n" +
            "Базовая проверка без проверки назначения, отзыва и загрузки из сети.\r\n" +
            $"Причины:\r\n{reasons}" + (readErrors.Length == 0 ? "" : $"\r\nОшибки чтения:\r\n{readErrors}");
    }

    private void RunAction(Action<InventoryCertificate> action)
    {
        InventoryCertificate? certificate = SelectedCertificate;
        if (certificate is null || certificate.Metadata.RawData.Length == 0 || operationBusy)
            return;
        try
        {
            action(certificate);
        }
        catch (Exception error)
        {
            ShowActionFailure(error);
        }
    }

    private async Task RunActionAsync(Func<InventoryCertificate, Task> action)
    {
        InventoryCertificate? certificate = SelectedCertificate;
        if (certificate is null || certificate.Metadata.RawData.Length == 0 || operationBusy)
            return;
        try
        {
            SetOperationBusy(true);
            await action(certificate);
        }
        catch (Exception error)
        {
            ShowActionFailure(error);
        }
        finally
        {
            if (!IsDisposed)
                SetOperationBusy(false);
        }
    }

    private async Task RunImportAsync()
    {
        if (operationBusy || actions == CertificateUiActions.Disabled)
            return;
        try
        {
            SetOperationBusy(true);
            await actions.ImportToDisallowed();
        }
        catch (Exception error)
        {
            ShowActionFailure(error);
        }
        finally
        {
            if (!IsDisposed)
                SetOperationBusy(false);
        }
    }

    private void ShowActionFailure(Exception error) => MessageBox.Show(this,
        $"Не удалось выполнить действие: {ErrorText.Describe(error)}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);

    private static ListView CreateInventoryList()
    {
        ListView list = new()
        {
            Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true,
            GridLines = true, HideSelection = false, MultiSelect = false
        };
        list.Columns.Add("Название", 290);
        list.Columns.Add("Категория", 210);
        list.Columns.Add("Срок", 130);
        list.Columns.Add("Доверие пользователя", 240);
        list.Columns.Add("Доверие компьютера", 240);
        list.Columns.Add("Хранилища", 240);
        list.Columns.Add("Disallowed", 270);
        list.Columns.Add("Идентификатор Windows", 360);
        return list;
    }

    private static void Populate(ListView list, IEnumerable<InventoryCertificate> certificates, DateTimeOffset scannedAt)
    {
        string? selectedId = list.SelectedItems.Count == 0 ? null
            : (list.SelectedItems[0].Tag as InventoryCertificate)?.Metadata.CertificateId;
        list.BeginUpdate();
        try
        {
            list.Items.Clear();
            foreach (InventoryCertificate certificate in certificates)
            {
                ListViewItem row = new(certificate.Metadata.DisplayName) { Tag = certificate };
                row.SubItems.Add(certificate.Category);
                row.SubItems.Add(certificate.ValidityStatus(scannedAt));
                row.SubItems.Add(certificate.Trust?.CurrentUser.StatusText ?? "Не проверено");
                row.SubItems.Add(certificate.Trust?.LocalMachine.StatusText ?? "Не проверено");
                row.SubItems.Add(string.Join("; ", certificate.Locations.Select(item => item.Path)));
                row.SubItems.Add(certificate.DisallowedStatus);
                row.SubItems.Add(certificate.Metadata.CertificateId);
                list.Items.Add(row);
                row.Selected = string.Equals(selectedId, certificate.Metadata.CertificateId, StringComparison.OrdinalIgnoreCase);
            }
        }
        finally
        {
            list.EndUpdate();
        }
    }

    private static Control CreateCatalogPanel(CertificateCatalog catalog)
    {
        TableLayoutPanel panel = new() { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        panel.Controls.Add(new Label
        {
            AutoSize = true, Dock = DockStyle.Fill, Padding = new Padding(8),
            Text = $"Публичный справочник на {catalog.SourceDate}: российских удостоверяющих центров " +
                $"{catalog.KnownRussianCount}. Локальная история удалений: " +
                $"{catalog.Certificates.Count(item => item.WasPreviouslyDeleted)} записей. " +
                "Текущее наличие отражено во вкладках «Совпадения» и «Все сертификаты»."
        });
        ListView list = new()
        {
            Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true
        };
        list.Columns.Add("Название", 370);
        list.Columns.Add("Принадлежность", 160);
        list.Columns.Add("Действует до", 130);
        list.Columns.Add("Идентификатор Windows", 360);
        foreach (CatalogCertificate certificate in catalog.Certificates)
        {
            ListViewItem row = new(certificate.Name ?? "Название не подтверждено");
            row.SubItems.Add(certificate.Affiliation == "russian" ? "Российский" : "Не определена");
            row.SubItems.Add(certificate.ValidTo ?? "Не установлено");
            row.SubItems.Add(certificate.CertificateId);
            list.Items.Add(row);
        }
        panel.Controls.Add(list);
        return panel;
    }

    private static string FormatDate(DateTimeOffset? value) => value?.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss")
        ?? "не прочитан";

    protected override void OnFormClosing(FormClosingEventArgs eventArgs)
    {
        if (eventArgs.CloseReason == CloseReason.UserClosing)
        {
            eventArgs.Cancel = true;
            Hide();
        }
        base.OnFormClosing(eventArgs);
    }

    protected override void OnLoad(EventArgs eventArgs)
    {
        base.OnLoad(eventArgs);
        Rectangle available = Screen.FromControl(this).WorkingArea;
        Size = new Size(Math.Min(Width, available.Width - 24), Math.Min(Height, available.Height - 24));
    }
}
