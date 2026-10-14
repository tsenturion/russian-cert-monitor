using RussianCertMonitor.Settings;

namespace RussianCertMonitor.UI;

internal sealed class SettingsForm : Form
{
    private readonly NumericUpDown interval = new()
    {
        Name = "PollIntervalSeconds", Minimum = 5, Maximum = 3600, Dock = DockStyle.Left, Width = 120
    };
    private readonly CheckBox notifications = new()
    {
        Name = "NotificationsEnabled", Text = "Показывать уведомления", AutoSize = true
    };
    private readonly TextBox authorityNames = CreateRulesBox("AuthorityNames");
    private readonly TextBox russianCertificateIds = CreateRulesBox("RussianCertificateIds");
    private readonly TextBox notificationExclusions = CreateRulesBox("NotificationExclusions");
    private readonly Label error = new()
    {
        Name = "ValidationError", Dock = DockStyle.Fill, ForeColor = Color.DarkRed,
        TextAlign = ContentAlignment.MiddleLeft, Visible = false
    };
    private readonly MonitorSettings originalSettings;

    public MonitorSettings? SelectedSettings { get; private set; }

    public SettingsForm(MonitorSettings settings, string? warning = null)
    {
        originalSettings = settings ?? throw new ArgumentNullException(nameof(settings));
        Text = "Настройки мониторинга";
        AutoScaleDimensions = new SizeF(96, 96);
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.CenterParent;
        Size = new Size(1200, 800);
        MinimumSize = new Size(800, 600);
        ShowInTaskbar = false;

        TableLayoutPanel layout = new()
        {
            Dock = DockStyle.Fill, Padding = new Padding(16), ColumnCount = 1, RowCount = 5
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        TableLayoutPanel general = new() { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2 };
        general.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        general.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        general.Controls.Add(new Label
        {
            Text = "Интервал проверки, секунд:", AutoSize = true, Anchor = AnchorStyles.Left,
            Margin = new Padding(0, 4, 12, 4)
        }, 0, 0);
        general.Controls.Add(interval, 1, 0);
        general.Controls.Add(notifications, 0, 1);
        general.SetColumnSpan(notifications, 2);
        layout.Controls.Add(general, 0, 0);

        Label warningLabel = new()
        {
            Name = "SettingsWarning", Text = string.IsNullOrWhiteSpace(warning) ? "" :
                $"{warning.Trim()}\nПри сохранении повреждённый существующий JSON будет заменён новыми настройками.",
            ForeColor = Color.DarkRed, AutoSize = true, MaximumSize = new Size(820, 0),
            Visible = !string.IsNullOrWhiteSpace(warning), Margin = new Padding(0, 8, 0, 8)
        };
        layout.Controls.Add(warningLabel, 0, 1);

        TabControl tabs = new() { Dock = DockStyle.Fill };
        tabs.TabPages.Add(CreateRulesPage("Названия УЦ", authorityNames,
            "Одно название на строку. Совпадение по границам слов с CN или O владельца либо издателя сертификата. Названия: от 3 до 200 символов; не более 500 строк."));
        tabs.TabPages.Add(CreateRulesPage("Российские ID", russianCertificateIds,
            "Один идентификатор сертификата на строку: ровно 40 шестнадцатеричных символов. Указанные вручную сертификаты помечаются как российские. Не более 500 строк."));
        tabs.TabPages.Add(CreateRulesPage("Исключения", notificationExclusions,
            "Один идентификатор сертификата на строку: ровно 40 шестнадцатеричных символов. Исключение подавляет только уведомление; обнаружение, классификация и список Disallowed сохраняются. Не более 500 строк."));
        layout.Controls.Add(tabs, 0, 2);
        layout.Controls.Add(error, 0, 3);

        FlowLayoutPanel buttons = new()
        {
            Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.RightToLeft
        };
        Button save = new() { Text = "Сохранить", AutoSize = true };
        Button cancel = new() { Text = "Отмена", AutoSize = true };
        save.Click += (_, _) => Save();
        cancel.Click += (_, _) => { SelectedSettings = null; DialogResult = DialogResult.Cancel; Close(); };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(save);
        layout.Controls.Add(buttons, 0, 4);
        AcceptButton = save;
        CancelButton = cancel;
        Controls.Add(layout);

        interval.Value = Math.Clamp(settings.PollIntervalSeconds, (int)interval.Minimum, (int)interval.Maximum);
        notifications.Checked = settings.NotificationsEnabled;
        authorityNames.Lines = settings.AuthorityNames ?? [];
        russianCertificateIds.Lines = settings.RussianCertificateIds ?? [];
        notificationExclusions.Lines = settings.NotificationExclusions ?? [];
    }

    protected override void OnLoad(EventArgs eventArgs)
    {
        base.OnLoad(eventArgs);
        Rectangle available = Screen.FromControl(this).WorkingArea;
        Size = new Size(Math.Min(Width, available.Width - 24), Math.Min(Height, available.Height - 24));
        Location = new Point(
            Math.Clamp(Left, available.Left, available.Right - Width),
            Math.Clamp(Top, available.Top, available.Bottom - Height));
    }

    private void Save()
    {
        try
        {
            MonitorSettings candidate = originalSettings with
            {
                PollIntervalSeconds = (int)interval.Value,
                NotificationsEnabled = notifications.Checked,
                AuthorityNames = ReadLines(authorityNames),
                RussianCertificateIds = ReadLines(russianCertificateIds),
                NotificationExclusions = ReadLines(notificationExclusions)
            };
            SelectedSettings = candidate.Validate();
            error.Visible = false;
            DialogResult = DialogResult.OK;
            Close();
        }
        catch (InvalidDataException exception)
        {
            SelectedSettings = null;
            error.Text = exception.Message;
            error.Visible = true;
        }
    }

    private static TextBox CreateRulesBox(string name) => new()
    {
        Name = name, Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Both,
        WordWrap = false, AcceptsReturn = true, AcceptsTab = false
    };

    private static TabPage CreateRulesPage(string title, TextBox editor, string description)
    {
        TabPage page = new(title);
        TableLayoutPanel layout = new()
        {
            Dock = DockStyle.Fill, Padding = new Padding(8), ColumnCount = 1, RowCount = 2
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.Controls.Add(new Label { Text = description, Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(0, 0, 0, 12) }, 0, 0);
        layout.Controls.Add(editor, 0, 1);
        page.Controls.Add(layout);
        return page;
    }

    private static string[] ReadLines(TextBox editor) => editor.Lines
        .Where(line => !string.IsNullOrWhiteSpace(line)).ToArray();
}
