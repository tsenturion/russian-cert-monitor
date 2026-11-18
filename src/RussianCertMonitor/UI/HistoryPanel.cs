using RussianCertMonitor.History;
using RussianCertMonitor.Infrastructure;

namespace RussianCertMonitor.UI;

internal sealed class HistoryPanel : UserControl
{
    private readonly Func<Task<HistoryReadResult>> load;
    private readonly Button refresh = new() { Text = "Обновить историю", AutoSize = true };
    private readonly TextBox search = new() { Width = 420, PlaceholderText = "Поиск по истории, идентификатору и хранилищу" };
    private readonly Label status = new() { Dock = DockStyle.Fill, AutoSize = true };
    private readonly ListView events = new()
    {
        Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true,
        HideSelection = false, MultiSelect = false
    };
    private readonly TextBox details = new()
    {
        Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
        BackColor = SystemColors.Window
    };
    private IReadOnlyList<HistoryEvent> items = [];
    private bool loading;

    public HistoryPanel(Func<Task<HistoryReadResult>> load)
    {
        this.load = load;
        Dock = DockStyle.Fill;
        TableLayoutPanel layout = new() { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 70));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 30));
        FlowLayoutPanel toolbar = new() { AutoSize = true, Dock = DockStyle.Fill };
        toolbar.Controls.AddRange([refresh, search]);
        status.Text = "История событий хранится не более 30 дней; показываются последние 1000 событий.";
        events.Columns.Add("Время", 300);
        events.Columns.Add("Событие", 310);
        events.Columns.Add("Идентификатор Windows", 360);
        events.Columns.Add("Хранилище", 240);
        events.Columns.Add("Результат", 300);
        refresh.Click += async (_, _) => await RefreshAsync();
        search.TextChanged += (_, _) => Populate();
        events.SelectedIndexChanged += (_, _) =>
            details.Text = events.SelectedItems.Count == 0 ? "Выберите событие для просмотра подробностей."
                : Describe((HistoryEvent)events.SelectedItems[0].Tag!);
        layout.Controls.Add(toolbar, 0, 0);
        layout.Controls.Add(status, 0, 1);
        layout.Controls.Add(events, 0, 2);
        layout.Controls.Add(details, 0, 3);
        Controls.Add(layout);
    }

    public async Task RefreshAsync()
    {
        if (loading || IsDisposed)
            return;
        loading = true;
        refresh.Enabled = false;
        try
        {
            HistoryReadResult result = await load();
            if (IsDisposed)
                return;
            items = result.Events;
            status.Text = $"Событий: {items.Count}. Хранение — не более 30 дней. "
                + (result.Truncated ? "Показана ограниченная часть истории (до 1000 событий / 4 МБ). " : "")
                + string.Join(" ", result.Errors.Take(2).Select(item => item.Length > 250 ? item[..250] + "…" : item))
                + (result.Errors.Count > 2 ? $" Ещё ошибок: {result.Errors.Count - 2}; подробности ниже и в отчёте." : "");
            status.ForeColor = result.Errors.Count > 0 ? Color.DarkRed : SystemColors.ControlText;
            Populate();
            if (result.Errors.Count > 0)
                details.Text = "Ошибки чтения истории:\r\n" + string.Join("\r\n", result.Errors);
        }
        catch (Exception error)
        {
            if (!IsDisposed)
            {
                status.Text = "История не прочитана. " + ErrorText.Describe(error);
                status.ForeColor = Color.DarkRed;
            }
        }
        finally
        {
            loading = false;
            if (!IsDisposed)
                refresh.Enabled = true;
        }
    }

    private void Populate()
    {
        HistoryEvent? selected = events.SelectedItems.Count == 0 ? null : events.SelectedItems[0].Tag as HistoryEvent;
        string term = search.Text.Trim();
        events.BeginUpdate();
        try
        {
            events.Items.Clear();
            foreach (HistoryEvent item in items.Reverse())
            {
                string title = EventTitle(item.EventName);
                if (term.Length > 0 && !new[] { title, item.Message, item.CertificateId, item.Location, item.Result }
                    .Any(value => value?.Contains(term, StringComparison.CurrentCultureIgnoreCase) == true))
                    continue;
                ListViewItem row = new(item.Timestamp.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss")) { Tag = item };
                row.SubItems.Add(title);
                row.SubItems.Add(item.CertificateId ?? "");
                row.SubItems.Add(item.Location ?? "");
                row.SubItems.Add(item.Result ?? "");
                events.Items.Add(row);
                row.Selected = item == selected;
            }
        }
        finally { events.EndUpdate(); }
        details.Text = selected is null ? "Выберите событие для просмотра подробностей." : Describe(selected);
    }

    private static string Describe(HistoryEvent item) =>
        $"{item.Timestamp.ToLocalTime():dd.MM.yyyy HH:mm:ss} · {EventTitle(item.EventName)}\r\n"
        + (item.CertificateId is null ? "" : $"Идентификатор Windows: {item.CertificateId}\r\n")
        + (item.Location is null ? "" : $"Хранилище: {item.Location}\r\n")
        + (item.Result is null ? "" : $"Результат: {item.Result}\r\n") + item.Message;

    private static string EventTitle(string name) => name switch
    {
        "application.started" => "Запуск приложения",
        "application.stopped" => "Завершение приложения",
        "monitor.match-changed" => "Изменение совпадения",
        "monitor.coverage-changed" => "Полнота проверки",
        "disallowed.requested" => "Запрошено изменение Disallowed",
        "disallowed.completed" => "Результат Disallowed подтверждён",
        "disallowed.trust-verified" => "Проверка цепочки после изменения Disallowed",
        "disallowed.elevation-requested" => "Запрошены права администратора",
        "disallowed.cancelled" => "Операция отменена",
        "disallowed.error" => "Ошибка изменения Disallowed",
        "settings.saved" => "Настройки сохранены",
        "report.exported" => "Отчёт сохранён",
        "certificate.exported" => "Публичный сертификат сохранён",
        "inventory.failed" => "Ошибка проверки",
        "inventory.recovered" => "Проверка снова доступна",
        "certificate.action-error" => "Ошибка действия с сертификатом",
        "monitor.state-save-error" => "Ошибка сохранения состояния",
        "monitor.state-save-recovered" => "Состояние снова сохраняется",
        "monitor.state-load-error" => "Ошибка чтения состояния",
        "settings.load-error" => "Ошибка чтения настроек",
        "settings.save-error" => "Ошибка сохранения настроек",
        "report.export-error" => "Ошибка экспорта отчёта",
        _ => name
    };
}
