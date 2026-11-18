using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.Disallowed;

namespace RussianCertMonitor.UI;

internal static class DisallowedDialogs
{
    public static StoreLocation? SelectScope(IWin32Window? owner, PublicCertificateData certificate,
        DisallowedOperation operation, StoreLocation initial, WindowsTrustAssessment? trust)
    {
        using Form dialog = CreateDialog("Область чёрного списка", out TableLayoutPanel layout);
        ComboBox scope = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top };
        scope.Items.AddRange(["Текущий пользователь", "Все пользователи компьютера — требуется UAC"]);
        scope.SelectedIndex = initial == StoreLocation.LocalMachine ? 1 : 0;
        layout.Controls.Add(new Label
        {
            AutoSize = true, Dock = DockStyle.Fill,
            Text = (operation == DisallowedOperation.Add ? "Добавить выбранный сертификат в чёрный список:" : "Убрать выбранный сертификат из чёрного списка:")
                + "\r\nЗапрет пользователя и запрет компьютера различаются. Выберите область вручную."
                + "\r\nДобавление запрета не блокирует установку сертификата."
                + $"\r\nПоследняя проверка для пользователя: {trust?.CurrentUser.StatusText ?? "нет результата"}"
                + $"\r\nПоследняя проверка для компьютера: {trust?.LocalMachine.StatusText ?? "нет результата"}"
        }, 0, 0);
        layout.Controls.Add(scope, 0, 1);
        layout.Controls.Add(Details(certificate), 0, 2);
        AddButtons(dialog, layout, "Продолжить");
        return dialog.ShowDialog(owner) == DialogResult.OK
            ? scope.SelectedIndex == 0 ? StoreLocation.CurrentUser : StoreLocation.LocalMachine : null;
    }

    public static bool Confirm(IWin32Window? owner, DisallowedPreview preview)
    {
        using Form dialog = CreateDialog("RussianCertMonitor — подтверждение изменения", out TableLayoutPanel layout);
        bool add = preview.Operation == DisallowedOperation.Add;
        layout.Controls.Add(new Label
        {
            AutoSize = true, Dock = DockStyle.Fill,
            Text = $"{(add ? "Добавление" : "Удаление")} в чёрном списке: {ScopeName(preview.Location)}.\r\n" +
                "Изменяется собственная запись Disallowed выбранной области."
        }, 0, 0);
        layout.Controls.Add(new Label
        {
            AutoSize = true, Dock = DockStyle.Fill,
            Text = $"Собственная запись сейчас: {(preview.OwnPresent ? "имеется" : "отсутствует")}.\r\n" +
                (add ? "Запрет влияет на оценку доверия Windows в выбранной области. Установка сертификата не блокируется."
                : "Удаляется только собственная запись выбранной области. Доверие по цепочке Windows проверяется отдельно; унаследованная запись или политика может остаться.")
        }, 0, 1);
        layout.Controls.Add(Details(preview.Certificate), 0, 2);
        AddButtons(dialog, layout, add ? "Добавить в чёрный список" : "Удалить запись");
        return dialog.ShowDialog(owner) == DialogResult.OK;
    }

    public static string ScopeName(StoreLocation location) => location == StoreLocation.CurrentUser
        ? "текущий пользователь" : "все пользователи компьютера";

    private static TextBox Details(PublicCertificateData certificate) => new()
    {
        ReadOnly = true, Multiline = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical,
        BackColor = SystemColors.Window,
        Text = $"Название: {certificate.Metadata.DisplayName}\r\n\r\n" +
            $"Идентификатор Windows: {certificate.Metadata.CertificateId}\r\n\r\n" +
            $"Владелец: {certificate.Metadata.Subject}\r\n\r\nИздатель: {certificate.Metadata.Issuer}\r\n\r\n" +
            $"Срок: {certificate.Metadata.NotBefore?.ToLocalTime():dd.MM.yyyy} — {certificate.Metadata.NotAfter?.ToLocalTime():dd.MM.yyyy}"
    };

    private static Form CreateDialog(string title, out TableLayoutPanel layout)
    {
        Form dialog = new()
        {
            Text = title, StartPosition = FormStartPosition.CenterScreen, Size = new Size(940, 650),
            MinimumSize = new Size(800, 550), Font = new Font("Segoe UI", 10),
            AutoScaleMode = AutoScaleMode.Dpi,
            MinimizeBox = false, MaximizeBox = false, ShowInTaskbar = false
        };
        layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, Padding = new Padding(16), ColumnCount = 1, RowCount = 4
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        dialog.Controls.Add(layout);
        return dialog;
    }

    private static void AddButtons(Form dialog, TableLayoutPanel layout, string applyText)
    {
        Button apply = new() { Text = applyText, AutoSize = true, DialogResult = DialogResult.OK };
        Button cancel = new() { Text = "Отмена", AutoSize = true, DialogResult = DialogResult.Cancel };
        FlowLayoutPanel buttons = new() { AutoSize = true, Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(apply);
        dialog.AcceptButton = apply;
        dialog.CancelButton = cancel;
        layout.Controls.Add(buttons, 0, 3);
    }
}
