using RussianCertMonitor.Settings;
using RussianCertMonitor.UI;

namespace RussianCertMonitor.Tests;

internal static class SettingsFormChecks
{
    private const string CertificateId = "abcdefabcdefabcdefabcdefabcdefabcdefabcd";

    public static void Run()
    {
        MonitorSettings original = MonitorSettings.Default;
        using (SettingsForm form = new(original, "Повреждённый файл настроек."))
        {
            form.Show();
            try
            {
                Require(Control<Label>(form, "SettingsWarning").Text.Contains("заменён"),
                    "Предупреждение должно объяснять замену повреждённого JSON.");
                Control<NumericUpDown>(form, "PollIntervalSeconds").Value = 25;
                Control<CheckBox>(form, "NotificationsEnabled").Checked = false;
                Control<TextBox>(form, "AuthorityNames").Text = "  Тестовый УЦ  \r\nтестовый уц";
                Control<TextBox>(form, "RussianCertificateIds").Text = CertificateId;
                Control<TextBox>(form, "NotificationExclusions").Text = CertificateId;
                Button(form, "Сохранить").PerformClick();
                MonitorSettings? selected = form.SelectedSettings;
                Require(form.DialogResult == DialogResult.OK && selected is not null,
                    "Корректные настройки должны возвращаться после сохранения.");
                Require(selected!.PollIntervalSeconds == 25 && !selected.NotificationsEnabled
                    && selected.AuthorityNames.SequenceEqual(["Тестовый УЦ"])
                    && selected.RussianCertificateIds.SequenceEqual([CertificateId.ToUpperInvariant()])
                    && selected.NotificationExclusions.SequenceEqual([CertificateId.ToUpperInvariant()]),
                    "Форма должна передавать нормализованные значения всех полей.");
                Require(original.PollIntervalSeconds == 10 && original.AuthorityNames.Length == 0,
                    "Редактирование не должно менять исходные настройки.");
            }
            finally { form.Close(); }
        }

        using (SettingsForm form = new(original))
        {
            form.Show();
            try
            {
                Control<TextBox>(form, "RussianCertificateIds").Text = "недопустимый ID";
                Button(form, "Сохранить").PerformClick();
                Require(form.Visible && form.DialogResult != DialogResult.OK && form.SelectedSettings is null,
                    "Недопустимый идентификатор должен оставлять форму открытой без результата.");
                Require(Control<Label>(form, "ValidationError").Visible,
                    "Причина ошибки должна быть видна в форме.");
            }
            finally { form.Close(); }
        }

        using (SettingsForm form = new(original))
        {
            form.Show();
            Control<NumericUpDown>(form, "PollIntervalSeconds").Value = 30;
            Button(form, "Отмена").PerformClick();
            Require(form.DialogResult == DialogResult.Cancel && form.SelectedSettings is null
                && original.PollIntervalSeconds == 10,
                "Отмена не должна выдавать результат или менять исходные настройки.");
        }
    }

    private static T Control<T>(Control parent, string name) where T : Control =>
        Descendants(parent).OfType<T>().Single(control => control.Name == name);

    private static Button Button(Control parent, string text) =>
        Descendants(parent).OfType<Button>().Single(button => button.Text == text);

    private static IEnumerable<Control> Descendants(Control parent)
    {
        foreach (Control child in parent.Controls)
        {
            yield return child;
            foreach (Control descendant in Descendants(child))
                yield return descendant;
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
