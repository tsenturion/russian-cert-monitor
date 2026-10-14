using RussianCertMonitor.Settings;

namespace RussianCertMonitor.Monitoring;

internal sealed record MonitorNotification(string Title, string Text, bool IsWarning)
{
    public static MonitorNotification? Create(IReadOnlyList<MonitorChange> changes, MonitorSettings settings)
    {
        if (!settings.NotificationsEnabled)
            return null;
        HashSet<string> excluded = new(settings.NotificationExclusions, StringComparer.OrdinalIgnoreCase);
        return Create(changes.Where(item => !excluded.Contains(item.Certificate.CertificateId)).ToArray());
    }

    public static MonitorNotification? Create(IReadOnlyList<MonitorChange> changes)
    {
        MonitorChange[] relevant = changes.Where(item => item.ShouldNotify).ToArray();
        if (relevant.Length == 0)
            return null;

        List<string> lines = [];
        foreach (MonitorChange change in relevant.Take(3))
        {
            string prefix = change.Kind switch
            {
                MonitorChangeKind.Reappeared => "Повторно",
                MonitorChangeKind.LocationsChanged => "Расположение",
                MonitorChangeKind.ClassificationChanged => "Принадлежность",
                _ => change.Certificate.WasPreviouslyDeleted ? "Ранее удалён" : "Новое"
            };
            string name = change.Certificate.DisplayName.Replace('\r', ' ').Replace('\n', ' ');
            if (name.Length > 42)
                name = name[..39] + "…";
            lines.Add($"{prefix}: {name}" + (change.Certificate.HasDisallowed ? " (Disallowed)" : ""));
        }
        if (relevant.Length > 3)
            lines.Add($"Ещё совпадений: {relevant.Length - 3}.");
        lines.Add("Нажмите, чтобы открыть приложение.");
        string text = string.Join("\n", lines);
        if (text.Length > 240)
            text = text[..237] + "…";
        return new MonitorNotification($"Изменения сертификатов: {relevant.Length}", text,
            relevant.Any(item => item.Certificate.IsRussian && !item.Certificate.HasDisallowed));
    }
}
