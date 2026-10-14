namespace RussianCertMonitor.Settings;

internal sealed record MonitorSettings
{
    public int SchemaVersion { get; init; } = 1;
    public int PollIntervalSeconds { get; init; } = 10;
    public bool NotificationsEnabled { get; init; } = true;
    public string[] AuthorityNames { get; init; } = [];
    public string[] RussianCertificateIds { get; init; } = [];
    public string[] NotificationExclusions { get; init; } = [];

    public static MonitorSettings Default => new();

    public MonitorSettings Validate()
    {
        if (SchemaVersion != 1)
            throw new InvalidDataException("Неподдерживаемая версия настроек. Требуется schemaVersion: 1.");
        if (PollIntervalSeconds is < 5 or > 3600)
            throw new InvalidDataException("Интервал проверки должен быть от 5 до 3600 секунд.");
        return this with
        {
            AuthorityNames = Normalize(AuthorityNames, false),
            RussianCertificateIds = Normalize(RussianCertificateIds, true),
            NotificationExclusions = Normalize(NotificationExclusions, true)
        };
    }

    private static string[] Normalize(string[]? values, bool certificateIds)
    {
        if (values is null || values.Length > 500)
            throw new InvalidDataException("Список правил должен содержать не более 500 строк и не может быть null.");
        List<string> result = [];
        foreach (string? item in values)
        {
            string value = item?.Trim() ?? "";
            if (certificateIds)
            {
                if (value.Length != 40 || !value.All(Uri.IsHexDigit))
                    throw new InvalidDataException("Идентификатор сертификата должен содержать ровно 40 шестнадцатеричных символов.");
                value = value.ToUpperInvariant();
            }
            else if (value.Length is < 3 or > 200 || value.Any(char.IsControl))
                throw new InvalidDataException("Название удостоверяющего центра должно содержать от 3 до 200 символов без управляющих знаков.");
            if (!result.Contains(value, StringComparer.OrdinalIgnoreCase))
                result.Add(value);
        }
        return result.ToArray();
    }
}
