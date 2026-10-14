namespace RussianCertMonitor.Infrastructure;

internal static class AppPaths
{
    public static string DataDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "RussianCertMonitor");

    public static string LogDirectory { get; } = Path.Combine(DataDirectory, "Logs");
    public static string MonitorStateFile { get; } = Path.Combine(DataDirectory, "monitor-state.json");
    public static string SettingsFile { get; } = Path.Combine(DataDirectory, "settings.json");
    public static string HistoryDirectory { get; } = Path.Combine(DataDirectory, "History");
    public static string LocalCatalogFile { get; } = Path.Combine(DataDirectory, "certificate-history-catalog.json");
}
