using RussianCertMonitor.History;

namespace RussianCertMonitor.UI;

internal sealed record ApplicationUiActions(Action Settings, Action ExportReport,
    Func<Task<HistoryReadResult>> LoadHistory);
