using System.Text.Json.Serialization;
using RussianCertMonitor.Inventory;

namespace RussianCertMonitor.Monitoring;

internal sealed record MonitorTrackingState(IReadOnlyList<TrackedMatch> Matches)
{
    public static MonitorTrackingState Empty { get; } = new([]);
}

internal sealed record TrackedMatch(
    string CertificateId, string DisplayName, string Category,
    bool IsRussian, bool IsPossibleRussian, bool WasPreviouslyDeleted,
    IReadOnlyList<CertificateStoreDescriptor> Locations)
{
    [JsonIgnore]
    public bool IsPresent => Locations.Count > 0;

    [JsonIgnore]
    public bool HasDisallowed => Locations.Any(location =>
        location.Name.Equals("Disallowed", StringComparison.OrdinalIgnoreCase));
}

internal enum MonitorChangeKind
{
    Found,
    Reappeared,
    LocationsChanged,
    ClassificationChanged,
    Disappeared,
    NoLongerMatches
}

internal sealed record MonitorChange(MonitorChangeKind Kind, TrackedMatch Certificate)
{
    [JsonIgnore]
    public bool ShouldNotify => Kind is not (MonitorChangeKind.Disappeared or MonitorChangeKind.NoLongerMatches);
}

internal sealed record MonitorComparison(MonitorTrackingState State, IReadOnlyList<MonitorChange> Changes);
