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
    IReadOnlyList<CertificateStoreDescriptor> Locations,
    uint? LastUserTrustStatus = null, uint? LastMachineTrustStatus = null, bool WasInDisallowed = false)
{
    [JsonIgnore]
    public bool IsPresent => Locations.Count > 0;

    [JsonIgnore]
    public bool HasDisallowed => Locations.Any(location =>
        location.Name.Equals("Disallowed", StringComparison.OrdinalIgnoreCase));

    [JsonIgnore]
    public bool HasComputerDisallowed => Locations.Any(location =>
        location.Location == System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine
        && location.Name.Equals("Disallowed", StringComparison.OrdinalIgnoreCase));

    [JsonIgnore]
    public bool IsMachineDistrusted => LastMachineTrustStatus is uint status
        && new Certificates.WindowsChainResult(status).IsExplicitlyDistrusted;
}

internal enum MonitorChangeKind
{
    Found,
    Reappeared,
    LocationsChanged,
    ClassificationChanged,
    Disappeared,
    NoLongerMatches,
    TrustWeakened,
    ComputerBlockRemoved
}

internal sealed record MonitorChange(MonitorChangeKind Kind, TrackedMatch Certificate)
{
    [JsonIgnore]
    public bool ShouldNotify => Kind is not (MonitorChangeKind.Disappeared or MonitorChangeKind.NoLongerMatches);
}

internal sealed record MonitorComparison(MonitorTrackingState State, IReadOnlyList<MonitorChange> Changes);
