using RussianCertMonitor.Certificates;
using RussianCertMonitor.Inventory;

namespace RussianCertMonitor.Monitoring;

internal static class MonitorChangeDetector
{
    public static MonitorComparison Compare(MonitorTrackingState previous, CertificateInventorySnapshot snapshot)
    {
        Dictionary<string, TrackedMatch> oldMatches = previous.Matches.ToDictionary(
            match => match.CertificateId, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, TrackedMatch> nextMatches = new(oldMatches, StringComparer.OrdinalIgnoreCase);
        List<MonitorChange> changes = [];

        foreach (InventoryCertificate certificate in snapshot.Certificates
            .Where(item => item.NeedsAttention)
            .OrderBy(item => item.Metadata.CertificateId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Metadata.CertificateId, StringComparer.Ordinal))
        {
            string id = certificate.Metadata.CertificateId;
            oldMatches.TryGetValue(id, out TrackedMatch? old);
            CertificateStoreDescriptor[] observed = SortLocations(certificate.Locations);
            CertificateStoreDescriptor[] locations = snapshot.IsComplete || old is null
                ? observed : SortLocations(old.Locations.Concat(observed));
            bool isRussian = certificate.Classification.IsRussian || (!snapshot.IsComplete && old?.IsRussian == true);
            bool isPossibleRussian = certificate.Classification.IsPossibleRussian
                || (!snapshot.IsComplete && old?.IsPossibleRussian == true);
            bool wasPreviouslyDeleted = certificate.Classification.WasPreviouslyDeleted
                || (!snapshot.IsComplete && old?.WasPreviouslyDeleted == true);
            string category = isRussian ? "Российский"
                : isPossibleRussian ? "Косвенные признаки"
                : "Ранее удалён; принадлежность неизвестна";
            uint? userStatus = snapshot.IsComplete ? certificate.Trust?.CurrentUser.ErrorStatus : null;
            uint? machineStatus = snapshot.IsComplete ? certificate.Trust?.LocalMachine.ErrorStatus : null;
            TrackedMatch current = new(id, certificate.Metadata.DisplayName, category,
                isRussian, isPossibleRussian, wasPreviouslyDeleted, locations,
                userStatus ?? old?.LastUserTrustStatus, machineStatus ?? old?.LastMachineTrustStatus);
            nextMatches[id] = current;

            MonitorChangeKind? kind = old is null ? MonitorChangeKind.Found
                : !old.IsPresent && current.IsPresent ? MonitorChangeKind.Reappeared
                : LostProtection(old.LastUserTrustStatus, userStatus)
                    || LostProtection(old.LastMachineTrustStatus, machineStatus) ? MonitorChangeKind.TrustWeakened
                : CategoryRank(current) > CategoryRank(old) ? MonitorChangeKind.ClassificationChanged
                : HasNewLocation(old.Locations, locations)
                    || (snapshot.IsComplete && old.Locations.Any(location =>
                        location.Name.Equals("Disallowed", StringComparison.OrdinalIgnoreCase)
                        && !locations.Any(item => SameLocation(item, location))))
                    ? MonitorChangeKind.LocationsChanged : null;
            if (kind is not null)
                changes.Add(new MonitorChange(kind.Value, current));
        }

        if (snapshot.IsComplete)
        {
            foreach (TrackedMatch old in oldMatches.Values)
            {
                if (nextMatches.TryGetValue(old.CertificateId, out TrackedMatch? current)
                    && !ReferenceEquals(old, current))
                    continue;
                if (!old.IsPresent)
                    continue;
                TrackedMatch disappeared = old with { Locations = Array.Empty<CertificateStoreDescriptor>() };
                nextMatches[old.CertificateId] = disappeared;
                bool stillObserved = snapshot.Certificates.Any(item =>
                    item.Metadata.CertificateId.Equals(old.CertificateId, StringComparison.OrdinalIgnoreCase));
                changes.Add(new MonitorChange(stillObserved ? MonitorChangeKind.NoLongerMatches
                    : MonitorChangeKind.Disappeared, disappeared));
            }
        }

        TrackedMatch[] state = nextMatches.Values
            .OrderBy(match => match.CertificateId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(match => match.CertificateId, StringComparer.Ordinal).ToArray();
        MonitorChange[] orderedChanges = changes
            .OrderBy(change => change.Certificate.CertificateId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(change => change.Certificate.CertificateId, StringComparer.Ordinal).ToArray();
        return new MonitorComparison(new MonitorTrackingState(state), orderedChanges);
    }

    private static int CategoryRank(TrackedMatch match) => match.IsRussian ? 3
        : match.IsPossibleRussian ? 2 : match.WasPreviouslyDeleted ? 1 : 0;

    private static bool LostProtection(uint? previous, uint? current)
    {
        if (!previous.HasValue || !current.HasValue || previous == current)
            return false;
        return current == 0 || (new WindowsChainResult(previous).IsExplicitlyDistrusted
            && !new WindowsChainResult(current).IsExplicitlyDistrusted);
    }

    private static bool HasNewLocation(IReadOnlyList<CertificateStoreDescriptor> oldLocations,
        IReadOnlyList<CertificateStoreDescriptor> newLocations) =>
        newLocations.Any(location => !oldLocations.Any(old => SameLocation(old, location)));

    private static bool SameLocation(CertificateStoreDescriptor left, CertificateStoreDescriptor right) =>
        left.Location == right.Location && left.Name.Equals(right.Name, StringComparison.OrdinalIgnoreCase);

    private static CertificateStoreDescriptor[] SortLocations(IEnumerable<CertificateStoreDescriptor> locations) =>
        locations.DistinctBy(location => (location.Location, location.Name.ToUpperInvariant()))
            .OrderBy(location => location.Location)
            .ThenBy(location => location.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(location => location.Name, StringComparer.Ordinal).ToArray();
}
