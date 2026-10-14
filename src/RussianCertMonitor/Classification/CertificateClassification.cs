namespace RussianCertMonitor.Classification;

internal sealed record CertificateClassification(
    bool IsRussian,
    bool IsPossibleRussian,
    bool WasPreviouslyDeleted,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<string> Errors,
    bool IsExcluded = false);
