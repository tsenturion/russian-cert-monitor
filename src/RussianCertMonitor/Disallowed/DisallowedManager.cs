using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.Infrastructure;

namespace RussianCertMonitor.Disallowed;

internal enum DisallowedOperation { Add, Remove }

internal sealed record DisallowedPreview(DisallowedOperation Operation, StoreLocation Location,
    PublicCertificateData Certificate, bool OwnPresent);

internal sealed record DisallowedResult(DisallowedOperation Operation, StoreLocation Location,
    string CertificateId, bool Changed, bool OwnPresentAfter, bool LogicalPresentAfter);

internal interface IDisallowedStoreBackend
{
    bool Contains(StoreLocation location, string id);
    byte[]? Find(StoreLocation location, string id);
    void Add(StoreLocation location, byte[] der);
    void Remove(StoreLocation location, string id);
    bool ContainsLogical(StoreLocation location, string id);
}

internal sealed class DisallowedManager(IDisallowedStoreBackend backend, DiagnosticLog? log = null)
{
    public DisallowedPreview Preview(DisallowedOperation operation, StoreLocation location,
        PublicCertificateData certificate)
    {
        Validate(operation, location);
        ArgumentNullException.ThrowIfNull(certificate);
        string id = certificate.Metadata.CertificateId;
        bool present = backend.Contains(location, id);
        if (operation == DisallowedOperation.Remove && present)
            certificate = FindVerified(location, id);
        return new(operation, location, certificate, present);
    }

    public DisallowedResult Execute(DisallowedPreview preview)
    {
        ArgumentNullException.ThrowIfNull(preview);
        Validate(preview.Operation, preview.Location);
        ArgumentNullException.ThrowIfNull(preview.Certificate);
        string id = preview.Certificate.Metadata.CertificateId;
        string context = $"Операция={preview.Operation}; область={preview.Location}; ID={id}";
        log?.TryWrite("disallowed.requested", context, context: new(id, $"{preview.Location}\\Disallowed", preview.Operation.ToString()));
        try
        {
            bool present = backend.Contains(preview.Location, id);
            bool changed = false;
            if (preview.Operation == DisallowedOperation.Add && !present)
            {
                if (!string.Equals(PublicCertificateData.FromDer(preview.Certificate.Metadata.RawData)
                    .Metadata.CertificateId, id, StringComparison.OrdinalIgnoreCase))
                    throw new CryptographicException("Данные сертификата не соответствуют идентификатору.");
                backend.Add(preview.Location, preview.Certificate.Metadata.RawData);
                changed = true;
            }
            else if (preview.Operation == DisallowedOperation.Remove && present)
            {
                if (!preview.OwnPresent || !FindVerified(preview.Location, id).Metadata.RawData.AsSpan()
                    .SequenceEqual(preview.Certificate.Metadata.RawData))
                    throw new CryptographicException("Сертификат в собственном Disallowed изменился после подтверждения.");
                backend.Remove(preview.Location, id);
                changed = true;
            }

            bool after = backend.Contains(preview.Location, id);
            if (after != (preview.Operation == DisallowedOperation.Add))
                throw new InvalidOperationException("Не удалось подтвердить состояние собственного хранилища Disallowed.");
            bool logical = backend.ContainsLogical(preview.Location, id);
            DisallowedResult result = new(preview.Operation, preview.Location, id, changed, after, logical);
            log?.TryWrite("disallowed.completed", $"{context}; изменено={changed}; своё={after}; логическое={logical}",
                context: new(id, $"{preview.Location}\\Disallowed", $"{preview.Operation}; changed={changed}; ownPresent={after}; logicalPresent={logical}"));
            return result;
        }
        catch (Exception error)
        {
            log?.TryWrite("disallowed.error", context, error, new(id, $"{preview.Location}\\Disallowed", "failed"));
            throw;
        }
    }

    private PublicCertificateData FindVerified(StoreLocation location, string id)
    {
        byte[]? der = backend.Find(location, id);
        if (der is null)
            throw new CryptographicException("Сертификат в собственном Disallowed изменился или исчез.");
        PublicCertificateData certificate = PublicCertificateData.FromDer(der);
        if (!string.Equals(certificate.Metadata.CertificateId, id, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("Сертификат в собственном Disallowed изменился или исчез.");
        return certificate;
    }

    private static void Validate(DisallowedOperation operation, StoreLocation location)
    {
        if (operation is not (DisallowedOperation.Add or DisallowedOperation.Remove))
            throw new ArgumentOutOfRangeException(nameof(operation));
        if (location is not (StoreLocation.CurrentUser or StoreLocation.LocalMachine))
            throw new ArgumentOutOfRangeException(nameof(location));
    }
}
