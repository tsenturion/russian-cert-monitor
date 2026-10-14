using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using RussianCertMonitor.Inventory;

namespace RussianCertMonitor.Certificates;

internal sealed class PublicCertificateData
{
    private const int MaxBytes = 1024 * 1024;

    public CertificateMetadata Metadata { get; }

    private PublicCertificateData(CertificateMetadata metadata) => Metadata = metadata;

    public static PublicCertificateData FromDer(byte[] der)
    {
        ArgumentNullException.ThrowIfNull(der);
        if (der.Length == 0 || der.Length > MaxBytes)
            throw new CryptographicException("Размер сертификата недопустим.");

        try
        {
            AsnReader reader = new(der, AsnEncodingRules.DER);
            reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(der);
            byte[] normalized = certificate.Export(X509ContentType.Cert);
            if (!normalized.AsSpan().SequenceEqual(der) || certificate.HasPrivateKey)
                throw new CryptographicException("Ожидался один публичный сертификат DER.");

            string id = certificate.Thumbprint;
            if (string.IsNullOrWhiteSpace(id))
                throw new CryptographicException("Идентификатор сертификата недоступен.");
            string subject = Read(() => certificate.Subject, $"Владелец не прочитан ({id})");
            string issuer = Read(() => certificate.Issuer, $"Издатель не прочитан ({id})");
            string display = Read(() => certificate.GetNameInfo(X509NameType.SimpleName, false), subject);
            if (string.IsNullOrWhiteSpace(display))
                display = string.IsNullOrWhiteSpace(subject) ? id : subject;
            return new(new CertificateMetadata(id, display, subject, issuer,
                Read(() => certificate.SerialNumber, "Серийный номер не прочитан"),
                Read<DateTimeOffset?>(() => new DateTimeOffset(certificate.NotBefore), null),
                Read<DateTimeOffset?>(() => new DateTimeOffset(certificate.NotAfter), null),
                Read(() => certificate.SubjectName.RawData, Array.Empty<byte>()),
                Read(() => certificate.IssuerName.RawData, Array.Empty<byte>()), normalized));
        }
        catch (AsnContentException error)
        {
            throw new CryptographicException("Некорректный DER сертификата.", error);
        }
    }

    public static PublicCertificateData FromFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length == 0 || stream.Length > MaxBytes)
            throw new CryptographicException("Размер файла сертификата недопустим.");
        byte[] bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        if (bytes.AsSpan().IndexOf("-----BEGIN"u8) < 0)
            return FromDer(bytes);

        string content = new UTF8Encoding(false, true).GetString(bytes);
        if (content.StartsWith('\uFEFF'))
            content = content[1..];
        if (!PemEncoding.TryFind(content, out PemFields fields))
            throw new CryptographicException("Некорректный PEM сертификата.");
        if (!content.AsSpan(0, fields.Location.Start.Value).Trim().IsEmpty
            || !content.AsSpan(fields.Location.End.Value).Trim().IsEmpty
            || !content.AsSpan(fields.Label).SequenceEqual("CERTIFICATE"))
            throw new CryptographicException("Ожидался один публичный PEM CERTIFICATE.");
        byte[] der = new byte[fields.DecodedDataLength];
        if (!Convert.TryFromBase64Chars(content.AsSpan(fields.Base64Data), der, out int written)
            || written != der.Length)
            throw new CryptographicException("Некорректные данные PEM сертификата.");
        return FromDer(der);
    }

    public void ExportCer(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        File.WriteAllBytes(path, Metadata.RawData);
    }

    private static T Read<T>(Func<T> getter, T fallback)
    {
        try { return getter(); }
        catch (Exception error) when (error is CryptographicException or ArgumentException or NotSupportedException)
        { return fallback; }
    }
}
