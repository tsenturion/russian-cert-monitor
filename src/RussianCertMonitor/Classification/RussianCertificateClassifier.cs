using System.Formats.Asn1;
using RussianCertMonitor.Catalog;
using RussianCertMonitor.Settings;

namespace RussianCertMonitor.Classification;

internal sealed class RussianCertificateClassifier(CertificateCatalog catalog, MonitorSettings? settings = null)
{
    private readonly MonitorSettings rules = (settings ?? MonitorSettings.Default).Validate();
    private const string CountryOid = "2.5.4.6";
    private const string CommonNameOid = "2.5.4.3";
    private const string OrganizationOid = "2.5.4.10";

    private static readonly string[] KnownAuthorities =
    [
        "Минцифры", "Минкомсвязь", "НУЦ России", "ГУЦ Минкомсвязи", "ФНС",
        "Федеральная налоговая служба", "Казначейство России",
        "Федеральное казначейство", "Федерального казначейства",
        "ЦБ РФ", "Банк России", "Центральный банк Российской Федерации",
        "ГНИВЦ", "КриптоПро", "Крипто-Про", "CryptoPro", "Crypto-Pro",
        "Russian Trusted Root CA", "Russian Trusted RootCA",
        "Russian Trusted Sub CA", "Russian Trusted SubCA"
    ];

    public CertificateClassification Classify(
        string certificateId, ReadOnlyMemory<byte> subjectNameRaw, ReadOnlyMemory<byte> issuerNameRaw)
    {
        List<string> reasons = [];
        List<string> errors = [];
        bool isRussian = false;
        bool isPossibleRussian = false;

        CatalogCertificate? historical = catalog.Certificates.FirstOrDefault(item =>
            string.Equals(item.CertificateId, certificateId, StringComparison.OrdinalIgnoreCase));
        bool wasPreviouslyDeleted = historical?.WasPreviouslyDeleted == true;
        if (wasPreviouslyDeleted)
        {
            reasons.Add("Сертификат ранее удалялся из хранилища Windows.");
        }
        if (historical?.Affiliation == "russian")
        {
            isRussian = true;
            reasons.Add("Идентификатор совпадает с российским сертификатом в справочнике.");
        }

        InspectName(subjectNameRaw, "владельца", reasons, errors, ref isRussian, ref isPossibleRussian);
        InspectName(issuerNameRaw, "издателя", reasons, errors, ref isRussian, ref isPossibleRussian);

        if (rules.RussianCertificateIds.Contains(certificateId, StringComparer.OrdinalIgnoreCase))
        {
            isRussian = true;
            reasons.Add("Идентификатор указан в пользовательском правиле российских сертификатов.");
        }
        bool excluded = rules.NotificationExclusions.Contains(certificateId, StringComparer.OrdinalIgnoreCase);
        if (excluded)
            reasons.Add("Пользователь исключил этот идентификатор из уведомлений. Обнаружение и принадлежность сохранены.");

        return new CertificateClassification(
            isRussian, isPossibleRussian, wasPreviouslyDeleted, reasons, errors, excluded);
    }

    private void InspectName(
        ReadOnlyMemory<byte> raw, string role, List<string> reasons, List<string> errors,
        ref bool isRussian, ref bool isPossibleRussian)
    {
        try
        {
            AsnReader reader = new(raw, AsnEncodingRules.DER);
            AsnReader name = reader.ReadSequence();
            while (name.HasData)
            {
                AsnReader rdn = name.ReadSetOf();
                while (rdn.HasData)
                {
                    AsnReader attribute = rdn.ReadSequence();
                    string oid = attribute.ReadObjectIdentifier();
                    string? value = ReadString(attribute);
                    attribute.ThrowIfNotEmpty();
                    if (value is null)
                        continue;

                    if (oid == CountryOid && string.Equals(value.Trim(), "RU", StringComparison.OrdinalIgnoreCase))
                    {
                        isRussian = true;
                        reasons.Add($"В поле страны {role} указано RU.");
                    }
                    else if ((oid == CommonNameOid || oid == OrganizationOid)
                        && rules.AuthorityNames.Any(authority => ContainsAuthority(value, authority)))
                    {
                        isRussian = true;
                        reasons.Add($"Имя {role} совпадает с пользовательским правилом удостоверяющего центра: {value}.");
                    }
                    else if ((oid == CommonNameOid || oid == OrganizationOid) && IsKnownAuthority(value))
                    {
                        isRussian = true;
                        reasons.Add($"В имени {role} указан известный российский удостоверяющий центр: {value}.");
                    }
                    else if (ContainsWeakHint(value))
                    {
                        isPossibleRussian = true;
                        reasons.Add($"В имени {role} есть косвенный российский признак: {value}.");
                    }
                }
            }
            reader.ThrowIfNotEmpty();
        }
        catch (AsnContentException error)
        {
            errors.Add($"Не удалось разобрать DER-имя {role}: {error.Message}");
        }
    }

    private static string? ReadString(AsnReader attribute)
    {
        Asn1Tag tag = attribute.PeekTag();
        if (tag.TagClass != TagClass.Universal)
        {
            attribute.ReadEncodedValue();
            return null;
        }

        UniversalTagNumber kind = (UniversalTagNumber)tag.TagValue;
        if (kind == UniversalTagNumber.UniversalString)
            throw new AsnContentException("Неподдерживаемый тип строки X.500: UniversalString.");

        if (kind is UniversalTagNumber.UTF8String or UniversalTagNumber.PrintableString
            or UniversalTagNumber.BMPString or UniversalTagNumber.IA5String
            or UniversalTagNumber.T61String)
            return attribute.ReadCharacterString(kind);

        attribute.ReadEncodedValue();
        return null;
    }

    private static bool IsKnownAuthority(string value)
    {
        return KnownAuthorities.Any(authority => ContainsAuthority(value, authority));
    }

    private static bool ContainsAuthority(string value, string authority)
    {
        int start = 0;
        while ((start = value.IndexOf(authority, start, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            int end = start + authority.Length;
            if ((start == 0 || !char.IsLetterOrDigit(value[start - 1]))
                && (end == value.Length || !char.IsLetterOrDigit(value[end])))
                return true;
            start = end;
        }
        return false;
    }

    private static bool ContainsWeakHint(string value)
    {
        int start = 0;
        while ((start = value.IndexOf(".ru", start, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            int end = start + 3;
            if (end == value.Length || (!char.IsLetterOrDigit(value[end]) && value[end] is not ('-' or '_')))
                return true;
            start = end;
        }
        return value.Any(character => character is >= '\u0400' and <= '\u04FF');
    }
}
