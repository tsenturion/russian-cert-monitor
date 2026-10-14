using System.Formats.Asn1;
using RussianCertMonitor.Catalog;
using RussianCertMonitor.Classification;

namespace RussianCertMonitor.Tests;

internal static class ClassifierChecks
{
    private const string OtherId = "0000000000000000000000000000000000000000";
    private const string UnknownHistoricalId = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    public static void Run()
    {
        CertificateCatalog catalog = CertificateCatalog.Load();
        RussianCertificateClassifier classifier = new(catalog);
        byte[] foreign = Name(("2.5.4.6", "US", UniversalTagNumber.PrintableString));

        CertificateClassification subject = classifier.Classify(OtherId,
            Name(("2.5.4.6", "RU", UniversalTagNumber.PrintableString)), foreign);
        Require(subject.IsRussian && subject.Reasons.Any(reason => reason.Contains("владельца")),
            "Страна владельца должна подтверждать российскую принадлежность.");

        CertificateClassification issuer = classifier.Classify(OtherId, foreign,
            Name(("2.5.4.6", "RU", UniversalTagNumber.PrintableString)));
        Require(issuer.IsRussian && issuer.Reasons.Any(reason => reason.Contains("издателя")),
            "Страна издателя должна учитываться отдельно.");

        CertificateClassification countries = classifier.Classify(OtherId,
            Name(("2.5.4.6", "US", UniversalTagNumber.PrintableString),
                ("2.5.4.6", "RU", UniversalTagNumber.PrintableString)), foreign);
        Require(countries.IsRussian, "Все RDN с указанием страны должны проверяться.");

        AsnWriter multiValueWriter = new(AsnEncodingRules.DER);
        using (multiValueWriter.PushSequence())
        using (multiValueWriter.PushSetOf())
        {
            using (multiValueWriter.PushSequence())
            {
                multiValueWriter.WriteObjectIdentifier("2.5.4.3");
                multiValueWriter.WriteCharacterString(UniversalTagNumber.UTF8String, "Example, C=US");
            }
            using (multiValueWriter.PushSequence())
            {
                multiValueWriter.WriteObjectIdentifier("2.5.4.6");
                multiValueWriter.WriteCharacterString(UniversalTagNumber.PrintableString, "RU");
            }
        }
        CertificateClassification multiValue = classifier.Classify(OtherId, multiValueWriter.Encode(), foreign);
        Require(multiValue.IsRussian && multiValue.Errors.Count == 0,
            "В многозначном RDN нужно проверить каждый атрибут.");

        CertificateClassification misleading = classifier.Classify(OtherId,
            Name(("2.5.4.3", "Example, C=RU", UniversalTagNumber.UTF8String)), foreign);
        Require(!misleading.IsRussian, "Текст C=RU внутри CN не является полем страны.");

        foreach (string authority in new[] { "Минцифры России", "Минкомсвязь России",
            "НУЦ России", "ГУЦ Минкомсвязи", "ФНС России", "Федеральная налоговая служба",
            "Казначейство России", "Федеральное казначейство", "Федерального казначейства",
            "ЦБ РФ", "ГНИВЦ", "КриптоПро", "CryptoPro", "Crypto-Pro",
            "Russian Trusted Root CA", "Russian Trusted RootCA",
            "Russian Trusted Sub CA", "Russian Trusted SubCA" })
        {
            CertificateClassification result = classifier.Classify(OtherId,
                Name(("2.5.4.10", authority, UniversalTagNumber.UTF8String)), foreign);
            Require(result.IsRussian, $"Не распознан известный УЦ: {authority}.");
        }
        CertificateClassification commonNameAuthority = classifier.Classify(OtherId,
            Name(("2.5.4.3", "Russian Trusted Root CA", UniversalTagNumber.PrintableString)), foreign);
        Require(commonNameAuthority.IsRussian, "Известный УЦ в CN должен распознаваться.");

        foreach (string ambiguous in new[] { "НУЦ", "ГУЦ", "Казначейство" })
        {
            CertificateClassification result = classifier.Classify(OtherId,
                Name(("2.5.4.3", ambiguous, UniversalTagNumber.UTF8String)), foreign);
            Require(!result.IsRussian && result.IsPossibleRussian,
                $"Общее обозначение {ambiguous} должно давать только предположение.");
        }
        byte[] kazakhstanAuthority = Name(
            ("2.5.4.3", "НУЦ Республики Казахстан", UniversalTagNumber.UTF8String),
            ("2.5.4.6", "KZ", UniversalTagNumber.PrintableString));
        CertificateClassification kazakhstan = classifier.Classify(OtherId,
            kazakhstanAuthority, kazakhstanAuthority);
        Require(!kazakhstan.IsRussian && kazakhstan.IsPossibleRussian,
            "НУЦ Республики Казахстан не должен подтверждать российскую принадлежность.");

        CertificateClassification cyrillic = classifier.Classify(OtherId,
            Name(("2.5.4.3", "Пример", UniversalTagNumber.BMPString)), foreign);
        Require(!cyrillic.IsRussian && cyrillic.IsPossibleRussian,
            "Одна кириллица должна давать только предположение.");

        CertificateClassification domain = classifier.Classify(OtherId,
            Name(("2.5.4.3", "example.ru", UniversalTagNumber.IA5String)), foreign);
        Require(!domain.IsRussian && domain.IsPossibleRussian,
            "Домен .ru должен давать только предположение.");
        foreach (string nonDomain in new[] { "example.rust", "example.rubbish", "example.ru-fake" })
        {
            CertificateClassification unrelated = classifier.Classify(OtherId,
                Name(("2.5.4.3", nonDomain, UniversalTagNumber.IA5String)), foreign);
            Require(!unrelated.IsPossibleRussian, $"Строка {nonDomain} не содержит домен .ru.");
        }
        CertificateClassification teletex = classifier.Classify(OtherId,
            Name(("2.5.4.3", "example.ru", UniversalTagNumber.T61String)), foreign);
        Require(teletex.IsPossibleRussian && teletex.Errors.Count == 0,
            "Строка Teletex/T61 должна читаться средствами .NET.");

        CertificateClassification privateCa = classifier.Classify(OtherId,
            Name(("2.5.4.3", "Private CA", UniversalTagNumber.PrintableString)), foreign);
        Require(!privateCa.IsRussian && !privateCa.IsPossibleRussian && !privateCa.WasPreviouslyDeleted,
            "Иностранный частный УЦ не должен считаться российским.");

        CertificateClassification unknown = classifier.Classify(UnknownHistoricalId, foreign, foreign);
        Require(!unknown.WasPreviouslyDeleted && !unknown.IsRussian && !unknown.IsPossibleRussian,
            "Неизвестный идентификатор без локальной истории не должен считаться историческим.");

        CatalogCertificate localUnknown = new(UnknownHistoricalId, null, "unknown",
            null, null, null, null, WasPreviouslyDeleted: true);
        RussianCertificateClassifier localClassifier = new(catalog with
        {
            Certificates = catalog.Certificates.Append(localUnknown).ToArray()
        });
        CertificateClassification historicalUnknown = localClassifier.Classify(UnknownHistoricalId, foreign, foreign);
        Require(historicalUnknown.WasPreviouslyDeleted && !historicalUnknown.IsRussian
            && !historicalUnknown.IsPossibleRussian,
            "Неизвестная локальная история не доказывает российскую принадлежность.");
        Require(historicalUnknown.Reasons.Any(reason => reason.Contains("удалялся")),
            "Локальная историческая запись должна иметь причину.");

        CertificateClassification unknownWithCountry = localClassifier.Classify(UnknownHistoricalId,
            Name(("2.5.4.6", "RU", UniversalTagNumber.PrintableString)), foreign);
        Require(unknownWithCountry.WasPreviouslyDeleted && unknownWithCountry.IsRussian,
            "Неизвестную историческую принадлежность могут уточнить реальные поля сертификата.");

        CatalogCertificate known = catalog.Certificates.First(item => item.Affiliation == "russian");
        CertificateClassification historical = classifier.Classify(known.CertificateId, foreign, foreign);
        Require(historical.IsRussian && !historical.WasPreviouslyDeleted,
            "Публичный российский ID подтверждает принадлежность без локальной истории.");

        CertificateCatalog expiredCatalog = catalog with
        {
            Certificates = [known with { ValidTo = "2000-01-01" }]
        };
        CertificateClassification expired = new RussianCertificateClassifier(expiredCatalog)
            .Classify(known.CertificateId, foreign, foreign);
        Require(expired.IsRussian, "Дата окончания действия не должна влиять на классификацию.");

        CertificateClassification malformed = classifier.Classify(OtherId, new byte[] { 0x30, 0x02, 0x31 },
            Name(("2.5.4.6", "RU", UniversalTagNumber.PrintableString)));
        Require(malformed.Errors.Count > 0 && malformed.IsRussian,
            "Повреждённый DER должен возвращать ошибку и не прерывать разбор второго имени.");

        AsnWriter unsupportedWriter = new(AsnEncodingRules.DER);
        using (unsupportedWriter.PushSequence())
        using (unsupportedWriter.PushSetOf())
        using (unsupportedWriter.PushSequence())
        {
            unsupportedWriter.WriteObjectIdentifier("2.5.4.3");
            unsupportedWriter.WriteEncodedValue(new byte[] { 0x1C, 0x04, 0x00, 0x00, 0x00, 0x41 });
        }
        CertificateClassification unsupported = classifier.Classify(OtherId, unsupportedWriter.Encode(),
            Name(("2.5.4.6", "RU", UniversalTagNumber.PrintableString)));
        Require(unsupported.Errors.Count > 0 && unsupported.IsRussian,
            "Неподдерживаемая UniversalString должна попасть в ошибки и не прерывать разбор издателя.");

        CertificateClassification gost = classifier.Classify(OtherId,
            Name(("1.2.643.100.1", "ГОСТ", UniversalTagNumber.BMPString)), foreign);
        Require(!gost.IsRussian && gost.IsPossibleRussian && gost.Errors.Count == 0,
            "Произвольный ГОСТ OID и строка должны разбираться без проверки ключей.");
    }

    private static byte[] Name(params (string Oid, string Value, UniversalTagNumber Kind)[] attributes)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach ((string oid, string value, UniversalTagNumber kind) in attributes)
            {
                using (writer.PushSetOf())
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(oid);
                    writer.WriteCharacterString(kind, value);
                }
            }
        }
        return writer.Encode();
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
