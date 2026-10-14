using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace RussianCertMonitor.Tests;

internal static class GostDerFixture
{
    public static (byte[] Der, byte[] SubjectName) Create()
    {
        byte[] name = new X500DistinguishedName("CN=RCM-GOST-Metadata, C=RU").RawData;
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        writer.WriteInteger(2);
        writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        writer.WriteInteger(1);
        WriteSignatureAlgorithm(writer);
        writer.WriteEncodedValue(name);
        writer.PushSequence();
        writer.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1));
        writer.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(1));
        writer.PopSequence();
        writer.WriteEncodedValue(name);
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.643.7.1.1.1.1");
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.643.7.1.2.1.1.1");
        writer.WriteObjectIdentifier("1.2.643.7.1.1.2.2");
        writer.PopSequence();
        writer.PopSequence();
        writer.WriteBitString(new byte[64]);
        writer.PopSequence();
        writer.PopSequence();
        WriteSignatureAlgorithm(writer);
        writer.WriteBitString(new byte[64]);
        writer.PopSequence();
        return (writer.Encode(), name);
    }

    private static void WriteSignatureAlgorithm(AsnWriter writer)
    {
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.643.7.1.1.3.2");
        writer.PopSequence();
    }
}
