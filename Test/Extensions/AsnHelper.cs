using System.Formats.Asn1;

namespace fido2_net_lib;

public static class AsnHelper
{
    public static byte[] GetBlob(byte[] input)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);

        writer.WriteOctetString(input);

        return writer.Encode();
    }
}
