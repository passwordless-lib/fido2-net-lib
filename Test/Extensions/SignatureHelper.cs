using System.Formats.Asn1;

namespace fido2_net_lib;

internal static class SignatureHelper
{
    public static byte[] EcDsaSigFromSig(ReadOnlySpan<byte> sig, int keySizeInBits)
    {
        var coefficientSize = (int)Math.Ceiling((decimal)keySizeInBits / 8);
        var r = sig.Slice(0, coefficientSize);
        var s = sig.Slice(sig.Length - coefficientSize);

        var writer = new AsnWriter(AsnEncodingRules.BER);

        ReadOnlySpan<byte> zero = new byte[1] { 0 };

        using (writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(r.TrimStart(zero));
            writer.WriteIntegerUnsigned(s.TrimStart(zero));
        }

        return writer.Encode();
    }
}
