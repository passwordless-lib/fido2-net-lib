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


    public static byte[] GetAaguidBlob(Guid aaGuid)
    {
        var aaguid = aaGuid.ToByteArray();

        if (BitConverter.IsLittleEndian)
        {
            SwapBytes(aaguid, 0, 3);
            SwapBytes(aaguid, 1, 2);
            SwapBytes(aaguid, 4, 5);
            SwapBytes(aaguid, 6, 7);
        }

        return GetBlob(aaguid);
    }

    private static void SwapBytes(byte[] bytes, int index1, int index2)
    {
        var temp = bytes[index1];
        bytes[index1] = bytes[index2];
        bytes[index2] = temp;
    }
}
