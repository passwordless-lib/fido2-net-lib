using System.Buffers.Binary;

using Fido2NetLib;

using Test;

namespace fido2_net_lib;

internal static class PubAreaHelper
{
    internal static byte[] CreatePubArea(
        TpmAlg type,
        ReadOnlySpan<byte> alg,
        ReadOnlySpan<byte> attributes,
        ReadOnlySpan<byte> policy,
        ReadOnlySpan<byte> symmetric,
        ReadOnlySpan<byte> scheme,
        ReadOnlySpan<byte> keyBits,
        ReadOnlySpan<byte> exponent,
        ReadOnlySpan<byte> curveID,
        ReadOnlySpan<byte> kdf,
        ReadOnlySpan<byte> unique = default)
    {
        using var stream = new MemoryStream();

        if (type is TpmAlg.TPM_ALG_ECC)
        {
            stream.Write(type.ToUInt16BigEndianBytes());
            stream.Write(alg);
            stream.Write(attributes);
            stream.Write(GetUInt16BigEndianBytes(policy.Length));
            stream.Write(policy);
            stream.Write(symmetric);
            stream.Write(scheme);
            stream.Write(curveID);
            stream.Write(kdf);
            stream.Write(unique);
        }
        else
        {
            stream.Write(type.ToUInt16BigEndianBytes());
            stream.Write(alg);
            stream.Write(attributes);
            stream.Write(GetUInt16BigEndianBytes(policy.Length));
            stream.Write(policy);
            stream.Write(symmetric);
            stream.Write(scheme);
            stream.Write(keyBits);
            stream.Write(BitConverter.GetBytes(exponent[0] + (exponent[1] << 8) + (exponent[2] << 16)));
            stream.Write(GetUInt16BigEndianBytes(unique.Length));
            stream.Write(unique);
        }

        return stream.ToArray();
    }

    private static byte[] GetUInt16BigEndianBytes(int value)
    {
        return GetUInt16BigEndianBytes((UInt16)value);
    }

    private static byte[] GetUInt16BigEndianBytes(UInt16 value)
    {
        var buffer = new byte[2];

        BinaryPrimitives.WriteUInt16BigEndian(buffer, value);

        return buffer;
    }
}
