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
        var raw = new MemoryStream();

        if (type is TpmAlg.TPM_ALG_ECC)
        {
            raw.Write(type.ToUInt16BigEndianBytes());
            raw.Write(alg);
            raw.Write(attributes);
            raw.Write(GetUInt16BigEndianBytes(policy.Length));
            raw.Write(policy);
            raw.Write(symmetric);
            raw.Write(scheme);
            raw.Write(curveID);
            raw.Write(kdf);
            raw.Write(unique);
        }
        else
        {
            raw.Write(type.ToUInt16BigEndianBytes());
            raw.Write(alg);
            raw.Write(attributes);
            raw.Write(GetUInt16BigEndianBytes(policy.Length));
            raw.Write(policy);
            raw.Write(symmetric);
            raw.Write(scheme);
            raw.Write(keyBits);
            raw.Write(BitConverter.GetBytes(exponent[0] + (exponent[1] << 8) + (exponent[2] << 16)));
            raw.Write(GetUInt16BigEndianBytes(unique.Length));
            raw.Write(unique);
        }

        return raw.ToArray();
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
