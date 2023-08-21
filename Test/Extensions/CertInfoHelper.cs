using Fido2NetLib;
using System.Buffers.Binary;

namespace fido2_net_lib;

internal static class PubAreaHelper
{
    public static byte[] Create(byte[] type, byte[] alg, byte[] attributes, byte[] policy, byte[] symmetric,
        byte[] scheme, byte[] keyBits, byte[] exponent, byte[] curveID, byte[] kdf, byte[] unique)
    {
        var tpmAlg = (TpmAlg)Enum.ToObject(typeof(TpmAlg), BinaryPrimitives.ReadUInt16BigEndian(type));

        IEnumerable<byte> raw = null;
        var uniqueLen = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(uniqueLen, (UInt16)unique.Length);

        if (TpmAlg.TPM_ALG_RSA == tpmAlg)
        {
            raw
                 = type
                .Concat(alg)
                .Concat(attributes)
                .Concat(BitConverter.GetBytes((UInt16)policy.Length)
                    .Reverse()
                    .ToArray())
                .Concat(policy)
                .Concat(symmetric)
                .Concat(scheme)
                .Concat(keyBits)
                .Concat(BitConverter.GetBytes(exponent[0] + (exponent[1] << 8) + (exponent[2] << 16)))
                .Concat(BitConverter.GetBytes((UInt16)unique.Length)
                    .Reverse()
                    .ToArray())
                .Concat(unique);
        }
        if (TpmAlg.TPM_ALG_ECC == tpmAlg)
        {
            raw = type
                .Concat(alg)
                .Concat(attributes)
                .Concat(BitConverter.GetBytes((UInt16)policy.Length)
                    .Reverse()
                    .ToArray())
                .Concat(policy)
                .Concat(symmetric)
                .Concat(scheme)
                .Concat(curveID)
                .Concat(kdf)
                .Concat(BitConverter.GetBytes((UInt16)unique.Length)
                    .Reverse()
                    .ToArray())
                .Concat(unique);
        }

        return raw.ToArray();
    }
}

internal static class CertInfoHelper
{
    public static byte[] Create(byte[] magic, byte[] type, byte[] qualifiedSigner,
        byte[] extraData, byte[] clock, byte[] resetCount, byte[] restartCount,
        byte[] safe, byte[] firmwareRevision, byte[] tPM2BName, byte[] attestedQualifiedNameBuffer)
    {
        var raw = new MemoryStream();

        raw.Write(magic);
        raw.Write(type);
        raw.Write(qualifiedSigner);
        raw.Write(extraData);
        raw.Write(clock);
        raw.Write(resetCount);
        raw.Write(restartCount);
        raw.Write(safe);
        raw.Write(firmwareRevision);
        raw.Write(tPM2BName);
        raw.Write(attestedQualifiedNameBuffer);

        return raw.ToArray();
    }
}
