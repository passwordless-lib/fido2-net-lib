using System;
using System.Linq;
using System.Collections.Generic;

namespace Fido2NetLib
{
    public enum TpmEccCurve : UInt16
    {
        // TCG TPM Rev 2.0, part 2, structures, section 6.4, TPM_ECC_CURVE
        TPM_ECC_NONE,       // 0x0000
        TPM_ECC_NIST_P192,  // 0x0001
        TPM_ECC_NIST_P224,  // 0x0002
        TPM_ECC_NIST_P256,  // 0x0003
        TPM_ECC_NIST_P384,  // 0x0004
        TPM_ECC_NIST_P521,  // 0x0005  
        TPM_ECC_BN_P256,    // 0x0010 curve to support ECDAA
        TPM_ECC_BN_P638,    // 0x0011 curve to support ECDAA
        TPM_ECC_SM2_P256    // 0x0020 
    }
    public enum TpmAlg : UInt16
    {
        // TCG TPM Rev 2.0, part 2, structures, section 6.3, TPM_ALG_ID
        TPM_ALG_ERROR, // 0
        TPM_ALG_RSA, // 1
        TPM_ALG_SHA1 = 4, // 4
        TPM_ALG_HMAC, // 5
        TPM_ALG_AES, // 6
        TPM_ALG_MGF1, // 7
        TPM_ALG_KEYEDHASH, // 8
        TPM_ALG_XOR = 0xA, // A
        TPM_ALG_SHA256, // B
        TPM_ALG_SHA384, // C
        TPM_ALG_SHA512, // D
        TPM_ALG_NULL = 0x10, // 10
        TPM_ALG_SM3_256 = 0x12, // 12
        TPM_ALG_SM4, // 13
        TPM_ALG_RSASSA, // 14
        TPM_ALG_RSAES, // 15
        TPM_ALG_RSAPSS, // 16
        TPM_ALG_OAEP, // 17
        TPM_ALG_ECDSA, // 18
        TPM_ALG_ECDH, // 19
        TPM_ALG_ECDAA, // 1A
        TPM_ALG_SM2, // 1B
        TPM_ALG_ECSCHNORR, // 1C
        TPM_ALG_ECMQV, // 1D
        TPM_ALG_KDF1_SP800_56A = 0x20,
        TPM_ALG_KDF2, // 21
        TPM_ALG_KDF1_SP800_108, // 22
        TPM_ALG_ECC, // 23
        TPM_ALG_SYMCIPHER = 0x25,
        TPM_ALG_CAMELLIA, // 26
        TPM_ALG_CTR = 0x40,
        TPM_ALG_OFB, // 41
        TPM_ALG_CBC, // 42 
        TPM_ALG_CFB, // 43
        TPM_ALG_ECB // 44
    };
    // TPMS_ATTEST, TPMv2-Part2, section 10.12.8
    public class CertInfo
    {
        public static readonly Dictionary<TpmAlg, UInt16> tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, UInt16>
        {
            {TpmAlg.TPM_ALG_SHA1,   (160/8) },
            {TpmAlg.TPM_ALG_SHA256, (256/8) },
            {TpmAlg.TPM_ALG_SHA384, (384/8) },
            {TpmAlg.TPM_ALG_SHA512, (512/8) }
        };
        public static (UInt16 size, byte[] name) NameFromTPM2BName(Memory<byte> ab, ref int offset)
        {
            // TCG TPM Rev 2.0, part 2, structures, section 10.5.3, TPM2B_NAME
            // This buffer holds a Name for any entity type. 
            // The type of Name in the structure is determined by context and the size parameter. 
            var totalBytes = AuthDataHelper.GetSizedByteArray(ab, ref offset, 2);
            UInt16 totalSize = 0;
            if (null != totalBytes)
            {
                totalSize = BitConverter.ToUInt16(totalBytes.ToArray().Reverse().ToArray(), 0);
            }
            UInt16 size = 0;
            var bytes = AuthDataHelper.GetSizedByteArray(ab, ref offset, 2);
            if (null != bytes)
            {
                size = BitConverter.ToUInt16(bytes.ToArray().Reverse().ToArray(), 0);
            }
            // If size is four, then the Name is a handle. 
            if (4 == size) throw new Fido2VerificationException("Unexpected handle in TPM2B_NAME");
            // If size is zero, then no Name is present. 
            if (0 == size) throw new Fido2VerificationException("Unexpected no name found in TPM2B_NAME");
            // Otherwise, the size shall be the size of a TPM_ALG_ID plus the size of the digest produced by the indicated hash algorithm.
            TpmAlg tpmalg = TpmAlg.TPM_ALG_ERROR;
            byte[] name = null;
            if (Enum.IsDefined(typeof(TpmAlg), size))
            {
                tpmalg = (TpmAlg)size;
                if (tpmAlgToDigestSizeMap.ContainsKey(tpmalg))
                {
                    name = AuthDataHelper.GetSizedByteArray(ab, ref offset, tpmAlgToDigestSizeMap[tpmalg]);
                }
            }
            if (totalSize != bytes.Length + name.Length) throw new Fido2VerificationException("Unexpected no name found in TPM2B_NAME");
            return (size, name);
        }
        public CertInfo(byte[] certInfo)
        {
            if (null == certInfo || 0 == certInfo.Length) throw new Fido2VerificationException("Malformed certInfo bytes");
            Raw = certInfo;
            var offset = 0;
            Magic = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 4);
            if (0xff544347 != BitConverter.ToUInt32(Magic.ToArray().Reverse().ToArray(), 0)) throw new Fido2VerificationException("Bad magic number " + Magic.ToString());
            Type = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 2);
            if (0x8017 != BitConverter.ToUInt16(Type.ToArray().Reverse().ToArray(), 0)) throw new Fido2VerificationException("Bad structure tag " + Type.ToString());
            QualifiedSigner = AuthDataHelper.GetSizedByteArray(certInfo, ref offset);
            ExtraData = AuthDataHelper.GetSizedByteArray(certInfo, ref offset);
            if (null == ExtraData || 0 == ExtraData.Length) throw new Fido2VerificationException("Bad extraData in certInfo");
            Clock = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 8);
            ResetCount = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 4);
            RestartCount = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 4);
            Safe = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 1);
            FirmwareVersion = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 8);
            var TPM2BName = NameFromTPM2BName(certInfo, ref offset);
            Alg = TPM2BName.size; // TPM_ALG_ID
            AttestedName = TPM2BName.name;
            AttestedQualifiedNameBuffer = AuthDataHelper.GetSizedByteArray(certInfo, ref offset);
            if (certInfo.Length != offset) throw new Fido2VerificationException("Leftover bits decoding certInfo");
        }
        public byte[] Raw { get; private set; }
        public byte[] Magic { get; private set; }
        public byte[] Type { get; private set; }
        public byte[] QualifiedSigner { get; private set; }
        public byte[] ExtraData { get; private set; }
        public byte[] Clock { get; private set; }
        public byte[] ResetCount { get; private set; }
        public byte[] RestartCount { get; private set; }
        public byte[] Safe { get; private set; }
        public byte[] FirmwareVersion { get; private set; }
        public UInt16 Alg { get; private set; }
        public byte[] AttestedName { get; private set; }
        public byte[] AttestedQualifiedNameBuffer { get; private set; }
    }
    // TPMT_PUBLIC, TPMv2-Part2, section 12.2.4
    public class PubArea
    {
        public PubArea(byte[] pubArea)
        {
            Raw = pubArea;
            var offset = 0;

            // TPMI_ALG_PUBLIC
            Type = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);
            var tpmalg = (TpmAlg)Enum.Parse(typeof(TpmAlg), BitConverter.ToUInt16(Type.ToArray().Reverse().ToArray(), 0).ToString());

            // TPMI_ALG_HASH 
            Alg = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);

            // TPMA_OBJECT, attributes that, along with type, determine the manipulations of this object 
            Attributes = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 4);

            // TPM2B_DIGEST, optional policy for using this key, computed using the alg of the object
            Policy = AuthDataHelper.GetSizedByteArray(pubArea, ref offset);

            // TPMU_PUBLIC_PARMS
            Symmetric = null;
            Scheme = null;

            if (TpmAlg.TPM_ALG_KEYEDHASH == tpmalg)
            {
                throw new Fido2VerificationException("TPM_ALG_KEYEDHASH not yet supported");
            }
            if (TpmAlg.TPM_ALG_SYMCIPHER == tpmalg)
            {
                throw new Fido2VerificationException("TPM_ALG_SYMCIPHER not yet supported");
            }

            // TPMS_ASYM_PARMS, for TPM_ALG_RSA and TPM_ALG_ECC
            if (TpmAlg.TPM_ALG_RSA == tpmalg || TpmAlg.TPM_ALG_ECC == tpmalg)
            {
                Symmetric = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);
                Scheme = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);
            }

            // TPMI_RSA_KEY_BITS, number of bits in the public modulus 
            KeyBits = null;
            // The public exponent, a prime number greater than 2. When zero, indicates that the exponent is the default of 2^16 + 1 
            Exponent = 0;

            if (TpmAlg.TPM_ALG_RSA == tpmalg)
            {
                KeyBits = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);
                var tmp = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 4);
                if (null != tmp)
                {
                    Exponent = BitConverter.ToUInt32(tmp.ToArray(), 0);
                    if (0 == Exponent) Exponent = System.Convert.ToUInt32(Math.Pow(2, 16) + 1);
                }
            }

            // TPMI_ECC_CURVE
            CurveID = null;

            // TPMT_KDF_SCHEME, an optional key derivation scheme for generating a symmetric key from a Z value 
            // If the kdf  parameter associated with curveID is not TPM_ALG_NULL then this is required to be NULL. 
            // NOTE There are currently no commands where this parameter has effect and, in the reference code, this field needs to be set to TPM_ALG_NULL. 
            KDF = null;

            if (TpmAlg.TPM_ALG_ECC == tpmalg)
            {
                CurveID = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);
                KDF = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);
            }

            // TPMU_PUBLIC_ID
            Unique = AuthDataHelper.GetSizedByteArray(pubArea, ref offset);
            if (pubArea.Length != offset) throw new Fido2VerificationException("Leftover bytes decoding pubArea");
                        if (null != CurveID)
            {
                var point = new System.Security.Cryptography.ECPoint();
                var uniqueOffset = 0;
                var size = AuthDataHelper.GetSizedByteArray(Unique, ref uniqueOffset, 2);
                point.X = AuthDataHelper.GetSizedByteArray(Unique, ref uniqueOffset, BitConverter.ToUInt16(size.Reverse().ToArray(), 0));
                size = AuthDataHelper.GetSizedByteArray(Unique, ref uniqueOffset, 2);
                point.Y = AuthDataHelper.GetSizedByteArray(Unique, ref uniqueOffset, BitConverter.ToUInt16(size.Reverse().ToArray(), 0));
                ECPoint = point;
            }
        }
        public byte[] Raw { get; private set; }
        public byte[] Type { get; private set; }
        public byte[] Alg { get; private set; }
        public byte[] Attributes { get; private set; }
        public byte[] Policy { get; private set; }
        public byte[] Symmetric { get; private set; }
        public byte[] Scheme { get; private set; }
        public byte[] KeyBits { get; private set; }
        public UInt32 Exponent { get; private set; }
        public byte[] CurveID { get; private set; }
        public TpmEccCurve EccCurve { get; private set; }
        public byte[] KDF { get; private set; }
        public byte[] Unique { get; private set; }
        public System.Security.Cryptography.ECPoint ECPoint { get; private set; }
    }
}
