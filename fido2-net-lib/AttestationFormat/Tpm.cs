using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib.AttestationFormat
{
    class Tpm : AttestationFormat
    {
        public Tpm(CBORObject attStmt, byte[] authenticatorData, byte[] clientDataHash) : base(attStmt, authenticatorData, clientDataHash)
        {
        }
        public override AttestationFormatVerificationResult Verify()
        {
            if (null == Sig || CBORType.ByteString != Sig.Type || 0 == Sig.GetByteString().Length)
                throw new Fido2VerificationException("Invalid TPM attestation signature");

            if ("2.0" != attStmt["ver"].AsString())
                throw new Fido2VerificationException("FIDO2 only supports TPM 2.0");

            // Verify that the public key specified by the parameters and unique fields of pubArea
            // is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData
            PubArea pubArea = null;
            if (null != attStmt["pubArea"] &&
                CBORType.ByteString == attStmt["pubArea"].Type &&
                0 != attStmt["pubArea"].GetByteString().Length)
                pubArea = new PubArea(attStmt["pubArea"].GetByteString());

            if (null == pubArea || null == pubArea.Unique || 0 == pubArea.Unique.Length)
                throw new Fido2VerificationException("Missing or malformed pubArea");

            var coseKty = CredentialPublicKey[CBORObject.FromObject(1)].AsInt32();
            if (3 == coseKty) // RSA
            {
                var coseMod = CredentialPublicKey[CBORObject.FromObject(-1)].GetByteString(); // modulus 
                var coseExp = CredentialPublicKey[CBORObject.FromObject(-2)].GetByteString(); // exponent

                if (!coseMod.ToArray().SequenceEqual(pubArea.Unique.ToArray())) throw new Fido2VerificationException("Public key mismatch between pubArea and credentialPublicKey");
                if ((coseExp[0] + (coseExp[1] << 8) + (coseExp[2] << 16)) != pubArea.Exponent) throw new Fido2VerificationException("Public key exponent mismatch between pubArea and credentialPublicKey");
            }
            else if (2 == coseKty) // ECC
            {
                var curve = CredentialPublicKey[CBORObject.FromObject(-1)].AsInt32();
                var X = CredentialPublicKey[CBORObject.FromObject(-2)].GetByteString();
                var Y = CredentialPublicKey[CBORObject.FromObject(-3)].GetByteString();

                if (pubArea.EccCurve != CoseCurveToTpm[curve]) throw new Fido2VerificationException("Curve mismatch between pubArea and credentialPublicKey");
                if (!pubArea.ECPoint.X.SequenceEqual(X)) throw new Fido2VerificationException("X-coordinate mismatch between pubArea and credentialPublicKey");
                if (!pubArea.ECPoint.Y.SequenceEqual(Y)) throw new Fido2VerificationException("Y-coordinate mismatch between pubArea and credentialPublicKey");
            }
            // Concatenate authenticatorData and clientDataHash to form attToBeSigned.
            // see data variable

            // Validate that certInfo is valid
            CertInfo certInfo = null;
            if (null != attStmt["certInfo"] &&
                CBORType.ByteString == attStmt["certInfo"].Type &&
                0 != attStmt["certInfo"].GetByteString().Length)
                certInfo = new CertInfo(attStmt["certInfo"].GetByteString());

            if (null == certInfo || null == certInfo.ExtraData || 0 == certInfo.ExtraData.Length)
                throw new Fido2VerificationException("CertInfo invalid parsing TPM format attStmt");

            // Verify that magic is set to TPM_GENERATED_VALUE and type is set to TPM_ST_ATTEST_CERTIFY 
            // handled in parser, see CertInfo.Magic

            // Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg"
            if (null == Alg || CBORType.Number != Alg.Type || false == CryptoUtils.algMap.ContainsKey(Alg.AsInt32())) throw new Fido2VerificationException("Invalid TPM attestation algorithm");
            if (!CryptoUtils.GetHasher(CryptoUtils.algMap[Alg.AsInt32()]).ComputeHash(Data).SequenceEqual(certInfo.ExtraData)) throw new Fido2VerificationException("Hash value mismatch extraData and attToBeSigned");

            // Verify that attested contains a TPMS_CERTIFY_INFO structure, whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea 
            if (false == CryptoUtils.GetHasher(CryptoUtils.algMap[certInfo.Alg]).ComputeHash(pubArea.Raw).SequenceEqual(certInfo.AttestedName)) throw new Fido2VerificationException("Hash value mismatch attested and pubArea");

            // If x5c is present, this indicates that the attestation type is not ECDAA
            if (null != X5c && CBORType.Array == X5c.Type && 0 != X5c.Count)
            {
                if (null == X5c.Values || 0 == X5c.Values.Count ||
                    CBORType.ByteString != X5c.Values.First().Type ||
                    0 == X5c.Values.First().GetByteString().Length)
                    throw new Fido2VerificationException("Malformed x5c in TPM attestation");

                // Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
                var aikCert = new X509Certificate2(X5c.Values.First().GetByteString());

                var coseKey = CryptoUtils.CoseKeyFromCertAndAlg(aikCert, Alg.AsInt32());

                if (true != CryptoUtils.VerifySigWithCoseKey(certInfo.Raw, coseKey, Sig.GetByteString()))
                    throw new Fido2VerificationException("Bad signature in TPM with aikCert");

                // Verify that aikCert meets the TPM attestation statement certificate requirements
                // https://www.w3.org/TR/webauthn/#tpm-cert-requirements
                // Version MUST be set to 3
                if (3 != aikCert.Version)
                    throw new Fido2VerificationException("aikCert must be V3");

                // Subject field MUST be set to empty - they actually mean subject name
                if (0 != aikCert.SubjectName.Name.Length)
                    throw new Fido2VerificationException("aikCert subject must be empty");

                // The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
                // https://www.w3.org/TR/webauthn/#tpm-cert-requirements
                var SAN = SANFromAttnCertExts(aikCert.Extensions);
                if (null == SAN || 0 == SAN.Length)
                    throw new Fido2VerificationException("SAN missing from TPM attestation certificate");

                // From https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
                // "The issuer MUST include TPM manufacturer, TPM part number and TPM firmware version, using the directoryName 
                // form within the GeneralName structure. The ASN.1 encoding is specified in section 3.1.2 TPM Device 
                // Attributes. In accordance with RFC 5280[11], this extension MUST be critical if subject is empty 
                // and SHOULD be non-critical if subject is non-empty"

                // Best I can figure to do for now?
                if (false == SAN.Contains("TPMManufacturer") || false == SAN.Contains("TPMModel") ||
                    false == SAN.Contains("TPMVersion"))
                    throw new Fido2VerificationException("SAN missing TPMManufacturer, TPMModel, or TPMVersopm from TPM attestation certificate");

                // The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
                // OID is 2.23.133.8.3
                var EKU = EKUFromAttnCertExts(aikCert.Extensions);
                if (null == EKU || 0 != EKU.CompareTo("Attestation Identity Key Certificate (2.23.133.8.3)"))
                    throw new Fido2VerificationException("Invalid EKU on AIK certificate");

                // The Basic Constraints extension MUST have the CA component set to false.
                if (IsAttnCertCACert(aikCert.Extensions))
                    throw new Fido2VerificationException("aikCert Basic Constraints extension CA component must be false");

                // If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData
                var aaguid = AaguidFromAttnCertExts(aikCert.Extensions);
                if ((null != aaguid) && (!aaguid.SequenceEqual(Guid.Empty.ToByteArray())) && (!aaguid.SequenceEqual(AuthData.AttData.Aaguid.ToArray()))) throw new Fido2VerificationException("aaguid malformed");

                // If successful, return attestation type AttCA and attestation trust path x5c.
                return new AttestationFormatVerificationResult()
                {
                    attnType = AttestationType.AttCa,
                    trustPath = X5c.Values
                    .Select(x => new X509Certificate2(x.GetByteString()))
                    .ToArray()
                };
            }
            // If ecdaaKeyId is present, then the attestation type is ECDAA
            else if (null != EcdaaKeyId)
            {
                // Perform ECDAA-Verify on sig to verify that it is a valid signature over certInfo
                // https://www.w3.org/TR/webauthn/#biblio-fidoecdaaalgorithm
                throw new Fido2VerificationException("ECDAA support for TPM attestation is not yet implemented");
                // If successful, return attestation type ECDAA and the identifier of the ECDAA-Issuer public key ecdaaKeyId.
                //attnType = AttestationType.ECDAA;
                //trustPath = ecdaaKeyId;
            }
            else throw new Fido2VerificationException("Neither x5c nor ECDAA were found in the TPM attestation statement");

        }
        private static readonly Dictionary<int, TpmEccCurve> CoseCurveToTpm = new Dictionary<int, TpmEccCurve>
        {
            { 1, TpmEccCurve.TPM_ECC_NIST_P256},
            { 2, TpmEccCurve.TPM_ECC_NIST_P384},
            { 3, TpmEccCurve.TPM_ECC_NIST_P521}
        };
        private static string SANFromAttnCertExts(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.17")) // subject alternative name
                {
                    var asn = new AsnEncodedData(ext.Oid, ext.RawData);
                    return asn.Format(true);
                }
            }
            return null;
        }
        private static string EKUFromAttnCertExts(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.37")) // EKU
                {
                    var asn = new AsnEncodedData(ext.Oid, ext.RawData);
                    return asn.Format(false);
                }
            }
            return null;
        }
    }

    public enum TpmEccCurve : ushort
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
    public enum TpmAlg : ushort
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
        private static readonly Dictionary<TpmAlg, ushort> tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
        {
            {TpmAlg.TPM_ALG_SHA1,   (160/8) },
            {TpmAlg.TPM_ALG_SHA256, (256/8) },
            {TpmAlg.TPM_ALG_SHA384, (384/8) },
            {TpmAlg.TPM_ALG_SHA512, (512/8) }
        };
        public static (ushort size, byte[] name) NameFromTPM2BName(Memory<byte> ab, ref int offset)
        {
            // TCG TPM Rev 2.0, part 2, structures, section 10.5.3, TPM2B_NAME
            // This buffer holds a Name for any entity type. 
            // The type of Name in the structure is determined by context and the size parameter. 
            var totalBytes = AuthDataHelper.GetSizedByteArray(ab, ref offset, 2);
            ushort totalSize = 0;
            if (null != totalBytes)
            {
                totalSize = BitConverter.ToUInt16(totalBytes.ToArray().Reverse().ToArray(), 0);
            }
            ushort size = 0;
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
            var tpmalg = TpmAlg.TPM_ALG_ERROR;
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
            var (size, name) = NameFromTPM2BName(certInfo, ref offset);
            Alg = size; // TPM_ALG_ID
            AttestedName = name;
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
        public ushort Alg { get; private set; }
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
            var tpmalg = (TpmAlg)Enum.Parse(typeof(TpmAlg), BitConverter.ToUInt16(Type.Reverse().ToArray(), 0).ToString());

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
                    if (0 == Exponent) Exponent = Convert.ToUInt32(Math.Pow(2, 16) + 1);
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
        }
        public byte[] Raw { get; private set; }
        public byte[] Type { get; private set; }
        public byte[] Alg { get; private set; }
        public byte[] Attributes { get; private set; }
        public byte[] Policy { get; private set; }
        public byte[] Symmetric { get; private set; }
        public byte[] Scheme { get; private set; }
        public byte[] KeyBits { get; private set; }
        public uint Exponent { get; private set; }
        public byte[] CurveID { get; private set; }
        public byte[] KDF { get; private set; }
        public byte[] Unique { get; private set; }
        public TpmEccCurve EccCurve { get { return (TpmEccCurve)Enum.Parse(typeof(TpmEccCurve), BitConverter.ToUInt16(CurveID.Reverse().ToArray(), 0).ToString()); }}
        public System.Security.Cryptography.ECPoint ECPoint
        {
            get
            {
                var point = new System.Security.Cryptography.ECPoint();
                var uniqueOffset = 0;
                var size = AuthDataHelper.GetSizedByteArray(Unique, ref uniqueOffset, 2);
                point.X = AuthDataHelper.GetSizedByteArray(Unique, ref uniqueOffset, BitConverter.ToUInt16(size.Reverse().ToArray(), 0));
                size = AuthDataHelper.GetSizedByteArray(Unique, ref uniqueOffset, 2);
                point.Y = AuthDataHelper.GetSizedByteArray(Unique, ref uniqueOffset, BitConverter.ToUInt16(size.Reverse().ToArray(), 0));
                return point;
            }
        }
    }
}
