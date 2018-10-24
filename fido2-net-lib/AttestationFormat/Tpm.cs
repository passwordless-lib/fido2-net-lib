using System;
using System.Linq;
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

                if (pubArea.EccCurve != CryptoUtils.CoseCurveToTpm[curve]) throw new Fido2VerificationException("Curve mismatch between pubArea and credentialPublicKey");
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
                var SAN = AuthDataHelper.SANFromAttnCertExts(aikCert.Extensions);
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
                var EKU = AuthDataHelper.EKUFromAttnCertExts(aikCert.Extensions);
                if (null == EKU || 0 != EKU.CompareTo("Attestation Identity Key Certificate (2.23.133.8.3)"))
                    throw new Fido2VerificationException("Invalid EKU on AIK certificate");

                // The Basic Constraints extension MUST have the CA component set to false.
                if (AuthDataHelper.IsAttnCertCACert(aikCert.Extensions))
                    throw new Fido2VerificationException("aikCert Basic Constraints extension CA component must be false");

                // If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData
                var aaguid = AuthDataHelper.AaguidFromAttnCertExts(aikCert.Extensions);
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
    }
}
