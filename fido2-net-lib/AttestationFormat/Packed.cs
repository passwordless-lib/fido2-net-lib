using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib.AttestationFormat
{
    class Packed : AttestationFormat
    {
        public Packed(CBORObject attStmt, byte[] authenticatorData, byte[] clientDataHash) : base(attStmt, authenticatorData, clientDataHash)
        {
        }
        public override AttestationFormatVerificationResult Verify()
        {
            // Verify that attStmt is valid CBOR conforming to the syntax defined above and 
            // perform CBOR decoding on it to extract the contained fields.
            if (0 == attStmt.Keys.Count || 0 == attStmt.Values.Count)
                throw new Fido2VerificationException("Attestation format packed must have attestation statement");

            if (null == Sig || CBORType.ByteString != Sig.Type || 0 == Sig.GetByteString().Length)
                throw new Fido2VerificationException("Invalid packed attestation signature");

            if (null == Alg || CBORType.Number != Alg.Type)
                throw new Fido2VerificationException("Invalid packed attestation algorithm");

            // If x5c is present, this indicates that the attestation type is not ECDAA
            if (null != X5c)
            {
                if (CBORType.Array != X5c.Type || 0 == X5c.Count || null != EcdaaKeyId)
                    throw new Fido2VerificationException("Malformed x5c array in packed attestation statement");
                var enumerator = X5c.Values.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    if (null == enumerator || null == enumerator.Current
                        || CBORType.ByteString != enumerator.Current.Type
                        || 0 == enumerator.Current.GetByteString().Length)
                        throw new Fido2VerificationException("Malformed x5c cert found in packed attestation statement");

                    var x5ccert = new X509Certificate2(enumerator.Current.GetByteString());

                    if (DateTime.UtcNow < x5ccert.NotBefore || DateTime.UtcNow > x5ccert.NotAfter)
                        throw new Fido2VerificationException("Packed signing certificate expired or not yet valid");
                }

                // The attestation certificate attestnCert MUST be the first element in the array.
                var attestnCert = new X509Certificate2(X5c.Values.First().GetByteString());

                // 2a. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash 
                // using the attestation public key in attestnCert with the algorithm specified in alg
                var packedPubKey = (ECDsaCng)attestnCert.GetECDsaPublicKey(); // attestation public key
                if (false == CryptoUtils.algMap.ContainsKey(Alg.AsInt32()))
                    throw new Fido2VerificationException("Invalid attestation algorithm");

                var coseKey = CryptoUtils.CoseKeyFromCertAndAlg(attestnCert, Alg.AsInt32());

                if (true != CryptoUtils.VerifySigWithCoseKey(Data, coseKey, Sig.GetByteString()))
                    throw new Fido2VerificationException("Invalid full packed signature");

                // Verify that attestnCert meets the requirements in https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements
                // 2b. Version MUST be set to 3
                if (3 != attestnCert.Version)
                    throw new Fido2VerificationException("Packed x5c attestation certificate not V3");

                // Subject field MUST contain C, O, OU, CN
                // OU must match "Authenticator Attestation"
                if (true != AuthDataHelper.IsValidPackedAttnCertSubject(attestnCert.Subject))
                    throw new Fido2VerificationException("Invalid attestation cert subject");

                // 2c. If the related attestation root certificate is used for multiple authenticator models, 
                // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING
                // verify that the value of this extension matches the aaguid in authenticatorData
                var aaguid = AuthDataHelper.AaguidFromAttnCertExts(attestnCert.Extensions);
                if (aaguid != null && !aaguid.SequenceEqual(AuthData.AttData.Aaguid.ToArray()))
                    throw new Fido2VerificationException("aaguid present in packed attestation but does not match aaguid from authData");

                // 2d. The Basic Constraints extension MUST have the CA component set to false
                if (AuthDataHelper.IsAttnCertCACert(attestnCert.Extensions))
                    throw new Fido2VerificationException("Attestion certificate has CA cert flag present");

                // id-fido-u2f-ce-transports 
                var u2ftransports = AuthDataHelper.U2FTransportsFromAttnCert(attestnCert.Extensions);

                return new AttestationFormatVerificationResult()
                {
                    attnType = AttestationType.Basic,
                    trustPath = X5c.Values
                    .Select(x => new X509Certificate2(x.GetByteString()))
                    .ToArray()
                };

            }
            // If ecdaaKeyId is present, then the attestation type is ECDAA
            else if (null != EcdaaKeyId)
            {
                // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
                // using ECDAA-Verify with ECDAA-Issuer public key identified by ecdaaKeyId
                // https://www.w3.org/TR/webauthn/#biblio-fidoecdaaalgorithm

                throw new Fido2VerificationException("ECDAA is not yet implemented");
                // If successful, return attestation type ECDAA and attestation trust path ecdaaKeyId.
                //attnType = AttestationType.ECDAA;
                //trustPath = ecdaaKeyId;
            }
            // If neither x5c nor ecdaaKeyId is present, self attestation is in use
            else
            {
                // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData
                var credentialPublicKey = CBORObject.DecodeFromBytes(AuthData.AttData.CredentialPublicKey);
                var coseAlg = credentialPublicKey[CBORObject.FromObject(3)].AsInt32();
                if (Alg.AsInt32() != coseAlg)
                    throw new Fido2VerificationException("Algorithm mismatch between credential public key and authenticator data in self attestation statement");

                // Verify that sig is a valid signature over the concatenation of authenticatorData and 
                // clientDataHash using the credential public key with alg
                
                if (true != CryptoUtils.VerifySigWithCoseKey(Data, credentialPublicKey, Sig.GetByteString()))
                    throw new Fido2VerificationException("Failed to validate signature");

                // If successful, return attestation type Self and empty attestation trust path.
                return new AttestationFormatVerificationResult()
                {
                    attnType = AttestationType.Self,
                    trustPath = null
                };
            }
        }
    }
}
