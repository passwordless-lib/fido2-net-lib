using System;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib
{
    internal sealed class Apple : AttestationVerifier
    {
        public static byte[] GetAppleAttestationExtensionValue(X509ExtensionCollection exts)
        {
            var appleExtension = exts.Cast<X509Extension>().FirstOrDefault(e => e.Oid.Value is "1.2.840.113635.100.8.2");
            
            if (appleExtension is null || appleExtension.RawData is null || appleExtension.RawData.Length < 0x26)
                throw new Fido2VerificationException("Extension with OID 1.2.840.113635.100.8.2 not found on Apple attestation credCert");

            try
            {
                var appleAttestationASN = Asn1Element.Decode(appleExtension.RawData);
                appleAttestationASN.CheckTag(new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true));
                appleAttestationASN.CheckExactSequenceLength(1);

                var appleAttestationASNSequence = appleAttestationASN[0];
                appleAttestationASNSequence.CheckConstructed();
                appleAttestationASNSequence.CheckExactSequenceLength(1);

                appleAttestationASNSequence[0].CheckTag(Asn1Tag.PrimitiveOctetString);

                return appleAttestationASNSequence[0].GetOctetString();
            }

            catch (Exception ex)
            {
                throw new Fido2VerificationException("Apple attestation extension has invalid data", ex);
            }
        }

        public override (AttestationType, X509Certificate2[]) Verify()
        {
            // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
            if (X5c is null || X5c.Type != CBORType.Array || X5c.Count < 2 ||
                X5c.Values is null || X5c.Values.Count is 0 ||
                X5c.Values.First().Type != CBORType.ByteString ||
                X5c.Values.First().GetByteString().Length is 0)
            {
                throw new Fido2VerificationException("Malformed x5c in Apple attestation");
            }

            // 2. Verify x5c is a valid certificate chain starting from the credCert to the Apple WebAuthn root certificate.
            // This happens in AuthenticatorAttestationResponse.VerifyAsync using metadata from MDS3

            var trustPath = X5c.Values
                .Select(x => new X509Certificate2(x.GetByteString()))
                .ToArray();

            // credCert is the first certificate in the trust path
            var credCert = trustPath[0];

            // 3. Concatenate authenticatorData and clientDataHash to form nonceToHash.
            var nonceToHash = Data;

            // 4. Perform SHA-256 hash of nonceToHash to produce nonce.
            byte[] nonce = SHA256.HashData(nonceToHash);

            // 5. Verify nonce matches the value of the extension with OID ( 1.2.840.113635.100.8.2 ) in credCert.
            var appleExtensionBytes = GetAppleAttestationExtensionValue(credCert.Extensions);

            if (!nonce.SequenceEqual(appleExtensionBytes))
                throw new Fido2VerificationException("Mismatch between nonce and credCert attestation extension in Apple attestation");

            // 6. Verify credential public key matches the Subject Public Key of credCert.
            // First, obtain COSE algorithm being used from credential public key
            var coseAlg = CredentialPublicKey[CBORObject.FromObject(COSE.KeyCommonParameter.Alg)].AsInt32();

            // Next, build temporary CredentialPublicKey for comparison from credCert and COSE algorithm
            var cpk = new CredentialPublicKey(credCert, coseAlg);

            // Finally, compare byte sequence of CredentialPublicKey built from credCert with byte sequence of CredentialPublicKey from AttestedCredentialData from authData
            if (!cpk.GetBytes().AsSpan().SequenceEqual(AuthData.AttestedCredentialData.CredentialPublicKey.GetBytes()))
                throw new Fido2VerificationException("Credential public key in Apple attestation does not match subject public key of credCert");

            // 7. If successful, return implementation-specific values representing attestation type Anonymous CA and attestation trust path x5c.
            return (AttestationType.Basic, trustPath);
        }
    }
}
