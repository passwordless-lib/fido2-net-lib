using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Asn1;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib
{
    internal class Apple : AttestationVerifier
    {
        public static byte[] GetAppleAttestationExtensionValue(X509ExtensionCollection exts)
        {
            var appleExtension = exts.Cast<X509Extension>().FirstOrDefault(e => e.Oid.Value == "1.2.840.113635.100.8.2");
            
            if (appleExtension == null || appleExtension.RawData == null || appleExtension.RawData.Length < 0x26)
                throw new Fido2VerificationException("Extension with OID 1.2.840.113635.100.8.2 not found on Apple attestation credCert");

            try
            {
                var appleAttestationASN = AsnElt.Decode(appleExtension.RawData);
                appleAttestationASN.CheckConstructed();
                appleAttestationASN.CheckTag(AsnElt.SEQUENCE);
                appleAttestationASN.CheckNumSub(1);

                var sequence = appleAttestationASN.GetSub(0);
                sequence.CheckConstructed();
                sequence.CheckNumSub(1);

                var context = sequence.GetSub(0);
                context.CheckPrimitive();
                context.CheckTag(AsnElt.OCTET_STRING);

                return context.GetOctetString();
            }

            catch (Exception ex)
            {
                throw new Fido2VerificationException("Apple attestation extension has invalid data", ex);
            }
        }

        public override (AttestationType, X509Certificate2[]) Verify()
        {
            // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
            if (null == X5c || CBORType.Array != X5c.Type || X5c.Count < 2 ||
                    null == X5c.Values || 0 == X5c.Values.Count ||
                    CBORType.ByteString != X5c.Values.First().Type ||
                    0 == X5c.Values.First().GetByteString().Length)
                throw new Fido2VerificationException("Malformed x5c in Apple attestation");

            // 2. Verify x5c is a valid certificate chain starting from the credCert to the Apple WebAuthn root certificate.
            // TODO: Pull this in instead of hard coding?
            // https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem
            var appleWebAuthnRoots =    new string[] {
                "MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w" +
                "HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ" +
                "bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx" +
                "NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG" +
                "A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49" +
                "AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k" +
                "xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/" +
                "pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk" +
                "2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA" +
                "MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3" +
                "jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B" +
                "1bWeT0vT"};

            var trustPath = X5c.Values
                .Select(x => new X509Certificate2(x.GetByteString()))
                .ToArray();

            var appleWebAuthnRootCerts = appleWebAuthnRoots
                .Select(x => new X509Certificate2(Convert.FromBase64String(x)))
                .ToArray();

            if (!CryptoUtils.ValidateTrustChain(trustPath, appleWebAuthnRootCerts))
                throw new Fido2VerificationException("Invalid certificate chain in Apple attestation");

            // credCert is the first certificate in the trust path
            var credCert = trustPath[0];

            // 3. Concatenate authenticatorData and clientDataHash to form nonceToHash.
            var nonceToHash = Data;

            // 4. Perform SHA-256 hash of nonceToHash to produce nonce.
            var nonce = CryptoUtils.GetHasher(HashAlgorithmName.SHA256).ComputeHash(nonceToHash);

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
            if (!cpk.GetBytes().SequenceEqual(AuthData.AttestedCredentialData.CredentialPublicKey.GetBytes()))
                throw new Fido2VerificationException("Credential public key in Apple attestation does not match subject public key of credCert");

            // 7. If successful, return implementation-specific values representing attestation type Anonymous CA and attestation trust path x5c.
            return (AttestationType.Basic, trustPath);
        }
    }
}
