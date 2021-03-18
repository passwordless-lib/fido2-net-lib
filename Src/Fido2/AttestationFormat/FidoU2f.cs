using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib
{
    internal class FidoU2f : AttestationVerifier
    {
        private readonly IMetadataService _metadataService;

        public override (AttestationType, X509Certificate2[]) Verify()
        {
            // verify that aaguid is 16 empty bytes (note: required by fido2 conformance testing, could not find this in spec?)
            if (0 != AuthData.AttestedCredentialData.AaGuid.CompareTo(Guid.Empty))
                throw new Fido2VerificationException("Aaguid was not empty parsing fido-u2f atttestation statement");

            // https://www.w3.org/TR/webauthn/#fido-u2f-attestation
            // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
            // (handled in base class)
            if (null == X5c || CBORType.Array != X5c.Type || X5c.Count != 1)
                throw new Fido2VerificationException("Malformed x5c in fido - u2f attestation");

            // 2a. Check that x5c has exactly one element and let attCert be that element.
            if (null == X5c.Values || 0 == X5c.Values.Count ||
                CBORType.ByteString != X5c.Values.First().Type ||
                0 == X5c.Values.First().GetByteString().Length)
                throw new Fido2VerificationException("Malformed x5c in fido-u2f attestation");

            var attCert = new X509Certificate2(X5c.Values.First().GetByteString());

            // TODO : Check why this variable isn't used. Remove it or use it.
            var u2ftransports = U2FTransportsFromAttnCert(attCert.Extensions);

            // 2b. If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error
            var pubKey = attCert.GetECDsaPublicKey();
            var keyParams = pubKey.ExportParameters(false);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (!keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP256.Oid.FriendlyName))
                    throw new Fido2VerificationException("Attestation certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve");
            }
            else
            {
                if (!keyParams.Curve.Oid.Value.Equals(ECCurve.NamedCurves.nistP256.Oid.Value))
                    throw new Fido2VerificationException("Attestation certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve");
            }

            // 3. Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData
            // see rpIdHash, credentialId, and credentialPublicKey members of base class AuthenticatorData (AuthData)

            // 4. Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to CTAP1/U2F public Key format (Raw ANSI X9.62 public key format)
            // 4a. Let x be the value corresponding to the "-2" key (representing x coordinate) in credentialPublicKey, and confirm its size to be of 32 bytes. If size differs or "-2" key is not found, terminate this algorithm and return an appropriate error
            var x = CredentialPublicKey[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString();

            // 4b. Let y be the value corresponding to the "-3" key (representing y coordinate) in credentialPublicKey, and confirm its size to be of 32 bytes. If size differs or "-3" key is not found, terminate this algorithm and return an appropriate error
            var y = CredentialPublicKey[CBORObject.FromObject(COSE.KeyTypeParameter.Y)].GetByteString();

            // 4c.Let publicKeyU2F be the concatenation 0x04 || x || y
            var publicKeyU2F = new byte[1] { 0x4 }.Concat(x).Concat(y).ToArray();

            // 5. Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
            var verificationData = new byte[1] { 0x00 };
            verificationData = verificationData
                                .Concat(AuthData.RpIdHash)
                                .Concat(clientDataHash)
                                .Concat(AuthData.AttestedCredentialData.CredentialID)
                                .Concat(publicKeyU2F.ToArray())
                                .ToArray();

            // 6. Verify the sig using verificationData and certificate public key
            if (null == Sig || CBORType.ByteString != Sig.Type || 0 == Sig.GetByteString().Length)
                throw new Fido2VerificationException("Invalid fido-u2f attestation signature");

            byte[] ecsig;
            try
            {
                ecsig = CryptoUtils.SigFromEcDsaSig(Sig.GetByteString(), pubKey.KeySize);
            }
            catch (Exception ex)
            {
                throw new Fido2VerificationException("Failed to decode fido-u2f attestation signature from ASN.1 encoded form", ex);
            }

            var coseAlg = CredentialPublicKey[CBORObject.FromObject(COSE.KeyCommonParameter.Alg)].AsInt32();
            var hashAlg = CryptoUtils.HashAlgFromCOSEAlg(coseAlg);

            if (true != pubKey.VerifyData(verificationData, ecsig, hashAlg))
                throw new Fido2VerificationException("Invalid fido-u2f attestation signature");

            // 7. Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation
            var trustPath = X5c.Values
                .Select(x => new X509Certificate2(x.GetByteString()))
                .ToArray();

            return (AttestationType.AttCa, trustPath);
        }
    }
}
