using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PeterO.Cbor;

namespace Fido2NetLib.AttestationFormat
{
    class FidoU2f : AttestationFormat
    {
        public FidoU2f(CBORObject attStmt, byte[] authenticatorData, byte[] clientDataHash) : base(attStmt, authenticatorData, clientDataHash)
        {
        }
        public override void Verify()
        {
            // verify that aaguid is 16 empty bytes (note: required by fido2 conformance testing, could not find this in spec?)
            if (false == AuthData.AttData.Aaguid.SequenceEqual(Guid.Empty.ToByteArray()))
                throw new Fido2VerificationException("Aaguid was not empty parsing fido-u2f atttestation statement");

            // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
            if (null == X5c || CBORType.Array != X5c.Type || X5c.Count != 1)
                throw new Fido2VerificationException("Malformed x5c in fido - u2f attestation");

            // 2a. the attestation certificate attestnCert MUST be the first element in the array
            if (null == X5c.Values || 0 == X5c.Values.Count ||
                CBORType.ByteString != X5c.Values.First().Type ||
                0 == X5c.Values.First().GetByteString().Length)
                throw new Fido2VerificationException("Malformed x5c in fido-u2f attestation");

            var cert = new X509Certificate2(X5c.Values.First().GetByteString());

            // 2b. If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error
            var pubKey = (ECDsaCng)cert.GetECDsaPublicKey();
            if (CngAlgorithm.ECDsaP256 != pubKey.Key.Algorithm)
                throw new Fido2VerificationException("Attestation certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve");

            // 3. Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData
            // see rpIdHash, credentialId, and credentialPublicKey variables

            // 4. Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to CTAP1/U2F public Key format
            var publicKeyU2F = CryptoUtils.U2FKeyFromCOSEKey(CredentialPublicKey);

            // 5. Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
            var verificationData = new byte[1] { 0x00 };
            verificationData = verificationData
                                .Concat(AuthData.RpIdHash)
                                .Concat(clientDataHash)
                                .Concat(AuthData.AttData.CredentialID)
                                .Concat(publicKeyU2F.ToArray())
                                .ToArray();

            // 6. Verify the sig using verificationData and certificate public key
            if (null == Sig || CBORType.ByteString != Sig.Type || 0 == Sig.GetByteString().Length)
                throw new Fido2VerificationException("Invalid fido-u2f attestation signature");

            var ecsig = CryptoUtils.SigFromEcDsaSig(Sig.GetByteString(), pubKey.KeySize);
            if (null == ecsig)
                throw new Fido2VerificationException("Failed to decode fido-u2f attestation signature from ASN.1 encoded form");

            if (true != pubKey.VerifyData(verificationData, ecsig, CryptoUtils.algMap[CredentialPublicKey[CBORObject.FromObject(3)].AsInt32()]))
                throw new Fido2VerificationException("Invalid fido-u2f attestation signature");
        }
    }
}
