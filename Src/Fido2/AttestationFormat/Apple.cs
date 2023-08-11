using System;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

internal sealed class Apple : AttestationVerifier
{
    public static byte[] GetAppleAttestationExtensionValue(X509ExtensionCollection exts)
    {
        var appleExtension = exts.FirstOrDefault(static e => e.Oid!.Value is "1.2.840.113635.100.8.2");
        
        if (appleExtension is null || appleExtension.RawData is null || appleExtension.RawData.Length < 0x26)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Extension with OID 1.2.840.113635.100.8.2 not found on Apple attestation credCert");

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
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Apple attestation extension has invalid data", ex);
        }
    }

    public override (AttestationType, X509Certificate2[]) Verify(VerifyAttestationRequest request)
    {
        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        if (!(request.X5c is CborArray { Length: >= 2 } x5cArray && x5cArray[0] is CborByteString { Length: > 0 }))
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.MalformedX5c_AppleAttestation);
        }

        // 2. Verify x5c is a valid certificate chain starting from the credCert to the Apple WebAuthn root certificate.
        // This happens in AuthenticatorAttestationResponse.VerifyAsync using metadata from MDS3

        var trustPath = new X509Certificate2[x5cArray.Length];

        for (int i = 0; i < trustPath.Length; i++)
        {
            trustPath[i] = new X509Certificate2((byte[])x5cArray[i]);
        }

        // credCert is the first certificate in the trust path
        var credCert = trustPath[0];

        // 3. Concatenate authenticatorData and clientDataHash to form nonceToHash.
        ReadOnlySpan<byte> nonceToHash = request.Data;

        // 4. Perform SHA-256 hash of nonceToHash to produce nonce.
        Span<byte> nonce = stackalloc byte[32];
        SHA256.HashData(nonceToHash, nonce);

        // 5. Verify nonce matches the value of the extension with OID ( 1.2.840.113635.100.8.2 ) in credCert.
        var appleExtensionBytes = GetAppleAttestationExtensionValue(credCert.Extensions);

        if (!nonce.SequenceEqual(appleExtensionBytes))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Mismatch between nonce and credCert attestation extension in Apple attestation");

        // 6. Verify credential public key matches the Subject Public Key of credCert.
        // First, obtain COSE algorithm being used from credential public key
        var coseAlg = (COSE.Algorithm)(int)request.CredentialPublicKey[COSE.KeyCommonParameter.Alg];

        // Next, build temporary CredentialPublicKey for comparison from credCert and COSE algorithm
        var cpk = new CredentialPublicKey(credCert, coseAlg);

        // Finally, compare byte sequence of CredentialPublicKey built from credCert with byte sequence of CredentialPublicKey from AttestedCredentialData from authData
        if (!cpk.GetBytes().AsSpan().SequenceEqual(request.AuthData.AttestedCredentialData!.CredentialPublicKey.GetBytes()))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Credential public key in Apple attestation does not match subject public key of credCert");

        // 7. If successful, return implementation-specific values representing attestation type Anonymous CA and attestation trust path x5c.
        return (AttestationType.Basic, trustPath);
    }
}
