using System;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

internal sealed class Apple : AttestationVerifier
{
    private readonly X509Certificate2 _trustAnchor;
    private readonly bool _verifyChain;

    /// <summary>
    /// Verifies against Apple's WebAuthn root.
    /// </summary>
    public Apple() : this(AppleWebAuthnRootCA, verifyChain: true) { }

    /// <summary>
    /// Verifies against the given root, so a Relying Party can override the trust anchor and the tests can use a
    /// root of their own.
    /// </summary>
    public Apple(X509Certificate2 trustAnchor) : this(trustAnchor, verifyChain: true) { }

    // AppleAppAttest reuses this verifier for the nonce and public-key checks only; it validates the chain
    // itself against the App Attest root (with its own expired-development-leaf handling), so it passes
    // verifyChain: false to avoid a second, wrong-root chain build here.
    internal Apple(bool verifyChain) : this(AppleWebAuthnRootCA, verifyChain) { }

    private Apple(X509Certificate2 trustAnchor, bool verifyChain)
    {
        _trustAnchor = trustAnchor;
        _verifyChain = verifyChain;
    }

    // From https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem
    // SHA-256 fingerprint 0915DD5C07A28DB549D1F677BB5A75D4BFBE9561A773424327762E9E02F9BB29.
    public static readonly X509Certificate2 AppleWebAuthnRootCA = X509CertificateHelper.CreateFromBase64String(
        "MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8wHQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMxNTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11kxu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cAMGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B1bWeT0vT"u8);

    public static byte[] GetAppleAttestationExtensionValue(X509ExtensionCollection exts)
    {
        var appleExtension = exts.FirstOrDefault(static e => e.Oid?.Value is "1.2.840.113635.100.8.2");

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

    public override ValueTask<VerifyAttestationResult> VerifyAsync(VerifyAttestationRequest request)
    {
        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        if (!(request.X5c is CborArray { Length: >= 2 } x5cArray && x5cArray[0] is CborByteString { Length: > 0 }))
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.MalformedX5c_AppleAttestation);
        }

        // 2. Verify x5c is a valid certificate chain starting from the credCert to the Apple WebAuthn root
        // certificate. Apple platform authenticators are not in the FIDO Metadata Service, so this cannot be
        // deferred to metadata-based trust-anchor validation; it is done at the end of this method (after the
        // cheaper structural, nonce, and public-key checks).

        var trustPath = new X509Certificate2[x5cArray.Length];

        for (int i = 0; i < trustPath.Length; i++)
        {
            // Only x5cArray[0] was type-checked above; casting the rest with (byte[]) would throw a raw
            // InvalidCastException on a malformed chain, so verify each element is a byte string first.
            if (x5cArray[i] is not CborByteString { Length: > 0 } x5cCert)
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.MalformedX5c_AppleAttestation);

            trustPath[i] = X509CertificateHelper.CreateFromRawData(x5cCert.Value);
        }

        // credCert is the first certificate in the trust path
        var credCert = trustPath[0];

        // 3. Concatenate authenticatorData and clientDataHash to form nonceToHash.
        ReadOnlySpan<byte> nonceToHash = request.Data;

        // 4. Perform SHA-256 hash of nonceToHash to produce nonce.
        Span<byte> nonce = stackalloc byte[SHA256.HashSizeInBytes];
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

        // 2 (deferred). Verify credCert chains to the Apple WebAuthn root. Without this a self-signed credCert
        // carrying a matching nonce and public key would pass the checks above and be accepted. Skipped when a
        // caller (AppleAppAttest) has already validated the chain against a different root.
        if (_verifyChain)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(_trustAnchor);

            for (int i = 1; i < trustPath.Length; i++)
                chain.ChainPolicy.ExtraStore.Add(trustPath[i]);

            if (!chain.Build(credCert))
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"Failed to build chain in Apple attestation: {chain.ChainStatus.FirstOrDefault().StatusInformation?.Trim()}");
        }

        // 7. If successful, return implementation-specific values representing attestation type Anonymization CA and attestation trust path x5c.
        return new(new VerifyAttestationResult(AttestationType.AnonCA, trustPath));
    }
}
