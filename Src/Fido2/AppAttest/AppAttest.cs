using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Verifies Apple App Attest attestations and assertions: proof that a request comes from a genuine instance of your
/// app on a genuine Apple device.
/// https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
/// </summary>
/// <remarks>
/// App Attest reuses WebAuthn's attestation object and authenticator data, but it is not a WebAuthn ceremony: there
/// is no client data JSON, no origin, and no user presence test, so its data does not go through
/// <see cref="IFido2.MakeNewCredentialAsync"/> or <see cref="IFido2.MakeAssertionAsync"/>. This is the entry point
/// for it instead.
/// </remarks>
public sealed class AppAttest
{
    private readonly AppAttestConfiguration _configuration;
    private readonly byte[] _appIdHash;

    /// <summary>
    /// Apple's App Attest root, which production and development attestation certificates both chain to.
    /// </summary>
    public static X509Certificate2 AppleRootCertificate => AppleAppAttest.AppleAppAttestRootCA;

    /// <summary>
    /// Initializes verification for one app.
    /// </summary>
    public AppAttest(AppAttestConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(configuration.AppId);

        _configuration = configuration;
        _appIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(configuration.AppId));
    }

    /// <summary>
    /// Verifies the attestation the app obtained from <c>DCAppAttestService.attestKey</c>.
    /// </summary>
    /// <param name="attestationObject">The attestation object the app sent, as returned by <c>attestKey</c>.</param>
    /// <param name="keyId">The key identifier the app sent alongside it.</param>
    /// <param name="clientDataHash">The hash the app passed to <c>attestKey</c>: by Apple's convention, the SHA-256
    /// of the one-time challenge the server issued. Compute it here from the challenge the server issued, never
    /// from anything the app sent.</param>
    /// <returns>The key to store, with the attestation's trust path.</returns>
    /// <exception cref="Fido2VerificationException">The attestation does not verify for this app.</exception>
    public async Task<AppAttestAttestationResult> VerifyAttestationAsync(byte[] attestationObject, byte[] keyId, byte[] clientDataHash)
    {
        ArgumentNullException.ThrowIfNull(attestationObject);
        ArgumentNullException.ThrowIfNull(keyId);
        ArgumentNullException.ThrowIfNull(clientDataHash);

        CborMap attStmt;
        AuthenticatorData authData;

        try
        {
            if (CborObject.Decode(attestationObject) is not CborMap map)
                throw new Fido2VerificationException(Fido2ErrorCode.MalformedAttestationObject, "The App Attest attestation object is not a CBOR map");

            if (map["fmt"] is not CborTextString { Value: "apple-appattest" })
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestationObject, $"The attestation format is not 'apple-appattest'. Was '{(map["fmt"] as CborTextString)?.Value}'");

            if (map["attStmt"] is not CborMap statement)
                throw new Fido2VerificationException(Fido2ErrorCode.MalformedAttestationObject, "The App Attest attestation object has no attStmt map");

            if (map["authData"] is not CborByteString { Length: > 0 } authDataBytes)
                throw new Fido2VerificationException(Fido2ErrorCode.MissingAuthenticatorData, "The App Attest attestation object has no authData");

            attStmt = statement;
            authData = AuthenticatorData.Parse(authDataBytes.Value);
        }
        catch (Exception ex) when (ex is System.Formats.Cbor.CborContentException or InvalidCastException)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.MalformedAttestationObject, "The App Attest attestation object is not well-formed CBOR", ex);
        }

        if (authData.AttestedCredentialData is null)
            throw new Fido2VerificationException(Fido2ErrorCode.AttestedCredentialDataFlagNotSet, "The App Attest authenticator data carries no attested credential");

        // Steps 1-5 and 7-9 of Apple's procedure: chain to the root, nonce, key identifier, counter, aaguid, credentialId.
        var verifier = new AppleAppAttest(_configuration.TrustAnchor);
        (AttestationType attestationType, X509Certificate2[] trustPath) = await verifier.VerifyAsync(attStmt, authData, clientDataHash).ConfigureAwait(false);

        // 6. Compute the SHA256 hash of your app's App ID, and verify that it's the same as the authenticator data's RP ID hash.
        // The verifier checked the certificate's own App ID extension against the hash; this checks it is *this* app.
        if (!authData.RpIdHash.SequenceEqual(_appIdHash))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidRpidHash, $"The App Attest attestation is for another app, not '{_configuration.AppId}'");

        // The key identifier the app claims must be the one the attestation is for.
        if (!keyId.AsSpan().SequenceEqual(authData.AttestedCredentialData.CredentialId))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "The key identifier does not match the attested key");

        // The verifier has already refused any AAGUID other than Apple's two
        AppAttestEnvironment environment = authData.AttestedCredentialData.AaGuid == AppleAppAttest.devAaguid
            ? AppAttestEnvironment.Development
            : AppAttestEnvironment.Production;

        if ((_configuration.Environments & environment) == 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, $"The App Attest key is from the {environment} environment, which is not accepted");

        byte[]? receipt = attStmt["receipt"] is CborByteString { Length: > 0 } receiptBytes ? receiptBytes.Value : null;

        return new AppAttestAttestationResult
        {
            Key = new AppAttestKey
            {
                KeyId = authData.AttestedCredentialData.CredentialId,
                PublicKey = authData.AttestedCredentialData.CredentialPublicKey.GetBytes(),
                Counter = authData.SignCount,
                Environment = environment,
                Receipt = receipt,
            },
            AttestationType = attestationType,
            TrustPath = trustPath,
        };
    }

    /// <summary>
    /// Verifies an assertion the app obtained from <c>DCAppAttestService.generateAssertion</c>.
    /// </summary>
    /// <param name="assertion">The assertion the app sent, as returned by <c>generateAssertion</c>.</param>
    /// <param name="clientDataHash">The hash the app passed to <c>generateAssertion</c>: the SHA-256 of the request
    /// data it asserted, which embeds a challenge the server issued. Compute it here from the request as received,
    /// and check the embedded challenge yourself; the library sees only the hash.</param>
    /// <param name="key">The key as stored from the attestation and advanced by every assertion since.</param>
    /// <returns>The advanced counter, and the key as it should now be stored.</returns>
    /// <exception cref="Fido2VerificationException">The assertion does not verify for this app and key.</exception>
    public AppAttestAssertionResult VerifyAssertion(byte[] assertion, byte[] clientDataHash, AppAttestKey key)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(clientDataHash);
        ArgumentNullException.ThrowIfNull(key);

        byte[] signature;
        byte[] authenticatorData;

        try
        {
            if (CborObject.Decode(assertion) is not CborMap map)
                throw new Fido2VerificationException(Fido2ErrorCode.MalformedAuthenticatorResponse, "The App Attest assertion is not a CBOR map");

            if (map["signature"] is not CborByteString { Length: > 0 } signatureBytes)
                throw new Fido2VerificationException(Fido2ErrorCode.InvalidAssertionResponse, "The App Attest assertion has no signature");

            if (map["authenticatorData"] is not CborByteString { Length: > 0 } authenticatorDataBytes)
                throw new Fido2VerificationException(Fido2ErrorCode.MissingAuthenticatorData, "The App Attest assertion has no authenticatorData");

            signature = signatureBytes.Value;
            authenticatorData = authenticatorDataBytes.Value;
        }
        catch (Exception ex) when (ex is System.Formats.Cbor.CborContentException or InvalidCastException)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.MalformedAuthenticatorResponse, "The App Attest assertion is not well-formed CBOR", ex);
        }

        var authData = AuthenticatorData.Parse(authenticatorData);

        // 1-2. Compute nonce as the SHA-256 of authenticatorData followed by clientDataHash.
        byte[] nonce = SHA256.HashData([.. authenticatorData, .. clientDataHash]);

        // 3. Use the public key that you stored from the attestation object to verify that the assertion's signature is valid for nonce.
        var publicKey = new CredentialPublicKey(key.PublicKey);

        if (!publicKey.Verify(nonce, signature))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignature, "The App Attest assertion signature does not verify under the stored key");

        // 4. Compute the SHA256 hash of the client's App ID, and verify that it matches the RP ID in the authenticator data.
        if (!authData.RpIdHash.SequenceEqual(_appIdHash))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidRpidHash, $"The App Attest assertion is for another app, not '{_configuration.AppId}'");

        // 5. Verify that the authenticator data's counter value is greater than the value from the previous assertion, or greater than 0 on the first assertion.
        if (authData.SignCount <= key.Counter)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignCount, $"The App Attest assertion counter {authData.SignCount} is not greater than the stored counter {key.Counter}");

        // 6. Verify that the embedded challenge in the client data matches the earlier challenge to the client.
        // The caller does this: the challenge is inside the request data whose hash was supplied.

        return new AppAttestAssertionResult
        {
            Counter = authData.SignCount,
            Key = new AppAttestKey
            {
                KeyId = key.KeyId,
                PublicKey = key.PublicKey,
                Counter = authData.SignCount,
                Environment = key.Environment,
                Receipt = key.Receipt,
            },
        };
    }
}
