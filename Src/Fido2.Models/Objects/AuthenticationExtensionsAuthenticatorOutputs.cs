namespace Fido2NetLib.Objects;

/// <summary>
/// The authenticator extension outputs carried in the extensions block of the authenticator data, decoded into
/// the outputs CTAP defines.
/// </summary>
/// <remarks>
/// WebAuthn requires a Relying Party to process these alongside the client extension outputs
/// (<see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">§7.1 step 28</see> and
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">§7.2 step 23</see>). Every member is
/// <see langword="null"/> when the authenticator did not return that extension, when its value had the wrong
/// CBOR type, or when the extensions block as a whole did not decode.
/// <para>
/// Outputs this library does not model can still be read from the raw CBOR map, which the authenticator data
/// exposes.
/// </para>
/// </remarks>
public sealed class AuthenticationExtensionsAuthenticatorOutputs
{
    /// <summary>
    /// The credential protection policy the authenticator applied to the credential, which may be stricter than
    /// the one the Relying Party asked for. Registration only.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credProtect-extension"/>
    /// </remarks>
    public CredentialProtectionPolicy? CredProtect { get; init; }

    /// <summary>
    /// Whether the authenticator stored the <c>credBlob</c> the Relying Party supplied. Registration only; on an
    /// assertion the authenticator returns the blob itself, in <see cref="CredBlob"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credBlob-extension"/>
    /// </remarks>
    public bool? CredBlobStored { get; init; }

    /// <summary>
    /// The <c>credBlob</c> the authenticator has stored for the credential. Assertion only; on a registration
    /// the authenticator instead reports whether it stored the blob, in <see cref="CredBlobStored"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credBlob-extension"/>
    /// </remarks>
    public byte[]? CredBlob { get; init; }

    /// <summary>
    /// The authenticator's current minimum PIN length. Only returned when the Relying Party is authorized to
    /// ask, and only during registration. An organization that issues configured authenticators can use this to
    /// check that the minimum PIN length still meets its requirements.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-minpinlength-extension"/>
    /// </remarks>
    public uint? MinPinLength { get; init; }

    /// <summary>
    /// The authenticator's current PIN complexity policy. Only returned when the Relying Party is authorized to
    /// ask, and only during registration. New in CTAP 2.3.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-pincomplexitypolicy-extension"/>
    /// </remarks>
    public bool? PinComplexityPolicy { get; init; }

    /// <summary>
    /// Whether the credential is third-party payment enabled, i.e. usable for a payment authentication started
    /// by a party other than the Relying Party. Assertion only. New in CTAP 2.3.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-thirdPartyPayment-extension"/>
    /// </remarks>
    public bool? ThirdPartyPayment { get; init; }

    /// <summary>
    /// Whether the credential was created with an <c>hmac-secret</c>, which is what backs the WebAuthn
    /// <c>prf</c> extension. Registration only; on an assertion the output is the encrypted salt values, which
    /// only the client can decrypt.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-extension"/>
    /// </remarks>
    public bool? HmacSecret { get; init; }
}
