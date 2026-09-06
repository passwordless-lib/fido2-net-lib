#nullable disable

namespace Fido2NetLib.Objects;

/// <summary>
/// Result of the MakeAssertion verification
/// </summary>
public class VerifyAssertionResult
{
    public byte[] CredentialId { get; init; }

    /// <summary>
    /// The latest value of the signature counter in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public uint SignCount { get; init; }

    /// <summary>
    /// The latest value of the BS flag in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public bool IsBackedUp { get; init; }

    /// <summary>
    /// The value of the UV flag in the authenticator data for this assertion.
    /// If the stored credential record's <c>uvInitialized</c> is <see langword="false"/>, the Relying Party
    /// should update it to this value. That change SHOULD require authorization by an additional authentication
    /// factor equivalent to WebAuthn user verification; if not authorized, the update should be skipped.
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion"/>
    /// </summary>
    public bool IsUserVerified { get; init; }

    /// <summary>
    /// The authenticator extension outputs from the extensions block of the authenticator data, decoded into
    /// the outputs CTAP defines. Never <see langword="null"/>; its members are <see langword="null"/> when the
    /// authenticator returned no such output.
    /// </summary>
    public AuthenticationExtensionsAuthenticatorOutputs AuthenticatorExtensionResults { get; init; } = new();
}
