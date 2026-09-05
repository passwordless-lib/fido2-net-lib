using System.ComponentModel;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Wraps the input for the MakeNewCredential function
/// </summary>
public sealed class MakeNewCredentialParams
{
    /// <summary>
    ///  The attestation response from the authenticator.
    /// </summary>
    public required AuthenticatorAttestationRawResponse AttestationResponse { get; init; }

    /// <summary>
    ///  The original options that was sent to the client.
    /// </summary>
    public required CredentialCreateOptions OriginalOptions { get; init; }

    /// <summary>
    ///  The delegate used to validate that the CredentialID is unique to this user.
    /// </summary>
    public required IsCredentialIdUniqueToUserAsyncDelegate IsCredentialIdUniqueToUserCallback { get; init; }

    /// <summary>
    /// The mediation requirement the Relying Party passed to <c>navigator.credentials.create()</c>. Defaults to
    /// <see cref="CredentialMediationRequirement.Optional"/>.
    /// </summary>
    /// <remarks>
    /// Only <see cref="CredentialMediationRequirement.Conditional"/> changes verification: a conditional create
    /// is allowed to complete without a user presence test, so the UP flag check is skipped. Do not set this
    /// unless the ceremony really was invoked with <c>mediation: "conditional"</c> -- doing otherwise waives a
    /// check the spec requires. See step 14 of
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential"/>.
    /// </remarks>
    public CredentialMediationRequirement Mediation { get; init; } = CredentialMediationRequirement.Optional;

    /// <summary>
    ///  DO NOT USE - Deprecated, but kept in code due to conformance testing tool
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public byte[]? RequestTokenBindingId { get; init; }
}
