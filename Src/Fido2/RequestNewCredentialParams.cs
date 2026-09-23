using System;
using System.Collections.Generic;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
///  The input arguments for generating CredentialCreateOptions
/// </summary>
public sealed class RequestNewCredentialParams
{
    /// <summary>
    ///  This member contains names and an identifier for the user account performing the registration. Its value’s name, displayName and id members are REQUIRED. id can be returned as the userHandle in some future authentication ceremonies, and is used to overwrite existing discoverable credentials that have the same rp.id and user.id on the same authenticator. name and displayName MAY be used by the authenticator and client in future authentication ceremonies to help the user select a credential, but are not returned to the Relying Party as a result of future authentication ceremonies
    /// </summary>
    public required Fido2User User { get; init; }

    /// <summary>
    ///  The Relying Party SHOULD use this OPTIONAL member to list any existing credentials mapped to this user account (as identified by user.id). This ensures that the new credential is not created on an authenticator that already contains a credential mapped to this user account. If it would be, the client is requested to instead guide the user to use a different authenticator, or return an error if that fails.
    /// </summary>
    public IReadOnlyList<PublicKeyCredentialDescriptor> ExcludeCredentials { get; init; } = [];

    /// <summary>
    /// The Relying Party MAY use this OPTIONAL member to specify capabilities and settings that the authenticator MUST or SHOULD satisfy to participate in the create() operation. See § 5.4.4 Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria).
    /// </summary>
    public AuthenticatorSelection AuthenticatorSelection { get; init; } = AuthenticatorSelection.Default;

    /// <summary>
    /// The Relying Party MAY use this OPTIONAL member to specify a preference regarding attestation conveyance. Its value SHOULD be a member of AttestationConveyancePreference. Client platforms MUST ignore unknown values, treating an unknown value as if the member does not exist.
    /// </summary>
    public AttestationConveyancePreference AttestationPreference { get; init; } = AttestationConveyancePreference.None;

    /// <summary>
    /// The Relying Party MAY use this OPTIONAL member to provide client extension inputs requesting additional processing by the client and authenticator. For example, the Relying Party may request that the client returns additional information about the credential that was created.
    /// </summary>
    public AuthenticationExtensionsClientInputs? Extensions { get; init; }

    /// <summary>
    /// For advanced use cases. This member lists the key types and signature algorithms the Relying Party supports, ordered from most preferred to least preferred. The client and authenticator make a best-effort to create a credential of the most preferred type possible. If none of the listed types can be created, the create() operation fails.
    /// </summary>
    public IReadOnlyList<PubKeyCredParam> PubKeyCredParams { get; init; } = PubKeyCredParam.Defaults;

    /// <summary>
    /// Zero or more hints, in descending order of preference, guiding the user agent in how it presents this
    /// registration to the user. Hints are not requirements and do not bind the user agent.
    /// <see href="https://www.w3.org/TR/webauthn-3/#enum-hints"/>
    /// </summary>
    /// <remarks>
    /// Setting this also derives <see cref="AuthenticatorSelection"/>'s attachment from the first hint; see
    /// <see cref="CredentialCreateOptions.Hints"/>.
    /// </remarks>
    public IReadOnlyList<PublicKeyCredentialHint> Hints { get; init; } = [];

    /// <summary>
    /// The attestation statement formats the Relying Party prefers, in descending order of preference. This is
    /// advisory: the authenticator MAY use a format not listed here.
    /// <see href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-attestationformats"/>
    /// </summary>
    public IReadOnlyList<AttestationStatementFormatIdentifier> AttestationFormats { get; init; } = [];
}
