using System;
using System.Collections.Generic;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
///  The input arguments for generating AssertionOptions
/// </summary>
public sealed class GetAssertionOptionsParams
{
    /// <summary>
    ///  This OPTIONAL member is used by the client to find authenticators eligible for this authentication ceremony. It can be used in two ways:
    /// 
    /// * If the user account to authenticate is already identified (e.g., if the user has entered a username), then the Relying Party SHOULD use this member to list credential descriptors for credential records in the user account. This SHOULD usually include all credential records in the user account.
    /// The items SHOULD specify transports whenever possible. This helps the client optimize the user experience for any given situation. Also note that the Relying Party does not need to filter the list when requesting user verification — the client will automatically ignore non-eligible credentials if userVerification is set to required.
    /// See also the § 14.6.3 Privacy leak via credential IDs privacy consideration.
    ///  * If the user account to authenticate is not already identified, then the Relying Party MAY leave this member empty or unspecified. In this case, only discoverable credentials will be utilized in this authentication ceremony, and the user account MAY be identified by the userHandle of the resulting AuthenticatorAssertionResponse. If the available authenticators contain more than one discoverable credential scoped to the Relying Party, the credentials are displayed by the client platform or authenticator for the user to select from (see step 7 of § 6.3.3 The authenticatorGetAssertion Operation).
    ///
    /// If not empty, the client MUST return an error if none of the listed credentials can be used.
    ///
    /// The list is ordered in descending order of preference: the first item in the list is the most preferred credential, and the last is the least preferred.
    /// </summary>
    public IReadOnlyList<PublicKeyCredentialDescriptor> AllowedCredentials { get; init; } = Array.Empty<PublicKeyCredentialDescriptor>();

    /// <summary>
    /// This OPTIONAL member specifies the Relying Party's requirements regarding user verification for the get() operation. The value SHOULD be a member of UserVerificationRequirement but client platforms MUST ignore unknown values, treating an unknown value as if the member does not exist. Eligible authenticators are filtered to only those capable of satisfying this requirement.
    /// </summary>
    public UserVerificationRequirement? UserVerification { get; init; }

    /// <summary>
    /// The Relying Party MAY use this OPTIONAL member to provide client extension inputs requesting additional processing by the client and authenticator.
    /// </summary>
    public AuthenticationExtensionsClientInputs? Extensions { get; init; }
}
