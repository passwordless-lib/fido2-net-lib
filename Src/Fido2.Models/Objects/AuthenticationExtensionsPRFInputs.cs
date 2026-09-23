#nullable disable

using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// This is a dictionary containing the PRF extension input values
/// </summary>
public sealed class AuthenticationExtensionsPRFInputs
{
    /// <summary>
    /// Inputs on which to evaluate PRF. Both members are optional: an empty <c>prf</c> input asks only
    /// whether PRFs are available for the credential, which the client answers in
    /// <see cref="AuthenticationExtensionsPRFOutputs.Enabled"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfinputs-eval"/>
    /// </remarks>
    [JsonPropertyName("eval")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsPRFValues Eval { get; set; }

    /// <summary>
    /// A record mapping base64url encoded credential IDs to PRF inputs to evaluate for that credential.
    /// Applicable only to assertions, and only when <c>allowCredentials</c> is not empty.
    /// </summary>
    /// <remarks>
    /// Every key must be the base64url encoding of the id of some member of <c>allowCredentials</c>; a
    /// client fails the ceremony otherwise. The client evaluates the entry matching whichever credential
    /// ends up being used, falling back to <see cref="Eval"/> when no entry matches.
    /// <para>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfinputs-evalbycredential"/>
    /// </para>
    /// </remarks>
    [JsonPropertyName("evalByCredential")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, AuthenticationExtensionsPRFValues> EvalByCredential { get; set; }
}
