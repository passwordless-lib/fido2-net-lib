using System.Text.Json;
using System.Text.Json.Serialization;

using Fido2NetLib.Objects;
using Fido2NetLib.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Sent to the browser when we want to Assert credentials and authenticate a user
/// </summary>
public class AssertionOptions : Fido2ResponseBase
{
    /// <summary>
    /// This member represents a challenge that the selected authenticator signs, along with other data, when producing an authentication assertion.
    /// See the §13.1 Cryptographic Challenges security consideration.
    /// </summary>
    [JsonPropertyName("challenge")]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] Challenge { get; set; }

#nullable enable

    /// <summary>
    /// This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
    /// This is treated as a hint, and MAY be overridden by the client.
    /// </summary>
    [JsonPropertyName("timeout")]
    public ulong Timeout { get; set; }

    /// <summary>
    /// This OPTIONAL member specifies the relying party identifier claimed by the caller.
    /// If omitted, its value will be the CredentialsContainer object’s relevant settings object's origin's effective domain
    /// </summary>
    [JsonPropertyName("rpId")]
    public string? RpId { get; set; }

    /// <summary>
    /// This OPTIONAL member contains a list of PublicKeyCredentialDescriptor objects representing public key credentials acceptable to the caller, in descending order of the caller’s preference(the first item in the list is the most preferred credential, and so on down the list)
    /// </summary>
    [JsonPropertyName("allowCredentials")]
    public IReadOnlyList<PublicKeyCredentialDescriptor> AllowCredentials { get; set; } = Array.Empty<PublicKeyCredentialDescriptor>();

    /// <summary>
    /// This member describes the Relying Party's requirements regarding user verification for the get() operation.
    /// Eligible authenticators are filtered to only those capable of satisfying this requirement
    /// </summary>
    [JsonPropertyName("userVerification")]
    public UserVerificationRequirement? UserVerification { get; set; }

    /// <summary>
    /// This OPTIONAL member contains zero or more elements from <see cref="PublicKeyCredentialHint"/> to guide the user agent in interacting with the user. Note that the elements have type DOMString despite being taken from that enumeration.
    /// </summary>
    [JsonPropertyName("hints")]
    public IReadOnlyList<PublicKeyCredentialHint> Hints { get; set; } = Array.Empty<PublicKeyCredentialHint>();

    /// <summary>
    /// This OPTIONAL member contains additional parameters requesting additional processing by the client and authenticator.
    /// For example, if transaction confirmation is sought from the user, then the prompt string might be included as an extension.
    /// </summary>
    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsClientInputs? Extensions { get; set; }

    public static AssertionOptions Create(
        Fido2Configuration config,
        byte[] challenge,
        IReadOnlyList<PublicKeyCredentialDescriptor> allowedCredentials,
        UserVerificationRequirement? userVerification,
        AuthenticationExtensionsClientInputs? extensions)
    {
        return new AssertionOptions()
        {
            Status = "ok",
            ErrorMessage = string.Empty,
            Challenge = challenge,
            Timeout = config.Timeout,
            RpId = config.ServerDomain,
            AllowCredentials = allowedCredentials,
            UserVerification = userVerification,
            Extensions = extensions
        };
    }

    public string ToJson()
    {
        return JsonSerializer.Serialize(this, FidoModelSerializerContext.Default.AssertionOptions);
    }

    public static AssertionOptions FromJson(string json)
    {
        return JsonSerializer.Deserialize(json, FidoModelSerializerContext.Default.AssertionOptions)!;
    }
}
