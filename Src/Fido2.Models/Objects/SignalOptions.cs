using System.Text.Json;
using System.Text.Json.Serialization;

using Fido2NetLib.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// The argument to <c>PublicKeyCredential.signalUnknownCredential()</c>, which tells the authenticator that a
/// credential it offered is not recognized by this Relying Party so it can be removed or hidden.
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-signalUnknownCredential"/>
/// </summary>
/// <remarks>
/// Signal methods are invoked in the browser; a Relying Party server's part is to produce this payload and hand
/// it to its front-end. They are best-effort and report no result: a resolved promise means only that the
/// options object was well formed.
/// </remarks>
public sealed class UnknownCredentialOptions
{
    /// <summary>The RP ID the credential is scoped to.</summary>
    [JsonPropertyName("rpId")]
    public required string RpId { get; init; }

    /// <summary>The credential ID that this Relying Party does not recognize.</summary>
    [JsonPropertyName("credentialId")]
    [JsonConverter(typeof(Base64UrlConverter))]
    public required byte[] CredentialId { get; init; }

    public string ToJson() => JsonSerializer.Serialize(this, FidoModelSerializerContext.Default.UnknownCredentialOptions);
}

/// <summary>
/// The argument to <c>PublicKeyCredential.signalAllAcceptedCredentials()</c>, which gives the authenticator the
/// complete set of credential IDs this Relying Party still accepts for a user, so it can remove or hide the rest.
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-signalAllAcceptedCredentials"/>
/// </summary>
/// <remarks>
/// <para>
/// The list must be exhaustive for <see cref="AllAcceptedCredentialsOptions.UserId"/>. An authenticator may delete credentials missing
/// from it, so sending a partial list can destroy credentials the user still needs. Only send this when the
/// Relying Party can enumerate every credential registered to the user.
/// </para>
/// <para>
/// Signal methods are invoked in the browser; a Relying Party server's part is to produce this payload and hand
/// it to its front-end.
/// </para>
/// </remarks>
public sealed class AllAcceptedCredentialsOptions
{
    /// <summary>The RP ID the credentials are scoped to.</summary>
    [JsonPropertyName("rpId")]
    public required string RpId { get; init; }

    /// <summary>The user handle whose credentials are being enumerated.</summary>
    [JsonPropertyName("userId")]
    [JsonConverter(typeof(Base64UrlConverter))]
    public required byte[] UserId { get; init; }

    /// <summary>Every credential ID this Relying Party still accepts for the user.</summary>
    [JsonPropertyName("allAcceptedCredentialIds")]
    [JsonConverter(typeof(Base64UrlListConverter))]
    public required IReadOnlyList<byte[]> AllAcceptedCredentialIds { get; init; }

    public string ToJson() => JsonSerializer.Serialize(this, FidoModelSerializerContext.Default.AllAcceptedCredentialsOptions);
}

/// <summary>
/// The argument to <c>PublicKeyCredential.signalCurrentUserDetails()</c>, which lets the authenticator refresh
/// the name and display name it shows for a user's credentials.
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-signalCurrentUserDetails"/>
/// </summary>
/// <remarks>
/// Signal methods are invoked in the browser; a Relying Party server's part is to produce this payload and hand
/// it to its front-end.
/// </remarks>
public sealed class CurrentUserDetailsOptions
{
    /// <summary>The RP ID the credentials are scoped to.</summary>
    [JsonPropertyName("rpId")]
    public required string RpId { get; init; }

    /// <summary>The user handle whose details are being updated.</summary>
    [JsonPropertyName("userId")]
    [JsonConverter(typeof(Base64UrlConverter))]
    public required byte[] UserId { get; init; }

    /// <summary>The user's current account name, e.g. an email address or username.</summary>
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    /// <summary>The user's current display name.</summary>
    [JsonPropertyName("displayName")]
    public required string DisplayName { get; init; }

    public string ToJson() => JsonSerializer.Serialize(this, FidoModelSerializerContext.Default.CurrentUserDetailsOptions);
}
