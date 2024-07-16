using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Base class for responses sent by the Authenticator Client
/// </summary>
public class AuthenticatorResponse
{
    [JsonConstructor]
    public AuthenticatorResponse(string type, byte[] challenge, string origin) // for deserialization
    {
        Type = type;
        Challenge = challenge;
        Origin = origin;
    }

    protected AuthenticatorResponse(ReadOnlySpan<byte> utf8EncodedJson)
    {
        if (utf8EncodedJson.Length is 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAuthenticatorResponse, "utf8EncodedJson may not be empty");

        // 1. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON

        // 2. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext
        // Note: C may be any implementation-specific data structure representation, as long as C’s components are referenceable, as required by this algorithm.
        // We call this AuthenticatorResponse
        AuthenticatorResponse? response;
        try
        {
            response = JsonSerializer.Deserialize(utf8EncodedJson, FidoSerializerContext.Default.AuthenticatorResponse);
        }
        catch (Exception e) when (e is JsonException)
        {
            throw new Fido2VerificationException(Fido2ErrorCode.MalformedAuthenticatorResponse, "Malformed clientDataJson");
        }

        if (response is null)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAuthenticatorResponse, "Deserialized authenticator response cannot be null");

        Type = response.Type;
        Challenge = response.Challenge;
        Origin = response.Origin;
        TokenBinding = response.TokenBinding;
    }

    public const int MAX_ORIGINS_TO_PRINT = 5;

    [JsonPropertyName("type")]
    public string Type { get; }

    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("challenge")]
    public byte[] Challenge { get; }

    [JsonPropertyName("origin")]
    public string Origin { get; }

    // [Obsolete("This property is not used and will be removed in a future version once the conformance tool stops testing for it.")]
    [JsonPropertyName("tokenBinding")]
    public TokenBindingDto? TokenBinding { get; set; }

    protected void BaseVerify(IReadOnlySet<string> fullyQualifiedExpectedOrigins, ReadOnlySpan<byte> originalChallenge, byte[]? requestTokenBindingId)
    {
        if (Type is not "webauthn.create" && Type is not "webauthn.get")
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAuthenticatorResponse, $"Type must be 'webauthn.create' or 'webauthn.get'. Was '{Type}'");

        if (Challenge is null)
            throw new Fido2VerificationException(Fido2ErrorCode.MissingAuthenticatorResponseChallenge, Fido2ErrorMessages.MissingAuthenticatorResponseChallenge);

        // 11. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call
        if (!Challenge.AsSpan().SequenceEqual(originalChallenge))
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAuthenticatorResponseChallenge, Fido2ErrorMessages.InvalidAuthenticatorResponseChallenge);

        var fullyQualifiedOrigin = Origin.ToFullyQualifiedOrigin();

        // 12. Verify that the value of C.origin matches the Relying Party's origin.
        if (!fullyQualifiedExpectedOrigins.Contains(fullyQualifiedOrigin))
            throw new Fido2VerificationException($"Fully qualified origin {fullyQualifiedOrigin} of {Origin} not equal to fully qualified original origin {string.Join(", ", fullyQualifiedExpectedOrigins.Take(MAX_ORIGINS_TO_PRINT))} ({fullyQualifiedExpectedOrigins.Count})");

        // 13?. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained. 
        // If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        TokenBinding?.Verify(requestTokenBindingId);
    }

    /*
    private static string FullyQualifiedOrigin(string origin)
    {
        var uri = new Uri(origin);

        if (UriHostNameType.Unknown != uri.HostNameType)
            return uri.IsDefaultPort ? $"{uri.Scheme}://{uri.Host}" : $"{uri.Scheme}://{uri.Host}:{uri.Port}";

        return origin;
    }
    */
}
