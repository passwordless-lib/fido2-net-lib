using System.Text.Json.Serialization;

namespace Fido2NetLib.Serialization;

[JsonSerializable(typeof(AssertionOptions))]
[JsonSerializable(typeof(AuthenticatorAssertionRawResponse))]
[JsonSerializable(typeof(AuthenticatorAttestationRawResponse))]
[JsonSerializable(typeof(MetadataBLOBPayload))]
[JsonSerializable(typeof(CredentialCreateOptions))]
[JsonSerializable(typeof(MetadataStatement))]
[JsonSerializable(typeof(WellKnownWebAuthn))]
[JsonSerializable(typeof(Objects.UnknownCredentialOptions))]
[JsonSerializable(typeof(Objects.AllAcceptedCredentialsOptions))]
[JsonSerializable(typeof(Objects.CurrentUserDetailsOptions))]
public partial class FidoModelSerializerContext : JsonSerializerContext
{
}
