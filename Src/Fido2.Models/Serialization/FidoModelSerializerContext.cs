using System.Text.Json.Serialization;

namespace Fido2NetLib.Serialization;

[JsonSerializable(typeof(AssertionOptions))]
[JsonSerializable(typeof(AuthenticatorAssertionRawResponse))]
[JsonSerializable(typeof(MetadataBLOBPayload))]
[JsonSerializable(typeof(CredentialCreateOptions))]
[JsonSerializable(typeof(MetadataStatement))]
[JsonSerializable(typeof(AuthenticatorAttestationRawResponse))]
public partial class FidoModelSerializerContext : JsonSerializerContext
{
}
