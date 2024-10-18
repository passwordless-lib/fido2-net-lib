namespace Fido2.BlazorWebAssembly;

using System.Text.Json.Serialization;

using Fido2NetLib;

[JsonSerializable(typeof(AssertionOptions))]
[JsonSerializable(typeof(AuthenticatorAssertionRawResponse))]
[JsonSerializable(typeof(AuthenticatorAttestationRawResponse))]
[JsonSerializable(typeof(CredentialCreateOptions))]
public partial class FidoBlazorSerializerContext : JsonSerializerContext
{
}
