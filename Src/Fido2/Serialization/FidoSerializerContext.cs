using System.Text.Json.Serialization;

using Fido2NetLib.Internal;

namespace Fido2NetLib.Serialization;

[JsonSerializable(typeof(AuthenticatorResponse))]
[JsonSerializable(typeof(MDSGetEndpointResponse))]
[JsonSerializable(typeof(GetBLOBRequest))]
public partial class FidoSerializerContext : JsonSerializerContext
{
}
