using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Objects;
using Fido2NetLib.Serialization;

namespace Test;

/// <summary>
/// Both raw ceremony responses arrive as JSON from the browser, so both must be reachable through the
/// source-generated (AOT-safe) serializer, not only the assertion one.
/// </summary>
public class L3AotSerializationTests
{
    [Fact]
    public void TheAttestationRawResponseIsReachableThroughTheSourceGeneratedContext()
    {
        string json = """
        {"id":"AAAA","rawId":"AAAA","type":"public-key","authenticatorAttachment":"platform",
         "clientExtensionResults":{"credProps":{"rk":true}},
         "response":{"attestationObject":"AAAA","clientDataJSON":"AAAA","transports":["internal","hybrid"],
                     "publicKeyAlgorithm":-7}}
        """;

        var parsed = JsonSerializer.Deserialize(json, FidoModelSerializerContext.Default.AuthenticatorAttestationRawResponse);

        Assert.Equal(PublicKeyCredentialType.PublicKey, parsed.Type);
        Assert.Equal(AuthenticatorAttachment.Platform, parsed.AuthenticatorAttachment);
        Assert.Equal([AuthenticatorTransport.Internal, AuthenticatorTransport.Hybrid], parsed.Response.Transports);
        Assert.Equal(COSE.Algorithm.ES256, parsed.Response.PublicKeyAlgorithm);
        Assert.True(parsed.ClientExtensionResults.CredProps.Rk);

        Assert.Contains("\"rawId\"", JsonSerializer.Serialize(parsed, FidoModelSerializerContext.Default.AuthenticatorAttestationRawResponse), StringComparison.Ordinal);
    }
}
