using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Objects;
using Fido2NetLib.Serialization;

namespace Test;

/// <summary>
/// The models changed for Level 3 must survive the source-generated (AOT) serializer, not only the
/// reflection-based one: prf's tri-state enabled and its evalByCredential record are both new shapes.
/// </summary>
public class L3ModelSerializationTests
{
    // The source-generated context is the AOT path; reflection-based Deserialize<T> is not.
    [Fact]
    public void EvalByCredentialRoundTripsThroughTheSourceGeneratedContext()
    {
        var options = new AssertionOptions
        {
            Challenge = [1, 2, 3],
            RpId = "example.com",
            AllowCredentials = [new PublicKeyCredentialDescriptor([0xf1, 0xd0])],
            Extensions = new AuthenticationExtensionsClientInputs
            {
                PRF = new AuthenticationExtensionsPRFInputs
                {
                    EvalByCredential = new Dictionary<string, AuthenticationExtensionsPRFValues>
                    {
                        ["8dA"] = new AuthenticationExtensionsPRFValues { First = [1, 2], Second = [3, 4] },
                        ["AAAA"] = new AuthenticationExtensionsPRFValues { First = [5, 6] },
                    }
                }
            }
        };

        string json = options.ToJson();
        var back = AssertionOptions.FromJson(json);

        Assert.Equal(2, back.Extensions.PRF.EvalByCredential.Count);
        Assert.Equal([1, 2], back.Extensions.PRF.EvalByCredential["8dA"].First);
        Assert.Equal([3, 4], back.Extensions.PRF.EvalByCredential["8dA"].Second);
        Assert.Equal([5, 6], back.Extensions.PRF.EvalByCredential["AAAA"].First);
        Assert.Null(back.Extensions.PRF.EvalByCredential["AAAA"].Second);
    }

    [Fact]
    public void CredentialCreateOptionsRoundTripsPrfThroughTheSourceGeneratedContext()
    {
        var options = CredentialCreateOptions.Create(
            new Fido2Configuration { RPID = "example.com", RPName = "x", Origins = new HashSet<string> { "https://example.com" } },
            [1, 2, 3],
            new Fido2User { Id = [1], Name = "n", DisplayName = "d" },
            new AuthenticatorSelection(),
            AttestationConveyancePreference.None,
            [],
            new AuthenticationExtensionsClientInputs { PRF = new AuthenticationExtensionsPRFInputs() },
            null, null, null);

        var back = CredentialCreateOptions.FromJson(options.ToJson());

        Assert.NotNull(back.Extensions.PRF);
        Assert.Null(back.Extensions.PRF.Eval);
        Assert.Null(back.Extensions.PRF.EvalByCredential);
    }

    // Enabled must survive as a tri-state through the source-generated path too.
    [Fact]
    public void EnabledTriStateSurvivesTheSourceGeneratedContext()
    {
        string json = """
        {"id":"AAAA","rawId":"AAAA","type":"public-key",
         "clientExtensionResults":{"prf":{"results":{"first":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}},
         "response":{"authenticatorData":"AAAA","signature":"AAAA","clientDataJSON":"AAAA"}}
        """;

        var parsed = JsonSerializer.Deserialize(json, FidoModelSerializerContext.Default.AuthenticatorAssertionRawResponse);

        Assert.Null(parsed.ClientExtensionResults.PRF.Enabled);

        string reserialized = JsonSerializer.Serialize(parsed, FidoModelSerializerContext.Default.AuthenticatorAssertionRawResponse);
        Assert.DoesNotContain("enabled", reserialized, StringComparison.Ordinal);
    }
}
