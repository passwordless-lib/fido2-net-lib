using System.Text.Json;

using Fido2NetLib;

using Xunit;

namespace Fido2NetLib.Models.Tests;

/// <summary>
/// Serialization contract tests for the <see cref="MetadataStatement"/> fields introduced in
/// FIDO Metadata Statement v3.1.1.
/// </summary>
public class MetadataStatementSerializationTests
{
    [Fact]
    public void Deserializes_V311_Fields_Using_Spec_Wire_Names()
    {
        const string json = """
        {
            "description": "Example Authenticator",
            "authenticatorVersion": 2,
            "protocolFamily": "fido2",
            "schema": 3,
            "upv": [ { "major": 1, "minor": 0 } ],
            "authenticationAlgorithms": [ "secp256r1_ecdsa_sha256_raw" ],
            "publicKeyAlgAndEncodings": [ "ecc_x962_raw" ],
            "attestationTypes": [ "basic_full" ],
            "keyProtection": [ "hardware" ],
            "matcherProtection": [ "on_chip" ],
            "tcDisplay": [],
            "attestationRootCertificates": [ "..." ],
            "iconDark": "data:image/png;base64,ZGFyaw==",
            "providerLogoLight": "data:image/png;base64,bGlnaHQ=",
            "providerLogoDark": "data:image/png;base64,ZGFya0xvZ28=",
            "multiDeviceCredentialSupport": "supported",
            "cxConfigURL": "https://example.com/cx-config.json"
        }
        """;

        var statement = JsonSerializer.Deserialize<MetadataStatement>(json);

        Assert.NotNull(statement);
        Assert.Equal("data:image/png;base64,ZGFyaw==", statement!.IconDark);
        Assert.Equal("data:image/png;base64,bGlnaHQ=", statement.ProviderLogoLight);
        Assert.Equal("data:image/png;base64,ZGFya0xvZ28=", statement.ProviderLogoDark);
        Assert.Equal("supported", statement.MultiDeviceCredentialSupport);
        Assert.Equal("https://example.com/cx-config.json", statement.CxConfigURL);
    }

    [Fact]
    public void Serializes_V311_Fields_Using_Spec_Wire_Names()
    {
        var statement = new MetadataStatement
        {
            Description = "Example Authenticator",
            IconDark = "data:image/png;base64,ZGFyaw==",
            ProviderLogoLight = "data:image/png;base64,bGlnaHQ=",
            ProviderLogoDark = "data:image/png;base64,ZGFya0xvZ28=",
            MultiDeviceCredentialSupport = "supported",
            CxConfigURL = "https://example.com/cx-config.json"
        };

        string json = JsonSerializer.Serialize(statement);

        Assert.Contains("\"iconDark\":\"data:image/png;base64,ZGFyaw==\"", json);
        Assert.Contains("\"providerLogoLight\":\"data:image/png;base64,bGlnaHQ=\"", json);
        Assert.Contains("\"providerLogoDark\":\"data:image/png;base64,ZGFya0xvZ28=\"", json);
        Assert.Contains("\"multiDeviceCredentialSupport\":\"supported\"", json);
        Assert.Contains("\"cxConfigURL\":\"https://example.com/cx-config.json\"", json);
    }

    /// <summary>
    /// A metadata statement produced against a newer revision of the spec must still deserialize;
    /// members this library does not model are ignored rather than treated as an error.
    /// </summary>
    [Fact]
    public void Tolerates_Unknown_Members_From_Newer_Spec_Revisions()
    {
        const string json = """
        {
            "description": "Example Authenticator",
            "iconDark": "data:image/png;base64,ZGFyaw==",
            "someMemberFromAFutureRevision": { "nested": [ 1, 2, 3 ] },
            "anotherUnknownMember": "ignored"
        }
        """;

        var statement = JsonSerializer.Deserialize<MetadataStatement>(json);

        Assert.NotNull(statement);
        Assert.Equal("Example Authenticator", statement!.Description);
        Assert.Equal("data:image/png;base64,ZGFyaw==", statement.IconDark);
    }

    /// <summary>
    /// A v3.0 statement omitting every v3.1.1 field must still deserialize, leaving the new
    /// members unset rather than failing.
    /// </summary>
    [Fact]
    public void Deserializes_Statement_Without_Any_V311_Fields()
    {
        const string json = """
        {
            "description": "Legacy Authenticator",
            "authenticatorVersion": 1,
            "protocolFamily": "u2f",
            "schema": 3
        }
        """;

        var statement = JsonSerializer.Deserialize<MetadataStatement>(json);

        Assert.NotNull(statement);
        Assert.Equal("Legacy Authenticator", statement!.Description);
        Assert.Null(statement.IconDark);
        Assert.Null(statement.ProviderLogoLight);
        Assert.Null(statement.ProviderLogoDark);
        Assert.Null(statement.MultiDeviceCredentialSupport);
        Assert.Null(statement.CxConfigURL);
    }
}
