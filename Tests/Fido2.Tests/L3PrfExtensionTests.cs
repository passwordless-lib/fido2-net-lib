using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Covers the <c>prf</c> extension as WebAuthn Level 3 §10.1.4 defines it: both inputs optional, salts of
/// any length, <c>evalByCredential</c> a map that is valid only on an assertion carrying a matching
/// <c>allowCredentials</c>, and an <c>enabled</c> output that registration always reports and authentication
/// never does.
/// </summary>
public class L3PrfRegistrationTests : Fido2Tests.Attestation
{
    public L3PrfRegistrationTests()
    {
        _attestationObject = new CborMap { { "fmt", "none" }, { "attStmt", new CborMap() } };
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);
    }

    private static AuthenticationExtensionsPRFValues Salt(int length) =>
        new() { First = RandomNumberGenerator.GetBytes(length) };

    [Fact]
    public async Task AnEmptyPrfInputAsksOnlyWhetherPrfsAreAvailableAsync()
    {
        // "// Example extension inputs: { prf: {} }" -- both members are optional, and an empty input is
        // how a Relying Party asks for nothing but the enabled output.
        var credential = await MakeAttestationResponseAsync(
            new AuthenticationExtensionsClientInputs { PRF = new AuthenticationExtensionsPRFInputs() });

        Assert.Equal(_credentialID, credential.Id);
    }

    [Fact]
    public async Task SaltsOfAnyLengthAreAcceptedAsync()
    {
        // The PRFs "map from BufferSources of any length"; §16.17.1.1's own examples use four bytes.
        var credential = await MakeAttestationResponseAsync(new AuthenticationExtensionsClientInputs
        {
            PRF = new AuthenticationExtensionsPRFInputs { Eval = new AuthenticationExtensionsPRFValues { First = [1, 2, 3, 4] } }
        });

        Assert.Equal(_credentialID, credential.Id);
    }

    [Fact]
    public async Task EvalByCredentialIsRejectedDuringRegistrationAsync()
    {
        // "If evalByCredential is present, return a DOMException whose name is NotSupportedError."
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync(
            new AuthenticationExtensionsClientInputs
            {
                PRF = new AuthenticationExtensionsPRFInputs
                {
                    EvalByCredential = new Dictionary<string, AuthenticationExtensionsPRFValues> { ["AAAA"] = Salt(32) }
                }
            }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("evalByCredential", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResultsAlongsideEnabledFalseAreRejectedAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs
        {
            PRF = new AuthenticationExtensionsPRFOutputs
            {
                Enabled = false,
                Results = new AuthenticationExtensionsPRFValues { First = RandomNumberGenerator.GetBytes(32) }
            }
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync(
            new AuthenticationExtensionsClientInputs { PRF = new AuthenticationExtensionsPRFInputs() }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
    }

    [Fact]
    public async Task ResultsAlongsideEnabledTrueAreAcceptedAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs
        {
            PRF = new AuthenticationExtensionsPRFOutputs
            {
                Enabled = true,
                Results = new AuthenticationExtensionsPRFValues
                {
                    First = RandomNumberGenerator.GetBytes(32),
                    Second = RandomNumberGenerator.GetBytes(32)
                }
            }
        };

        var credential = await MakeAttestationResponseAsync(new AuthenticationExtensionsClientInputs
        {
            PRF = new AuthenticationExtensionsPRFInputs { Eval = Salt(32) }
        });

        Assert.Equal(_credentialID, credential.Id);
    }

    [Fact]
    public async Task AResultThatIsNotThirtyTwoBytesIsRejectedAsync()
    {
        _clientExtensionResults = new AuthenticationExtensionsClientOutputs
        {
            PRF = new AuthenticationExtensionsPRFOutputs
            {
                Enabled = true,
                Results = new AuthenticationExtensionsPRFValues { First = RandomNumberGenerator.GetBytes(64) }
            }
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync(
            new AuthenticationExtensionsClientInputs { PRF = new AuthenticationExtensionsPRFInputs() }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("32 bytes", ex.Message, StringComparison.Ordinal);
    }
}

public class L3PrfAssertionTests
{
    private const string Rp = "https://www.passwordless.dev";
    private static readonly byte[] s_credentialId = [0xf1, 0xd0];

    private static AuthenticationExtensionsPRFValues Salt(int length) =>
        new() { First = RandomNumberGenerator.GetBytes(length) };

    /// <summary>
    /// Runs a complete, correctly signed ES256 assertion so that a failure can only come from the extension
    /// rules under test rather than from anything else in the ceremony.
    /// </summary>
    private static Task<VerifyAssertionResult> AssertAsync(
        AuthenticationExtensionsClientInputs requestedExtensions,
        AuthenticationExtensionsClientOutputs clientExtensionResults = null,
        IReadOnlyList<PublicKeyCredentialDescriptor> allowCredentials = null)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdsa.ExportParameters(false);
        var credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(
            COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, parameters.Q.X, parameters.Q.Y);

        byte[] challenge = RandomNumberGenerator.GetBytes(128);

        byte[] clientDataJson = JsonSerializer.SerializeToUtf8Bytes(new MockClientData
        {
            Type = "webauthn.get",
            Challenge = challenge,
            Origin = Rp
        });

        byte[] authenticatorData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(Rp)),
            AuthenticatorFlags.UP | AuthenticatorFlags.UV,
            1,
            null).ToByteArray();

        byte[] signature = Fido2Tests.SignData(
            COSE.KeyType.EC2,
            COSE.Algorithm.ES256,
            [.. authenticatorData, .. SHA256.HashData(clientDataJson)],
            ecdsa);

        var options = new AssertionOptions
        {
            Challenge = challenge,
            RpId = Rp,
            AllowCredentials = allowCredentials ?? [new PublicKeyCredentialDescriptor(s_credentialId)],
            Extensions = requestedExtensions
        };

        var response = new AuthenticatorAssertionRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "8dA",
            RawId = s_credentialId,
            ClientExtensionResults = clientExtensionResults ?? new AuthenticationExtensionsClientOutputs(),
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = authenticatorData,
                Signature = signature,
                ClientDataJson = clientDataJson,
                UserHandle = [0xf1, 0xd0]
            }
        };

        var lib = new Fido2(new Fido2Configuration
        {
            RPID = Rp,
            RPName = Rp,
            Origins = new HashSet<string> { Rp }
        });

        return lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = options,
            StoredPublicKey = credentialPublicKey.GetBytes(),
            StoredSignatureCounter = 0,
            IsUserHandleOwnerOfCredentialIdCallback = static (args, cancellationToken) => Task.FromResult(true)
        });
    }

    [Fact]
    public async Task ResultsWithoutEnabledAreAcceptedAsync()
    {
        // The regression this whole change exists for. Client extension processing for an assertion
        // initializes the output to an empty dictionary and only ever sets results, so every conforming
        // client returns results with no enabled -- which the registration-only rule used to reject.
        var result = await AssertAsync(
            new AuthenticationExtensionsClientInputs { PRF = new AuthenticationExtensionsPRFInputs { Eval = Salt(32) } },
            new AuthenticationExtensionsClientOutputs
            {
                PRF = new AuthenticationExtensionsPRFOutputs
                {
                    Results = new AuthenticationExtensionsPRFValues { First = RandomNumberGenerator.GetBytes(32) }
                }
            });

        Assert.Equal(s_credentialId, result.CredentialId);
    }

    [Fact]
    public async Task AnEmptyPrfInputIsAcceptedAsync()
    {
        var result = await AssertAsync(
            new AuthenticationExtensionsClientInputs { PRF = new AuthenticationExtensionsPRFInputs() });

        Assert.Equal(s_credentialId, result.CredentialId);
    }

    [Fact]
    public async Task SaltsOfAnyLengthAreAcceptedAsync()
    {
        var result = await AssertAsync(new AuthenticationExtensionsClientInputs
        {
            PRF = new AuthenticationExtensionsPRFInputs { Eval = new AuthenticationExtensionsPRFValues { First = [1, 2, 3, 4] } }
        });

        Assert.Equal(s_credentialId, result.CredentialId);
    }

    [Fact]
    public async Task EvalByCredentialCarriesInputsForEveryAllowedCredentialAsync()
    {
        // evalByCredential is a record, not a single pair: a Relying Party offering several credentials
        // supplies one entry per credential.
        byte[] second = [0xbe, 0xef];

        var result = await AssertAsync(
            new AuthenticationExtensionsClientInputs
            {
                PRF = new AuthenticationExtensionsPRFInputs
                {
                    EvalByCredential = new Dictionary<string, AuthenticationExtensionsPRFValues>
                    {
                        [Base64Url.EncodeToString(s_credentialId)] = Salt(32),
                        [Base64Url.EncodeToString(second)] = Salt(32)
                    }
                }
            },
            allowCredentials: [new PublicKeyCredentialDescriptor(s_credentialId), new PublicKeyCredentialDescriptor(second)]);

        Assert.Equal(s_credentialId, result.CredentialId);
    }

    [Fact]
    public async Task EvalByCredentialRequiresANonEmptyAllowCredentialsAsync()
    {
        // "If evalByCredential is not empty but allowCredentials is empty, return ... NotSupportedError."
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => AssertAsync(
            new AuthenticationExtensionsClientInputs
            {
                PRF = new AuthenticationExtensionsPRFInputs
                {
                    EvalByCredential = new Dictionary<string, AuthenticationExtensionsPRFValues>
                    {
                        [Base64Url.EncodeToString(s_credentialId)] = Salt(32)
                    }
                }
            },
            allowCredentials: []));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("allowCredentials", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EvalByCredentialKeysMustNameAnAllowedCredentialAsync()
    {
        // "... or does not equal the id of some element of allowCredentials after performing base64url
        //  decoding, then return a DOMException whose name is SyntaxError."
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => AssertAsync(
            new AuthenticationExtensionsClientInputs
            {
                PRF = new AuthenticationExtensionsPRFInputs
                {
                    EvalByCredential = new Dictionary<string, AuthenticationExtensionsPRFValues>
                    {
                        [Base64Url.EncodeToString([0x00, 0x01])] = Salt(32)
                    }
                }
            }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("does not match any allowCredentials", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EvalByCredentialKeysMustBeBase64UrlAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => AssertAsync(
            new AuthenticationExtensionsClientInputs
            {
                PRF = new AuthenticationExtensionsPRFInputs
                {
                    EvalByCredential = new Dictionary<string, AuthenticationExtensionsPRFValues> { ["not base64url!"] = Salt(32) }
                }
            }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
        Assert.Contains("base64url", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AResultThatIsNotThirtyTwoBytesIsRejectedAsync()
    {
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => AssertAsync(
            new AuthenticationExtensionsClientInputs { PRF = new AuthenticationExtensionsPRFInputs { Eval = Salt(32) } },
            new AuthenticationExtensionsClientOutputs
            {
                PRF = new AuthenticationExtensionsPRFOutputs
                {
                    Results = new AuthenticationExtensionsPRFValues { First = RandomNumberGenerator.GetBytes(16) }
                }
            }));

        Assert.Equal(Fido2ErrorCode.MalformedExtensionsDetected, ex.Code);
    }
}

public class L3PrfSerializationTests
{
    [Fact]
    public void EvalByCredentialSerializesAsAJsonRecord()
    {
        // A KeyValuePair would have serialized as {"Key":...,"Value":...}, which is not what
        // record<DOMString, AuthenticationExtensionsPRFValues> means on the wire.
        var options = new AssertionOptions
        {
            Challenge = [1, 2, 3],
            Extensions = new AuthenticationExtensionsClientInputs
            {
                PRF = new AuthenticationExtensionsPRFInputs
                {
                    EvalByCredential = new Dictionary<string, AuthenticationExtensionsPRFValues>
                    {
                        ["AAAA"] = new AuthenticationExtensionsPRFValues { First = [0xf1, 0xd0] }
                    }
                }
            }
        };

        var json = options.ToJson();

        Assert.Contains("""evalByCredential":{"AAAA":{"first":""", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"Key\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAbsentEnabledDeserializesAsNullRatherThanFalse()
    {
        var outputs = JsonSerializer.Deserialize<AuthenticationExtensionsClientOutputs>(
            """{"prf":{"results":{"first":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}}""");

        Assert.Null(outputs.PRF.Enabled);
        Assert.NotNull(outputs.PRF.Results);
    }

    [Fact]
    public void AReportedEnabledStillRoundTrips()
    {
        var outputs = JsonSerializer.Deserialize<AuthenticationExtensionsClientOutputs>("""{"prf":{"enabled":false}}""");

        Assert.False(outputs.PRF.Enabled);
        Assert.Contains("""prf":{"enabled":false}""", JsonSerializer.Serialize(outputs), StringComparison.Ordinal);
    }
}
