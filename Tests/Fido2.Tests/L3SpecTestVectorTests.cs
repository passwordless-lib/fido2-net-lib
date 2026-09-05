using System.Text.Json;
using System.Text.Json.Serialization;

using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Drives the literal test vectors published in WebAuthn L3 §16 through the real verification pipeline.
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-test-vectors"/>
/// </summary>
/// <remarks>
/// <para>
/// Every other attestation test in this suite signs its own fixtures with keys generated in-process, which
/// checks the library against its own idea of what an authenticator produces. These vectors are authored by the
/// working group and are byte-exact -- clientDataJSON, attestationObject, authenticatorData and signature all
/// come from the specification -- so they check the library against something other than itself.
/// </para>
/// <para>
/// The specification addresses them to Relying Party implementers directly: "Relying Party implementers may
/// check that they can successfully validate the registration outputs given the same challenge input, and that
/// they can successfully validate the authentication outputs given the same challenge input and the credential
/// public key and credential ID from the associated registration example." That is the shape of
/// <see cref="RegisterThenAuthenticateAsync"/>: each vector's registration output feeds its authentication.
/// </para>
/// <para>
/// All vectors use the RP ID <c>example.org</c>, the origin <c>https://example.org</c> and, where applicable,
/// the topOrigin <c>https://example.com</c>. The data lives in <c>TestFiles/L3SpecTestVectors.json</c>,
/// extracted verbatim from the specification.
/// </para>
/// </remarks>
public class L3SpecTestVectorTests
{
    private const string RpId = "example.org";
    private const string Origin = "https://example.org";
    /// <summary>
    /// Vectors the library does not verify today, each for a reason recorded in its own test below. They are
    /// excluded from <see cref="SupportedVectors"/> rather than deleted, so the count check keeps them visible.
    /// </summary>
    private static readonly string[] s_divergentSections = ["16.12", "16.13", "16.15", "16.16"];

    private static readonly IReadOnlyList<SpecVector> s_vectors =
        JsonSerializer.Deserialize<List<SpecVector>>(File.ReadAllBytes("./L3SpecTestVectors.json"))!;

    private static SpecVector Vector(string section) => s_vectors.Single(v => v.Section == section);

    /// <summary>Every vector the library is expected to verify end to end.</summary>
    public static TheoryData<string> SupportedVectors()
    {
        var data = new TheoryData<string>();

        foreach (var vector in s_vectors.Where(v => !s_divergentSections.Contains(v.Section)))
            data.Add(vector.Section);

        return data;
    }

    [Theory]
    [MemberData(nameof(SupportedVectors))]
    public async Task RegisterThenAuthenticateAsync(string section)
    {
        var vector = Vector(section);
        var lib = MakeLib(vector);

        var credential = await lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = MakeAttestationResponse(vector),
            OriginalOptions = MakeCreateOptions(vector),
            IsCredentialIdUniqueToUserCallback = static (args, cancellationToken) => Task.FromResult(true),
        });

        Assert.Equal(vector.Format, credential.AttestationFormat);
        Assert.Equal(Convert.FromHexString(vector.CredentialId), credential.Id);
        Assert.Equal(new Guid(Convert.FromHexString(vector.Aaguid), bigEndian: true), credential.AaGuid);

        // The registration output is what the authentication is verified against, exactly as a Relying Party
        // would do it: the stored public key, signature counter and backup eligibility all come from above.
        var assertion = await lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = MakeAssertionResponse(vector),
            OriginalOptions = MakeAssertionOptions(vector, credential),
            StoredPublicKey = credential.PublicKey,
            StoredSignatureCounter = credential.SignCount,
            StoredBackupEligible = credential.IsBackupEligible,
            IsUserHandleOwnerOfCredentialIdCallback = static (args, cancellationToken) => Task.FromResult(true),
        });

        Assert.Equal(credential.Id, assertion.CredentialId);
    }

    [Fact]
    public async Task Sctn_16_6_AcceptsACredentialIdAtTheMaximumLengthAsync()
    {
        // 1023 bytes is the largest credential ID a Relying Party may accept (§7.1 step 25).
        var vector = Vector("16.6");

        Assert.Equal(1023, Convert.FromHexString(vector.CredentialId).Length);

        var credential = await RegisterAsync(vector);

        Assert.Equal(1023, credential.Id.Length);
    }

    private Task<RegisteredPublicKeyCredential> RegisterAsync(SpecVector vector) =>
        MakeLib(vector).MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = MakeAttestationResponse(vector),
            OriginalOptions = MakeCreateOptions(vector),
            IsCredentialIdUniqueToUserCallback = static (args, cancellationToken) => Task.FromResult(true),
        });

    // --- Vectors the library does not verify -----------------------------------------------------------
    //
    // Each of these pins the library's current behaviour against a vector the working group published, so the
    // divergence is visible in the suite rather than hidden by omission. Three of the four are library
    // limitations rather than problems with the vectors.

    [Fact]
    public async Task Sctn_16_12_Ed448UsesAnUnmodelledCoseAlgorithmAsync()
    {
        // This vector's credential public key declares COSE algorithm -53, which IANA registers as the
        // fully-specified Ed448 (the Ed25519 vector in §16.11 still uses the generic EdDSA, -8). The library
        // models neither -53 nor the other fully-specified identifiers -9, -19, -51 and -52, and an
        // unrecognized algorithm escapes as InvalidOperationException rather than a Fido2VerificationException.
        //
        // Ed448 would additionally need signature support that NSec.Cryptography does not provide.
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => RegisterAsync(Vector("16.12")));

        Assert.Contains("-53", ex.Message);
    }

    [Fact]
    public async Task Sctn_16_13_TpmVectorUsesAPlaceholderManufacturerAsync()
    {
        // The vector's TPM manufacturer is "id:000000000", which is not a TCG-assigned vendor. The library
        // checks the manufacturer against the real vendor list, so this vector cannot pass -- and should not:
        // the check is doing its job. Recorded here so the gap is not mistaken for missing TPM support.
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => RegisterAsync(Vector("16.13")));

        Assert.Equal("Invalid TPM manufacturer found parsing TPM attestation", ex.Message);
    }

    [Fact]
    public async Task Sctn_16_15_AppleVectorCarriesASingleCertificateAsync()
    {
        // §8.8 defines the statement as x5c: [ credCert: bytes, * (caCert: bytes) ] -- zero or more CA
        // certificates follow credCert, so this vector's single-element x5c is well formed. The library
        // requires at least two elements, which is stricter than the specification.
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => RegisterAsync(Vector("16.15")));

        Assert.Equal(Fido2ErrorMessages.MalformedX5c_AppleAttestation, ex.Message);
    }

    [Fact]
    public async Task Sctn_16_16_FidoU2fVectorHasANonZeroAaguidAsync()
    {
        // The library requires a zeroed AAGUID for fido-u2f, with a comment noting the rule came from FIDO
        // conformance testing and could not be found in the specification. It is indeed absent from §8.6's
        // verification procedure, and this vector carries a non-zero AAGUID, so the check rejects a vector the
        // working group published. Relaxing it may affect FIDO conformance, so the behaviour stands for now.
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => RegisterAsync(Vector("16.16")));

        Assert.Equal("Aaguid was not empty parsing fido-u2f attestation statement", ex.Message);
    }

    [Fact]
    public void EveryPublishedVectorIsAccountedFor()
    {
        // §16 ships 15 registration/authentication pairs. If a future revision adds more, this fails rather
        // than letting a new vector go silently uncovered.
        Assert.Equal(15, s_vectors.Count);
        Assert.Equal(15 - s_divergentSections.Length, SupportedVectors().Count);
        Assert.All(s_divergentSections, section => Assert.NotNull(Vector(section)));

        Assert.Equal(
            ["android-key", "apple", "fido-u2f", "none", "packed", "tpm"],
            s_vectors.Select(v => v.Format).Distinct().Order());
    }

    // --- Fixture construction -------------------------------------------------------------------------

    private static Fido2 MakeLib(SpecVector vector) => new(new Fido2Configuration
    {
        RPID = RpId,
        RPName = RpId,
        // topOrigin is checked against the configured origins, so a vector framed by example.com needs it listed.
        Origins = vector.TopOrigin is null
            ? new HashSet<string> { Origin }
            : new HashSet<string> { Origin, vector.TopOrigin },
        AllowCrossOriginRequests = vector.CrossOrigin,
    });

    private static CredentialCreateOptions MakeCreateOptions(SpecVector vector) => new()
    {
        Rp = new PublicKeyCredentialRpEntity(RpId, RpId, null),
        User = new Fido2User { Name = "testuser", Id = "testuser"u8.ToArray(), DisplayName = "Test User" },
        Challenge = Convert.FromHexString(vector.Registration.Challenge),
        PubKeyCredParams = [new PubKeyCredParam((COSE.Algorithm)vector.Alg)],
        AuthenticatorSelection = new AuthenticatorSelection { UserVerification = UserVerificationRequirement.Discouraged },
        Attestation = AttestationConveyancePreference.Direct,
        Timeout = 60000,
    };

    private static AssertionOptions MakeAssertionOptions(SpecVector vector, RegisteredPublicKeyCredential credential) => new()
    {
        Challenge = Convert.FromHexString(vector.Authentication.Challenge),
        RpId = RpId,
        AllowCredentials = [new PublicKeyCredentialDescriptor(credential.Id)],
        UserVerification = UserVerificationRequirement.Discouraged,
        Timeout = 60000,
    };

    private static AuthenticatorAttestationRawResponse MakeAttestationResponse(SpecVector vector) => new()
    {
        Type = PublicKeyCredentialType.PublicKey,
        Id = Base64Url(vector.CredentialId),
        RawId = Convert.FromHexString(vector.CredentialId),
        ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
        Response = new AuthenticatorAttestationRawResponse.AttestationResponse
        {
            AttestationObject = Convert.FromHexString(vector.Registration.AttestationObject),
            ClientDataJson = Convert.FromHexString(vector.Registration.ClientDataJson),
            Transports = [],
        },
    };

    private static AuthenticatorAssertionRawResponse MakeAssertionResponse(SpecVector vector) => new()
    {
        Type = PublicKeyCredentialType.PublicKey,
        Id = Base64Url(vector.CredentialId),
        RawId = Convert.FromHexString(vector.CredentialId),
        ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
        Response = new AuthenticatorAssertionRawResponse.AssertionResponse
        {
            AuthenticatorData = Convert.FromHexString(vector.Authentication.AuthenticatorData),
            ClientDataJson = Convert.FromHexString(vector.Authentication.ClientDataJson),
            Signature = Convert.FromHexString(vector.Authentication.Signature),
        },
    };

    private static string Base64Url(string hex) =>
        Convert.ToBase64String(Convert.FromHexString(hex)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public sealed class SpecVector
    {
        [JsonPropertyName("section")] public required string Section { get; init; }
        [JsonPropertyName("title")] public required string Title { get; init; }
        [JsonPropertyName("format")] public required string Format { get; init; }
        [JsonPropertyName("alg")] public required int Alg { get; init; }
        [JsonPropertyName("aaguid")] public required string Aaguid { get; init; }
        [JsonPropertyName("credentialId")] public required string CredentialId { get; init; }
        [JsonPropertyName("crossOrigin")] public bool CrossOrigin { get; init; }
        [JsonPropertyName("topOrigin")] public string TopOrigin { get; init; }
        [JsonPropertyName("registration")] public required RegistrationVector Registration { get; init; }
        [JsonPropertyName("authentication")] public required AuthenticationVector Authentication { get; init; }
    }

    public sealed class RegistrationVector
    {
        [JsonPropertyName("challenge")] public required string Challenge { get; init; }
        [JsonPropertyName("clientDataJSON")] public required string ClientDataJson { get; init; }
        [JsonPropertyName("attestationObject")] public required string AttestationObject { get; init; }
    }

    public sealed class AuthenticationVector
    {
        [JsonPropertyName("challenge")] public required string Challenge { get; init; }
        [JsonPropertyName("authenticatorData")] public required string AuthenticatorData { get; init; }
        [JsonPropertyName("clientDataJSON")] public required string ClientDataJson { get; init; }
        [JsonPropertyName("signature")] public required string Signature { get; init; }
    }
}
