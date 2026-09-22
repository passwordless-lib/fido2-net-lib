using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test.Attestation;

/// <summary>
/// Covers the <c>compound</c> attestation statement format introduced in WebAuthn Level 3 (§8.9), whose
/// <c>attStmt</c> is an array of two or more self-contained sub-statements rather than a map.
/// </summary>
public class L3CompoundAttestationTests : Fido2Tests.Attestation
{
    private readonly COSE.KeyType _kty;
    private readonly COSE.Algorithm _alg;
    private readonly COSE.EllipticCurve _crv;

    public L3CompoundAttestationTests()
    {
        (_kty, _alg, _crv) = Fido2Tests._validCOSEParameters[0];
        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);
    }

    /// <summary>A <c>packed</c> self-attestation sub-statement that verifies against the current authenticator data.</summary>
    private CborMap ValidPackedSubStatement() => new()
    {
        { "fmt", "packed" },
        { "attStmt", new CborMap { { "alg", _alg }, { "sig", SignData(_kty, _alg, _crv) } } }
    };

    private static CborMap ValidNoneSubStatement() => new()
    {
        { "fmt", "none" },
        { "attStmt", new CborMap() }
    };

    private static CborMap InvalidNoneSubStatement() => new()
    {
        // "none" must carry an empty attestation statement, so this one always fails verification.
        { "fmt", "none" },
        { "attStmt", new CborMap { { "foo", "bar" } } }
    };

    private void SetCompound(params CborMap[] subStatements)
    {
        var array = new CborArray();

        foreach (var subStatement in subStatements)
            array.Add(subStatement);

        _attestationObject = new CborMap { { "fmt", "compound" }, { "attStmt", array } };
    }

    [Fact]
    public async Task CompoundWithAllSubStatementsValidIsAcceptedAsync()
    {
        SetCompound(ValidPackedSubStatement(), ValidNoneSubStatement());

        var credential = await MakeAttestationResponseAsync();

        Assert.Equal("compound", credential.AttestationFormat);
        Assert.Equal(_credentialID, credential.Id);
        Assert.Equal(_credentialPublicKey.GetBytes(), credential.PublicKey);
    }

    [Fact]
    public async Task CompoundRequiringAllRejectsAPartiallyValidStatementAsync()
    {
        SetCompound(ValidPackedSubStatement(), InvalidNoneSubStatement());

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Contains("required 2 of 2 sub-statements", ex.Message);
    }

    [Fact]
    public async Task CompoundRequiringAnyAcceptsAPartiallyValidStatementAsync()
    {
        SetCompound(ValidPackedSubStatement(), InvalidNoneSubStatement());

        var credential = await MakeAttestationResponseAsync(
            null,
            configure: static c => c.CompoundAttestationPolicy = CompoundAttestationPolicy.RequireAny);

        Assert.Equal("compound", credential.AttestationFormat);
    }

    [Fact]
    public async Task CompoundRequiringAnyStillRejectsWhenEverySubStatementFailsAsync()
    {
        SetCompound(InvalidNoneSubStatement(), InvalidNoneSubStatement());

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync(
            null,
            configure: static c => c.CompoundAttestationPolicy = CompoundAttestationPolicy.RequireAny));

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Contains("required 1 of 2 sub-statements", ex.Message);
    }

    [Fact]
    public async Task CompoundWithFewerThanTwoSubStatementsIsRejectedAsync()
    {
        SetCompound(ValidPackedSubStatement());

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Contains("at least 2 sub-statements", ex.Message);
    }

    [Fact]
    public async Task NestedCompoundIsRejectedAsync()
    {
        // nonCompoundAttStmt = { $$attStmtType } .within { fmt: text .ne "compound", * any => any }
        SetCompound(
            ValidPackedSubStatement(),
            new CborMap { { "fmt", "compound" }, { "attStmt", new CborMap() } });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Contains("may not be nested", ex.Message);
    }

    [Fact]
    public async Task CompoundSubStatementMissingAttStmtIsRejectedAsync()
    {
        SetCompound(ValidPackedSubStatement(), new CborMap { { "fmt", "none" } });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Contains("missing an 'attStmt' map", ex.Message);
    }

    [Fact]
    public async Task CompoundWithAMapAttStmtIsRejectedAsync()
    {
        // A compound statement's attStmt must be an array of sub-statements.
        _attestationObject = new CborMap { { "fmt", "compound" }, { "attStmt", new CborMap() } };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Equal(Fido2ErrorMessages.InvalidCompoundAttestationStatement, ex.Message);
    }

    [Fact]
    public async Task CompoundReportsTheAttestationTypeOfARealSubStatementAsync()
    {
        // "none" is listed first, but reporting AttestationType.None would throw away the fact that a
        // sub-statement actually attested to the credential.
        SetCompound(ValidNoneSubStatement(), ValidPackedSubStatement());

        var credential = await MakeAttestationResponseAsync();

        Assert.Equal("compound", credential.AttestationFormat);
    }

    [Fact]
    public void AttestationVerifierCreateRefusesCompoundDirectly()
    {
        // AttestationVerifier.Create() takes a CborMap attStmt, which "compound" doesn't use -- the
        // ceremony dispatches to Compound.VerifyAsync itself instead of going through Create() at all.
        var ex = Assert.Throws<Fido2VerificationException>(() => AttestationVerifier.Create("compound", new Fido2Configuration()));

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Contains(nameof(Compound), ex.Message, System.StringComparison.Ordinal);
    }

    [Fact]
    public async Task CompoundFallsBackToTheFirstSuccessWhenNoneConveyRealAttestationAsync()
    {
        // Every sub-statement here verifies but reports AttestationType.None, so there is no "real"
        // attestation to prefer -- the first successful result is returned as-is.
        SetCompound(ValidNoneSubStatement(), ValidNoneSubStatement());

        var credential = await MakeAttestationResponseAsync();

        Assert.Equal("compound", credential.AttestationFormat);
    }

    [Fact]
    public async Task CompoundSubStatementThatIsNotAMapIsRejectedAsync()
    {
        var array = new CborArray();
        array.Add(ValidPackedSubStatement());
        array.Add("not a sub-statement map");

        _attestationObject = new CborMap { { "fmt", "compound" }, { "attStmt", array } };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Contains("must be a CBOR map", ex.Message);
    }

    [Fact]
    public async Task CompoundSubStatementMissingFmtIsRejectedAsync()
    {
        SetCompound(ValidPackedSubStatement(), new CborMap { { "attStmt", new CborMap() } });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponseAsync);

        Assert.Equal(Fido2ErrorCode.InvalidAttestation, ex.Code);
        Assert.Contains("missing a 'fmt' text string", ex.Message);
    }
}
