using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.NSec;
using Fido2NetLib.Objects;

using NSec.Cryptography;

using Xunit;

namespace Fido2.NSec.Tests;

public class NSecOkpSignatureVerifierTests
{
    private static readonly byte[] Data = "authenticator data || client data hash"u8.ToArray();

    private static (byte[] PublicKey, byte[] Signature) CreateSignedEd25519()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var signature = SignatureAlgorithm.Ed25519.Sign(key, Data);

        return (publicKey, signature);
    }

    [Fact]
    public void CanVerify_returns_true_for_Ed25519()
    {
        var verifier = new NSecOkpSignatureVerifier();

        Assert.True(verifier.CanVerify(COSE.EllipticCurve.Ed25519));
    }

    [Theory]
    [InlineData(COSE.EllipticCurve.Ed448)]
    [InlineData(COSE.EllipticCurve.X25519)]
    [InlineData(COSE.EllipticCurve.X448)]
    [InlineData(COSE.EllipticCurve.P256)]
    public void CanVerify_returns_false_for_every_other_curve(COSE.EllipticCurve curve)
    {
        var verifier = new NSecOkpSignatureVerifier();

        Assert.False(verifier.CanVerify(curve));
    }

    [Fact]
    public void Verify_accepts_a_genuine_Ed25519_signature()
    {
        var (publicKey, signature) = CreateSignedEd25519();
        var verifier = new NSecOkpSignatureVerifier();

        Assert.True(verifier.Verify(COSE.EllipticCurve.Ed25519, publicKey, Data, signature));
    }

    [Fact]
    public void Verify_rejects_a_signature_from_the_wrong_key()
    {
        var (_, signature) = CreateSignedEd25519();
        var (otherPublicKey, _) = CreateSignedEd25519();
        var verifier = new NSecOkpSignatureVerifier();

        Assert.False(verifier.Verify(COSE.EllipticCurve.Ed25519, otherPublicKey, Data, signature));
    }

    [Fact]
    public void Verify_rejects_a_signature_over_different_data()
    {
        var (publicKey, signature) = CreateSignedEd25519();
        var verifier = new NSecOkpSignatureVerifier();

        Assert.False(verifier.Verify(COSE.EllipticCurve.Ed25519, publicKey, "different data"u8, signature));
    }

    [Fact]
    public void Verify_throws_Fido2VerificationException_for_a_malformed_public_key()
    {
        var (_, signature) = CreateSignedEd25519();
        var verifier = new NSecOkpSignatureVerifier();

        var ex = Assert.Throws<Fido2VerificationException>(
            () => verifier.Verify(COSE.EllipticCurve.Ed25519, [1, 2, 3], Data, signature));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
    }

    [Fact]
    public void Verify_throws_for_a_curve_it_does_not_support()
    {
        var verifier = new NSecOkpSignatureVerifier();

        Assert.Throws<ArgumentOutOfRangeException>(
            () => verifier.Verify(COSE.EllipticCurve.Ed448, [], Data, []));
    }

    [Fact]
    public void Registers_itself_via_the_module_initializer()
    {
        // The module initializer runs once, the first time this assembly loads -- which already happened by
        // the time this test runs, since it's in the same assembly. Confirms OkpSignatureVerifiers.Find
        // actually resolves to (some) verifier for Ed25519 without any test-local registration call.
        var found = OkpSignatureVerifiers.Find(COSE.EllipticCurve.Ed25519);

        Assert.NotNull(found);
        Assert.True(found.CanVerify(COSE.EllipticCurve.Ed25519));
    }

    [Fact]
    public void BootstrapError_is_null_when_Fido2_NSec_loads_successfully()
    {
        // This test process is exactly the "Fido2.NSec present and working" case: BootstrapError exists to
        // flag a provider that's present but broken, which this isn't, so it should stay null rather than
        // the expected-but-still-successful bootstrap tripping it.
        Assert.Null(OkpSignatureVerifiers.BootstrapError);
    }
}
