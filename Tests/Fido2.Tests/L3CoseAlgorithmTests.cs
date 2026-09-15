using System.Security.Cryptography;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Covers the "fully-specified" COSE algorithm identifiers and the credential public key constraints WebAuthn
/// L3 §5.8.5 places on EC2 and OKP keys.
/// </summary>
public class L3CoseAlgorithmTests
{
    private static CredentialPublicKey Ec2Key(COSE.Algorithm alg, COSE.EllipticCurve crv, ECCurve curve)
    {
        var parameters = ECDsa.Create(curve).ExportParameters(false);

        return new CredentialPublicKey(new CborMap
        {
            { COSE.KeyCommonParameter.KeyType, COSE.KeyType.EC2 },
            { COSE.KeyCommonParameter.Alg, alg },
            { COSE.KeyTypeParameter.Crv, crv },
            { COSE.KeyTypeParameter.X, parameters.Q.X! },
            { COSE.KeyTypeParameter.Y, parameters.Q.Y! },
        });
    }

    [Theory]
    [InlineData(COSE.Algorithm.ESP256, COSE.EllipticCurve.P256)]
    [InlineData(COSE.Algorithm.ESP384, COSE.EllipticCurve.P384)]
    [InlineData(COSE.Algorithm.ESP512, COSE.EllipticCurve.P521)]
    public void FullySpecifiedEcdsaAlgorithmsAreUnderstood(COSE.Algorithm alg, COSE.EllipticCurve crv)
    {
        var curve = crv switch
        {
            COSE.EllipticCurve.P256 => ECCurve.NamedCurves.nistP256,
            COSE.EllipticCurve.P384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };

        var key = Ec2Key(alg, crv, curve);

        Assert.True(key.IsSameAlg(alg));
    }

    [Fact]
    public void FullySpecifiedAlgorithmsIgnoreTheCurveParameter()
    {
        // ESP256 fixes P-256 as part of the algorithm, so the crv parameter carries no information and a
        // disagreeing value must not change which curve is used.
        var key = Ec2Key(COSE.Algorithm.ESP256, COSE.EllipticCurve.P521, ECCurve.NamedCurves.nistP256);

        Assert.Equal(256, key.CreateECDsa().KeySize);
    }

    [Theory]
    [InlineData(COSE.Algorithm.ES256, COSE.EllipticCurve.P384)]
    [InlineData(COSE.Algorithm.ES384, COSE.EllipticCurve.P256)]
    [InlineData(COSE.Algorithm.ES512, COSE.EllipticCurve.P256)]
    public void EcdsaAlgorithmsPinTheirCurve(COSE.Algorithm alg, COSE.EllipticCurve crv)
    {
        // "Keys with algorithm -7 (ES256) MUST specify 1 (P-256) as the crv parameter", and likewise for
        // ES384/P-384 and ES512/P-521 (§5.8.5).
        var curve = crv is COSE.EllipticCurve.P256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384;

        var ex = Assert.Throws<Fido2VerificationException>(() => Ec2Key(alg, crv, curve));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Contains("not valid with curve", ex.Message);
    }

    [Fact]
    public void CompressedEc2PointsAreRejected()
    {
        // §5.8.5 requires the uncompressed point form for every EC2 algorithm. A compressed COSE key encodes y
        // as a boolean sign bit rather than a byte string.
        var parameters = ECDsa.Create(ECCurve.NamedCurves.nistP256).ExportParameters(false);

        var ex = Assert.Throws<Fido2VerificationException>(() => new CredentialPublicKey(new CborMap
        {
            { COSE.KeyCommonParameter.KeyType, COSE.KeyType.EC2 },
            { COSE.KeyCommonParameter.Alg, COSE.Algorithm.ES256 },
            { COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.P256 },
            { COSE.KeyTypeParameter.X, parameters.Q.X! },
            { (long)COSE.KeyTypeParameter.Y, CborBoolean.True },
        }));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Contains("uncompressed point form", ex.Message);
    }

    [Fact]
    public void EdDsaMustSpecifyEd25519()
    {
        // "Keys with algorithm -8 (EdDSA) MUST specify 6 (Ed25519) as the crv parameter" (§5.8.5). An Ed448
        // key is expected to declare the fully-specified algorithm -53 instead.
        var ex = Assert.Throws<Fido2VerificationException>(() => new CredentialPublicKey(new CborMap
        {
            { COSE.KeyCommonParameter.KeyType, COSE.KeyType.OKP },
            { COSE.KeyCommonParameter.Alg, COSE.Algorithm.EdDSA },
            { COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.Ed448 },
            { COSE.KeyTypeParameter.X, new byte[57] },
        }));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Contains("must specify curve Ed25519", ex.Message);
    }

    [Fact]
    public void Ed448IsRecognizedButUnimplemented()
    {
        var ex = Assert.Throws<Fido2VerificationException>(() => new CredentialPublicKey(new CborMap
        {
            { COSE.KeyCommonParameter.KeyType, COSE.KeyType.OKP },
            { COSE.KeyCommonParameter.Alg, COSE.Algorithm.Ed448 },
            { COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.Ed448 },
            { COSE.KeyTypeParameter.X, new byte[57] },
        }));

        Assert.Equal(Fido2ErrorCode.UnimplementedAlgorithm, ex.Code);
    }

    [Fact]
    public void AnUnknownKeyTypeIsRejectedRatherThanThrowingInvalidOperation()
    {
        // Credential public keys arrive from the wire, so anything unrecognized has to surface as a
        // Fido2VerificationException the caller can catch alongside every other verification failure.
        var ex = Assert.Throws<Fido2VerificationException>(() => new CredentialPublicKey(new CborMap
        {
            { COSE.KeyCommonParameter.KeyType, (COSE.KeyType)42 },
            { COSE.KeyCommonParameter.Alg, COSE.Algorithm.ES256 },
        }));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Contains("Missing or unknown kty", ex.Message);
    }
}
