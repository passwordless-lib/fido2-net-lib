using System;
using System.Security.Cryptography;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Xunit;

namespace Test;

/// <summary>
/// Verification of ML-DSA credential public keys: the AKP key type and the three algorithms RFC 9964
/// registers for COSE (-48, -49, -50).
/// </summary>
/// <remarks>
/// ML-DSA verification is available only where the platform provides <c>System.Security.Cryptography.MLDsa</c>,
/// which means .NET 10 or later. On earlier targets the library refuses the key cleanly, the way it already
/// does for Ed448, and the tests below assert that refusal instead.
/// </remarks>
public class MLDsaCredentialPublicKeyTests
{
    private static CborMap MakeAkpKey(COSE.Algorithm alg, byte[] pub)
    {
        return new CborMap
        {
            { COSE.KeyCommonParameter.KeyType, COSE.KeyType.AKP },
            { COSE.KeyCommonParameter.Alg, alg },
            // RFC 9964 carries the public key at label -1, as a byte string.
            { (int)COSE.KeyTypeParameter.Pub, pub }
        };
    }

#if NET10_0_OR_GREATER

    public static TheoryData<COSE.Algorithm> Algorithms => new()
    {
        COSE.Algorithm.MLDSA44,
        COSE.Algorithm.MLDSA65,
        COSE.Algorithm.MLDSA87,
    };

    private static MLDsaAlgorithm ParameterSet(COSE.Algorithm alg) => alg switch
    {
        COSE.Algorithm.MLDSA44 => MLDsaAlgorithm.MLDsa44,
        COSE.Algorithm.MLDSA65 => MLDsaAlgorithm.MLDsa65,
        COSE.Algorithm.MLDSA87 => MLDsaAlgorithm.MLDsa87,
        _ => throw new ArgumentOutOfRangeException(nameof(alg)),
    };

    [Fact]
    public void TheRuntimeProvidesMLDsa()
    {
        // Everything below depends on this. Asserted separately so that a platform without ML-DSA fails
        // with one clear message rather than five confusing ones.
        Assert.True(MLDsa.IsSupported,
            "This .NET 10 runtime does not implement ML-DSA, so the credential public key tests below cannot run.");
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void VerifiesAGenuineSignature(COSE.Algorithm alg)
    {
        using var key = MLDsa.GenerateKey(ParameterSet(alg));
        var data = "authenticatorData || clientDataHash"u8.ToArray();
        var signature = key.SignData(data);

        var cpk = new CredentialPublicKey(MakeAkpKey(alg, key.ExportMLDsaPublicKey()));

        Assert.True(cpk.Verify(data, signature));
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void RejectsATamperedSignature(COSE.Algorithm alg)
    {
        using var key = MLDsa.GenerateKey(ParameterSet(alg));
        var data = "authenticatorData || clientDataHash"u8.ToArray();
        var signature = key.SignData(data);
        signature[0] ^= 0x01;

        var cpk = new CredentialPublicKey(MakeAkpKey(alg, key.ExportMLDsaPublicKey()));

        Assert.False(cpk.Verify(data, signature));
    }

    [Fact]
    public void RejectsASignatureOverDifferentData()
    {
        using var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
        var signature = key.SignData("one message"u8.ToArray());

        var cpk = new CredentialPublicKey(MakeAkpKey(COSE.Algorithm.MLDSA44, key.ExportMLDsaPublicKey()));

        Assert.False(cpk.Verify("another message"u8.ToArray(), signature));
    }

    [Fact]
    public void RejectsAKeyFromADifferentParameterSet()
    {
        // An ML-DSA-65 public key declared as ML-DSA-44. The algorithm fixes the parameter set, so the key
        // is the wrong length for what it claims to be.
        using var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);

        var ex = Assert.Throws<Fido2VerificationException>(
            () => new CredentialPublicKey(MakeAkpKey(COSE.Algorithm.MLDSA44, key.ExportMLDsaPublicKey())));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
    }

    [Fact]
    public void RejectsAnAkpKeyWithoutAPubParameter()
    {
        var cpk = new CborMap
        {
            { COSE.KeyCommonParameter.KeyType, COSE.KeyType.AKP },
            { COSE.KeyCommonParameter.Alg, COSE.Algorithm.MLDSA44 }
        };

        var ex = Assert.Throws<Fido2VerificationException>(() => new CredentialPublicKey(cpk));

        Assert.Equal(Fido2ErrorCode.InvalidCredentialPublicKey, ex.Code);
        Assert.Contains("pub", ex.Message);
    }

    [Fact]
    public void RejectsAnAkpKeyWithANonMLDsaAlgorithm()
    {
        // ES256 is not an AKP algorithm; the key type and the algorithm disagree.
        var ex = Assert.Throws<Fido2VerificationException>(
            () => new CredentialPublicKey(MakeAkpKey(COSE.Algorithm.ES256, [1, 2, 3])));

        Assert.Equal(Fido2ErrorCode.UnimplementedAlgorithm, ex.Code);
    }

#else

    [Fact]
    public void ReportsMLDsaAsUnimplementedOnPlatformsWithoutIt()
    {
        // The refusal has to be clean rather than a crash: a Relying Party offering -48 in pubKeyCredParams
        // on a runtime that cannot verify it should get the same treatment as Ed448.
        var ex = Assert.Throws<Fido2VerificationException>(
            () => new CredentialPublicKey(MakeAkpKey(COSE.Algorithm.MLDSA44, new byte[1312])));

        Assert.Equal(Fido2ErrorCode.UnimplementedAlgorithm, ex.Code);
        Assert.Contains(".NET 10", ex.Message);
    }

#endif

    [Fact]
    public void RegistersTheAlgorithmIdentifiersRfc9964Assigns()
    {
        // Guards against a transcription slip in values that are easy to get wrong and hard to notice.
        Assert.Equal(-48, (int)COSE.Algorithm.MLDSA44);
        Assert.Equal(-49, (int)COSE.Algorithm.MLDSA65);
        Assert.Equal(-50, (int)COSE.Algorithm.MLDSA87);
        Assert.Equal(7, (int)COSE.KeyType.AKP);
        Assert.Equal(-1, (int)COSE.KeyTypeParameter.Pub);
    }
}
