using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;

using NSec.Cryptography;

namespace Fido2NetLib.Objects;

public sealed class CredentialPublicKey
{
    internal readonly COSE.KeyType _type;
    internal readonly COSE.Algorithm _alg;
    internal readonly CborMap _cpk;
    internal readonly ECDsa? _ecdsa;
    internal readonly RSA? _rsa;
    internal readonly NSec.Cryptography.PublicKey? _eddsa;
#if NET10_0_OR_GREATER
    internal readonly MLDsa? _mldsa;
#endif

    public CredentialPublicKey(byte[] cpk)
        : this((CborMap)CborObject.Decode(cpk)) { }

    public CredentialPublicKey(CborMap cpk)
    {
        _cpk = cpk;
        _type = (COSE.KeyType)(int)cpk[COSE.KeyCommonParameter.KeyType];
        _alg = (COSE.Algorithm)(int)cpk[COSE.KeyCommonParameter.Alg];
        switch (_type)
        {
            case COSE.KeyType.EC2:
                {
                    _ecdsa = CreateECDsa();
                    return;
                }
            case COSE.KeyType.RSA:
                {
                    _rsa = CreateRSA();
                    return;
                }
            case COSE.KeyType.OKP:
                {
                    _eddsa = CreateEdDSA();
                    return;
                }
            case COSE.KeyType.AKP:
                {
#if NET10_0_OR_GREATER
                    _mldsa = CreateMLDsa();
                    return;
#else
                    throw new Fido2VerificationException(
                        Fido2ErrorCode.UnimplementedAlgorithm,
                        $"Credential public key algorithm {_alg} requires .NET 10 or later, which provides System.Security.Cryptography.MLDsa.");
#endif
                }
        }

        // Reached with a credential public key from the wire, so this is a rejection rather than a bug.
        throw new Fido2VerificationException(Fido2ErrorCode.InvalidCredentialPublicKey, $"Missing or unknown kty {_type}");
    }

    public CredentialPublicKey(ECDsa ecdsaPublicKey, COSE.Algorithm alg)
    {
        _type = COSE.KeyType.EC2;
        _alg = alg;

        var keyParams = ecdsaPublicKey.ExportParameters(false);

        _cpk = new CborMap
        {
            { COSE.KeyCommonParameter.KeyType, _type },
            { COSE.KeyCommonParameter.Alg, _alg },
            { COSE.KeyTypeParameter.Crv, keyParams.Curve.ToCoseCurve() },
            { COSE.KeyTypeParameter.X, keyParams.Q.X! },
            { COSE.KeyTypeParameter.Y, keyParams.Q.Y! }
        };
        _ecdsa = CreateECDsa();
    }

    public CredentialPublicKey(X509Certificate2 cert, COSE.Algorithm alg)
    {
        var keyAlg = cert.GetKeyAlgorithm();
        _type = COSE.GetKeyTypeFromOid(oid: keyAlg);
        _alg = alg;
        _cpk = new CborMap
        {
            { COSE.KeyCommonParameter.KeyType, _type },
            { COSE.KeyCommonParameter.Alg, _alg }
        };
        switch (_type)
        {
            case COSE.KeyType.RSA:
                {
                    var keyParams = cert.GetRSAPublicKey()!.ExportParameters(false);
                    _cpk.Add(COSE.KeyTypeParameter.N, keyParams.Modulus!);
                    _cpk.Add(COSE.KeyTypeParameter.E, keyParams.Exponent!);
                    _rsa = CreateRSA();
                    break;
                }
            case COSE.KeyType.EC2:
                {
                    var ecDsaPubKey = cert.GetECDsaPublicKey()!;
                    var keyParams = ecDsaPubKey.ExportParameters(false);

                    _cpk.Add(COSE.KeyTypeParameter.Crv, keyParams.Curve.ToCoseCurve());
                    _cpk.Add(COSE.KeyTypeParameter.X, keyParams.Q.X!);
                    _cpk.Add(COSE.KeyTypeParameter.Y, keyParams.Q.Y!);
                    _ecdsa = CreateECDsa();
                    break;
                }
            case COSE.KeyType.OKP:
                {
                    _cpk.Add(COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.Ed25519);
                    _cpk.Add(COSE.KeyTypeParameter.X, cert.PublicKey.EncodedKeyValue.RawData);
                    _eddsa = CreateEdDSA();
                    break;
                }
            default:
                throw new InvalidOperationException($"Missing or unknown kty {_type}");
        }
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        switch (_type)
        {
            case COSE.KeyType.EC2:
                byte[] ecsig;
                try
                {
                    ecsig = CryptoUtils.SigFromEcDsaSig(signature.ToArray(), _ecdsa!.KeySize);
                }
                catch (Exception ex)
                {
                    throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignature, Fido2ErrorMessages.InvalidSignature, ex);
                }
                return _ecdsa!.VerifyData(data, ecsig, CryptoUtils.HashAlgFromCOSEAlg(_alg));

            case COSE.KeyType.RSA:
                return _rsa!.VerifyData(data, signature, CryptoUtils.HashAlgFromCOSEAlg(_alg), Padding);

            case COSE.KeyType.OKP:
                return SignatureAlgorithm.Ed25519.Verify(_eddsa!, data, signature);

            case COSE.KeyType.AKP:
#if NET10_0_OR_GREATER
                // ML-DSA signs the message directly; there is no separate digest step to select, and the
                // signature is the fixed-size FIPS 204 encoding rather than a DER structure to unwrap.
                return _mldsa!.VerifyData(data, signature);
#else
                throw new Fido2VerificationException(
                    Fido2ErrorCode.UnimplementedAlgorithm,
                    $"Credential public key algorithm {_alg} requires .NET 10 or later, which provides System.Security.Cryptography.MLDsa.");
#endif
        }

        throw new Fido2VerificationException(Fido2ErrorCode.InvalidCredentialPublicKey, $"Missing or unknown kty {_type}");
    }

    internal RSA CreateRSA()
    {
        if (_type != COSE.KeyType.RSA)
        {
            throw new InvalidOperationException($"Must be a RSA key. Was {_type}");
        }

        return RSA.Create(new RSAParameters
        {
            Modulus = (byte[])_cpk[COSE.KeyTypeParameter.N],
            Exponent = (byte[])_cpk[COSE.KeyTypeParameter.E]
        });
    }

    public ECDsa CreateECDsa()
    {
        if (_type != COSE.KeyType.EC2)
        {
            throw new InvalidOperationException($"Must be a EC2 key. Was {_type}");
        }

        // WebAuthn L3 §5.8.5 requires every EC2 credential public key to use the uncompressed point form, so
        // both coordinates must be present as byte strings. A compressed key encodes y as a boolean sign bit.
        if (_cpk[COSE.KeyTypeParameter.X] is not CborByteString x || _cpk[COSE.KeyTypeParameter.Y] is not CborByteString y)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.InvalidCredentialPublicKey,
                $"EC2 credential public key with algorithm {_alg} must use the uncompressed point form");
        }

        var point = new ECPoint
        {
            X = x.Value,
            Y = y.Value,
        };

        ECCurve curve;

        // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
        // A fully-specified algorithm (ESP256/ESP384/ESP512) fixes its own curve, so crv carries no information
        // for it and is not consulted.
        switch (_alg)
        {
            case COSE.Algorithm.ESP256:
                curve = ECCurve.NamedCurves.nistP256;
                break;
            case COSE.Algorithm.ESP384:
                curve = ECCurve.NamedCurves.nistP384;
                break;
            case COSE.Algorithm.ESP512:
                curve = ECCurve.NamedCurves.nistP521;
                break;
            default:
                curve = CurveFromAlgAndCrv();
                break;
        }

        // ECDsa.Create validates that the point actually lies on the curve, which WebAuthn L3 §5.8.5 calls out
        // as being at particular risk of falling between a crypto library and its caller.
        return ECDsa.Create(new ECParameters
        {
            Q = point,
            Curve = curve
        });
    }

    private ECCurve CurveFromAlgAndCrv()
    {
        var crv = (COSE.EllipticCurve)(int)_cpk[COSE.KeyTypeParameter.Crv]!;

        ECCurve curve;

        switch ((_alg, crv))
        {
            case (COSE.Algorithm.ES256K, COSE.EllipticCurve.P256K):
                if (OperatingSystem.IsMacOS()) // see https://github.com/dotnet/runtime/issues/47770
                {
                    throw new PlatformNotSupportedException("The secP256k1 curve is not supported on macOS");
                }

                curve = ECCurve.CreateFromFriendlyName("secP256k1");
                break;
            case (COSE.Algorithm.ES256, COSE.EllipticCurve.P256):
                curve = ECCurve.NamedCurves.nistP256;
                break;
            case (COSE.Algorithm.ES384, COSE.EllipticCurve.P384):
                curve = ECCurve.NamedCurves.nistP384;
                break;
            case (COSE.Algorithm.ES512, COSE.EllipticCurve.P521):
                curve = ECCurve.NamedCurves.nistP521;
                break;
            default:
                // ES256/ES384/ES512 each pin their curve (WebAuthn L3 §5.8.5), so a mismatched pair is a
                // malformed key rather than an unsupported one.
                throw new Fido2VerificationException(
                    Fido2ErrorCode.InvalidCredentialPublicKey,
                    $"Credential public key algorithm {_alg} is not valid with curve {crv}");
        }

        return curve;
    }

    internal RSASignaturePadding Padding
    {
        get
        {
            if (_type != COSE.KeyType.RSA)
            {
                throw new InvalidOperationException($"Must be a RSA key. Was {_type}");
            }

            switch (_alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
            {
                case COSE.Algorithm.PS256:
                case COSE.Algorithm.PS384:
                case COSE.Algorithm.PS512:
                    return RSASignaturePadding.Pss;

                case COSE.Algorithm.RS1:
                case COSE.Algorithm.RS256:
                case COSE.Algorithm.RS384:
                case COSE.Algorithm.RS512:
                    return RSASignaturePadding.Pkcs1;
                default:
                    throw new Fido2VerificationException(Fido2ErrorCode.InvalidCredentialPublicKey, $"Missing or unknown alg {_alg}");
            }
        }
    }

    internal NSec.Cryptography.PublicKey CreateEdDSA()
    {
        if (_type != COSE.KeyType.OKP)
        {
            throw new InvalidOperationException($"Must be a OKP key. Was {_type}");
        }

        // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        switch (_alg)
        {
            case COSE.Algorithm.EdDSA:
                // WebAuthn L3 §5.8.5: "Keys with algorithm -8 (EdDSA) MUST specify 6 (Ed25519) as the crv
                // parameter." An Ed448 key is expected to declare the fully-specified algorithm -53 instead.
                var crv = (COSE.EllipticCurve)(int)_cpk[COSE.KeyTypeParameter.Crv];

                if (crv is not COSE.EllipticCurve.Ed25519)
                {
                    throw new Fido2VerificationException(
                        Fido2ErrorCode.InvalidCredentialPublicKey,
                        $"Credential public key algorithm EdDSA must specify curve Ed25519, was {crv}");
                }

                goto case COSE.Algorithm.Ed25519;

            case COSE.Algorithm.Ed25519:
                return NSec.Cryptography.PublicKey.Import(SignatureAlgorithm.Ed25519, (byte[])_cpk[COSE.KeyTypeParameter.X], KeyBlobFormat.RawPublicKey);

            case COSE.Algorithm.Ed448:
                throw new Fido2VerificationException(Fido2ErrorCode.UnimplementedAlgorithm, "Ed448 is not yet supported. NSec.Cryptography library version does not include Ed448 support.");

            default:
                throw new Fido2VerificationException(
                    Fido2ErrorCode.UnimplementedAlgorithm,
                    $"Credential public key algorithm {_alg} is not supported for OKP keys");
        }
    }

#if NET10_0_OR_GREATER
    /// <summary>
    /// Imports an <see cref="COSE.KeyType.AKP"/> credential public key as an ML-DSA key.
    /// </summary>
    /// <remarks>
    /// RFC 9964 carries the public key as a single byte string at label -1, in the FIPS 204 encoding, which is
    /// exactly what <see cref="MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm, byte[])"/> takes. The algorithm fixes
    /// the parameter set, so nothing else in the key selects it.
    /// </remarks>
    internal MLDsa CreateMLDsa()
    {
        if (_type != COSE.KeyType.AKP)
        {
            throw new InvalidOperationException($"Must be an AKP key. Was {_type}");
        }

        var parameterSet = _alg switch
        {
            COSE.Algorithm.MLDSA44 => MLDsaAlgorithm.MLDsa44,
            COSE.Algorithm.MLDSA65 => MLDsaAlgorithm.MLDsa65,
            COSE.Algorithm.MLDSA87 => MLDsaAlgorithm.MLDsa87,
            _ => throw new Fido2VerificationException(
                Fido2ErrorCode.UnimplementedAlgorithm,
                $"Credential public key algorithm {_alg} is not supported for AKP keys")
        };

        if (!MLDsa.IsSupported)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.UnimplementedAlgorithm,
                $"Credential public key algorithm {_alg} is not available: this platform does not implement ML-DSA.");
        }

        // The indexer throws when the label is absent, so go through TryGetValue: a key that arrives from
        // the wire without pub is malformed input to be rejected, not a missing-key bug to surface.
        if (!_cpk.TryGetValue(new CborInteger((int)COSE.KeyTypeParameter.Pub), out var pubValue)
            || pubValue is not CborByteString pub)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.InvalidCredentialPublicKey,
                "AKP credential public key is missing the pub parameter, or it is not a byte string");
        }

        try
        {
            return MLDsa.ImportMLDsaPublicKey(parameterSet, (byte[])pub);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            // A key of the wrong length for the parameter set the algorithm names raises ArgumentException,
            // which must not reach the caller as-is.
            throw new Fido2VerificationException(
                Fido2ErrorCode.InvalidCredentialPublicKey,
                $"AKP credential public key is not a valid {_alg} public key", ex);
        }
    }

#endif
    public static CredentialPublicKey Decode(ReadOnlyMemory<byte> cpk, out int bytesRead)
    {
        var map = (CborMap)CborObject.Decode(cpk, out bytesRead);

        return new CredentialPublicKey(map);
    }

    public byte[] GetBytes() => _cpk.Encode();

    public bool IsSameAlg(COSE.Algorithm alg) => _alg.Equals(alg);

    public CborMap GetCborObject() => _cpk;
}
