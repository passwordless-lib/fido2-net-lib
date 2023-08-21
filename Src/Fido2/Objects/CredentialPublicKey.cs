using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Cbor;

using NSec.Cryptography;

namespace Fido2NetLib.Objects;

public sealed class CredentialPublicKey
{
    internal readonly COSE.KeyType _type;
    internal readonly COSE.Algorithm _alg;
    internal readonly CborMap _cpk;

    public CredentialPublicKey(byte[] cpk) 
        : this((CborMap)CborObject.Decode(cpk)) { }

    public CredentialPublicKey(CborMap cpk)
    {
        _cpk = cpk;
        _type = (COSE.KeyType)(int)cpk[COSE.KeyCommonParameter.KeyType];
        _alg = (COSE.Algorithm)(int)cpk[COSE.KeyCommonParameter.Alg];
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

        if (_type is COSE.KeyType.RSA)
        {
            var keyParams = cert.GetRSAPublicKey()!.ExportParameters(false);
            _cpk.Add(COSE.KeyTypeParameter.N, keyParams.Modulus!);
            _cpk.Add(COSE.KeyTypeParameter.E, keyParams.Exponent!);
        }
        else if (_type is COSE.KeyType.EC2)
        {
            var ecDsaPubKey = cert.GetECDsaPublicKey()!;
            var keyParams = ecDsaPubKey.ExportParameters(false);

            _cpk.Add(COSE.KeyTypeParameter.Crv, keyParams.Curve.ToCoseCurve());
            _cpk.Add(COSE.KeyTypeParameter.X, keyParams.Q.X!);
            _cpk.Add(COSE.KeyTypeParameter.Y, keyParams.Q.Y!);
        }
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        switch (_type)
        {
            case COSE.KeyType.EC2:
                using(ECDsa ecdsa = CreateECDsa())
                {
                    var ecsig = CryptoUtils.SigFromEcDsaSig(signature.ToArray(), ecdsa.KeySize);
                    return ecdsa.VerifyData(data, ecsig, CryptoUtils.HashAlgFromCOSEAlg(_alg));
                }

            case COSE.KeyType.RSA:
                using (RSA rsa = CreateRSA())
                {
                    return rsa.VerifyData(data, signature, CryptoUtils.HashAlgFromCOSEAlg(_alg), Padding);
                }

            case COSE.KeyType.OKP:
                return SignatureAlgorithm.Ed25519.Verify(EdDSAPublicKey, data, signature);
        }
        throw new InvalidOperationException($"Missing or unknown kty {_type}");
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
                   
        var point = new ECPoint
        {
            X = (byte[])_cpk[COSE.KeyTypeParameter.X],
            Y = (byte[])_cpk[COSE.KeyTypeParameter.Y],
        };

        ECCurve curve;

        var crv = (COSE.EllipticCurve)(int)_cpk[COSE.KeyTypeParameter.Crv]!;

        // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves

        switch ((_alg, crv))
        {
            case (COSE.Algorithm.ES256K, COSE.EllipticCurve.P256K):
                if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) // see https://github.com/dotnet/runtime/issues/47770
                {
                    throw new PlatformNotSupportedException($"The secP256k1 curve is not supported on macOS");
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
                throw new InvalidOperationException($"Missing or unknown alg {_alg}");
        }

        return ECDsa.Create(new ECParameters
        {
            Q = point,
            Curve = curve
        });
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
                    throw new InvalidOperationException($"Missing or unknown alg {_alg}");
            }
        }
    }

    internal NSec.Cryptography.PublicKey EdDSAPublicKey
    {
        get
        {
            if (_type != COSE.KeyType.OKP)
            {
                throw new InvalidOperationException($"Must be a OKP key. Was {_type}");
            }
          
            switch (_alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
            {
                case COSE.Algorithm.EdDSA:
                    var crv = (COSE.EllipticCurve)(int)_cpk[COSE.KeyTypeParameter.Crv];

                    // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                    if (crv is COSE.EllipticCurve.Ed25519)
                    {
                        return NSec.Cryptography.PublicKey.Import(SignatureAlgorithm.Ed25519, (byte[])_cpk[COSE.KeyTypeParameter.X], KeyBlobFormat.RawPublicKey);
                    }
                    else
                    {
                        throw new InvalidOperationException($"Missing or unknown crv {crv}");
                    }
                default:
                    throw new InvalidOperationException($"Missing or unknown alg {_alg}");
            }
        }
    }

    public static CredentialPublicKey Decode(ReadOnlyMemory<byte> cpk, out int bytesRead)
    {
        var map = (CborMap)CborObject.Decode(cpk, out bytesRead);

        return new CredentialPublicKey(map);
    }

    public byte[] GetBytes() => _cpk.Encode();

    public bool IsSameAlg(COSE.Algorithm alg) => _alg.Equals(alg);

    public CborMap GetCborObject() => _cpk;
}
