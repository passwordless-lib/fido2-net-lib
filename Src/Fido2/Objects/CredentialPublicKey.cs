using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib.Cbor;
using NSec.Cryptography;

namespace Fido2NetLib.Objects
{
    public sealed class CredentialPublicKey
    {
        public CredentialPublicKey(byte[] cpk) : this((CborMap)CborObject.Parse(cpk)) { }

        public CredentialPublicKey(CborMap cpk)
        {
            _cpk = cpk;
            _type = (COSE.KeyType)(int)cpk[COSE.KeyCommonParameter.KeyType];
            _alg = (COSE.Algorithm)(int)cpk[COSE.KeyCommonParameter.Alg];
        }

        public CredentialPublicKey(X509Certificate2 cert, int alg)
        {
            _cpk = new CborMap();

            var keyAlg = cert.GetKeyAlgorithm();
            _type = CoseKeyTypeFromOid[keyAlg];
            _alg = (COSE.Algorithm)alg;
            _cpk.Add((int)COSE.KeyCommonParameter.KeyType, (int)_type);
            _cpk.Add((int)COSE.KeyCommonParameter.Alg, alg);

            if (_type is COSE.KeyType.RSA)
            {
                var keyParams = cert.GetRSAPublicKey()!.ExportParameters(false);
                _cpk.Add((int)COSE.KeyTypeParameter.N, keyParams.Modulus!);
                _cpk.Add((int)COSE.KeyTypeParameter.E, keyParams.Exponent!);
            }
            else if (_type is COSE.KeyType.EC2)
            {
                var ecDsaPubKey = cert.GetECDsaPublicKey()!;
                var keyParams = ecDsaPubKey.ExportParameters(false);

                if (keyParams.Curve.Oid.FriendlyName is "secP256k1")
                    _cpk.Add((int)COSE.KeyTypeParameter.Crv, (int)COSE.EllipticCurve.P256K);

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (keyParams.Curve.Oid.FriendlyName!.Equals(ECCurve.NamedCurves.nistP256.Oid.FriendlyName, StringComparison.Ordinal))
                        _cpk.Add((int)COSE.KeyTypeParameter.Crv, (int)COSE.EllipticCurve.P256);

                    if (keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP384.Oid.FriendlyName, StringComparison.Ordinal))
                        _cpk.Add((int)COSE.KeyTypeParameter.Crv, (int)COSE.EllipticCurve.P384);

                    if (keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP521.Oid.FriendlyName, StringComparison.Ordinal))
                        _cpk.Add((int)COSE.KeyTypeParameter.Crv, (int)COSE.EllipticCurve.P521);
                }
                else
                {
                    if (keyParams.Curve.Oid.Value!.Equals(ECCurve.NamedCurves.nistP256.Oid.Value, StringComparison.Ordinal))
                        _cpk.Add((int)COSE.KeyTypeParameter.Crv, (int)COSE.EllipticCurve.P256);

                    if (keyParams.Curve.Oid.Value.Equals(ECCurve.NamedCurves.nistP384.Oid.Value, StringComparison.Ordinal))
                        _cpk.Add((int)COSE.KeyTypeParameter.Crv, (int)COSE.EllipticCurve.P384);
                    
                    if (keyParams.Curve.Oid.Value.Equals(ECCurve.NamedCurves.nistP521.Oid.Value, StringComparison.Ordinal))
                        _cpk.Add((int)COSE.KeyTypeParameter.Crv, (int)COSE.EllipticCurve.P521);
                }

                _cpk.Add((int)COSE.KeyTypeParameter.X, keyParams.Q.X!);
                _cpk.Add((int)COSE.KeyTypeParameter.Y, keyParams.Q.Y!);
            }
        }

        public bool Verify(ReadOnlySpan<byte> data, byte[] sig)
        {
            switch (_type)
            {
                case COSE.KeyType.EC2:
                    using(ECDsa ecdsa = CreateECDsa())
                    {
                        var ecsig = CryptoUtils.SigFromEcDsaSig(sig, ecdsa.KeySize);
                        return ecdsa.VerifyData(data, ecsig, CryptoUtils.HashAlgFromCOSEAlg(_alg));
                    }

                case COSE.KeyType.RSA:
                    using (RSA rsa = CreateRsa())
                    {
                        return rsa.VerifyData(data, sig, CryptoUtils.HashAlgFromCOSEAlg(_alg), Padding);
                    }

                case COSE.KeyType.OKP:
                    return SignatureAlgorithm.Ed25519.Verify(EdDSAPublicKey, data, sig);
            }
            throw new InvalidOperationException($"Missing or unknown kty {_type}");
        }

        internal RSA CreateRsa()
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

        internal ECDsa CreateECDsa()
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

            var crv = (COSE.EllipticCurve)(int)_cpk[new CborInteger((int)COSE.KeyTypeParameter.Crv)]!;

            // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves

            switch (_alg)
            {
                case COSE.Algorithm.ES256K when (crv is COSE.EllipticCurve.P256K):
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) // see https://github.com/dotnet/runtime/issues/47770
                    {
                        throw new PlatformNotSupportedException($"No support currently for secP256k1 on MacOS");
                    }

                    curve = ECCurve.CreateFromFriendlyName("secP256k1");
                    break;
                case COSE.Algorithm.ES256 when (crv is COSE.EllipticCurve.P256):
                    curve = ECCurve.NamedCurves.nistP256;             
                    break;
                case COSE.Algorithm.ES384 when (crv is COSE.EllipticCurve.P384):
                    curve = ECCurve.NamedCurves.nistP384;
                    break;                   
                case COSE.Algorithm.ES512 when(crv is COSE.EllipticCurve.P521):
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
                        var crv = (COSE.EllipticCurve)(int)_cpk[new CborInteger((int)COSE.KeyTypeParameter.Crv)]!;
                        switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                        {
                            case COSE.EllipticCurve.Ed25519:
                                return NSec.Cryptography.PublicKey.Import(SignatureAlgorithm.Ed25519, (byte[])_cpk[COSE.KeyTypeParameter.X], KeyBlobFormat.RawPublicKey);

                            default:
                                throw new InvalidOperationException($"Missing or unknown crv {crv}");
                        }
                    default:
                        throw new InvalidOperationException($"Missing or unknown alg {_alg}");
                }
            }
        }

        internal readonly COSE.KeyType _type;

        internal readonly COSE.Algorithm _alg;

        internal readonly CborMap _cpk;

        internal static readonly Dictionary<string, COSE.KeyType> CoseKeyTypeFromOid = new ()
        {
            { "1.2.840.10045.2.1", COSE.KeyType.EC2 },
            { "1.2.840.113549.1.1.1", COSE.KeyType.RSA}
        };

        public static CredentialPublicKey Decode(ReadOnlyMemory<byte> cpk, out int bytesRead)
        {
            var map = (CborMap)CborObject.Decode(cpk, out bytesRead);

            return new CredentialPublicKey(map);
        }

        public byte[] GetBytes()
        {
            return _cpk.Encode();
        }

        public bool IsSameAlg(COSE.Algorithm alg)
        {
            return _alg.Equals(alg);
        }

        public CborMap GetCborObject()
        {
            return _cpk;
        }
    }
}
