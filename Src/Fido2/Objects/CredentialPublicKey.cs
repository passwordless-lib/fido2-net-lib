using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Chaos.NaCl;
using PeterO.Cbor;

namespace Fido2NetLib.Objects
{
    public class CredentialPublicKey
    {
        public CredentialPublicKey(Stream stream) : this(CBORObject.Read(stream))
        {
        }

        public CredentialPublicKey(byte[] cpk) : this(CBORObject.DecodeFromBytes(cpk))
        {
        }

        public CredentialPublicKey(CBORObject cpk)
        {
            _cpk = cpk;
            _type = (COSE.KeyType)cpk[CBORObject.FromObject(COSE.KeyCommonParameter.KeyType)].AsInt32();
            _alg = (COSE.Algorithm)cpk[CBORObject.FromObject(COSE.KeyCommonParameter.Alg)].AsInt32();
        }

        public CredentialPublicKey(X509Certificate2 cert, int alg)
        {
            _cpk = CBORObject.NewMap();
            var keyAlg = cert.GetKeyAlgorithm();
            _type = CoseKeyTypeFromOid[keyAlg];
            _alg = (COSE.Algorithm)alg;
            _cpk.Add(COSE.KeyCommonParameter.KeyType, _type);
            _cpk.Add(COSE.KeyCommonParameter.Alg, alg);
            if (COSE.KeyType.RSA == _type)
            {
                var keyParams = cert.GetRSAPublicKey().ExportParameters(false);
                _cpk.Add(COSE.KeyTypeParameter.N, keyParams.Modulus);
                _cpk.Add(COSE.KeyTypeParameter.E, keyParams.Exponent);
            }
            if (COSE.KeyType.EC2 == _type)
            {
                var ecDsaPubKey = cert.GetECDsaPublicKey();
                var keyParams = ecDsaPubKey.ExportParameters(false);

                if (keyParams.Curve.Oid.FriendlyName.Equals("secP256k1"))
                    _cpk.Add(COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.P256K);

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP256.Oid.FriendlyName))
                        _cpk.Add(COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.P256);

                    if (keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP384.Oid.FriendlyName))
                        _cpk.Add(COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.P384);

                    if (keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP521.Oid.FriendlyName))
                        _cpk.Add(COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.P521);
                }
                else
                {
                    if (keyParams.Curve.Oid.Value.Equals(ECCurve.NamedCurves.nistP256.Oid.Value))
                        _cpk.Add(COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.P256);

                    if (keyParams.Curve.Oid.Value.Equals(ECCurve.NamedCurves.nistP384.Oid.Value))
                        _cpk.Add(COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.P384);
                    
                    if (keyParams.Curve.Oid.Value.Equals(ECCurve.NamedCurves.nistP521.Oid.Value))
                        _cpk.Add(COSE.KeyTypeParameter.Crv, COSE.EllipticCurve.P521);
                }

                _cpk.Add(COSE.KeyTypeParameter.X, keyParams.Q.X);
                _cpk.Add(COSE.KeyTypeParameter.Y, keyParams.Q.Y);
            }
        }

        public bool Verify(byte[] data, byte[] sig)
        {
            switch (_type)
            {
                case COSE.KeyType.EC2:
                    using(ECDsa ecdsa = CreateECDsa())
                    {
                        var ecsig = CryptoUtils.SigFromEcDsaSig(sig, ecdsa.KeySize);
                        return ecdsa.VerifyData(data, ecsig, CryptoUtils.algMap[(int)_alg]);
                    }

                case COSE.KeyType.RSA:
                    using (RSA rsa = CreateRsa())
                    {
                        return rsa.VerifyData(data, sig, CryptoUtils.algMap[(int)_alg], Padding);
                    }

                case COSE.KeyType.OKP:
                    return Ed25519.Verify(sig, data, EdDSAPublicKey);
            }
            throw new InvalidOperationException($"Missing or unknown kty {_type}");
        }

        internal RSA CreateRsa()
        {
            if (_type == COSE.KeyType.RSA)
            {
                var rsa = RSA.Create();
                rsa.ImportParameters(
                    new RSAParameters()
                    {
                        Modulus = _cpk[CBORObject.FromObject(COSE.KeyTypeParameter.N)].GetByteString(),
                        Exponent = _cpk[CBORObject.FromObject(COSE.KeyTypeParameter.E)].GetByteString()
                    }
                );
                return rsa;
            }
            return null;
        }

        internal ECDsa CreateECDsa()
        {
            if (_type == COSE.KeyType.EC2)
            {
                var point = new ECPoint
                {
                    X = _cpk[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString(),
                    Y = _cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Y)].GetByteString(),
                };
                ECCurve curve;
                var crv = (COSE.EllipticCurve)_cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Crv)].AsInt32();
                switch (_alg)
                {
                    case COSE.Algorithm.ES256:
                        switch (crv)
                        {
                            case COSE.EllipticCurve.P256:
                            case COSE.EllipticCurve.P256K:
                                curve = ECCurve.NamedCurves.nistP256;
                                break;
                            default:
                                throw new InvalidOperationException($"Missing or unknown crv {crv}");
                        }
                        break;
                    case COSE.Algorithm.ES384:
                        switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                        {
                            case COSE.EllipticCurve.P384:
                                curve = ECCurve.NamedCurves.nistP384;
                                break;
                            default:
                                throw new InvalidOperationException($"Missing or unknown crv {crv}");
                        }
                        break;
                    case COSE.Algorithm.ES512:
                        switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                        {
                            case COSE.EllipticCurve.P521:
                                curve = ECCurve.NamedCurves.nistP521;
                                break;
                            default:
                                throw new InvalidOperationException($"Missing or unknown crv {crv}");
                        }
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
            return null;
        }

        internal RSASignaturePadding Padding
        {
            get
            {
                if (_type == COSE.KeyType.RSA)
                {
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
                return null;
            }
        }

        internal byte[] EdDSAPublicKey
        {
            get
            {
                if (_type == COSE.KeyType.OKP)
                {
                    switch (_alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                    {
                        case COSE.Algorithm.EdDSA:
                            var crv = (COSE.EllipticCurve)_cpk[CBORObject.FromObject(COSE.KeyTypeParameter.Crv)].AsInt32();
                            switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                            {
                                case COSE.EllipticCurve.Ed25519:
                                    return _cpk[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString();

                                default:
                                    throw new InvalidOperationException($"Missing or unknown crv {crv}");
                            }
                        default:
                            throw new InvalidOperationException($"Missing or unknown alg {_alg}");
                    }
                }
                return null;
            }
        }

        internal readonly COSE.KeyType _type;

        internal readonly COSE.Algorithm _alg;

        internal readonly CBORObject _cpk;

        internal static readonly Dictionary<string, COSE.KeyType> CoseKeyTypeFromOid = new Dictionary<string, COSE.KeyType>
        {
            { "1.2.840.10045.2.1", COSE.KeyType.EC2 },
            { "1.2.840.113549.1.1.1", COSE.KeyType.RSA}
        };

        public override string ToString()
        {
            return _cpk.ToString();
        }

        public byte[] GetBytes()
        {
            return _cpk.EncodeToBytes();
        }

        public bool IsSameAlg(COSE.Algorithm alg)
        {
            return _alg.Equals(alg);
        }

        public CBORObject GetCBORObject()
        {
            return _cpk;
        }
    }
}
