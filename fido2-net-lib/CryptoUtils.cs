using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PeterO.Cbor;

namespace Fido2NetLib
{
    public static class CryptoUtils
    {
        public static HashAlgorithm GetHasher(HashAlgorithmName hashName)
        {
            switch (hashName.Name)
            {
                case "SHA1":
                    return SHA1.Create();
                case "SHA256":
                case "HS256":
                case "RS256":
                case "ES256":
                case "PS256":
                    return SHA256.Create();
                case "SHA384":
                case "HS384":
                case "RS384":
                case "ES384":
                case "PS384":
                    return SHA384.Create();
                case "SHA512":
                case "HS512":
                case "RS512":
                case "ES512":
                case "PS512":
                    return SHA512.Create();
                default:
                    throw new ArgumentOutOfRangeException("hashName");
            }
        }
        public static readonly Dictionary<int, HashAlgorithmName> algMap = new Dictionary<int, HashAlgorithmName>
        {
            {-65535, HashAlgorithmName.SHA1 },
            {-7, HashAlgorithmName.SHA256},
            {-35, HashAlgorithmName.SHA384 },
            {-36, HashAlgorithmName.SHA512 },
            {-37, HashAlgorithmName.SHA256 },
            {-38, HashAlgorithmName.SHA384 },
            {-39, HashAlgorithmName.SHA512 },
            {-257, HashAlgorithmName.SHA256 },
            {-258, HashAlgorithmName.SHA384 },
            {-259, HashAlgorithmName.SHA512 },
            {4, HashAlgorithmName.SHA1 },
            {11, HashAlgorithmName.SHA256 },
            {12, HashAlgorithmName.SHA384 },
            {13, HashAlgorithmName.SHA512 }
        };
        public static readonly Dictionary<string, int> CoseKeyTypeFromOid = new Dictionary<string, int>
        {
            { "1.2.840.10045.2.1", 2 }, // ECC
            { "1.2.840.113549.1.1.1", 3} // RSA
        };

        public static CBORObject CoseKeyFromCertAndAlg(X509Certificate2 cert, int alg)
        {
            var coseKey = CBORObject.NewMap();
            var kty = CoseKeyTypeFromOid[cert.GetKeyAlgorithm()];
            coseKey.Add(1, kty);
            coseKey.Add(3, alg);
            if (3 == kty)
            {
                var keyParams = cert.GetRSAPublicKey().ExportParameters(false);
                coseKey.Add(-1, keyParams.Modulus);
                coseKey.Add(-2, keyParams.Exponent);
            }
            if (2 == kty)
            {
                var ecDsaPubKey = (ECDsaCng)cert.GetECDsaPublicKey();
                var keyParams = ecDsaPubKey.ExportParameters(false);
                if (keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP256.Oid.FriendlyName)) coseKey.Add(-1, 1);
                if (keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP384.Oid.FriendlyName)) coseKey.Add(-1, 2);
                if (keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP521.Oid.FriendlyName)) coseKey.Add(-1, 3);
                coseKey.Add(-2, keyParams.Q.X);
                coseKey.Add(-3, keyParams.Q.Y);
            }
            return coseKey;
        }
        public static bool VerifySigWithCoseKey(byte[] data, CBORObject coseKey, byte[] sig)
        {
            // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData
            var kty = coseKey[CBORObject.FromObject(1)].AsInt32();
            var alg = coseKey[CBORObject.FromObject(3)].AsInt32();
            var crv = 0;
            if (1 == kty || 2 == kty) crv = coseKey[CBORObject.FromObject(-1)].AsInt32();
            switch (kty) // https://www.iana.org/assignments/cose/cose.xhtml#key-type
            {
                case 1: // OKP
                    {
                        switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                        {
                            case -8:
                                switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                                {
                                    case 6:
                                        return Chaos.NaCl.Ed25519.Verify(sig, GetHasher(HashAlgorithmName.SHA512).ComputeHash(data), coseKey[CBORObject.FromObject(-2)].GetByteString());
                                    default:
                                        throw new ArgumentOutOfRangeException("crv");
                                }
                            default:
                                throw new ArgumentOutOfRangeException("alg");
                        }
                    }
                case 2: // EC2
                    {
                        var point = new ECPoint
                        {
                            X = coseKey[CBORObject.FromObject(-2)].GetByteString(),
                            Y = coseKey[CBORObject.FromObject(-3)].GetByteString()
                        };
                        ECCurve curve;
                        switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                        {
                            case -7:
                                switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                                {
                                    case 1:
                                    case 8:
                                        curve = ECCurve.NamedCurves.nistP256;
                                        break;
                                    default:
                                        throw new ArgumentOutOfRangeException("crv");
                                }
                                break;
                            case -35:
                                switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                                {
                                    case 2:
                                        curve = ECCurve.NamedCurves.nistP384;
                                        break;
                                    default:
                                        throw new ArgumentOutOfRangeException("crv");
                                }
                                break;
                            case -36:
                                switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                                {
                                    case 3:
                                        curve = ECCurve.NamedCurves.nistP521;
                                        System.Diagnostics.Debug.WriteLine(BitConverter.ToString(sig).Replace("-", ""));
                                        System.Diagnostics.Debug.WriteLine(BitConverter.ToString(sig));
                                        System.Diagnostics.Debug.WriteLine(BitConverter.ToString(point.X));
                                        System.Diagnostics.Debug.WriteLine(BitConverter.ToString(point.Y));
                                        System.Diagnostics.Debug.WriteLine(BitConverter.ToString(data));
                                        break;
                                    default:
                                        throw new ArgumentOutOfRangeException("crv");
                                }
                                break;
                            default:
                                throw new ArgumentOutOfRangeException("alg");
                        }
                        var cng = ECDsa.Create(new ECParameters
                        {
                            Q = point,
                            Curve = curve
                        });
                        var ecsig = SigFromEcDsaSig(sig);
                        System.Diagnostics.Debug.WriteLine(BitConverter.ToString(ecsig).Replace("-", ""));
                        return cng.VerifyData(data, ecsig, algMap[alg]);
                    }
                case 3: // RSA
                    {
                        var rsa = new RSACng();
                        rsa.ImportParameters(
                            new RSAParameters()
                            {
                                Modulus = coseKey[CBORObject.FromObject(-1)].GetByteString(),
                                Exponent = coseKey[CBORObject.FromObject(-2)].GetByteString()
                            }
                        );
                        RSASignaturePadding padding;
                        switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                        {

                            case -37:
                            case -38:
                            case -39:
                                padding = RSASignaturePadding.Pss;
                                break;

                            case -65535:
                            case -257:
                            case -258:
                            case -259:
                                padding = RSASignaturePadding.Pkcs1;
                                break;
                            default:
                                throw new ArgumentOutOfRangeException("alg");
                        }
                        return rsa.VerifyData(data, sig, algMap[alg], padding);
                    }
            }
            throw new Fido2VerificationException("Missing or unknown keytype");
        }
        public static Memory<byte> U2FKeyFromCOSEKey(CBORObject COSEKey)
        {
            var x = COSEKey[CBORObject.FromObject(-2)].GetByteString();
            var y = COSEKey[CBORObject.FromObject(-3)].GetByteString();
            var publicKeyU2F = new byte[1] { 0x4 }; // uncompressed
            return publicKeyU2F.Concat(x).Concat(y).ToArray();
        }

        public static byte[] SigFromEcDsaSig(byte[] ecDsaSig)
        {
            // sanity check of input data
            if (null == ecDsaSig || 0 == ecDsaSig.Length || ecDsaSig.Length > ushort.MaxValue) throw new Fido2VerificationException("Invalid ECDsa signature value");
            // first byte should be DER sequence marker
            var offset = 0;
            var derSequence = AuthDataHelper.GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == derSequence || 0x30 != derSequence[0]) throw new Fido2VerificationException("ECDsa signature not a valid DER sequence");
            // two forms of length, short form and long form
            // short form, one byte, bit 8 not set, rest of the bits indicate data length
            var dataLen = AuthDataHelper.GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == dataLen) throw new Fido2VerificationException("ECDsa signature has invalid length");
            // long form, first byte, bit 8 is set, rest of bits indicate the length of the data length
            // so if bit 8 is on...
            var longForm = (0 != (dataLen[0] & (1 << 7)));
            if (true == longForm)
            {
                // rest of bits indicate the length of the data length
                var longLen = (dataLen[0] & ~(1 << 7));
                // sanity check of input data
                if (ushort.MinValue > longLen || ushort.MaxValue < longLen) throw new Fido2VerificationException("ECDsa signature has invalid long form length");
                // total length of remaining data
                var longLenByte = AuthDataHelper.GetSizedByteArray(ecDsaSig, ref offset, (ushort)longLen);
                if (null == longLenByte) throw new Fido2VerificationException("ECDsa signature has invalid long form length");
                longLen = longLenByte[0];
                // sanity check the length
                if (ecDsaSig.Length != (offset + longLen)) throw new Fido2VerificationException("ECDsa signature has invalid long form length");
            }

            // Get R value
            var r = GetEcDsaSigValue(ecDsaSig, ref offset, longForm);
            if (null == r) throw new Fido2VerificationException("ECDsa signature R integer value invalid");

            // Get S value
            var s = GetEcDsaSigValue(ecDsaSig, ref offset, longForm);
            if (null == s) throw new Fido2VerificationException("ECDsa signature S integer value invalid");

            // make sure we are at the end
            if (ecDsaSig.Length != offset) throw new Fido2VerificationException("ECDsa signature has bytes leftover after parsing R and S values");

            // combine the coordinates and return the raw sign
            var sig = new byte[s.Length + r.Length];
            Buffer.BlockCopy(r, 0, sig, 0, r.Length);
            Buffer.BlockCopy(s, 0, sig, r.Length, s.Length);
            return sig;
        }
        public static byte[] GetEcDsaSigValue(byte[] ecDsaSig, ref int offset, bool longForm)
        {
            var derInt = AuthDataHelper.GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == derInt || 0x02 != derInt[0]) throw new Fido2VerificationException("ECDsa signature coordinate sequence does not contain DER integer value"); // DER INTEGER
            var lenByte = AuthDataHelper.GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == lenByte) throw new Fido2VerificationException("ECDsa signature coordinate integer size invalid");
            var len = (ushort)lenByte[0];
            if (false == longForm)
            {
                /*
                 *  Ecdsa-Sig-Value  ::=  SEQUENCE  {
                 *       r     INTEGER,
                 *       s     INTEGER  } 
                 *       
                 *  From: https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/about-integer
                 *  
                 *  "Integer values are encoded into a TLV triplet that begins with a Tag value of 0x02. 
                 *  The Value field of the TLV triplet contains the encoded integer if it is positive, 
                 *  or its two's complement if it is negative. If the integer is positive but the high 
                 *  order bit is set to 1, a leading 0x00 is added to the content to indicate that the
                 *  number is not negative."
                 *  
                 */
                if (0x00 == ecDsaSig[offset] && ((ecDsaSig[offset + 1] & (1 << 7)) != 0))
                {
                    offset++;
                    len--;
                }
            }
            return AuthDataHelper.GetSizedByteArray(ecDsaSig, ref offset, len);
        }
    }
}
