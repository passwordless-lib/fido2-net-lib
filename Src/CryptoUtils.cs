using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using LipingShare.LCLib.Asn1Processor;
using PeterO.Cbor;
using Fido2NetLib.Objects;

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
            {(int) COSE.Algorithms.RS1, HashAlgorithmName.SHA1 },
            {(int) COSE.Algorithms.ES256, HashAlgorithmName.SHA256},
            {(int) COSE.Algorithms.ES384, HashAlgorithmName.SHA384 },
            {(int) COSE.Algorithms.ES512, HashAlgorithmName.SHA512 },
            {(int) COSE.Algorithms.PS256, HashAlgorithmName.SHA256 },
            {(int) COSE.Algorithms.PS384, HashAlgorithmName.SHA384 },
            {(int) COSE.Algorithms.PS512, HashAlgorithmName.SHA512 },
            {(int) COSE.Algorithms.RS256, HashAlgorithmName.SHA256 },
            {(int) COSE.Algorithms.RS384, HashAlgorithmName.SHA384 },
            {(int) COSE.Algorithms.RS512, HashAlgorithmName.SHA512 },
            {4, HashAlgorithmName.SHA1 },
            {11, HashAlgorithmName.SHA256 },
            {12, HashAlgorithmName.SHA384 },
            {13, HashAlgorithmName.SHA512 }
        };
        public static readonly Dictionary<string, COSE.KeyTypes> CoseKeyTypeFromOid = new Dictionary<string, COSE.KeyTypes>
        {
            { "1.2.840.10045.2.1", COSE.KeyTypes.EC2 },
            { "1.2.840.113549.1.1.1", COSE.KeyTypes.RSA}
        };

        public static CBORObject CoseKeyFromCertAndAlg(X509Certificate2 cert, int alg)
        {
            var coseKey = CBORObject.NewMap();
            var keyAlg = cert.GetKeyAlgorithm();
            var kty = CoseKeyTypeFromOid[keyAlg];
            coseKey.Add(COSE.KeyCommonParameters.kty, kty);
            coseKey.Add(COSE.KeyCommonParameters.alg, alg);
            if (COSE.KeyTypes.RSA == kty)
            {
                var keyParams = cert.GetRSAPublicKey().ExportParameters(false);
                coseKey.Add(COSE.KeyTypeParameters.n, keyParams.Modulus);
                coseKey.Add(COSE.KeyTypeParameters.e, keyParams.Exponent);
            }
            if (COSE.KeyTypes.EC2 == kty)
            {
                var ecDsaPubKey = (ECDsaCng)cert.GetECDsaPublicKey();
                var keyParams = ecDsaPubKey.ExportParameters(false);

                if (keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP256.Oid.FriendlyName))
                    coseKey.Add(COSE.KeyTypeParameters.crv, COSE.EllipticCurves.P256);

                if (keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP384.Oid.FriendlyName))
                    coseKey.Add(COSE.KeyTypeParameters.crv, COSE.EllipticCurves.P384);

                if (keyParams.Curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP521.Oid.FriendlyName))
                    coseKey.Add(COSE.KeyTypeParameters.crv, COSE.EllipticCurves.P521);

                coseKey.Add(COSE.KeyTypeParameters.x, keyParams.Q.X);
                coseKey.Add(COSE.KeyTypeParameters.y, keyParams.Q.Y);
            }
            return coseKey;
        }
        public static bool VerifySigWithCoseKey(byte[] data, CBORObject coseKey, byte[] sig)
        {
            // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData
            var kty = coseKey[CBORObject.FromObject(COSE.KeyCommonParameters.kty)].AsInt32();
            var alg = coseKey[CBORObject.FromObject(COSE.KeyCommonParameters.alg)].AsInt32();
            var crv = 0;
            if (COSE.KeyTypes.OKP == (COSE.KeyTypes) kty || COSE.KeyTypes.EC2 == (COSE.KeyTypes) kty)
                crv = coseKey[CBORObject.FromObject(COSE.KeyTypeParameters.crv)].AsInt32();
            switch (kty) // https://www.iana.org/assignments/cose/cose.xhtml#key-type
            {
                case (int) COSE.KeyTypes.OKP: // OKP
                    {
                        switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                        {
                            case (int) COSE.Algorithms.EdDSA:
                                switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                                {
                                    case (int) COSE.EllipticCurves.Ed25519:
                                        var message = GetHasher(HashAlgorithmName.SHA512).ComputeHash(data);
                                        var publicKey = coseKey[CBORObject.FromObject(COSE.KeyTypeParameters.x)].GetByteString();
                                        return Chaos.NaCl.Ed25519.Verify(sig, message, publicKey);
                                    default:
                                        throw new ArgumentOutOfRangeException(string.Format("Missing or unknown crv {0}", crv.ToString()));
                                }
                            default:
                                throw new ArgumentOutOfRangeException(string.Format("Missing or unknown alg {0}", alg.ToString()));
                        }
                    }
                case (int) COSE.KeyTypes.EC2: // EC2
                    {
                        var point = new ECPoint
                        {
                            X = coseKey[CBORObject.FromObject(COSE.KeyTypeParameters.x)].GetByteString(),
                            Y = coseKey[CBORObject.FromObject(COSE.KeyTypeParameters.y)].GetByteString()
                        };
                        ECCurve curve;
                        switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                        {
                            case (int) COSE.Algorithms.ES256:
                                switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                                {
                                    case (int) COSE.EllipticCurves.P256:
                                    case (int) COSE.EllipticCurves.P256K:
                                        curve = ECCurve.NamedCurves.nistP256;
                                        break;
                                    default:
                                        throw new ArgumentOutOfRangeException(string.Format("Missing or unknown crv {0}", crv.ToString()));
                                }
                                break;
                            case (int) COSE.Algorithms.ES384:
                                switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                                {
                                    case (int) COSE.EllipticCurves.P384:
                                        curve = ECCurve.NamedCurves.nistP384;
                                        break;
                                    default:
                                        throw new ArgumentOutOfRangeException(string.Format("Missing or unknown crv {0}", crv.ToString()));
                                }
                                break;
                            case (int) COSE.Algorithms.ES512:
                                switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                                {
                                    case (int) COSE.EllipticCurves.P521:
                                        curve = ECCurve.NamedCurves.nistP521;
                                        break;
                                    default:
                                        throw new ArgumentOutOfRangeException(string.Format("Missing or unknown crv {0}", crv.ToString()));
                                }
                                break;
                            default:
                                throw new ArgumentOutOfRangeException(string.Format("Missing or unknown alg {0}", alg.ToString()));
                        }
                        var cng = ECDsa.Create(new ECParameters
                        {
                            Q = point,
                            Curve = curve
                        });
                        var ecsig = SigFromEcDsaSig(sig, cng.KeySize);
                        return cng.VerifyData(data, ecsig, algMap[alg]);
                    }
                case (int) COSE.KeyTypes.RSA: // RSA
                    {
                        var rsa = new RSACng();
                        rsa.ImportParameters(
                            new RSAParameters()
                            {
                                Modulus = coseKey[CBORObject.FromObject(COSE.KeyTypeParameters.n)].GetByteString(),
                                Exponent = coseKey[CBORObject.FromObject(COSE.KeyTypeParameters.e)].GetByteString()
                            }
                        );
                        RSASignaturePadding padding;
                        switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                        {

                            case (int) COSE.Algorithms.PS256:
                            case (int) COSE.Algorithms.PS384:
                            case (int) COSE.Algorithms.PS512:
                                padding = RSASignaturePadding.Pss;
                                break;

                            case (int) COSE.Algorithms.RS1:
                            case (int) COSE.Algorithms.RS256:
                            case (int) COSE.Algorithms.RS384:
                            case (int) COSE.Algorithms.RS512:
                                padding = RSASignaturePadding.Pkcs1;
                                break;
                            default:
                                throw new ArgumentOutOfRangeException(string.Format("Missing or unknown alg {0}", alg.ToString()));
                        }
                        return rsa.VerifyData(data, sig, algMap[alg], padding);
                    }
            }
            throw new ArgumentOutOfRangeException(string.Format("Missing or unknown kty {0}", kty.ToString()));
        }
        public static Memory<byte> U2FKeyFromCOSEKey(CBORObject COSEKey)
        {
            var x = COSEKey[CBORObject.FromObject(COSE.KeyTypeParameters.x)].GetByteString();
            var y = COSEKey[CBORObject.FromObject(COSE.KeyTypeParameters.y)].GetByteString();
            var publicKeyU2F = new byte[1] { 0x4 }; // uncompressed
            return publicKeyU2F.Concat(x).Concat(y).ToArray();
        }

        public static byte[] SigFromEcDsaSig(byte[] ecDsaSig, int keySize)
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

            // .NET requires IEEE P-1363 fixed size unsigned big endian values for R and S
            // ASN.1 requires storing positive integer values with any leading 0s removed
            // Convert ASN.1 format to IEEE P-1363 format 
            // determine coefficient size 
            var coefficientSize = (int)Math.Ceiling((decimal)keySize / 8);

            // Sanity check R and S value lengths
            if ((coefficientSize * 2) < (r.Length + s.Length)) throw new Fido2VerificationException("ECDsa signature has invalid length for given curve key size");

            // Create byte array to copy R into 
            var P1363R = new byte[coefficientSize];

            // Copy reversed ASN.1 R value to P1363R buffer, to get trailing zeroes if needed
            Buffer.BlockCopy(r.Reverse().ToArray(), 0, P1363R, 0, r.Length);

            // Create byte array to copy S into 
            var P1363S = new byte[coefficientSize];

            // Copy reversed ASN.1 S value to P1363S buffer, to get trailing zeroes if needed
            Buffer.BlockCopy(s.Reverse().ToArray(), 0, P1363S, 0, s.Length);

            // Reverse and combine each coordinate and return the raw signature
            // Any trailing zeroes will become leading zeroes
            var sig = P1363R.Reverse().ToArray().Concat(P1363S.Reverse().ToArray()).ToArray();

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
        public static string CDPFromCertificateExts(X509ExtensionCollection exts)
        {
            var cdp = "";
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.31")) // id-ce-CRLDistributionPoints
                {
                    var asnData = new AsnEncodedData(ext.Oid, ext.RawData);
                    cdp += asnData.Format(false).Split('=')[1];
                }
            }
            return cdp;
        }
        public static bool IsCertInCRL(byte[] crl, X509Certificate2 cert)
        {
            var asnParser = new Asn1Parser();
            var strCRL = Asn1Util.BytesToString(crl);

            if (Asn1Util.IsPemFormated(strCRL))
            {
                asnParser.LoadData(Asn1Util.PemToStream(strCRL));
            }
            else asnParser.LoadData(new System.IO.MemoryStream(crl));

            if (7 > asnParser.RootNode.GetChildNode(0).ChildNodeCount)
                return false; // empty CRL

            var revokedCertificates = asnParser.RootNode.GetChildNode(0).GetChildNode(5);

            // throw revoked certs into a list so someday we eventually cache CRLs 
            var revoked = new List<long>();
            for (var i = 0;i < revokedCertificates.ChildNodeCount;i++)
            {
                revoked.Add(Asn1Util.BytesToLong(revokedCertificates.GetChildNode(i).GetChildNode(0).Data.Reverse().ToArray()));
            }

            if (revoked.Contains(Asn1Util.BytesToLong(cert.GetSerialNumber())))
                return true;
            
            else return false;
        }
    }
}
