using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Fido2NetLib
{
    /// <summary>
    /// Helper functions that implements https://w3c.github.io/webauthn/#authenticator-data
    /// </summary>
    public static class AuthDataHelper
    {
        public static HashAlgorithm GetHasher(HashAlgorithmName hashName)
        {
            switch (hashName.Name)
            {
                case "SHA1":
                    return SHA1.Create();
                case "SHA256":
                    return SHA256.Create();
                case "SHA384":
                    return SHA384.Create();
                case "SHA512":
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
        public static string CoseToFido(Int32 kty, Int32 alg, Int32 crv)
        {
            switch (kty) // https://www.iana.org/assignments/cose/cose.xhtml#key-type
            {
                case 1: // OKP
                    switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                    {
                        case -8:
                            switch (crv) // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
                            {
                                case 6:
                                    return "ALG_SIGN_ED25519_EDDSA_SHA256_RAW";
                                default:
                                    throw new ArgumentOutOfRangeException("crv");
                            }
                        default:
                            throw new ArgumentOutOfRangeException("alg");
                    }
                case 2: // EC2
                    switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                    {
                        case -7:
                            switch (crv)
                            {
                                case 1:
                                    return "ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW";
                                case 8:
                                    return "ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW";
                                default:
                                    throw new ArgumentOutOfRangeException("crv");
                            }
                        case -35:
                            switch (crv)
                            {
                                case 2:
                                    return "ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW";
                                default:
                                    throw new ArgumentOutOfRangeException("crv");
                            }
                        case -36:
                            switch (crv)
                            {
                                case 3:
                                    return "ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW";
                                default:
                                    throw new ArgumentOutOfRangeException("crv");
                            }
                        default:
                            throw new ArgumentOutOfRangeException("alg");
                    }
                case 3: // RSA
                    switch (alg) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                    {
                        case -37:
                            return "ALG_SIGN_RSASSA_PSS_SHA256_RAW";
                        case -38:
                            return "ALG_SIGN_RSASSA_PSS_SHA384_RAW";
                        case -39:
                            return "ALG_SIGN_RSASSA_PSS_SHA512_RAW";
                        case -65535:
                            return "ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW";
                        case -257:
                            return "ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW";
                        case -258:
                            return "ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW";
                        case -259:
                            return "ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW";
                        default:
                            throw new ArgumentOutOfRangeException("alg");
                    }
                case 4: // Symmetric
                    throw new Fido2VerificationException("Symmetric keys not supported");
                default:
                    throw new ArgumentOutOfRangeException("kty");
            }
        }
        public static bool VerifySigWithCoseKey(byte[] data, PeterO.Cbor.CBORObject coseKey, byte[] sig)
        {
            // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData
            var coseKty = coseKey[PeterO.Cbor.CBORObject.FromObject(1)].AsInt32();
            var coseAlg = coseKey[PeterO.Cbor.CBORObject.FromObject(3)].AsInt32();
            var packedCrv = 0;
            if (1 == coseKty || 2 == coseKty) packedCrv = coseKey[PeterO.Cbor.CBORObject.FromObject(-1)].AsInt32();
            var FidoAlg = CoseToFido(coseKty, coseAlg, packedCrv);
            if (1 == coseKty)
            {
                if (true == FidoAlg.Equals("ALG_SIGN_ED25519_EDDSA_SHA512_RAW")) throw new Fido2VerificationException("ALG_SIGN_ED25519_EDDSA_SHA512_RAW support not yet implmented");
                else throw new Fido2VerificationException("Unknown algorithm");
            }
            else if (2 == coseKty)
            {
                var x = coseKey[PeterO.Cbor.CBORObject.FromObject(-2)].GetByteString();
                var y = coseKey[PeterO.Cbor.CBORObject.FromObject(-3)].GetByteString();
                var curve = ECCurve.NamedCurves.nistP256;
                if (FidoAlg.Equals("ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW")) curve = ECCurve.NamedCurves.nistP384;
                if (FidoAlg.Equals("ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW")) curve = ECCurve.NamedCurves.nistP521;
                var cng = ECDsaCng.Create(new ECParameters
                {
                    Curve = curve,
                    Q = new ECPoint
                    {
                        X = x,
                        Y = y
                    }
                });
                var ecsig = SigFromEcDsaSig(sig);
                // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg
                return cng.VerifyData(data, ecsig, algMap[coseAlg]);
            }
            else if (3 == coseKty)
            {
                RSACng rsa = new RSACng();
                rsa.ImportParameters(
                    new RSAParameters()
                    {
                        Modulus = coseKey[PeterO.Cbor.CBORObject.FromObject(-1)].GetByteString(),
                        Exponent = coseKey[PeterO.Cbor.CBORObject.FromObject(-2)].GetByteString()
                    }
                    );

                if (FidoAlg.Contains("RSASSA_PKCSV15"))
                    return rsa.VerifyData(data, sig, algMap[coseAlg], RSASignaturePadding.Pkcs1);
                if (FidoAlg.Contains("RSASSA_PSS"))
                    return rsa.VerifyData(data, sig, algMap[coseAlg], RSASignaturePadding.Pss);
            }
            else throw new Fido2VerificationException("Missing or unknown keytype");
            return false;
        }
        public static byte[] AaguidFromAttnCertExts(X509ExtensionCollection exts)
        {
            byte[] aaguid = null;
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.1.1.4")) // id-fido-gen-ce-aaguid
                {
                    aaguid = new byte[16];
                    var ms = new System.IO.MemoryStream(ext.RawData.ToArray());
                    // OCTET STRING
                    if (0x4 != ms.ReadByte()) throw new Fido2VerificationException();
                    // AAGUID
                    if (0x10 != ms.ReadByte()) throw new Fido2VerificationException();
                    ms.Read(aaguid, 0, 0x10);
                    //The extension MUST NOT be marked as critical
                    if (true == ext.Critical) throw new Fido2VerificationException();
                }
            }
            return aaguid;
        }
        public static string SANFromAttnCertExts(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.17")) // subject alternative name
                {
                    var asn = new AsnEncodedData(ext.Oid, ext.RawData);
                    return asn.Format(true);
                }
            }
            return null;
        }
        public static string EKUFromAttnCertExts(X509ExtensionCollection exts)
        {
            var EKU = new byte[0];
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.37")) // EKU
                {
                    var asn = new AsnEncodedData(ext.Oid, ext.RawData);
                    return asn.Format(false);
                }
            }
            return null;
        }
        public static bool IsAttnCertCACert(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.FriendlyName == "Basic Constraints")
                {
                    X509BasicConstraintsExtension baseExt = (X509BasicConstraintsExtension)ext;
                    return baseExt.CertificateAuthority;
                }
            }
            return true;
        }

        public static int U2FTransportsFromAttnCert(X509ExtensionCollection exts)
        {
            var u2ftransports = 0;
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.2.1.1"))
                {
                    var ms = new System.IO.MemoryStream(ext.RawData.ToArray());
                    // BIT STRING
                    if (0x3 != ms.ReadByte()) throw new Fido2VerificationException();
                    if (0x2 != ms.ReadByte()) throw new Fido2VerificationException();
                    var unused = ms.ReadByte(); // unused byte
                    // https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-authenticator-transports-extension-v1.1-id-20160915.html#fido-u2f-certificate-transports-extension
                    u2ftransports = ms.ReadByte(); // do something with this?
                }
            }
            return u2ftransports;
        }

        public static bool IsValidPackedAttnCertSubject(string attnCertSubj)
        {
            var dictSubject = attnCertSubj.Split(", ").Select(part => part.Split('=')).ToDictionary(split => split[0], split => split[1]);
            return (0 != dictSubject["C"].Length ||
                0 != dictSubject["O"].Length ||
                0 != dictSubject["OU"].Length ||
                0 != dictSubject["CN"].Length ||
                "Authenticator Attestation" == dictSubject["OU"].ToString());
        }

        public static Memory<byte> U2FKeyFromCOSEKey(PeterO.Cbor.CBORObject COSEKey)
        {
            var x = COSEKey[PeterO.Cbor.CBORObject.FromObject(-2)].GetByteString();
            var y = COSEKey[PeterO.Cbor.CBORObject.FromObject(-3)].GetByteString();
            var publicKeyU2F = new byte[1] { 0x4 }; // uncompressed
            return  publicKeyU2F.Concat(x).Concat(y).ToArray();
        }

        public static byte[] ParseSigData(ReadOnlySpan<byte> sigData)
        {

            if (sigData.IsEmpty || (sigData.Length > Math.Pow(2, 1008))) return null;

            var ms = new System.IO.MemoryStream(sigData.ToArray());
            if (0x30 != ms.ReadByte()) throw new Fido2VerificationException("Invalid DER sequence"); // DER SEQUENCE
            var dataLen = ms.ReadByte(); // length of r + s
            bool longForm = (dataLen > 127);
            var longLen = 0;
            if (true == longForm)
            {
                longLen = ms.ReadByte();
                var mask = 1 << 7;
                longLen &= ~mask;
            }
            if (0x2 != ms.ReadByte()) throw new Fido2VerificationException(); // DER INTEGER
            var rLen = ms.ReadByte(); // length of r
            if (false == longForm)
            {
                if (0 != (rLen % 8)) // must be on 8 byte boundary
                {
                    if (0 == ms.ReadByte()) rLen--; // strip leading 0x00
                    else throw new Fido2VerificationException();
                }
            }
            var r = new byte[rLen]; // r
            ms.Read(r, 0, r.Length);

            if (0x2 != ms.ReadByte()) throw new Fido2VerificationException(); // DER INTEGER
            var sLen = ms.ReadByte(); // length of s
            if (false == longForm)
            {
                if (0 != (sLen % 8)) // must be on 8 byte boundary
                {
                    if (0 == ms.ReadByte()) sLen--; // strip leading 0x00
                        else throw new Fido2VerificationException();
                }
            }
            var s = new byte[sLen]; // s
            ms.Read(s, 0, s.Length);

            var sig = new byte[r.Length + s.Length];
            r.CopyTo(sig, 0);
            s.CopyTo(sig, r.Length);
            return sig;
        }

        public static byte[] GetRpIdHash(ReadOnlySpan<byte> authData)
        {
            // todo: Switch to spans
            return authData.Slice(0, 32).ToArray();
        }

        public static bool IsUserPresent(ReadOnlySpan<byte> authData)
        {
            return (authData[32] & 0x01) != 0;
        }

        public static bool HasExtensions(ReadOnlySpan<byte> authData)
        {
            return (authData[32] & 0x80) != 0;
        }

        public static bool HasAttested(ReadOnlySpan<byte> authData)
        {
            return (authData[32] & 0x40) != 0;
        }

        public static bool IsUserVerified(ReadOnlySpan<byte> authData)
        {
            return (authData[32] & 0x04) != 0;
        }

        public static uint GetSignCount(ReadOnlySpan<byte> ad)
        {
            var bytes = ad.Slice(33, 4);
            var reversebytes = bytes.ToArray().Reverse().ToArray();
            return BitConverter.ToUInt32(reversebytes);
            //return BitConverter.ToUInt32(ad.Slice(33, 4),);
            //using (var ms = new MemoryStream(ad.ToArray()))
            //using (var br = new BinaryReader(ms))
            //{
            //    var pos = br.BaseStream.Seek(33, SeekOrigin.Current);
            //    var x = br.ReadUInt32();
            //    // https://w3c.github.io/webauthn/#attestedcredentialdata
            //    
            //    return x;
            //}
        }

        public static (Memory<byte> aaguid, Memory<byte> credId, Memory<byte> credentialPublicKey) GetAttestionData(Memory<byte> ad)
        {
            int offset = 37; // https://w3c.github.io/webauthn/#attestedcredentialdata
            Memory<byte> aaguid = null;
            if ((offset + 16) <= ad.Length)
            {
                aaguid = GetSizedByteArray(ad, ref offset, 16);
            }
            var credId = GetSizedByteArray(ad, ref offset);
            var hasExtensions = AuthDataHelper.HasExtensions(ad.Span);
            Memory<byte> credentialPublicKey = null;
            if ((ad.Length - offset) > 0) credentialPublicKey = GetSizedByteArray(ad, ref offset, (ushort)(ad.Length - offset)).ToArray();

            if (true == aaguid.IsEmpty || 
                null == credId || 
                true == credentialPublicKey.IsEmpty)
                throw new Fido2VerificationException("Malformed attestation data");

            return (aaguid, credId, credentialPublicKey);
        }

        public static byte[] GetSizedByteArray(Memory<byte> ab, ref int offset, UInt16 len = 0)
        {
            if ((0 == len) && ((offset + 2) <= ab.Length))
            {
                len = BitConverter.ToUInt16(ab.Slice(offset, 2).ToArray().Reverse().ToArray());
                offset += 2;
            }
            byte[] result = null;
            if ((0 < len) && ((offset + len) <= ab.Length)) 
            {
                result = ab.Slice(offset, len).ToArray();
                offset += len;
            }
            return result;
        }
        public static byte[] SigFromEcDsaSig(byte[] ecDsaSig)
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
            if (null == ecDsaSig || 0 == ecDsaSig.Length || ecDsaSig.Length > Math.Pow(2, 1008)) throw new Fido2VerificationException("Invalid ECDsa signature value");
            var offset = 0;
            var uint16Buffer = new byte[2];
            var derSequence = GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == derSequence || 0x30 != derSequence[0]) throw new Fido2VerificationException("ECDsa signature not a valid DER sequence");
            var dataLen = GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == dataLen) throw new Fido2VerificationException("ECDsa signature has invalid length");
            var longForm = (dataLen[0] > 0x7f);
            var longLen = 0;
            if (true == longForm)
            {
                var longLenByte = GetSizedByteArray(ecDsaSig, ref offset, 1);
                if (null == longLenByte) throw new Fido2VerificationException("ECDsa signature has invalid long form length");
                Buffer.BlockCopy(longLenByte, 0, uint16Buffer, 0, 1); 
                longLen = BitConverter.ToUInt16(uint16Buffer);
                longLen &= (1 << 7);
            }

            // Get R value
            var derInt = GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == derInt || 0x02 != derInt[0]) throw new Fido2VerificationException("ECDsa signature R sequence does not contain integer value"); // DER INTEGER
            var rLenByte = GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == rLenByte) throw new Fido2VerificationException("ECDsa signature R integer size invalid");
            Buffer.BlockCopy(rLenByte, 0, uint16Buffer, 0, 1);
            var rLen = BitConverter.ToUInt16(uint16Buffer);
            if (false == longForm)
            {
                if ((0x00 == ecDsaSig[offset]) && ((ecDsaSig[offset + 1] & (1 << 7)) != 0))
                {
                    offset++;
                    rLen--;
                }
            }
            var r = GetSizedByteArray(ecDsaSig, ref offset, rLen);
            if (null == r) throw new Fido2VerificationException("ECDsa signature R integer value invalid");
            // Get S value
            derInt = GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == derInt || 0x02 != derInt[0]) throw new Fido2VerificationException("ECDsa signature S sequence does not contain integer value"); // DER INTEGER
            var sLenByte = GetSizedByteArray(ecDsaSig, ref offset, 1);
            if (null == sLenByte) throw new Fido2VerificationException("ECDsa signature S integer size invalid");
            Buffer.BlockCopy(sLenByte, 0, uint16Buffer, 0, 1);
            var sLen = BitConverter.ToUInt16(uint16Buffer);
            if (false == longForm)
            {
                if ((0x00 == ecDsaSig[offset]) && ((ecDsaSig[offset + 1] & (1 << 7)) != 0))
                {
                    offset++;
                    sLen--;
                }
            }
            var s = GetSizedByteArray(ecDsaSig, ref offset, sLen);
            if (null == s) throw new Fido2VerificationException("ECDsa signature S integer value invalid");
            if (ecDsaSig.Length != offset) throw new Fido2VerificationException("ECDsa signature has bytes leftover after parsing R and S values");
            var sig = new byte[rLen + sLen];
            r.CopyTo(sig, 0);
            s.CopyTo(sig, rLen);
            return sig;
        }
    }
        // https://w3c.github.io/webauthn/#authenticator-data
    public class AuthenticatorData
    {
        public AuthenticatorData(byte[] authData)
        {
            if (null == authData || authData.Length < 37) throw new Fido2VerificationException("Authenticator data is invalid");
            var offset = 0;
            RpIdHash = AuthDataHelper.GetSizedByteArray(authData, ref offset, 32);
            Flags = AuthDataHelper.GetSizedByteArray(authData, ref offset, 1)[0];
            SignCount = AuthDataHelper.GetSizedByteArray(authData, ref offset, 4);
            if (false == AttestedCredentialDataPresent && false == ExtensionsPresent && 37 != authData.Length) throw new Fido2VerificationException("Authenticator data flags and data mismatch");
            AttData = null;
            if (true == AttestedCredentialDataPresent && false == ExtensionsPresent) AttData = new AttestedCredentialData(authData, ref offset);
            Extensions = null;
            if (false == AttestedCredentialDataPresent && true == ExtensionsPresent) Extensions = AuthDataHelper.GetSizedByteArray(authData, ref offset, (UInt16) (authData.Length - offset));
            // Determining attested credential data's length, which is variable, involves determining credentialPublicKey’s beginning location given the preceding credentialId’s length, and then determining the credentialPublicKey’s length
            if (true == AttestedCredentialDataPresent && true == ExtensionsPresent) throw new Fido2VerificationException("Not yet implemented");
            if (authData.Length != offset) throw new Fido2VerificationException("Leftover bits decoding AuthenticatorData");
        }
        public byte[] RpIdHash { get; private set; }
        public byte Flags { get; private set; }
        public byte[] SignCount { get; private set; }
        public AttestedCredentialData AttData { get; private set; }
        public byte[] Extensions { get; private set; }
        public bool UserPresent { get { return ((Flags & (1 << 0)) != 0); } }
        public bool Reserved1 { get { return ((Flags & (1 << 1)) != 0); } }
        public bool UserVerified { get { return ((Flags & (1 << 2)) != 0); } }
        public bool Reserved2 { get { return ((Flags & (1 << 3)) != 0); } }
        public bool Reserved3 { get { return ((Flags & (1 << 4)) != 0); } }
        public bool Reserved4 { get { return ((Flags & (1 << 5)) != 0); } }
        public bool AttestedCredentialDataPresent { get { return ((Flags & (1 << 6)) != 0); } }
        public bool ExtensionsPresent { get { return ((Flags & (1 << 7)) != 0); } }
    }
    // https://w3c.github.io/webauthn/#attested-credential-data
    public class AttestedCredentialData
    {
        public AttestedCredentialData(byte[] attData, ref int offset)
        {
            Aaguid = AuthDataHelper.GetSizedByteArray(attData, ref offset, 16);
            CredentialID = AuthDataHelper.GetSizedByteArray(attData, ref offset);
            CredentialPublicKey = AuthDataHelper.GetSizedByteArray(attData, ref offset, (UInt16)(attData.Length - offset));
            if (null == Aaguid || null == CredentialID || null == CredentialPublicKey) throw new Fido2VerificationException("Attested credential data is invalid");
        }
        public byte[] Aaguid { get; private set; }
        public byte[] CredentialID { get; private set; }
        public byte[] CredentialPublicKey { get; private set; }
    }
}
