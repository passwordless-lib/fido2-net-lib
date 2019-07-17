using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using LipingShare.LCLib.Asn1Processor;
using PeterO.Cbor;
using Fido2NetLib.Objects;
using System.IO;

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
            {(int) COSE.Algorithm.RS1, HashAlgorithmName.SHA1 },
            {(int) COSE.Algorithm.ES256, HashAlgorithmName.SHA256},
            {(int) COSE.Algorithm.ES384, HashAlgorithmName.SHA384 },
            {(int) COSE.Algorithm.ES512, HashAlgorithmName.SHA512 },
            {(int) COSE.Algorithm.PS256, HashAlgorithmName.SHA256 },
            {(int) COSE.Algorithm.PS384, HashAlgorithmName.SHA384 },
            {(int) COSE.Algorithm.PS512, HashAlgorithmName.SHA512 },
            {(int) COSE.Algorithm.RS256, HashAlgorithmName.SHA256 },
            {(int) COSE.Algorithm.RS384, HashAlgorithmName.SHA384 },
            {(int) COSE.Algorithm.RS512, HashAlgorithmName.SHA512 },
            {4, HashAlgorithmName.SHA1 },
            {11, HashAlgorithmName.SHA256 },
            {12, HashAlgorithmName.SHA384 },
            {13, HashAlgorithmName.SHA512 }
        };

        public static byte[] GetEcDsaSigValue(BinaryReader reader)
        {
            // First byte should be DER int marker
            var derInt = reader.ReadByte();
            if (0x02 != derInt) throw new Fido2VerificationException("ECDsa signature coordinate sequence does not contain DER integer value"); // DER INTEGER

            // Second byte is length to read
            var len = reader.ReadByte();

            // a leading 0x00 is added to the content to indicate that the number is not negative...
            if (0x00 == reader.BaseStream.ReadByte())
            {
                // If the integer is positive but the high order bit is set to 1
                if ((reader.BaseStream.ReadByte() & (1 << 7)) != 0)
                {
                    // we don't want to copy that leading 0x00, so reduce the length to read
                    len--;
                }
                // back the stream up one byte from the high order bit check
                reader.BaseStream.Seek(-1, SeekOrigin.Current);
            }
            // back the stream up one byte from the leading 0x00 check
            else reader.BaseStream.Seek(-1, SeekOrigin.Current);

            // read the calculated number of bytes from the stream and return the result
            return reader.ReadBytes(len);
        }

        public static byte[] SigFromEcDsaSig(byte[] ecDsaSig, int keySize)
        {
            using (var stream = new MemoryStream(ecDsaSig, false))
            {
                using (var reader = new BinaryReader(stream))
                {
                    // first byte should be DER sequence marker
                    var derSequence = reader.ReadByte();
                    if (0x30 != derSequence) throw new Fido2VerificationException("ECDsa signature not a valid DER sequence");

                    // two forms of length, short form and long form
                    // short form, one byte, bit 8 not set, rest of the bits indicate data length
                    var dataLen = reader.ReadByte();

                    // long form, first byte, bit 8 is set, rest of bits indicate the length of the data length
                    // so if bit 8 is on...
                    var longForm = (0 != (dataLen & (1 << 7)));
                    if (true == longForm)
                    {
                        // rest of bits indicate the number of bytes containing the data length in long form
                        var longLenBytes = (dataLen & ~(1 << 7));

                        // we are expecting a single byte to hold the data length at the time of this writing
                        if (1 != longLenBytes) throw new Fido2VerificationException("ECDsa signature has invalid long form data length bytes");

                        // read the length of the data
                        var longLen = reader.ReadBytes(longLenBytes)[0];

                        // must be more than 127 bytes otherwise we'd be using the short form
                        if (0x80 > longLen) throw new Fido2VerificationException("ECDsa signature has invalid long form data length");

                        // sanity check the length
                        if (ecDsaSig.Length != (reader.BaseStream.Position + longLen)) throw new Fido2VerificationException("ECDsa signature has invalid long form length");
                    }

                    // Get R value
                    var r = GetEcDsaSigValue(reader);

                    // Get S value
                    var s = GetEcDsaSigValue(reader);

                    // make sure we are at the end
                    if (reader.BaseStream.Position != reader.BaseStream.Length) throw new Fido2VerificationException("ECDsa signature has bytes leftover after parsing R and S values");

                    // .NET requires IEEE P-1363 fixed size unsigned big endian values for R and S
                    // ASN.1 requires storing positive integer values with any leading 0s removed
                    // Convert ASN.1 format to IEEE P-1363 format 
                    // determine coefficient size 
                    var coefficientSize = (int)Math.Ceiling((decimal)keySize / 8);

                    // Sanity check R and S value lengths
                    if ((coefficientSize * 2) < (r.Length + s.Length)) throw new Fido2VerificationException("ECDsa signature has invalid length for given curve key size");

                    // Create byte array to copy R into 
                    var P1363R = new byte[coefficientSize];
                    r.CopyTo(P1363R, coefficientSize - r.Length);

                    // Create byte array to copy S into 
                    var P1363S = new byte[coefficientSize];
                    s.CopyTo(P1363S, coefficientSize - s.Length);

                    // Concatenate R + S coordinates and return the raw signature
                    return P1363R.Concat(P1363S).ToArray();
                }
            }
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
