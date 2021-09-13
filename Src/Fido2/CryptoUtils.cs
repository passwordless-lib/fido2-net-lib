using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Asn1;
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
                    throw new ArgumentOutOfRangeException(nameof(hashName));
            }
        }

        public static HashAlgorithmName HashAlgFromCOSEAlg(int alg)
        {
            return (COSE.Algorithm)alg switch
            {
                COSE.Algorithm.RS1 => HashAlgorithmName.SHA1,
                COSE.Algorithm.ES256 => HashAlgorithmName.SHA256,
                COSE.Algorithm.ES384 => HashAlgorithmName.SHA384,
                COSE.Algorithm.ES512 => HashAlgorithmName.SHA512,
                COSE.Algorithm.PS256 => HashAlgorithmName.SHA256,
                COSE.Algorithm.PS384 => HashAlgorithmName.SHA384,
                COSE.Algorithm.PS512 => HashAlgorithmName.SHA512,
                COSE.Algorithm.RS256 => HashAlgorithmName.SHA256,
                COSE.Algorithm.RS384 => HashAlgorithmName.SHA384,
                COSE.Algorithm.RS512 => HashAlgorithmName.SHA512,
                COSE.Algorithm.ES256K => HashAlgorithmName.SHA256,
                (COSE.Algorithm)4 => HashAlgorithmName.SHA1,
                (COSE.Algorithm)11 => HashAlgorithmName.SHA256,
                (COSE.Algorithm)12 => HashAlgorithmName.SHA384,
                (COSE.Algorithm)13 => HashAlgorithmName.SHA512,
                COSE.Algorithm.EdDSA => HashAlgorithmName.SHA512,
                _ => throw new Fido2VerificationException("Unrecognized COSE alg value"),
            };
        }

        public static bool ValidateTrustChain(X509Certificate2[] trustPath, X509Certificate2[] attestationRootCertificates)
        {
            foreach (var attestationRootCert in attestationRootCertificates)
            {
                var chain = new X509Chain();
                chain.ChainPolicy.ExtraStore.Add(attestationRootCert);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                if (trustPath.Length > 1)
                {
                    foreach (var cert in trustPath.Skip(1).Reverse())
                    {
                        chain.ChainPolicy.ExtraStore.Add(cert);
                    }
                }
                var valid = chain.Build(trustPath[0]);

                // because we are using AllowUnknownCertificateAuthority we have to verify that the root matches ourselves
                var chainRoot = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                valid = valid && chainRoot.RawData.SequenceEqual(attestationRootCert.RawData);

                if (true == valid)
                    return true;
            }
            return false;
        }

        public static byte[] SigFromEcDsaSig(byte[] ecDsaSig, int keySize)
        {
            var decoded = AsnElt.Decode(ecDsaSig);
            var r = decoded.Sub[0].GetOctetString();
            var s = decoded.Sub[1].GetOctetString();

            // .NET requires IEEE P-1363 fixed size unsigned big endian values for R and S
            // ASN.1 requires storing positive integer values with any leading 0s removed
            // Convert ASN.1 format to IEEE P-1363 format 
            // determine coefficient size 
            var coefficientSize = (int)Math.Ceiling((decimal)keySize / 8);

            // Create byte array to copy R into 
            var P1363R = new byte[coefficientSize];

            if (0x0 == r[0] && (r[1] & (1 << 7)) != 0)
            {
                r.Skip(1).ToArray().CopyTo(P1363R, coefficientSize - r.Length + 1);
            }
            else
            {
                r.CopyTo(P1363R, coefficientSize - r.Length);
            }

            // Create byte array to copy S into 
            var P1363S = new byte[coefficientSize];

            if (0x0 == s[0] && (s[1] & (1 << 7)) != 0)
            {
                s.Skip(1).ToArray().CopyTo(P1363S, coefficientSize - s.Length + 1);
            }
            else
            {
                s.CopyTo(P1363S, coefficientSize - s.Length);
            }

            // Concatenate R + S coordinates and return the raw signature
            return P1363R.Concat(P1363S).ToArray();
        }

        /// <summary>
        /// Convert PEM formated string into byte array.
        /// </summary>
        /// <param name="pemStr">source string.</param>
        /// <returns>output byte array.</returns>
        public static byte[] PemToBytes(string pemStr)
        {
            const string PemStartStr = "-----BEGIN";
            const string PemEndStr = "-----END";
            byte[] retval = null;
            var lines = pemStr.Split('\n');
            var base64Str = "";
            bool started = false, ended = false;
            var cline = "";
            for (var i = 0; i < lines.Length; i++)
            {
                cline = lines[i].ToUpper();
                if (cline == "")
                    continue;
                if (cline.Length > PemStartStr.Length)
                {
                    if (!started && cline.Substring(0, PemStartStr.Length) == PemStartStr)
                    {
                        started = true;
                        continue;
                    }
                }
                if (cline.Length > PemEndStr.Length)
                {
                    if (cline.Substring(0, PemEndStr.Length) == PemEndStr)
                    {
                        ended = true;
                        break;
                    }
                }
                if (started)
                {
                    base64Str += lines[i];
                }
            }
            if (!(started && ended))
            {
                throw new Exception("'BEGIN'/'END' line is missing.");
            }
            base64Str = base64Str.Replace("\r", "");
            base64Str = base64Str.Replace("\n", "");
            base64Str = base64Str.Replace("\n", " ");
            retval = Convert.FromBase64String(base64Str);
            return retval;
        }

        public static string CDPFromCertificateExts(X509ExtensionCollection exts)
        {
            var cdp = "";
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.31")) // id-ce-CRLDistributionPoints
                {
                    var asnData = AsnElt.Decode(ext.RawData);
                    cdp = System.Text.Encoding.ASCII.GetString(asnData.Sub[0].Sub[0].Sub[0].Sub[0].GetOctetString());
                }
            }
            return cdp;
        }
        public static bool IsCertInCRL(byte[] crl, X509Certificate2 cert)
        {
            var asnData = AsnElt.Decode(crl);
            if (7 > asnData.Sub[0].Sub.Length)
                return false; // empty CRL

            var revokedCertificates = asnData.Sub[0].Sub[5].Sub;
            var revoked = new List<long>();

            foreach (AsnElt s in revokedCertificates)
            {
                revoked.Add(BitConverter.ToInt64(s.Sub[0].GetOctetString().Reverse().ToArray(), 0));
            }

            return revoked.Contains(BitConverter.ToInt64(cert.GetSerialNumber(), 0));
        }
    }
}
