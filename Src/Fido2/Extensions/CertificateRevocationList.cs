using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Fido2NetLib;

/// <summary>
/// A decoded X.509 certificate revocation list (RFC 5280 §5).
/// </summary>
/// <remarks>
/// .NET can produce a CRL (<see cref="CertificateRevocationListBuilder"/>) but exposes nothing that reads one, and
/// <see cref="X509Chain"/> only consults CRLs it fetched itself. A CRL obtained from a known location therefore has
/// to be decoded, and its signature verified, by hand.
/// </remarks>
internal sealed class CertificateRevocationList
{
    private const string EcdsaWithSha1 = "1.2.840.10045.4.1";
    private const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";
    private const string EcdsaWithSha384 = "1.2.840.10045.4.3.3";
    private const string EcdsaWithSha512 = "1.2.840.10045.4.3.4";
    private const string Sha1WithRsaEncryption = "1.2.840.113549.1.1.5";
    private const string Sha256WithRsaEncryption = "1.2.840.113549.1.1.11";
    private const string Sha384WithRsaEncryption = "1.2.840.113549.1.1.12";
    private const string Sha512WithRsaEncryption = "1.2.840.113549.1.1.13";

    private readonly ReadOnlyMemory<byte> _tbsCertList;
    private readonly string _signatureAlgorithm;
    private readonly ReadOnlyMemory<byte> _signature;
    private readonly List<BigInteger> _revokedSerialNumbers;

    private CertificateRevocationList(
        ReadOnlyMemory<byte> tbsCertList,
        string signatureAlgorithm,
        ReadOnlyMemory<byte> signature,
        X500DistinguishedName issuer,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate,
        List<BigInteger> revokedSerialNumbers)
    {
        _tbsCertList = tbsCertList;
        _signatureAlgorithm = signatureAlgorithm;
        _signature = signature;
        Issuer = issuer;
        ThisUpdate = thisUpdate;
        NextUpdate = nextUpdate;
        _revokedSerialNumbers = revokedSerialNumbers;
    }

    /// <summary>
    /// The name of the CA that issued the CRL. Only certificates whose issuer name matches are covered by it.
    /// </summary>
    public X500DistinguishedName Issuer { get; }

    /// <summary>
    /// When the CRL was issued.
    /// </summary>
    public DateTimeOffset ThisUpdate { get; }

    /// <summary>
    /// When the next CRL will be issued, after which this one is stale. Conforming issuers always include it.
    /// </summary>
    public DateTimeOffset? NextUpdate { get; }

    /// <summary>
    /// The number of certificates the CRL lists as revoked.
    /// </summary>
    public int RevokedCertificateCount => _revokedSerialNumbers.Count;

    /// <summary>
    /// Decodes a DER-encoded CertificateList.
    /// </summary>
    /// <exception cref="CryptographicException">The data is not a well-formed CertificateList.</exception>
    public static CertificateRevocationList Decode(ReadOnlyMemory<byte> encoded)
    {
        try
        {
            return DecodeCore(encoded);
        }
        catch (AsnContentException ex)
        {
            throw new CryptographicException("The data is not a valid DER-encoded certificate revocation list", ex);
        }
    }

    private static CertificateRevocationList DecodeCore(ReadOnlyMemory<byte> encoded)
    {
        // CertificateList ::= SEQUENCE {
        //     tbsCertList          TBSCertList,
        //     signatureAlgorithm   AlgorithmIdentifier,
        //     signatureValue       BIT STRING }
        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        var certificateList = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        // The signature covers the DER encoding of tbsCertList exactly as received, so keep the raw bytes.
        ReadOnlyMemory<byte> tbsCertList = certificateList.ReadEncodedValue();
        ReadOnlyMemory<byte> signatureAlgorithm = certificateList.ReadEncodedValue();
        byte[] signature = certificateList.ReadBitString(out int unusedBitCount);
        certificateList.ThrowIfNotEmpty();

        if (unusedBitCount != 0)
        {
            throw new AsnContentException("The CRL signature is not a whole number of octets");
        }

        // TBSCertList ::= SEQUENCE {
        //     version                 Version OPTIONAL,  -- if present, MUST be v2
        //     signature               AlgorithmIdentifier,
        //     issuer                  Name,
        //     thisUpdate              Time,
        //     nextUpdate              Time OPTIONAL,
        //     revokedCertificates     SEQUENCE OF SEQUENCE {
        //         userCertificate         CertificateSerialNumber,
        //         revocationDate          Time,
        //         crlEntryExtensions      Extensions OPTIONAL } OPTIONAL,
        //     crlExtensions           [0] EXPLICIT Extensions OPTIONAL }
        //
        // Four of the seven fields are optional, so the list is walked by tag rather than by position.
        var tbs = new AsnReader(tbsCertList, AsnEncodingRules.DER).ReadSequence();

        if (tbs.PeekTag() == Asn1Tag.Integer)
        {
            // Version ::= INTEGER { v1(0), v2(1), v3(2) }; a v1 CRL omits the field entirely.
            if (tbs.ReadInteger() != 1)
            {
                throw new AsnContentException("Only version 2 certificate revocation lists are supported");
            }
        }

        // RFC 5280 §5.1.1.2: the inner signature field MUST contain the same algorithm identifier as the outer one.
        if (!tbs.ReadEncodedValue().Span.SequenceEqual(signatureAlgorithm.Span))
        {
            throw new AsnContentException("The CRL signature algorithm does not match the one in tbsCertList");
        }

        var issuer = new X500DistinguishedName(tbs.ReadEncodedValue().Span);
        DateTimeOffset thisUpdate = ReadTime(tbs);

        DateTimeOffset? nextUpdate = null;
        if (tbs.HasData && IsTime(tbs.PeekTag()))
        {
            nextUpdate = ReadTime(tbs);
        }

        var revokedSerialNumbers = new List<BigInteger>();
        if (tbs.HasData && tbs.PeekTag() == Asn1Tag.Sequence)
        {
            var revokedCertificates = tbs.ReadSequence();
            while (revokedCertificates.HasData)
            {
                var revokedCertificate = revokedCertificates.ReadSequence();
                revokedSerialNumbers.Add(revokedCertificate.ReadInteger());
                // revocationDate and crlEntryExtensions carry nothing needed to decide membership.
            }
        }

        if (tbs.HasData)
        {
            tbs.ReadEncodedValue(); // crlExtensions
        }

        tbs.ThrowIfNotEmpty();

        // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL }
        string signatureAlgorithmOid = new AsnReader(signatureAlgorithm, AsnEncodingRules.DER).ReadSequence().ReadObjectIdentifier();

        return new CertificateRevocationList(tbsCertList, signatureAlgorithmOid, signature, issuer, thisUpdate, nextUpdate, revokedSerialNumbers);
    }

    // Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
    private static bool IsTime(Asn1Tag tag) => tag == Asn1Tag.UtcTime || tag == Asn1Tag.GeneralizedTime;

    private static DateTimeOffset ReadTime(AsnReader reader)
    {
        return reader.PeekTag() == Asn1Tag.UtcTime ? reader.ReadUtcTime() : reader.ReadGeneralizedTime();
    }

    /// <summary>
    /// Verifies that the CRL was signed by the holder of the public key in <paramref name="issuer"/>.
    /// </summary>
    /// <returns><see langword="true"/> if the signature verifies; <see langword="false"/> if it does not, or if the
    /// certificate's key is of the wrong type for the CRL's signature algorithm.</returns>
    /// <exception cref="CryptographicException">The CRL uses a signature algorithm that is not supported.</exception>
    public bool VerifySignature(X509Certificate2 issuer)
    {
        switch (_signatureAlgorithm)
        {
            case EcdsaWithSha1:
            case EcdsaWithSha256:
            case EcdsaWithSha384:
            case EcdsaWithSha512:
                {
                    using ECDsa? ecdsa = issuer.GetECDsaPublicKey();

                    return ecdsa is not null
                        && ecdsa.VerifyData(_tbsCertList.Span, _signature.Span, HashAlgorithm(_signatureAlgorithm), DSASignatureFormat.Rfc3279DerSequence);
                }
            case Sha1WithRsaEncryption:
            case Sha256WithRsaEncryption:
            case Sha384WithRsaEncryption:
            case Sha512WithRsaEncryption:
                {
                    using RSA? rsa = issuer.GetRSAPublicKey();

                    return rsa is not null
                        && rsa.VerifyData(_tbsCertList.Span, _signature.Span, HashAlgorithm(_signatureAlgorithm), RSASignaturePadding.Pkcs1);
                }
            default:
                // RSASSA-PSS is the notable omission: its parameters name a salt length, and RSA.VerifyData only
                // supports a salt as long as the digest.
                throw new CryptographicException($"Unsupported CRL signature algorithm {_signatureAlgorithm}");
        }
    }

    private static HashAlgorithmName HashAlgorithm(string signatureAlgorithm)
    {
        return signatureAlgorithm switch
        {
            EcdsaWithSha1 or Sha1WithRsaEncryption => HashAlgorithmName.SHA1,
            EcdsaWithSha256 or Sha256WithRsaEncryption => HashAlgorithmName.SHA256,
            EcdsaWithSha384 or Sha384WithRsaEncryption => HashAlgorithmName.SHA384,
            EcdsaWithSha512 or Sha512WithRsaEncryption => HashAlgorithmName.SHA512,
            _ => throw new CryptographicException($"Unsupported CRL signature algorithm {signatureAlgorithm}"),
        };
    }

    /// <summary>
    /// Determines whether the CRL lists the serial number of <paramref name="certificate"/>.
    /// </summary>
    /// <remarks>
    /// A serial number only identifies a certificate within its issuer, so this says nothing unless the CRL was
    /// issued by the certificate's issuer (compare <see cref="Issuer"/>) and <see cref="VerifySignature"/> holds.
    /// </remarks>
    public bool IsRevoked(X509Certificate2 certificate)
    {
        // Serial numbers are compared as the integers they are, so an encoding difference (such as the sign-padding
        // octet a value with its top bit set carries) between the certificate and the CRL entry cannot hide a match.
        var serialNumber = new BigInteger(certificate.SerialNumberBytes.Span, isUnsigned: false, isBigEndian: true);

        foreach (BigInteger revokedSerialNumber in _revokedSerialNumbers)
        {
            if (revokedSerialNumber == serialNumber)
            {
                return true;
            }
        }

        return false;
    }
}
