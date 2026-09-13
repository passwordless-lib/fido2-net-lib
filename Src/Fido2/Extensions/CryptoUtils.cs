using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

internal static class CryptoUtils
{
    public static byte[] HashData(HashAlgorithmName hashName, ReadOnlySpan<byte> data)
    {
        #pragma warning disable format
        return hashName.Name switch
        {
            "SHA1"                                               => SHA1.HashData(data),
            "SHA256" or "HS256" or "RS256" or "ES256" or "PS256" => SHA256.HashData(data),
            "SHA384" or "HS384" or "RS384" or "ES384" or "PS384" => SHA384.HashData(data),
            "SHA512" or "HS512" or "RS512" or "ES512" or "PS512" => SHA512.HashData(data),
            _ => throw new ArgumentOutOfRangeException(nameof(hashName)),
        };
        #pragma warning restore format
    }

    public static HashAlgorithmName HashAlgFromCOSEAlg(COSE.Algorithm alg)
    {
        return alg switch
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
            _ => throw new Fido2VerificationException(Fido2ErrorMessages.InvalidCoseAlgorithmValue),
        };
    }

    /// <summary>
    /// Determines whether an attestation certificate chains to one of the trust anchors an authenticator's metadata
    /// statement declares.
    /// </summary>
    /// <param name="trustPath">The attestation certificate followed by whatever issuing certificates the authenticator
    /// supplied (the x5c array), in order.</param>
    /// <param name="attestationRootCertificates">The metadata statement's attestationRootCertificates.</param>
    /// <param name="validationMode">Conformance mode skips revocation checking, as the conformance tool's certificates
    /// name CRL distribution points that do not exist.</param>
    /// <remarks>
    /// <para>
    /// https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationrootcertificates
    /// </para>
    /// <para>
    /// "Each element of this array represents a PKIX [RFC5280] X.509 certificate that is a valid trust anchor for this
    /// authenticator model. Multiple certificates might be used for different batches of the same model. The array does
    /// not represent a certificate chain, but only the trust anchor of that chain. A trust anchor can be a root
    /// certificate, an intermediate CA certificate or even the attestation certificate itself."
    /// </para>
    /// <para>
    /// <see cref="X509Chain"/> has no notion of an intermediate CA as a trust anchor: on Linux and macOS a certificate in
    /// <see cref="X509ChainPolicy.CustomTrustStore"/> that is not self-signed is used only as an issuer, and the chain it
    /// heads is reported as partial. So the chain is built with partial chains permitted, letting the engine verify every
    /// link, and the trust decision is made here: the attestation certificate is trusted when a declared anchor appears
    /// anywhere above it in the chain the engine verified.
    /// </para>
    /// <para>
    /// Revocation of the attestation certificate is checked here as well, rather than by the engine: with an
    /// intermediate anchor the chain is partial on Linux and macOS, and on a partial chain OpenSSL never consults a
    /// CRL at all, while macOS never fetches one for a chain under a custom trust anchor in any configuration. So if
    /// the attestation certificate names a CRL distribution point, the CRL is fetched from it and verified against
    /// the issuer the engine found for the certificate, on every platform alike. An issuing CA's own status is not
    /// checked; the metadata statement vouches for the CA by naming it, or something above it, as the anchor.
    /// </para>
    /// </remarks>
    public static bool ValidateTrustChain(X509Certificate2[] trustPath, X509Certificate2[] attestationRootCertificates, FidoValidationMode validationMode = FidoValidationMode.Default)
    {
        if (trustPath.Length == 0)
        {
            throw new ArgumentException("The trust path must contain the attestation certificate", nameof(trustPath));
        }

        X509Certificate2 attestationCert = trustPath[0];

        // The anchor may be the attestation certificate itself, in which case nothing else in x5c matters.
        if (IsDeclaredTrustAnchor(attestationCert, attestationRootCertificates))
        {
            return true;
        }

        using var chain = new X509Chain();

        // Trust comes from the metadata statement alone; the platform's own root store has no say. A self-signed
        // anchor becomes a genuine root this way, and an intermediate anchor is still found as an issuer.
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(attestationRootCertificates);

        // A chain that ends at an intermediate anchor, or at a root the authenticator supplied, is not an error here:
        // whether it is trusted is decided below.
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        // Windows consults the exclusive root store for trust, not for issuer lookup, so the anchors go here too.
        chain.ChainPolicy.ExtraStore.AddRange(attestationRootCertificates);

        for (int i = 1; i < trustPath.Length; i++) // skip the attestation certificate
        {
            chain.ChainPolicy.ExtraStore.Add(trustPath[i]);
        }

        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        if (!chain.Build(attestationCert))
        {
            return false;
        }

        // Every link in the chain now verifies. The attestation certificate is trusted if a declared anchor sits
        // anywhere above it; anything above the anchor is immaterial.
        bool anchored = false;

        for (int i = 1; i < chain.ChainElements.Count; i++) // skip the attestation certificate
        {
            if (IsDeclaredTrustAnchor(chain.ChainElements[i].Certificate, attestationRootCertificates))
            {
                anchored = true;
                break;
            }
        }

        if (!anchored)
        {
            return false;
        }

        // The conformance tool's certificates name CRL distribution points that do not exist.
        if (validationMode == FidoValidationMode.FidoConformance2024)
        {
            return true;
        }

        // The engine established that the second element issued the attestation certificate, so that is who must
        // have signed its CRL.
        return HasClearRevocationStatus(attestationCert, chain.ChainElements[1].Certificate);
    }

    // Attestation CAs issue small CRLs; this is far above any real one, and keeps a misbehaving distribution point
    // from filling memory.
    private const int MaxCrlBytes = 32 * 1024 * 1024;

    // The timeout covers the whole response, body included, since the content is buffered before Send returns.
    private static readonly Lazy<HttpClient> s_crlClient = new(() => new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(15),
        MaxResponseContentBufferSize = MaxCrlBytes,
    });

    // A CRL is good until its next update, and every attestation certificate a CA issued names the same one, so a
    // fetched CRL is kept until then. Bounded crudely: a relying party sees a few dozen CAs at most.
    private static readonly ConcurrentDictionary<string, (byte[] Crl, DateTimeOffset Expires)> s_crlCache = new();
    private const int MaxCachedCrls = 64;

    /// <summary>
    /// Determines whether <paramref name="cert"/> is known not to be revoked: either it names no CRL distribution
    /// point, or the CRL there is genuine, current, and does not list it. A CRL that cannot be fetched, does not
    /// verify under <paramref name="issuer"/>, or is past its next update leaves the status unknown, which is not
    /// good enough for an attestation certificate.
    /// </summary>
    private static bool HasClearRevocationStatus(X509Certificate2 cert, X509Certificate2 issuer)
    {
        if (!TryGetCrlDistributionPointUrl(cert, out string? url))
        {
            return true;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;

        if (!s_crlCache.TryGetValue(url, out var cached) || cached.Expires <= now)
        {
            if (DownloadCrl(url) is not { } crl)
            {
                return false;
            }

            cached = (crl, DateTimeOffset.MinValue);
        }

        try
        {
            var revocationList = CertificateRevocationList.Decode(cached.Crl);

            if (IsCertInCRL(revocationList, cert, issuer, now))
            {
                return false;
            }

            // Verified and current, so worth keeping. A CRL that names no next update is refetched every time.
            if (cached.Expires == DateTimeOffset.MinValue && revocationList.NextUpdate is { } nextUpdate)
            {
                if (s_crlCache.Count >= MaxCachedCrls)
                {
                    s_crlCache.Clear();
                }

                s_crlCache[url] = (cached.Crl, nextUpdate);
            }

            return true;
        }
        catch (CryptographicException)
        {
            // Malformed, forged, or stale: unknown status, and nothing worth caching.
            s_crlCache.TryRemove(url, out _);
            return false;
        }
    }

    private static byte[]? DownloadCrl(string url)
    {
        try
        {
            // Synchronous on purpose: this stands in for the fetch X509Chain.Build itself used to make, and it sits
            // behind the same synchronous surface. A body over MaxResponseContentBufferSize fails the send.
            using var response = s_crlClient.Value.Send(new HttpRequestMessage(HttpMethod.Get, url), HttpCompletionOption.ResponseContentRead);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var content = response.Content.ReadAsStream();
            using var buffer = new MemoryStream();
            content.CopyTo(buffer);

            return buffer.ToArray();
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException or InvalidOperationException)
        {
            return null;
        }
    }

    private static bool IsDeclaredTrustAnchor(X509Certificate2 certificate, X509Certificate2[] attestationRootCertificates)
    {
        foreach (X509Certificate2 attestationRootCertificate in attestationRootCertificates)
        {
            // MDS3: "a binary comparison is sufficient to determine if the attestation trust anchor is the attestation
            // certificate itself".
            if (attestationRootCertificate.RawDataMemory.Span.SequenceEqual(certificate.RawDataMemory.Span))
            {
                return true;
            }
        }

        return false;
    }

    public static byte[] SigFromEcDsaSig(byte[] ecDsaSig, int keySize)
    {
        var decoded = Asn1Element.Decode(ecDsaSig);
        var r = decoded[0].GetIntegerBytes();
        var s = decoded[1].GetIntegerBytes();

        // .NET requires IEEE P-1363 fixed size unsigned big endian values for R and S
        // ASN.1 requires storing positive integer values with any leading 0s removed
        // Convert ASN.1 format to IEEE P-1363 format
        // determine coefficient size

        // common coefficient sizes include: 32, 48, and 64
        var coefficientSize = (int)Math.Ceiling((decimal)keySize / 8);

        // Create buffer to copy R into
        Span<byte> p1363R = coefficientSize <= 64
            ? stackalloc byte[coefficientSize]
            : new byte[coefficientSize];

        if (0x0 == r[0] && (r[1] & (1 << 7)) != 0)
        {
            r.Slice(1).CopyTo(p1363R.Slice(coefficientSize - r.Length + 1));
        }
        else
        {
            r.CopyTo(p1363R.Slice(coefficientSize - r.Length));
        }

        // Create byte array to copy S into
        Span<byte> p1363S = coefficientSize <= 64
            ? stackalloc byte[coefficientSize]
            : new byte[coefficientSize];

        if (0x0 == s[0] && (s[1] & (1 << 7)) != 0)
        {
            s.Slice(1).CopyTo(p1363S.Slice(coefficientSize - s.Length + 1));
        }
        else
        {
            s.CopyTo(p1363S.Slice(coefficientSize - s.Length));
        }

        // Concatenate R + S coordinates and return the raw signature
        return [.. p1363R, .. p1363S];
    }

    /// <summary>
    /// Finds the first HTTP or HTTPS location in the certificate's CRL Distribution Points extension.
    /// </summary>
    /// <returns><see langword="false"/> if the certificate has no such extension, the extension names no HTTP location,
    /// or it is malformed.</returns>
    public static bool TryGetCrlDistributionPointUrl(X509Certificate2 certificate, [NotNullWhen(true)] out string? url)
    {
        url = null;

        if (certificate.Extensions["2.5.29.31"] is not { } extension) // id-ce-cRLDistributionPoints
        {
            return false;
        }

        var distributionPointTag = new Asn1Tag(TagClass.ContextSpecific, 0);  // DistributionPoint.distributionPoint
        var fullNameTag = new Asn1Tag(TagClass.ContextSpecific, 0);           // DistributionPointName.fullName
        var uriTag = new Asn1Tag(TagClass.ContextSpecific, 6);                // GeneralName.uniformResourceIdentifier

        try
        {
            // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
            var distributionPoints = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();

            while (distributionPoints.HasData)
            {
                // DistributionPoint ::= SEQUENCE {
                //     distributionPoint       [0]     DistributionPointName OPTIONAL,
                //     reasons                 [1]     ReasonFlags OPTIONAL,
                //     cRLIssuer               [2]     GeneralNames OPTIONAL }
                var distributionPoint = distributionPoints.ReadSequence();

                if (!distributionPoint.HasData || !distributionPoint.PeekTag().HasSameClassAndValue(distributionPointTag))
                {
                    continue;
                }

                // DistributionPointName ::= CHOICE {
                //     fullName                [0]     GeneralNames,
                //     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
                //
                // The [0] around the CHOICE is explicit, so the name is nested one level down.
                var distributionPointName = distributionPoint.ReadSequence(distributionPointTag);

                if (!distributionPointName.PeekTag().HasSameClassAndValue(fullNameTag))
                {
                    continue;
                }

                // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
                var generalNames = distributionPointName.ReadSequence(fullNameTag);

                while (generalNames.HasData)
                {
                    if (!generalNames.PeekTag().HasSameClassAndValue(uriTag))
                    {
                        generalNames.ReadEncodedValue();
                        continue;
                    }

                    string candidate = generalNames.ReadCharacterString(UniversalTagNumber.IA5String, uriTag);

                    if (Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri) && uri.Scheme is "http" or "https")
                    {
                        url = candidate;
                        return true;
                    }
                }
            }
        }
        catch (AsnContentException)
        {
            // A malformed extension names no usable distribution point.
        }

        return false;
    }

    /// <summary>
    /// Determines whether <paramref name="crl"/> lists <paramref name="cert"/>, taking the CRL at its word. Use the
    /// overload that takes the issuer wherever the issuing certificate is known, so that the CRL is verified first.
    /// </summary>
    /// <exception cref="CryptographicException">The CRL is malformed.</exception>
    public static bool IsCertInCRL(ReadOnlyMemory<byte> crl, X509Certificate2 cert)
    {
        return CertificateRevocationList.Decode(crl).IsRevoked(cert);
    }

    /// <summary>
    /// Determines whether <paramref name="cert"/> is revoked according to <paramref name="crl"/>, a DER-encoded CRL
    /// obtained from the certificate's CRL distribution point.
    /// </summary>
    /// <param name="crl">The DER-encoded CertificateList.</param>
    /// <param name="cert">The certificate whose status is in question.</param>
    /// <param name="issuer">The certificate of the CA that issued <paramref name="cert"/>, which must also have
    /// issued and signed the CRL.</param>
    /// <param name="verificationTime">When given, the CRL must not have passed its nextUpdate time. A stale CRL is one
    /// an attacker on the path to the distribution point could replay to hide a later revocation.</param>
    /// <exception cref="CryptographicException">The CRL is malformed, was not issued by <paramref name="issuer"/>,
    /// or is stale.</exception>
    public static bool IsCertInCRL(ReadOnlyMemory<byte> crl, X509Certificate2 cert, X509Certificate2 issuer, DateTimeOffset? verificationTime = null)
    {
        return IsCertInCRL(CertificateRevocationList.Decode(crl), cert, issuer, verificationTime);
    }

    private static bool IsCertInCRL(CertificateRevocationList revocationList, X509Certificate2 cert, X509Certificate2 issuer, DateTimeOffset? verificationTime)
    {
        // RFC 5280 §6.3.3 (b): the CRL must have been issued by the certificate's issuer...
        if (!revocationList.Issuer.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData))
        {
            throw new CryptographicException($"The CRL was issued by '{revocationList.Issuer.Name}', not by the certificate's issuer '{cert.IssuerName.Name}'");
        }

        if (!issuer.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData))
        {
            throw new CryptographicException($"The certificate was issued by '{cert.IssuerName.Name}', not by '{issuer.SubjectName.Name}'");
        }

        // ...and (f) its signature must verify under that issuer's key.
        if (!revocationList.VerifySignature(issuer))
        {
            throw new CryptographicException($"The CRL signature does not verify with the public key of '{issuer.SubjectName.Name}'");
        }

        if (verificationTime is { } time && revocationList.NextUpdate is { } nextUpdate && nextUpdate < time)
        {
            throw new CryptographicException($"The CRL issued by '{revocationList.Issuer.Name}' is stale: its next update was due {nextUpdate:u}");
        }

        return revocationList.IsRevoked(cert);
    }
}
