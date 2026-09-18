using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib;

namespace Test;

/// <summary>
/// A root, an intermediate it issued, and a leaf the intermediate issued, with the keys needed to issue more.
/// </summary>
internal sealed class TestPki : IDisposable
{
    public const string EcdsaWithSha1 = "1.2.840.10045.4.1";
    public const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";
    public const string Sha256WithRsaEncryption = "1.2.840.113549.1.1.11";
    public const string RsassaPss = "1.2.840.113549.1.1.10";

    private readonly DateTimeOffset _now = DateTimeOffset.UtcNow;
    private readonly bool _useRsa;
    private readonly AsymmetricAlgorithm _rootKey;
    private readonly AsymmetricAlgorithm _intermediateKey;
    private readonly AsymmetricAlgorithm _lookalikeKey;
    private readonly X509Certificate2 _rootWithKey;
    private readonly X509Certificate2 _intermediateWithKey;
    private readonly X509Certificate2 _lookalikeWithKey;
    private int _serial = 0x80; // top bit set, so every serial number carries a sign-padding octet

    /// <param name="useRsa">Issue RSA rather than ECDSA keys throughout.</param>
    public TestPki(bool useRsa = false)
    {
        _useRsa = useRsa;
        _rootKey = CreateKey();
        _intermediateKey = CreateKey();
        _lookalikeKey = CreateKey();

        // The names carry a unique suffix so that no run can be served a CRL another run left in a cache
        string suffix = Guid.NewGuid().ToString("N");

        var rootRequest = CreateRequest($"CN=Test Root {suffix}", _rootKey);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        _rootWithKey = rootRequest.CreateSelfSigned(_now.AddDays(-2), _now.AddYears(10));
        Root = WithoutKey(_rootWithKey);

        _intermediateWithKey = IssueIntermediate($"CN=Test Intermediate {suffix}", _intermediateKey);
        Intermediate = WithoutKey(_intermediateWithKey);

        _lookalikeWithKey = IssueIntermediate($"CN=Test Intermediate {suffix}", _lookalikeKey, subjectKeyIdentifierOf: _intermediateWithKey);
        IntermediateLookalike = WithoutKey(_lookalikeWithKey);

        Leaf = IssueLeaf();
        ExpiredLeaf = IssueLeaf(notBefore: _now.AddDays(-2), notAfter: _now.AddDays(-1));

        EmptyCrl = BuildCrl();
        CrlRevokingLeaf = BuildCrl(Leaf);
    }

    public X509Certificate2 Root { get; }
    public X509Certificate2 Intermediate { get; }

    /// <summary>
    /// Same subject, same issuer and same subject key identifier as <see cref="Intermediate"/>, but a different key.
    /// </summary>
    public X509Certificate2 IntermediateLookalike { get; }
    public X509Certificate2 Leaf { get; }
    public X509Certificate2 ExpiredLeaf { get; }

    /// <summary>The intermediate's CRL, listing nothing.</summary>
    public byte[] EmptyCrl { get; }

    /// <summary>The intermediate's CRL, listing <see cref="Leaf"/>.</summary>
    public byte[] CrlRevokingLeaf { get; }

    /// <summary>
    /// Issues a leaf naming the given CRL distribution points, in order.
    /// </summary>
    public X509Certificate2 IssueLeaf(params string[] crlDistributionPointUrls)
    {
        return IssueLeaf(_now.AddDays(-1), _now.AddYears(1), crlDistributionPointUrls);
    }

    private X509Certificate2 IssueLeaf(DateTimeOffset notBefore, DateTimeOffset notAfter, params string[] crlDistributionPointUrls)
    {
        using var leafKey = CreateKey();
        var request = CreateRequest("CN=Test Leaf", leafKey);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_intermediateWithKey, true, false));

        if (crlDistributionPointUrls.Length > 0)
        {
            request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(crlDistributionPointUrls));
        }

        return request.Create(_intermediateWithKey, notBefore, notAfter, NextSerial());
    }

    /// <summary>
    /// Issues a leaf carrying a CRL Distribution Points extension supplied verbatim, however malformed.
    /// </summary>
    public X509Certificate2 IssueLeafWithRawCrlDistributionPoints(byte[] rawExtension)
    {
        using var leafKey = CreateKey();
        var request = CreateRequest("CN=Test Leaf", leafKey);
        request.CertificateExtensions.Add(new X509Extension("2.5.29.31", rawExtension, false));

        return request.Create(_intermediateWithKey, _now.AddDays(-1), _now.AddYears(1), NextSerial());
    }

    /// <summary>
    /// Builds the intermediate's CRL, listing the given certificates, good for a week.
    /// </summary>
    public byte[] BuildCrl(params X509Certificate2[] revoked) => BuildCrl(_now.AddDays(7), null, revoked);

    /// <summary>
    /// Builds the intermediate's CRL with <see cref="CertificateRevocationListBuilder"/>.
    /// </summary>
    public byte[] BuildCrl(DateTimeOffset nextUpdate, HashAlgorithmName? hashAlgorithm, params X509Certificate2[] revoked)
    {
        return Build(_intermediateWithKey, nextUpdate, hashAlgorithm ?? HashAlgorithmName.SHA256, revoked);
    }

    /// <summary>
    /// Builds the root's CRL, which covers the intermediate and so is the wrong CRL for a leaf.
    /// </summary>
    public byte[] BuildRootCrl(params X509Certificate2[] revoked) => Build(_rootWithKey, _now.AddDays(7), HashAlgorithmName.SHA256, revoked);

    /// <summary>
    /// Builds a CRL in the intermediate's name but signed with the look-alike's key: a forgery.
    /// </summary>
    public byte[] BuildLookalikeCrl(params X509Certificate2[] revoked) => Build(_lookalikeWithKey, _now.AddDays(7), HashAlgorithmName.SHA256, revoked);

    private byte[] Build(X509Certificate2 issuer, DateTimeOffset nextUpdate, HashAlgorithmName hashAlgorithm, X509Certificate2[] revoked)
    {
        var builder = new CertificateRevocationListBuilder();

        foreach (X509Certificate2 certificate in revoked)
        {
            builder.AddEntry(certificate);
        }

        // A stale CRL must still have been issued before it fell due
        DateTimeOffset thisUpdate = nextUpdate < _now ? nextUpdate.AddDays(-7) : _now.AddMinutes(-1);

        return builder.Build(issuer, crlNumber: 1, nextUpdate, hashAlgorithm, _useRsa ? RSASignaturePadding.Pkcs1 : null, thisUpdate);
    }

    /// <summary>
    /// Hand-assembles the intermediate's CRL with every optional TBSCertList field other than revokedCertificates
    /// omitted -- a shape <see cref="CertificateRevocationListBuilder"/> cannot produce -- with the version, signature
    /// algorithm and BIT STRING padding under the caller's control.
    /// </summary>
    /// <param name="revokedSerialNumber">The one serial number the CRL lists.</param>
    /// <param name="version">The version field, or <see langword="null"/> to omit it as a v1 CRL does.</param>
    /// <param name="signatureAlgorithm">The algorithm identifier to write; the signature itself is always made with
    /// the key's own algorithm and <paramref name="hashAlgorithm"/>.</param>
    /// <param name="hashAlgorithm">The digest to sign with.</param>
    /// <param name="unusedBitCount">Padding bits to declare on the signature BIT STRING; a CRL has none.</param>
    public byte[] BuildMinimalCrl(ReadOnlySpan<byte> revokedSerialNumber, int? version = 1, string signatureAlgorithm = null, HashAlgorithmName? hashAlgorithm = null, int unusedBitCount = 0)
    {
        signatureAlgorithm ??= _useRsa ? Sha256WithRsaEncryption : EcdsaWithSha256;
        HashAlgorithmName hash = hashAlgorithm ?? HashAlgorithmName.SHA256;

        var tbs = new AsnWriter(AsnEncodingRules.DER);
        using (tbs.PushSequence())
        {
            if (version is { } v)
                tbs.WriteInteger(v);

            using (tbs.PushSequence())
            {
                tbs.WriteObjectIdentifier(signatureAlgorithm);
                if (_useRsa)
                    tbs.WriteNull();
            }

            tbs.WriteEncodedValue(Intermediate.SubjectName.RawData);
            tbs.WriteUtcTime(_now.AddMinutes(-1));

            using (tbs.PushSequence())
            using (tbs.PushSequence())
            {
                tbs.WriteInteger(revokedSerialNumber);
                tbs.WriteUtcTime(_now.AddMinutes(-1));
            }
        }

        byte[] tbsCertList = tbs.Encode();

        byte[] signature = _useRsa
            ? ((RSA)_intermediateKey).SignData(tbsCertList, hash, RSASignaturePadding.Pkcs1)
            : ((ECDsa)_intermediateKey).SignData(tbsCertList, hash, DSASignatureFormat.Rfc3279DerSequence);

        var crl = new AsnWriter(AsnEncodingRules.DER);
        using (crl.PushSequence())
        {
            crl.WriteEncodedValue(tbsCertList);

            using (crl.PushSequence())
            {
                crl.WriteObjectIdentifier(signatureAlgorithm);
                if (_useRsa)
                    crl.WriteNull();
            }

            if (unusedBitCount > 0)
                signature[^1] &= (byte)(0xff << unusedBitCount); // the writer insists the padding bits are clear

            crl.WriteBitString(signature, unusedBitCount);
        }

        return crl.Encode();
    }

    private X509Certificate2 IssueIntermediate(string subject, AsymmetricAlgorithm key, X509Certificate2 subjectKeyIdentifierOf = null)
    {
        var request = CreateRequest(subject, key);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_rootWithKey, true, false));

        // A look-alike claims the real intermediate's subject key identifier, so chain building cannot tell them apart by name
        request.CertificateExtensions.Add(subjectKeyIdentifierOf is null
            ? new X509SubjectKeyIdentifierExtension(request.PublicKey, false)
            : subjectKeyIdentifierOf.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single());

        using var issued = request.Create(_rootWithKey, _now.AddDays(-2), _now.AddYears(5), NextSerial());

        return key is RSA rsa ? issued.CopyWithPrivateKey(rsa) : issued.CopyWithPrivateKey((ECDsa)key);
    }

    private AsymmetricAlgorithm CreateKey() => _useRsa ? RSA.Create(2048) : ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private static CertificateRequest CreateRequest(string subject, AsymmetricAlgorithm key)
    {
        return key is RSA rsa
            ? new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            : new CertificateRequest(subject, (ECDsa)key, HashAlgorithmName.SHA256);
    }

    private byte[] NextSerial() => [(byte)(_serial++ & 0xff)];

    private static X509Certificate2 WithoutKey(X509Certificate2 certificate) => X509CertificateHelper.CreateFromRawData(certificate.RawData);

    public void Dispose()
    {
        _rootKey.Dispose();
        _intermediateKey.Dispose();
        _lookalikeKey.Dispose();
        _rootWithKey.Dispose();
        _intermediateWithKey.Dispose();
        _lookalikeWithKey.Dispose();
        Root.Dispose();
        Intermediate.Dispose();
        IntermediateLookalike.Dispose();
        Leaf.Dispose();
        ExpiredLeaf.Dispose();
    }
}
