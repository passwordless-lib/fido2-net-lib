using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib;

using Xunit;

namespace Fido2NetLib.Models.Tests;

/// <summary>
/// Tests for matching a <see cref="MetadataBLOBPayloadEntry"/> that has neither an AAID nor an AAGUID (e.g. a
/// FIDO U2F authenticator) via <see cref="MetadataBLOBPayloadEntry.AttestationCertificateKeyIdentifiers"/>.
/// </summary>
public class MetadataBLOBPayloadEntryTests
{
    private static X509Certificate2 CreateSelfSignedCertificate()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Test Attestation Cert", ecdsa, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    [Fact]
    public void MatchesAttestationCertificate_Returns_True_For_Known_Key_Identifier()
    {
        using var cert = CreateSelfSignedCertificate();
        var keyIdentifier = MetadataBLOBPayloadEntry.ComputeAttestationCertificateKeyIdentifier(cert);

        var entry = new MetadataBLOBPayloadEntry
        {
            AttestationCertificateKeyIdentifiers = [keyIdentifier]
        };

        Assert.True(entry.MatchesAttestationCertificate(cert));
    }

    [Fact]
    public void MatchesAttestationCertificate_Is_Case_Insensitive()
    {
        using var cert = CreateSelfSignedCertificate();
        var keyIdentifier = MetadataBLOBPayloadEntry.ComputeAttestationCertificateKeyIdentifier(cert);

        var entry = new MetadataBLOBPayloadEntry
        {
            AttestationCertificateKeyIdentifiers = [keyIdentifier.ToUpperInvariant()]
        };

        Assert.True(entry.MatchesAttestationCertificate(cert));
    }

    [Fact]
    public void MatchesAttestationCertificate_Returns_False_For_Unrelated_Certificate()
    {
        using var cert = CreateSelfSignedCertificate();
        using var otherCert = CreateSelfSignedCertificate();

        var entry = new MetadataBLOBPayloadEntry
        {
            AttestationCertificateKeyIdentifiers = [MetadataBLOBPayloadEntry.ComputeAttestationCertificateKeyIdentifier(otherCert)]
        };

        Assert.False(entry.MatchesAttestationCertificate(cert));
    }

    [Fact]
    public void MatchesAttestationCertificate_Returns_False_When_No_Key_Identifiers_Present()
    {
        using var cert = CreateSelfSignedCertificate();

        var entry = new MetadataBLOBPayloadEntry
        {
            AttestationCertificateKeyIdentifiers = null
        };

        Assert.False(entry.MatchesAttestationCertificate(cert));
    }
}
