#nullable enable

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Apple App Attest through its own entry point: attestations and assertions have no client data JSON, no origin and
/// no user presence, so they cannot go through the WebAuthn ceremonies.
/// </summary>
public class AppAttestTests
{
    private const string AppId = "ABCDE12345.com.example.app";

    /// <summary>
    /// A stand-in for Apple's App Attest PKI (a root, the "App Attestation CA 1" intermediate) and one app key, able
    /// to produce the attestation object and assertions the device would.
    /// </summary>
    public sealed class AppAttestDevice : IDisposable
    {
        private static readonly Guid s_productionAaguid = new("61707061-7474-6573-7400-000000000000");
        private static readonly Guid s_developmentAaguid = new("61707061-7474-6573-7464-6576656c6f70");

        private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        private readonly ECDsa _intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly X509Certificate2 _rootWithKey;
        private readonly X509Certificate2 _intermediateWithKey;

        public ECDsa AppKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public X509Certificate2 Root { get; }
        public X509Certificate2 Intermediate { get; }

        /// <summary>The SHA-256 of the uncompressed public key, which is how the app names the key.</summary>
        public byte[] KeyId { get; }

        public CredentialPublicKey PublicKey { get; }

        public AppAttestDevice()
        {
            var rootRequest = new CertificateRequest("CN=Test App Attestation Root CA, O=Test", _rootKey, HashAlgorithmName.SHA384);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
            _rootWithKey = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(20));
            Root = X509CertificateHelper.CreateFromRawData(_rootWithKey.RawData);

            var intermediateRequest = new CertificateRequest("CN=Test App Attestation CA 1, O=Test", _intermediateKey, HashAlgorithmName.SHA256);
            intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            intermediateRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_rootWithKey, true, false));
            intermediateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, false));
            using var intermediate = intermediateRequest.Create(_rootWithKey, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10), [0x02]);
            _intermediateWithKey = intermediate.CopyWithPrivateKey(_intermediateKey);
            Intermediate = X509CertificateHelper.CreateFromRawData(_intermediateWithKey.RawData);

            var q = AppKey.ExportParameters(false).Q;
            KeyId = SHA256.HashData([0x04, .. q.X!, .. q.Y!]);

            // Built the way the verifier rebuilds it from the certificate, since the two are compared byte for byte
            PublicKey = new CredentialPublicKey(AppKey, COSE.Algorithm.ES256);
        }

        /// <summary>
        /// What DCAppAttestService.attestKey returns for this key and clientDataHash.
        /// </summary>
        public byte[] Attest(
            byte[] clientDataHash,
            string appId = AppId,
            bool development = false,
            byte[]? credentialId = null,
            bool includeReceipt = true,
            Guid? aaguid = null,
            uint counter = 0,
            string? certificateAppId = null,
            string? certificateSubject = null,
            CredentialPublicKey? attestedPublicKey = null,
            byte[]? appIdExtension = null)
        {
            byte[] authData = new AuthenticatorData(
                SHA256.HashData(Encoding.UTF8.GetBytes(appId)),
                AuthenticatorFlags.AT,
                counter,
                new AttestedCredentialData(aaguid ?? (development ? s_developmentAaguid : s_productionAaguid), credentialId ?? KeyId, attestedPublicKey ?? PublicKey),
                null).ToByteArray();

            byte[] nonce = SHA256.HashData([.. authData, .. clientDataHash]);
            using var credCert = IssueCredentialCertificate(nonce, certificateAppId ?? appId, _intermediateWithKey, certificateSubject, appIdExtension);

            var attStmt = new CborMap { { "x5c", new CborArray { credCert.RawData, Intermediate.RawData } } };

            if (includeReceipt)
                attStmt.Add("receipt", "receipt bytes"u8.ToArray());

            return new CborMap
            {
                { "fmt", "apple-appattest" },
                { "attStmt", attStmt },
                { "authData", authData },
            }.Encode();
        }

        /// <summary>
        /// What DCAppAttestService.generateAssertion returns for this key, clientDataHash and counter.
        /// </summary>
        public byte[] Assert(byte[] clientDataHash, uint counter, string appId = AppId, ECDsa? signingKey = null)
        {
            byte[] authenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(appId)), 0, counter, null, null).ToByteArray();
            byte[] nonce = SHA256.HashData([.. authenticatorData, .. clientDataHash]);

            return new CborMap
            {
                { "signature", (signingKey ?? AppKey).SignData(nonce, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence) },
                { "authenticatorData", authenticatorData },
            }.Encode();
        }

        /// <summary>
        /// The App ID extension as Apple encodes it: SEQUENCE { ..., [1204] { OCTET STRING appId }, ... }.
        /// </summary>
        public static byte[] AppIdExtension(string appId)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1204)))
            {
                writer.WriteOctetString(Encoding.UTF8.GetBytes(appId));
            }

            return writer.Encode();
        }

        private X509Certificate2 IssueCredentialCertificate(byte[] nonce, string appId, X509Certificate2 issuer, string? subject, byte[]? appIdExtension)
        {
            // Apple names the certificate after the key identifier
            var request = new CertificateRequest(subject ?? $"CN={Convert.ToHexString(KeyId).ToLowerInvariant()}, OU=AAA Certification, O=Test", AppKey, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

            // An empty array stands for "no App ID extension at all"
            if (appIdExtension is not { Length: 0 })
            {
                request.CertificateExtensions.Add(new X509Extension("1.2.840.113635.100.8.5", appIdExtension ?? AppIdExtension(appId), false));
            }

            // 1.2.840.113635.100.8.2: SEQUENCE { [1] { OCTET STRING nonce } }
            var nonceWriter = new AsnWriter(AsnEncodingRules.DER);
            using (nonceWriter.PushSequence())
            using (nonceWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                nonceWriter.WriteOctetString(nonce);
            }

            request.CertificateExtensions.Add(new X509Extension("1.2.840.113635.100.8.2", nonceWriter.Encode(), false));

            return request.Create(issuer, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(3), RandomNumberGenerator.GetBytes(12));
        }

        public void Dispose()
        {
            _rootKey.Dispose();
            _intermediateKey.Dispose();
            _rootWithKey.Dispose();
            _intermediateWithKey.Dispose();
            AppKey.Dispose();
            Root.Dispose();
            Intermediate.Dispose();
        }
    }

    private static byte[] ClientDataHash(string challenge) => SHA256.HashData(Encoding.UTF8.GetBytes(challenge));

    private static AppAttest Verifier(AppAttestDevice device, string appId = AppId, AppAttestEnvironment environments = AppAttestEnvironment.Production)
    {
        return new AppAttest(new AppAttestConfiguration { AppId = appId, Environments = environments, TrustAnchor = device.Root });
    }

    [Fact]
    public async Task Attestation_verifies_and_yields_the_key_to_store()
    {
        using var device = new AppAttestDevice();
        byte[] clientDataHash = ClientDataHash("challenge-1");

        var result = await Verifier(device).VerifyAttestationAsync(device.Attest(clientDataHash), device.KeyId, clientDataHash);

        Assert.Equal(device.KeyId, result.Key.KeyId);
        Assert.Equal(device.PublicKey.GetBytes(), result.Key.PublicKey);
        Assert.Equal(0u, result.Key.Counter);
        Assert.Equal(AppAttestEnvironment.Production, result.Key.Environment);
        Assert.Equal("receipt bytes"u8.ToArray(), result.Key.Receipt);
        Assert.Equal(AttestationType.Basic, result.AttestationType);
        Assert.Equal(2, result.TrustPath.Length);
        Assert.Equal(device.Intermediate.Thumbprint, result.TrustPath[1].Thumbprint);
        Assert.StartsWith($"CN={Convert.ToHexString(device.KeyId).ToLowerInvariant()}", result.TrustPath[0].Subject);
    }

    [Fact]
    public async Task Attestation_without_a_receipt_still_verifies()
    {
        using var device = new AppAttestDevice();
        byte[] clientDataHash = ClientDataHash("challenge-1");

        var result = await Verifier(device).VerifyAttestationAsync(device.Attest(clientDataHash, includeReceipt: false), device.KeyId, clientDataHash);

        Assert.Null(result.Key.Receipt);
    }

    [Fact]
    public async Task Development_keys_are_accepted_only_when_the_configuration_says_so()
    {
        using var device = new AppAttestDevice();
        byte[] clientDataHash = ClientDataHash("challenge-1");
        byte[] attestation = device.Attest(clientDataHash, development: true);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => Verifier(device).VerifyAttestationAsync(attestation, device.KeyId, clientDataHash));
        Assert.Contains("Development environment", ex.Message);

        var result = await Verifier(device, environments: AppAttestEnvironment.Production | AppAttestEnvironment.Development).VerifyAttestationAsync(attestation, device.KeyId, clientDataHash);
        Assert.Equal(AppAttestEnvironment.Development, result.Key.Environment);
    }

    [Fact]
    public async Task Attestation_for_another_app_is_refused()
    {
        using var device = new AppAttestDevice();
        byte[] clientDataHash = ClientDataHash("challenge-1");

        // Genuine in every respect, but scoped to a different App ID than the server is configured for
        byte[] attestation = device.Attest(clientDataHash, appId: "ABCDE12345.com.example.other");

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => Verifier(device).VerifyAttestationAsync(attestation, device.KeyId, clientDataHash));

        Assert.Equal(Fido2ErrorCode.InvalidRpidHash, ex.Code);
        Assert.Contains(AppId, ex.Message);
    }

    [Fact]
    public async Task Attestation_is_refused_when_the_challenge_differs()
    {
        using var device = new AppAttestDevice();

        byte[] attestation = device.Attest(ClientDataHash("challenge-1"));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => Verifier(device).VerifyAttestationAsync(attestation, device.KeyId, ClientDataHash("challenge-2")));

        Assert.Contains("nonce", ex.Message);
    }

    [Fact]
    public async Task Attestation_is_refused_when_the_key_identifier_is_not_the_attested_key()
    {
        using var device = new AppAttestDevice();
        byte[] clientDataHash = ClientDataHash("challenge-1");
        byte[] attestation = device.Attest(clientDataHash);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => Verifier(device).VerifyAttestationAsync(attestation, RandomNumberGenerator.GetBytes(32), clientDataHash));

        Assert.Contains("key identifier", ex.Message);
    }

    [Fact]
    public async Task Attestation_is_refused_when_the_certificate_names_a_different_key()
    {
        using var device = new AppAttestDevice();
        byte[] clientDataHash = ClientDataHash("challenge-1");

        // credentialId in authData differs from the key the certificate is for
        byte[] attestation = device.Attest(clientDataHash, credentialId: RandomNumberGenerator.GetBytes(32));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => Verifier(device).VerifyAttestationAsync(attestation, device.KeyId, clientDataHash));

        Assert.Contains("credentialId", ex.Message);
    }

    public static IEnumerable<object[]> VerifierRefusals()
    {
        // Each item: a way of tampering with an otherwise genuine attestation, and the refusal it must produce
        yield return ["a counter other than zero", new Func<AppAttestDevice, byte[], byte[]>((d, h) => d.Attest(h, counter: 1)), "Sign count does not equal 0"];
        yield return ["an unknown aaguid", new Func<AppAttestDevice, byte[], byte[]>((d, h) => d.Attest(h, aaguid: Guid.NewGuid())), "Invalid aaguid"];
        yield return ["a certificate whose App ID is not the one attested", new Func<AppAttestDevice, byte[], byte[]>((d, h) => d.Attest(h, certificateAppId: "ABCDE12345.com.example.other")), "App ID hash does not match"];
        yield return ["a certificate not named after its key", new Func<AppAttestDevice, byte[], byte[]>((d, h) => d.Attest(h, certificateSubject: $"CN={Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant()}, O=Test")), "Public key hash does not match"];
        yield return ["a certificate without the App ID extension", new Func<AppAttestDevice, byte[], byte[]>((d, h) => d.Attest(h, appIdExtension: [])), "1.2.840.113635.100.8.5 not found"];
        yield return ["a malformed App ID extension", new Func<AppAttestDevice, byte[], byte[]>((d, h) => d.Attest(h, appIdExtension: [0x30, 0x00])), "1.2.840.113635.100.8.5 has invalid data"];
        yield return ["an attested key other than the certificate's", new Func<AppAttestDevice, byte[], byte[]>((d, h) => d.Attest(h, attestedPublicKey: new CredentialPublicKey(ECDsa.Create(ECCurve.NamedCurves.nistP256), COSE.Algorithm.ES256))), "does not match subject public key"];
    }

    [Theory]
    [MemberData(nameof(VerifierRefusals))]
    public async Task Attestation_is_refused_by_each_of_apples_checks(string because, Func<AppAttestDevice, byte[], byte[]> tamper, string refusal)
    {
        using var device = new AppAttestDevice();
        byte[] clientDataHash = ClientDataHash("challenge-1");

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => Verifier(device).VerifyAttestationAsync(tamper(device, clientDataHash), device.KeyId, clientDataHash));

        Assert.True(ex.Message.Contains(refusal), $"{because}: expected '{refusal}', got '{ex.Message}'");
    }

    public static IEnumerable<object[]> MalformedAttestationObjects()
    {
        byte[] authData = new AuthenticatorData(new byte[32], AuthenticatorFlags.AT, 0, null, null).ToByteArray();
        yield return ["no attStmt", new CborMap { { "fmt", "apple-appattest" }, { "authData", authData } }.Encode(), "no attStmt"];
        yield return ["no authData", new CborMap { { "fmt", "apple-appattest" }, { "attStmt", new CborMap() } }.Encode(), "no authData"];
        yield return ["authData without an attested credential", new CborMap { { "fmt", "apple-appattest" }, { "attStmt", new CborMap() }, { "authData", new AuthenticatorData(new byte[32], 0, 0, null, null).ToByteArray() } }.Encode(), "no attested credential"];
    }

    [Theory]
    [MemberData(nameof(MalformedAttestationObjects))]
    public async Task Attestation_object_missing_a_part_is_refused(string because, byte[] attestation, string refusal)
    {
        using var device = new AppAttestDevice();

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => Verifier(device).VerifyAttestationAsync(attestation, device.KeyId, ClientDataHash("challenge-1")));

        Assert.True(ex.Message.Contains(refusal), $"{because}: expected '{refusal}', got '{ex.Message}'");
    }

    [Fact]
    public async Task Attestation_is_refused_when_the_chain_does_not_reach_the_trust_anchor()
    {
        using var device = new AppAttestDevice();
        using var other = new AppAttestDevice();
        byte[] clientDataHash = ClientDataHash("challenge-1");

        // A certificate from another PKI altogether
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => Verifier(other).VerifyAttestationAsync(device.Attest(clientDataHash), device.KeyId, clientDataHash));

        Assert.Contains("chain", ex.Message);
    }

    [Theory]
    [InlineData(new byte[] { 0xff }, "not well-formed CBOR")]
    [InlineData(new byte[] { 0x80 }, "not a CBOR map")]
    public async Task Attestation_that_is_not_an_attestation_object_is_refused(byte[] attestation, string because)
    {
        using var device = new AppAttestDevice();

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => Verifier(device).VerifyAttestationAsync(attestation, device.KeyId, ClientDataHash("challenge-1")));

        Assert.Contains(because, ex.Message);
    }

    [Fact]
    public async Task Attestation_of_another_format_is_refused()
    {
        using var device = new AppAttestDevice();
        byte[] packed = new CborMap { { "fmt", "packed" }, { "attStmt", new CborMap() }, { "authData", new byte[37] } }.Encode();

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => Verifier(device).VerifyAttestationAsync(packed, device.KeyId, ClientDataHash("challenge-1")));

        Assert.Contains("'apple-appattest'", ex.Message);
        Assert.Contains("'packed'", ex.Message);
    }

    [Fact]
    public async Task Assertions_verify_and_advance_the_counter()
    {
        using var device = new AppAttestDevice();
        byte[] clientDataHash = ClientDataHash("challenge-1");
        var verifier = Verifier(device);
        var key = (await verifier.VerifyAttestationAsync(device.Attest(clientDataHash), device.KeyId, clientDataHash)).Key;

        // Each assertion is over the hash of the request it accompanies
        var first = verifier.VerifyAssertion(device.Assert(ClientDataHash("request-1"), counter: 1), ClientDataHash("request-1"), key);
        Assert.Equal(1u, first.Counter);
        Assert.Equal(1u, first.Key.Counter);
        Assert.Equal(key.KeyId, first.Key.KeyId);
        Assert.Equal(key.PublicKey, first.Key.PublicKey);
        Assert.Equal(key.Receipt, first.Key.Receipt);

        var second = verifier.VerifyAssertion(device.Assert(ClientDataHash("request-2"), counter: 7), ClientDataHash("request-2"), first.Key);
        Assert.Equal(7u, second.Counter);
    }

    [Fact]
    public async Task Assertion_whose_counter_did_not_advance_is_refused()
    {
        using var device = new AppAttestDevice();
        byte[] clientDataHash = ClientDataHash("challenge-1");
        var verifier = Verifier(device);
        var key = (await verifier.VerifyAttestationAsync(device.Attest(clientDataHash), device.KeyId, clientDataHash)).Key;

        var advanced = verifier.VerifyAssertion(device.Assert(ClientDataHash("request-1"), counter: 5), ClientDataHash("request-1"), key);

        // Replayed, and a stale one from a clone
        foreach (uint counter in new uint[] { 5, 4, 0 })
        {
            var ex = Assert.Throws<Fido2VerificationException>(() => verifier.VerifyAssertion(device.Assert(ClientDataHash("request-2"), counter), ClientDataHash("request-2"), advanced.Key));
            Assert.Equal(Fido2ErrorCode.InvalidSignCount, ex.Code);
        }
    }

    [Fact]
    public void Assertion_by_another_key_or_over_other_data_is_refused()
    {
        using var device = new AppAttestDevice();
        using var other = new AppAttestDevice();
        var key = new AppAttestKey { KeyId = device.KeyId, PublicKey = device.PublicKey.GetBytes(), Counter = 0, Environment = AppAttestEnvironment.Production };
        var verifier = Verifier(device);

        var ex = Assert.Throws<Fido2VerificationException>(() => verifier.VerifyAssertion(device.Assert(ClientDataHash("request-1"), 1, signingKey: other.AppKey), ClientDataHash("request-1"), key));
        Assert.Equal(Fido2ErrorCode.InvalidSignature, ex.Code);

        ex = Assert.Throws<Fido2VerificationException>(() => verifier.VerifyAssertion(device.Assert(ClientDataHash("request-1"), 1), ClientDataHash("request-tampered"), key));
        Assert.Equal(Fido2ErrorCode.InvalidSignature, ex.Code);
    }

    [Fact]
    public void Assertion_for_another_app_is_refused()
    {
        using var device = new AppAttestDevice();
        var key = new AppAttestKey { KeyId = device.KeyId, PublicKey = device.PublicKey.GetBytes(), Counter = 0, Environment = AppAttestEnvironment.Production };

        var ex = Assert.Throws<Fido2VerificationException>(() => Verifier(device).VerifyAssertion(device.Assert(ClientDataHash("request-1"), 1, appId: "ABCDE12345.com.example.other"), ClientDataHash("request-1"), key));

        Assert.Equal(Fido2ErrorCode.InvalidRpidHash, ex.Code);
    }

    [Theory]
    [InlineData(new byte[] { 0xff }, "not well-formed CBOR")]
    [InlineData(new byte[] { 0x80 }, "not a CBOR map")]
    [InlineData(new byte[] { 0xa0 }, "no signature")]
    [InlineData(new byte[] { 0xa1, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x41, 0x01 }, "no authenticatorData")]
    public void Assertion_that_is_not_an_assertion_is_refused(byte[] assertion, string because)
    {
        using var device = new AppAttestDevice();
        var key = new AppAttestKey { KeyId = device.KeyId, PublicKey = device.PublicKey.GetBytes(), Counter = 0, Environment = AppAttestEnvironment.Production };

        var ex = Assert.Throws<Fido2VerificationException>(() => Verifier(device).VerifyAssertion(assertion, ClientDataHash("request-1"), key));

        Assert.Contains(because, ex.Message);
    }

    [Fact]
    public async Task Apples_own_development_attestation_chains_to_apples_root()
    {
        // A real attestation from a development build (see Attestation/AppleAppAttest.cs). Its one-time challenge is
        // not known, so it cannot verify, but it gets as far as the nonce: the real root, the real chain and the
        // expired-in-development leaf are all accepted first.
        byte[] attestation = Convert.FromBase64String(Attestation.AppleAppAttest.DevelopmentAttestationBase64);

        var verifier = new AppAttest(new AppAttestConfiguration
        {
            AppId = "VNP5A9S22V.76R387MAVZ",
            Environments = AppAttestEnvironment.Development,
        });

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => verifier.VerifyAttestationAsync(attestation, new byte[32], new byte[32]));

        Assert.Contains("nonce", ex.Message);
        Assert.Same(AppAttest.AppleRootCertificate, new AppAttestConfiguration { AppId = "x" }.TrustAnchor);
    }
}
