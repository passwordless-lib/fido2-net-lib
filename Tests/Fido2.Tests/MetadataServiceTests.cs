using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;

namespace Test;

public class MetadataServiceTests
{
    private sealed class StubHttpMessageHandler(IReadOnlyList<HttpResponseMessage> responses) : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = responses[Math.Min(CallCount, responses.Count - 1)];
            CallCount++;
            return Task.FromResult(response);
        }
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler) { BaseAddress = new Uri("https://mds.example.test") };
    }

    private static HttpResponseMessage ThrottledResponse(TimeSpan retryAfter)
    {
        var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(retryAfter);
        return response;
    }

    [Fact]
    public async Task Fido2MetadataServiceRepository_Retries_On_429_Then_Succeeds()
    {
        var handler = new StubHttpMessageHandler(
        [
            ThrottledResponse(TimeSpan.FromMilliseconds(10)),
            ThrottledResponse(TimeSpan.FromMilliseconds(10)),
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("not-a-valid-jwt") }
        ]);

        var repository = new Fido2MetadataServiceRepository(new StubHttpClientFactory(handler));

        // GetRawBlobAsync succeeds after retrying the two 429 responses; the returned content then
        // fails JWT parsing (expected, since it's not a real BLOB), which proves the raw fetch itself
        // used the third (successful) response rather than one of the throttled ones.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());

        Assert.Contains("3 expected components", ex.Message);
        Assert.Equal(3, handler.CallCount);
    }

    [Fact]
    public async Task Fido2MetadataServiceRepository_Throws_After_Exhausting_Retries_On_Persistent_429()
    {
        var handler = new StubHttpMessageHandler(
        [
            ThrottledResponse(TimeSpan.FromMilliseconds(10))
        ]);

        var repository = new Fido2MetadataServiceRepository(new StubHttpClientFactory(handler));

        var ex = await Assert.ThrowsAsync<Fido2MetadataException>(() => repository.GetBLOBAsync());

        Assert.Contains("429", ex.Message);
        // initial attempt + 4 retries (MaxRetryAttempts) = 5 total requests
        Assert.Equal(5, handler.CallCount);
    }

    private sealed class ETagAwareHttpMessageHandler : HttpMessageHandler
    {
        private const string ETag = "\"blob-etag-v1\"";
        private const string Body = "not-a-valid-jwt";

        public int CallCount { get; private set; }

        public EntityTagHeaderValue LastIfNoneMatch { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            LastIfNoneMatch = request.Headers.IfNoneMatch.FirstOrDefault();

            if (LastIfNoneMatch is not null && LastIfNoneMatch.Tag == ETag)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotModified));
            }

            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Body) };
            response.Headers.ETag = new EntityTagHeaderValue(ETag);
            return Task.FromResult(response);
        }
    }

    [Fact]
    public async Task Fido2MetadataServiceRepository_Sends_Conditional_Get_Using_Previous_ETag()
    {
        var handler = new ETagAwareHttpMessageHandler();
        var repository = new Fido2MetadataServiceRepository(new StubHttpClientFactory(handler));

        // First fetch: no cached ETag yet, so no If-None-Match is sent; server returns 200 + ETag.
        var firstEx = await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());
        Assert.Contains("3 expected components", firstEx.Message);
        Assert.Null(handler.LastIfNoneMatch);

        // Second fetch: the repository (a singleton in production) reuses the ETag from the first
        // response, the server replies 304, and the repository falls back to its cached raw BLOB
        // content -- proven by getting the same downstream JWT-parsing error rather than one about
        // empty/missing content (a 304 response has no body).
        var secondEx = await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());
        Assert.Contains("3 expected components", secondEx.Message);
        Assert.NotNull(handler.LastIfNoneMatch);
        Assert.Equal("\"blob-etag-v1\"", handler.LastIfNoneMatch.Tag);

        Assert.Equal(2, handler.CallCount);
    }

    private sealed class NoETagHttpMessageHandler : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        public bool AnyRequestSentIfNoneMatch { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            AnyRequestSentIfNoneMatch |= request.Headers.IfNoneMatch.Any();

            // Deliberately never returns an ETag, e.g. a server/proxy that doesn't support conditional GET.
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("not-a-valid-jwt") });
        }
    }

    [Fact]
    public async Task Fido2MetadataServiceRepository_Does_Not_Send_Conditional_Get_Without_A_Prior_ETag()
    {
        var handler = new NoETagHttpMessageHandler();
        var repository = new Fido2MetadataServiceRepository(new StubHttpClientFactory(handler));

        await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());
        await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());

        Assert.Equal(2, handler.CallCount);
        Assert.False(handler.AnyRequestSentIfNoneMatch);
    }

    // The live MDS BLOB lists most entries' status reports newest first (BLOB #280: 42 entries newest first, 3
    // oldest first), and the spec defines no order at all, so the latest report has to be picked by effective date.
    [Fact]
    public void GetLatestStatusReport_Uses_Effective_Date_Not_Array_Position()
    {
        // TruU Windows Authenticator, ba86dc56-635f-4141-aef6-00227b1b9af6, as published in BLOB #280
        var newestFirst = new MetadataBLOBPayloadEntry
        {
            StatusReports =
            [
                new StatusReport { Status = AuthenticatorStatus.REVOKED, EffectiveDate = "2023-12-20", AuthenticatorVersion = 1 },
                new StatusReport { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED, EffectiveDate = "2023-11-07" }
            ]
        };
        Assert.Equal(AuthenticatorStatus.REVOKED, newestFirst.GetLatestStatusReport().Status);

        var oldestFirst = new MetadataBLOBPayloadEntry
        {
            StatusReports =
            [
                new StatusReport { Status = AuthenticatorStatus.FIDO_CERTIFIED, EffectiveDate = "2018-11-08" },
                new StatusReport { Status = AuthenticatorStatus.FIDO_CERTIFIED_L1, EffectiveDate = "2020-11-19" }
            ]
        };
        Assert.Equal(AuthenticatorStatus.FIDO_CERTIFIED_L1, oldestFirst.GetLatestStatusReport().Status);

        var dateTimes = new MetadataBLOBPayloadEntry
        {
            StatusReports =
            [
                new StatusReport { Status = AuthenticatorStatus.UPDATE_AVAILABLE, EffectiveDate = "2024-02-19T10:00:00Z" },
                new StatusReport { Status = AuthenticatorStatus.USER_VERIFICATION_BYPASS, EffectiveDate = "2024-02-19T09:00:00Z" },
                new StatusReport { Status = AuthenticatorStatus.FIDO_CERTIFIED, EffectiveDate = "2024-01-07" }
            ]
        };
        Assert.Equal(AuthenticatorStatus.UPDATE_AVAILABLE, dateTimes.GetLatestStatusReport().Status);
    }

    [Fact]
    public void GetLatestStatusReport_Ties_Missing_Dates_And_Empty_Arrays()
    {
        // same effective date: the last in the array wins, as it always did for undated reports
        var tied = new MetadataBLOBPayloadEntry
        {
            StatusReports =
            [
                new StatusReport { Status = AuthenticatorStatus.FIDO_CERTIFIED, EffectiveDate = "2023-12-28" },
                new StatusReport { Status = AuthenticatorStatus.FIDO_CERTIFIED_L1, EffectiveDate = "2023-12-28" }
            ]
        };
        Assert.Equal(AuthenticatorStatus.FIDO_CERTIFIED_L1, tied.GetLatestStatusReport().Status);

        var undatedInOrder = new MetadataBLOBPayloadEntry
        {
            StatusReports =
            [
                new StatusReport { Status = AuthenticatorStatus.FIDO_CERTIFIED },
                new StatusReport { Status = AuthenticatorStatus.REVOKED },
                new StatusReport { Status = AuthenticatorStatus.UPDATE_AVAILABLE }
            ]
        };
        Assert.Equal(AuthenticatorStatus.UPDATE_AVAILABLE, undatedInOrder.GetLatestStatusReport().Status);

        // a report without a date (as FileSystemMetadataRepository produces) is older than any dated one
        var undated = new MetadataBLOBPayloadEntry
        {
            StatusReports =
            [
                new StatusReport { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED },
                new StatusReport { Status = AuthenticatorStatus.FIDO_CERTIFIED, EffectiveDate = "2019-01-01" },
                new StatusReport { Status = AuthenticatorStatus.SELF_ASSERTION_SUBMITTED, EffectiveDate = "not a date" }
            ]
        };
        Assert.Equal(AuthenticatorStatus.FIDO_CERTIFIED, undated.GetLatestStatusReport().Status);

        var onlyUndated = new MetadataBLOBPayloadEntry { StatusReports = [new StatusReport { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED }] };
        Assert.Equal(AuthenticatorStatus.NOT_FIDO_CERTIFIED, onlyUndated.GetLatestStatusReport().Status);

        Assert.Null(new MetadataBLOBPayloadEntry { StatusReports = [] }.GetLatestStatusReport());
        Assert.Null(new MetadataBLOBPayloadEntry().GetLatestStatusReport());
    }

    private sealed class StatusReportRepository(Guid aaguid, params StatusReport[] statusReports) : IMetadataRepository
    {
        public Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new MetadataBLOBPayload
            {
                Number = 1,
                NextUpdate = "2099-01-01",
                LegalHeader = "test",
                Entries =
                [
                    new MetadataBLOBPayloadEntry
                    {
                        AaGuid = aaguid,
                        MetadataStatement = new MetadataStatement { Description = "Revoked model", AttestationTypes = ["basic_full"] },
                        StatusReports = statusReports
                    }
                ]
            });
        }

        public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(entry.MetadataStatement);
        }
    }

    private static DistributedCacheMetadataService CreateService(IMetadataRepository repository, ISystemClock clock = null, IMemoryCache memoryCache = null)
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddLogging();

        var provider = services.BuildServiceProvider();

        return new DistributedCacheMetadataService(
            [repository],
            provider.GetService<IDistributedCache>(),
            memoryCache ?? provider.GetService<IMemoryCache>(),
            provider.GetService<ILogger<DistributedCacheMetadataService>>(),
            clock ?? new MockClock(DateTimeOffset.UtcNow)
        );
    }

    [Fact]
    public async Task Registration_Is_Refused_For_An_Authenticator_Whose_Revocation_Is_Not_The_Last_Status_Report()
    {
        var aaguid = new Guid("ba86dc56-635f-4141-aef6-00227b1b9af6");
        var metadataService = CreateService(new StatusReportRepository(aaguid,
            new StatusReport { Status = AuthenticatorStatus.REVOKED, EffectiveDate = "2023-12-20", AuthenticatorVersion = 1 },
            new StatusReport { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED, EffectiveDate = "2023-11-07" }));

        const string rp = "https://www.passwordless.dev";
        var config = new Fido2Configuration { RPID = rp, RPName = rp, Origins = new HashSet<string> { rp } };
        var lib = new Fido2(config, metadataService);

        var challenge = RandomNumberGenerator.GetBytes(32);
        var credentialId = RandomNumberGenerator.GetBytes(16);
        var credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);
        var authData = new AuthenticatorData(
            SHA256.HashData(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.AT | AuthenticatorFlags.UP,
            0,
            new AttestedCredentialData(aaguid, credentialId, credentialPublicKey));
        var attestationObject = new CborMap
        {
            { "fmt", "none" },
            { "attStmt", new CborMap() },
            { "authData", authData.ToByteArray() }
        };
        var clientDataJson = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new MockClientData { Type = "webauthn.create", Challenge = challenge, Origin = rp });

        var ex = await Assert.ThrowsAsync<UndesiredMetadataStatusFido2VerificationException>(() => lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = "8dA",
                RawId = [0xf1, 0xd0],
                Response = new AuthenticatorAttestationRawResponse.AttestationResponse
                {
                    AttestationObject = attestationObject.Encode(),
                    ClientDataJson = clientDataJson,
                    Transports = [AuthenticatorTransport.Usb]
                },
                ClientExtensionResults = new AuthenticationExtensionsClientOutputs()
            },
            OriginalOptions = new CredentialCreateOptions
            {
                Challenge = challenge,
                Rp = new PublicKeyCredentialRpEntity(rp, rp),
                User = new Fido2User { Id = "testuser"u8.ToArray(), Name = "testuser", DisplayName = "Test User" },
                PubKeyCredParams = PubKeyCredParam.Defaults,
                AuthenticatorSelection = AuthenticatorSelection.Default
            },
            IsCredentialIdUniqueToUserCallback = (_, _) => Task.FromResult(true)
        }));

        Assert.Equal(AuthenticatorStatus.REVOKED, ex.StatusReport.Status);
    }

    private sealed class FlakyRepository(int failures) : IMetadataRepository
    {
        private int _remainingFailures = failures;

        public int Calls { get; private set; }

        public Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
        {
            Calls++;

            if (_remainingFailures-- > 0)
                throw new HttpRequestException("MDS is unreachable");

            return Task.FromResult(new MetadataBLOBPayload
            {
                Number = 1,
                NextUpdate = "2099-01-01",
                LegalHeader = "test",
                Entries =
                [
                    new MetadataBLOBPayloadEntry
                    {
                        AaGuid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"),
                        MetadataStatement = new MetadataStatement { Description = "Security Key by Yubico with NFC" },
                        StatusReports = [new StatusReport { Status = AuthenticatorStatus.FIDO_CERTIFIED_L1 }]
                    }
                ]
            });
        }

        public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(entry.MetadataStatement);
        }
    }

    [Fact]
    public async Task DistributedCacheMetadataService_Does_Not_Cache_A_Failed_Fetch()
    {
        var repository = new FlakyRepository(failures: 1);
        var service = CreateService(repository);
        var aaguid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

        // the repository is unreachable on the first lookup...
        Assert.Null(await service.GetEntryAsync(aaguid));
        Assert.Equal(1, repository.Calls);

        // ...so the next lookup must try it again rather than answer from a cached failure
        var entry = await service.GetEntryAsync(aaguid);

        Assert.Equal(2, repository.Calls);
        Assert.NotNull(entry);
        Assert.Equal("Security Key by Yubico with NFC", entry.MetadataStatement.Description);

        // and once the BLOB is in hand it is cached, with no further fetches
        await service.GetEntryAsync(aaguid);
        Assert.Equal(2, repository.Calls);
    }

    private sealed class SlowRepository(TimeSpan delay) : IMetadataRepository
    {
        public int Calls { get; private set; }

        public async Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
        {
            Calls++;
            await Task.Delay(delay, cancellationToken);

            return new MetadataBLOBPayload
            {
                Number = 1,
                NextUpdate = "2099-01-01",
                LegalHeader = "test",
                Entries =
                [
                    new MetadataBLOBPayloadEntry
                    {
                        AaGuid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"),
                        MetadataStatement = new MetadataStatement { Description = "Security Key by Yubico with NFC" },
                        StatusReports = [new StatusReport { Status = AuthenticatorStatus.FIDO_CERTIFIED_L1 }]
                    }
                ]
            };
        }

        public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(entry.MetadataStatement);
        }
    }

    [Fact]
    public async Task DistributedCacheMetadataService_Coalesces_Concurrent_Fetches_For_A_Cold_Cache()
    {
        var repository = new SlowRepository(TimeSpan.FromMilliseconds(100));
        var service = CreateService(repository);
        var aaguid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

        // 20 lookups racing a cold cache must produce one repository fetch, not 20.
        var lookups = Enumerable.Range(0, 20).Select(_ => service.GetEntryAsync(aaguid));
        var entries = await Task.WhenAll(lookups);

        Assert.Equal(1, repository.Calls);
        Assert.All(entries, entry => Assert.Equal("Security Key by Yubico with NFC", entry.MetadataStatement.Description));
    }

    [Fact]
    public async Task DistributedCacheMetadataService_Retries_A_Lookup_That_Had_No_Blob_To_Search()
    {
        var clock = new MockClock(DateTimeOffset.Parse("2021-11-30T00:00:00Z"));
        var memoryCache = new MemoryCache(new MemoryCacheOptions { Clock = clock });
        var repository = new FlakyRepository(failures: 1);
        var service = CreateService(repository, clock, memoryCache);
        var known = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

        // no BLOB could be fetched: nothing is found, and nothing is remembered
        Assert.Null(await service.GetEntryAsync(known));

        // so the next lookup fetches again, and finds the entry
        Assert.NotNull(await service.GetEntryAsync(known));
        Assert.Equal(2, repository.Calls);
    }

    [Fact]
    public async Task DistributedCacheMetadataService_Lookups_Do_Not_Add_To_The_Cache()
    {
        // Registrations choose their own AAGUIDs; looking one up must not leave anything behind for it.
        var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var service = CreateService(new MockRepository("2099-01-01"), memoryCache: memoryCache);

        await service.GetEntryAsync(Guid.NewGuid());
        var afterFirst = memoryCache.Count;

        for (int i = 0; i < 100; i++)
            Assert.Null(await service.GetEntryAsync(Guid.NewGuid()));

        Assert.Equal(afterFirst, memoryCache.Count);
    }

    [Fact]
    public async Task FileSystemMetadataRepository_Can_Be_Fetched_More_Than_Once()
    {
        var repository = new FileSystemMetadataRepository("./metadata");

        var first = await repository.GetBLOBAsync();
        var second = await repository.GetBLOBAsync();

        Assert.NotEmpty(first.Entries);
        Assert.Equal(first.Entries.Select(e => e.AaGuid), second.Entries.Select(e => e.AaGuid));
    }

    [Fact]
    public async Task FileSystemMetadataRepository_Refuses_Two_Statements_With_The_Same_Aaguid()
    {
        var directory = Directory.CreateTempSubdirectory("fido2-metadata-");
        try
        {
            var statement = Directory.GetFiles("./metadata").First();
            File.Copy(statement, Path.Combine(directory.FullName, "one.json"));
            File.Copy(statement, Path.Combine(directory.FullName, "two.json"));

            var repository = new FileSystemMetadataRepository(directory.FullName);

            var ex = await Assert.ThrowsAsync<Fido2MetadataException>(() => repository.GetBLOBAsync());
            Assert.Contains("same AAGUID", ex.Message);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task ConformanceTestClient()
    {
        var client = new ConformanceMetadataRepository(null, "http://localhost:80");

        var cancellationToken = CancellationToken.None;

        var blob = await client.GetBLOBAsync(cancellationToken);

        Assert.NotEmpty(blob.Entries);

        var entry_1 = await client.GetMetadataStatementAsync(blob, blob.Entries[^1], cancellationToken);

        Assert.NotNull(entry_1.Description);
    }

    public class MockRepository : IMetadataRepository
    {
        public int GetBLOBAsyncCount { get; private set; }

        private string _nextUpdate;
        private int _number;

        public string NextUpdate
        {
            set
            {
                _nextUpdate = value;
                _number++;
            }
            get
            {
                return _nextUpdate;
            }
        }

        public MockRepository(string nextUpdate)
        {
            _nextUpdate = nextUpdate;
            _number = 1;
        }

        public Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
        {
            GetBLOBAsyncCount++;

            var payload = new MetadataBLOBPayload
            {
                NextUpdate = NextUpdate,
                Number = _number,
                Entries =
                [
                    new MetadataBLOBPayloadEntry
                    {
                        AaGuid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"),
                        MetadataStatement = new MetadataStatement
                        {
                            Description = "Security Key by Yubico with NFC"
                        }
                    }
                ]
            };

            return Task.FromResult(payload);

        }

        public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(entry.MetadataStatement);
        }
    }

    public class MockClock(DateTimeOffset time) : ISystemClock
    {
        public DateTimeOffset UtcNow { get; set; } = time;
    }

    private sealed class U2FStyleMockRepository(string attestationCertificateKeyIdentifier) : IMetadataRepository
    {
        public Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
        {
            var payload = new MetadataBLOBPayload
            {
                NextUpdate = "2099-01-01",
                Number = 1,
                Entries =
                [
                    new MetadataBLOBPayloadEntry
                    {
                        // FIDO U2F authenticators have neither an AAID nor an AAGUID in MDS; they're
                        // identified solely by the attestation certificate's key identifier.
                        AaGuid = null,
                        AttestationCertificateKeyIdentifiers = [attestationCertificateKeyIdentifier],
                        MetadataStatement = new MetadataStatement
                        {
                            Description = "U2F Security Key"
                        }
                    }
                ]
            };

            return Task.FromResult(payload);
        }

        public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(entry.MetadataStatement);
        }
    }

    [Fact]
    public async Task DistributedCacheMetadataService_Falls_Back_To_Attestation_Certificate_Key_Identifier()
    {
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=Test U2F Attestation Cert", ecdsa, System.Security.Cryptography.HashAlgorithmName.SHA256);
        using var attestationCertificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var keyIdentifier = MetadataBLOBPayloadEntry.ComputeAttestationCertificateKeyIdentifier(attestationCertificate);

        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddLogging();

        var provider = services.BuildServiceProvider();

        var repositories = new List<IMetadataRepository> { new U2FStyleMockRepository(keyIdentifier) };

        var service = new DistributedCacheMetadataService(
            repositories,
            provider.GetService<IDistributedCache>(),
            provider.GetService<IMemoryCache>(),
            provider.GetService<ILogger<DistributedCacheMetadataService>>(),
            new MockClock(DateTimeOffset.UtcNow)
        );

        // An AAGUID-only lookup finds nothing, since this entry has no AAGUID.
        var noMatch = await service.GetEntryAsync(Guid.NewGuid());
        Assert.Null(noMatch);

        // But passing the attestation trust path lets it match via AttestationCertificateKeyIdentifiers.
        var match = await service.GetEntryAsync(Guid.NewGuid(), [attestationCertificate]);

        Assert.NotNull(match);
        Assert.Equal("U2F Security Key", match.MetadataStatement.Description);
    }

    // Every FIDO U2F registration carries the all-zero AAGUID, and U2F metadata is found by the attestation
    // certificate instead. The answer for one certificate must never be handed to another -- as it was when lookups
    // were cached by AAGUID alone, in either order below.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DistributedCacheMetadataService_Finds_Aaguidless_Entries_By_Each_Lookups_Own_Certificate(bool unmatchedFirst)
    {
        static System.Security.Cryptography.X509Certificates.X509Certificate2 SelfSigned(string subject)
        {
            using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            return new System.Security.Cryptography.X509Certificates.CertificateRequest(subject, key, System.Security.Cryptography.HashAlgorithmName.SHA256)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        }

        using var listed = SelfSigned("CN=Listed U2F Attestation");
        using var unlisted = SelfSigned("CN=Unlisted Attestation");
        var service = CreateService(new U2FStyleMockRepository(MetadataBLOBPayloadEntry.ComputeAttestationCertificateKeyIdentifier(listed)));

        if (unmatchedFirst)
        {
            Assert.Null(await service.GetEntryAsync(Guid.Empty, [unlisted]));
            Assert.Equal("U2F Security Key", (await service.GetEntryAsync(Guid.Empty, [listed]))?.MetadataStatement.Description);
        }
        else
        {
            Assert.Equal("U2F Security Key", (await service.GetEntryAsync(Guid.Empty, [listed]))?.MetadataStatement.Description);
            Assert.Null(await service.GetEntryAsync(Guid.Empty, [unlisted]));
        }

        // and a lookup with no certificate at all never matches an AAGUID-less entry
        Assert.Null(await service.GetEntryAsync(Guid.Empty));
    }

    [Fact]
    public async Task DistributeCacheMetadataService_Cache_Rollover_Works()
    {
        var nextUpdateTime = DateTimeOffset.Parse("2021-12-01T00:00:00Z");
        var currentTime = DateTimeOffset.Parse("2021-11-30T00:00:00Z");

        var services = new ServiceCollection();

        var staticClient = new MockRepository(nextUpdateTime.ToString("yyyy-MM-dd"));

        var repositories = new List<IMetadataRepository>();

        var currentTimeClock = new MockClock(currentTime);

        repositories.Add(staticClient);

        services.AddDistributedMemoryCache(options =>
        {
            options.Clock = currentTimeClock;
        });
        services.AddMemoryCache(options =>
        {
            options.Clock = currentTimeClock;
        });
        services.AddLogging();

        var provider = services.BuildServiceProvider();

        var distributedCache = provider.GetService<IDistributedCache>();
        var memCache = provider.GetService<IMemoryCache>();

        var serviceInstance1 = new DistributedCacheMetadataService(
            repositories,
            distributedCache,
            memCache,
            provider.GetService<ILogger<DistributedCacheMetadataService>>(),
            currentTimeClock
        );

        var entryIdGuid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

        var entry = await serviceInstance1.GetEntryAsync(entryIdGuid);

        for (int x = 0; x < 10; x++)
        {
            await serviceInstance1.GetEntryAsync(entryIdGuid);
        }

        Assert.Equal(1, staticClient.GetBLOBAsyncCount);

        Assert.Equal("Security Key by Yubico with NFC", entry.MetadataStatement.Description);

        var blobEntry = await distributedCache.GetStringAsync("DistributedCacheMetadataService:V2:" + staticClient.GetType().Name + ":TOC");

        // The BLOB is what is cached in memory; entries are looked up in it, not cached one by one.
        var memoryCachedBlob = memCache.Get<MetadataBLOBPayload>("DistributedCacheMetadataService:V2:" + staticClient.GetType().Name + ":TOC");

        Assert.NotNull(blobEntry);

        Assert.Contains(memoryCachedBlob.Entries, e => e.AaGuid == entryIdGuid);

        currentTimeClock.UtcNow = DateTimeOffset.Parse("2021-11-30 23:59:59.999Z"); //Before next update

        await serviceInstance1.GetEntryAsync(entryIdGuid);

        Assert.Equal(1, staticClient.GetBLOBAsyncCount);

        currentTimeClock.UtcNow = DateTimeOffset.Parse("2021-12-01 23:59:59.999Z"); //Before buffer period (24 hours)

        await serviceInstance1.GetEntryAsync(entryIdGuid);
        await serviceInstance1.GetEntryAsync(entryIdGuid);

        Assert.Equal(1, staticClient.GetBLOBAsyncCount);

        currentTimeClock.UtcNow = DateTimeOffset.Parse("2021-12-02 00:00:00.001Z"); //After buffer period (24 hours)

        staticClient.NextUpdate = "2021-12-30";

        await serviceInstance1.GetEntryAsync(entryIdGuid);

        Assert.Equal(2, staticClient.GetBLOBAsyncCount);

        currentTimeClock.UtcNow = DateTimeOffset.Parse("2021-12-29 01:00:00.001Z");

        await serviceInstance1.GetEntryAsync(entryIdGuid);

        Assert.Equal(2, staticClient.GetBLOBAsyncCount);
    }

    [Fact]
    public async Task Fido2MetadataServiceRepository_Logs_Each_Fetch_Retry_And_Download()
    {
        var handler = new StubHttpMessageHandler(
        [
            ThrottledResponse(TimeSpan.FromMilliseconds(10)),
            ThrottledResponse(TimeSpan.FromMilliseconds(10)),
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("not-a-valid-jwt") }
        ]);
        var logger = new ListLogger<Fido2MetadataServiceRepository>();

        var repository = new Fido2MetadataServiceRepository(new StubHttpClientFactory(handler), logger: logger);
        await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());

        // One fetch attempt per request, two throttled answers, one download
        Assert.Equal(3, logger.WithEventId(1000).Count());

        var throttled = logger.WithEventId(1003).ToList();
        Assert.Equal(2, throttled.Count);
        Assert.All(throttled, e => Assert.Equal(LogLevel.Warning, e.Level));
        Assert.Contains("429", throttled[0].Message);
        Assert.Contains("attempt 1 of 5", throttled[0].Message);
        Assert.Contains("attempt 2 of 5", throttled[1].Message);

        var downloaded = Assert.Single(logger.WithEventId(1002));
        Assert.Equal(LogLevel.Information, downloaded.Level);
        Assert.Contains("https://mds.example.test", downloaded.Message);
        Assert.Contains("15 bytes", downloaded.Message);

        // Nothing was accepted: the content never got as far as signature verification
        Assert.Empty(logger.WithEventId(1004));
        Assert.Empty(logger.WithEventId(1007));
    }

    [Fact]
    public async Task Fido2MetadataServiceRepository_Logs_When_The_Blob_Is_Not_Modified()
    {
        var logger = new ListLogger<Fido2MetadataServiceRepository>();
        var repository = new Fido2MetadataServiceRepository(new StubHttpClientFactory(new ETagAwareHttpMessageHandler()), logger: logger);

        await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());
        await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());

        // The first fetch is unconditional and downloads; the second sends the ETag and gets a 304
        Assert.Contains("conditional: False", logger.WithEventId(1000).First().Message);
        Assert.Contains("conditional: True", logger.WithEventId(1000).Last().Message);
        Assert.Single(logger.WithEventId(1002));
        Assert.Single(logger.WithEventId(1001));
    }

    [Fact]
    public async Task Fido2MetadataServiceRepository_Works_Without_A_Logger()
    {
        var handler = new StubHttpMessageHandler([new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("not-a-valid-jwt") }]);

        // The logger parameter is optional, so existing callers and DI containers without logging are unaffected
        var repository = new Fido2MetadataServiceRepository(new StubHttpClientFactory(handler));

        await Assert.ThrowsAsync<ArgumentException>(() => repository.GetBLOBAsync());
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task FileSystemMetadataRepository_Logs_What_It_Loaded_And_What_It_Skipped()
    {
        string directory = Path.Combine(Path.GetTempPath(), "fido2-metadata-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        try
        {
            // One statement as the conformance tool ships them, and one with its AAGUID removed
            string source = Path.Combine("metadata", "256K1 U2F Authenticator basic_full.json");
            File.Copy(source, Path.Combine(directory, "with-aaguid.json"));

            var statement = JsonNode.Parse(File.ReadAllText(source))!.AsObject();
            statement.Remove("aaguid");
            File.WriteAllText(Path.Combine(directory, "without-aaguid.json"), statement.ToJsonString());

            var logger = new ListLogger<FileSystemMetadataRepository>();
            var repository = new FileSystemMetadataRepository(directory, logger);

            var blob = await repository.GetBLOBAsync();

            Assert.Single(blob.Entries);

            var loaded = Assert.Single(logger.WithEventId(1011));
            Assert.Contains("with-aaguid.json", loaded.Message);

            var skipped = Assert.Single(logger.WithEventId(1012));
            Assert.Equal(LogLevel.Warning, skipped.Level);
            Assert.Contains("without-aaguid.json", skipped.Message);

            var summary = Assert.Single(logger.WithEventId(1013));
            Assert.Equal(LogLevel.Information, summary.Level);
            Assert.StartsWith("Loaded 1 metadata statement(s)", summary.Message);
            Assert.Empty(logger.WithEventId(1010));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task FileSystemMetadataRepository_Warns_When_The_Directory_Is_Missing()
    {
        string directory = Path.Combine(Path.GetTempPath(), "fido2-metadata-missing-" + Guid.NewGuid().ToString("N"));
        var logger = new ListLogger<FileSystemMetadataRepository>();

        var blob = await new FileSystemMetadataRepository(directory, logger).GetBLOBAsync();

        Assert.Empty(blob.Entries);
        var missing = Assert.Single(logger.Entries);
        Assert.Equal(1010, missing.EventId.Id);
        Assert.Equal(LogLevel.Warning, missing.Level);
        Assert.Contains(directory, missing.Message);
    }

    private sealed class ConformanceToolStubHandler(string[] endpoints) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // POST getEndpoints answers with the provisioned BLOB URLs; every GET of a BLOB answers with junk
            HttpResponseMessage response = request.Method == HttpMethod.Post
                ? new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(new { status = "ok", result = endpoints }), Encoding.UTF8, "application/json")
                }
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("not-a-blob") };

            return Task.FromResult(response);
        }
    }

    [Fact]
    public async Task ConformanceMetadataRepository_Logs_Every_Rejected_Blob_Instead_Of_Dropping_It_Silently()
    {
        string[] endpoints = ["https://mds3.fido.tools/execute/aaaa", "https://mds3.fido.tools/execute/bbbb"];
        var logger = new ListLogger<ConformanceMetadataRepository>();
        var repository = new ConformanceMetadataRepository(new HttpClient(new ConformanceToolStubHandler(endpoints)), "https://rp.example", logger);

        var blob = await repository.GetBLOBAsync();

        Assert.Empty(blob.Entries);

        var provisioned = Assert.Single(logger.WithEventId(1020));
        Assert.Contains("2 metadata endpoint(s) for https://rp.example", provisioned.Message);

        var rejected = logger.WithEventId(1021).ToList();
        Assert.Equal(2, rejected.Count);
        Assert.All(rejected, e => Assert.Equal(LogLevel.Warning, e.Level));
        Assert.All(rejected, e => Assert.NotNull(e.Exception));
        Assert.Contains(endpoints[0], rejected[0].Message);
        Assert.Contains(endpoints[1], rejected[1].Message);

        var combined = Assert.Single(logger.WithEventId(1022));
        Assert.Contains("0 entries from 0 conformance BLOB(s)", combined.Message);
    }

    /// <summary>
    /// A <see cref="MockRepository"/> that can be told to fail. The cache is keyed by repository type, so the phases of
    /// a test that fill the cache and then fail must use the same type.
    /// </summary>
    private sealed class FailableCacheRepository(string nextUpdate) : IMetadataRepository
    {
        private readonly MockRepository _inner = new(nextUpdate);

        public bool Fail { get; set; }

        public Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
        {
            return Fail ? throw new HttpRequestException("metadata service down") : _inner.GetBLOBAsync(cancellationToken);
        }

        public Task<MetadataStatement> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default) => Task.FromResult(entry.MetadataStatement);
    }

    private static DistributedCacheMetadataService CreateCachedService(IMetadataRepository repository, DateTimeOffset now, ListLogger<DistributedCacheMetadataService> logger, out IDistributedCache distributedCache)
    {
        var clock = new MockClock(now);
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache(options => options.Clock = clock);
        services.AddMemoryCache(options => options.Clock = clock);
        var provider = services.BuildServiceProvider();

        distributedCache = provider.GetRequiredService<IDistributedCache>();

        return new DistributedCacheMetadataService([repository], distributedCache, provider.GetRequiredService<IMemoryCache>(), logger, clock);
    }

    [Fact]
    public async Task DistributedCacheMetadataService_Logs_A_Failed_Fetch_And_That_Nothing_Is_Cached()
    {
        var logger = new ListLogger<DistributedCacheMetadataService>();
        var service = CreateCachedService(new FailableCacheRepository("2021-12-01") { Fail = true }, DateTimeOffset.Parse("2021-11-30T00:00:00Z"), logger, out _);

        Assert.Null(await service.GetEntryAsync(Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73")));

        var failed = Assert.Single(logger.WithEventId(1100));
        Assert.Equal(LogLevel.Error, failed.Level);
        Assert.IsType<HttpRequestException>(failed.Exception);
        Assert.Contains(nameof(FailableCacheRepository), failed.Message);

        var unavailable = Assert.Single(logger.WithEventId(1106));
        Assert.Equal(LogLevel.Warning, unavailable.Level);
    }

    [Fact]
    public async Task DistributedCacheMetadataService_Logs_Caching_Reuse_And_Falling_Back_To_A_Due_Copy()
    {
        var aaguid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");
        var now = DateTimeOffset.Parse("2021-11-30T00:00:00Z");

        var repository = new FailableCacheRepository("2021-12-01");

        // A working repository fills the cache...
        var fillLogger = new ListLogger<DistributedCacheMetadataService>();
        var working = CreateCachedService(repository, now, fillLogger, out var distributedCache);
        Assert.NotNull(await working.GetEntryAsync(aaguid));

        var cached = Assert.Single(fillLogger.WithEventId(1105));
        Assert.Equal(LogLevel.Information, cached.Level);
        Assert.Contains(nameof(FailableCacheRepository), cached.Message);

        // ...which a second service instance over the same distributed cache reads back while it is current...
        var reuseLogger = new ListLogger<DistributedCacheMetadataService>();
        var clock = new MockClock(now);
        var reusing = new DistributedCacheMetadataService([repository], distributedCache, new MemoryCache(new MemoryCacheOptions { Clock = clock }), reuseLogger, clock);
        Assert.NotNull(await reusing.GetEntryAsync(aaguid));
        Assert.Single(reuseLogger.WithEventId(1102));
        Assert.Empty(reuseLogger.WithEventId(1103));

        // ...and, once it is due, a failing fetch is reported and the due copy is kept rather than losing metadata
        repository.Fail = true;
        var dueLogger = new ListLogger<DistributedCacheMetadataService>();
        var later = new MockClock(DateTimeOffset.Parse("2021-12-03T00:00:00Z"));
        var stale = new DistributedCacheMetadataService([repository], distributedCache, new MemoryCache(new MemoryCacheOptions { Clock = later }), dueLogger, later);
        Assert.NotNull(await stale.GetEntryAsync(aaguid));
        Assert.Single(dueLogger.WithEventId(1103));
        Assert.Single(dueLogger.WithEventId(1100));
        var fallback = Assert.Single(dueLogger.WithEventId(1104));
        Assert.Equal(LogLevel.Warning, fallback.Level);
    }

    [Fact]
    public async Task DistributedCacheMetadataService_Logs_A_Refresh_Once_The_Cached_Blob_Is_Due()
    {
        var aaguid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");
        var repository = new FailableCacheRepository("2021-12-01");

        var fillLogger = new ListLogger<DistributedCacheMetadataService>();
        var filling = CreateCachedService(repository, DateTimeOffset.Parse("2021-11-30T00:00:00Z"), fillLogger, out var distributedCache);
        Assert.NotNull(await filling.GetEntryAsync(aaguid));

        // Past the next update plus the buffer, with the repository answering: due, fetched, cached again
        var later = new MockClock(DateTimeOffset.Parse("2021-12-03T00:00:00Z"));
        var refreshLogger = new ListLogger<DistributedCacheMetadataService>();
        var refreshing = new DistributedCacheMetadataService([repository], distributedCache, new MemoryCache(new MemoryCacheOptions { Clock = later }), refreshLogger, later);

        Assert.NotNull(await refreshing.GetEntryAsync(aaguid));
        Assert.Single(refreshLogger.WithEventId(1103));
        Assert.Single(refreshLogger.WithEventId(1105));
        Assert.Empty(refreshLogger.WithEventId(1104));
    }

    [Fact]
    public async Task DistributedCacheMetadataService_Logs_An_Unreadable_Cache_Entry_And_Fetches_Again()
    {
        var aaguid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");
        var logger = new ListLogger<DistributedCacheMetadataService>();
        var service = CreateCachedService(new FailableCacheRepository("2021-12-01"), DateTimeOffset.Parse("2021-11-30T00:00:00Z"), logger, out var distributedCache);

        // Something that is not a BLOB under the key the service uses for this repository
        await distributedCache.SetStringAsync($"{nameof(DistributedCacheMetadataService)}:V2:{nameof(FailableCacheRepository)}:TOC", "{not json");

        Assert.NotNull(await service.GetEntryAsync(aaguid));

        var unreadable = Assert.Single(logger.WithEventId(1101));
        Assert.Equal(LogLevel.Warning, unreadable.Level);
        Assert.IsAssignableFrom<System.Text.Json.JsonException>(unreadable.Exception);
        Assert.Single(logger.WithEventId(1105));
    }

    [Fact]
    public async Task DistributedCacheMetadataService_Caches_A_Blob_Without_A_Next_Update_For_The_Default_Interval()
    {
        var aaguid = Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");
        var now = DateTimeOffset.Parse("2021-11-30T00:00:00Z");
        var logger = new ListLogger<DistributedCacheMetadataService>();
        var service = CreateCachedService(new FailableCacheRepository(nextUpdate: ""), now, logger, out _);

        Assert.NotNull(await service.GetEntryAsync(aaguid));
        Assert.Null(await service.GetEntryAsync(Guid.NewGuid()));

        // No next update to go by: the default 30-day interval from now. Microsoft.Extensions.Logging's
        // message formatter always renders arguments with CultureInfo.InvariantCulture (LogValuesFormatter),
        // regardless of the host's current culture -- match that here rather than using the thread's
        // CurrentCulture, which can format the AM/PM designator differently (e.g. a narrow no-break space
        // on some ICU versions vs. a plain space under InvariantCulture) and make this assertion flaky
        // across machines/runners even though the logged message itself never changes.
        var cached = Assert.Single(logger.WithEventId(1105));
        Assert.Contains(now.AddDays(30).ToString(CultureInfo.InvariantCulture), cached.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FileSystemMetadataRepository_Loads_On_First_Statement_Lookup()
    {
        string directory = Path.Combine(Path.GetTempPath(), "fido2-metadata-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        try
        {
            string source = Path.Combine("metadata", "256K1 U2F Authenticator basic_full.json");
            File.Copy(source, Path.Combine(directory, "statement.json"));
            var aaguid = JsonNode.Parse(File.ReadAllText(source))!["aaguid"]!.GetValue<string>();

            var repository = new FileSystemMetadataRepository(directory);

            // Looking a statement up before any BLOB was requested loads the directory; an unknown AAGUID finds nothing
            var statement = await repository.GetMetadataStatementAsync(null!, new MetadataBLOBPayloadEntry { AaGuid = Guid.Parse(aaguid) });
            Assert.NotNull(statement);
            Assert.Null(await repository.GetMetadataStatementAsync(null!, new MetadataBLOBPayloadEntry { AaGuid = Guid.NewGuid() }));
            Assert.Null(await repository.GetMetadataStatementAsync(null!, new MetadataBLOBPayloadEntry { AaGuid = null }));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task ConformanceMetadataService_Logs_What_Each_Repository_Contributed()
    {
        var logger = new ListLogger<ConformanceMetadataService>();
        var service = new ConformanceMetadataService([new MockRepository("2099-01-01")], logger);

        await service.InitializeAsync();

        var loaded = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Information, loaded.Level);
        Assert.Contains("Loaded 1 of 1 metadata entries from MockRepository", loaded.Message);
    }
}
