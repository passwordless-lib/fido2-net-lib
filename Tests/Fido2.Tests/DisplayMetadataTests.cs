using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib;

using Microsoft.Extensions.Logging;

namespace Test;

/// <summary>
/// Covers <see cref="ConvenienceMetadataService"/>, <see cref="FileSystemDisplayMetadataRepository"/>, and
/// <see cref="CompositeAuthenticatorDisplayMetadataService"/> -- the display-only AAGUID name/icon lookups that are
/// separate from the signed FIDO Metadata Service used for trust decisions.
/// </summary>
public class DisplayMetadataTests
{
    private static readonly Uri s_source = new("https://c-mds.example.test/");

    private sealed class ManualTimeProvider : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;
    }

    /// <summary>Answers each request with the next response from <c>respond</c>, recording what was asked.</summary>
    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];

        public int CallCount => Requests.Count;

        public StubHttpMessageHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond)
            : this((request, _) => respond(request))
        {
        }

        public StubHttpMessageHandler(string content, string etag = null)
            : this(_ => Task.FromResult(Ok(content, etag)))
        {
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            lock (Requests)
                Requests.Add(request.RequestUri);

            return respond(request, cancellationToken);
        }
    }

    private static HttpResponseMessage Ok(string content, string etag = null)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(content) };
        if (etag is not null)
            response.Headers.TryAddWithoutValidation("ETag", etag);
        return response;
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private static ConvenienceMetadataService CreateService(
        HttpMessageHandler handler,
        ManualTimeProvider time = null,
        ListLogger<ConvenienceMetadataService> logger = null,
        DisplayMetadataOptions options = null)
    {
        options ??= new DisplayMetadataOptions { ConvenienceMetadataServiceUrl = s_source };
        return new ConvenienceMetadataService(new StubHttpClientFactory(handler), options, logger, time ?? new ManualTimeProvider());
    }

    private static string Document(Guid aaguid, string details, int? no = 85)
    {
        var serial = no is int n ? $"\"no\": {n}," : "";
        return $$"""{ {{serial}} "{{aaguid}}": {{details}} }""";
    }

    private static string Base64Url(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [Fact]
    public async Task ResolvesAKnownAaguidFromTheSpecsDocumentShapeAsync()
    {
        // FIDO Convenience Metadata Service v1.0 §3.1.3: a numeric "no" alongside one member per AAGUID.
        var aaguid = Guid.NewGuid();
        var json = Document(aaguid, """
            {
              "friendlyNames": { "en-US": "Google Password Manager", "de-DE": "Google Passwortmanager" },
              "icon": "data:image/svg+xml;base64,PHN2Zy8+",
              "iconDark": "data:image/svg+xml;base64,PHN2ZyBkYXJrLz4="
            }
            """);

        var info = await CreateService(new StubHttpMessageHandler(json)).GetDisplayInfoAsync(aaguid);

        Assert.NotNull(info);
        Assert.Equal("Google Password Manager", info.Name);
        Assert.Equal("data:image/svg+xml;base64,PHN2Zy8+", info.IconLight);
        Assert.Equal("data:image/svg+xml;base64,PHN2ZyBkYXJrLz4=", info.IconDark);
        Assert.Equal("Google Passwortmanager", info.FriendlyNames["de-DE"]);
    }

    [Fact]
    public async Task ReadsThePayloadOfAJwsWrappedDocumentAsync()
    {
        var aaguid = Guid.NewGuid();
        var payload = Document(aaguid, """{ "friendlyNames": { "en-US": "Wrapped" } }""");
        var jws = $"{Base64Url("""{"alg":"ES256"}""")}.{Base64Url(payload)}.c2lnbmF0dXJl\n";

        var info = await CreateService(new StubHttpMessageHandler(jws)).GetDisplayInfoAsync(aaguid);

        Assert.Equal("Wrapped", info?.Name);
    }

    [Fact]
    public async Task FallsBackToTheProviderLogosWhenThereIsNoAuthenticatorIconAsync()
    {
        var aaguid = Guid.NewGuid();
        var json = Document(aaguid, """
            {
              "friendlyNames": { "en-US": "Provider" },
              "providerLogoLight": "data:image/svg+xml;base64,bGlnaHQ=",
              "providerLogoDark": "data:image/svg+xml;base64,ZGFyaw=="
            }
            """);

        var info = await CreateService(new StubHttpMessageHandler(json)).GetDisplayInfoAsync(aaguid);

        Assert.Equal("data:image/svg+xml;base64,bGlnaHQ=", info?.IconLight);
        Assert.Equal("data:image/svg+xml;base64,ZGFyaw==", info?.IconDark);
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("https://tracker.example/icon.png")]
    [InlineData("data:text/html;base64,PHNjcmlwdD4=")]
    public async Task DropsIconsThatAreNotImageDataUrlsAsync(string icon)
    {
        var aaguid = Guid.NewGuid();
        var json = Document(aaguid, $$"""{ "friendlyNames": { "en-US": "Evil" }, "icon": "{{icon}}", "iconDark": "{{icon}}" }""");

        var info = await CreateService(new StubHttpMessageHandler(json)).GetDisplayInfoAsync(aaguid);

        Assert.Equal("Evil", info?.Name);
        Assert.Null(info?.IconLight);
        Assert.Null(info?.IconDark);
    }

    [Fact]
    public async Task DropsAnOversizedIconAsync()
    {
        var aaguid = Guid.NewGuid();
        var icon = "data:image/png;base64," + new string('A', 1024 * 1024);
        var json = Document(aaguid, $$"""{ "friendlyNames": { "en-US": "Big" }, "icon": "{{icon}}" }""");

        var info = await CreateService(new StubHttpMessageHandler(json)).GetDisplayInfoAsync(aaguid);

        Assert.Null(info?.IconLight);
    }

    [Theory]
    [InlineData("""{ "en-US": "US", "en-GB": "GB" }""", "US")]
    [InlineData("""{ "de-DE": "Deutsch", "en-GB": "British" }""", "British")]
    [InlineData("""{ "de-DE": "Deutsch", "en": "English" }""", "English")]
    [InlineData("""{ "en-US": "  ", "de-DE": "Deutsch" }""", "Deutsch")]
    [InlineData("""{ "de-DE": "Deutsch", "fr-FR": "Français" }""", "Deutsch")]
    [InlineData("""{ "en-US": "Line\nbreak\u0007" }""", "Linebreak")]
    [InlineData("""{ "en-US": " " }""", null)]
    [InlineData("""{ "en-US": "\u0007\u0008" }""", null)]
    [InlineData("""{ }""", null)]
    public async Task PicksAnEnglishNameAndStripsControlCharactersAsync(string friendlyNames, string expected)
    {
        var aaguid = Guid.NewGuid();
        var json = Document(aaguid, $$"""{ "friendlyNames": {{friendlyNames}} }""");

        var info = await CreateService(new StubHttpMessageHandler(json)).GetDisplayInfoAsync(aaguid);

        Assert.Equal(expected, info?.Name);
    }

    [Fact]
    public async Task TruncatesAnOverlongNameAsync()
    {
        var aaguid = Guid.NewGuid();
        var json = Document(aaguid, $$"""{ "friendlyNames": { "en-US": "{{new string('x', 500)}}" } }""");

        var info = await CreateService(new StubHttpMessageHandler(json)).GetDisplayInfoAsync(aaguid);

        Assert.Equal(128, info?.Name.Length);
    }

    [Fact]
    public async Task SkipsMembersThatAreNotAaguidEntriesAsync()
    {
        var aaguid = Guid.NewGuid();
        var json = $$"""
            {
              "no": "not a number",
              "legalHeader": "Use of this document is subject to ...",
              "not-a-guid": { "friendlyNames": { "en-US": "Ignored" } },
              "{{Guid.NewGuid()}}": "not an object",
              "{{aaguid}}": { "friendlyNames": { "en-US": "Kept" } }
            }
            """;

        var handler = new StubHttpMessageHandler(json);
        var service = CreateService(handler);

        Assert.Equal("Kept", (await service.GetDisplayInfoAsync(aaguid))?.Name);
    }

    [Fact]
    public async Task ReturnsNullForAnUnknownAaguidAsync()
    {
        var json = Document(Guid.NewGuid(), """{ "friendlyNames": { "en-US": "Something Else" } }""");

        var info = await CreateService(new StubHttpMessageHandler(json)).GetDisplayInfoAsync(Guid.NewGuid());

        Assert.Null(info);
    }

    [Fact]
    public async Task KeepsTheDocumentUntilTheRefreshIntervalThenChecksConditionallyAsync()
    {
        var aaguid = Guid.NewGuid();
        var time = new ManualTimeProvider();
        var first = true;
        var handler = new StubHttpMessageHandler(_ =>
        {
            var response = first ? Ok(Document(aaguid, """{ "friendlyNames": { "en-US": "Cached" } }""", no: 85)) : new HttpResponseMessage(HttpStatusCode.NotModified);
            first = false;
            return Task.FromResult(response);
        });
        var logger = new ListLogger<ConvenienceMetadataService>();
        var service = CreateService(handler, time, logger);

        await service.GetDisplayInfoAsync(aaguid);
        await service.GetDisplayInfoAsync(Guid.NewGuid());
        time.Now += TimeSpan.FromHours(23);
        await service.GetDisplayInfoAsync(aaguid);

        Assert.Equal(1, handler.CallCount);
        Assert.Equal(s_source, handler.Requests[0]);

        time.Now += TimeSpan.FromHours(2);
        var info = await service.GetDisplayInfoAsync(aaguid);

        Assert.Equal(2, handler.CallCount);
        Assert.Equal("?localCopySerial=85", handler.Requests[1].Query);
        Assert.Equal("Cached", info?.Name);
        Assert.Single(logger.WithEventId(1300));
        Assert.Single(logger.WithEventId(1301));
    }

    [Fact]
    public async Task TakesTheSerialFromTheETagWhenTheDocumentHasNoneAsync()
    {
        var aaguid = Guid.NewGuid();
        var time = new ManualTimeProvider();
        var calls = 0;
        var handler = new StubHttpMessageHandler(_ => Task.FromResult(Interlocked.Increment(ref calls) == 1
            ? Ok(Document(aaguid, """{ "friendlyNames": { "en-US": "Tagged" } }""", no: null), etag: "286")
            : new HttpResponseMessage(HttpStatusCode.NotModified)));
        var options = new DisplayMetadataOptions { ConvenienceMetadataServiceUrl = new Uri("https://c-mds.example.test/blob?format=json") };
        var service = CreateService(handler, time, options: options);

        await service.GetDisplayInfoAsync(aaguid);
        time.Now += TimeSpan.FromDays(2);
        await service.GetDisplayInfoAsync(aaguid);

        Assert.Equal("?format=json&localCopySerial=286", handler.Requests[1].Query);
        Assert.Equal("Tagged", (await service.GetDisplayInfoAsync(aaguid))?.Name);
    }

    [Fact]
    public async Task AFailedDownloadReturnsNothingAndIsNotRetriedUntilTheBackoffEndsAsync()
    {
        var time = new ManualTimeProvider();
        var handler = new StubHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.TooManyRequests)));
        var logger = new ListLogger<ConvenienceMetadataService>();
        var service = CreateService(handler, time, logger);

        Assert.Null(await service.GetDisplayInfoAsync(Guid.NewGuid()));
        Assert.Null(await service.GetDisplayInfoAsync(Guid.NewGuid()));
        time.Now += TimeSpan.FromMinutes(59);
        Assert.Null(await service.GetDisplayInfoAsync(Guid.NewGuid()));

        Assert.Equal(1, handler.CallCount);
        var failure = Assert.Single(logger.WithEventId(1302));
        Assert.Equal(LogLevel.Warning, failure.Level);
        Assert.IsType<HttpRequestException>(failure.Exception);

        time.Now += TimeSpan.FromMinutes(2);
        await service.GetDisplayInfoAsync(Guid.NewGuid());

        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task AFailedRefreshKeepsServingTheLastGoodCopyAsync()
    {
        var aaguid = Guid.NewGuid();
        var time = new ManualTimeProvider();
        var calls = 0;
        var handler = new StubHttpMessageHandler(_ => calls++ == 0
            ? Task.FromResult(Ok(Document(aaguid, """{ "friendlyNames": { "en-US": "Good" } }""")))
            : throw new HttpRequestException("down"));
        var service = CreateService(handler, time);

        await service.GetDisplayInfoAsync(aaguid);
        time.Now += TimeSpan.FromDays(2);

        Assert.Equal("Good", (await service.GetDisplayInfoAsync(aaguid))?.Name);
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task ADocumentLargerThanTheLimitIsRejectedAsync()
    {
        var aaguid = Guid.NewGuid();
        var json = Document(aaguid, $$"""{ "friendlyNames": { "en-US": "{{new string('x', 2000)}}" } }""");
        var logger = new ListLogger<ConvenienceMetadataService>();
        var options = new DisplayMetadataOptions { ConvenienceMetadataServiceUrl = s_source, MaxDocumentBytes = 1024 };

        var info = await CreateService(new StubHttpMessageHandler(json), logger: logger, options: options).GetDisplayInfoAsync(aaguid);

        Assert.Null(info);
        Assert.Single(logger.WithEventId(1302));
    }

    [Theory]
    [InlineData("this is not a document")]
    [InlineData("[ 1, 2, 3 ]")]
    [InlineData("a.b")]
    [InlineData("eyJhbGciOiJFUzI1NiJ9.WzEsMiwzXQ.c2ln")] // a JWS whose payload is [1,2,3]
    public async Task AnUnreadableDocumentIsAFailedDownloadAsync(string body)
    {
        var logger = new ListLogger<ConvenienceMetadataService>();

        var info = await CreateService(new StubHttpMessageHandler(body), logger: logger).GetDisplayInfoAsync(Guid.NewGuid());

        Assert.Null(info);
        Assert.Single(logger.WithEventId(1302));
    }

    [Fact]
    public async Task ConcurrentCallersOnAColdCacheShareOneDownloadAsync()
    {
        var aaguid = Guid.NewGuid();
        var release = new TaskCompletionSource();
        var handler = new StubHttpMessageHandler(async _ =>
        {
            await release.Task;
            return Ok(Document(aaguid, """{ "friendlyNames": { "en-US": "Shared" } }"""));
        });
        var service = CreateService(handler);

        var first = service.GetDisplayInfoAsync(aaguid);
        var second = service.GetDisplayInfoAsync(aaguid);
        release.SetResult();

        Assert.Equal("Shared", (await first)?.Name);
        Assert.Equal("Shared", (await second)?.Name);
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task CallersAreAnsweredFromTheOldCopyWhileARefreshIsRunningAsync()
    {
        var aaguid = Guid.NewGuid();
        var time = new ManualTimeProvider();
        var release = new TaskCompletionSource();
        var calls = 0;
        var handler = new StubHttpMessageHandler(async _ =>
        {
            if (Interlocked.Increment(ref calls) == 1)
                return Ok(Document(aaguid, """{ "friendlyNames": { "en-US": "Old" } }""", no: 1));

            await release.Task;
            return Ok(Document(aaguid, """{ "friendlyNames": { "en-US": "New" } }""", no: 2));
        });
        var service = CreateService(handler, time);

        await service.GetDisplayInfoAsync(aaguid);
        time.Now += TimeSpan.FromDays(2);

        var refreshing = service.GetDisplayInfoAsync(aaguid);
        var meanwhile = await service.GetDisplayInfoAsync(aaguid);
        release.SetResult();

        Assert.Equal("Old", meanwhile?.Name);
        Assert.Equal("New", (await refreshing)?.Name);
        Assert.Equal("New", (await service.GetDisplayInfoAsync(aaguid))?.Name);
    }

    [Fact]
    public async Task ALookupCancelledMidDownloadDoesNotStartTheBackoffAsync()
    {
        var aaguid = Guid.NewGuid();
        var started = new TaskCompletionSource();
        var calls = 0;
        var handler = new StubHttpMessageHandler(async (request, cancellationToken) =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                started.SetResult();
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            return Ok(Document(aaguid, """{ "friendlyNames": { "en-US": "After" } }"""));
        });
        var service = CreateService(handler);
        using var cancellation = new CancellationTokenSource();

        var lookup = service.GetDisplayInfoAsync(aaguid, cancellation.Token);
        await started.Task;
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => lookup);
        Assert.Equal("After", (await service.GetDisplayInfoAsync(aaguid))?.Name);
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task ALookupCancelledWhileWaitingForTheFirstDownloadThrowsAsync()
    {
        var release = new TaskCompletionSource();
        var handler = new StubHttpMessageHandler(async _ =>
        {
            await release.Task;
            return Ok(Document(Guid.NewGuid(), "{}"));
        });
        var service = CreateService(handler);
        using var cancellation = new CancellationTokenSource();

        var downloading = service.GetDisplayInfoAsync(Guid.NewGuid());
        var waiting = service.GetDisplayInfoAsync(Guid.NewGuid(), cancellation.Token);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        release.SetResult();
        Assert.Null(await downloading);
    }

    [Theory]
    [InlineData("\"286\"")]
    [InlineData("W/\"286\"")]
    public async Task ReadsAQuotedOrWeakETagSerialAsync(string etag)
    {
        var time = new ManualTimeProvider();
        var handler = new StubHttpMessageHandler(Document(Guid.NewGuid(), "{}", no: null), etag);
        var service = CreateService(handler, time);

        await service.GetDisplayInfoAsync(Guid.NewGuid());
        time.Now += TimeSpan.FromDays(2);
        await service.GetDisplayInfoAsync(Guid.NewGuid());

        Assert.Equal("?localCopySerial=286", handler.Requests[1].Query);
    }

    [Fact]
    public async Task WithoutAnySerialTheRefreshIsAPlainDownloadAsync()
    {
        var time = new ManualTimeProvider();
        var handler = new StubHttpMessageHandler(Document(Guid.NewGuid(), "{}", no: null), etag: "not-a-number");
        var service = CreateService(handler, time);

        await service.GetDisplayInfoAsync(Guid.NewGuid());
        time.Now += TimeSpan.FromDays(2);
        await service.GetDisplayInfoAsync(Guid.NewGuid());

        Assert.Equal(s_source, handler.Requests[1]);
    }

    [Fact]
    public async Task UsesTheDefaultsWhenNoOptionsAreGivenAsync()
    {
        var handler = new StubHttpMessageHandler(Document(Guid.NewGuid(), "{}"));
        var service = new ConvenienceMetadataService(new StubHttpClientFactory(handler));

        await service.GetDisplayInfoAsync(Guid.NewGuid());

        Assert.Equal(DisplayMetadataOptions.DefaultConvenienceMetadataServiceUrl, handler.Requests[0]);
    }

    [Fact]
    public async Task UsesTheDefaultUrlWhenNoneIsConfiguredAsync()
    {
        var handler = new StubHttpMessageHandler(Document(Guid.NewGuid(), "{}"));
        var service = new ConvenienceMetadataService(new StubHttpClientFactory(handler), new DisplayMetadataOptions { ConvenienceMetadataServiceUrl = null });

        await service.GetDisplayInfoAsync(Guid.NewGuid());

        Assert.Equal(DisplayMetadataOptions.DefaultConvenienceMetadataServiceUrl, handler.Requests[0]);
    }

    [Fact]
    public void RequiresAnHttpClientFactory()
    {
        Assert.Throws<ArgumentNullException>(() => new ConvenienceMetadataService(null));
    }

    [Fact]
    public async Task FileSystemDisplayMetadataRepositoryResolvesAKnownAaguidAsync()
    {
        var aaguid = Guid.NewGuid();
        var path = Path.GetTempFileName();

        try
        {
            await File.WriteAllTextAsync(path, $$"""
                {
                  "{{aaguid}}": {
                    "name": "Google Password Manager",
                    "icon_light": "data:image/svg+xml;base64,AAAA",
                    "icon_dark": "javascript:alert(1)"
                  },
                  "not-a-guid": { "name": "Ignored" }
                }
                """);

            var repository = new FileSystemDisplayMetadataRepository(path);
            var info = await repository.GetDisplayInfoAsync(aaguid);

            Assert.NotNull(info);
            Assert.Equal("Google Password Manager", info.Name);
            Assert.Equal("data:image/svg+xml;base64,AAAA", info.IconLight);
            Assert.Null(info.IconDark);

            // Read once: the file going away afterwards changes nothing.
            File.Delete(path);
            Assert.Equal("Google Password Manager", (await repository.GetDisplayInfoAsync(aaguid))?.Name);
            Assert.Null(await repository.GetDisplayInfoAsync(Guid.NewGuid()));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task FileSystemDisplayMetadataRepositoryReportsAMissingFileAsync()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var logger = new ListLogger<FileSystemDisplayMetadataRepository>();

        var info = await new FileSystemDisplayMetadataRepository(path, logger).GetDisplayInfoAsync(Guid.NewGuid());

        Assert.Null(info);
        Assert.Equal(LogLevel.Warning, Assert.Single(logger.WithEventId(1303)).Level);
    }

    [Fact]
    public async Task FileSystemDisplayMetadataRepositoryReportsAnUnreadableFileAsync()
    {
        var path = Path.GetTempFileName();
        var logger = new ListLogger<FileSystemDisplayMetadataRepository>();

        try
        {
            await File.WriteAllTextAsync(path, "{ not json");

            var info = await new FileSystemDisplayMetadataRepository(path, logger).GetDisplayInfoAsync(Guid.NewGuid());

            Assert.Null(info);
            Assert.Equal(LogLevel.Error, Assert.Single(logger.WithEventId(1304)).Level);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("{ not json")]
    [InlineData("null")]
    public async Task FileSystemDisplayMetadataRepositoryWorksWithoutALoggerAsync(string content)
    {
        var path = content is null ? Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json") : Path.GetTempFileName();

        try
        {
            if (content is not null)
                await File.WriteAllTextAsync(path, content);

            Assert.Null(await new FileSystemDisplayMetadataRepository(path).GetDisplayInfoAsync(Guid.NewGuid()));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void FileSystemDisplayMetadataRepositoryRequiresAPath()
    {
        Assert.Throws<ArgumentNullException>(() => new FileSystemDisplayMetadataRepository(null));
    }

    private sealed class FixedSource(AuthenticatorDisplayInfo info) : IAuthenticatorDisplayMetadataService
    {
        public Task<AuthenticatorDisplayInfo> GetDisplayInfoAsync(Guid aaguid, CancellationToken cancellationToken = default) => Task.FromResult(info);
    }

    private sealed class ThrowingSource(Exception exception) : IAuthenticatorDisplayMetadataService
    {
        public Task<AuthenticatorDisplayInfo> GetDisplayInfoAsync(Guid aaguid, CancellationToken cancellationToken = default) => Task.FromException<AuthenticatorDisplayInfo>(exception);
    }

    [Fact]
    public async Task CompositeServiceFillsGapsFromLowerPrioritySourcesAsync()
    {
        var names = new Dictionary<string, string> { ["en-US"] = "Remote" };
        var composite = new CompositeAuthenticatorDisplayMetadataService([
            new FixedSource(new AuthenticatorDisplayInfo("Local Override", null, "data:image/png;base64,DARK")),
            new FixedSource(null),
            new FixedSource(new AuthenticatorDisplayInfo("Remote", "data:image/png;base64,LIGHT", null) { FriendlyNames = names })
        ]);

        var info = await composite.GetDisplayInfoAsync(Guid.NewGuid());

        Assert.NotNull(info);
        Assert.Equal("Local Override", info.Name);
        Assert.Equal("data:image/png;base64,LIGHT", info.IconLight);
        Assert.Equal("data:image/png;base64,DARK", info.IconDark);
        Assert.Same(names, info.FriendlyNames);
        Assert.Equal(3, composite.Sources.Count);
    }

    [Fact]
    public async Task CompositeServiceReturnsNullWhenNoSourceKnowsTheAaguidAsync()
    {
        var composite = new CompositeAuthenticatorDisplayMetadataService([new FixedSource(null)]);

        Assert.Null(await composite.GetDisplayInfoAsync(Guid.NewGuid()));
        Assert.Null(await new CompositeAuthenticatorDisplayMetadataService([]).GetDisplayInfoAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task CompositeServiceSkipsAFailingSourceAndReportsItAsync()
    {
        var logger = new ListLogger<CompositeAuthenticatorDisplayMetadataService>();
        var composite = new CompositeAuthenticatorDisplayMetadataService(
            [new ThrowingSource(new IOException("disk")), new FixedSource(new AuthenticatorDisplayInfo("Still here", null, null))],
            logger);

        var info = await composite.GetDisplayInfoAsync(Guid.NewGuid());

        Assert.Equal("Still here", info?.Name);
        var entry = Assert.Single(logger.WithEventId(1305));
        Assert.IsType<IOException>(entry.Exception);
        Assert.Contains(nameof(ThrowingSource), entry.Message);
    }

    [Fact]
    public async Task CompositeServiceSkipsAFailingSourceWithoutALoggerAsync()
    {
        var composite = new CompositeAuthenticatorDisplayMetadataService([new ThrowingSource(new IOException("disk"))]);

        Assert.Null(await composite.GetDisplayInfoAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task CompositeServicePropagatesCancellationAsync()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var composite = new CompositeAuthenticatorDisplayMetadataService([new ThrowingSource(new OperationCanceledException(cancelled.Token))]);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => composite.GetDisplayInfoAsync(Guid.NewGuid(), cancelled.Token));
    }

    [Fact]
    public void CompositeServiceRequiresSources()
    {
        Assert.Throws<ArgumentNullException>(() => new CompositeAuthenticatorDisplayMetadataService(null));
    }
}
