using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Test;

/// <summary>
/// Stands in for an internal service an attacker would like the server to reach: a loopback port that records every
/// request made to it, and certificates whose Authority Information Access (caIssuers) URL points there.
/// </summary>
/// <remarks>
/// Certificate chain building fetches a missing issuer from the AIA URL of the certificate being built unless told
/// not to. Every certificate in an attestation statement is the sender's, so the server must never make that request.
/// </remarks>
internal sealed class AiaTrap : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly string _path = $"/{Guid.NewGuid():N}.cer";
    private readonly ConcurrentQueue<string> _requestLines = new();

    public AiaTrap()
    {
        _listener.Start();

        // Unique per trap: the platform's chain engine caches what it fetched by URL, and a unique path tells this
        // trap's requests apart from anything else in the test run that happens to connect to a reused port.
        Url = $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}{_path}";

        _ = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    var client = await _listener.AcceptTcpClientAsync();
                    _ = Task.Run(async () =>
                    {
                        using (client)
                        {
                            try
                            {
                                using var reader = new StreamReader(client.GetStream());
                                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                                _requestLines.Enqueue(await reader.ReadLineAsync(timeout.Token) ?? "");
                            }
                            catch (Exception)
                            {
                                _requestLines.Enqueue("");
                            }
                        }
                    });
                }
            }
            catch (Exception)
            {
                // Stopped
            }
        });
    }

    public string Url { get; }

    /// <summary>
    /// How many requests for <see cref="Url"/> have been made, after giving one still in flight a moment to arrive.
    /// </summary>
    public int CountRequests()
    {
        Thread.Sleep(200);
        return _requestLines.Count(line => line.StartsWith($"GET {_path} ", StringComparison.Ordinal));
    }

    /// <summary>
    /// Issues <paramref name="request"/> from a CA that appears nowhere else, adding an AIA extension that names this
    /// trap as where to find that CA. Nothing built from the result can find the issuer without fetching it.
    /// </summary>
    public X509Certificate2 IssueFromAbsentIssuer(CertificateRequest request)
    {
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(1);

        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuerRequest = new CertificateRequest("CN=Absent Issuing CA", issuerKey, HashAlgorithmName.SHA256);
        issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var issuer = issuerRequest.CreateSelfSigned(notBefore.AddDays(-1), notAfter.AddDays(1));

        request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(ocspUris: null, caIssuersUris: [Url]));

        return request.Create(issuer, notBefore, notAfter, RandomNumberGenerator.GetBytes(12));
    }

    public void Dispose() => _listener.Stop();
}
