using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using Fido2NetLib;
using Fido2NetLib.Exceptions;

namespace Fido2Demo;

/// <summary>
/// Records every request to the FIDO conformance endpoints as one JSON line, including the exception
/// (type, <see cref="Fido2ErrorCode"/>, message) that caused a rejection. The conformance tool only checks
/// that a negative test was rejected; this log shows <em>why</em> it was rejected, so a crash before the
/// intended check can be told apart from the check itself.
/// </summary>
public sealed class ConformanceTrafficLogMiddleware
{
    private static readonly HashSet<string> _routes = new(StringComparer.OrdinalIgnoreCase)
    {
        "/attestation/options",
        "/attestation/result",
        "/assertion/options",
        "/assertion/result"
    };

    private static readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = false };

    private static readonly object _syncRoot = new();

    private static int _sequence;

    private readonly RequestDelegate _next;
    private readonly string _logPath;

    public ConformanceTrafficLogMiddleware(RequestDelegate next, string logPath)
    {
        _next = next;
        _logPath = logPath;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_routes.Contains(context.Request.Path.Value ?? string.Empty))
        {
            await _next(context);
            return;
        }

        context.Request.EnableBuffering();
        var requestBody = await ReadRequestBodyAsync(context.Request);

        var originalBody = context.Response.Body;
        using var captured = new MemoryStream();
        context.Response.Body = captured;

        Exception exception = null;
        try
        {
            await _next(context);
        }
        catch (Exception e)
        {
            exception = e;
            await WriteFailureResponseAsync(context, e);
        }
        finally
        {
            context.Response.Body = originalBody;
        }

        captured.Position = 0;
        var responseBody = await new StreamReader(captured, Encoding.UTF8).ReadToEndAsync();

        Append(new TrafficRecord
        {
            Sequence = Interlocked.Increment(ref _sequence),
            Utc = DateTimeOffset.UtcNow,
            Path = context.Request.Path.Value,
            UserAgent = context.Request.Headers.UserAgent.ToString(),
            HasSessionCookie = context.Request.Cookies.ContainsKey(".AspNetCore.Session"),
            StatusCode = context.Response.StatusCode,
            Outcome = Classify(exception),
            ExceptionType = Innermost(exception)?.GetType().FullName,
            ErrorCode = FindFido2Exception(exception)?.Code.ToString(),
            ErrorMessage = exception?.Message,
            InnerMessage = exception?.InnerException?.Message,
            StackTrace = exception is null or Fido2VerificationException ? null : exception.ToString(),
            Request = AsJson(requestBody),
            Response = AsJson(responseBody)
        });

        captured.Position = 0;
        await captured.CopyToAsync(originalBody);
    }

    private static async Task<string> ReadRequestBodyAsync(HttpRequest request)
    {
        using var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        request.Body.Position = 0;
        return body;
    }

    private static async Task WriteFailureResponseAsync(HttpContext context, Exception e)
    {
        var fido2Exception = FindFido2Exception(e);

        context.Response.Clear();
        context.Response.StatusCode = fido2Exception is not null ? StatusCodes.Status400BadRequest : StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/json";

        var label = fido2Exception is not null
            ? $"{nameof(Fido2VerificationException)}/{fido2Exception.Code}: {fido2Exception.Message}"
            : $"{Innermost(e).GetType().Name}: {Innermost(e).Message}";

        await context.Response.WriteAsync(JsonSerializer.Serialize(new { status = "failed", errorMessage = label }, _jsonOptions));
    }

    /// <summary>
    /// "verified" = a coded <see cref="Fido2VerificationException"/> (the library made a deliberate decision);
    /// "uncoded" = a <see cref="Fido2VerificationException"/> without a <see cref="Fido2ErrorCode"/>;
    /// "crash" = anything else, i.e. the request was rejected by accident.
    /// </summary>
    private static string Classify(Exception e)
    {
        if (e is null)
            return "ok";

        var fido2Exception = FindFido2Exception(e);
        if (fido2Exception is null)
            return "crash";

        return fido2Exception.Code == Fido2ErrorCode.Unknown ? "uncoded" : "verified";
    }

    private static Fido2VerificationException FindFido2Exception(Exception e)
    {
        for (var current = e; current is not null; current = current.InnerException)
        {
            if (current is Fido2VerificationException fido2Exception)
                return fido2Exception;
        }
        return null;
    }

    private static Exception Innermost(Exception e)
    {
        if (e is null)
            return null;

        while (e.InnerException is not null)
            e = e.InnerException;
        return e;
    }

    private static JsonNode AsJson(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return null;

        try
        {
            return JsonNode.Parse(body);
        }
        catch (JsonException)
        {
            return JsonValue.Create(body);
        }
    }

    private void Append(TrafficRecord record)
    {
        var line = JsonSerializer.Serialize(record, _jsonOptions);
        lock (_syncRoot)
        {
            File.AppendAllText(_logPath, line + Environment.NewLine);
        }
        Console.WriteLine($"[conformance] #{record.Sequence} {record.Path} -> {record.StatusCode} {record.Outcome} {record.ErrorCode} {record.ErrorMessage}");
    }

    private sealed class TrafficRecord
    {
        public int Sequence { get; set; }
        public DateTimeOffset Utc { get; set; }
        public string Path { get; set; }
        public string UserAgent { get; set; }
        public bool HasSessionCookie { get; set; }
        public int StatusCode { get; set; }
        public string Outcome { get; set; }
        public string ExceptionType { get; set; }
        public string ErrorCode { get; set; }
        public string ErrorMessage { get; set; }
        public string InnerMessage { get; set; }
        public string StackTrace { get; set; }
        public JsonNode Request { get; set; }
        public JsonNode Response { get; set; }
    }
}
