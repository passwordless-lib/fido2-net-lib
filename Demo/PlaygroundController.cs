#nullable enable

using System.Buffers.Text;
using System.Formats.Cbor;
using System.Text;
using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Objects;

using Microsoft.AspNetCore.Mvc;

namespace Fido2Demo;

/// <summary>
/// Endpoints behind the playground page: a decoder for the binary structures a WebAuthn ceremony produces,
/// and credential management.
/// </summary>
/// <remarks>
/// The decoder is the part a client-side playground cannot do as well: the same parsing the library uses to
/// verify a ceremony is reused here to explain one.
/// </remarks>
[Route("api/playground")]
public class PlaygroundController : Controller
{
    private readonly IMetadataService _metadataService;

    /// <summary>Credential nicknames, keyed by base64url credential ID. Demo-local; not part of a credential record.</summary>
    private static readonly Dictionary<string, string> s_nicknames = new(StringComparer.Ordinal);

    public PlaygroundController(IMetadataService metadataService)
    {
        _metadataService = metadataService;
    }

    // ---------------------------------------------------------------------------------------------------
    // Decoder
    // ---------------------------------------------------------------------------------------------------

    public sealed class DecodeRequest
    {
        public string? Input { get; set; }

        /// <summary>auto | attestationObject | authenticatorData | clientDataJSON | coseKey</summary>
        public string? Kind { get; set; }
    }

    [HttpPost]
    [Route("decode")]
    public JsonResult Decode([FromBody] DecodeRequest request)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request?.Input))
                return Json(new { status = "error", errorMessage = "Nothing to decode." });

            var input = request.Input.Trim();
            var bytes = DecodeFlexible(input);
            var kind = string.IsNullOrWhiteSpace(request.Kind) || request.Kind == "auto"
                ? Sniff(bytes, input)
                : request.Kind;

            object? decoded = kind switch
            {
                "clientDataJSON" => DecodeClientData(bytes),
                "authenticatorData" => DescribeAuthenticatorData(bytes),
                "coseKey" => DecodeCbor(bytes),
                "attestationObject" => DecodeAttestationObject(bytes),
                _ => throw new InvalidOperationException($"Unrecognized input kind '{kind}'.")
            };

            return Json(new { status = "ok", kind, byteLength = bytes.Length, decoded });
        }
        catch (Exception e)
        {
            return Json(new { status = "error", errorMessage = e.Message });
        }
    }

    /// <summary>
    /// Accepts the encodings these values are pasted in: base64url (how WebAuthn JSON carries them), standard
    /// base64, hex, or a raw JSON object for clientDataJSON.
    /// </summary>
    private static byte[] DecodeFlexible(string input)
    {
        if (input.StartsWith('{'))
            return Encoding.UTF8.GetBytes(input);

        var compact = new string(input.Where(c => !char.IsWhiteSpace(c)).ToArray());

        if (compact.Length % 2 == 0 && compact.All(Uri.IsHexDigit) && compact.Any(char.IsDigit))
        {
            try
            { return Convert.FromHexString(compact); }
            catch (FormatException) { /* fall through to base64 */ }
        }

        try
        { return Base64Url.DecodeFromChars(compact); }
        catch (FormatException) { }

        try
        { return Convert.FromBase64String(compact); }
        catch (FormatException) { }

        throw new InvalidOperationException("Input is not base64url, base64, or hex.");
    }

    private static string Sniff(byte[] bytes, string original)
    {
        // clientDataJSON is usually pasted base64url-encoded, so test the decoded bytes rather than the
        // input text -- checking only the text sent an encoded blob down the authenticatorData path.
        if (original.StartsWith('{') || (bytes.Length > 0 && bytes[0] == (byte)'{'))
            return "clientDataJSON";

        // A CBOR map is the attestation object or a COSE key; anything else of a plausible length is authData.
        if (bytes.Length > 0 && (bytes[0] & 0xE0) == 0xA0)
        {
            try
            {
                var reader = new CborReader(bytes, CborConformanceMode.Lax);
                var map = ReadCborValue(reader);
                if (map is Dictionary<string, object?> d && d.ContainsKey("fmt") && d.ContainsKey("authData"))
                    return "attestationObject";
                return "coseKey";
            }
            catch (CborContentException) { }
            catch (InvalidOperationException) { }
        }

        // Authenticator data is rpIdHash(32) + flags(1) + signCount(4) at minimum.
        if (bytes.Length >= 37)
            return "authenticatorData";

        throw new InvalidOperationException("Could not tell what this is. Pick a type explicitly.");
    }

    private static object DecodeClientData(byte[] bytes)
    {
        var text = Encoding.UTF8.GetString(bytes);
        using var doc = JsonDocument.Parse(text);
        var root = doc.RootElement;

        string? Get(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() : null;

        return new
        {
            type = Get("type"),
            challenge = Get("challenge"),
            origin = Get("origin"),
            // WebAuthn L3 §5.8.1 added topOrigin, set when the ceremony ran in a cross-origin iframe.
            crossOrigin = root.TryGetProperty("crossOrigin", out var co) && co.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? co.GetBoolean() : (bool?)null,
            topOrigin = Get("topOrigin"),
            raw = JsonSerializer.Deserialize<JsonElement>(text)
        };
    }

    private object DecodeAttestationObject(byte[] bytes)
    {
        var reader = new CborReader(bytes, CborConformanceMode.Lax);
        var map = ReadCborValue(reader) as Dictionary<string, object?>
            ?? throw new InvalidOperationException("Attestation object is not a CBOR map.");

        object? authDataDescribed = null;
        if (map.TryGetValue("authData", out var ad) && ad is byte[] authDataBytes)
        {
            try
            { authDataDescribed = DescribeAuthenticatorData(authDataBytes); }
            catch (Exception e) { authDataDescribed = new { error = e.Message }; }
        }

        return new
        {
            fmt = map.TryGetValue("fmt", out var f) ? f : null,
            attStmt = map.TryGetValue("attStmt", out var a) ? Summarize(a) : null,
            authData = authDataDescribed
        };
    }

    /// <summary>
    /// Decodes authenticator data structurally, without building a <see cref="CredentialPublicKey"/>.
    /// </summary>
    /// <remarks>
    /// A decoder has to explain input it cannot verify. Going through
    /// <see cref="AuthenticatorData.Parse(byte[])"/> would construct the credential public key and therefore
    /// reject anything the library declines to verify -- an Ed448 key, say -- losing the flags, sign count and
    /// AAGUID that are perfectly readable. The key itself is still reported, as raw COSE, plus whatever the
    /// library says about it.
    /// </remarks>
    private object DescribeAuthenticatorData(byte[] bytes)
    {
        if (bytes.Length < 37)
            throw new InvalidOperationException($"Authenticator data is {bytes.Length} bytes; the minimum is 37.");

        var flags = (AuthenticatorFlags)bytes[32];
        var signCount = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(33, 4));

        object? attested = null;
        object? extensions = null;
        var offset = 37;

        if (flags.HasFlag(AuthenticatorFlags.AT))
        {
            if (bytes.Length < offset + 18)
                throw new InvalidOperationException("Authenticator data claims attested credential data but is too short.");

            var aaguid = new Guid(bytes.AsSpan(offset, 16), bigEndian: true);
            offset += 16;

            int credentialIdLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset, 2));
            offset += 2;

            if (bytes.Length < offset + credentialIdLength)
                throw new InvalidOperationException("Credential ID length runs past the end of the authenticator data.");

            var credentialId = bytes.AsSpan(offset, credentialIdLength).ToArray();
            offset += credentialIdLength;

            var keyStart = offset;
            var keyReader = new CborReader(bytes.AsMemory(offset), CborConformanceMode.Lax);
            var coseKey = Summarize(ReadCborValue(keyReader));
            offset = bytes.Length - keyReader.BytesRemaining;

            var keyBytes = bytes.AsSpan(keyStart, offset - keyStart).ToArray();

            attested = new
            {
                aaguid = aaguid.ToString(),
                aaguidDescription = DescribeAuthenticator(aaguid),
                credentialId = Base64Url.EncodeToString(credentialId),
                credentialIdLength,
                credentialPublicKey = coseKey,
                credentialPublicKeySupported = DescribeKeySupport(keyBytes)
            };
        }

        if (flags.HasFlag(AuthenticatorFlags.ED) && offset < bytes.Length)
        {
            var extReader = new CborReader(bytes.AsMemory(offset), CborConformanceMode.Lax);
            extensions = Summarize(ReadCborValue(extReader));
        }

        return new
        {
            rpIdHash = Convert.ToHexString(bytes.AsSpan(0, 32)).ToLowerInvariant(),
            signCount,
            flags = new
            {
                UP = flags.HasFlag(AuthenticatorFlags.UP),
                UV = flags.HasFlag(AuthenticatorFlags.UV),
                BE = flags.HasFlag(AuthenticatorFlags.BE),
                BS = flags.HasFlag(AuthenticatorFlags.BS),
                AT = flags.HasFlag(AuthenticatorFlags.AT),
                ED = flags.HasFlag(AuthenticatorFlags.ED)
            },
            flagsByte = "0x" + bytes[32].ToString("x2"),
            attestedCredentialData = attested,
            extensions
        };
    }

    /// <summary>
    /// Reports whether the library can actually use this credential public key. The decoder shows the key
    /// either way; this says whether a real ceremony carrying it would verify, and if not, why not.
    /// </summary>
    private static object DescribeKeySupport(byte[] coseKey)
    {
        try
        {
            _ = new CredentialPublicKey(coseKey);
            return new { supported = true, reason = (string?)null };
        }
        catch (Exception e)
        {
            return new { supported = false, reason = e.Message };
        }
    }

    private string? DescribeAuthenticator(Guid aaguid)
    {
        if (aaguid == Guid.Empty)
            return null;

        try
        {
            return _metadataService.GetEntryAsync(aaguid).GetAwaiter().GetResult()?.MetadataStatement?.Description;
        }
        catch
        {
            return null;
        }
    }

    private static object? DecodeCbor(byte[] bytes)
    {
        var reader = new CborReader(bytes, CborConformanceMode.Lax);
        return Summarize(ReadCborValue(reader));
    }

    /// <summary>
    /// Reads one CBOR value into plain CLR objects. Map keys are stringified so the result serializes to JSON;
    /// COSE uses negative integer labels, which JSON object keys cannot express otherwise.
    /// </summary>
    private static object? ReadCborValue(CborReader reader)
    {
        switch (reader.PeekState())
        {
            case CborReaderState.UnsignedInteger:
                return reader.ReadUInt64();
            case CborReaderState.NegativeInteger:
                return reader.ReadInt64();
            case CborReaderState.ByteString:
                return reader.ReadByteString();
            case CborReaderState.TextString:
                return reader.ReadTextString();
            case CborReaderState.Boolean:
                return reader.ReadBoolean();
            case CborReaderState.Null:
                reader.ReadNull();
                return null;
            case CborReaderState.SinglePrecisionFloat:
            case CborReaderState.DoublePrecisionFloat:
                return reader.ReadDouble();
            case CborReaderState.StartArray:
                {
                    var count = reader.ReadStartArray();
                    var list = new List<object?>();
                    while (reader.PeekState() != CborReaderState.EndArray)
                        list.Add(ReadCborValue(reader));
                    reader.ReadEndArray();
                    return list;
                }
            case CborReaderState.StartMap:
                {
                    reader.ReadStartMap();
                    var map = new Dictionary<string, object?>(StringComparer.Ordinal);
                    while (reader.PeekState() != CborReaderState.EndMap)
                    {
                        var key = ReadCborValue(reader);
                        map[key switch
                        {
                            string s => s,
                            ulong u => u.ToString(),
                            long l => l.ToString(),
                            _ => key?.ToString() ?? "null"
                        }] = ReadCborValue(reader);
                    }
                    reader.ReadEndMap();
                    return map;
                }
            case CborReaderState.Tag:
                reader.ReadTag();
                return ReadCborValue(reader);
            default:
                throw new InvalidOperationException($"Unsupported CBOR state {reader.PeekState()}.");
        }
    }

    /// <summary>Renders byte strings as base64url so the decoded tree survives JSON serialization.</summary>
    private static object? Summarize(object? value) => value switch
    {
        byte[] b => new { base64url = Base64Url.EncodeToString(b), hex = Convert.ToHexString(b).ToLowerInvariant(), length = b.Length },
        Dictionary<string, object?> map => map.ToDictionary(kv => kv.Key, kv => Summarize(kv.Value)),
        List<object?> list => list.Select(Summarize).ToList(),
        _ => value
    };

    // ---------------------------------------------------------------------------------------------------
    // Credential management
    // ---------------------------------------------------------------------------------------------------

    [HttpGet]
    [Route("credentials")]
    public async Task<JsonResult> Credentials([FromQuery] string username, CancellationToken cancellationToken)
    {
        try
        {
            var user = DemoController.DemoStorage.GetUser(username);
            if (user is null)
                return Json(new { status = "ok", credentials = Array.Empty<object>() });

            var result = new List<object>();

            foreach (var c in DemoController.DemoStorage.GetCredentialsByUser(user))
            {
                var id = Base64Url.EncodeToString(c.Id);
                string? description = null;

                try
                {
                    if (c.AaGuid != Guid.Empty)
                        description = (await _metadataService.GetEntryAsync(c.AaGuid, cancellationToken))?.MetadataStatement?.Description;
                }
                catch { /* metadata is best-effort */ }

                result.Add(new
                {
                    id,
                    nickname = s_nicknames.TryGetValue(id, out var n) ? n : null,
                    authenticator = description,
                    aaguid = c.AaGuid.ToString(),
                    regDate = c.RegDate,
                    signCount = c.SignCount,
                    attestationFormat = c.AttestationFormat,
                    transports = c.Transports?.Select(t => t.ToString()).ToArray() ?? [],
                    attachment = c.AuthenticatorAttachment?.ToString(),
                    isDiscoverable = c.IsDiscoverable,
                    uvInitialized = c.UvInitialized,
                    isBackupEligible = c.IsBackupEligible,
                    isBackedUp = c.IsBackedUp
                });
            }

            return Json(new { status = "ok", credentials = result });
        }
        catch (Exception e)
        {
            return Json(new { status = "error", errorMessage = e.Message });
        }
    }

    [HttpPost]
    [Route("credentials/nickname")]
    public JsonResult SetNickname([FromForm] string credentialId, [FromForm] string nickname)
    {
        if (string.IsNullOrWhiteSpace(nickname))
            s_nicknames.Remove(credentialId);
        else
            s_nicknames[credentialId] = nickname.Trim();

        return Json(new { status = "ok" });
    }

    [HttpPost]
    [Route("credentials/delete")]
    public JsonResult DeleteCredential([FromForm] string credentialId)
    {
        try
        {
            var removed = DemoController.DemoStorage.RemoveCredential(Base64Url.DecodeFromChars(credentialId));
            s_nicknames.Remove(credentialId);

            // A deleted credential is exactly the case WebAuthn L3 §5.1.10 exists for: the authenticator will
            // keep offering it until told otherwise. The page follows up with a signal call.
            return Json(new { status = "ok", removed });
        }
        catch (Exception e)
        {
            return Json(new { status = "error", errorMessage = e.Message });
        }
    }
}
