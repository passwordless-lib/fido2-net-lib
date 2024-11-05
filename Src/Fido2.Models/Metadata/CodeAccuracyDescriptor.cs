using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// The CodeAccuracyDescriptor describes the relevant accuracy/complexity aspects of passcode user verification methods.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#codeaccuracydescriptor-dictionary"/>
/// </remarks>
public sealed class CodeAccuracyDescriptor
{
    /// <summary>
    /// Gets or sets the numeric system base (radix) of the code, e.g.  10 in the case of decimal digits.
    /// </summary>
    [JsonPropertyName("base")]
    public required ushort Base { get; set; }

    /// <summary>
    /// Gets or sets the minimum number of digits of the given base required for that code, e.g. 4 in the case of 4 digits.
    /// </summary>
    [JsonPropertyName("minLength")]
    public required ushort MinLength { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of false attempts before the authenticator will block this method (at least for some time).
    /// <para>Zero (0) means it will never block.</para>
    /// </summary>
    [JsonPropertyName("maxRetries")]
    public ushort MaxRetries { get; set; }

    /// <summary>
    /// Gets or sets the enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or similar).
    /// <para>Zero (0) means this user verification method will be blocked, either permanently or until an alternative user verification method method succeeded.</para>
    /// </summary>
    /// <remarks>
    /// All alternative user verification methods MUST be specified appropriately in the Metadata in <see cref="MetadataStatement.UserVerificationDetails"/>.
    /// </remarks>
    [JsonPropertyName("blockSlowdown")]
    public ushort BlockSlowdown { get; set; }
}
