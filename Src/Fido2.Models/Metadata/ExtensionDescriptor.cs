#nullable enable

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// This descriptor contains an extension supported by the authenticator.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#extensiondescriptor-dictionary"/>
/// </remarks>
public class ExtensionDescriptor
{
    /// <summary>
    /// Gets or sets the identifier that identifies the extension.
    /// </summary>
    [JsonPropertyName("id")]
    public required string Id { get; set; }

    /// <summary>
    /// Gets or sets the tag.
    /// <para>This field may be empty.</para>
    /// </summary>
    /// <remarks>
    /// The TAG of the extension if this was assigned. TAGs are assigned to extensions if they could appear in an assertion.
    /// </remarks>
    [JsonPropertyName("tag")]
    public ushort Tag { get; set; }

    /// <summary>
    /// Gets or sets arbitrary data further describing the extension and/or data needed to correctly process the extension.
    /// <para>This field may be empty.</para>
    /// </summary>
    /// <remarks>
    /// This field MAY be missing or it MAY be empty.
    /// </remarks>
    [JsonPropertyName("data")]
    public string? Data { get; set; }

    /// <summary>
    /// Gets or sets a value indication whether an unknown extensions must be ignored (<c>false</c>) or must lead to an error (<c>true</c>) when the extension is to be processed by the FIDO Server, FIDO Client, ASM, or FIDO Authenticator.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    ///     <item>A value of false indicates that unknown extensions MUST be ignored.</item>
    ///     <item>A value of true indicates that unknown extensions MUST result in an error.</item>
    /// </list>
    /// </remarks>
    [JsonPropertyName("fail_if_unknown"), Required]
    public bool Fail_If_Unknown { get; set; }
}
