#nullable enable

using System;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// PublicKeyCredentialRpEntity
/// Provides the details of the relying party with which a credential is associated.
/// </summary>
public sealed class PublicKeyCredentialRpEntity
{
    [JsonConstructor]
    public PublicKeyCredentialRpEntity(string id, string name, string? icon = null)
    {
        ArgumentNullException.ThrowIfNull(id);
        ArgumentNullException.ThrowIfNull(name);

        Name = name;
        Id = id;
        Icon = icon;
    }

    /// <summary>
    /// A unique identifier for the Relying Party entity, which sets the RP ID.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; }

    /// <summary>
    /// A human-readable name for the entity. Its function depends on what the PublicKeyCredentialEntity represents:
    /// </summary>
    [JsonPropertyName("name")]
    public string Name { get; }

    [JsonPropertyName("icon")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Icon { get; }
}
