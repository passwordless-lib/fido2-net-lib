using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Represents a generic version with major and minor fields.
/// </summary>
/// <remarks>
/// https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html#version-interface
/// </remarks>
public readonly struct UafVersion : IEquatable<UafVersion>
{
    [JsonConstructor]
    public UafVersion(ushort major, ushort minor)
    {
        Major = major;
        Minor = minor;
    }

    /// <summary>
    /// Major version
    /// </summary>
    [JsonPropertyName("major")]
    public ushort Major { get; }

    /// <summary>
    /// Minor version
    /// </summary>
    [JsonPropertyName("minor")]
    public ushort Minor { get; }

    public bool Equals(UafVersion other)
    {
        return Major == other.Major
            && Minor == other.Minor;
    }

    public override bool Equals(object obj)
    {
        return obj is UafVersion other && Equals(other);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Major, Minor);
    }

    public static bool operator ==(UafVersion left, UafVersion right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(UafVersion left, UafVersion right)
    {
        return !left.Equals(right);
    }
}
