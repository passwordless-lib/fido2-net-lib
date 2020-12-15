using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib
{
    /// <summary>
    /// Represents a generic version with major and minor fields.
    /// </summary>
    /// <remarks>
    /// https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html#version-interface
    /// </remarks>
    public class UafVersion
    {
        [JsonPropertyName("major")]
        public ushort Major { get; set; }

        [JsonPropertyName("minor")]
        public ushort Minor { get; set; }
    }
}
