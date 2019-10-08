using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// Version represents a generic version with major and minor fields.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html#version-interface"/>
    /// </remarks>

    public class Version
    {
        /// <summary>
        /// Major version.
        /// </summary>
        [JsonProperty("major")]
        public ushort Major { get; set; }

        /// <summary>
        /// Minor version.
        /// </summary>
        [JsonProperty("minor")]
        public ushort Minor { get; set; }
    }
}
