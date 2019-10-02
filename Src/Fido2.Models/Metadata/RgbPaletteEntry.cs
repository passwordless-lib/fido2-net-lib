using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// The rgbPaletteEntry is an RGB three-sample tuple palette entry.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#rgbpaletteentry-dictionary"/>
    /// </remarks>
    public class RgbPaletteEntry
    {
        /// <summary>
        /// Gets or sets the red channel sample value.
        /// </summary>
        [JsonProperty("r", Required = Required.Always)]
        public ushort R { get; set; }
        /// <summary>
        /// Gets or sets the green channel sample value.
        /// </summary>
        [JsonProperty("g", Required = Required.Always)]
        public ushort G { get; set; }
        /// <summary>
        /// Gets or sets the blue channel sample value.
        /// </summary>
        [JsonProperty("b", Required = Required.Always)]
        public ushort B { get; set; }
    }
}
