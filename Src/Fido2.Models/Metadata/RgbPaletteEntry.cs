using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

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
        [JsonPropertyName("r"), Required]
        public ushort R { get; set; }

        /// <summary>
        /// Gets or sets the green channel sample value.
        /// </summary>
        [JsonPropertyName("g"), Required]
        public ushort G { get; set; }

        /// <summary>
        /// Gets or sets the blue channel sample value.
        /// </summary>
        [JsonPropertyName("b"), Required]
        public ushort B { get; set; }
    }
}
