using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// The DisplayPNGCharacteristicsDescriptor describes a PNG image characteristics as defined in the PNG [PNG] spec for IHDR (image header) and PLTE (palette table)
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#displaypngcharacteristicsdescriptor-dictionary"/>
/// </remarks>
public sealed class DisplayPNGCharacteristicsDescriptor
{
    /// <summary>
    /// Gets or sets the image width.
    /// </summary>
    [JsonPropertyName("width"), Required]
    public ulong Width { get; set; }
    
    /// <summary>
    /// Gets or sets the image height.
    /// </summary>
    [JsonPropertyName("height"), Required]
    public ulong Height { get; set; }

    /// <summary>
    /// Gets or sets the bit depth - bits per sample or per palette index.
    /// </summary>
    [JsonPropertyName("bitDepth"), Required]
    public byte BitDepth { get; set; }

    /// <summary>
    /// Gets or sets the color type defines the PNG image type.
    /// </summary>
    [JsonPropertyName("colorType"), Required]
    public byte ColorType { get; set; }

    /// <summary>
    /// Gets or sets the compression method used to compress the image data.
    /// </summary>
    [JsonPropertyName("compression"), Required]
    public byte Compression { get; set; }

    /// <summary>
    /// Gets or sets the filter method is the preprocessing method applied to the image data before compression.
    /// </summary>
    [JsonPropertyName("filter"), Required]
    public byte Filter { get; set; }

    /// <summary>
    /// Gets or sets the interlace method is the transmission order of the image data.
    /// </summary>
    [JsonPropertyName("interlace"), Required]
    public byte Interlace { get; set; }

    /// <summary>
    /// Gets or sets the palette (1 to 256 palette entries).
    /// </summary>
    [JsonPropertyName("plte")]
    public RgbPaletteEntry[] Plte { get; set; }
}
