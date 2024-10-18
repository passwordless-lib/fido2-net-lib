using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Represents the the ECDAA attestation data.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#ecdaatrustanchor-dictionary"/>
/// <para>In the case of ECDAA attestation, the ECDAA-Issuer's trust anchor MUST be specified in this field.</para>
/// </remarks>
public sealed class EcdaaTrustAnchor
{
    /// <summary>
    /// Gets or sets a base64url encoding of the result of ECPoint2ToB of the ECPoint2 X=P2​x​​.
    /// </summary>
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("x")]
    public required byte[] X { get; set; }

    /// <summary>
    /// Gets or sets a base64url encoding of the result of ECPoint2ToB of the ECPoint2.
    /// </summary>
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("y")]
    public required byte[] Y { get; set; }

    /// <summary>
    /// Gets or sets a base64url encoding of the result of BigNumberToB(c).
    /// </summary>
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("c")]
    public required byte[] C { get; set; }

    /// <summary>
    /// Gets or sets the base64url encoding of the result of BigNumberToB(sx).
    /// </summary>
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("sx")]
    public required byte[] SX { get; set; }

    /// <summary>
    /// Gets or sets the base64url encoding of the result of BigNumberToB(sy).
    /// </summary>
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("sy")]
    public required byte[] SY { get; set; }

    /// <summary>
    /// Gets or sets a name of the Barreto-Naehrig elliptic curve for G1.
    /// <para>"BN_P256", "BN_P638", "BN_ISOP256", and "BN_ISOP512" are supported.</para>
    /// </summary>
    [JsonPropertyName("G1Curve")]
    public required string G1Curve { get; set; }
}
