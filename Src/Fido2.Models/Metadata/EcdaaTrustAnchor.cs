using System.ComponentModel.DataAnnotations;
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
    [JsonPropertyName("x"), Required]
    public string X { get; set; }

    /// <summary>
    /// Gets or sets a base64url encoding of the result of ECPoint2ToB of the ECPoint2.
    /// </summary>
    [JsonPropertyName("y"), Required]
    public string Y { get; set; }

    /// <summary>
    /// Gets or sets a base64url encoding of the result of BigNumberToB(c).
    /// </summary>
    [JsonPropertyName("c"), Required]
    public string C { get; set; }

    /// <summary>
    /// Gets or sets the base64url encoding of the result of BigNumberToB(sx).
    /// </summary>
    [JsonPropertyName("sx"), Required]
    public string SX { get; set; }

    /// <summary>
    /// Gets or sets the base64url encoding of the result of BigNumberToB(sy).
    /// </summary>
    [JsonPropertyName("sy"), Required]
    public string SY { get; set; }

    /// <summary>
    /// Gets or sets a name of the Barreto-Naehrig elliptic curve for G1.
    /// <para>"BN_P256", "BN_P638", "BN_ISOP256", and "BN_ISOP512" are supported.</para>
    /// </summary>
    [JsonPropertyName("G1Curve"), Required]
    public string G1Curve { get; set; }
}
