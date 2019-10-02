using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// Represents the the ECDAA attestation data.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#ecdaatrustanchor-dictionary"/>
    /// <para>In the case of ECDAA attestation, the ECDAA-Issuer's trust anchor MUST be specified in this field.</para>
    /// </remarks>
    public class EcdaaTrustAnchor
    {
        /// <summary>
        /// Gets or sets a base64url encoding of the result of ECPoint2ToB of the ECPoint2 X=P2​x​​.
        /// </summary>
        [JsonProperty("x", Required = Required.Always)]
        public string X { get; set; }
        /// <summary>
        /// Gets or sets a base64url encoding of the result of ECPoint2ToB of the ECPoint2.
        /// </summary>
        [JsonProperty("y", Required = Required.Always)]
        public string Y { get; set; }
        /// <summary>
        /// Gets or sets a base64url encoding of the result of BigNumberToB(c).
        /// </summary>
        [JsonProperty("c", Required = Required.Always)]
        public string C { get; set; }
        /// <summary>
        /// Gets or sets the base64url encoding of the result of BigNumberToB(sx).
        /// </summary>
        [JsonProperty("sx", Required = Required.Always)]
        public string SX { get; set; }
        /// <summary>
        /// Gets or sets the base64url encoding of the result of BigNumberToB(sy).
        /// </summary>
        [JsonProperty("sy", Required = Required.Always)]
        public string SY { get; set; }
        /// <summary>
        /// Gets or sets a name of the Barreto-Naehrig elliptic curve for G1.
        /// <para>"BN_P256", "BN_P638", "BN_ISOP256", and "BN_ISOP512" are supported.</para>
        /// </summary>
        [JsonProperty("G1Curve", Required = Required.Always)]
        public string G1Curve { get; set; }
    }
}
