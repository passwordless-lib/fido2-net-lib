using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib
{
    /// <summary>
    /// Represents the MetadataTOCPayload
    /// </summary>
    /// <remarks>
    /// <see xref="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-service-v2.0-rd-20180702.html#metadata-toc-payload-dictionary"/>
    /// </remarks>
    public class MetadataTOCPayload
    {
        /// <summary>
        /// Gets or sets the legalHeader, if present, contains a legal guide for accessing and using metadata.
        /// </summary>
        /// <remarks>
        /// This value MAY contain URL(s) pointing to further information, such as a full Terms and Conditions statement. 
        /// </remarks>
        [JsonPropertyName("legalHeader")]
        public string LegalHeader { get; set; }
        /// <summary>   
        /// Gets or sets the serial number of this UAF Metadata TOC Payload. 
        /// </summary>
        /// <remarks>
        /// Serial numbers MUST be consecutive and strictly monotonic, i.e. the successor TOC will have a no value exactly incremented by one.
        /// </remarks>
        [JsonPropertyName("no")]
        public int Number { get; set; }
        /// <summary>
        /// Gets or sets a formatted date (ISO-8601) when the next update will be provided at latest.
        /// </summary>
        [JsonPropertyName("nextUpdate")]
        public string NextUpdate { get; set; }
        /// <summary>
        /// Gets or sets a list of zero or more entries of <see cref="MetadataTOCPayloadEntry"/>.
        /// </summary>
        [JsonProperty("entries", Required = Required.Always)]
        public MetadataTOCPayloadEntry[] Entries { get; set; }

        /// <summary>
        /// The "alg" property from the original JWT header. Used to validate MetadataStatements.
        /// </summary>
        [JsonProperty("jwtAlg", Required = Required.Default)]
        public string JwtAlg { get; set; }
    }
}
