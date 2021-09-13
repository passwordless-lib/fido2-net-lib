using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// Represents the metadata BLOB payload data strucutre.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary"/>
    /// </remarks>
    public class MetadataBLOBPayloadEntry
    {
        /// <summary>
        /// Gets or sets the AAID.
        /// <para>The AAID of the authenticator this metadata BLOB payload entry relates to.</para>
        /// </summary>
        [JsonProperty("aaid")]
        public string Aaid { get; set; }
        /// <summary>
        /// Gets or sets the AAGUID.
        /// <para>The Authenticator Attestation GUID.</para>
        /// </summary>
        [JsonProperty("aaguid")]
        public string AaGuid { get; set; }
        /// <summary>
        /// Gets or sets a list of the attestation certificate public key identifiers encoded as hex string.
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        ///     <item>The hex string must not contain any non-hex characters (e.g. spaces).</item>
        ///     <item>All hex letters must be lower case.</item>
        ///     <item>This field must be set if neither aaid nor aaguid are set.</item>
        ///     <item>Setting this field implies that the attestation certificate(s) are dedicated to a single authenticator model.</item>
        /// </list>
        /// <para>FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.</para>
        /// </remarks>
        [JsonProperty("attestationCertificateKeyIdentifiers")]
        public string[] AttestationCertificateKeyIdentifiers { get; set; }
        /// <summary>
        /// Gets or sets the hash value computed over the base64url encoding of the UTF-8 representation of the JSON encoded metadata statement available at url.
        /// </summary>
        /// <remarks>
        /// The hash algorithm related to the signature algorithm specified in the JWTHeader (see Metadata BLOB) must be used.
        /// <para>This method of base64url encoding the UTF-8 representation is also used by JWT [JWT] to avoid encoding ambiguities.</para>
        /// </remarks>
        [JsonProperty("hash")]
        public string Hash { get; set; }
        /// <summary>
        /// Gets or sets the Uniform resource locator (URL) of the encoded metadata statement for this authenticator model (identified by its AAID, AAGUID or attestationCertificateKeyIdentifier).
        /// </summary>
        /// <remarks>
        /// This URL must point to the base64url encoding of the UTF-8 representation of the JSON encoded metadata statement.
        /// <para>If this field is missing, the metadata statement has not been published.</para>
        /// </remarks>
        [JsonProperty("url")]
        public string Url { get; set; }
        /// <summary>
        /// Gets or sets the status of the FIDO Biometric Certification of one or more biometric components of the Authenticator.
        /// </summary>
        [JsonProperty("biometricStatusReports")]
        public BiometricStatusReport[] BiometricStatusReports { get; set; }
        /// <summary>
        /// Gets or sets an array of status reports applicable to this authenticator.
        /// </summary>
        [JsonProperty("statusReports", Required = Required.Always)]
        public StatusReport[] StatusReports { get; set; }
        /// <summary>
        /// Gets or sets ISO-8601 formatted date since when the status report array was set to the current value. 
        /// </summary>
        [JsonProperty("timeOfLastStatusChange")]
        public string TimeOfLastStatusChange { get; set; }
        /// <summary>
        /// Gets or sets an URL of a list of rogue (i.e. untrusted) individual authenticators. 
        /// </summary>
        [JsonProperty("rogueListURL")]
        public string RogueListURL { get; set; }
        /// <summary>
        /// Gets or sets the hash value computed of <see cref="RogueListURL"/>.
        /// </summary>
        /// <remarks>
        /// This hash value must be present and non-empty whenever rogueListURL is present.
        /// </remarks>
        [JsonProperty("rogueListHash")]
        public string RogueListHash { get; set; }
        /// <summary>
        /// Gets or sets the metadata statement.
        /// </summary>
        [JsonProperty("metadataStatement")]
        //[JsonConverter(typeof(Base64UrlConverter))]
        public MetadataStatement MetadataStatement { get; set; }
    }
}
